package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// streamingRelay stands in for the Cloudflare relay and lets a test hold the
// response open mid-body, so "did the client receive bytes before the origin
// finished" becomes an observable fact rather than a claim.
type streamingRelay struct {
	server  *httptest.Server
	release chan struct{}
	started chan struct{}
}

func newStreamingRelay(t *testing.T, contentType string) *streamingRelay {
	t.Helper()
	sr := &streamingRelay{
		release: make(chan struct{}),
		started: make(chan struct{}),
	}
	sr.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Phaethon-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if contentType == "application/octet-stream" {
			// No Content-Length: the body length is not known up front.
			w.WriteHeader(http.StatusOK)
		}
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, strings.Repeat("a", 4096))
		if flusher != nil {
			flusher.Flush()
		}
		close(sr.started)
		<-sr.release // hold the body open
		_, _ = io.WriteString(w, strings.Repeat("b", 4096))
	}))
	t.Cleanup(sr.server.Close)
	return sr
}

// streamingProxy builds a daemon whose relay route points at the streaming
// test server.
func streamingProxy(t *testing.T, relay *streamingRelay) string {
	t.Helper()
	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "local-secret",
		DefaultRoute: config.RouteDirect,
		Routes:       []config.RouteRule{{Host: "stream.test", Route: config.RouteRelay}},
		Relay: config.RelayConfig{
			URL: relay.server.URL, Token: "relay-secret",
			Timeout: 30 * time.Second, InsecureSkipVerify: true,
		},
		Dial:                     config.DialConfig{Timeout: 5 * time.Second, PreflightTimeout: time.Second},
		AllowPrivateDestinations: true,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	httpSrv := &http.Server{Handler: srv}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	})
	return ln.Addr().String()
}

// A non-rewritable response (a binary blob, a Git packfile) must be streamed
// straight through: the first bytes must reach the client while the origin is
// still holding the body open. A buffering implementation would deliver
// nothing until the origin finished.
func TestLargeBodyStreamsWithoutBuffering(t *testing.T) {
	relay := newStreamingRelay(t, "application/octet-stream")
	addr := streamingProxy(t, relay)

	resp, err := http.Get("http://" + addr + "/r/stream.test/blob.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Phaethon-Streamed") != "1" {
		t.Errorf("a binary response should be marked streamed, headers: %v", resp.Header)
	}
	if resp.Header.Get("X-Phaethon-Rewritten") != "" {
		t.Error("a binary response must not be rewritten")
	}
	// The origin has started its body but is holding it open.
	select {
	case <-relay.started:
	case <-time.After(5 * time.Second):
		t.Fatal("origin never started its body")
	}

	// The first 4096 bytes must arrive before the origin is released.
	first := make([]byte, 4096)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(resp.Body, first)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reading the first chunk: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no bytes reached the client while the origin held the body open: the response is being buffered")
	}
	if first[0] != 'a' {
		t.Fatalf("first byte = %q, want 'a'", first[0])
	}

	// Release the rest and confirm the whole body arrives intact.
	close(relay.release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 4096 {
		t.Fatalf("remaining body = %d bytes, want 4096", len(rest))
	}
	if rest[0] != 'b' {
		t.Fatalf("second chunk starts with %q, want 'b'", rest[0])
	}
}

// Markup is the one thing that must be buffered, because it has to be
// rewritten. The same harness shows the difference: an HTML response does not
// reach the client until the origin has finished, and carries the rewrite
// markers instead of the streaming markers.
func TestHTMLIsBufferedForRewriting(t *testing.T) {
	relay := newStreamingRelay(t, "text/html; charset=utf-8")
	addr := streamingProxy(t, relay)

	type result struct {
		resp *http.Response
		body string
	}
	got := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/r/stream.test/page")
		if err != nil {
			got <- result{}
			return
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		got <- result{resp: resp, body: string(body)}
	}()

	select {
	case <-time.After(300 * time.Millisecond):
		// Still waiting, as expected while the origin holds the body.
	case r := <-got:
		t.Fatalf("HTML arrived before the origin finished (%d bytes); it should have been buffered",
			len(r.body))
	}

	close(relay.release)
	select {
	case r := <-got:
		if r.resp == nil {
			t.Fatal("request failed")
		}
		if r.resp.Header.Get("X-Phaethon-Rewritten") != "1" {
			t.Errorf("HTML should be marked rewritten, headers: %v", r.resp.Header)
		}
		if r.resp.Header.Get("X-Phaethon-Streamed") != "" {
			t.Error("HTML should not be marked streamed")
		}
		if len(r.body) != 8192 {
			t.Errorf("body = %d bytes, want 8192", len(r.body))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTML never completed after the origin was released")
	}
}

// A streamed response must keep its original headers, including Content-Length
// and the validators a client uses for range requests and revalidation.
func TestStreamedResponseKeepsHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Phaethon-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "5")
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()

	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "t",
		DefaultRoute: config.RouteDirect,
		Routes:       []config.RouteRule{{Host: "hdr.test", Route: config.RouteRelay}},
		Relay: config.RelayConfig{
			URL: srv.URL, Token: "relay-secret",
			Timeout: 10 * time.Second, InsecureSkipVerify: true,
		},
		Dial:                     config.DialConfig{Timeout: 5 * time.Second, PreflightTimeout: time.Second},
		AllowPrivateDestinations: true,
	}
	daemon, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	httpSrv := &http.Server{Handler: daemon}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/r/hdr.test/file.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Errorf("status = %d, want 206 preserved from upstream", resp.StatusCode)
	}
	for header, want := range map[string]string{
		"ETag":           `"abc123"`,
		"Accept-Ranges":  "bytes",
		"Last-Modified":  "Wed, 21 Oct 2026 07:28:00 GMT",
		"Content-Length": "5",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// A relayed request that fails must not leave a durable relay lease behind.
func TestRelayFailureClearsRelayLease(t *testing.T) {
	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "t",
		DefaultRoute: config.RouteDirect,
		Routes:       []config.RouteRule{{Host: "refuse.test", Route: config.RouteRelay}},
		// A relay endpoint that does not exist: every relayed request fails.
		Relay: config.RelayConfig{
			URL: "https://127.0.0.1:1", Token: "relay-secret",
			Timeout: 2 * time.Second, InsecureSkipVerify: true,
		},
		Dial:                     config.DialConfig{Timeout: 2 * time.Second, PreflightTimeout: time.Second},
		AllowPrivateDestinations: true,
	}
	daemon, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	httpSrv := &http.Server{Handler: daemon}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/r/refuse.test/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for a failing relay", resp.StatusCode)
	}
	// Nothing may be remembered as a working relay route. (The router's own
	// reaction to a failed relay is covered by TestRelayFailureDoesNotPoisonCache
	// with a fake oracle; here the point is that the daemon reports the
	// failure rather than pretending the route worked.)
	for _, l := range daemon.router.LeaseViews() {
		if l.Route == "relay" && l.State == "relay_verified" {
			t.Fatalf("a failed relay left a verified relay lease: %+v", l)
		}
	}
}

// tls import is used by the streaming harness's httptest server type.
var _ = tls.VersionTLS12

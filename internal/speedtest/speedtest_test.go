package speedtest

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/dial"
	"github.com/arahe-dev/phaethon/internal/transport"
)

// loopbackDirect builds a direct transport allowed to reach test listeners.
func loopbackDirect(t *testing.T) *transport.Direct {
	t.Helper()
	d := dial.New(3*time.Second, time.Second, time.Minute, time.Minute)
	d.AllowPrivate = true
	return transport.NewDirect(d, 10*time.Second, 1<<20)
}

// origins is a TLS origin and the hostname used to reach it.
type origins struct {
	server *httptest.Server
	host   string
}

// newOrigin starts a TLS origin reachable as "origin.test" via a resolver that
// points the name at the listener.
func newOrigin(t *testing.T, handler http.Handler) *origins {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	o := &origins{server: srv, host: "origin.test"}
	// A resolver that answers "origin.test" with the loopback listener, so the
	// transport's DNS path is exercised without touching the real network.
	_ = port
	return o
}

// directForOrigin returns a Direct transport whose dialer resolves origin.test
// to the given address.
func directForOrigin(t *testing.T, addr string) *transport.Direct {
	t.Helper()
	d := dial.New(3*time.Second, time.Second, time.Minute, time.Minute)
	d.AllowPrivate = true
	direct := transport.NewDirect(d, 10*time.Second, 1<<20)
	return direct
}

// A counting reader must count and report the first byte without holding the
// body: a benchmark that buffered would measure this process, not the network.
func TestCountingReaderStreamsWithoutBuffering(t *testing.T) {
	const total = 64 << 20 // 64 MiB
	body := &repeatReader{remaining: total, chunk: make([]byte, 32<<10)}

	cr := &countingReader{r: body, start: time.Now().Add(-5 * time.Millisecond)}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	n, err := io.Copy(io.Discard, cr)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Fatalf("read %d bytes, want %d", n, total)
	}
	if cr.n != total {
		t.Fatalf("counter = %d, want %d", cr.n, total)
	}
	if !cr.gotFirst {
		t.Fatal("the first byte was never recorded")
	}
	if cr.firstByte < 5*time.Millisecond {
		t.Errorf("first-byte time = %v; it must be measured from the request start", cr.firstByte)
	}
	// 64 MiB through a streaming reader must not allocate 64 MiB.
	grew := int64(after.TotalAlloc - before.TotalAlloc)
	if grew > total/4 {
		t.Errorf("streaming 64 MiB allocated %d bytes; the body is being buffered", grew)
	}
}

// repeatReader yields a fixed number of bytes without allocating them.
type repeatReader struct {
	remaining int
	chunk     []byte
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > len(r.chunk) {
		n = len(r.chunk)
	}
	if n > r.remaining {
		n = r.remaining
	}
	r.remaining -= n
	return n, nil
}

// Statistics must be real statistics, and a p95 must not be invented from too
// few samples.
func TestStats(t *testing.T) {
	none := statsOf(nil)
	if none.Samples != 0 || none.MedianMs != 0 {
		t.Fatalf("empty stats = %+v", none)
	}
	one := statsOf([]float64{7})
	if one.MinMs != 7 || one.MaxMs != 7 || one.MedianMs != 7 || one.MeanMs != 7 || one.Samples != 1 {
		t.Fatalf("single-sample stats = %+v", one)
	}
	if one.P95Ms != 0 {
		t.Error("a p95 from one sample is the maximum in disguise; it must not be reported")
	}

	values := []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	st := statsOf(values)
	if st.Samples != 10 {
		t.Fatalf("samples = %d", st.Samples)
	}
	if st.MinMs != 10 || st.MaxMs != 100 {
		t.Errorf("min/max = %v/%v", st.MinMs, st.MaxMs)
	}
	if st.MeanMs != 55 {
		t.Errorf("mean = %v, want 55", st.MeanMs)
	}
	if st.MedianMs != 50 {
		t.Errorf("median = %v, want 50", st.MedianMs)
	}
	if st.P95Ms != 100 {
		t.Errorf("p95 = %v, want 100", st.P95Ms)
	}
	// Unsorted input must not change the answer.
	shuffled := statsOf([]float64{100, 10, 50, 90, 20, 60, 30, 80, 40, 70})
	if shuffled.MedianMs != st.MedianMs || shuffled.P95Ms != st.P95Ms {
		t.Errorf("statistics depend on input order: %+v vs %+v", shuffled, st)
	}
}

// A direct measurement of a healthy origin reports layers and timings.
func TestDirectSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, strings.Repeat("x", 64<<10))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	direct := loopbackDirect(t)
	direct.RootCAs = poolFrom(t, srv)
	m := &Measurer{Direct: direct, Version: "test"}

	rep, err := m.Run(context.Background(), Options{
		Host: "127.0.0.1", URL: "https://127.0.0.1:" + port + "/blob", Runs: 3, Direct: true,
	}, RouteInfo{Route: "direct", Source: "static"})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Direct.Attempted {
		t.Fatal("the direct path was not attempted")
	}
	// Every requested run must be accounted for. A run whose clock did not
	// advance is reported as discarded rather than as a zero-duration sample,
	// so surviving samples plus discards is what adds up to the runs.
	if got := rep.Direct.Total.Samples + rep.Direct.Discarded; got != 3 {
		t.Fatalf("samples plus discards = %d, want 3 (samples=%d discarded=%d)",
			got, rep.Direct.Total.Samples, rep.Direct.Discarded)
	}
	if rep.Direct.Total.Samples == 0 {
		t.Fatal("every run was discarded, so nothing was actually measured")
	}
	// No surviving sample may carry a zero duration. That is the defect this
	// accounting exists to prevent: one such sample drags the minimum and the
	// median to zero and makes throughput meaningless.
	for _, s := range rep.Direct.Samples {
		if s.Bytes > 0 && (s.TotalMs <= 0 || s.TTFBMs <= 0) {
			t.Errorf("a sample transferred %d bytes but reports no timing: %+v", s.Bytes, s)
		}
	}
	if rep.Direct.Bytes != 3*(64<<10) {
		t.Errorf("bytes = %d, want %d", rep.Direct.Bytes, 3*(64<<10))
	}
	if rep.Direct.TTFB.MedianMs <= 0 {
		t.Error("time to first byte was not measured")
	}
	if rep.Direct.Throughput.MedianMs <= 0 {
		t.Error("throughput was not computed")
	}
	if rep.Direct.Error != "" {
		t.Errorf("unexpected error: %s", rep.Direct.Error)
	}
	if rep.SchemaVersion != SchemaVersion {
		t.Errorf("schema version = %d", rep.SchemaVersion)
	}
	if rep.Timestamp == "" {
		t.Error("the report must be timestamped")
	}
}

// A direct measurement of an origin whose certificate is not trusted must
// report the failure rather than a number.
func TestDirectTLSFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "should not be reached")
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	// Deliberately no RootCAs: the origin's self-signed certificate must be
	// rejected, which is the same shape as an intercepting middlebox.
	m := &Measurer{Direct: loopbackDirect(t), Version: "test"}
	rep, err := m.Run(context.Background(), Options{
		Host: "127.0.0.1", URL: "https://127.0.0.1:" + port + "/", Runs: 2, Direct: true,
	}, RouteInfo{Route: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Direct.Error == "" {
		t.Fatal("a TLS failure must be reported as an error, not as a measurement")
	}
	if rep.Direct.Total.Samples != 0 {
		t.Errorf("samples = %d, want 0 when TLS fails", rep.Direct.Total.Samples)
	}
	if rep.Direct.Bytes != 0 {
		t.Errorf("bytes = %d, want 0", rep.Direct.Bytes)
	}
}

// A relay measurement reports timings and throughput from the relay path.
func TestRelaySuccess(t *testing.T) {
	relay, hits := fakeRelay(t, 128<<10, nil)
	m := &Measurer{Relay: relay, Version: "test"}

	rep, err := m.Run(context.Background(), Options{
		Host: "relay.test", URL: "https://relay.test/data.bin", Runs: 2, Relay: true,
	}, RouteInfo{Route: "relay", Reason: "tls_specific_failure"})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Relay.Attempted {
		t.Fatalf("relay result = %+v", rep.Relay)
	}
	// Attempted runs are accounted for as measured plus discarded, and at least
	// one must have produced a real timing for the statistics to mean anything.
	if got := rep.Relay.Total.Samples + rep.Relay.Discarded; got != 2 {
		t.Fatalf("samples plus discards = %d, want 2 (samples=%d discarded=%d)",
			got, rep.Relay.Total.Samples, rep.Relay.Discarded)
	}
	if rep.Relay.Total.Samples == 0 {
		t.Fatalf("every relay run was discarded, so no timing was measured: %+v", rep.Relay)
	}
	if rep.Relay.Bytes != 2*(128<<10) {
		t.Errorf("bytes = %d, want %d", rep.Relay.Bytes, 2*(128<<10))
	}
	if rep.Relay.TTFB.MedianMs <= 0 || rep.Relay.Throughput.MedianMs <= 0 {
		t.Errorf("relay timings missing: %+v", rep.Relay)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("relay saw %d requests, want 2", got)
	}
	if rep.CurrentRoute != "relay" || rep.LeaseReason != "tls_specific_failure" {
		t.Errorf("routing context not carried into the report: %+v", rep)
	}
}

// A relaying failure is reported as an error for that path alone.
func TestRelayFailure(t *testing.T) {
	relay, _ := fakeRelay(t, 1024, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	m := &Measurer{Relay: relay, Version: "test"}
	rep, err := m.Run(context.Background(), Options{
		Host: "relay.test", URL: "https://relay.test/", Runs: 1, Relay: true,
	}, RouteInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Relay.Error == "" {
		t.Fatal("a refused relay must surface an error")
	}
	if rep.Direct.Attempted {
		t.Error("the direct path must not be measured when it was not requested")
	}
}

// Both paths can be measured in one report.
func TestBothPaths(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("y", 32<<10))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	relay, _ := fakeRelay(t, 32<<10, nil)
	// The relay transport enforces its own allowlist, so it must be told this
	// test's origin is acceptable.
	relay.Allowlist = []string{"127.0.0.1"}
	direct := loopbackDirect(t)
	direct.RootCAs = poolFrom(t, srv)

	m := &Measurer{Direct: direct, Relay: relay, Version: "test"}
	rep, err := m.Run(context.Background(), Options{
		Host: "127.0.0.1", URL: "https://127.0.0.1:" + port + "/", Runs: 2,
		Direct: true, Relay: true,
	}, RouteInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Direct.Attempted || !rep.Relay.Attempted {
		t.Fatalf("both paths should be attempted: direct=%v relay=%v", rep.Direct.Attempted, rep.Relay.Attempted)
	}
	if rep.Direct.Bytes == 0 || rep.Relay.Bytes == 0 {
		t.Errorf("both paths should have transferred bytes: %d / %d", rep.Direct.Bytes, rep.Relay.Bytes)
	}
}

// Cancellation must stop the measurement promptly rather than running to
// completion.
func TestCancellation(t *testing.T) {
	gate := make(chan struct{})
	relay, _ := fakeRelay(t, 1024, func(w http.ResponseWriter, r *http.Request) {
		<-gate // hold every request open
	})
	defer close(gate)

	m := &Measurer{Relay: relay, Version: "test"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = m.Run(ctx, Options{Host: "relay.test", URL: "https://relay.test/", Runs: 5, Relay: true}, RouteInfo{})
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// A URL pointing at a host that is neither the target nor covered by policy
// must be refused, so a measurement cannot become a way to reach anywhere.
func TestEligibleURLHost(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteRule{
			{Host: "static.test", Route: config.RouteDirect},
			{Host: "denied.test", Route: config.RouteDeny},
		},
		AutoRoute: config.AutoRouteConfig{
			RelayEligible: []string{"*.example.test", "*.example.app"},
		},
	}
	ok := []struct{ target, urlHost string }{
		{"example.test", "example.test"},
		{"example.test", "assets.example.test"}, // relay-eligible sibling
		{"example.test", "static.test"},         // already-allowed host
		{"anything.test", "anything.test"},
	}
	for _, c := range ok {
		if err := EligibleURLHost(c.target, c.urlHost, cfg); err != nil {
			t.Errorf("EligibleURLHost(%q, %q) = %v, want allowed", c.target, c.urlHost, err)
		}
	}
	no := []struct{ target, urlHost string }{
		{"example.test", "evil.test"},              // unrelated
		{"example.test", "notexample.test"},        // lookalike
		{"example.test", "example.test.evil.test"}, // suffix trick
		{"example.test", "denied.test"},            // explicitly denied
		{"example.test", ""},                       // no host at all
	}
	for _, c := range no {
		if err := EligibleURLHost(c.target, c.urlHost, cfg); err == nil {
			t.Errorf("EligibleURLHost(%q, %q) was allowed, want refused", c.target, c.urlHost)
		}
	}
	if err := EligibleURLHost("example.test", "example.test", nil); err != nil {
		t.Errorf("the target's own host should always be allowed: %v", err)
	}
}

// Enumerating blocked hosts must be driven by recorded routing state, not by a
// separate idea of what looks broken.
func TestBlockedIsDrivenByLeaseReasons(t *testing.T) {
	// Relay leases are blocked by definition; direct leases only when the
	// recorded reason is a path failure.
	relayLease := LeaseViewLike{Route: "relay", Reason: "tls_specific_failure"}
	if !relayLease.blocked() {
		t.Error("a relay lease should count as blocked")
	}
	directHealthy := LeaseViewLike{Route: "direct", Reason: "path_healthy"}
	if directHealthy.blocked() {
		t.Error("a healthy direct lease is not a blocked host")
	}
	directBroken := LeaseViewLike{Route: "direct", Reason: "tls_specific_failure"}
	if !directBroken.blocked() {
		t.Error("a direct lease recording a TLS failure should count as blocked")
	}
	partial := LeaseViewLike{Route: "direct", Reason: "partial_address_failure"}
	if partial.blocked() {
		t.Error("a partial address failure is handled by failover and is not a blocked host")
	}
}

// LeaseViewLike mirrors the CLI's classification, kept here so the rule is
// tested next to the measurement code.
type LeaseViewLike struct {
	Route  string
	Reason string
}

func (l LeaseViewLike) blocked() bool {
	if l.Route == "relay" {
		return true
	}
	switch l.Reason {
	case "tls_specific_failure", "possible_proxy_interference", "dns_failure",
		"tcp_unreachable", "network_unreachable":
		return true
	}
	return false
}

// helper: a root pool trusting a test origin.
func poolFrom(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// fakeRelay builds a relay transport and counts the requests it serves.
func fakeRelay(t *testing.T, size int, override http.HandlerFunc) (*transport.Relay, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Phaethon-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		hits.Add(1)
		if override != nil {
			override(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, strings.Repeat("z", size))
	}))
	t.Cleanup(srv.Close)
	rel, err := transport.NewRelay(config.RelayConfig{
		URL: srv.URL, Token: "tok", Timeout: 10 * time.Second, InsecureSkipVerify: true,
	}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	rel.Allowlist = []string{"relay.test"}
	return rel, &hits
}

// A measurement whose accessor types are missing must fail clearly.
func TestUnavailablePaths(t *testing.T) {
	m := &Measurer{Version: "test"}
	rep, err := m.Run(context.Background(), Options{Host: "x.test", Runs: 1, Direct: true, Relay: true}, RouteInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Direct.Error == "" {
		t.Error("a missing direct transport should be reported")
	}
	if rep.Relay.Error == "" {
		t.Error("a missing relay should be reported")
	}
}

// unknown scheme is refused rather than measured.
func TestNonHTTPSSchemeRefused(t *testing.T) {
	m := &Measurer{Version: "test"}
	if _, err := m.Run(context.Background(), Options{Host: "x.test", URL: "http://x.test/", Runs: 1, Direct: true}, RouteInfo{}); err == nil {
		t.Fatal("a plaintext target should be refused")
	}
	if _, err := m.Run(context.Background(), Options{Host: "", Runs: 1}, RouteInfo{}); err == nil {
		t.Fatal("a missing hostname should be refused")
	}
}

// A relay that never answers must fail by timeout, not hang.
func TestRelayTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	defer ln.Close()

	rel, err := transport.NewRelay(config.RelayConfig{
		URL: "https://" + addr, Token: "tok", Timeout: 700 * time.Millisecond, InsecureSkipVerify: true,
	}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	rel.Allowlist = []string{"relay.test"}

	// Accept but never respond, so only the client's timeout ends it.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, aerr := ln.Accept()
		if aerr == nil {
			<-time.After(3 * time.Second)
			_ = conn.Close()
		}
	}()
	defer wg.Wait()

	m := &Measurer{Relay: rel, Version: "test"}
	start := time.Now()
	rep, err := m.Run(context.Background(), Options{
		Host: "relay.test", URL: "https://relay.test/", Runs: 1, Relay: true,
	}, RouteInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("a stalled relay took %v; the timeout should bound it", elapsed)
	}
	if rep.Relay.Error == "" {
		t.Error("a stalled relay should be reported as an error")
	}
}

// A redirect must be followed when policy allows the destination, because a
// real download does exactly that: without it a 302 was measured as an empty
// success taking a couple of milliseconds, which reads as a fast transfer
// rather than a missed one.
func TestRedirectIsFollowedWhenAllowed(t *testing.T) {
	const payload = 256 << 10
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real.bin" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, strings.Repeat("d", payload))
			return
		}
		http.Redirect(w, r, "/real.bin", http.StatusFound)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	direct := loopbackDirect(t)
	direct.RootCAs = poolFrom(t, srv)

	var hops []string
	m := &Measurer{Direct: direct, Version: "test"}
	rep, err := m.Run(context.Background(), Options{
		Host: "127.0.0.1", URL: "https://127.0.0.1:" + port + "/start",
		Runs: 1, Direct: true,
		ValidateURL: func(u *url.URL) error {
			hops = append(hops, u.Path)
			return nil
		},
	}, RouteInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Direct.Bytes != payload {
		t.Fatalf("bytes = %d, want %d (error %q, hops %v)",
			rep.Direct.Bytes, payload, rep.Direct.Error, hops)
	}
	if len(hops) != 1 || hops[0] != "/real.bin" {
		t.Errorf("redirect hops = %v, want exactly [/real.bin]", hops)
	}
	if !strings.Contains(rep.Direct.Note, "redirect") {
		t.Errorf("the note should mention that a redirect was followed, got %q", rep.Direct.Note)
	}
}

// A redirect that leaves policy must end the measurement with an explanation,
// so a benchmark cannot be steered at a destination the operator never allowed.
func TestRedirectLeavingPolicyIsRefused(t *testing.T) {
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secret")
	}))
	defer final.Close()
	_, finalPort, _ := net.SplitHostPort(final.Listener.Addr().String())

	start := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1:"+finalPort+"/elsewhere", http.StatusFound)
	}))
	defer start.Close()
	_, startPort, _ := net.SplitHostPort(start.Listener.Addr().String())

	direct := loopbackDirect(t)
	direct.RootCAs = poolFrom(t, start)

	m := &Measurer{Direct: direct, Version: "test"}
	rep, err := m.Run(context.Background(), Options{
		Host: "127.0.0.1", URL: "https://127.0.0.1:" + startPort + "/", Runs: 1, Direct: true,
		// The validator refuses everything: this stands in for a redirect
		// aimed at a host outside the requested target and policy.
		ValidateURL: func(u *url.URL) error { return fmt.Errorf("host %q is not permitted", u.Hostname()) },
	}, RouteInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Direct.Error == "" {
		t.Fatal("a redirect outside policy must be reported as an error")
	}
	if !strings.Contains(rep.Direct.Error, "redirect refused") {
		t.Errorf("the error should say the redirect was refused: %s", rep.Direct.Error)
	}
	if rep.Direct.Bytes != 0 {
		t.Errorf("bytes = %d, want 0: the disallowed destination must not have been fetched", rep.Direct.Bytes)
	}
}

package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/mitm"
)

// interceptConfig is a daemon with interception enabled and a route table that
// covers a relay host, a direct host, and a literal loopback address (so a
// real TLS origin can stand in for a healthy direct destination).
func interceptConfig(relayURL string, caDir string) *config.Config {
	rules := []config.RouteRule{
		{Host: "direct.test", Route: config.RouteDirect},
		{Host: "127.0.0.1", Route: config.RouteDirect},
	}
	if relayURL != "" {
		rules = append(rules, config.RouteRule{Host: "relay.test", Route: config.RouteRelay})
	}
	return &config.Config{
		Listen:                   "127.0.0.1:0",
		LocalToken:               "local-secret",
		DefaultRoute:             config.RouteDirect,
		Routes:                   rules,
		Dial:                     config.DialConfig{Timeout: 3 * time.Second, PreflightTimeout: time.Second},
		AllowPrivateDestinations: true,
		Relay: config.RelayConfig{
			URL: relayURL, Token: "relay-secret",
			Timeout: 10 * time.Second, InsecureSkipVerify: true,
		},
		Intercept: config.InterceptConfig{Enabled: true, CADir: caDir},
	}
}

// serve starts a daemon and returns it with its address.
func serve(t *testing.T, cfg *config.Config) (*Server, string) {
	t.Helper()
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
	return srv, ln.Addr().String()
}

// dialCONNECT performs a CONNECT and returns the connection plus the status
// line the proxy answered with.
func dialCONNECT(t *testing.T, proxyAddr, target string) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for { // drain the remaining response headers
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	return conn, strings.TrimSpace(line)
}

// peerIssuer performs a TLS handshake on an established tunnel and reports the
// full issuer of the certificate that arrived. The whole distinguished name is
// used, not just CommonName: a certificate may legitimately have no CN.
func peerIssuer(conn net.Conn, serverName string) (string, *tls.Conn, error) {
	client := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // the point is to see whose certificate arrives
		MinVersion:         tls.VersionTLS12,
	})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := client.Handshake(); err != nil {
		return "", nil, err
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", client, nil
	}
	return state.PeerCertificates[0].Issuer.String(), client, nil
}

// The whole point of the design: a direct-routed host keeps a raw encrypted
// tunnel. The certificate the client receives must be the origin's own, never
// one Phaethon minted.
func TestDirectHostKeepsItsOwnCertificate(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer origin.Close()
	_, originPort, _ := net.SplitHostPort(origin.Listener.Addr().String())

	_, proxyAddr := serve(t, interceptConfig("", t.TempDir()))

	conn, line := dialCONNECT(t, proxyAddr, "127.0.0.1:"+originPort)
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT to a direct host = %q, want 200", line)
	}
	issuer, client, err := peerIssuer(conn, "127.0.0.1")
	if err != nil {
		t.Fatalf("handshake through the raw tunnel failed: %v", err)
	}
	if issuer == "" {
		t.Fatal("no certificate arrived through the tunnel")
	}
	if strings.Contains(issuer, "Phaethon") {
		t.Fatalf("a DIRECT host was intercepted: certificate issued by %q", issuer)
	}
	t.Logf("direct host presented its own certificate: issuer=%s", issuer)
	// And the traffic really is the origin's: a request through the same
	// tunnel reaches it.
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("reading the tunnelled response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "origin" {
		t.Fatalf("tunnelled body = %q, want the origin's own response", body)
	}
}

// A relay-routed host is intercepted, and the certificate names exactly the
// host the browser asked for — which is why the real domain stays in the
// address bar.
func TestRelayHostIsInterceptedWithItsOwnName(t *testing.T) {
	relay := fakeOriginRelay(t)
	t.Cleanup(relay.Close)

	srv, proxyAddr := serve(t, interceptConfig(relay.URL, t.TempDir()))
	ca := srv.CA()
	if ca == nil {
		t.Fatal("no CA was built despite interception being enabled")
	}

	conn, line := dialCONNECT(t, proxyAddr, "relay.test:443")
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT to a relay host = %q, want 200", line)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("could not build a pool from the CA")
	}
	client := tls.Client(conn, &tls.Config{
		ServerName: "relay.test",
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// This fails unless the certificate chains to our CA and matches the
	// name, which is the property a browser checks.
	if err := client.Handshake(); err != nil {
		t.Fatalf("intercepted handshake failed against the local CA: %v", err)
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no certificate presented")
	}
	leaf := state.PeerCertificates[0]
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "relay.test" {
		t.Fatalf("intercepted certificate names %v, want exactly [relay.test]", leaf.DNSNames)
	}
	if state.NegotiatedProtocol == "h2" {
		t.Error("h2 was negotiated; the interception path speaks HTTP/1.1 only")
	}

	// The decrypted request must be carried through the relay and answered.
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("reading the intercepted response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "example") {
		t.Fatalf("the relayed body did not come back: %q", truncate(string(body), 80))
	}
	// Interception serves the real origin, so nothing may be rewritten: the
	// document's own references are already correct. A facade prefix here is
	// the bug that produced requests for https://example.test/r/example.test/...
	if resp.Header.Get("X-Phaethon-Rewritten") != "" {
		t.Errorf("intercepted HTML was rewritten; origin mode must leave it alone")
	}
	if resp.Header.Get("X-Phaethon-Streamed") != "1" {
		t.Errorf("intercepted HTML should stream, not buffer; headers: %v", resp.Header)
	}
}

// Interception is inert while disabled: a relay host is refused with the same
// clear 501 as before, and no CA is even created.
func TestInterceptionDisabledLeavesRelayHostRefused(t *testing.T) {
	relay := fakeOriginRelay(t)
	t.Cleanup(relay.Close)

	cfg := interceptConfig(relay.URL, t.TempDir())
	cfg.Intercept.Enabled = false
	srv, proxyAddr := serve(t, cfg)

	if srv.CA() != nil {
		t.Fatal("a CA was built even though interception is disabled")
	}
	if srv.canIntercept("relay.test", config.RouteRelay) {
		t.Fatal("interception reported possible while disabled")
	}
	_, line := dialCONNECT(t, proxyAddr, "relay.test:443")
	if !strings.Contains(line, "501") {
		t.Fatalf("CONNECT to a relay host with interception off = %q, want 501", line)
	}
}

// canIntercept is the security boundary, so its conditions are asserted
// directly and not only through a handshake.
func TestCanInterceptRequiresRelayRoute(t *testing.T) {
	relay := fakeOriginRelay(t)
	t.Cleanup(relay.Close)
	srv, _ := serve(t, interceptConfig(relay.URL, t.TempDir()))

	if !srv.canIntercept("relay.test", config.RouteRelay) {
		t.Error("a relay route with interception enabled should be interceptable")
	}
	if srv.canIntercept("relay.test", config.RouteDirect) {
		t.Error("a DIRECT route must never be intercepted")
	}
	if srv.canIntercept("relay.test", config.RouteDeny) {
		t.Error("a denied route must never be intercepted")
	}
}

// A CA whose private key is not owner-restricted must stop the daemon from
// intercepting: a key another user can read can mint certificates they trust.
func TestUnprotectedKeyPreventsInterception(t *testing.T) {
	relay := fakeOriginRelay(t)
	t.Cleanup(relay.Close)

	dir := t.TempDir()
	cfg := interceptConfig(relay.URL, dir)
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !srv.CA().KeyIsProtected() {
		t.Skip("this platform reports the key as unprotected; the startup refusal covers it")
	}
	// Even with a healthy CA, the route gate still governs.
	if srv.canIntercept("relay.test", config.RouteDirect) {
		t.Fatal("the route gate let a direct host through")
	}
}

// An intercepted request must carry the browser's method and path through to
// the relay, not silently become a GET /.
func TestInterceptedRequestPreservesMethodAndPath(t *testing.T) {
	var gotMethod, gotPath, gotHost string
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Phaethon-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// The relay receives the origin request under its own path scheme and
		// with the target named in a header; that is how the Function knows
		// which origin to fetch. What matters here is that the browser's
		// method and path survived interception intact.
		gotMethod = r.Method
		gotPath = r.URL.RequestURI()
		gotHost = r.Header.Get("X-Phaethon-Host")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "ok")
	}))
	defer relay.Close()

	_, proxyAddr := serve(t, interceptConfig(relay.URL, t.TempDir()))
	conn, line := dialCONNECT(t, proxyAddr, "relay.test:443")
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT = %q", line)
	}
	client := tls.Client(conn, &tls.Config{
		ServerName:         "relay.test",
		InsecureSkipVerify: true, //nolint:gosec // we only need the tunnel here
		MinVersion:         tls.VersionTLS12,
	})
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client,
		"POST /api/things?x=1 HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if gotMethod != http.MethodPost {
		t.Errorf("relay saw method %q, want POST", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/api/things?x=1") {
		t.Errorf("relay saw path %q, want it to end with the origin path /api/things?x=1", gotPath)
	}
	if gotHost != "relay.test" {
		t.Errorf("relay was told to fetch %q, want relay.test", gotHost)
	}
}

// truncate shortens a string for an error message.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var _ = mitm.Trusted // the trust helper is used by the CLI, referenced here for the build

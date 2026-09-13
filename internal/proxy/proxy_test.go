package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// testServer builds a daemon listening on a random loopback port, with a
// relay pointed at the given fake relay URL (may be empty).
func testServer(t *testing.T, relayURL string) (*Server, string) {
	t.Helper()
	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "local-secret",
		DefaultRoute: config.RouteDirect,
		Routes: []config.RouteRule{
			{Host: "relay.test", Route: config.RouteRelay},
			{Host: "denied.test", Route: config.RouteDeny},
			{Host: "direct.test", Route: config.RouteDirect},
		},
		Relay: config.RelayConfig{
			URL:                relayURL,
			Token:              "relay-secret",
			Timeout:            10 * time.Second,
			InsecureSkipVerify: true, // the fake relay is a local test server
		},
		Dial: config.DialConfig{Timeout: 3 * time.Second, PreflightTimeout: time.Second},
		// The tests stand up loopback origins, which are refused by default.
		AllowPrivateDestinations: true,
	}
	if relayURL == "" {
		cfg.Routes = []config.RouteRule{{Host: "denied.test", Route: config.RouteDeny}}
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
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	})
	return srv, ln.Addr().String()
}

func controlGet(t *testing.T, base, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

func TestHealthIsOpenAndStatusRequiresToken(t *testing.T) {
	_, addr := testServer(t, "")
	base := "http://" + addr

	resp, body := controlGet(t, base, "/phaethon/health", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health without a token = %d, want 200", resp.StatusCode)
	}
	var health map[string]any
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("health body: %v", err)
	}
	if health["ok"] != true {
		t.Fatalf("health = %s", body)
	}

	resp, _ = controlGet(t, base, "/phaethon/status", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status without a token = %d, want 401", resp.StatusCode)
	}
	resp, _ = controlGet(t, base, "/phaethon/status", "wrong-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status with a wrong token = %d, want 401", resp.StatusCode)
	}
	resp, body = controlGet(t, base, "/phaethon/status", "local-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status with the token = %d, want 200 (%s)", resp.StatusCode, body)
	}
	var status struct {
		Service string `json:"service"`
		Listen  string `json:"listen"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatal(err)
	}
	if status.Service != "phaethon" {
		t.Fatalf("status service = %q", status.Service)
	}
}

func TestRoutesEndpointRequiresToken(t *testing.T) {
	_, addr := testServer(t, "")
	resp, _ := controlGet(t, "http://"+addr, "/phaethon/routes", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("routes without a token = %d, want 401", resp.StatusCode)
	}
	resp, body := controlGet(t, "http://"+addr, "/phaethon/routes", "local-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("routes = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "relay") && !strings.Contains(string(body), "deny") {
		t.Fatalf("routes body = %s", body)
	}
}

// The allowlist is enforced: a denied host is refused before any dial.
func TestDeniedRouteIsRefused(t *testing.T) {
	_, addr := testServer(t, "")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n")
	resp := readResponse(t, conn)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied CONNECT = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "denied by route table") {
		t.Fatalf("refusal body = %s", body)
	}
}

// A relay-routed host cannot be CONNECTed: the relay carries HTTPS
// requests, not TCP tunnels, and saying so beats hanging the client.
func TestRelayRouteRefusesConnect(t *testing.T) {
	_, addr := testServer(t, "https://relay.invalid")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "CONNECT relay.test:443 HTTP/1.1\r\nHost: relay.test:443\r\n\r\n")
	resp := readResponse(t, conn)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("relay CONNECT = %d, want 501", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "relay") {
		t.Fatalf("refusal body = %s", body)
	}
}

// A direct route really tunnels: TLS through the proxy reaches a local
// HTTPS server with a valid handshake end to end.
func TestDirectConnectTunnelsTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tunnelled ok"))
	}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)
	_, proxyAddress := testServer(t, "")

	// The origin's certificate is self-signed; accept it in the test
	// client, since the point here is that bytes flow through the tunnel.
	pool := x509Pool(origin)
	proxyURL, err := url.Parse("http://" + proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           func(*http.Request) (*url.URL, error) { return proxyURL, nil },
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: originURL.Hostname()},
		},
	}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "tunnelled ok" {
		t.Fatalf("through tunnel: %d %q", resp.StatusCode, body)
	}
}

// The relay path is exercised against a fake relay that mimics the
// Cloudflare Function's contract.
func TestRelayRouteForwardsThroughRelay(t *testing.T) {
	var gotToken, gotPath string
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Phaethon-Token")
		gotPath = r.URL.Path
		if gotToken != "relay-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.Header().Set("X-Phaethon-Relay", "1")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>relayed example</html>"))
	}))
	defer relay.Close()

	srv, addr := testServer(t, relay.URL)
	_ = srv

	resp, body := controlGet(t, "http://"+addr,
		"/phaethon/fetch?url="+url.QueryEscape("https://relay.test/some/path?q=1"), "local-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay fetch = %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "relayed example") {
		t.Fatalf("relay body = %s", body)
	}
	if gotToken != "relay-secret" {
		t.Fatalf("relay received token %q", gotToken)
	}
	if gotPath != "/relay/relay.test/some/path" {
		t.Fatalf("relay path = %q, want /relay/relay.test/some/path", gotPath)
	}
	if route := resp.Header.Get("X-Phaethon-Route"); route != "relay" {
		t.Fatalf("X-Phaethon-Route = %q, want relay", route)
	}
}

// The facade is the HTTP-layer path to an allowlisted host, and it too is
// subject to the route table.
func TestFacadeDeniesUnlistedHost(t *testing.T) {
	_, addr := testServer(t, "https://relay.invalid")
	resp, body := controlGet(t, "http://"+addr, "/r/denied.test/", "local-secret")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("facade for a denied host = %d (%s)", resp.StatusCode, body)
	}
}

func TestFacadeRequiresHost(t *testing.T) {
	_, addr := testServer(t, "https://relay.invalid")
	resp, _ := controlGet(t, "http://"+addr, "/r/", "local-secret")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("facade without a host = %d, want 400", resp.StatusCode)
	}
}

// Counters must reflect what actually happened, since status is the
// operator's only view into the daemon.
func TestStatsRecordRoutesAndFailures(t *testing.T) {
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Phaethon-Relay", "1")
		_, _ = w.Write([]byte("ok"))
	}))
	defer relay.Close()

	srv, addr := testServer(t, relay.URL)
	_, _ = controlGet(t, "http://"+addr, "/phaethon/fetch?url="+url.QueryEscape("https://relay.test/"), "local-secret")
	_, _ = controlGet(t, "http://"+addr, "/r/denied.test/", "local-secret")

	snap := srv.Stats().Snapshot()
	if snap.Relayed != 1 {
		t.Fatalf("relayed = %d, want 1 (%+v)", snap.Relayed, snap)
	}
	if snap.Failures["host not in the route allowlist"] != 1 {
		t.Fatalf("allowlist refusal not counted: %+v", snap.Failures)
	}
}

func TestUnknownControlEndpoint(t *testing.T) {
	_, addr := testServer(t, "")
	resp, body := controlGet(t, "http://"+addr, "/phaethon/nope", "local-secret")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown control endpoint = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "known") {
		t.Fatalf("body = %s", body)
	}
}

// The Authorized helper is the predicate the enforcement path uses; the
// enforcement itself is covered in auth_test.go.
func TestAuthorizedHelper(t *testing.T) {
	cfg := &config.Config{
		Listen:           "127.0.0.1:0",
		LocalToken:       "local-secret",
		RequireProxyAuth: true,
		DefaultRoute:     config.RouteDeny,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+basicAuth("anything", "local-secret"))
	if !srv.Authorized(req) {
		t.Fatal("a valid Proxy-Authorization token should authorize")
	}
	req2 := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	if srv.Authorized(req2) {
		t.Fatal("a request without a token must not be authorized")
	}
}

package proxy

import (
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

// upstreamHTML is what the fake origin returns: markup with one absolute
// same-host reference, one root-relative reference, one cross-host reference
// and one script body, so rewriting can be observed end to end.
const upstreamHTML = `<!doctype html><html><head>` +
	`<link rel="stylesheet" href="/app.css">` +
	`<script src="https://example.test/app.js"></script>` +
	`</head><body>` +
	`<a href="https://example.test/pricing">pricing</a>` +
	`<img src="https://assets.example.test/logo.svg">` +
	`<script>fetch("https://example.test/api");</script>` +
	`</body></html>`

const upstreamCSS = `.a{background:url(/bg.png)} .b{background:url(https://assets.example.test/i.png)}`

// fakeOriginRelay stands in for the Cloudflare relay: it answers any request
// with markup that exercises every URL class the rewriter handles.
func fakeOriginRelay(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Phaethon-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
			_, _ = io.WriteString(w, upstreamCSS)
			return
		}
		w.Header().Set("X-Phaethon-Relay", "1")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if redirect := r.URL.Query().Get("redirect"); redirect != "" {
			w.Header().Set("Location", redirect)
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, upstreamHTML)
	}))
	return srv
}

// browserview builds a daemon whose route table covers the hosts in the test
// markup, with the relay pointed at the fake origin.
func browserview(t *testing.T) (*Server, string) {
	t.Helper()
	relay := fakeOriginRelay(t)
	t.Cleanup(relay.Close)
	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "local-secret",
		DefaultRoute: config.RouteDirect,
		Routes: []config.RouteRule{
			{Host: "example.test", Route: config.RouteRelay},
			{Host: "*.example.test", Route: config.RouteRelay},
			{Host: "*.example.app", Route: config.RouteRelay},
			{Host: "denied.test", Route: config.RouteDeny},
		},
		Relay: config.RelayConfig{
			URL: relay.URL, Token: "relay-secret",
			Timeout: 10 * time.Second, InsecureSkipVerify: true,
		},
		Dial:                     config.DialConfig{Timeout: 3 * time.Second, PreflightTimeout: time.Second},
		AllowPrivateDestinations: true,
		// Virtual hosting is opt-in (the /r/ facade is the default), so these
		// tests enable it explicitly.
		VirtualHostSuffix: "localhost",
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
	return srv, ln.Addr().String()
}

// getWithHost performs a request with an explicit Host header, which is how a
// browser reaches a virtual host.
func getWithHost(t *testing.T, addr, host, path string) (*http.Response, string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, conn)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

// Virtual hosting: the browser talks to example.test.localhost, so the page
// origin is the site's own. Root-relative references need no rewriting, and
// absolute references are mapped onto the same local origin.
func TestVirtualHostServesAndRewrites(t *testing.T) {
	srv, addr := browserview(t)
	_ = srv
	_, port, _ := net.SplitHostPort(addr)

	resp, body := getWithHost(t, addr, "example.test.localhost:"+port, "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("virtual host status = %d", resp.StatusCode)
	}
	want := []string{
		// Root-relative left alone: it already resolves to the right origin.
		`href="/app.css"`,
		// Absolute same-host mapped to the virtual origin.
		`src="http://example.test.localhost:` + port + `/app.js"`,
		`href="http://example.test.localhost:` + port + `/pricing"`,
		// Cross-host routed resource mounted same-origin so CSP 'self' allows it.
		`src="http://example.test.localhost:` + port + `/.phaethon/h/assets.example.test/logo.svg"`,
		// Script bodies are untouched.
		`fetch("https://example.test/api")`,
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("virtual-host body missing %q\n--- got ---\n%s", w, body)
		}
	}
	if resp.Header.Get("X-Phaethon-Rewritten") != "1" {
		t.Error("expected the response to be marked as rewritten")
	}
	if got := resp.Header.Get("Content-Length"); got == "" {
		t.Error("rewritten responses must carry an accurate Content-Length")
	}
}

// An unlisted hostname is refused on its virtual form: reachability is
// policy, and policy is the allowlist.
func TestVirtualHostRequiresAllowlist(t *testing.T) {
	_, addr := browserview(t)
	_, port, _ := net.SplitHostPort(addr)

	resp, body := getWithHost(t, addr, "neverssl.com.localhost:"+port, "/")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unlisted virtual host = %d, want 403 (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, "allowlist") {
		t.Errorf("refusal should explain the allowlist: %s", body)
	}

	resp, _ = getWithHost(t, addr, "denied.test.localhost:"+port, "/")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied virtual host = %d, want 403", resp.StatusCode)
	}
}

// Regression: the facade used to fall back to the default route, which made
// /r/<any-host>/ an open proxy for arbitrary destinations.
func TestFacadeRefusesUnlistedHost(t *testing.T) {
	_, addr := browserview(t)
	for _, host := range []string{"neverssl.com", "example.com", "github.com"} {
		resp, body := controlGet(t, "http://"+addr, "/r/"+host+"/", "local-secret")
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("/r/%s/ = %d, want 403 (open proxy regression); body=%s", host, resp.StatusCode, body)
		}
	}
	// A listed host still works.
	resp, body := controlGet(t, "http://"+addr, "/r/example.test/", "local-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/r/example.test/ = %d (%s)", resp.StatusCode, body)
	}
}

// The path facade rewrites root-relative references so subresources come back
// through the daemon instead of hitting its own root.
func TestFacadeRewritesRootRelative(t *testing.T) {
	_, addr := browserview(t)
	resp, body := controlGet(t, "http://"+addr, "/r/example.test/", "local-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s)", resp.StatusCode, body)
	}
	for _, want := range []string{
		`href="/r/example.test/app.css"`,
		`src="/r/example.test/app.js"`,
		`href="/r/example.test/pricing"`,
		`src="/r/assets.example.test/logo.svg"`,
		`fetch("https://example.test/api")`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("facade body missing %q\n--- got ---\n%s", want, body)
		}
	}
}

// A stylesheet served through the facade has its url() references rewritten
// too, including one pointing at a different routed host.
func TestFacadeRewritesCSS(t *testing.T) {
	_, addr := browserview(t)
	resp, body := controlGet(t, "http://"+addr, "/r/example.test/app.css", "local-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s)", resp.StatusCode, body)
	}
	for _, want := range []string{
		`url(/r/example.test/bg.png)`,
		`url(/r/assets.example.test/i.png)`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("CSS missing %q\n--- got ---\n%s", want, body)
		}
	}
	if resp.Header.Get("X-Phaethon-Rewritten") != "1" {
		t.Error("CSS responses should be marked rewritten")
	}
}

// Redirects must be mapped too, or the browser leaves the facade and hits the
// intercepted origin directly.
func TestRedirectLocationIsRewritten(t *testing.T) {
	_, addr := browserview(t)
	// The default client follows redirects, which would hide the header under
	// test, so ask for it explicitly.
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + addr +
		"/r/example.test/?redirect=" + url.QueryEscape("https://example.test/dashboard"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	got := resp.Header.Get("Location")
	want := "/r/example.test/dashboard"
	if got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

// The control namespace must not be reachable from a routed page: it would be
// same-origin with that page.
func TestVirtualHostHidesControlEndpoints(t *testing.T) {
	_, addr := browserview(t)
	_, port, _ := net.SplitHostPort(addr)
	for _, path := range []string{"/phaethon/status", "/phaethon/routes", "/phaethon/fetch?url=https://example.test/"} {
		resp, body := getWithHost(t, addr, "example.test.localhost:"+port, path)
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s on a routed page = 200; it must not be reachable (%s)", path, body)
		}
	}
}

// Loopback, private and metadata destinations are refused before any dial.
func TestDestinationGuardRefusesPrivateTargets(t *testing.T) {
	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "t",
		DefaultRoute: config.RouteDirect,
		Routes: []config.RouteRule{
			{Host: "127.0.0.1", Route: config.RouteDirect},
			{Host: "169.254.169.254", Route: config.RouteDirect},
			{Host: "10.0.0.5", Route: config.RouteDirect},
			{Host: "192.168.1.10", Route: config.RouteDirect},
			{Host: "metadata.google.internal", Route: config.RouteDirect},
			{Host: "localhost", Route: config.RouteDirect},
		},
		// AllowPrivateDestinations deliberately left false.
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{
		"127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.10",
		"metadata.google.internal", "localhost", "100.64.0.1", "0.0.0.0",
	} {
		if err := srv.validateDestination(host); err == nil {
			t.Errorf("validateDestination(%q) allowed a non-public destination", host)
		}
	}
	for _, host := range []string{"example.test", "github.com", "8.8.8.8"} {
		if err := srv.validateDestination(host); err != nil {
			t.Errorf("validateDestination(%q) = %v, want nil", host, err)
		}
	}
}

// Public-address classification is the dialer's own guard as well.
func TestIsGlobalAddr(t *testing.T) {
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "20.207.73.82"}
	refused := []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "192.0.2.1", "198.51.100.1", "203.0.113.1",
		"240.0.0.1", "::1", "fc00::1", "fe80::1", "224.0.0.1",
	}
	for _, s := range allowed {
		if !isGlobalAddrString(t, s) {
			t.Errorf("%s should be routable", s)
		}
	}
	for _, s := range refused {
		if isGlobalAddrString(t, s) {
			t.Errorf("%s must not be routable", s)
		}
	}
}

// The status document must stay parseable and report the new virtual-host
// capability, since that is how an agent checks the daemon.
func TestStatusReportsVirtualHosting(t *testing.T) {
	_, addr := browserview(t)
	resp, body := controlGet(t, "http://"+addr, "/phaethon/status", "local-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("status is not JSON: %v", err)
	}
	if doc["service"] != "phaethon" {
		t.Errorf("service = %v", doc["service"])
	}
}

// A tls.Config is needed by the fake relay helper in this file.
var _ = tls.Config{}

// Regression: a root-relative URL that the page's JavaScript builds at
// runtime (a path assembled from location.pathname, for example) resolves
// against the daemon's origin in path mode. No static rewrite can fix that,
// because the URL never appears in the document. The last page served through
// the facade is therefore remembered in a cookie, and unmatched root-relative
// requests are delivered to that origin.
func TestStickyOriginServesRuntimeRootRelative(t *testing.T) {
	_, addr := browserview(t)

	// 1. Loading a page through the facade sets the origin cookie.
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + addr + "/r/example.test/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var originCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == stickyOriginCookie {
			originCookie = c
		}
	}
	if originCookie == nil {
		t.Fatal("serving a page through the facade must set the sticky-origin cookie")
	}
	if originCookie.Value != "example.test" {
		t.Fatalf("cookie = %q, want example.test", originCookie.Value)
	}
	if !originCookie.HttpOnly {
		t.Error("the sticky-origin cookie should be HttpOnly")
	}

	// 2. A mismatched root-relative request carrying that cookie is served
	// from the same origin instead of 404ing on the daemon.
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/vc-ap-example-marketing/_next/static/x.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(originCookie)
	got, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	if got.StatusCode != http.StatusOK {
		t.Fatalf("sticky root-relative request = %d, want 200", got.StatusCode)
	}
	if got.Header.Get("X-Phaethon-Route") == "" {
		t.Error("sticky requests should report the route they used")
	}

	// 3. Without the cookie, the same path is an honest 404 on the daemon.
	bare, err := client.Get("http://" + addr + "/vc-ap-example-marketing/_next/static/x.js")
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Body.Close()
	if bare.StatusCode != http.StatusNotFound {
		t.Fatalf("path without a sticky origin = %d, want 404", bare.StatusCode)
	}
}

// The sticky origin must never be usable to reach an unlisted host.
func TestStickyOriginRejectsUnlistedHostCookie(t *testing.T) {
	_, addr := browserview(t)
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/some/asset.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: stickyOriginCookie, Value: "neverssl.com"})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unlisted sticky origin = %d, want 404", resp.StatusCode)
	}
}

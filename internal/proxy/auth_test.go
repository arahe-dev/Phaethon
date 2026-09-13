package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// startAuthDaemon starts a daemon with require_proxy_auth enabled, so the
// token must be enforced on proxy requests.
func startAuthDaemon(t *testing.T) (addr, token string) {
	t.Helper()
	cfg := &config.Config{
		Listen:                   "127.0.0.1:0",
		LocalToken:               "proxy-secret",
		RequireProxyAuth:         true,
		DefaultRoute:             config.RouteDirect,
		Dial:                     config.DialConfig{Timeout: 2 * time.Second, PreflightTimeout: time.Second},
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
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	})
	return ln.Addr().String(), "proxy-secret"
}

// sendRaw writes a raw request and reads the response.
func sendRaw(t *testing.T, addr, request string) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	return readResponse(t, conn)
}

// Regression: require_proxy_auth must actually gate the proxy. Before this
// was enforced the option was documented but had no effect, so on a shared
// machine any local user could route traffic through the daemon (and its
// relay credentials).
func TestProxyAuthRequiredOnConnect(t *testing.T) {
	addr, token := startAuthDaemon(t)

	resp := sendRaw(t, addr, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT without a token = %d, want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Fatal("407 must advertise Proxy-Authenticate")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy authentication required") {
		t.Fatalf("body = %s", body)
	}

	// With a valid token the request is no longer refused for auth. The
	// assertion is about authorisation, not whether the origin answers.
	resp2 := sendRaw(t, addr, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n"+
		"Proxy-Authorization: Bearer "+token+"\r\n\r\n")
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusProxyAuthRequired {
		t.Fatal("a valid token was still rejected with 407")
	}
}

func TestProxyAuthRejectsWrongToken(t *testing.T) {
	addr, _ := startAuthDaemon(t)
	// Basic dXNlcjp3cm9uZw== is "user:wrong".
	resp := sendRaw(t, addr, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n"+
		"Proxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n\r\n")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT with a wrong token = %d, want 407", resp.StatusCode)
	}
}

// Basic auth carries the token as the password, which is what curl -x
// user:pass@host sends.
func TestProxyAuthAcceptsBasicPassword(t *testing.T) {
	addr, token := startAuthDaemon(t)
	resp := sendRaw(t, addr, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n"+
		"Proxy-Authorization: Basic "+basicAuth("phaethon", token)+"\r\n\r\n")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired {
		t.Fatal("Basic auth carrying the token as the password must be accepted")
	}
}

func TestProxyAuthRequiredOnFacade(t *testing.T) {
	addr, token := startAuthDaemon(t)
	base := "http://" + addr

	resp, _ := controlGet(t, base, "/r/github.com/", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("facade without a token = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("401 must advertise WWW-Authenticate")
	}

	resp2, _ := controlGet(t, base, "/r/github.com/", token)
	if resp2.StatusCode == http.StatusUnauthorized || resp2.StatusCode == http.StatusProxyAuthRequired {
		t.Fatalf("facade with a valid token = %d, want a routed response", resp2.StatusCode)
	}
}

func TestProxyAuthRequiredOnAbsoluteURI(t *testing.T) {
	addr, token := startAuthDaemon(t)

	resp := sendRaw(t, addr, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("absolute-URI GET without a token = %d, want 407", resp.StatusCode)
	}

	resp2 := sendRaw(t, addr, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"+
		"Proxy-Authorization: Bearer "+token+"\r\n\r\n")
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusProxyAuthRequired {
		t.Fatal("absolute-URI GET with a valid token must not be refused")
	}
}

// Health must stay reachable without a token even when proxy auth is on,
// because monitors poll it.
func TestHealthOpenDespiteProxyAuth(t *testing.T) {
	addr, _ := startAuthDaemon(t)
	resp, _ := controlGet(t, "http://"+addr, "/phaethon/health", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d, want 200", resp.StatusCode)
	}
}

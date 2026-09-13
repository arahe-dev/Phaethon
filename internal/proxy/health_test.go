package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// Relay health must not mangle the endpoint URL, since a wrong host:port would
// report a healthy relay as down (or worse, a down one as healthy).
func TestHostPortOf(t *testing.T) {
	cases := map[string]string{
		"https://relay.example":      "relay.example:443",
		"https://example.com:8443/x": "example.com:8443",
		"http://plain.example.com":   "plain.example.com:80",
	}
	for in, want := range cases {
		if got := hostPortOf(in); got != want {
			t.Errorf("hostPortOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// A reachable relay is reported healthy with a latency, and the answer is
// cached: the endpoint must not be re-probed on every status request.
func TestRelayHealthIsProbedAndCached(t *testing.T) {
	// The relay URL must be https by configuration; the health probe itself is
	// a TCP dial, so a TLS test server is enough.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "t",
		DefaultRoute: config.RouteDirect,
		Routes:       []config.RouteRule{{Host: "r.test", Route: config.RouteRelay}},
		Relay: config.RelayConfig{
			URL: upstream.URL, Token: "tok",
			Timeout: 5 * time.Second, InsecureSkipVerify: true,
		},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := srv.relayStatus()
	if first == nil {
		t.Fatal("no relay health was reported although a relay is configured")
	}
	if !first.OK {
		t.Fatalf("a listening relay was reported unhealthy: %+v", first)
	}
	if first.Latency == "" {
		t.Error("relay health should include a latency")
	}
	if first.Checked == "" {
		t.Error("relay health should record when it was checked")
	}
	// Repeated status reads must reuse the cached answer rather than probing
	// again: the check timestamp must not move.
	for i := 0; i < 5; i++ {
		again := srv.relayStatus()
		if again.Checked != first.Checked {
			t.Fatalf("relay health was re-probed on request %d (%s -> %s); it must be cached",
				i, first.Checked, again.Checked)
		}
	}
}

// An unreachable relay must be reported as unhealthy with a reason, not
// silently as fine.
func TestRelayHealthReportsFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "t",
		DefaultRoute: config.RouteDirect,
		Routes:       []config.RouteRule{{Host: "r.test", Route: config.RouteRelay}},
		Relay:        config.RelayConfig{URL: "https://" + addr, Token: "tok", Timeout: 2 * time.Second},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.relayStatus()
	if h == nil {
		t.Fatal("no relay health")
	}
	if h.OK {
		t.Fatalf("a closed relay endpoint was reported healthy: %+v", h)
	}
	if !strings.Contains(h.Detail, "refused") && h.Detail == "" {
		t.Errorf("relay failure should carry a reason, got %q", h.Detail)
	}
}

// With no relay configured there is nothing to report, and status must not
// pretend otherwise.
func TestRelayHealthAbsentWithoutRelay(t *testing.T) {
	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "t",
		DefaultRoute: config.RouteDirect,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if h := srv.relayStatus(); h != nil {
		t.Errorf("relay health = %+v, want nil when no relay is configured", h)
	}
}

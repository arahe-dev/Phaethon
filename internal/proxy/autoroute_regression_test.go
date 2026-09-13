package proxy

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/rewrite"
	"github.com/arahe-dev/phaethon/internal/transport"
)

// Regression, twice over: the served page's URL rewriting and the relay's local
// allowlist mirror were both derived from the *static* route table. Once
// automatic routing made example hosts learnable instead of pinned, both went
// silently wrong:
//
//   - the rewriter mapped nothing, so every root-relative reference pointed at
//     the daemon origin and the page rendered unstyled, while
//     X-Phaethon-Rewritten was still set (a false success);
//   - the relay client refused the host locally, so the facade answered 502
//     for a host the daemon had just decided to relay.
//
// Both now use the same policy predicate as reachability. These tests fail if
// either drifts back to depending on static rules alone.
func autoroutedConfig(relayURL string) *config.Config {
	return &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "local-secret",
		DefaultRoute: config.RouteDirect,
		// Deliberately no rule for the hosts under test: they are reachable
		// and relayable only through relay eligibility.
		Routes: []config.RouteRule{{Host: "pinned.test", Route: config.RouteDirect}},
		Relay: config.RelayConfig{
			URL: relayURL, Token: "relay-secret",
			Timeout: 10 * time.Second, InsecureSkipVerify: true,
		},
		Dial:                     config.DialConfig{Timeout: 3 * time.Second, PreflightTimeout: time.Second},
		AllowPrivateDestinations: true,
		AutoRoute: config.AutoRouteConfig{
			Enabled:       true,
			RelayEligible: []string{"*.example.test", "thing.auto.test"},
		},
	}
}

func TestAutoRoutedHostIsRewrittenAndRelayable(t *testing.T) {
	relay := fakeOriginRelay(t)
	t.Cleanup(relay.Close)

	srv, err := New(autoroutedConfig(relay.URL))
	if err != nil {
		t.Fatal(err)
	}

	// 1. The rewriter must map an auto-routed host.
	if !srv.reachable("app.example.test") {
		t.Fatal("reachability refused an eligible host")
	}
	mapped := srv.rw.MapURL(rewrite.ModePath, "app.example.test", "/_next/static/x.css")
	if mapped != "/r/app.example.test/_next/static/x.css" {
		t.Fatalf("MapURL = %q, want the facade prefix (the rewriter is not honouring eligibility)", mapped)
	}
	// 2. And it must still refuse a host policy does not cover.
	if srv.rw.Allowed("evil.test") {
		t.Error("the rewriter allowed an unlisted host")
	}
	// 3. The relay client's local mirror must accept it.
	if !containsPattern(relayAllowlist(autoroutedConfig(relay.URL)), "*.example.test") {
		t.Fatalf("relay mirror missing the eligible pattern: %v", relayAllowlist(autoroutedConfig(relay.URL)))
	}
}

// The body served for an auto-routed host must actually be rewritten.
func TestFacadeRewritesAutoRoutedHostBody(t *testing.T) {
	relay := fakeOriginRelay(t)
	t.Cleanup(relay.Close)

	srv, err := New(autoroutedConfig(relay.URL))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`<html><head><link rel="stylesheet" href="/app.css">` +
		`<script src="https://app.example.test/x.js"></script></head></html>`)
	out := string(srv.rw.HTML(rewrite.ModePath, "app.example.test", body))

	for _, want := range []string{
		`href="/r/app.example.test/app.css"`,
		`src="/r/app.example.test/x.js"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("auto-routed body missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// A host the daemon may relay must not be refused locally by the relay
// client's allowlist mirror. This is the 502 regression, tested through the
// transport rather than the handler.
func TestRelayClientAcceptsAutoRoutedHost(t *testing.T) {
	relay := fakeOriginRelay(t)
	t.Cleanup(relay.Close)

	cfg := autoroutedConfig(relay.URL)
	rel, err := transport.NewRelay(cfg.Relay, cfg.MaxBodyBytes)
	if err != nil {
		t.Fatal(err)
	}
	rel.Allowlist = relayAllowlist(cfg)

	req, err := http.NewRequest(http.MethodGet, "https://thing.auto.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rel.Do(t.Context(), req)
	if err != nil {
		if strings.Contains(err.Error(), "not in the relay allowlist") {
			t.Fatalf("the relay client refused an auto-routed host: %v", err)
		}
		t.Fatalf("relay request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay status = %d, want 200", resp.StatusCode)
	}
}

// The predicates the two bugs depended on are asserted directly, so the tests
// above cannot pass vacuously: the static table really does not cover these
// hosts, and reachability really does come from eligibility.
func TestPolicyPredicatesAreNotStaticOnly(t *testing.T) {
	srv, err := New(autoroutedConfig(""))
	if err != nil {
		t.Fatal(err)
	}
	if srv.routes.Allowed("thing.auto.test") {
		t.Fatal("this test needs the static table NOT to cover the auto host")
	}
	if !srv.reachable("thing.auto.test") {
		t.Error("reachability must consult eligibility, not just static rules")
	}
	if srv.reachable("unlisted.test") {
		t.Error("an unlisted host must not be reachable")
	}
	// A host pinned to direct is reachable but not relayable.
	if !srv.reachable("pinned.test") {
		t.Error("a statically pinned host must be reachable")
	}
	if srv.router.Stats().Enabled && srv.router.Leases() == nil {
		t.Error("expected a lease cache")
	}

	// An explicit deny rule beats relay eligibility.
	denyCfg := autoroutedConfig("")
	denyCfg.Routes = []config.RouteRule{{Host: "thing.auto.test", Route: config.RouteDeny}}
	denySrv, err := New(denyCfg)
	if err != nil {
		t.Fatal(err)
	}
	if denySrv.reachable("thing.auto.test") {
		t.Error("an explicit deny rule must beat relay eligibility")
	}
}

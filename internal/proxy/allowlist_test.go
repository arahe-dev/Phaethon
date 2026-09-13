package proxy

import (
	"strings"
	"testing"

	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// Regression: the relay client's local allowlist mirror was derived only from
// static relay rules. With automatic routing a host can be relayed without
// appearing in the route table at all, so a mirror that ignored
// relay_eligible refused every learned relay locally — the facade answered
// 502 for a host the daemon had just decided to relay.
func TestRelayAllowlistIncludesEligiblePatterns(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteRule{
			{Host: "static-relay.test", Route: config.RouteRelay},
			{Host: "direct.test", Route: config.RouteDirect},
		},
		AutoRoute: config.AutoRouteConfig{
			Enabled:       true,
			RelayEligible: []string{"*.learned.test", "exact.learned.test", "*.learned.test"},
		},
	}
	got := relayAllowlist(cfg)

	want := map[string]bool{
		"static-relay.test":  true,
		"*.learned.test":     true,
		"exact.learned.test": true,
	}
	for pattern := range want {
		found := false
		for _, g := range got {
			if g == pattern {
				found = true
			}
		}
		if !found {
			t.Errorf("allowlist %v is missing %q", got, pattern)
		}
	}
	// A direct-only rule must not become relayable by being listed.
	for _, g := range got {
		if g == "direct.test" {
			t.Errorf("a direct-only rule leaked into the relay allowlist: %v", got)
		}
	}
	// Duplicates are collapsed.
	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	for pattern, n := range seen {
		if n > 1 {
			t.Errorf("%q appears %d times in the allowlist", pattern, n)
		}
	}
}

// A learned relay host must be served by the facade, because the daemon
// itself decided to relay it.
func TestFacadeServesLearnedRelayHost(t *testing.T) {
	relay := fakeOriginRelay(t)
	t.Cleanup(relay.Close)

	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		LocalToken:   "local-secret",
		DefaultRoute: config.RouteDirect,
		// No static rule for the host under test: it is reachable only
		// through relay eligibility.
		Routes: []config.RouteRule{{Host: "static.test", Route: config.RouteDirect}},
		Relay: config.RelayConfig{
			URL: relay.URL, Token: "relay-secret",
			Timeout: 10 * time.Second, InsecureSkipVerify: true,
		},
		Dial:                     config.DialConfig{Timeout: 3 * time.Second, PreflightTimeout: time.Second},
		AllowPrivateDestinations: true,
		AutoRoute: config.AutoRouteConfig{
			Enabled:       true,
			RelayEligible: []string{"*.example.test"},
		},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// The host is reachable (policy) and relayable (eligibility), so the
	// local allowlist mirror must accept it.
	if !srv.reachable("app.example.test") {
		t.Error("an eligible host should be reachable through the facade")
	}
	if !srv.routes.Allowed("app.example.test") {
		// Expected: it has no static rule. The facade must not depend on
		// this alone.
		t.Log("no static rule, as intended for this test")
	}
	hosts := relayAllowlist(cfg)
	if !containsPattern(hosts, "*.example.test") {
		t.Fatalf("eligible pattern missing from the relay allowlist: %v", hosts)
	}
	// And an ineligible host stays refused.
	if srv.reachable("evil.test") {
		t.Error("an unlisted, ineligible host must not be reachable")
	}
}

func containsPattern(patterns []string, want string) bool {
	for _, p := range patterns {
		if strings.EqualFold(p, want) {
			return true
		}
	}
	return false
}

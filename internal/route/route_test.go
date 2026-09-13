package route

import (
	"testing"

	"github.com/arahe-dev/phaethon/internal/config"
)

func testTable() *Table {
	return New(&config.Config{
		DefaultRoute: config.RouteDirect,
		Routes: []config.RouteRule{
			{Host: "example.test", Route: config.RouteRelay},
			{Host: "*.example.test", Route: config.RouteRelay},
			{Host: "*.example.app", Route: config.RouteRelay},
			{Host: "github.com", Route: config.RouteDirect},
			{Host: "*.githubusercontent.com", Route: config.RouteDirect},
			{Host: "blocked.example", Route: config.RouteDeny},
		},
	})
}

func TestDecideRoutes(t *testing.T) {
	table := testTable()
	cases := []struct {
		host  string
		route config.RouteKind
		rule  string
	}{
		{"example.test", config.RouteRelay, "example.test"},
		{"api.example.test", config.RouteRelay, "*.example.test"},
		{"example.test", config.RouteRelay, "example.test"},
		{"example.app", config.RouteRelay, "*.example.app"},
		{"swr.example.app", config.RouteRelay, "*.example.app"},
		{"github.com", config.RouteDirect, "github.com"},
		{"objects.githubusercontent.com", config.RouteDirect, "*.githubusercontent.com"},
		{"raw.githubusercontent.com", config.RouteDirect, "*.githubusercontent.com"},
		{"blocked.example", config.RouteDeny, "blocked.example"},
		// Unlisted hosts fall back to the configured default.
		{"example.com", config.RouteDirect, "(default)"},
		{"drive.google.com", config.RouteDirect, "(default)"},
	}
	for _, tc := range cases {
		got, matched := table.Decide(tc.host)
		if got.Route != tc.route {
			t.Errorf("Decide(%q).Route = %s, want %s", tc.host, got.Route, tc.route)
		}
		if got.Rule != tc.rule {
			t.Errorf("Decide(%q).Rule = %q, want %q", tc.host, got.Rule, tc.rule)
		}
		wantMatched := tc.rule != "(default)"
		if matched != wantMatched {
			t.Errorf("Decide(%q) matched = %v, want %v", tc.host, matched, wantMatched)
		}
	}
}

// A hostname must not be reachable through a lookalike rule: "notexample.test"
// is not "example.test", and "x.example.test.evil.test" is not under example.test.
func TestWildcardDoesNotOverreach(t *testing.T) {
	table := testTable()
	for _, host := range []string{"notexample.test", "example.test.evil.test", "xexample.app", "exampleapp"} {
		got, matched := table.Decide(host)
		if matched {
			t.Errorf("Decide(%q) matched rule %q; lookalike hostnames must not match", host, got.Rule)
		}
	}
}

func TestDefaultRouteCanDeny(t *testing.T) {
	table := New(&config.Config{DefaultRoute: config.RouteDeny})
	for _, host := range []string{"example.com", "anything.test"} {
		got, matched := table.Decide(host)
		if got.Route != config.RouteDeny || matched {
			t.Errorf("Decide(%q) = %s (matched=%v), want deny from default", host, got.Route, matched)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM":     "example.com",
		"example.com:443": "example.com",
		"example.com.":    "example.com",
		"  example.com  ": "example.com",
		"[::1]:8080":      "::1",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// A port in a rule must not silently change matching.
func TestRuleWithPortIsNormalized(t *testing.T) {
	table := New(&config.Config{
		DefaultRoute: config.RouteDirect,
		Routes:       []config.RouteRule{{Host: "api.example.test:443", Route: config.RouteRelay}},
	})
	if got := table.Route("api.example.test"); got != config.RouteRelay {
		t.Fatalf("route = %s, want relay", got)
	}
}

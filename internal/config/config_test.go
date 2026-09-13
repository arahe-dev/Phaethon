package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsFillEveryOperationalField(t *testing.T) {
	var c Config
	c.Defaults()
	if c.Listen == "" || c.DefaultRoute != RouteDirect {
		t.Fatalf("defaults = %+v", c)
	}
	if c.Dial.Timeout <= 0 || c.Dial.PreflightTimeout <= 0 || c.Dial.HealthTTL <= 0 || c.Dial.RankTTL <= 0 {
		t.Fatalf("dial defaults missing: %+v", c.Dial)
	}
	if c.MaxBodyBytes <= 0 {
		t.Fatalf("max body default missing: %d", c.MaxBodyBytes)
	}
}

// A relay route without a relay endpoint would silently break traffic, so
// it must be rejected at load time.
func TestValidateRequiresRelayDetails(t *testing.T) {
	c := &Config{
		DefaultRoute: RouteDirect,
		Routes:       []RouteRule{{Host: "example.test", Route: RouteRelay}},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error when a relay route has no relay.url")
	}

	c.Relay.URL = "https://relay.example"
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error when a relay route has no relay.token")
	}

	c.Relay.Token = "secret"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// The relay must be HTTPS: the whole point is an authenticated, encrypted
// egress path.
func TestValidateRejectsPlainHTTPRelay(t *testing.T) {
	c := &Config{
		DefaultRoute: RouteDirect,
		Routes:       []RouteRule{{Host: "example.test", Route: RouteRelay}},
		Relay:        RelayConfig{URL: "http://relay.example", Token: "secret"},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("plain HTTP relay URL must be rejected")
	}
}

func TestValidateRejectsBadRouteKind(t *testing.T) {
	c := &Config{
		DefaultRoute: RouteDirect,
		Routes:       []RouteRule{{Host: "x.test", Route: RouteKind("tunnel")}},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("unknown route kind must be rejected")
	}
}

func TestValidateRejectsEmptyHostRule(t *testing.T) {
	c := &Config{
		DefaultRoute: RouteDirect,
		Routes:       []RouteRule{{Host: "   ", Route: RouteDirect}},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("a rule without a host must be rejected")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "phaethon.json")
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	original := &Config{
		Listen:       "127.0.0.1:9000",
		LocalToken:   token,
		DefaultRoute: RouteDirect,
		Routes:       ExampleRoutes(),
		Relay:        RelayConfig{URL: "https://relay.example", Token: "relay-secret"},
		Dial:         DialConfig{Timeout: 7 * time.Second},
	}
	if err := Save(path, original); err != nil {
		t.Fatal(err)
	}
	// The file holds tokens, so it must be readable only by its owner.
	// "Readable only by the owner" is platform-specific: POSIX mode bits
	// on Unix, an explicit ACL on Windows.
	if !fileAccessIsRestricted(path) {
		t.Fatalf("configuration file %s is readable by users other than the owner", path)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LocalToken != token || loaded.Listen != "127.0.0.1:9000" {
		t.Fatalf("round trip lost values: %+v", loaded)
	}
	if loaded.Dial.Timeout != 7*time.Second {
		t.Fatalf("dial timeout = %v, want 7s", loaded.Dial.Timeout)
	}
	if len(loaded.Routes) != len(original.Routes) {
		t.Fatalf("routes = %d, want %d", len(loaded.Routes), len(original.Routes))
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
}

func TestNewTokenIsRandom(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) < 32 {
		t.Fatalf("tokens look weak or repeated: %q / %q", a, b)
	}
}

// ExampleRoutes must be generic placeholders, not a real network profile.
//
// The seed configuration is the first thing a new user reads, so it must not
// describe any particular network's observed behaviour: that is
// environment-specific, wrong for everyone else, and would go stale silently.
// This asserts the shape rather than specific hostnames, so it keeps holding
// whatever the placeholders are changed to.
func TestExampleRoutesAreGenericPlaceholders(t *testing.T) {
	routes := ExampleRoutes()
	if len(routes) == 0 {
		t.Fatal("the example routes must not be empty: a new user needs to see the shape")
	}
	for _, r := range routes {
		if !isPlaceholderHost(r.Host) {
			t.Errorf("example route %q looks like a real network profile rather than a placeholder", r.Host)
		}
	}

	// Relay eligibility is the operator's decision and cannot ship pre-filled
	// with anyone's real hosts, because that would relay traffic the operator
	// never chose to relay.
	for _, p := range ExampleRelayEligible() {
		if !isPlaceholderHost(p) {
			t.Errorf("example relay-eligible %q looks like a real host rather than a placeholder", p)
		}
	}
}

// isPlaceholderHost reports whether a host pattern is a documentation
// placeholder rather than a real destination.
//
// RFC 2606 reserves example.com, example.net, example.org and .example for
// exactly this, and .test is reserved by RFC 6761, so any of those is safe to
// ship. Anything else is a real host someone chose for a particular network.
func isPlaceholderHost(pattern string) bool {
	host := strings.ToLower(strings.TrimPrefix(pattern, "*."))
	for _, suffix := range []string{".test", ".example", ".invalid", ".localhost"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	for _, reserved := range []string{"example.com", "example.net", "example.org"} {
		if host == reserved || strings.HasSuffix(host, "."+reserved) ||
			strings.HasPrefix(host, reserved[:len("example")+1]) {
			return true
		}
	}
	return false
}

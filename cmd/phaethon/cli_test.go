package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/provision"
	"github.com/arahe-dev/phaethon/internal/speedtest"
	"github.com/arahe-dev/phaethon/internal/transport"
)

// leaseDaemon stands in for the daemon's read-only lease endpoints.
func leaseDaemon(t *testing.T, leases string) *config.Config {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/phaethon/leases":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"leases":%s,"counters":{}}`, leases)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &config.Config{
		Listen:     srv.Listener.Addr().String(),
		LocalToken: "test-token",
	}
}

// Blocked enumeration must follow recorded routing state: relay leases, plus
// direct leases whose reason is a path failure. It must not invent hosts, and
// it must skip wildcard scopes it cannot meaningfully measure.
func TestBlockedHostsEnumeration(t *testing.T) {
	cfg := leaseDaemon(t, `[
		{"scope":"example.test","route":"relay","state":"relay_verified","reason":"tls_specific_failure"},
		{"scope":"api.example.test","route":"relay","state":"relay_candidate","reason":"tls_specific_failure"},
		{"scope":"intercepted.test","route":"direct","state":"direct_verified","reason":"tls_specific_failure"},
		{"scope":"healthy.test","route":"direct","state":"direct_verified","reason":"path_healthy"},
		{"scope":"partial.test","route":"direct","state":"direct_verified","reason":"partial_address_failure"},
		{"scope":"*.wildcard.test","route":"relay","state":"relay_verified","reason":"tls_specific_failure"},
		{"scope":"example.test","route":"relay","state":"relay_verified","reason":"tls_specific_failure"}
	]`)

	got, err := blockedHosts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, h := range got {
		names[h.Host] = true
	}
	for _, want := range []string{"example.test", "api.example.test", "intercepted.test"} {
		if !names[want] {
			t.Errorf("%s should be enumerated as blocked (got %v)", want, names)
		}
	}
	for _, unwanted := range []string{"healthy.test", "partial.test", "*.wildcard.test"} {
		if names[unwanted] {
			t.Errorf("%s must not be enumerated as blocked", unwanted)
		}
	}
	// Duplicates must collapse, so a host is not measured twice.
	count := 0
	for _, h := range got {
		if h.Host == "example.test" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("example.test appears %d times, want 1", count)
	}
}

// An empty lease set is not an error: it means nothing is known to be broken.
func TestBlockedHostsEmpty(t *testing.T) {
	cfg := leaseDaemon(t, `[]`)
	got, err := blockedHosts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d blocked hosts, want none", len(got))
	}
}

// A --url target must be the requested host, or a host policy already allows.
func TestValidateBenchmarkURL(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteRule{
			{Host: "static.test", Route: config.RouteDirect},
			{Host: "blocked.test", Route: config.RouteDeny},
		},
		AutoRoute: config.AutoRouteConfig{RelayEligible: []string{"*.example.test"}},
	}
	// Accepted: the target itself.
	if err := validateBenchmarkURL("example.test", "https://example.test/big.bin", cfg); err != nil {
		t.Errorf("the target's own host should be allowed: %v", err)
	}
	// Accepted: an already-allowed host.
	if err := validateBenchmarkURL("static.test", "https://static.test/big.bin", cfg); err != nil {
		t.Errorf("a statically allowed host should be allowed: %v", err)
	}
	// Refused: unrelated, lookalike, denied, non-https, and private.
	for _, bad := range []struct{ target, url string }{
		{"example.test", "https://evil.test/big.bin"},
		{"example.test", "https://notexample.test/big.bin"},
		{"example.test", "https://example.test.evil.test/big.bin"},
		{"static.test", "https://blocked.test/big.bin"},
		{"example.test", "http://example.test/big.bin"},
		{"example.test", "https://127.0.0.1/big.bin"},
		{"example.test", "https://169.254.169.254/latest/meta-data/"},
		{"example.test", "https://localhost/big.bin"},
	} {
		if err := validateBenchmarkURL(bad.target, bad.url, cfg); err == nil {
			t.Errorf("validateBenchmarkURL(%q, %q) was allowed, want refused", bad.target, bad.url)
		}
	}
}

// --blocked must not exceed its concurrency bound, because a benchmark that
// saturates the link measures its own queueing.
func TestBlockedRespectsConcurrencyBound(t *testing.T) {
	var inFlight, peak atomic.Int64
	var mu sync.Mutex
	mu.Lock() // released below to keep the handler simple
	mu.Unlock()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The relay transport is the unit under test here; the handler simply
		// counts how many requests are open at once.
		cur := inFlight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		time.Sleep(120 * time.Millisecond)
		inFlight.Add(-1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rel, err := transport.NewRelay(config.RelayConfig{
		URL: srv.URL, Token: "tok", Timeout: 5 * time.Second, InsecureSkipVerify: true,
	}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	rel.Allowlist = []string{"a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test"}
	m := &speedtest.Measurer{Relay: rel, Version: "test"}

	hosts := []blockedEntry{}
	for _, h := range []string{"a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test"} {
		hosts = append(hosts, blockedEntry{Host: h, Route: "relay", Reason: "tls_specific_failure"})
	}

	// Run with a bound of 3 and confirm no more than 3 are ever open at once.
	done := make(chan struct{})
	go func() {
		runBlocked(&config.Config{LocalToken: "t"}, m, hosts, true, 1, 3)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("runBlocked did not finish")
	}
	if got := peak.Load(); got > 3 {
		t.Errorf("peak concurrency was %d, want at most 3", got)
	}
}

// The JSON report must carry the schema fields a consumer relies on.
func TestReportJSONSchema(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	rel, err := transport.NewRelay(config.RelayConfig{
		URL: srv.URL, Token: "tok", Timeout: 5 * time.Second, InsecureSkipVerify: true,
	}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	rel.Allowlist = []string{"schema.test"}
	m := &speedtest.Measurer{Relay: rel, Version: "1.2.3"}

	rep, err := m.Run(t.Context(), speedtest.Options{
		Host: "schema.test", URL: "https://schema.test/", Runs: 1, Relay: true,
	}, speedtest.RouteInfo{Route: "relay", Reason: "tls_specific_failure", Source: "lease"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"schema_version", "phaethon_version", "host", "url", "current_route",
		"lease_reason", "route_source", "runs", "timestamp", "direct", "relay",
	} {
		if _, ok := doc[key]; !ok {
			t.Errorf("the JSON report is missing %q", key)
		}
	}
	if doc["schema_version"].(float64) != float64(speedtest.SchemaVersion) {
		t.Errorf("schema_version = %v", doc["schema_version"])
	}
	if doc["phaethon_version"] != "1.2.3" {
		t.Errorf("phaethon_version = %v", doc["phaethon_version"])
	}
	if doc["current_route"] != "relay" || doc["lease_reason"] != "tls_specific_failure" {
		t.Errorf("routing context missing: %v / %v", doc["current_route"], doc["lease_reason"])
	}
}

// Flags after the hostname must still be parsed, which is how people type it.
func TestSpeedtestArgReordering(t *testing.T) {
	got := reorderLike([]string{"example.test", "--both", "--runs", "5"})
	flags, positionals := splitFlags(got, map[string]bool{"config": true, "url": true, "runs": true, "concurrency": true})
	if len(positionals) != 1 || positionals[0] != "example.test" {
		t.Fatalf("positionals = %v", positionals)
	}
	joined := fmt.Sprint(flags)
	for _, want := range []string{"--both", "--runs", "5"} {
		if !contains(joined, want) {
			t.Errorf("flags %v are missing %q", flags, want)
		}
	}
}

// contains is a tiny helper for the assertion above.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Every route to a relay must be discoverable from one failure message, because
// a provisioning failure with no stated alternatives is a dead end.
func TestCloudflareOptionsNameEveryRoute(t *testing.T) {
	got := cloudflareOptions()
	for _, want := range []string{
		"--cloudflare-client-id", // browser authorization
		"CLOUDFLARE_API_TOKEN",   // scripted installs
		"--dump-relay",           // deploy it yourself
		"--relay-url",            // adopt an existing relay
		"OAuth clients",          // where the client is registered
		"None (PKCE)",            // the token authentication method
		provision.RedirectURI(),  // the exact redirect URI to register
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the guidance should mention %q:\n%s", want, got)
		}
	}
}

// This source ships with an empty Cloudflare OAuth client identifier on
// purpose: an OAuth client belongs to the Cloudflare account that registered
// it, so baking one in would make every user of this source authenticate
// against that account. The flag, the environment and the build flags are how a
// real deployment supplies its own, and they must all work.
func TestOAuthClientIDResolution(t *testing.T) {
	t.Setenv("PHAETHON_CLOUDFLARE_CLIENT_ID", "")

	if got := oauthClientID("from-flag"); got != "from-flag" {
		t.Errorf("the flag must win, got %q", got)
	}
	t.Setenv("PHAETHON_CLOUDFLARE_CLIENT_ID", "from-env")
	if got := oauthClientID(""); got != "from-env" {
		t.Errorf("the environment must be used when no flag is given, got %q", got)
	}
	if got := oauthClientID("from-flag"); got != "from-flag" {
		t.Errorf("the flag must still win over the environment, got %q", got)
	}

	// With neither set, whatever the build supplied is used.
	t.Setenv("PHAETHON_CLOUDFLARE_CLIENT_ID", "")
	if got := oauthClientID(""); got != cloudflareClientID {
		t.Errorf("with no override the built-in value must be used, got %q", got)
	}
	if cloudflareClientID == "" {
		// The expected state for a source build. Setup must then explain what
		// to register rather than failing obscurely.
		if err := (&provision.OAuthProvider{}).Available(); err == nil {
			t.Error("with no client identifier the provider must report itself unavailable, with instructions")
		}
	}
}

// The shipped identifier must be empty or well-formed.
//
// Empty is the correct default here, so an empty value is not a failure. What
// must never ship is a malformed or placeholder-looking identifier, because
// that fails only at the consent screen where it is hardest to diagnose.
func TestShippedClientIDIsEmptyOrWellFormed(t *testing.T) {
	if cloudflareClientID == "" {
		return
	}
	// 32 hex characters, which is the shape of a Cloudflare OAuth client id.
	if len(cloudflareClientID) != 32 {
		t.Errorf("the built-in client id is %d characters, want 32", len(cloudflareClientID))
	}
	for _, r := range cloudflareClientID {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("the built-in client id contains %q, which is not hexadecimal", r)
		}
	}
	for _, avoid := range []string{"test", "example", "placeholder", "changeme", "dev"} {
		if strings.Contains(strings.ToLower(cloudflareClientID), avoid) {
			t.Errorf("the built-in client id looks like a placeholder (%q)", avoid)
		}
	}
}

// The new cloudflare flags must survive the positional reordering that lets
// people type the host before the flags.
func TestSetupFlagsAreReordered(t *testing.T) {
	got := reorderFlagsForSetup([]string{"--cloudflare-client-id", "cid", "--yes"})
	flags, positionals := splitFlags(got, map[string]bool{
		"config": true, "relay-url": true, "relay-token": true, "project": true,
		"cloudflare-client-id": true, "cloudflare-account": true, "dump-relay": true,
	})
	joined := fmt.Sprint(flags)
	if !strings.Contains(joined, "--cloudflare-client-id") || !strings.Contains(joined, "cid") {
		t.Errorf("flags = %v", flags)
	}
	if len(positionals) != 0 {
		t.Errorf("positionals = %v, want none", positionals)
	}
}

// A TCP allowlist entry must carry a port. Under TCP the entry is the whole
// policy, so a bare host would silently allow every port on it — the opposite
// of what an operator writing "ssh.example.com" means.
func TestTCPAllowRequiresAPort(t *testing.T) {
	if _, err := parseTCPAllow("ssh.example.com"); err == nil {
		t.Fatal("a host with no port must be refused, not treated as every port")
	}
	if _, err := parseTCPAllow("ssh.example.com:22"); err != nil {
		t.Fatalf("a valid host:port was refused: %v", err)
	}
	for _, bad := range []string{"host:", "host:0", "host:99999", "host:abc"} {
		if _, err := parseTCPAllow(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	// Wildcards carry a port like anything else.
	got, err := parseTCPAllow("*.example.com:22, DevOps.Example.COM:443 ")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*.example.com:22", "devops.example.com:443"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// Merging must not duplicate, and must not drop what a previous run persisted.
func TestMergeTCPAllowPreservesExisting(t *testing.T) {
	got := mergeTCPAllow([]string{"a.test:22"}, []string{"A.TEST:22", "b.test:443"})
	if len(got) != 2 {
		t.Fatalf("got %v, want a.test:22 and b.test:443", got)
	}
	if got[0] != "a.test:22" || got[1] != "b.test:443" {
		t.Errorf("got %v", got)
	}
	// Re-running with no new entries must not empty the stored policy.
	if again := mergeTCPAllow(got, nil); len(again) != 2 {
		t.Errorf("a redeploy with no flags must reproduce the stored policy, got %v", again)
	}
}

// The TCP allowlist must never fall back to the HTTP one: an HTTP entry names
// no port, so reusing it would allow every port on those hosts.
func TestTCPAndHTTPAllowlistsAreSeparate(t *testing.T) {
	src, err := os.ReadFile("../../internal/provision/cloudflare.go")
	if err != nil {
		t.Skip("source not reachable")
	}
	if !strings.Contains(string(src), "RELAY_TCP_ALLOWLIST") {
		t.Error("the upload must set RELAY_TCP_ALLOWLIST separately from RELAY_ALLOWLIST")
	}
	cfgSrc, err := os.ReadFile("../../internal/config/config.go")
	if err != nil {
		t.Skip("source not reachable")
	}
	if !strings.Contains(string(cfgSrc), "relay_tcp_allowlist") {
		t.Error("the TCP allowlist must be persisted under its own key so a redeploy reproduces it")
	}
}

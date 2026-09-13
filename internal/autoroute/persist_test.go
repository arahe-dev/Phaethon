package autoroute

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// Learned routes must survive a restart, so a daemon restart does not trigger
// a survey for every hostname it had already decided about.
func TestLeasePersistAndRestore(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{RelayTTL: 15 * time.Minute})
	h.oracle.decide = tlsBroken
	for _, host := range []string{"a.example.com", "b.example.com"} {
		if _, err := h.router.Decide(context.Background(), host); err != nil {
			t.Fatal(err)
		}
		h.router.NoteRelayOutcome(host, nil) // verified, so it is worth keeping
	}
	path := filepath.Join(t.TempDir(), "routes.json")
	saved, err := h.router.Persist(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved < 2 {
		t.Fatalf("persisted %d leases, want at least 2", saved)
	}

	// A fresh router, as after a restart, must learn nothing new for hosts it
	// already knows.
	fresh := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{RelayTTL: 15 * time.Minute})
	fresh.oracle.decide = tlsBroken
	loaded, skipped, err := fresh.router.Restore(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded < 2 {
		t.Fatalf("restored %d leases, want at least 2", loaded)
	}
	before := fresh.oracle.Calls()
	d, err := fresh.router.Decide(context.Background(), "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteRelay {
		t.Fatalf("restored route = %s, want relay", d.Route)
	}
	if d.Source != SourceLease {
		t.Errorf("source = %s, want lease (a restored lease, not a new survey)", d.Source)
	}
	if fresh.oracle.Calls() != before {
		t.Error("a restored lease should have avoided a survey")
	}
	_ = skipped
}

// An expired lease must not be resurrected: the network may well have changed
// while the daemon was down, which is exactly what leases exist to notice.
func TestExpiredLeasesAreNotRestored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	now := time.Now()
	stale := &persistedLeases{Version: persistVersion, SavedAt: now, Leases: []*RouteLease{{
		Scope:     Scope{Type: ScopeExact, Value: "old.example.com"},
		Route:     config.RouteRelay,
		State:     StateRelayVerified,
		Reason:    "tls_specific_failure",
		CreatedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}}}
	data, err := jsonMarshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewLeaseCache(CacheOptions{StaleGrace: 30 * time.Second})
	loaded, skipped, err := c.Restore(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != 0 {
		t.Fatalf("restored %d expired leases, want 0", loaded)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

// A corrupt state file must fail safe: discard it, never act on a guess.
func TestCorruptStateFailsSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewLeaseCache(CacheOptions{})
	if loaded, _, err := c.Restore(path); err == nil || loaded != 0 {
		t.Fatalf("a corrupt file produced loaded=%d err=%v, want 0 and an error", loaded, err)
	}
	if c.Count() != 0 {
		t.Fatalf("a corrupt file left %d leases in the cache", c.Count())
	}
}

// A public-suffix lease must never be restored, however it got written.
func TestPublicSuffixLeaseIsNotRestored(t *testing.T) {
	now := time.Now()
	state := &persistedLeases{Version: persistVersion, Leases: []*RouteLease{{
		Scope:     Scope{Type: ScopeRegistrable, Value: "co.uk"},
		Route:     config.RouteRelay,
		State:     StateRelayVerified,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}}}
	path := filepath.Join(t.TempDir(), "routes.json")
	data, err := jsonMarshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewLeaseCache(CacheOptions{})
	if loaded, _, err := c.Restore(path); err != nil || loaded != 0 {
		t.Fatalf("loaded=%d err=%v, want the public-suffix lease refused", loaded, err)
	}
}

// jsonMarshal keeps the test file free of an encoding/json import at the top.
func jsonMarshal(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

// Persistence must read the router's clock, not the wall clock.
//
// This is the regression test for a defect that hid for most of a day: Persist
// used time.Now() while the router used an injected clock, so a lease the
// router considered live looked expired to the code writing it out. It only
// showed up once real time passed the date the harness pins.
//
// The harness is therefore pinned far in the past. Any wall-clock read anywhere
// in the persistence path makes every lease look long expired, so this fails
// loudly and immediately rather than waiting for the calendar to reach a
// particular day.
func TestPersistUsesTheRouterClock(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{RelayTTL: 15 * time.Minute})
	// 2000 is unambiguously in the past, so a wall-clock read cannot pass.
	h.now = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	h.oracle.decide = tlsBroken

	if _, err := h.router.Decide(context.Background(), "a.example.com"); err != nil {
		t.Fatal(err)
	}
	h.router.NoteRelayOutcome("a.example.com", nil)

	saved, err := h.router.Persist(filepath.Join(t.TempDir(), "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if saved == 0 {
		t.Fatal("a lease the router considers live was not persisted; " +
			"persistence is reading a different clock from the router")
	}

	// A restore on the same clock must accept it too.
	fresh := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{RelayTTL: 15 * time.Minute})
	fresh.now = h.now
	path := filepath.Join(t.TempDir(), "routes.json")
	if _, err := h.router.Persist(path); err != nil {
		t.Fatal(err)
	}
	loaded, skipped, err := fresh.router.Restore(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == 0 || skipped != 0 {
		t.Fatalf("restored %d leases, skipped %d; want them all restored", loaded, skipped)
	}
}

package autoroute

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/route"
)

// fakeOracle counts calls and returns scripted decisions, so no test touches
// the network or Fairy.
type fakeOracle struct {
	mu    sync.Mutex
	calls int
	hosts []string
	// decide returns the decision for a host.
	decide func(host string) PathDecision
	// block, when non-nil, holds each check until it is closed.
	block chan struct{}
	// delay simulates a slow survey.
	delay time.Duration
	err   error
}

func (f *fakeOracle) Check(ctx context.Context, host string) (PathDecision, error) {
	f.mu.Lock()
	f.calls++
	f.hosts = append(f.hosts, host)
	block, delay, err, decide := f.block, f.delay, f.err, f.decide
	f.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return PathDecision{}, ctx.Err()
		}
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return PathDecision{}, ctx.Err()
		}
	}
	if err != nil {
		return PathDecision{}, err
	}
	if decide == nil {
		return PathDecision{DirectHealthy: true, Reason: "path_healthy", Confidence: "confirmed"}, nil
	}
	return decide(host), nil
}

func (f *fakeOracle) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func healthy(string) PathDecision {
	return PathDecision{DirectHealthy: true, Reason: "path_healthy", Confidence: "confirmed"}
}

func tlsBroken(string) PathDecision {
	return PathDecision{
		DirectHealthy:  false,
		RelaySuggested: true,
		Reason:         "tls_specific_failure",
		Confidence:     "confirmed",
		Evidence:       []string{"tls handshake: certificate signed by unknown authority"},
	}
}

// harness builds a router with a controllable clock.
type harness struct {
	router *AutoRouter
	oracle *fakeOracle
	now    time.Time
}

func newHarness(t *testing.T, rules []config.RouteRule, eligible []string, opts CacheOptions) *harness {
	t.Helper()
	cfg := &config.Config{DefaultRoute: config.RouteDirect, Routes: rules}
	table := route.New(cfg)
	oracle := &fakeOracle{decide: healthy}
	h := &harness{oracle: oracle, now: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return h.now }
	router := NewAutoRouter(RouterOptions{
		Oracle:  oracle,
		Leases:  NewLeaseCache(opts),
		Policy:  Policy{Table: table, RelayEligible: eligible, DefaultRoute: config.RouteDirect},
		Enabled: true,
		Now:     clock,
		Logf:    func(string, ...any) {},
	})
	h.router = router
	return h
}

func (h *harness) advance(d time.Duration) { h.now = h.now.Add(d) }

// 1. A valid DIRECT lease skips Fairy entirely.
func TestValidDirectLeaseSkipsOracle(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{DirectTTL: 5 * time.Minute})

	d, err := h.router.Decide(context.Background(), "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteDirect || d.Source != SourceFairy {
		t.Fatalf("first decision = %+v, want direct from fairy", d)
	}
	if h.oracle.Calls() != 1 {
		t.Fatalf("oracle calls = %d, want 1", h.oracle.Calls())
	}

	for i := 0; i < 50; i++ {
		d, err = h.router.Decide(context.Background(), "a.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if d.Route != config.RouteDirect || d.Source != SourceLease {
			t.Fatalf("decision %d = %+v, want direct from lease", i, d)
		}
	}
	if h.oracle.Calls() != 1 {
		t.Fatalf("oracle calls = %d after 50 more lookups, want 1", h.oracle.Calls())
	}
}

// 2. A valid RELAY lease skips Fairy entirely.
func TestValidRelayLeaseSkipsOracle(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{RelayTTL: 15 * time.Minute})
	h.oracle.decide = tlsBroken

	if _, err := h.router.Decide(context.Background(), "a.example.com"); err != nil {
		t.Fatal(err)
	}
	// Promote the candidate to a verified relay lease, as a real relayed
	// request would.
	h.router.NoteRelayOutcome("a.example.com", nil)
	if h.oracle.Calls() != 1 {
		t.Fatalf("oracle calls = %d, want 1", h.oracle.Calls())
	}

	for i := 0; i < 20; i++ {
		d, err := h.router.Decide(context.Background(), "a.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if d.Route != config.RouteRelay || d.Source != SourceLease {
			t.Fatalf("decision = %+v, want relay from lease", d)
		}
	}
	if h.oracle.Calls() != 1 {
		t.Fatalf("oracle calls = %d, want 1", h.oracle.Calls())
	}
}

// 3. A lease miss invokes the oracle exactly once.
func TestLeaseMissInvokesOracleOnce(t *testing.T) {
	h := newHarness(t, nil, nil, CacheOptions{})
	if _, err := h.router.Decide(context.Background(), "cold.example.com"); err != nil {
		t.Fatal(err)
	}
	if h.oracle.Calls() != 1 {
		t.Fatalf("oracle calls = %d, want 1", h.oracle.Calls())
	}
}

// 4. A hundred concurrent requests for one unseen scope run ONE survey.
// This is the property that keeps a page load from launching hundreds of
// Fairy campaigns.
func TestConcurrentRequestsShareOneSurvey(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{})
	h.oracle.block = make(chan struct{})
	h.oracle.delay = 20 * time.Millisecond
	// Unblock after the waiters have piled up.
	go func() {
		time.Sleep(60 * time.Millisecond)
		close(h.oracle.block)
	}()

	const n = 100
	var wg sync.WaitGroup
	var okCount atomic.Int64
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			d, err := h.router.Decide(context.Background(), "burst.example.com")
			if err == nil && d.Route == config.RouteDirect {
				okCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := h.oracle.Calls(); got != 1 {
		t.Fatalf("oracle calls = %d for %d concurrent requests, want 1", got, n)
	}
	if got := okCount.Load(); got != n {
		t.Fatalf("successful decisions = %d, want %d", got, n)
	}
}

// 5. A healthy direct result produces a DIRECT lease.
func TestHealthyResultProducesDirectLease(t *testing.T) {
	h := newHarness(t, nil, nil, CacheOptions{})
	d, err := h.router.Decide(context.Background(), "ok.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteDirect {
		t.Fatalf("route = %s, want direct", d.Route)
	}
	leases := h.router.LeaseViews()
	if len(leases) != 1 || leases[0].Route != "direct" || leases[0].State != string(StateDirectVerified) {
		t.Fatalf("leases = %+v", leases)
	}
}

// 6. Path interference on an eligible host produces a relay decision.
func TestInterferenceOnEligibleHostRelays(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{})
	h.oracle.decide = tlsBroken

	d, err := h.router.Decide(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteRelay {
		t.Fatalf("route = %s, want relay", d.Route)
	}
	if d.Reason != "tls_specific_failure" {
		t.Fatalf("reason = %q", d.Reason)
	}
	if len(d.Evidence) == 0 {
		t.Error("a learned decision should carry its evidence")
	}
	// Until a relayed request succeeds the lease stays a candidate, so a
	// relay that does not work cannot be remembered as if it did.
	if got := h.router.LeaseViews()[0].State; got != string(StateRelayCandidate) {
		t.Fatalf("state = %s, want relay_candidate", got)
	}
}

// 7. partial_address_failure must stay DIRECT: multi-address failover already
// handles one bad address, so relaying would fix nothing.
func TestPartialAddressFailureStaysDirect(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{})
	h.oracle.decide = func(string) PathDecision {
		return PathDecision{
			DirectHealthy:  true,
			RelaySuggested: false,
			Reason:         "partial_address_failure",
			Confidence:     "confirmed",
		}
	}
	d, err := h.router.Decide(context.Background(), "objects.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteDirect {
		t.Fatalf("route = %s, want direct", d.Route)
	}
}

// 8. A QUIC-only failure must stay DIRECT: TCP and TLS are what routing uses.
func TestQUICOnlyFailureStaysDirect(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{})
	h.oracle.decide = func(string) PathDecision {
		return PathDecision{
			DirectHealthy:  true,
			RelaySuggested: false,
			Reason:         "quic_unavailable",
			Confidence:     "confirmed",
		}
	}
	d, err := h.router.Decide(context.Background(), "h3.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteDirect {
		t.Fatalf("route = %s, want direct", d.Route)
	}
}

// 9. An ordinary HTTP 404 must not create a relay lease.
func TestHTTP404DoesNotRelay(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{})
	h.oracle.decide = func(string) PathDecision {
		return PathDecision{
			DirectHealthy:  true,
			RelaySuggested: false,
			Reason:         "http_application_rejection",
			Confidence:     "confirmed",
		}
	}
	d, err := h.router.Decide(context.Background(), "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteDirect {
		t.Fatalf("route = %s, want direct", d.Route)
	}
}

// 10. An unallowlisted host is never relayed, even when the path is broken.
func TestUnallowlistedHostNeverRelays(t *testing.T) {
	h := newHarness(t, nil, []string{"*.allowed.test"}, CacheOptions{})
	h.oracle.decide = tlsBroken

	for _, host := range []string{"blocked.test", "other.test", "allowed.test.evil.test"} {
		d, err := h.router.Decide(context.Background(), host)
		if err != nil {
			t.Fatal(err)
		}
		if d.Route == config.RouteRelay {
			t.Errorf("%s: route = relay, want direct (not relay-eligible)", host)
		}
		if d.Note == "" {
			t.Errorf("%s: a withheld relay should be explained", host)
		}
	}
	if h.router.Stats().RelayDenied == 0 {
		t.Error("withheld relays should be counted")
	}
}

// 11. An expired lease is revalidated rather than trusted.
func TestExpiredLeaseIsRevalidated(t *testing.T) {
	h := newHarness(t, nil, nil, CacheOptions{DirectTTL: time.Minute, StaleGrace: 5 * time.Second})
	if _, err := h.router.Decide(context.Background(), "ttl.example.com"); err != nil {
		t.Fatal(err)
	}
	if h.oracle.Calls() != 1 {
		t.Fatalf("calls = %d", h.oracle.Calls())
	}

	// Past the lease and its grace: the oracle must be consulted again.
	h.advance(2 * time.Minute)
	d, err := h.router.Decide(context.Background(), "ttl.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Stale {
		t.Error("a fully expired lease must not be served")
	}
	if h.oracle.Calls() != 2 {
		t.Fatalf("oracle calls = %d, want 2 after expiry", h.oracle.Calls())
	}
}

// 12. A stale lease serves immediately and revalidates once in the
// background, so expiry never becomes a latency spike.
func TestStaleLeaseServesAndRevalidates(t *testing.T) {
	h := newHarness(t, nil, nil, CacheOptions{DirectTTL: time.Minute, StaleGrace: time.Minute})
	if _, err := h.router.Decide(context.Background(), "stale.example.com"); err != nil {
		t.Fatal(err)
	}

	// Just past the lease, inside the grace window.
	h.advance(time.Minute + time.Second)
	start := time.Now()
	d, err := h.router.Decide(context.Background(), "stale.example.com")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Stale {
		t.Error("decision should be marked stale")
	}
	if d.Source != SourceLease {
		t.Errorf("source = %s, want lease", d.Source)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("stale decision took %v; it must not block on revalidation", elapsed)
	}

	// The background revalidation runs exactly once.
	deadline := time.Now().Add(2 * time.Second)
	for h.oracle.Calls() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.oracle.Calls() != 2 {
		t.Fatalf("oracle calls = %d, want 2 (one background revalidation)", h.oracle.Calls())
	}
	// More stale lookups must not start more surveys while one is running.
	for i := 0; i < 10; i++ {
		if _, err := h.router.Decide(context.Background(), "stale.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.oracle.Calls(); got > 3 {
		t.Fatalf("oracle calls = %d; stale lookups must not each revalidate", got)
	}
}

// A failed relay must NOT fall back to direct.
//
// Direct is the path we have evidence is broken — that is why the host is
// relayed — so switching back would send the request into the very
// interference the relay exists to bypass. The relay decision must stand, be
// demoted to a short-lived candidate so the next request retries it, and the
// failure must be recorded rather than hidden.
func TestRelayFailureKeepsRelayAndRecordsError(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{RelayTTL: 15 * time.Minute})
	h.oracle.decide = tlsBroken

	if _, err := h.router.Decide(context.Background(), "broken.example.com"); err != nil {
		t.Fatal(err)
	}
	h.router.NoteRelayOutcome("broken.example.com", errors.New("relay refused (403)"))

	leases := h.router.LeaseViews()
	if len(leases) != 1 {
		t.Fatalf("leases = %+v, want the single lease for the host", leases)
	}
	got := leases[0]
	if got.Route != "relay" {
		t.Fatalf("a failed relay fell back to %s; direct is the path known to be broken", got.Route)
	}
	if got.State != string(StateRelayCandidate) {
		t.Errorf("state = %s, want relay_candidate so the next request retries", got.State)
	}
	if got.LastError == "" {
		t.Error("the relay failure should be recorded for status")
	}
	// The lease must be short-lived now: a fresh diagnosis is due soon.
	if got.ExpiresInMs > int64(CacheOptions{}.withDefaults().CandidateTTL/time.Millisecond)+1000 {
		t.Errorf("expires_in = %d ms; a failed relay should be re-diagnosed soon", got.ExpiresInMs)
	}
	if h.router.Stats().RelayFailed != 1 {
		t.Error("the failed relay should be counted")
	}

	// And the route the next request receives is still relay.
	d, err := h.router.Decide(context.Background(), "broken.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteRelay {
		t.Fatalf("next decision = %s, want relay", d.Route)
	}
}

// 13. A successful relay commits a durable RELAY lease.
func TestRelaySuccessCommitsVerifiedLease(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{RelayTTL: 15 * time.Minute})
	h.oracle.decide = tlsBroken

	if _, err := h.router.Decide(context.Background(), "ok.example.com"); err != nil {
		t.Fatal(err)
	}
	before := h.router.LeaseViews()[0]
	h.router.NoteRelayOutcome("ok.example.com", nil)
	after := h.router.LeaseViews()[0]

	if after.State != string(StateRelayVerified) {
		t.Fatalf("state = %s, want relay_verified", after.State)
	}
	if after.ExpiresInMs <= before.ExpiresInMs {
		t.Errorf("verified relay should be longer-lived: %d -> %d ms", before.ExpiresInMs, after.ExpiresInMs)
	}
	if h.router.Stats().RelayOK != 1 {
		t.Error("the successful relay should be counted")
	}
}

// 15. Exact-host scope covers only that host.
func TestExactHostScope(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"}, CacheOptions{})
	h.oracle.decide = func(host string) PathDecision {
		if host == "one.example.com" {
			return tlsBroken(host)
		}
		return healthy(host)
	}

	if d, _ := h.router.Decide(context.Background(), "one.example.com"); d.Route != config.RouteRelay {
		t.Fatalf("one.example.com = %s, want relay", d.Route)
	}
	// A sibling is diagnosed on its own merits: one broken host must not
	// drag its siblings through the relay.
	d, err := h.router.Decide(context.Background(), "two.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteDirect {
		t.Fatalf("two.example.com = %s, want direct", d.Route)
	}
	if d.Source != SourceFairy {
		t.Errorf("the sibling should have been diagnosed, not covered by a domain lease")
	}
}

// 16. A scope can never widen to a public suffix.
func TestScopeNeverWidensToPublicSuffix(t *testing.T) {
	for _, host := range []string{"foo.bar.co.uk", "a.b.example.co.jp", "shop.github.io"} {
		rd := RegistrableDomain(host)
		if rd == "" {
			t.Fatalf("RegistrableDomain(%q) = empty", host)
		}
		if IsPublicSuffix(rd) {
			t.Errorf("RegistrableDomain(%q) = %q, which is a public suffix", host, rd)
		}
	}
	if got := RegistrableDomain("foo.bar.co.uk"); got != "bar.co.uk" {
		t.Errorf("foo.bar.co.uk -> %q, want bar.co.uk (naive label stripping would give co.uk)", got)
	}

	// Even if a lease for a public suffix is constructed directly, the cache
	// refuses to store it.
	c := NewLeaseCache(CacheOptions{})
	c.Put(&RouteLease{
		Scope:     Scope{Type: ScopeRegistrable, Value: "co.uk"},
		Route:     config.RouteRelay,
		State:     StateRelayVerified,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if lk, ok := c.Lookup("anything.co.uk", time.Now()); ok {
		t.Fatalf("a public-suffix lease was honoured: %+v", lk.Lease)
	}
}

// 17. Sibling escalation widens only after independent corroboration.
func TestSiblingEscalation(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"},
		CacheOptions{SiblingThreshold: 2, SiblingWindow: 5 * time.Minute, ScopeMode: "adaptive"})
	h.oracle.decide = tlsBroken

	// One host needing the relay is not evidence about the domain.
	if _, err := h.router.Decide(context.Background(), "one.example.com"); err != nil {
		t.Fatal(err)
	}
	h.router.NoteRelayOutcome("one.example.com", nil)
	if d, _ := h.router.Decide(context.Background(), "three.example.com"); d.Source == SourceLease {
		t.Error("one sibling must not widen the domain")
	}

	// A second sibling independently needing the relay is corroboration.
	if _, err := h.router.Decide(context.Background(), "two.example.com"); err != nil {
		t.Fatal(err)
	}
	h.router.NoteRelayOutcome("two.example.com", nil)

	// A host not yet diagnosed is now covered by the widened domain lease,
	// without a new survey.
	before := h.oracle.Calls()
	d, err := h.router.Decide(context.Background(), "four.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteRelay {
		t.Fatalf("four.example.com = %s, want relay from the widened domain lease", d.Route)
	}
	if d.Scope.Type != ScopeRegistrable || d.Scope.Value != "example.com" {
		t.Errorf("scope = %+v, want registrable example.com", d.Scope)
	}
	if h.oracle.Calls() != before {
		t.Errorf("the widened scope should have avoided a survey")
	}
}

// Sibling escalation must not widen in "exact" mode.
func TestExactScopeModeNeverWidens(t *testing.T) {
	h := newHarness(t, nil, []string{"*.example.com"},
		CacheOptions{SiblingThreshold: 1, ScopeMode: "exact"})
	h.oracle.decide = tlsBroken
	for _, host := range []string{"one.example.com", "two.example.com", "three.example.com"} {
		if _, err := h.router.Decide(context.Background(), host); err != nil {
			t.Fatal(err)
		}
		h.router.NoteRelayOutcome(host, nil)
	}
	for _, l := range h.router.LeaseViews() {
		if l.ScopeType != string(ScopeExact) {
			t.Fatalf("exact mode produced a %s lease: %+v", l.ScopeType, l)
		}
	}
}

// 18. Wildcard patterns must not match lookalike hostnames.
func TestWildcardLookalikesRejected(t *testing.T) {
	patterns := []string{"*.example.com"}
	// A trailing dot is the DNS root-qualified form of the same name, so it
	// matches; it is not a different hostname.
	yes := []string{"example.com", "a.example.com", "a.b.example.com", "example.com."}
	no := []string{
		"example.com.evil.test", "notexample.com", "evilexample.com",
		"aexample.com", "example.org", "xexample.com",
	}
	for _, host := range yes {
		if !MatchAny(patterns, host) {
			t.Errorf("%q should match %v", host, patterns)
		}
	}
	for _, host := range no {
		if MatchAny(patterns, host) {
			t.Errorf("%q must NOT match %v", host, patterns)
		}
	}
}

// 21. Cancellation propagates: a cancelled request does not hang waiting for
// a survey.
func TestCancellation(t *testing.T) {
	h := newHarness(t, nil, nil, CacheOptions{})
	h.oracle.block = make(chan struct{})
	defer close(h.oracle.block)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.router.Decide(ctx, "slow.example.com")
		done <- err
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Decide did not return after cancellation")
	}
}

// A cancelled waiter must not cancel the shared survey for other waiters.
func TestCancelledWaiterDoesNotCancelSharedSurvey(t *testing.T) {
	h := newHarness(t, nil, nil, CacheOptions{})
	h.oracle.block = make(chan struct{})
	h.oracle.delay = 20 * time.Millisecond

	var wg sync.WaitGroup
	results := make([]error, 2)
	wg.Add(2)
	// Waiter 1 joins the survey and is cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer wg.Done()
		_, results[0] = h.router.Decide(ctx, "shared.example.com")
	}()
	time.Sleep(20 * time.Millisecond)
	// Waiter 2 joins the same survey and must still succeed.
	go func() {
		defer wg.Done()
		_, results[1] = h.router.Decide(context.Background(), "shared.example.com")
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	close(h.oracle.block)
	wg.Wait()

	if results[1] != nil {
		t.Fatalf("second waiter failed because the first was cancelled: %v", results[1])
	}
	if h.oracle.Calls() != 1 {
		t.Fatalf("oracle calls = %d, want 1 shared survey", h.oracle.Calls())
	}
}

// Static rules always beat learning, in both directions.
func TestStaticRulesWin(t *testing.T) {
	rules := []config.RouteRule{
		{Host: "always-direct.test", Route: config.RouteDirect},
		{Host: "always-relay.test", Route: config.RouteRelay},
		{Host: "never.test", Route: config.RouteDeny},
	}
	h := newHarness(t, rules, []string{"*.test"}, CacheOptions{})
	h.oracle.decide = tlsBroken // the oracle would relay everything

	cases := map[string]config.RouteKind{
		"always-direct.test": config.RouteDirect,
		"always-relay.test":  config.RouteRelay,
		"never.test":         config.RouteDeny,
	}
	for host, want := range cases {
		d, err := h.router.Decide(context.Background(), host)
		if err != nil {
			t.Fatal(err)
		}
		if d.Route != want {
			t.Errorf("%s: route = %s, want %s", host, d.Route, want)
		}
		if d.Source != SourceStatic {
			t.Errorf("%s: source = %s, want static", host, d.Source)
		}
	}
	if h.oracle.Calls() != 0 {
		t.Fatalf("static rules must not trigger surveys; oracle calls = %d", h.oracle.Calls())
	}
}

// Clearing a host forgets its learning.
func TestClearForgetsLearning(t *testing.T) {
	h := newHarness(t, nil, nil, CacheOptions{})
	if _, err := h.router.Decide(context.Background(), "clear.example.com"); err != nil {
		t.Fatal(err)
	}
	if n := h.router.Clear("clear.example.com"); n == 0 {
		t.Fatal("clear removed nothing")
	}
	if len(h.router.LeaseViews()) != 0 {
		t.Fatal("leases remain after clear")
	}
	if _, err := h.router.Decide(context.Background(), "clear.example.com"); err != nil {
		t.Fatal(err)
	}
	if h.oracle.Calls() != 2 {
		t.Fatalf("oracle calls = %d, want 2 (one after clearing)", h.oracle.Calls())
	}
}

// The router must not run Fairy when automatic routing is disabled.
func TestDisabledRouterUsesDefault(t *testing.T) {
	cfg := &config.Config{DefaultRoute: config.RouteDirect}
	oracle := &fakeOracle{decide: tlsBroken}
	r := NewAutoRouter(RouterOptions{
		Oracle:  oracle,
		Policy:  Policy{Table: route.New(cfg), DefaultRoute: config.RouteDirect},
		Enabled: false,
	})
	d, err := r.Decide(context.Background(), "anything.test")
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != config.RouteDirect || d.Source != SourceDefault {
		t.Fatalf("decision = %+v", d)
	}
	if oracle.Calls() != 0 {
		t.Fatalf("oracle calls = %d, want 0 when disabled", oracle.Calls())
	}
}

// An oracle error is not evidence: the route falls back and nothing is
// cached as if it had been diagnosed.
func TestOracleErrorDoesNotCache(t *testing.T) {
	h := newHarness(t, nil, nil, CacheOptions{})
	h.oracle.err = errors.New("survey blew up")

	if _, err := h.router.Decide(context.Background(), "err.example.com"); err == nil {
		t.Fatal("expected the oracle error to surface")
	}
	if len(h.router.LeaseViews()) != 0 {
		t.Fatalf("a failed survey must not leave a lease: %+v", h.router.LeaseViews())
	}
	// And the proxy-level wrapper falls back to the default route.
	s := &routerFallback{router: h.router, def: config.RouteDirect}
	if got := s.route(context.Background(), "err.example.com"); got != config.RouteDirect {
		t.Fatalf("fallback route = %s, want direct", got)
	}
}

// routerFallback mirrors the proxy's error handling.
type routerFallback struct {
	router *AutoRouter
	def    config.RouteKind
}

func (r *routerFallback) route(ctx context.Context, host string) config.RouteKind {
	d, err := r.router.Decide(ctx, host)
	if err != nil {
		return r.def
	}
	return d.Route
}

// Leases expire and are pruned, so route state cannot accumulate forever.
func TestPruneDropsExpiredState(t *testing.T) {
	h := newHarness(t, nil, nil, CacheOptions{DirectTTL: time.Minute, StaleGrace: time.Second})
	for i := 0; i < 5; i++ {
		host := fmt.Sprintf("h%d.example.com", i)
		if _, err := h.router.Decide(context.Background(), host); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(h.router.LeaseViews()); got != 5 {
		t.Fatalf("leases = %d, want 5", got)
	}
	h.advance(10 * time.Minute)
	h.router.Prune()
	if got := len(h.router.LeaseViews()); got != 0 {
		t.Fatalf("leases = %d after pruning, want 0", got)
	}
}

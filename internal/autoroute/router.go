package autoroute

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/arahe-dev/phaethon/internal/config"
)

// AutoRouter is the whole decision layer: static rules first, then a
// remembered decision, then Fairy — once per scope, never per request.
//
// The hot path is a map lookup. Fairy runs on the first request for an
// unknown scope, and again only when a lease expires.
type AutoRouter struct {
	oracle PathOracle
	leases *LeaseCache
	policy Policy
	group  singleflight.Group

	// enabled turns learning off entirely, leaving the static table only.
	enabled bool
	// now is injectable so lease lifetimes and revalidation are testable
	// without sleeping.
	now func() time.Time
	// logf reports unusual conditions. It never logs headers or bodies.
	logf func(format string, args ...any)

	// Counters, so "Fairy is not on the hot path" is measurable rather than
	// asserted.
	lookups     atomic.Int64
	staticHits  atomic.Int64
	leaseHits   atomic.Int64
	oracleCalls atomic.Int64
	coalesced   atomic.Int64
	revalidated atomic.Int64
	relayDenied atomic.Int64
	relayOK     atomic.Int64
	relayFailed atomic.Int64
}

// RouterOptions configure the router.
type RouterOptions struct {
	Oracle  PathOracle
	Leases  *LeaseCache
	Policy  Policy
	Enabled bool
	// Now overrides the clock (tests).
	Now func() time.Time
	// Logf overrides the diagnostic logger.
	Logf func(format string, args ...any)
}

// NewAutoRouter builds a router. A nil cache gets default lifetimes.
func NewAutoRouter(opts RouterOptions) *AutoRouter {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}
	leases := opts.Leases
	if leases == nil {
		leases = NewLeaseCache(CacheOptions{})
	}
	// Persistence must read the same clock as the decisions. Using the wall
	// clock while decisions use an injected one makes lease lifetime depend on
	// two different time sources, which is both wrong and untestable: a lease
	// the router considers live can look expired to the code writing it out.
	leases.SetClock(now)
	return &AutoRouter{
		oracle:  opts.Oracle,
		leases:  leases,
		policy:  opts.Policy,
		enabled: opts.Enabled,
		now:     now,
		logf:    logf,
	}
}

// Leases exposes the cache for status output and tests.
func (r *AutoRouter) Leases() *LeaseCache { return r.leases }

// Enabled reports whether automatic routing is active.
func (r *AutoRouter) Enabled() bool { return r.enabled }

// Decide answers the only question the proxy asks: which route should this
// host use, and why.
//
// Order of authority:
//
//	explicit static rule          (operator's word is final)
//	fresh or in-grace lease       (remembered learning)
//	Fairy                         (diagnosis, once per scope)
//	default route                 (fallback)
func (r *AutoRouter) Decide(ctx context.Context, host string) (Decision, error) {
	r.lookups.Add(1)
	host = normalizeHost(host)
	if host == "" {
		return Decision{}, errors.New("autoroute: empty host")
	}

	// 1. Static configuration always wins: an operator who listed a host
	// should never be second-guessed by a survey.
	if kind, matched := r.policy.Static(host); matched {
		r.staticHits.Add(1)
		d := Decision{Route: kind, Source: SourceStatic, Reason: "static rule"}
		if kind == config.RouteDeny {
			d.Reason = "denied by static rule"
		}
		return d, nil
	}

	if !r.enabled || r.oracle == nil {
		r.staticHits.Add(1)
		return Decision{Route: r.policy.Default(), Source: SourceDefault, Reason: "automatic routing disabled"}, nil
	}

	now := r.now()

	// 2. A usable lease answers immediately.
	if lk, ok := r.leases.Lookup(host, now); ok {
		r.leaseHits.Add(1)
		lease := lk.Lease
		r.leases.NoteUsed(lease, now)
		d := decisionFromLease(lease, now, r.leases.Options().StaleGrace)
		if !lk.Fresh {
			// Stale: serve the previous route and revalidate behind the
			// request, so expiry never becomes a latency spike.
			d.Stale = true
			r.revalidateAsync(host, lease.Scope)
		}
		// Policy is re-checked even for a lease, so a widened scope can never
		// relay a host the operator did not allow.
		if d.Route == config.RouteRelay && !r.policy.AllowsRelay(host) {
			r.relayDenied.Add(1)
			d.Route = r.policy.Default()
			d.Note = "learned relay withheld: host is not relay-eligible"
		}
		return d, nil
	}

	// 3. Unknown scope: ask the oracle, once, shared by every concurrent
	// request for the same scope.
	decision, err := r.decideViaOracle(ctx, host)
	if err != nil {
		return Decision{}, err
	}
	return decision, nil
}

// decisionFromLease converts a lease into a decision.
func decisionFromLease(l *RouteLease, now time.Time, grace time.Duration) Decision {
	return Decision{
		Route:      l.Route,
		Source:     SourceLease,
		Scope:      l.Scope,
		Reason:     l.Reason,
		Confidence: l.Confidence,
		Evidence:   append([]string(nil), l.Evidence...),
		ReportID:   l.FairyReportID,
		lease:      l,
	}
}

// scopeFor picks the smallest scope a fresh decision should be stored under.
func scopeFor(host string) Scope {
	return Scope{Type: ScopeExact, Value: normalizeHost(host)}
}

// decideViaOracle runs (or joins) a Fairy check for a host's scope and stores
// the resulting lease.
//
// Every concurrent request for the same scope shares one survey through
// singleflight: a page issuing eighty requests for a cold host causes one
// Fairy check, not eighty.
func (r *AutoRouter) decideViaOracle(ctx context.Context, host string) (Decision, error) {
	key := "scope:" + normalizeHost(host)

	type result struct {
		decision Decision
	}
	ch := r.group.DoChan(key, func() (any, error) {
		// A survey outlives the request that triggered it: it is shared with
		// every waiter, so one client disconnecting must not cancel the
		// diagnosis the others are waiting for.
		checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.oracleBudget())
		defer cancel()

		r.oracleCalls.Add(1)
		pd, err := r.oracle.Check(checkCtx, host)
		if err != nil {
			return nil, err
		}
		return result{decision: r.commit(host, pd, r.now())}, nil
	})

	select {
	case <-ctx.Done():
		return Decision{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return Decision{}, res.Err
		}
		out, _ := res.Val.(result)
		return out.decision, nil
	}
}

// oracleBudget is the longest a shared survey may run.
func (r *AutoRouter) oracleBudget() time.Duration {
	if fo, ok := r.oracle.(*FairyOracle); ok && fo.timeout > 0 {
		return fo.timeout + 2*time.Second
	}
	return 10 * time.Second
}

// commit turns a path decision into a lease, applying policy.
// The decision it returns is marked SourceFairy rather than SourceLease: this
// request paid for a survey, and saying so is what makes "Fairy is not on the
// hot path" observable in status output and tests.
func (r *AutoRouter) commit(host string, pd PathDecision, now time.Time) Decision {
	scope := scopeFor(host)
	lease := r.leases.newLease(scope, config.RouteDirect, StateDirectVerified, now)
	lease.Reason = pd.Reason
	lease.Confidence = pd.Confidence
	lease.Evidence = pd.Evidence
	lease.FairyReportID = pd.ReportID

	switch {
	case pd.DirectHealthy:
		// Healthy direct: nothing more to do. This is the common case and it
		// costs one survey per direct TTL.
		if lease.Reason == "" {
			lease.Reason = "path_healthy"
		}
		r.leases.Put(lease)
		return freshDecision(lease, now, r.leases.Options().StaleGrace)

	case pd.RelaySuggested && r.policy.AllowsRelay(host):
		// Deliberately a *candidate*: the lease only becomes durable once a
		// real relayed request has succeeded, so a relay that Fairy thinks
		// should work but does not cannot poison the cache.
		cand := r.leases.newLease(scope, config.RouteRelay, StateRelayCandidate, now)
		cand.Reason = pd.Reason
		cand.Confidence = pd.Confidence
		cand.Evidence = pd.Evidence
		cand.FairyReportID = pd.ReportID
		r.leases.Put(cand)
		return freshDecision(cand, now, r.leases.Options().StaleGrace)

	case pd.RelaySuggested:
		// The path is unsuitable but policy forbids relaying this host. Say
		// so; never quietly open a route the operator did not allow.
		r.relayDenied.Add(1)
		r.logf("phaethon: direct path to %s looks unsuitable (%s) but the host is not relay-eligible; staying direct",
			host, pd.Reason)
		lease.Route = config.RouteDirect
		lease.State = StateDirectVerified
		lease.Reason = pd.Reason
		r.leases.Put(lease)
		d := freshDecision(lease, now, r.leases.Options().StaleGrace)
		d.Note = "path unsuitable but host is not relay-eligible"
		return d

	default:
		// A problem a relay would not fix (or no problem at all): stay
		// direct and record why.
		if lease.Reason == "" {
			lease.Reason = "direct_usable"
		}
		r.leases.Put(lease)
		return freshDecision(lease, now, r.leases.Options().StaleGrace)
	}
}

// freshDecision marks a decision as freshly diagnosed rather than remembered.
func freshDecision(l *RouteLease, now time.Time, grace time.Duration) Decision {
	d := decisionFromLease(l, now, grace)
	d.Source = SourceFairy
	return d
}

// revalidateAsync refreshes a stale lease in the background, at most once per
// scope at a time.
func (r *AutoRouter) revalidateAsync(host string, scope Scope) {
	key := "revalidate:" + scope.Value
	go func() {
		_, _, _ = r.group.Do(key, func() (any, error) {
			r.revalidated.Add(1)
			ctx, cancel := context.WithTimeout(context.Background(), r.oracleBudget())
			defer cancel()
			r.oracleCalls.Add(1)
			pd, err := r.oracle.Check(ctx, host)
			if err != nil {
				// Keep serving whatever we had; a failed revalidation is not
				// evidence about the path.
				r.logf("phaethon: revalidation of %s failed: %v", host, err)
				return nil, nil
			}
			r.commit(host, pd, r.now())
			return nil, nil
		})
	}()
}

// NoteRelayOutcome records whether a relayed request actually succeeded.
//
// A candidate lease is only promoted to a verified, long-lived lease after a
// relayed request works, and a failed relay never leaves a durable relay
// lease behind.
func (r *AutoRouter) NoteRelayOutcome(host string, err error) {
	host = normalizeHost(host)
	if host == "" {
		return
	}
	now := r.now()
	lk, ok := r.leases.Lookup(host, now)
	if !ok || lk.Lease.Route != config.RouteRelay {
		return
	}
	lease := lk.Lease

	if err != nil {
		r.relayFailed.Add(1)
		// A failed relay must NOT fall back to direct. Direct is the path we
		// have evidence is broken — that is why this host is relayed — so
		// silently switching back would send the request into the very
		// interference the relay exists to bypass, and a browser would see a
		// certificate error instead of a clear failure.
		//
		// Instead the relay decision stands but is demoted to a candidate with
		// a short life, so the next request retries the relay and a fresh
		// diagnosis happens soon. The failure is counted and surfaced rather
		// than hidden.
		lease.State = StateRelayCandidate
		lease.ExpiresAt = now.Add(r.leases.Options().CandidateTTL)
		lease.LastError = err.Error()
		r.logf("phaethon: relay request for %s failed (%v); keeping relay and re-diagnosing within %s",
			host, err, r.leases.Options().CandidateTTL)
		return
	}
	// Success clears any recorded failure.
	lease.LastError = ""

	r.relayOK.Add(1)
	if lease.State == StateRelayCandidate {
		lease.State = StateRelayVerified
		lease.ExpiresAt = now.Add(r.leases.Options().RelayTTL)
	}

	// Only now, with a proven relay, may a whole registrable domain widen:
	// two sibling hostnames independently needing the relay is corroboration,
	// one hostname is not.
	if domain, widen := r.leases.noteRelayHost(host, lease.Reason, now); widen {
		widened := r.leases.newLease(Scope{Type: ScopeRegistrable, Value: domain},
			config.RouteRelay, StateRelayVerified, now)
		widened.Reason = lease.Reason
		widened.Confidence = lease.Confidence
		widened.Evidence = lease.Evidence
		widened.FairyReportID = lease.FairyReportID
		r.leases.Put(widened)
		r.logf("phaethon: widened relay scope to %s after %d sibling hostnames needed it",
			domain, r.leases.SiblingHosts(domain))
	}
}

// Clear forgets everything learned about a host.
func (r *AutoRouter) Clear(host string) int {
	return r.leases.Delete(host)
}

// ClearAll forgets all learned state.
func (r *AutoRouter) ClearAll() { r.leases.Clear() }

// RouterStats is a snapshot of routing counters.
type RouterStats struct {
	Lookups       int64 `json:"lookups"`
	StaticHits    int64 `json:"static_hits"`
	LeaseHits     int64 `json:"lease_hits"`
	OracleCalls   int64 `json:"oracle_calls"`
	Coalesced     int64 `json:"coalesced"`
	Revalidations int64 `json:"revalidations"`
	RelayDenied   int64 `json:"relay_denied_by_policy"`
	RelayOK       int64 `json:"relay_verified"`
	RelayFailed   int64 `json:"relay_failed"`
	Leases        int   `json:"leases"`
	Enabled       bool  `json:"enabled"`
}

// Stats reports counters, so "Fairy is not on the hot path" can be measured.
func (r *AutoRouter) Stats() RouterStats {
	return RouterStats{
		Lookups:       r.lookups.Load(),
		StaticHits:    r.staticHits.Load(),
		LeaseHits:     r.leaseHits.Load(),
		OracleCalls:   r.oracleCalls.Load(),
		Coalesced:     r.coalesced.Load(),
		Revalidations: r.revalidated.Load(),
		RelayDenied:   r.relayDenied.Load(),
		RelayOK:       r.relayOK.Load(),
		RelayFailed:   r.relayFailed.Load(),
		Leases:        len(r.leases.Snapshot(r.now())),
		Enabled:       r.enabled,
	}
}

// LeaseViews exposes leases for status output.
func (r *AutoRouter) LeaseViews() []LeaseView {
	return r.leases.Snapshot(r.now())
}

// Prune drops expired state.
func (r *AutoRouter) Prune() { r.leases.Prune(r.now()) }

// String helps debugging.
func (r *AutoRouter) String() string {
	s := r.Stats()
	return fmt.Sprintf("autoroute(enabled=%v lookups=%d static=%d lease=%d oracle=%d)",
		s.Enabled, s.Lookups, s.StaticHits, s.LeaseHits, s.OracleCalls)
}

// Persist writes the learned leases so a restart does not force a survey for
// every hostname already known.
func (r *AutoRouter) Persist(path string) (int, error) { return r.leases.Persist(path) }

// Restore loads persisted leases, reporting what was kept and what was stale.
func (r *AutoRouter) Restore(path string) (int, int, error) { return r.leases.Restore(path) }

// LeaseCount reports how many leases are held.
func (r *AutoRouter) LeaseCount() int { return r.leases.Count() }

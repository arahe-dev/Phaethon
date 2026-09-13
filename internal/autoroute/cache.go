package autoroute

import (
	"sort"
	"sync"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// CacheOptions tune lease lifetimes and scope escalation.
type CacheOptions struct {
	// DirectTTL is how long a healthy-direct decision is trusted.
	DirectTTL time.Duration
	// RelayTTL is how long a verified relay decision is trusted.
	RelayTTL time.Duration
	// CandidateTTL is the short lifetime of a relay decision that has not
	// yet been proven by a successful relayed request.
	CandidateTTL time.Duration
	// StaleGrace is how long an expired lease may still serve its previous
	// route while a revalidation runs in the background.
	StaleGrace time.Duration
	// SiblingWindow is how recent sibling evidence must be to widen a scope.
	SiblingWindow time.Duration
	// SiblingThreshold is how many sibling hostnames under one registrable
	// domain must independently need the relay before the domain widens.
	SiblingThreshold int
	// ScopeMode is "exact" (never widen) or "adaptive" (widen on repeated
	// sibling evidence).
	ScopeMode string
}

// defaults fills unset options.
func (o CacheOptions) withDefaults() CacheOptions {
	if o.DirectTTL <= 0 {
		o.DirectTTL = 5 * time.Minute
	}
	if o.RelayTTL <= 0 {
		o.RelayTTL = 15 * time.Minute
	}
	if o.CandidateTTL <= 0 {
		o.CandidateTTL = 30 * time.Second
	}
	if o.StaleGrace <= 0 {
		o.StaleGrace = 30 * time.Second
	}
	if o.SiblingWindow <= 0 {
		o.SiblingWindow = 5 * time.Minute
	}
	if o.SiblingThreshold <= 0 {
		o.SiblingThreshold = 2
	}
	if o.ScopeMode == "" {
		o.ScopeMode = "adaptive"
	}
	return o
}

// Lookup is the result of consulting the cache.
type Lookup struct {
	// Lease is the lease covering the host, when one exists.
	Lease *RouteLease
	// Fresh reports whether the lease is still within its lifetime. A
	// non-fresh lease is stale: usable only inside the grace period, and
	// only while a revalidation is started.
	Fresh bool
}

// siblingRecord accumulates relay evidence for siblings of one registrable
// domain so an entire domain can be widened without poisoning it on a single
// hostname.
type siblingRecord struct {
	hosts    map[string]time.Time
	reason   string
	widened  bool
	lastSeen time.Time
}

// LeaseCache is the hot path: a concurrency-safe in-memory map from scope to
// lease. It holds no locks across work and runs no I/O.
type LeaseCache struct {
	mu sync.RWMutex
	// now is the time source for every lifetime decision, so persistence and
	// restore cannot disagree with the router about whether a lease is live.
	now    func() time.Time
	exact  map[string]*RouteLease
	suffix map[string]*RouteLease
	sib    map[string]*siblingRecord
	opts   CacheOptions
}

// NewLeaseCache builds a cache; zero options select the documented defaults.
func NewLeaseCache(opts CacheOptions) *LeaseCache {
	return &LeaseCache{
		exact:  map[string]*RouteLease{},
		suffix: map[string]*RouteLease{},
		sib:    map[string]*siblingRecord{},
		opts:   opts.withDefaults(),
		now:    time.Now,
	}
}

// Options returns the effective options.
func (c *LeaseCache) Options() CacheOptions { return c.opts }

// SetClock points the cache at the clock its owner uses.
//
// Persistence and restore are decisions about lease lifetime, so they must read
// the same time source as the router that produced the leases. Reading the wall
// clock instead makes a lease the router considers live look expired when it is
// written, and makes any test with a pinned clock depend on the real date.
func (c *LeaseCache) SetClock(now func() time.Time) {
	if now == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// clock returns the cache's time source, defaulting to the wall clock.
func (c *LeaseCache) clock() func() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.now == nil {
		return time.Now
	}
	return c.now
}

// Lookup returns the lease covering host, if any. Exact-host leases take
// priority over domain leases. Expired-but-in-grace leases are returned with
// Fresh=false so the caller can serve the previous route and revalidate.
func (c *LeaseCache) Lookup(host string, now time.Time) (Lookup, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, key := range scopeCandidates(host) {
		var lease *RouteLease
		if key == normalizeHost(host) {
			lease = c.exact[key]
		}
		if lease == nil {
			lease = c.suffix[key]
		}
		if lease == nil || !lease.Usable(now, c.opts.StaleGrace) {
			continue
		}
		return Lookup{Lease: lease, Fresh: lease.Fresh(now)}, true
	}
	return Lookup{}, false
}

// Put stores a lease under its scope key.
func (c *LeaseCache) Put(lease *RouteLease) {
	if lease == nil || lease.Scope.Value == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if lease.Scope.Type == ScopeExact {
		c.exact[lease.Scope.Value] = lease
		return
	}
	if IsPublicSuffix(lease.Scope.Value) {
		// A lease on a public suffix would route every host under it; that
		// must never be reachable, however the lease was constructed.
		return
	}
	c.suffix[lease.Scope.Value] = lease
}

// Delete removes every lease covering a host and returns how many were
// dropped, so an operator can clear one host's learning.
func (c *LeaseCache) Delete(host string) int {
	host = normalizeHost(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	if _, ok := c.exact[host]; ok {
		delete(c.exact, host)
		removed++
	}
	for _, key := range scopeCandidates(host) {
		if _, ok := c.suffix[key]; ok {
			delete(c.suffix, key)
			removed++
		}
	}
	return removed
}

// Clear drops all learned state.
func (c *LeaseCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exact = map[string]*RouteLease{}
	c.suffix = map[string]*RouteLease{}
	c.sib = map[string]*siblingRecord{}
}

// noteRelayHost records that a hostname independently needed the relay, and
// reports the registrable domain to widen to once enough siblings agree.
//
// Widening requires SiblingThreshold distinct hostnames under the same
// registrable domain, needing the relay for the same reason, inside
// SiblingWindow. One broken host therefore never routes a whole domain.
func (c *LeaseCache) noteRelayHost(host, reason string, now time.Time) (widenTo string, ok bool) {
	if c.opts.ScopeMode != "adaptive" {
		return "", false
	}
	domain := RegistrableDomain(host)
	if domain == "" || domain == host || IsPublicSuffix(domain) {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.sib[domain]
	if rec == nil {
		rec = &siblingRecord{hosts: map[string]time.Time{}}
		c.sib[domain] = rec
	}
	// Forget siblings that have gone quiet, and reopen a domain that had
	// previously widened if its evidence has aged out.
	if now.Sub(rec.lastSeen) > c.opts.SiblingWindow {
		rec.hosts = map[string]time.Time{}
		rec.reason = ""
		rec.widened = false
	}
	rec.hosts[normalizeHost(host)] = now
	rec.lastSeen = now
	if rec.reason == "" {
		rec.reason = reason
	}
	if rec.reason != reason {
		// Different failure shapes under one domain are not corroboration.
		rec.hosts = map[string]time.Time{normalizeHost(host): now}
		rec.reason = reason
		rec.widened = false
		return "", false
	}
	if rec.widened || len(rec.hosts) < c.opts.SiblingThreshold {
		return "", false
	}
	rec.widened = true
	return domain, true
}

// SiblingHosts reports how many distinct hostnames under a registrable domain
// currently support widening, for status output.
func (c *LeaseCache) SiblingHosts(domain string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if rec := c.sib[domain]; rec != nil {
		return len(rec.hosts)
	}
	return 0
}

// LeaseView is the status representation of one lease.
type LeaseView struct {
	Scope       string   `json:"scope"`
	ScopeType   string   `json:"scope_type"`
	Route       string   `json:"route"`
	State       string   `json:"state"`
	Reason      string   `json:"reason"`
	Confidence  string   `json:"confidence,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Source      string   `json:"source"`
	CreatedAt   string   `json:"created_at"`
	ExpiresAt   string   `json:"expires_at"`
	ExpiresInMs int64    `json:"expires_in_ms"`
	LastUsedAt  string   `json:"last_used_at,omitempty"`
	FairyReport string   `json:"fairy_report_id,omitempty"`
	Stale       bool     `json:"stale"`
	// LastError is the most recent relayed-request failure for this scope, so
	// a broken relay is visible in status rather than only in a log.
	LastError string `json:"last_error,omitempty"`
}

// Snapshot lists current leases for status output, newest first.
func (c *LeaseCache) Snapshot(now time.Time) []LeaseView {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]LeaseView, 0, len(c.exact)+len(c.suffix))
	add := func(l *RouteLease, source string) {
		if l == nil || !l.Usable(now, c.opts.StaleGrace) {
			return
		}
		v := LeaseView{
			Scope:       l.Scope.Value,
			ScopeType:   string(l.Scope.Type),
			Route:       string(l.Route),
			State:       string(l.State),
			Reason:      l.Reason,
			Confidence:  l.Confidence,
			Evidence:    append([]string(nil), l.Evidence...),
			Source:      source,
			CreatedAt:   l.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt:   l.ExpiresAt.UTC().Format(time.RFC3339),
			ExpiresInMs: l.expiresInMs(now),
			Stale:       !l.Fresh(now),
			FairyReport: l.FairyReportID,
			LastError:   l.LastError,
		}
		if !l.LastUsedAt.IsZero() {
			v.LastUsedAt = l.LastUsedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, v)
	}
	for _, l := range c.exact {
		add(l, "fairy")
	}
	for _, l := range c.suffix {
		add(l, "fairy")
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}

// NoteUsed records that a lease was just used for a request.
func (c *LeaseCache) NoteUsed(lease *RouteLease, now time.Time) {
	if lease == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	lease.LastUsedAt = now
}

// Prune drops leases and sibling records that are fully past their grace.
func (c *LeaseCache) Prune(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, l := range c.exact {
		if !l.Usable(now, c.opts.StaleGrace) {
			delete(c.exact, k)
		}
	}
	for k, l := range c.suffix {
		if !l.Usable(now, c.opts.StaleGrace) {
			delete(c.suffix, k)
		}
	}
	for k, rec := range c.sib {
		if now.Sub(rec.lastSeen) > 2*c.opts.SiblingWindow {
			delete(c.sib, k)
		}
	}
}

// newLease builds a lease for a scope and route.
func (c *LeaseCache) newLease(scope Scope, route config.RouteKind, state LeaseState, now time.Time) *RouteLease {
	ttl := c.opts.DirectTTL
	switch {
	case route == config.RouteRelay && state == StateRelayVerified:
		ttl = c.opts.RelayTTL
	case route == config.RouteRelay:
		ttl = c.opts.CandidateTTL
	}
	return &RouteLease{
		Scope:     scope,
		Route:     route,
		State:     state,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
}

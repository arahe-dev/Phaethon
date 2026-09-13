// Package autoroute turns Phaethon from a static route table into a router
// that learns.
//
// The design has exactly four concepts:
//
//	PathOracle  answers "what happened on the direct network path?" — Fairy
//	RouteLease  a temporary, evidenced routing decision for a scope
//	LeaseCache  the in-memory lookup that makes the hot path a map hit
//	AutoRouter  the policy layer: static rules first, then leases, then Fairy
//
// Phaethon does not diagnose. It asks Fairy once per scope, remembers the
// answer for a bounded time, and forgets it again — because a path that is
// broken today can be healthy in an hour, which this network demonstrated
// when TLS interception of a host disappeared without any local change.
package autoroute

import (
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// Scope is the set of hostnames a lease applies to.
type Scope struct {
	// Type is how the scope was derived.
	Type ScopeType `json:"type"`
	// Value is the scope key: a hostname, a registrable domain, or an
	// explicitly configured suffix.
	Value string `json:"value"`
}

// ScopeType enumerates how a lease scope was derived. The distinction
// matters: an exact-host lease is a fact about one name, while a
// registrable-domain lease is an inference about siblings and must be
// earned by repeated evidence.
type ScopeType string

const (
	// ScopeExact applies to one hostname only.
	ScopeExact ScopeType = "exact_host"
	// ScopeRegistrable applies to a registrable domain and its subdomains,
	// derived with the Public Suffix List.
	ScopeRegistrable ScopeType = "registrable_domain"
	// ScopeSuffix applies to an explicitly configured eligible suffix.
	ScopeSuffix ScopeType = "configured_suffix"
)

// LeaseState is the small state machine behind a lease. It exists so that a
// relay chosen on Fairy's say-so is only made durable once a real relayed
// request has actually succeeded.
type LeaseState string

const (
	// StateDirectVerified means Fairy saw the direct path work.
	StateDirectVerified LeaseState = "direct_verified"
	// StateRelayCandidate means Fairy judged the direct path unsuitable and
	// the host is relay-eligible, but no relayed request has succeeded yet.
	StateRelayCandidate LeaseState = "relay_candidate"
	// StateRelayVerified means a relayed request has actually succeeded.
	StateRelayVerified LeaseState = "relay_verified"
)

// RouteLease is a temporary routing decision for a scope, with the evidence
// that produced it and a hard expiry. It is deliberately short-lived: its
// whole purpose is to let Phaethon forget stale network state.
type RouteLease struct {
	Scope      Scope            `json:"scope"`
	Route      config.RouteKind `json:"route"`
	State      LeaseState       `json:"state"`
	Reason     string           `json:"reason"`
	Confidence string           `json:"confidence,omitempty"`
	Evidence   []string         `json:"evidence,omitempty"`

	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`

	// FairyReportID identifies the survey that produced this lease, so an
	// operator can correlate a routing decision with its diagnosis.
	FairyReportID string `json:"fairy_report_id,omitempty"`

	// LastError records the most recent relayed-request failure for this
	// scope, so a broken relay is visible in status instead of only in a log.
	LastError string `json:"last_error,omitempty"`
}

// Usable reports whether the lease may still be acted on at time now,
// including the stale grace period during which the previous route is served
// while a revalidation runs in the background.
func (l *RouteLease) Usable(now time.Time, staleGrace time.Duration) bool {
	if l == nil {
		return false
	}
	return now.Before(l.StaleUntil(staleGrace))
}

// Fresh reports whether the lease is still within its stated lifetime.
func (l *RouteLease) Fresh(now time.Time) bool {
	return l != nil && now.Before(l.ExpiresAt)
}

// StaleUntil is the end of the grace period after expiry.
func (l *RouteLease) StaleUntil(staleGrace time.Duration) time.Time {
	if l == nil {
		return time.Time{}
	}
	return l.ExpiresAt.Add(staleGrace)
}

// expiresInMs is a convenience for status output.
func (l *RouteLease) expiresInMs(now time.Time) int64 {
	if l == nil {
		return 0
	}
	return l.ExpiresAt.Sub(now).Milliseconds()
}

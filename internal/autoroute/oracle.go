package autoroute

import (
	"context"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/route"
)

// PathDecision is what a PathOracle answers: what happened on the direct
// network path, in Fairy's evidence-first terms. It deliberately says nothing
// about whether relaying is permitted — that is policy, not diagnosis.
type PathDecision struct {
	// DirectHealthy reports whether the direct path carried the layers that
	// matter for a routed request (name resolution, TCP, TLS).
	DirectHealthy bool `json:"direct_healthy"`
	// RelaySuggested reports whether the evidence indicates a path problem
	// that a relay can plausibly avoid. It is a hint, not an instruction:
	// AutoRouter only relays when policy also allows it.
	RelaySuggested bool `json:"relay_suggested"`
	// Reason is the finding kind that drove the decision, or a short
	// explanation when no finding applied.
	Reason string `json:"reason"`
	// Confidence is Fairy's confidence for that finding, when there is one.
	Confidence string `json:"confidence,omitempty"`
	// Evidence lists the observations behind the decision.
	Evidence []string `json:"evidence,omitempty"`
	// ReportID identifies the survey this decision came from.
	ReportID string `json:"report_id,omitempty"`
}

// PathOracle diagnoses the direct path for one host. Implementations must be
// safe for concurrent use: the router may ask about several hosts at once.
type PathOracle interface {
	Check(ctx context.Context, host string) (PathDecision, error)
}

// OracleFunc adapts a function to PathOracle, which keeps tests free of Fairy
// and of the network.
type OracleFunc func(ctx context.Context, host string) (PathDecision, error)

// Check implements PathOracle.
func (f OracleFunc) Check(ctx context.Context, host string) (PathDecision, error) {
	return f(ctx, host)
}

// Policy is the configuration side of routing: what the operator has already
// decided, and what Phaethon is allowed to relay. Kept separate from path
// diagnosis on purpose.
type Policy struct {
	// Table is the static route table, which always wins.
	Table *route.Table
	// RelayEligible lists hostname patterns that may be relayed. A hostname
	// outside this list is never relayed, whatever the path evidence says.
	RelayEligible []string
	// DefaultRoute applies when nothing else decides.
	DefaultRoute config.RouteKind
}

// Static returns the explicit rule for a host, when one matches.
func (p *Policy) Static(host string) (config.RouteKind, bool) {
	if p == nil || p.Table == nil {
		return "", false
	}
	d, matched := p.Table.Decide(host)
	if !matched {
		return "", false
	}
	return d.Route, true
}

// AllowsRelay reports whether policy permits relaying a host.
//
// A host is relay-eligible if the operator listed it for relaying explicitly
// or named it in the relay eligibility patterns. This is checked for the
// hostname actually being requested, every time, so a widened lease can never
// become a way to relay something the operator did not allow.
func (p *Policy) AllowsRelay(host string) bool {
	if p == nil {
		return false
	}
	if kind, matched := p.Static(host); matched {
		return kind == config.RouteRelay
	}
	return MatchAny(p.RelayEligible, host)
}

// Default returns the fallback route.
func (p *Policy) Default() config.RouteKind {
	if p == nil || p.DefaultRoute == "" {
		return config.RouteDirect
	}
	return p.DefaultRoute
}

// DecisionSource explains where a routing decision came from, so status output
// and tests can tell static configuration apart from learning.
type DecisionSource string

const (
	// SourceStatic is an explicit rule from configuration.
	SourceStatic DecisionSource = "static"
	// SourceLease is a remembered decision, still fresh or in its grace.
	SourceLease DecisionSource = "lease"
	// SourceFairy is a decision made by asking the oracle just now.
	SourceFairy DecisionSource = "fairy"
	// SourceDefault is the configured fallback route.
	SourceDefault DecisionSource = "default"
)

// Decision is what the proxy asks for and executes.
type Decision struct {
	// Route is the route to execute.
	Route config.RouteKind `json:"route"`
	// Source explains where the route came from.
	Source DecisionSource `json:"source"`
	// Scope is the lease scope that produced the decision, when learned.
	Scope Scope `json:"scope,omitempty"`
	// Reason is the finding kind or explanation behind a learned decision.
	Reason string `json:"reason,omitempty"`
	// Confidence is Fairy's confidence, when the decision came from evidence.
	Confidence string `json:"confidence,omitempty"`
	// Evidence lists the supporting observations.
	Evidence []string `json:"evidence,omitempty"`
	// Stale reports that the decision came from a lease past its lifetime and
	// is being revalidated in the background.
	Stale bool `json:"stale,omitempty"`
	// Note is a human-readable remark, e.g. why a relay was withheld.
	Note string `json:"note,omitempty"`
	// ReportID identifies the survey behind a learned decision.
	ReportID string `json:"report_id,omitempty"`

	lease *RouteLease
}

// Lease exposes the underlying lease to callers inside this package.
func (d Decision) Lease() *RouteLease { return d.lease }

// Rule names the static rule behind a decision, for refusal messages.
func (d Decision) Rule() string {
	if d.Source == SourceStatic {
		return string(d.Scope.Value)
	}
	return ""
}

// ScopeValue is the lease scope value that produced a decision, if any.
func (d Decision) ScopeValue() string { return d.Scope.Value }

// RouteDecision adapts a decision to the route-table type that refusal
// messages expect, so the proxy keeps one vocabulary for explaining refusals.
func (d Decision) RouteDecision() route.Decision {
	return route.Decision{Route: d.Route, Rule: d.Rule(), Note: d.Note}
}

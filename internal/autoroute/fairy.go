package autoroute

import (
	"context"
	"fmt"
	"time"

	"github.com/arahe-dev/fairy"

	"github.com/arahe-dev/phaethon/internal/config"
)

// Finding kinds that justify considering a relay. Everything not listed here
// deliberately leaves the direct route alone.
const (
	// TLS interception or hostname-dependent TLS failure is the signature
	// this whole design exists for: TCP works, the handshake does not.
	findingTLSSpecific = "tls_specific_failure"
	// Proxy interference is only acted on when a TLS observation actually
	// failed, because "possible" on its own is not proof.
	findingProxyInterference = "possible_proxy_interference"
	// Confirmed resolution failure is relay-worthy because the relay
	// resolves names at the Cloudflare edge instead of locally.
	findingDNSFailure = "dns_failure"
)

// Findings that must NOT cause a relay, with the reason they are excluded:
//
//	partial_address_failure  the direct route already fails over across
//	                         addresses, so relaying would fix nothing
//	quic_unavailable         UDP being blocked says nothing about TCP/TLS
//	udp_unavailable          same
//	http_application_rejection an application answered; that is not a path
//	                         problem
//	ipv6_path_failure        IPv4 works, and failover already prefers it
//	tcp_unreachable          ambiguous: the host may simply be down, so the
//	                         relay would gain nothing; reported, not relayed
//	path_healthy             the path is fine
//
// This list is enforced by relayWorthy() below, not by comments.

// FairyOracle asks FairySDK about the direct path. It is the only place in
// Phaethon that imports Fairy: one adapter owns the dependency, and nothing
// else in the codebase interprets findings.
type FairyOracle struct {
	fairy     *fairy.Fairy
	timeout   time.Duration
	probeHTTP bool

	// Calls counts oracle invocations, so tests and status output can prove
	// that Fairy is not consulted per request.
	calls int64
}

// OracleOptions configure the bounded Fairy check.
type OracleOptions struct {
	// Timeout bounds one check. This is the whole-survey budget handed to
	// Fairy, so an unknown host costs at most this much once per lease.
	Timeout time.Duration
	// MaxProbes caps experiments in one check.
	MaxProbes int
	// MaxConcurrent caps concurrency inside Fairy.
	MaxConcurrent int
	// ProbeHTTP additionally probes HTTP. Off by default: an application's
	// 404/403 must never influence routing.
	ProbeHTTP bool
}

// NewFairyOracle builds the oracle. The Fairy instance is reused across hosts;
// it holds configuration only, so concurrent checks are safe.
func NewFairyOracle(opts OracleOptions) (*FairyOracle, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.MaxProbes <= 0 {
		opts.MaxProbes = 8
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = 4
	}
	f, err := fairy.New(fairy.Config{
		Policy:        tlsPathPolicy{probeHTTP: opts.ProbeHTTP},
		MaxProbes:     opts.MaxProbes,
		Timeout:       opts.Timeout,
		MaxConcurrent: opts.MaxConcurrent,
	})
	if err != nil {
		return nil, fmt.Errorf("autoroute: build fairy: %w", err)
	}
	return &FairyOracle{fairy: f, timeout: opts.Timeout, probeHTTP: opts.ProbeHTTP}, nil
}

// Check runs one bounded Fairy survey and maps it to a path decision.
func (o *FairyOracle) Check(ctx context.Context, host string) (PathDecision, error) {
	if host == "" {
		return PathDecision{}, fmt.Errorf("autoroute: empty host")
	}
	report, err := o.fairy.Survey(ctx, "https://"+host)
	if report == nil {
		return PathDecision{}, fmt.Errorf("autoroute: fairy survey of %s: %w", host, err)
	}
	o.calls++
	decision := DecisionFromReport(report)
	// A survey that ran out of budget still carries whatever was observed,
	// which is exactly what the mapping above used.
	return decision, nil
}

// Calls reports how many Fairy checks have run, for status and tests.
func (o *FairyOracle) Calls() int64 { return o.calls }

// DecisionFromReport maps a Fairy report onto a path decision.
//
// It reads Fairy's structured findings and canonical observations rather than
// matching error strings, and it never claims more than the report supports.
// It is a pure function so the mapping rules are testable without a network.
func DecisionFromReport(rep *fairy.Report) PathDecision {
	if rep == nil {
		return PathDecision{Reason: "no report"}
	}
	d := PathDecision{ReportID: reportID(rep)}

	worst := worstFinding(rep.Findings)
	if worst != nil {
		d.Reason = worst.Kind
		d.Confidence = string(worst.Confidence)
		d.Evidence = append([]string(nil), worst.Evidence...)
	}

	d.DirectHealthy = tlsHealthy(rep)

	switch {
	case d.DirectHealthy && !relayWorthy(worst, rep):
		// Nothing wrong, or nothing wrong that a relay would fix.
		if d.Reason == "" {
			d.Reason = "path_healthy"
			if worst != nil {
				d.Confidence = string(worst.Confidence)
				d.Evidence = append([]string(nil), worst.Evidence...)
			}
		}
		return d
	case relayWorthy(worst, rep):
		d.RelaySuggested = true
		return d
	default:
		// The path has a problem, but not one a relay addresses: a dead
		// origin, an application answer, or an address-specific failure the
		// direct transport already handles.
		if d.Reason == "" {
			d.Reason = "direct_unhealthy"
		}
		return d
	}
}

// relayWorthy reports whether the evidence justifies considering a relay.
func relayWorthy(worst *fairy.Finding, rep *fairy.Report) bool {
	switch {
	case worst == nil:
		return false
	case worst.Kind == findingTLSSpecific:
		return true
	case worst.Kind == findingProxyInterference:
		// Only with a TLS observation that actually failed: "possible"
		// interference without a failed handshake is not evidence.
		return !tlsHealthy(rep)
	case worst.Kind == findingDNSFailure:
		// The relay resolves at the edge, so confirmed resolution failure is
		// something it can bypass. A timeout stays "possible", not cause.
		return worst.Confidence == fairy.Confirmed || worst.Confidence == fairy.Likely
	default:
		return false
	}
}

// tlsHealthy reports whether TLS completed against the canonical experiment.
func tlsHealthy(rep *fairy.Report) bool {
	for _, o := range rep.Observations {
		if o.Layer != fairy.LayerTLS {
			continue
		}
		if isCanonicalTLS(o) {
			return o.Status == fairy.Pass
		}
	}
	return false
}

// isCanonicalTLS reports whether an observation is the default TLS experiment
// rather than an adaptive variant, so a passing variant cannot stand in for
// the real path check.
func isCanonicalTLS(o fairy.Observation) bool {
	return o.Experiment.SNI == "" && o.Experiment.ALPN == ""
}

// worstFinding picks the finding that best explains why the path is unusable,
// preferring the ones that can drive a relay and then the strongest
// confidence.
func worstFinding(findings []fairy.Finding) *fairy.Finding {
	rank := func(f fairy.Finding) int {
		base := 0
		switch f.Kind {
		case findingTLSSpecific:
			base = 300
		case findingProxyInterference:
			base = 250
		case findingDNSFailure:
			base = 200
		case "tcp_unreachable":
			base = 100
		case "partial_address_failure", "ipv6_path_failure", "quic_unavailable", "udp_unavailable":
			base = 50
		case "http_application_rejection":
			base = 40
		case "path_healthy":
			base = 10
		}
		switch f.Confidence {
		case fairy.Confirmed:
			return base + 3
		case fairy.Likely:
			return base + 2
		case fairy.Possible:
			return base + 1
		default:
			return base
		}
	}
	var best *fairy.Finding
	bestRank := -1
	for i := range findings {
		if r := rank(findings[i]); r > bestRank {
			bestRank = r
			best = &findings[i]
		}
	}
	return best
}

// reportID derives a stable identifier for a report so a lease can name the
// survey behind it.
func reportID(rep *fairy.Report) string {
	if rep.State != nil && rep.State.SurveyID != "" {
		return rep.State.SurveyID
	}
	if rep.Target.Host != "" {
		return fmt.Sprintf("%s@%d", rep.Target.Host, rep.StartedAt.Unix())
	}
	return ""
}

// tlsPathPolicy is the smallest survey that can answer the routing question:
// DNS, then TCP, then TLS.
//
// Fairy's FastPolicy additionally probes QUIC, which on a UDP-blocked path
// costs its whole budget and only ever yields quic_unavailable — a finding
// that must not influence routing. This policy reuses Fairy's experiment model
// and findings; it adds no diagnosis of its own. It is an implementation of
// Fairy's public Policy extension point, not a change to Fairy.
type tlsPathPolicy struct {
	probeHTTP bool
}

// Propose returns the next experiments needed to judge the direct path.
func (p tlsPathPolicy) Propose(_ context.Context, state fairy.SurveyState, budget int) ([]fairy.Experiment, error) {
	plan := p.plan(state)
	if budget > 0 && len(plan) > budget {
		plan = plan[:budget]
	}
	return plan, nil
}

// Done reports whether the survey has everything it needs.
func (p tlsPathPolicy) Done(state fairy.SurveyState) bool {
	return len(p.plan(state)) == 0
}

// plan is the pure heart of the policy: what is still missing.
func (p tlsPathPolicy) plan(state fairy.SurveyState) []fairy.Experiment {
	if state.Target == nil {
		return nil
	}
	target := *state.Target

	dns := latestFor(state, fairy.LayerDNS, "")
	if dns == nil {
		return []fairy.Experiment{newDNSExperiment(target)}
	}
	if dns.Status != fairy.Pass {
		// Names did not resolve: nothing downstream can be probed, and the
		// resolution failure is itself the evidence.
		return nil
	}

	v4, v6 := resolvedFamilies(dns)
	families := orderedFamilies(v4, v6)
	if len(families) == 0 {
		families = []fairy.IPFamily{fairy.IPv4}
	}

	var out []fairy.Experiment
	for _, fam := range families {
		if latestFor(state, fairy.LayerTCP, fam) == nil {
			out = append(out, newTCPExperiment(target, fam))
		}
	}
	if len(out) > 0 {
		return out
	}

	fam := passingFamily(state, fairy.LayerTCP)
	if fam == "" {
		return nil // no TCP path; TLS cannot be judged
	}
	tls := latestFor(state, fairy.LayerTLS, fam)
	if tls == nil {
		return []fairy.Experiment{newTLSExperiment(target, fam)}
	}
	if p.probeHTTP && tls.Status == fairy.Pass && latestFor(state, fairy.LayerHTTP, fam) == nil {
		return []fairy.Experiment{newHTTPExperiment(target, fam)}
	}
	return nil
}

// latestFor returns the most recent observation for a layer and family.
func latestFor(state fairy.SurveyState, layer fairy.Layer, family fairy.IPFamily) *fairy.Observation {
	for i := len(state.Observations) - 1; i >= 0; i-- {
		o := &state.Observations[i]
		if o.Layer != layer {
			continue
		}
		if family != "" && o.Experiment.IPFamily != family {
			continue
		}
		return o
	}
	return nil
}

// passingFamily returns a family whose most recent TCP attempt passed.
func passingFamily(state fairy.SurveyState, layer fairy.Layer) fairy.IPFamily {
	for _, fam := range []fairy.IPFamily{fairy.IPv4, fairy.IPv6} {
		if o := latestFor(state, layer, fam); o != nil && o.Status == fairy.Pass {
			return fam
		}
	}
	return ""
}

// resolvedFamilies reads address-family presence from DNS evidence.
func resolvedFamilies(o *fairy.Observation) (v4, v6 bool) {
	ev, ok := o.FirstEvidenceOf(fairy.KindDNSAnswer)
	if !ok {
		return true, false
	}
	if list, ok := asStrings(ev.Values["v4"]); ok {
		v4 = len(list) > 0
	}
	if list, ok := asStrings(ev.Values["v6"]); ok {
		v6 = len(list) > 0
	}
	return v4, v6
}

// orderedFamilies lists families to probe, IPv4 first for determinism.
func orderedFamilies(v4, v6 bool) []fairy.IPFamily {
	var out []fairy.IPFamily
	if v4 {
		out = append(out, fairy.IPv4)
	}
	if v6 {
		out = append(out, fairy.IPv6)
	}
	return out
}

// asStrings coerces an evidence value into []string.
func asStrings(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out, true
	default:
		return nil, false
	}
}

// newDNSExperiment builds the canonical system-resolver DNS experiment.
func newDNSExperiment(t fairy.Target) fairy.Experiment {
	e := fairy.Experiment{
		Target:    t,
		Layer:     fairy.LayerDNS,
		IPFamily:  fairy.FamilyAny,
		Transport: fairy.UDP,
		Resolver:  fairy.ResolverSystem,
	}
	e.Normalize()
	return e
}

// newTCPExperiment builds a TCP connect experiment.
func newTCPExperiment(t fairy.Target, fam fairy.IPFamily) fairy.Experiment {
	e := fairy.Experiment{Target: t, Layer: fairy.LayerTCP, IPFamily: fam, Transport: fairy.TCP}
	e.Normalize()
	return e
}

// newTLSExperiment builds the canonical TLS handshake experiment.
func newTLSExperiment(t fairy.Target, fam fairy.IPFamily) fairy.Experiment {
	e := fairy.Experiment{Target: t, Layer: fairy.LayerTLS, IPFamily: fam, Transport: fairy.TCP}
	e.Normalize()
	return e
}

// newHTTPExperiment builds the canonical HTTP experiment (opt-in).
func newHTTPExperiment(t fairy.Target, fam fairy.IPFamily) fairy.Experiment {
	e := fairy.Experiment{Target: t, Layer: fairy.LayerHTTP, IPFamily: fam, Transport: fairy.TCP}
	e.Normalize()
	return e
}

// ensure config stays imported for the route kinds used in decisions.
var _ = config.RouteDirect

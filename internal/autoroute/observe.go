package autoroute

import (
	"context"
	"time"

	"github.com/arahe-dev/fairy"

	"github.com/arahe-dev/phaethon/internal/config"
)

// Peek answers "which route would this host use right now?" without doing
// anything about it.
//
// It is deliberately separate from Decide, which is allowed to run a survey
// and write a lease. Reporting tools must be able to inspect routing without
// changing it: a speed test that silently created leases would be measuring a
// system it had just modified.
func (r *AutoRouter) Peek(host string) Decision {
	host = normalizeHost(host)
	if host == "" {
		return Decision{Route: config.RouteDirect, Source: SourceDefault}
	}
	if kind, matched := r.policy.Static(host); matched {
		return Decision{Route: kind, Source: SourceStatic, Reason: "static rule"}
	}
	if !r.enabled {
		return Decision{Route: r.policy.Default(), Source: SourceDefault, Reason: "automatic routing disabled"}
	}
	now := r.now()
	if lk, ok := r.leases.Lookup(host, now); ok {
		d := decisionFromLease(lk.Lease, now, r.leases.Options().StaleGrace)
		if !lk.Fresh {
			d.Stale = true
		}
		return d
	}
	return Decision{Route: r.policy.Default(), Source: SourceDefault, Reason: "no lease; not yet diagnosed"}
}

// Leases exposes the cache for read-only inspection.
func (r *AutoRouter) LeasesForReporting() []LeaseView { return r.leases.Snapshot(r.now()) }

// KnownFailure reports whether a lease records a direct-path problem, which is
// what makes a host worth benchmarking or considering for a relay.
func KnownFailure(view LeaseView) bool {
	switch view.Reason {
	case "tls_specific_failure", "possible_proxy_interference", "dns_failure",
		"tcp_unreachable", "network_unreachable":
		return true
	default:
		return false
	}
}

// LayerSample is one measured layer from a Fairy survey.
type LayerSample struct {
	// Layer is "dns", "tcp", "tls", or "http".
	Layer string `json:"layer"`
	// Status is "ok" or "failed".
	Status string `json:"status"`
	// DurationMs is how long the layer took, from Fairy's own observation.
	DurationMs float64 `json:"duration_ms"`
	// Family is the address family the probe used, when it matters.
	Family string `json:"family,omitempty"`
	// Error is the observation's reported error, if any.
	Error string `json:"error,omitempty"`
	// AddressesPassed and AddressesFailed surface partial failures, so a slow
	// address cannot hide behind a fast sibling.
	AddressesPassed int `json:"addresses_passed,omitempty"`
	AddressesFailed int `json:"addresses_failed,omitempty"`
}

// DirectObservation is what Fairy saw on the direct path, with timings.
type DirectObservation struct {
	// Layers are the per-layer measurements, in probe order.
	Layers []LayerSample `json:"layers"`
	// Findings are Fairy's inferences, as structured data rather than text.
	Findings []FindingSummary `json:"findings,omitempty"`
	// ReportID identifies the survey, so a measurement can be correlated with
	// a diagnosis.
	ReportID string `json:"report_id,omitempty"`
	// DurationMs is the whole survey's wall time.
	DurationMs float64 `json:"duration_ms"`
}

// FindingSummary is one Fairy finding in a stable shape.
type FindingSummary struct {
	Kind       string   `json:"kind"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

// Layer returns the sample for a layer name, if the survey produced one.
func (o DirectObservation) Layer(name string) (LayerSample, bool) {
	for _, l := range o.Layers {
		if l.Layer == name {
			return l, true
		}
	}
	return LayerSample{}, false
}

// Observe runs one bounded Fairy survey and reports what it measured, without
// touching routing state.
//
// This is the same policy the router uses, so the numbers describe the path
// Phaethon actually reasons about rather than a separate notion of health.
func (o *FairyOracle) Observe(ctx context.Context, host string) (DirectObservation, error) {
	if host == "" {
		return DirectObservation{}, errEmptyHost
	}
	start := time.Now()
	report, err := o.fairy.Survey(ctx, "https://"+host)
	elapsed := time.Since(start)
	if report == nil {
		return DirectObservation{DurationMs: msOf(elapsed)}, err
	}
	out := DirectObservation{
		DurationMs: msOf(elapsed),
		ReportID:   reportID(report),
	}
	for _, obs := range report.Observations {
		sample := LayerSample{
			Layer:      string(obs.Layer),
			Status:     statusWord(obs.Status),
			DurationMs: msOf(obs.Duration),
			Error:      obs.Error,
		}
		if obs.Experiment.IPFamily != "" {
			sample.Family = string(obs.Experiment.IPFamily)
		}
		sample.AddressesPassed, sample.AddressesFailed = obs.AddressTally()
		// Keep the canonical measurement per layer: an adaptive variant must
		// not stand in for the real path.
		if obs.Layer == fairy.LayerTLS && !isCanonicalTLS(obs) {
			continue
		}
		out.Layers = replaceLayer(out.Layers, sample)
	}
	for _, f := range report.Findings {
		out.Findings = append(out.Findings, FindingSummary{
			Kind:       f.Kind,
			Confidence: string(f.Confidence),
			Evidence:   append([]string(nil), f.Evidence...),
		})
	}
	return out, nil
}

// replaceLayer keeps the last sample for a layer, which is the most recent
// attempt.
func replaceLayer(layers []LayerSample, sample LayerSample) []LayerSample {
	for i := range layers {
		if layers[i].Layer == sample.Layer {
			layers[i] = sample
			return layers
		}
	}
	return append(layers, sample)
}

// statusWord renders a Fairy status without leaking its console formatting.
func statusWord(s fairy.Status) string {
	if s == fairy.Pass {
		return "ok"
	}
	return "failed"
}

// msOf converts a duration to milliseconds for reporting.
func msOf(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

// errEmptyHost is returned rather than surveying nothing.
var errEmptyHost = errString("speedtest: a hostname is required")

// errString is a minimal error type, avoiding an import for one value.
type errString string

func (e errString) Error() string { return string(e) }

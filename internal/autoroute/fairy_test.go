package autoroute

import (
	"testing"

	"github.com/arahe-dev/fairy"
)

// decision builds a Fairy report with the given findings and TLS outcome,
// mirroring what Fairy actually produces.
func reportWith(t tHelper, findings []fairy.Finding, tlsStatus fairy.Status, sni string) *fairy.Report {
	t.Helper()
	target := fairy.Target{Host: "example.com", Port: 443}
	state := fairy.NewSurveyState(target)
	state.SurveyID = "survey-1"
	tlsExp := fairy.Experiment{Target: target, Layer: fairy.LayerTLS, IPFamily: fairy.IPv4, Transport: fairy.TCP, SNI: sni}
	tlsExp.Normalize()
	state.Observations = append(state.Observations, fairy.Observation{
		Experiment: tlsExp,
		Layer:      fairy.LayerTLS,
		Status:     tlsStatus,
		Evidence:   []fairy.Evidence{{Kind: "tls_handshake", Values: map[string]any{"error": "x509: certificate signed by unknown authority"}}},
	})
	return &fairy.Report{State: state, Target: target, Findings: findings, Observations: state.Observations}
}

type tHelper interface {
	Helper()
	Fatalf(format string, args ...any)
}

// The mapping from Fairy findings to route decisions is the core of the
// integration, so each finding class is pinned by a test.
func TestDecisionFromReportMapping(t *testing.T) {
	cases := []struct {
		name        string
		finding     string
		confidence  fairy.Confidence
		tlsStatus   fairy.Status
		wantHealthy bool
		wantRelay   bool
	}{
		{"path healthy", "path_healthy", fairy.Confirmed, fairy.Pass, true, false},
		{"tls specific failure", "tls_specific_failure", fairy.Confirmed, fairy.Fail, false, true},
		{"proxy interference with failed TLS", "possible_proxy_interference", fairy.Possible, fairy.Fail, false, true},
		{"proxy interference with passing TLS", "possible_proxy_interference", fairy.Possible, fairy.Pass, true, false},
		{"dns failure confirmed", "dns_failure", fairy.Confirmed, fairy.Fail, false, true},
		{"dns failure possible", "dns_failure", fairy.Possible, fairy.Fail, false, false},
		{"tcp unreachable", "tcp_unreachable", fairy.Confirmed, fairy.Fail, false, false},
		{"partial address failure", "partial_address_failure", fairy.Confirmed, fairy.Pass, true, false},
		{"quic unavailable", "quic_unavailable", fairy.Confirmed, fairy.Pass, true, false},
		{"udp unavailable", "udp_unavailable", fairy.Confirmed, fairy.Pass, true, false},
		{"http application rejection", "http_application_rejection", fairy.Confirmed, fairy.Pass, true, false},
		{"ipv6 path failure", "ipv6_path_failure", fairy.Confirmed, fairy.Pass, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := reportWith(t, []fairy.Finding{{
				Kind: tc.finding, Confidence: tc.confidence, Evidence: []string{"observed"},
			}}, tc.tlsStatus, "")
			d := DecisionFromReport(rep)
			if d.DirectHealthy != tc.wantHealthy {
				t.Errorf("DirectHealthy = %v, want %v", d.DirectHealthy, tc.wantHealthy)
			}
			if d.RelaySuggested != tc.wantRelay {
				t.Errorf("RelaySuggested = %v, want %v", d.RelaySuggested, tc.wantRelay)
			}
			if d.Reason == "" {
				t.Error("every decision should carry a reason")
			}
		})
	}
}

// An adaptive TLS variant must not stand in for the canonical path check: a
// passing variant experiment must not make a failed canonical handshake look
// healthy.
func TestVariantTLSDoesNotMaskCanonicalFailure(t *testing.T) {
	target := fairy.Target{Host: "example.com", Port: 443}
	state := fairy.NewSurveyState(target)
	canonical := fairy.Experiment{Target: target, Layer: fairy.LayerTLS, IPFamily: fairy.IPv4, Transport: fairy.TCP}
	canonical.Normalize()
	variant := canonical
	variant.SNI = "other.example.com"

	state.Observations = []fairy.Observation{
		{Experiment: canonical, Layer: fairy.LayerTLS, Status: fairy.Fail},
		{Experiment: variant, Layer: fairy.LayerTLS, Status: fairy.Pass},
	}
	rep := &fairy.Report{State: state, Target: target, Observations: state.Observations,
		Findings: []fairy.Finding{{Kind: "tls_specific_failure", Confidence: fairy.Confirmed}}}

	d := DecisionFromReport(rep)
	if d.DirectHealthy {
		t.Fatal("a passing variant masked the canonical TLS failure")
	}
	if !d.RelaySuggested {
		t.Fatal("a canonical TLS failure should suggest the relay")
	}
}

// A nil or empty report must never be read as "healthy".
func TestDecisionFromReportNoEvidence(t *testing.T) {
	if d := DecisionFromReport(nil); d.DirectHealthy || d.RelaySuggested {
		t.Fatalf("nil report produced %+v", d)
	}
	target := fairy.Target{Host: "example.com", Port: 443}
	state := fairy.NewSurveyState(target)
	rep := &fairy.Report{State: state, Target: target}
	d := DecisionFromReport(rep)
	if d.DirectHealthy {
		t.Error("a survey with no TLS observation must not be called healthy")
	}
	if d.RelaySuggested {
		t.Error("a survey with no evidence must not suggest a relay")
	}
}

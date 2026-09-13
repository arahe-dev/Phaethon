package sshdiag

import (
	"context"

	"github.com/arahe-dev/fairy"
)

// pathPolicy is the smallest survey that answers the SSH question: resolve the
// name, then try to connect, and additionally attempt a handshake only where
// the port is expected to carry TLS.
//
// It is a deliberate variant of the policy Phaethon uses for routing, and it
// exists for a reason specific to this diagnostic: the routing policy always
// probes TLS, but most SSH ports are not TLS. Running a handshake against port
// 22 would produce a failure that says nothing about whether the path works,
// and reporting that failure would be misleading. Where TLS *is* attempted on
// port 443 the result is kept, because "TLS succeeded" versus "a raw SSH banner
// arrived" is precisely how HTTPS and SSH-over-443 are told apart.
//
// This implements Fairy's public Policy extension point. Fairy itself is
// unchanged, and no diagnosis is added here: it only decides which experiments
// to run, and Fairy still performs them and produces the findings.
type pathPolicy struct {
	// withTLS attempts a handshake once TCP succeeds.
	withTLS bool
}

// Propose returns the experiments still needed.
func (p pathPolicy) Propose(_ context.Context, state fairy.SurveyState, budget int) ([]fairy.Experiment, error) {
	plan := p.plan(state)
	if budget > 0 && len(plan) > budget {
		plan = plan[:budget]
	}
	return plan, nil
}

// Done reports whether the survey has what it needs.
func (p pathPolicy) Done(state fairy.SurveyState) bool {
	return len(p.plan(state)) == 0
}

// plan is the pure heart of the policy: what is still missing.
func (p pathPolicy) plan(state fairy.SurveyState) []fairy.Experiment {
	if state.Target == nil {
		return nil
	}
	target := *state.Target

	dns := latestLayer(state, fairy.LayerDNS)
	if dns == nil {
		return []fairy.Experiment{{
			Target:    target,
			Layer:     fairy.LayerDNS,
			IPFamily:  fairy.FamilyAny,
			Transport: fairy.UDP,
			Resolver:  fairy.ResolverSystem,
		}}
	}
	if dns.Status != fairy.Pass {
		// Nothing resolved, so there is no address to connect to. The
		// resolution outcome is itself the evidence.
		return nil
	}

	var out []fairy.Experiment
	for _, fam := range []fairy.IPFamily{fairy.IPv4, fairy.IPv6} {
		if latestFamily(state, fairy.LayerTCP, fam) == nil {
			out = append(out, fairy.Experiment{
				Target: target, Layer: fairy.LayerTCP, Transport: fairy.TCP, IPFamily: fam,
			})
		}
	}
	if len(out) > 0 {
		return out
	}

	if !p.withTLS {
		return nil
	}
	// TLS is only meaningful if something actually accepted a connection.
	if !anyPassed(state, fairy.LayerTCP) {
		return nil
	}
	if latestLayer(state, fairy.LayerTLS) == nil {
		return []fairy.Experiment{{
			Target: target, Layer: fairy.LayerTLS, Transport: fairy.TCP, IPFamily: fairy.IPv4,
		}}
	}
	return nil
}

// latestLayer returns the most recent observation for a layer.
func latestLayer(state fairy.SurveyState, layer fairy.Layer) *fairy.Observation {
	for i := len(state.Observations) - 1; i >= 0; i-- {
		if state.Observations[i].Layer == layer {
			return &state.Observations[i]
		}
	}
	return nil
}

// latestFamily returns the most recent observation for a layer and family.
func latestFamily(state fairy.SurveyState, layer fairy.Layer, family fairy.IPFamily) *fairy.Observation {
	for i := len(state.Observations) - 1; i >= 0; i-- {
		o := &state.Observations[i]
		if o.Layer == layer && o.Experiment.IPFamily == family {
			return o
		}
	}
	return nil
}

// anyPassed reports whether any observation at a layer succeeded.
func anyPassed(state fairy.SurveyState, layer fairy.Layer) bool {
	for _, o := range state.Observations {
		if o.Layer == layer && o.Status == fairy.Pass {
			return true
		}
	}
	return false
}

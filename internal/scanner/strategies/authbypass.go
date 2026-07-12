package strategies

import (
	"github.com/Omkardalvi01/sentry/internal/model"

)

// AuthBypass generates probes that re-test zombie endpoints WITHOUT auth headers.
// Strategy: if a deprecated-but-alive endpoint also works without auth → critical.
// This runs as a second pass using findings from Strategy 1.
type AuthBypass struct{}

func (a *AuthBypass) Name() string { return model.StrategyAuthBypass }

// GenerateProbesFromFindings creates auth bypass probes from existing findings.
// Unlike other strategies, this doesn't query the graph directly —
// it takes Strategy 1 findings as input.
func (a *AuthBypass) GenerateProbesFromFindings(findings []*model.Finding, cfg *model.ScanConfig) []*model.Probe {
	var probes []*model.Probe

	for _, f := range findings {
		// Only re-test findings from deprecated_alive strategy
		if f.Strategy != model.StrategyDeprecatedAlive {
			continue
		}

		probe := model.MakeProbe(
			cfg.Target,
			f.Path,
			f.Method,
			model.StrategyAuthBypass,
			map[string]string{
				"originalFindingId": f.ID,
			},
		)
		// Mark this probe to skip auth headers
		// The engine will use the no-auth HTTP client for these
		probe.Headers["_noAuth"] = "true"
		probes = append(probes, probe)
	}
	return probes
}

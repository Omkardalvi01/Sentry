package strategies

import (
	"context"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"

)

// allHTTPMethods is the set of standard HTTP methods to test against.
var allHTTPMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

// MethodProbe generates probes for HTTP methods NOT defined in the spec.
// Strategy: if spec only defines GET for /users, probe POST, PUT, DELETE, etc.
type MethodProbe struct{}

func (m *MethodProbe) Name() string { return model.StrategyMethodProbe }

func (m *MethodProbe) GenerateProbes(ctx context.Context, client *graph.Client, cfg *model.ScanConfig) ([]*model.Probe, error) {
	paths, err := client.ReadPaths(ctx, cfg.SpecTitle, cfg.SpecVer)
	if err != nil {
		return nil, err
	}

	var probes []*model.Probe
	for _, pathTemplate := range paths {
		// Get methods defined in the spec for this path
		definedMethods, err := client.ReadMethodsForPath(ctx, pathTemplate)
		if err != nil {
			continue
		}

		defined := make(map[string]bool)
		for _, m := range definedMethods {
			defined[m] = true
		}

		// Probe methods NOT in the spec
		for _, method := range allHTTPMethods {
			if defined[method] {
				continue
			}
			probe := model.MakeProbe(
				cfg.Target,
				pathTemplate,
				method,
				model.StrategyMethodProbe,
				map[string]string{
					"definedMethods": joinMethods(definedMethods),
				},
			)
			probes = append(probes, probe)
		}
	}
	return probes, nil
}

func joinMethods(methods []string) string {
	result := ""
	for i, m := range methods {
		if i > 0 {
			result += ","
		}
		result += m
	}
	return result
}

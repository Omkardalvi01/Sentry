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
	ops, err := client.ReadOperationsWithPaths(ctx, cfg.SpecTitle, cfg.SpecVer)
	if err != nil {
		return nil, err
	}
	copy := *cfg
	copy.Strategies = []string{m.Name()}
	return Plan(ops, &copy), nil
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

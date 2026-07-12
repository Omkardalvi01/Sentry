// Package strategies implements zombie API detection strategies.
package strategies

import (
	"context"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"

)

// DeprecatedAlive generates probes for all deprecated operations.
// Strategy: if a deprecated endpoint still responds, it's a zombie.
type DeprecatedAlive struct{}

func (d *DeprecatedAlive) Name() string { return model.StrategyDeprecatedAlive }

func (d *DeprecatedAlive) GenerateProbes(ctx context.Context, client *graph.Client, cfg *model.ScanConfig) ([]*model.Probe, error) {
	ops, err := client.ReadOperationsWithPaths(ctx, cfg.SpecTitle, cfg.SpecVer)
	if err != nil {
		return nil, err
	}

	var probes []*model.Probe
	for _, op := range ops {
		if !op.Deprecated {
			continue
		}
		probe := model.MakeProbe(
			cfg.Target,
			op.PathTemplate,
			op.Method,
			model.StrategyDeprecatedAlive,
			map[string]string{
				"operationId":      op.OperationID,
				"responses_schema": op.Responses,
				"summary":          op.Summary,
			},
		)
		probes = append(probes, probe)
	}
	return probes, nil
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/parser"
	"github.com/Omkardalvi01/sentry/internal/scanner"
	"github.com/spf13/cobra"
)

// scan-spec uses the same planner and verifier without requiring external services.
func scanSpecCmd() *cobra.Command {
	var file, output, candidates string
	cfg := &model.ScanConfig{Workers: 5, RPS: 100, Timeout: 5 * time.Second}
	var headers []string
	cmd := &cobra.Command{Use: "scan-spec", Short: "Reproduce scanner behavior against a local spec and target", RunE: func(cmd *cobra.Command, args []string) error {
		p, err := parser.NewParser(file)
		if err != nil {
			return err
		}
		spec, err := p.Parse(file)
		if err != nil {
			return err
		}
		cfg.Headers = scanner.ParseHeaders(headers)
		if candidates != "" {
			b, err := os.ReadFile(candidates)
			if err != nil {
				return err
			}
			if err = json.Unmarshal(b, &cfg.PassiveCandidates); err != nil {
				return err
			}
		}
		cfg.SpecTitle, cfg.SpecVer = spec.Title, spec.Version
		ops := []graph.OperationWithPath{}
		for _, path := range spec.Paths {
			for _, op := range path.Operations {
				ops = append(ops, graph.OperationWithPath{Operation: op, PathTemplate: path.Template})
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		scan, findings, err := scanner.NewEngine(cfg, nil).RunWithOperations(ctx, ops)
		if err != nil {
			return err
		}
		b, err := json.MarshalIndent(map[string]any{"scan": scan, "findings": findings}, "", "  ")
		if err != nil {
			return err
		}
		if output != "" {
			return os.WriteFile(output, b, 0644)
		}
		fmt.Println(string(b))
		return nil
	}}
	cmd.Flags().BoolVar(&cfg.DisableSchema, "disable-schema", false, "Research ablation: omit schema evidence")
	cmd.Flags().BoolVar(&cfg.DisableCatchAll, "disable-catch-all", false, "Research ablation: omit catch-all suppression")
	cmd.Flags().StringVar(&candidates, "candidate-file", "", "JSON passive operation candidates")
	cmd.Flags().IntVar(&cfg.RPS, "rps", 100, "Maximum requests per second")
	cmd.Flags().IntVar(&cfg.MaxRequests, "max-requests", 0, "Total request budget including baselines (0 unlimited)")
	cmd.Flags().StringVar(&file, "file", "", "OpenAPI/Swagger file")
	cmd.Flags().StringVar(&cfg.Target, "target", "", "Authorized local API base URL")
	cmd.Flags().StringVar(&output, "output-file", "", "JSON report path")
	cmd.Flags().BoolVar(&cfg.AllowMutating, "allow-mutating", false, "Enable mutating methods")
	cmd.Flags().BoolVar(&cfg.DryRun, "dry-run", false, "Plan only; zero target requests")
	cmd.Flags().StringSliceVar(&cfg.Strategies, "strategies", nil, "Strategy selection")
	cmd.Flags().StringSliceVar(&headers, "header", nil, "Authentication headers")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

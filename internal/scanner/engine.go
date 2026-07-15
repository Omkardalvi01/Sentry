package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	"github.com/google/uuid"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/scanner/strategies"
)

// Strategy defines the interface that all detection strategies implement.
type Strategy interface {
	Name() string
	GenerateProbes(ctx context.Context, client *graph.Client, cfg *model.ScanConfig) ([]*model.Probe, error)
}

// Engine orchestrates the scanning process.
type Engine struct {
	cfg         *model.ScanConfig
	graphClient *graph.Client
	httpClient  *HTTPClient
	noAuthHTTP  *HTTPClient
	limiter     *rate.Limiter
	baseline    *model.ProbeResult
}

// NewEngine creates a new scan engine.
func NewEngine(cfg *model.ScanConfig, graphClient *graph.Client) *Engine {
	return &Engine{
		cfg:         cfg,
		graphClient: graphClient,
		httpClient:  NewHTTPClient(cfg),
		noAuthHTTP:  NewHTTPClientWithoutAuth(cfg),
		limiter:     rate.NewLimiter(rate.Limit(cfg.RPS), cfg.RPS),
	}
}

// Run executes the full scan pipeline.
func (e *Engine) Run(ctx context.Context) (*model.Scan, []*model.Finding, error) {
	scan := &model.Scan{
		ID:        uuid.New().String(),
		Target:    e.cfg.Target,
		SpecTitle: e.cfg.SpecTitle,
		SpecVersion: e.cfg.SpecVer,
		StartedAt: time.Now().UTC(),
		Status:    "running",
	}

	// Resolve which strategies to run
	activeStrategies := e.resolveStrategies()

	fmt.Printf("⏳ Generating probes from %d strategies...\n", len(activeStrategies))

	// Determine baseline for differential analysis
	e.determineBaseline(ctx)

	// Phase 1: Generate probes from all strategies (except auth_bypass)
	var allProbes []*model.Probe
	for _, strat := range activeStrategies {
		if strat.Name() == model.StrategyAuthBypass {
			continue // auth bypass runs as Phase 2
		}

		probes, err := strat.GenerateProbes(ctx, e.graphClient, e.cfg)
		if err != nil {
			fmt.Printf("  ⚠ %s: %v\n", strat.Name(), err)
			continue
		}
		fmt.Printf("  ✓ %s: %d probes\n", strat.Name(), len(probes))
		allProbes = append(allProbes, probes...)
	}

	if e.cfg.DryRun {
		e.printDryRun(allProbes)
		scan.Status = "dry_run"
		scan.CompletedAt = time.Now().UTC()
		return scan, nil, nil
	}

	fmt.Printf("\n⏳ Executing %d probes (%d workers, %d RPS)...\n", len(allProbes), e.cfg.Workers, e.cfg.RPS)

	// Phase 1: Execute probes
	phase1Findings := e.executeProbes(ctx, allProbes)
	fmt.Printf("✓ Phase 1 complete: %d findings\n", len(phase1Findings))

	// Phase 2: Auth bypass (second pass using Phase 1 findings)
	var phase2Findings []*model.Finding
	if e.isStrategyActive(model.StrategyAuthBypass) && len(phase1Findings) > 0 {
		fmt.Printf("\n⏳ Phase 2: Auth bypass testing on %d zombie findings...\n", len(phase1Findings))
		authBypass := &strategies.AuthBypass{}
		bypassProbes := authBypass.GenerateProbesFromFindings(phase1Findings, e.cfg)
		if len(bypassProbes) > 0 {
			phase2Findings = e.executeAuthBypassProbes(ctx, bypassProbes)
			fmt.Printf("✓ Phase 2 complete: %d findings\n", len(phase2Findings))
		}
	}

	// Combine all findings
	allFindings := append(phase1Findings, phase2Findings...)

	// Update scan metadata
	scan.CompletedAt = time.Now().UTC()
	scan.FindingsCount = len(allFindings)
	scan.ProbesSent = len(allProbes)
	scan.Status = "completed"
	scan.Strategies = e.cfg.Strategies

	// Persist to graph
	if err := e.persistResults(ctx, scan, allFindings); err != nil {
		fmt.Printf("  ⚠ Failed to persist results to Memgraph: %v\n", err)
	}

	return scan, allFindings, nil
}

func (e *Engine) resolveStrategies() []Strategy {
	wanted := make(map[string]bool)
	if len(e.cfg.Strategies) == 0 {
		// All strategies
		for _, s := range model.AllStrategies {
			wanted[s] = true
		}
	} else {
		for _, s := range e.cfg.Strategies {
			wanted[s] = true
		}
	}

	var active []Strategy
	registry := []Strategy{
		&strategies.DeprecatedAlive{},
		&strategies.VersionProbe{},
		&strategies.MethodProbe{},
		&strategies.ShadowPath{},
		// AuthBypass is handled separately in Phase 2
	}

	for _, strat := range registry {
		if wanted[strat.Name()] {
			active = append(active, strat)
		}
	}

	// Add a placeholder for auth bypass tracking
	if wanted[model.StrategyAuthBypass] {
		active = append(active, &authBypassPlaceholder{})
	}

	return active
}

func (e *Engine) isStrategyActive(name string) bool {
	if len(e.cfg.Strategies) == 0 {
		return true
	}
	for _, s := range e.cfg.Strategies {
		if s == name {
			return true
		}
	}
	return false
}

func (e *Engine) executeProbes(ctx context.Context, probes []*model.Probe) []*model.Finding {
	probeCh := make(chan *model.Probe, len(probes))
	resultCh := make(chan *model.Finding, len(probes))

	// Feed probes
	for _, p := range probes {
		probeCh <- p
	}
	close(probeCh)

	// Progress tracking
	var completed int64
	total := int64(len(probes))

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < e.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for probe := range probeCh {
				// Rate limit
				if err := e.limiter.Wait(ctx); err != nil {
					return
				}

				result := e.httpClient.SendProbe(ctx, probe)
				n := atomic.AddInt64(&completed, 1)

				if e.cfg.Verbose && result.Error == nil {
					fmt.Printf("  [%d/%d] %s %s → %d (%s)\n",
						n, total, probe.Method, probe.Path, result.StatusCode, result.Duration.Round(time.Millisecond))
				} else if e.cfg.Verbose && result.Error != nil {
					fmt.Printf("  [%d/%d] %s %s → ERR: %v\n",
						n, total, probe.Method, probe.Path, result.Error)
				}

				if finding := Analyze(ctx, result, e.baseline, e.graphClient); finding != nil {
					resultCh <- finding
				}
			}
		}()
	}

	// Wait for all workers then close results
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect findings
	var findings []*model.Finding
	for f := range resultCh {
		findings = append(findings, f)
	}
	return findings
}

func (e *Engine) executeAuthBypassProbes(ctx context.Context, probes []*model.Probe) []*model.Finding {
	probeCh := make(chan *model.Probe, len(probes))
	resultCh := make(chan *model.Finding, len(probes))

	for _, p := range probes {
		probeCh <- p
	}
	close(probeCh)

	var wg sync.WaitGroup
	for i := 0; i < e.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for probe := range probeCh {
				if err := e.limiter.Wait(ctx); err != nil {
					return
				}
				// Use the no-auth HTTP client
				result := e.noAuthHTTP.SendProbe(ctx, probe)

				if e.cfg.Verbose {
					if result.Error == nil {
						fmt.Printf("  [auth-bypass] %s %s → %d\n", probe.Method, probe.Path, result.StatusCode)
					} else {
						fmt.Printf("  [auth-bypass] %s %s → ERR: %v\n", probe.Method, probe.Path, result.Error)
					}
				}

				if finding := Analyze(ctx, result, e.baseline, e.graphClient); finding != nil {
					resultCh <- finding
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var findings []*model.Finding
	for f := range resultCh {
		findings = append(findings, f)
	}
	return findings
}

func (e *Engine) persistResults(ctx context.Context, scan *model.Scan, findings []*model.Finding) error {
	if err := e.graphClient.WriteScan(ctx, scan); err != nil {
		return fmt.Errorf("writing scan: %w", err)
	}

	for _, f := range findings {
		if err := e.graphClient.WriteFinding(ctx, f, scan.ID); err != nil {
			return fmt.Errorf("writing finding %s: %w", f.ID, err)
		}
	}
	return nil
}

func (e *Engine) printDryRun(probes []*model.Probe) {
	fmt.Printf("\n🔍 Dry Run — %d probes would be sent:\n\n", len(probes))

	// Group by strategy
	byStrategy := make(map[string][]*model.Probe)
	for _, p := range probes {
		byStrategy[p.Strategy] = append(byStrategy[p.Strategy], p)
	}

	for strategy, stratProbes := range byStrategy {
		fmt.Printf("  [%s] (%d probes)\n", strategy, len(stratProbes))
		limit := 10
		if len(stratProbes) < limit {
			limit = len(stratProbes)
		}
		for _, p := range stratProbes[:limit] {
			fmt.Printf("    %s %s\n", p.Method, p.URL)
		}
		if len(stratProbes) > limit {
			fmt.Printf("    ... and %d more\n", len(stratProbes)-limit)
		}
		fmt.Println()
	}
}

// authBypassPlaceholder implements Strategy for registration purposes.
// The actual probe generation happens in Phase 2 via GenerateProbesFromFindings.
type authBypassPlaceholder struct{}

func (a *authBypassPlaceholder) Name() string { return model.StrategyAuthBypass }
func (a *authBypassPlaceholder) GenerateProbes(_ context.Context, _ *graph.Client, _ *model.ScanConfig) ([]*model.Probe, error) {
	return nil, nil
}

// determineBaseline sends a request to a guaranteed non-existent path to see how the server responds
func (e *Engine) determineBaseline(ctx context.Context) {
	fmt.Println("⏳ Determining baseline response for non-existent paths...")
	dummyPath := "/sentry-baseline-not-found-" + uuid.New().String()
	probe := &model.Probe{
		URL:      e.cfg.Target + dummyPath,
		Path:     dummyPath,
		Method:   "GET",
		Strategy: "baseline",
		Headers:  e.cfg.Headers,
	}
	
	// Bypass limiter for the single baseline check
	result := e.httpClient.SendProbe(ctx, probe)
	e.baseline = result

	if result.Error == nil {
		fmt.Printf("  ✓ Baseline determined: Status %d, Length %d bytes\n", result.StatusCode, len(result.Body))
	} else {
		fmt.Printf("  ⚠ Baseline determination failed: %v\n", result.Error)
	}
}

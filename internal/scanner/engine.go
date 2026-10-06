package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/scanner/strategies"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

type Strategy interface {
	Name() string
	GenerateProbes(context.Context, *graph.Client, *model.ScanConfig) ([]*model.Probe, error)
}
type Engine struct {
	traceMu                sync.Mutex
	traceErr               error
	scanID                 string
	scanStarted            time.Time
	phase                  string
	planned                atomic.Int64
	completed              atomic.Int64
	controls               atomic.Int64
	findingsCount          atomic.Int64
	lastProgress           time.Time
	requestErrors          atomic.Int64
	budgetExhausted        atomic.Bool
	cfg                    *model.ScanConfig
	graphClient            *graph.Client
	httpClient, noAuthHTTP *HTTPClient
	limiter                *rate.Limiter
	sent                   atomic.Int64
	baselines              map[string][]*model.ProbeResult
}

func NewEngine(cfg *model.ScanConfig, g *graph.Client) *Engine {
	return &Engine{cfg: cfg, graphClient: g, httpClient: NewHTTPClient(cfg), noAuthHTTP: NewHTTPClientWithoutAuth(cfg), limiter: rate.NewLimiter(rate.Limit(max(cfg.RPS, 1)), 1), baselines: map[string][]*model.ProbeResult{}}
}
func ValidateConfig(cfg *model.ScanConfig) error {
	u, err := url.Parse(cfg.Target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("target must be an HTTP(S) base URL without credentials, query, or fragment")
	}
	if cfg.Workers < 1 || cfg.Workers > 64 || cfg.RPS < 1 || cfg.RPS > 1000 {
		return fmt.Errorf("workers must be 1–64 and rps 1–1000")
	}
	if cfg.MaxRequests < 0 {
		return fmt.Errorf("max requests must be nonnegative")
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	for _, wanted := range cfg.Strategies {
		found := false
		for _, name := range model.AllStrategies {
			if wanted == name {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("unknown strategy %q", wanted)
		}
	}
	return nil
}
func (e *Engine) Run(ctx context.Context) (*model.Scan, []*model.Finding, error) {
	scan := &model.Scan{ID: e.cfg.ID, Target: e.cfg.Target, SpecTitle: e.cfg.SpecTitle, SpecVersion: e.cfg.SpecVer, StartedAt: time.Now().UTC(), Status: "running", Strategies: e.cfg.Strategies, TraceVersion: e.traceVersion(), SelectedOperations: e.cfg.SelectedOperations}
	if scan.ID == "" {
		scan.ID = uuid.NewString()
	}
	if err := ValidateConfig(e.cfg); err != nil {
		return scan, nil, err
	}
	if len(scan.Strategies) == 0 {
		scan.Strategies = append([]string{}, model.AllStrategies...)
	}
	if e.graphClient == nil {
		return scan, nil, fmt.Errorf("inventory graph is required")
	}
	ops, err := e.graphClient.ReadOperationsWithPaths(ctx, e.cfg.SpecTitle, e.cfg.SpecVer)
	if err != nil {
		return scan, nil, err
	}
	e.cfg.ID = scan.ID
	return e.RunWithOperations(ctx, ops)
}

func (e *Engine) RunWithOperations(ctx context.Context, ops []graph.OperationWithPath) (*model.Scan, []*model.Finding, error) {
	scan := &model.Scan{ID: e.cfg.ID, Target: e.cfg.Target, SpecTitle: e.cfg.SpecTitle, SpecVersion: e.cfg.SpecVer, StartedAt: time.Now().UTC(), Status: "running", Strategies: e.cfg.Strategies, TraceVersion: e.traceVersion(), SelectedOperations: e.cfg.SelectedOperations}
	if scan.ID == "" {
		scan.ID = uuid.NewString()
	}
	if err := ValidateConfig(e.cfg); err != nil {
		return scan, nil, err
	}
	if len(scan.Strategies) == 0 {
		scan.Strategies = append([]string{}, model.AllStrategies...)
	}
	scopes := map[string]bool{}
	for _, op := range ops {
		scopes[model.OperationKey(op.SpecTitle, op.SpecVersion, "", "")] = true
	}
	if len(scopes) != 1 {
		return scan, nil, fmt.Errorf("select exactly one spec and version; matched %d inventories", len(scopes))
	}
	scan.SpecTitle, scan.SpecVersion = ops[0].SpecTitle, ops[0].SpecVersion
	e.cfg.SpecTitle, e.cfg.SpecVer = scan.SpecTitle, scan.SpecVersion
	e.scanID = scan.ID
	e.scanStarted = scan.StartedAt
	e.phase = "planning"
	if err := ValidateSelection(ops, e.cfg); err != nil {
		return scan, nil, err
	}
	probes := strategies.Plan(ops, e.cfg)
	e.planned.Store(int64(len(probes)))
	conditional := map[string]*model.Probe{}
	for _, p := range probes {
		e.record(e.requestRecord(p, false))
		if e.active(model.StrategyAuthBypass) && p.Strategy == model.StrategyDeprecatedAlive && p.Meta["requires_auth"] == "true" && e.hasCredentials(p) {
			b := *p
			b.ID = uuid.NewString()
			b.Strategy = model.StrategyAuthBypass
			b.Meta = copyMeta(p.Meta)
			b.Meta["compared_request_id"] = p.ID
			conditional[p.ID] = &b
			r := e.requestRecord(&b, true)
			r.Conditional = true
			r.Reason = "Runs if the authenticated check produces eligible evidence"
			e.record(r)
			e.planned.Add(1)
		}
	}
	e.progress(true)
	if e.cfg.DisableSchema {
		for _, p := range probes {
			delete(p.Meta, "responses_schema")
		}
	}
	if e.cfg.DryRun {
		for _, p := range probes {
			fmt.Printf("%s %s [%s]\n", p.Method, model.SafeProbeURL(p), p.Strategy)
		}
		scan.Status = "dry_run"
		scan.PlannedChecks = int(e.planned.Load())
		scan.Phase = "planned"
		scan.CompletedAt = time.Now().UTC()
		return scan, nil, nil
	}
	e.setPhase("baseline")
	e.prepareBaselines(ctx, probes, false)
	e.setPhase("checks")
	findings, results := e.execute(ctx, probes, false)
	if e.active(model.StrategyAuthBypass) {
		bypass := []*model.Probe{}
		for _, r := range results {
			if r.Probe.Strategy != model.StrategyDeprecatedAlive || r.Probe.Meta["requires_auth"] != "true" || !e.hasCredentials(r.Probe) {
				continue
			}
			if Analyze(ctx, r, e.baseline(r, false), nil) == nil {
				continue
			}
			original := r.Probe
			p := *original
			if scheduled := conditional[original.ID]; scheduled != nil {
				p.ID = scheduled.ID
				delete(conditional, original.ID)
			} else {
				p.ID = uuid.NewString()
			}
			p.Strategy = model.StrategyAuthBypass
			p.Headers = map[string]string{}
			for k, v := range original.Headers {
				p.Headers[k] = v
			}
			p.Meta = map[string]string{}
			for k, v := range original.Meta {
				p.Meta[k] = v
			}
			p.Meta["authenticated"] = "true"
			p.Meta["compared_request_id"] = original.ID
			b, _ := json.Marshal(r)
			p.Meta["authenticated_response"] = string(b)
			e.stripCredentials(&p)
			bypass = append(bypass, &p)
		}
		e.setPhase("authentication")
		e.prepareBaselines(ctx, bypass, true)
		additional, _ := e.execute(ctx, bypass, true)
		findings = append(findings, additional...)
	}
	for _, p := range conditional {
		r := e.requestRecord(p, true)
		r.Conditional = true
		r.Outcome = "skipped"
		r.Reason = "Authenticated response did not meet verification prerequisites"
		e.record(r)
		e.completed.Add(1)
	}
	sortedFindings(findings)
	scan.CompletedAt = time.Now().UTC()
	scan.ProbesSent = int(e.sent.Load())
	scan.PlannedChecks = int(e.planned.Load())
	scan.CompletedChecks = int(e.completed.Load())
	scan.BaselineRequests = int(e.controls.Load())
	scan.Phase = "finished"
	scan.RequestErrors = int(e.requestErrors.Load())
	scan.FindingsCount = len(findings)
	scan.Status = "completed"
	if scan.RequestErrors > 0 {
		scan.Status = "partial"
		scan.Error = "Some requests failed; detection coverage is incomplete"
	}
	if e.budgetExhausted.Load() {
		scan.Status = "budget_exhausted"
		scan.Error = "Request budget exhausted; scan coverage is incomplete"
	}
	if ctx.Err() != nil {
		scan.Status = "cancelled"
		scan.Error = ctx.Err().Error()
	}
	for _, f := range findings {
		f.ScanID = scan.ID
	}
	if e.traceErr != nil {
		scan.Status = "failed"
		scan.Error = "Request history could not be persisted: " + e.traceErr.Error()
		return scan, findings, e.traceErr
	}
	if e.graphClient == nil {
		return scan, findings, ctx.Err()
	}
	persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.graphClient.WriteScan(persistCtx, scan); err != nil {
		scan.Status = "failed"
		scan.Error = err.Error()
		return scan, findings, err
	}
	for _, f := range findings {
		if err := e.graphClient.WriteFinding(persistCtx, f, scan.ID); err != nil {
			scan.Status = "failed"
			scan.Error = err.Error()
			return scan, findings, err
		}
	}
	return scan, findings, ctx.Err()
}
func (e *Engine) active(name string) bool {
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
func baselineKey(p *model.Probe, noAuth bool) string {
	u, _ := url.Parse(p.URL)
	return fmt.Sprintf("%s://%s%s|%s|%t", u.Scheme, u.Host, u.Path[:strings.LastIndex(u.Path, "/")+1], p.Method, noAuth)
}
func (e *Engine) prepareBaselines(ctx context.Context, probes []*model.Probe, noAuth bool) {
	for _, p := range probes {
		key := baselineKey(p, noAuth)
		if _, ok := e.baselines[key]; ok {
			continue
		}
		e.baselines[key] = nil
		u, _ := url.Parse(p.URL)
		prefix := u.Path[:strings.LastIndex(u.Path, "/")+1]
		for i := 0; i < 3; i++ {
			b := *p
			b.ID = uuid.NewString()
			b.Origins = nil
			for _, related := range probes {
				if baselineKey(related, noAuth) == key {
					for _, origin := range related.Origins {
						found := false
						for _, prev := range b.Origins {
							if prev.Key == origin.Key {
								found = true
							}
						}
						if !found {
							b.Origins = append(b.Origins, origin)
						}
					}
				}
			}
			b.Strategy = "baseline"
			v := *u
			v.Path = prefix + "sentry-not-found-" + uuid.NewString()
			v.RawQuery = ""
			b.URL = v.String()
			b.Path = v.Path
			e.record(e.requestRecord(&b, noAuth))
			r := e.send(ctx, &b, noAuth)
			rec := e.requestRecord(&b, noAuth)
			e.finishRecord(rec, r)
			rec.Reason = "Nonexistent-route control for response comparison"
			e.record(rec)
			e.progress(false)
			e.baselines[key] = append(e.baselines[key], r)
		}
	}
}
func (e *Engine) baseline(r *model.ProbeResult, noAuth bool) *model.ProbeResult {
	if e.cfg.DisableCatchAll {
		return nil
	}
	for _, b := range e.baselines[baselineKey(r.Probe, noAuth)] {
		if isCatchAll(r, b) {
			return b
		}
	}
	return nil
}
func (e *Engine) send(ctx context.Context, p *model.Probe, noAuth bool) *model.ProbeResult {
	e.traceMu.Lock()
	failed := e.traceErr != nil
	e.traceMu.Unlock()
	if failed {
		return &model.ProbeResult{Probe: p, Error: fmt.Errorf("request history unavailable")}
	}
	if err := e.limiter.Wait(ctx); err != nil {
		return &model.ProbeResult{Probe: p, Error: err}
	}
	for {
		n := e.sent.Load()
		if e.cfg.MaxRequests > 0 && n >= int64(e.cfg.MaxRequests) {
			e.budgetExhausted.Store(true)
			return &model.ProbeResult{Probe: p, Error: fmt.Errorf("request budget exhausted")}
		}
		if e.sent.CompareAndSwap(n, n+1) {
			break
		}
	}
	client := e.httpClient
	if noAuth {
		client = e.noAuthHTTP
	}
	r := client.SendProbe(ctx, p)
	r.Sent = true
	if p.Strategy == "baseline" {
		e.controls.Add(1)
	}
	if r.Error != nil {
		e.requestErrors.Add(1)
	}
	return r
}
func (e *Engine) execute(ctx context.Context, probes []*model.Probe, noAuth bool) ([]*model.Finding, []*model.ProbeResult) {
	jobs := make(chan *model.Probe)
	var wg sync.WaitGroup
	var mu sync.Mutex
	findings := []*model.Finding{}
	results := []*model.ProbeResult{}
	for i := 0; i < e.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				r := e.send(ctx, p, noAuth)
				baseline := e.baseline(r, noAuth)
				f := Analyze(ctx, r, baseline, nil)
				rec := e.requestRecord(p, noAuth)
				e.finishRecord(rec, r)
				for _, b := range e.baselines[baselineKey(p, noAuth)] {
					rec.BaselineIDs = append(rec.BaselineIDs, b.Probe.ID)
				}
				if f != nil {
					evidenceResult := *r
					evidenceResult.Body = model.RedactBody(r.Body, e.secrets(p))
					f.Evidence = model.FormatEvidence(&evidenceResult)
					f.RequestID = p.ID
					f.Origins = p.Origins
					rec.Outcome = "finding"
					rec.Reason = f.Description
					rec.SchemaResult = f.SchemaResult
					rec.FindingIDs = []string{f.ID}
					e.findingsCount.Add(1)
				} else if r.Error == nil {
					rec.Outcome, rec.Reason = ExplainOutcome(r, baseline)
					rec.SchemaResult, _ = InspectSchema(p.Meta["responses_schema"], r.StatusCode, contentType(r), r.Body, r.Truncated)
				}
				e.record(rec)
				e.completed.Add(1)
				e.progress(false)
				mu.Lock()
				results = append(results, r)
				if f != nil {
					findings = append(findings, f)
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, p := range probes {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	for _, p := range probes {
		seen := false
		for _, r := range results {
			if r.Probe.ID == p.ID {
				seen = true
				break
			}
		}
		if !seen {
			rec := e.requestRecord(p, noAuth)
			rec.Outcome = "skipped"
			rec.Reason = "Scan cancelled before this check started"
			e.record(rec)
			e.completed.Add(1)
		}
	}
	return findings, results
}
func (e *Engine) hasCredentials(p *model.Probe) bool {
	names := append([]string{"Authorization", "X-API-Key", "X-Auth-Token", "Cookie"}, strings.Split(p.Meta["auth_headers"], ",")...)
	for _, name := range names {
		for k, v := range e.cfg.Headers {
			if strings.EqualFold(k, name) && v != "" {
				return true
			}
		}
		for k, v := range p.Headers {
			if strings.EqualFold(k, name) && v != "" {
				return true
			}
		}
	}
	u, _ := url.Parse(p.URL)
	for _, name := range strings.Split(p.Meta["auth_query"], ",") {
		if name != "" && u.Query().Get(name) != "" {
			return true
		}
	}
	return false
}
func (e *Engine) stripCredentials(p *model.Probe) {
	for _, k := range []string{"Authorization", "X-API-Key", "X-Auth-Token", "Cookie"} {
		p.Headers[k] = ""
	}
	// Names of custom API keys come from the inventory. Populated by scan configuration when needed.
	for _, k := range strings.Split(p.Meta["auth_headers"], ",") {
		if k != "" {
			p.Headers[k] = ""
		}
	}
	u, _ := url.Parse(p.URL)
	q := u.Query()
	for _, k := range strings.Split(p.Meta["auth_query"], ",") {
		q.Del(k)
	}
	u.RawQuery = q.Encode()
	p.URL = u.String()
}

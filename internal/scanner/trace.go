package scanner

import (
	"context"
	"fmt"
	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/scanner/strategies"
	"net/url"
	"strings"
	"time"
)

func copyMeta(source map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range source {
		out[k] = v
	}
	return out
}
func ValidateSelection(ops []graph.OperationWithPath, cfg *model.ScanConfig) error {
	for _, wanted := range cfg.SelectedOperations {
		found := false
		for _, op := range ops {
			if op.Method == wanted.Method && op.PathTemplate == wanted.Path {
				found = true
			}
		}
		for _, op := range cfg.PassiveCandidates {
			if op.Method == wanted.Method && op.Path == wanted.Path {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("selected operation %s %s is absent from this inventory and its observed candidates", wanted.Method, wanted.Path)
		}
	}
	return nil
}
func (e *Engine) requestRecord(p *model.Probe, noAuth bool) *model.RequestRecord {
	headers := map[string]string{"User-Agent": "Sentry-DAST/0.1.0", "Accept": "*/*"}
	for k, v := range e.cfg.Headers {
		headers[k] = v
	}
	for k, v := range p.Headers {
		if v == "" {
			delete(headers, k)
		} else {
			headers[k] = v
		}
	}
	names := append([]string{"Authorization", "X-API-Key", "X-Auth-Token", "Cookie"}, strings.Split(p.Meta["auth_headers"], ",")...)
	if noAuth {
		for k := range headers {
			for _, name := range names {
				if strings.EqualFold(k, name) {
					delete(headers, k)
				}
			}
		}
	}
	secrets := e.secrets(p)
	for k, v := range e.cfg.Headers {
		for _, name := range names {
			if strings.EqualFold(k, name) {
				secrets = append(secrets, v)
			}
		}
	}
	for k, v := range p.Headers {
		for _, name := range names {
			if strings.EqualFold(k, name) {
				secrets = append(secrets, v)
			}
		}
	}
	body, truncated := model.PreviewBody(model.RedactBody(p.Body, secrets), 4096)
	auth := "public"
	if noAuth {
		auth = "credential-free"
	} else if e.hasCredentials(p) {
		auth = "credentials supplied"
	}
	kind := "check"
	if p.Strategy == "baseline" {
		kind = "baseline"
	}
	u, _ := url.Parse(p.URL)
	return &model.RequestRecord{ID: p.ID, ScanID: e.scanID, SpecTitle: e.cfg.SpecTitle, SpecVersion: e.cfg.SpecVer, Target: e.cfg.Target, Origins: p.Origins, Method: p.Method, Path: u.Path, RouteTemplate: p.Path, URL: model.SafeProbeURL(p), Strategy: p.Strategy, Kind: kind, Outcome: "planned", Reason: "Waiting to execute", AuthContext: auth, RequestHeaders: model.RedactHeaders(headers, names), ResponseHeaders: map[string]string{}, RequestBody: body, RequestTruncated: truncated, BaselineIDs: []string{}, FindingIDs: []string{}, ComparedRequestID: p.Meta["compared_request_id"], SchemaResult: SchemaUnavailable}
}
func (e *Engine) finishRecord(rec *model.RequestRecord, r *model.ProbeResult) {
	rec.Sent = r.Sent
	rec.CompletedAt = time.Now().UTC()
	rec.StartedAt = rec.CompletedAt.Add(-r.Duration)
	rec.DurationMS = float64(r.Duration.Microseconds()) / 1000
	rec.StatusCode = r.StatusCode
	headers := map[string]string{}
	for k, v := range r.Headers {
		headers[k] = strings.Join(v, ", ")
	}
	rec.ResponseHeaders = model.RedactHeaders(headers, nil)
	secrets := e.secrets(r.Probe)
	rec.ResponseBody, rec.ResponseTruncated = model.PreviewBody(model.RedactBody(r.Body, secrets), 16384)
	rec.ResponseTruncated = rec.ResponseTruncated || r.Truncated
	if !r.Sent {
		rec.Outcome = "skipped"
		rec.Reason = "Request was not sent (cancellation, request budget, or persistence failure)"
	} else if r.Error != nil {
		rec.Outcome = "error"
		rec.Reason = model.RedactBody(strings.ReplaceAll(r.Error.Error(), r.Probe.URL, model.SafeProbeURL(r.Probe)), secrets)
	} else {
		rec.Outcome = "no_finding"
		rec.Reason = "No finding from this check"
	}
}
func ExplainOutcome(r, b *model.ProbeResult) (string, string) {
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return "no_finding", "HTTP response did not meet the successful-response criteria"
	}
	if isCatchAll(r, b) {
		return "suppressed", "Response matches a nonexistent-route control"
	}
	if r.Probe.Strategy == model.StrategyMethodProbe && (r.Probe.Method == "HEAD" || r.Probe.Method == "OPTIONS") {
		return "no_finding", "HEAD/OPTIONS success alone does not establish an undocumented operation"
	}
	if r.Probe.Strategy == model.StrategyAuthBypass {
		return "no_finding", "Credential-free response was not equivalent to eligible authenticated content"
	}
	return "no_finding", "No finding from this check"
}
func (e *Engine) record(r *model.RequestRecord) {
	if e.cfg.RecordRequest == nil {
		return
	}
	e.traceMu.Lock()
	defer e.traceMu.Unlock()
	if e.traceErr != nil {
		return
	}
	if err := e.cfg.RecordRequest(r); err != nil {
		e.traceErr = err
	}
}
func (e *Engine) setPhase(phase string) {
	e.traceMu.Lock()
	e.phase = phase
	e.traceMu.Unlock()
	e.progress(true)
}
func (e *Engine) progress(force bool) {
	if e.cfg.RecordProgress == nil {
		return
	}
	e.traceMu.Lock()
	defer e.traceMu.Unlock()
	if !force && time.Since(e.lastProgress) < time.Second {
		return
	}
	e.lastProgress = time.Now()
	scan := &model.Scan{ID: e.scanID, Target: e.cfg.Target, SpecTitle: e.cfg.SpecTitle, SpecVersion: e.cfg.SpecVer, StartedAt: e.scanStarted, Status: "running", TraceVersion: e.traceVersion(), SelectedOperations: e.cfg.SelectedOperations, Strategies: e.cfg.Strategies, Phase: e.phase, PlannedChecks: int(e.planned.Load()), CompletedChecks: int(e.completed.Load()), ProbesSent: int(e.sent.Load()), BaselineRequests: int(e.controls.Load()), RequestErrors: int(e.requestErrors.Load()), FindingsCount: int(e.findingsCount.Load())}
	if err := e.cfg.RecordProgress(scan); err != nil && e.traceErr == nil {
		e.traceErr = err
	}
}

// Preview executes the production planner without sending HTTP requests.
func (e *Engine) Preview(ctx context.Context, ops []graph.OperationWithPath) ([]*model.RequestRecord, error) {
	if err := ValidateConfig(e.cfg); err != nil {
		return nil, err
	}
	if err := ValidateSelection(ops, e.cfg); err != nil {
		return nil, err
	}
	e.scanID = "preview"
	out := []*model.RequestRecord{}
	probes := strategies.Plan(ops, e.cfg)
	controls := map[string]bool{}
	for _, p := range probes {
		out = append(out, e.requestRecord(p, false))
		key := baselineKey(p, false)
		if !controls[key] {
			controls[key] = true
			for i := 0; i < 3; i++ {
				b := *p
				b.ID = fmt.Sprintf("control-%d-%d", len(out), i)
				b.Strategy = "baseline"
				b.URL = baselinePreviewURL(p.URL)
				r := e.requestRecord(&b, false)
				r.Reason = "Nonexistent-route control; randomized path at execution"
				out = append(out, r)
			}
		}
		if e.active(model.StrategyAuthBypass) && p.Strategy == model.StrategyDeprecatedAlive && p.Meta["requires_auth"] == "true" && e.hasCredentials(p) {
			b := *p
			b.ID = "conditional-" + p.ID
			b.Strategy = model.StrategyAuthBypass
			r := e.requestRecord(&b, true)
			r.Conditional = true
			r.Reason = "Conditional on eligible authenticated evidence"
			out = append(out, r)
			key = baselineKey(p, true)
			if !controls[key] {
				controls[key] = true
				for i := 0; i < 3; i++ {
					b.Strategy = "baseline"
					b.ID = fmt.Sprintf("auth-control-%d-%d", len(out), i)
					b.URL = baselinePreviewURL(p.URL)
					r = e.requestRecord(&b, true)
					r.Conditional = true
					r.Reason = "Conditional credential-free control"
					out = append(out, r)
				}
			}
		}
	}
	return out, nil
}

func baselinePreviewURL(raw string) string {
	u, _ := url.Parse(raw)
	u.Path = u.Path[:strings.LastIndex(u.Path, "/")+1] + "sentry-not-found-{random}"
	u.RawQuery = ""
	return u.String()
}

func (e *Engine) secrets(p *model.Probe) []string {
	names := strings.Split(p.Meta["auth_headers"], ",")
	out := []string{}
	for k, v := range e.cfg.Headers {
		match := model.SensitiveName(k)
		for _, name := range names {
			if strings.EqualFold(name, k) {
				match = true
			}
		}
		if match {
			out = append(out, v)
		}
	}
	for k, v := range p.Headers {
		match := model.SensitiveName(k)
		for _, name := range names {
			if strings.EqualFold(name, k) {
				match = true
			}
		}
		if match {
			out = append(out, v)
		}
	}
	u, _ := url.Parse(p.URL)
	for name, values := range u.Query() {
		match := model.SensitiveName(name)
		for _, extra := range strings.Split(p.Meta["auth_query"], ",") {
			if name == extra {
				match = true
			}
		}
		if match {
			out = append(out, values...)
		}
	}
	return out
}

func (e *Engine) traceVersion() int {
	if e.cfg.RecordRequest != nil {
		return 1
	}
	return 0
}

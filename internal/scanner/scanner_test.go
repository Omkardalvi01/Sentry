package scanner

import (
	"context"
	"encoding/json"
	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const responseSchema = `{"200":{"content":{"application/json":{"schema":{"type":"object","required":["data"],"properties":{"data":{"type":"string"}}}}}}}`

func result(body string) *model.ProbeResult {
	return &model.ProbeResult{Probe: &model.Probe{Method: "GET", Path: "/v1/users", Strategy: model.StrategyDeprecatedAlive, Meta: map[string]string{"responses_schema": responseSchema}}, StatusCode: 200, Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: body}
}
func TestSchemaStates(t *testing.T) {
	for _, tc := range []struct {
		schema, body, want string
		truncated          bool
	}{{responseSchema, `{"data":"ok"}`, SchemaMatched, false}, {responseSchema, `{"error":"no"}`, SchemaMismatched, false}, {"", `{}`, SchemaUnavailable, false}, {responseSchema, `{"data":`, SchemaTruncated, true}} {
		got, _ := InspectSchema(tc.schema, 200, "application/json; charset=utf-8", tc.body, tc.truncated)
		if got != tc.want {
			t.Fatal(got, tc)
		}
	}
}
func TestSchemaConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, err := InspectSchema(responseSchema, 200, "application/json", `{"data":"ok"}`, false)
			if err != nil || state != SchemaMatched {
				t.Error(state, err)
			}
		}()
	}
	wg.Wait()
}
func TestFindingEvidence(t *testing.T) {
	r := result(`{"data":"deprecated is a field value"}`)
	f := Analyze(context.Background(), r, nil, nil)
	if f == nil || f.Severity == model.SeverityCritical {
		t.Fatal(f)
	}
	r.StatusCode = 302
	if Analyze(context.Background(), r, nil, nil) != nil {
		t.Fatal("redirect classified")
	}
	r.StatusCode = 401
	r.Probe.Strategy = model.StrategyMethodProbe
	if Analyze(context.Background(), r, nil, nil) != nil {
		t.Fatal("401 is not method acceptance")
	}
}
func TestCatchAllDoesNotUseLength(t *testing.T) {
	a := result(`{"data":"abc"}`)
	b := result(`{"error":"x"}`)
	if isCatchAll(a, b) {
		t.Fatal("equal length differs semantically")
	}
	a.Body = `{"error":"missing","request_id":"abc"}`
	b.Body = `{"error":"missing","request_id":"xyz"}`
	if !isCatchAll(a, b) {
		t.Fatal("dynamic IDs should normalize")
	}
}
func TestAuthComparison(t *testing.T) {
	r := result(`{"data":"ok"}`)
	r.Probe.Strategy = model.StrategyAuthBypass
	r.Probe.Meta["requires_auth"] = "true"
	r.Probe.Meta["authenticated"] = "true"
	authenticated := result(`{"data":"ok"}`)
	b, _ := json.Marshal(authenticated)
	r.Probe.Meta["authenticated_response"] = string(b)
	if Analyze(context.Background(), r, nil, nil) == nil {
		t.Fatal("expected exposure")
	}
	r.Body = `{"data":"login"}`
	if Analyze(context.Background(), r, nil, nil) != nil {
		t.Fatal("login response differs")
	}
	r.Probe.Meta["requires_auth"] = "false"
	if Analyze(context.Background(), r, nil, nil) != nil {
		t.Fatal("public operation")
	}
}
func TestLargeBodyAndLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":"` + strings.Repeat("x", 2048) + `"}`))
	}))
	defer server.Close()
	cfg := &model.ScanConfig{Timeout: time.Second}
	p := model.MakeProbe(server.URL, "/", "GET", "test", nil)
	r := NewHTTPClient(cfg).SendProbe(context.Background(), p)
	state, _ := InspectSchema(responseSchema, r.StatusCode, contentType(r), r.Body, r.Truncated)
	if state != SchemaMatched {
		t.Fatal(state)
	}
	cfg.MaxResponseBytes = 512
	r = NewHTTPClient(cfg).SendProbe(context.Background(), p)
	if !r.Truncated {
		t.Fatal("missing truncation")
	}
}
func TestDryRunZeroRequests(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	cfg := &model.ScanConfig{Target: server.URL, Workers: 2, RPS: 10, Timeout: time.Second, DryRun: true}
	ops := []graph.OperationWithPath{{Operation: model.Operation{SpecTitle: "test", SpecVersion: "1", Method: "GET", Deprecated: true}, PathTemplate: "/old"}}
	scan, _, err := NewEngine(cfg, nil).RunWithOperations(context.Background(), ops)
	if err != nil || requests.Load() != 0 || scan.Status != "dry_run" || scan.ProbesSent != 0 {
		t.Fatal(scan, err, requests.Load())
	}
}
func TestActualScanCountAndAuth(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/old" {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"missing"}`))
			return
		}
		w.Write([]byte(`{"data":"ok"}`))
	}))
	defer server.Close()
	cfg := &model.ScanConfig{Target: server.URL, Workers: 2, RPS: 1000, Timeout: time.Second, Headers: map[string]string{"Authorization": "Bearer test"}, Strategies: []string{model.StrategyDeprecatedAlive, model.StrategyAuthBypass}}
	ops := []graph.OperationWithPath{{Operation: model.Operation{SpecTitle: "test", SpecVersion: "1", Method: "GET", Deprecated: true, Security: `[{"bearer":[]}]`, Responses: responseSchema}, PathTemplate: "/old"}}
	scan, findings, err := NewEngine(cfg, nil).RunWithOperations(context.Background(), ops)
	if err != nil || len(findings) != 2 || int64(scan.ProbesSent) != requests.Load() || scan.ProbesSent != 8 {
		t.Fatal(scan, len(findings), err, requests.Load())
	}
}

func TestTransportFailureIsPartial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target := server.URL
	server.Close()
	cfg := &model.ScanConfig{Target: target, Workers: 1, RPS: 1000, Timeout: time.Second, Strategies: []string{model.StrategyDeprecatedAlive}}
	ops := []graph.OperationWithPath{{Operation: model.Operation{SpecTitle: "test", SpecVersion: "1", Method: "GET", Deprecated: true}, PathTemplate: "/old"}}
	scan, _, err := NewEngine(cfg, nil).RunWithOperations(context.Background(), ops)
	if err != nil || scan.Status != "partial" || scan.RequestErrors != 4 {
		t.Fatal(scan, err)
	}
}

func TestRequestBudgetIncludesBaseline(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(404) }))
	defer server.Close()
	cfg := &model.ScanConfig{Target: server.URL, Workers: 8, RPS: 1000, Timeout: time.Second, MaxRequests: 2, Strategies: []string{model.StrategyDeprecatedAlive}}
	ops := []graph.OperationWithPath{{Operation: model.Operation{SpecTitle: "test", SpecVersion: "1", Method: "GET", Deprecated: true}, PathTemplate: "/old"}}
	scan, _, err := NewEngine(cfg, nil).RunWithOperations(context.Background(), ops)
	if err != nil || scan.Status != "budget_exhausted" || scan.ProbesSent != 2 || requests.Load() != 2 {
		t.Fatal(scan, err, requests.Load())
	}
}

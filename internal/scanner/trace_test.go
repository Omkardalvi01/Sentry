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
	"testing"
	"time"
)

func TestScopedTraceCapturesEverySentRequestAndRedacts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/protected" {
			w.Header().Set("Set-Cookie", "secret-cookie")
			w.Write([]byte(`{"data":"Bearer secret-value"}`))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()
	var mu sync.Mutex
	records := map[string]*model.RequestRecord{}
	cfg := &model.ScanConfig{Target: server.URL, Workers: 4, RPS: 1000, Timeout: time.Second, Headers: map[string]string{"Authorization": "Bearer secret-value"}, SelectedOperations: []model.ObservedOperation{{Method: "GET", Path: "/v1/protected"}}, RecordRequest: func(r *model.RequestRecord) error { mu.Lock(); defer mu.Unlock(); records[r.ID] = r; return nil }}
	ops := []graph.OperationWithPath{{Operation: model.Operation{SpecTitle: "api", SpecVersion: "1", PathTemplate: "/v1/protected", Method: "GET", Deprecated: true, Security: `[{"bearer":[]}]`, Responses: responseSchema}, PathTemplate: "/v1/protected"}, {Operation: model.Operation{SpecTitle: "api", SpecVersion: "1", PathTemplate: "/unrelated", Method: "GET"}, PathTemplate: "/unrelated"}}
	scan, findings, err := NewEngine(cfg, nil).RunWithOperations(context.Background(), ops)
	if err != nil {
		t.Fatal(err)
	}
	sent, controls := 0, 0
	for _, r := range records {
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "secret-value") || strings.Contains(string(b), "secret-cookie") {
			t.Fatal("credential leaked", string(b))
		}
		if r.Sent {
			sent++
			if r.Kind == "baseline" {
				controls++
			}
		}
		if r.Strategy == model.StrategyShadowPath {
			t.Fatal("unrelated shadow guess")
		}
		for _, origin := range r.Origins {
			if origin.Path != "/v1/protected" {
				t.Fatal(origin)
			}
		}
	}
	if sent != scan.ProbesSent || controls != scan.BaselineRequests || len(findings) != 2 {
		t.Fatal(scan, sent, controls, len(findings))
	}
	for _, f := range findings {
		if f.RequestID == "" || records[f.RequestID] == nil {
			t.Fatal("finding trace link missing")
		}
	}
}
func TestPreviewDoesNotSendHTTPAndRejectsUnknownSelection(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer server.Close()
	cfg := &model.ScanConfig{Target: server.URL, SpecTitle: "api", SpecVer: "1", Workers: 1, RPS: 10, Timeout: time.Second, SelectedOperations: []model.ObservedOperation{{Method: "GET", Path: "/v2/users"}}}
	ops := []graph.OperationWithPath{{Operation: model.Operation{SpecTitle: "api", SpecVersion: "1", PathTemplate: "/v2/users", Method: "GET"}, PathTemplate: "/v2/users"}}
	rows, err := NewEngine(cfg, nil).Preview(context.Background(), ops)
	if err != nil || len(rows) == 0 || calls != 0 {
		t.Fatal(err, len(rows), calls)
	}
	cfg.SelectedOperations[0].Path = "/missing"
	if _, err = NewEngine(cfg, nil).Preview(context.Background(), ops); err == nil {
		t.Fatal("unknown selection accepted")
	}
}

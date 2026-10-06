package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Omkardalvi01/sentry/internal/model"
	"path/filepath"
	"testing"
	"time"
)

func TestExplorerFiltersBeforePaginationAndSnapshot(t *testing.T) {
	s, err := NewTrafficStore(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	for i := 0; i < 140; i++ {
		scan := &model.Scan{ID: fmt.Sprint(i), SpecTitle: "api", SpecVersion: "1", Target: "http://local", Status: "completed", StartedAt: time.Now().Add(time.Duration(i) * time.Second)}
		f := &model.Finding{ID: fmt.Sprint(i), SpecTitle: "api", SpecVersion: "1", Method: "GET", Path: fmt.Sprintf("/item/%d", i), Severity: model.SeverityLow, Timestamp: scan.StartedAt}
		if i == 0 {
			f.Path = "/needle"
			f.Severity = model.SeverityHigh
		}
		if err = s.SaveScan(ctx, scan, []*model.Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
	q := ExplorerQuery{SpecTitle: "api", Search: "needle", Limit: 25}
	page, err := s.Explore(ctx, "findings", q)
	if err != nil || page.Total != 1 {
		t.Fatal(page, err)
	}
	q = ExplorerQuery{Limit: 25, Sort: "time", Direction: "desc"}
	first, err := s.Explore(ctx, "scans", q)
	if err != nil || first.Total != 140 {
		t.Fatal(first, err)
	}
	s.SaveScan(ctx, &model.Scan{ID: "new", StartedAt: time.Now().Add(time.Hour)}, nil)
	q.Snapshot = first.Snapshot
	q.Offset = 25
	second, err := s.Explore(ctx, "scans", q)
	if err != nil || second.Total != 140 {
		t.Fatal(second, err)
	}
	seen := map[string]bool{}
	for _, raw := range first.Items {
		var row model.Scan
		json.Unmarshal(raw, &row)
		seen[row.ID] = true
	}
	for _, raw := range second.Items {
		var row model.Scan
		json.Unmarshal(raw, &row)
		if seen[row.ID] || row.ID == "new" {
			t.Fatal("unstable pagination")
		}
	}
	q.Sort = "id;DROP TABLE scans"
	if _, err = s.Explore(ctx, "scans", q); err == nil {
		t.Fatal("unsafe sort accepted")
	}
}
func TestRequestOriginAndTrafficTargetFiltering(t *testing.T) {
	s, err := NewTrafficStore(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	origin := model.OperationRef{Key: model.OperationKey("api", "1", "GET", "/v2/users"), Method: "GET", Path: "/v2/users"}
	s.SaveScan(ctx, &model.Scan{ID: "scan", Target: "http://local", SpecTitle: "api", SpecVersion: "1"}, nil)
	s.SaveRequest(ctx, &model.RequestRecord{ID: "baseline", ScanID: "scan", Origins: []model.OperationRef{origin}, Kind: "baseline"})
	if err = s.SaveRequest(ctx, &model.RequestRecord{ID: "probe", ScanID: "scan", SpecTitle: "api", SpecVersion: "1", Target: "http://local", Method: "GET", Path: "/v1/users", Origins: []model.OperationRef{origin}, BaselineIDs: []string{"baseline"}, StatusCode: 200, Sent: true}); err != nil {
		t.Fatal(err)
	}
	page, err := s.Explore(ctx, "requests", ExplorerQuery{OperationKey: origin.Key, Limit: 25})
	if err != nil || page.Total != 2 {
		t.Fatal(page, err)
	}
	for _, id := range []string{"unknown", "known"} {
		target := ""
		if id == "known" {
			target = "http://local"
		}
		e := model.TrafficEvent{RequestID: id, SpecTitle: "api", SpecVersion: "1", Method: "GET", Path: "/v2/users", GraphPathTemplate: "/v2/users", Timestamp: time.Now(), TargetOrigin: target}
		if err = s.SavePrediction(ctx, e, "evaluated", json.RawMessage(`{"is_anomaly":false}`)); err != nil {
			t.Fatal(err)
		}
	}
	page, err = s.Explore(ctx, "traffic", ExplorerQuery{Target: "http://local/api", Limit: 25})
	if err != nil || page.Total != 1 {
		t.Fatal(page, err)
	}
	page, err = s.Explore(ctx, "traffic", ExplorerQuery{Target: "__unknown", Limit: 25})
	if err != nil || page.Total != 1 {
		t.Fatal(page, err)
	}
}

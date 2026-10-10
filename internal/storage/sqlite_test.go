package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/Omkardalvi01/sentry/internal/model"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrateAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.db")
	db, _ := sql.Open("sqlite", path)
	_, err := db.Exec(`CREATE TABLE api_traffic(id INTEGER PRIMARY KEY,request_id TEXT UNIQUE,method TEXT,path TEXT,query_params TEXT,request_headers TEXT,request_body TEXT,status_code INTEGER,response_headers TEXT,response_body TEXT,timestamp TEXT)`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := NewTrafficStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e := model.TrafficEvent{RequestID: "one", Method: "GET", Path: "/users/1", QueryParams: "page=2",
		RequestHeaders:  map[string]string{"Content-Type": "application/json"},
		ResponseHeaders: map[string]string{"Content-Length": "42"}, ResponseTimeMS: 12.5,
		ResponseSizeBytes: 42, Timestamp: time.Now().UTC()}
	if err = s.SavePrediction(context.Background(), e, "pending", json.RawMessage(`{"error":"offline"}`)); err != nil {
		t.Fatal(err)
	}
	scan := &model.Scan{ID: "scan", Status: "completed"}
	if err = s.SaveScan(context.Background(), scan, []*model.Finding{{ID: "finding", Path: "/old"}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = NewTrafficStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pending, err := s.Pending(context.Background())
	if err != nil || len(pending) != 1 {
		t.Fatal(err, len(pending))
	}
	if pending[0].QueryParams != e.QueryParams || pending[0].RequestHeaders["Content-Type"] != "application/json" ||
		pending[0].ResponseTimeMS != e.ResponseTimeMS || pending[0].ResponseSizeBytes != e.ResponseSizeBytes {
		t.Fatalf("pending event lost detector features: %+v", pending[0])
	}
	if err = s.SavePrediction(context.Background(), e, "evaluated", json.RawMessage(`{"is_anomaly":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE api_traffic SET review_label=1 WHERE request_id=?`, e.RequestID); err != nil {
		t.Fatal("review-label migration missing:", err)
	}
	rows, err := s.Traffic(context.Background(), 100, 0, true)
	if err != nil || len(rows) != 1 {
		t.Fatal(err, len(rows))
	}
	counts, _ := s.Counts(context.Background())
	if counts["api_traffic"] != 1 || counts["findings"] != 1 || counts["scans"] != 1 {
		t.Fatal(counts)
	}
}
func TestFailedBatchRollsBack(t *testing.T) {
	s, err := NewTrafficStore(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = s.InsertBatch(context.Background(), []model.TrafficEvent{{RequestID: "valid"}, {RequestID: ""}})
	if err == nil {
		t.Fatal("expected failure")
	}
	counts, _ := s.Counts(context.Background())
	if counts["api_traffic"] != 0 {
		t.Fatal("partial transaction")
	}
}

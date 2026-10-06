package dashboard

import (
	"context"
	"encoding/json"
	"github.com/Omkardalvi01/sentry/internal/model"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoryAndInputValidation(t *testing.T) {
	cfg := Config{DBPath: filepath.Join(t.TempDir(), "traffic.db"), DashboardDir: "../../dashboard", MemgraphURI: "bolt://127.0.0.1:1"}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.store.SaveScan(context.Background(), &model.Scan{ID: "persisted", Status: "running"}, nil)
	s.Close(context.Background())
	s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	handler, _ := s.Handler()
	req := httptest.NewRequest("GET", "/api/scans/persisted", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var scan model.Scan
	json.Unmarshal(rec.Body.Bytes(), &scan)
	if scan.Status != "cancelled" {
		t.Fatal(rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/findings?limit=501", nil))
	if rec.Code != 400 {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/scans?limit=1&offset=1", nil))
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatal(rec.Code, rec.Body.String())
	}
	for _, body := range []string{`{"target":"file:///tmp"}`, `{"target":"http://localhost","workers":999}`, `{"target":"http://localhost","strategies":["oops"]}`} {
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/scans", strings.NewReader(body)))
		if rec.Code != 400 {
			t.Fatal(rec.Code, rec.Body.String())
		}
	}
	rec = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(`{"target":"http://localhost"}`))
	r.Header.Set("Origin", "https://foreign.example")
	handler.ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Fatal(rec.Code)
	}
}

package consumer

import (
	"context"
	"encoding/json"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/storage"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestPredictionOutageThenRecovery(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"evaluation_status":"evaluated","is_anomaly":true}`))
	}))
	defer server.Close()
	store, err := storage.NewTrafficStore(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	c := &KafkaConsumer{store: store, httpClient: server.Client(), pythonAPI: server.URL}
	e := model.TrafficEvent{RequestID: "one", Method: "GET", Path: "/unknown", Timestamp: time.Now()}
	status, b := c.evaluate(context.Background(), e)
	if status != "pending" {
		t.Fatal(status)
	}
	if err = store.SavePrediction(context.Background(), e, status, b); err != nil {
		t.Fatal(err)
	}
	status, b = c.evaluate(context.Background(), e)
	if status != "evaluated" {
		t.Fatal(status)
	}
	if err = store.SavePrediction(context.Background(), e, status, json.RawMessage(b)); err != nil {
		t.Fatal(err)
	}
	pending, _ := store.Pending(context.Background())
	if len(pending) != 0 {
		t.Fatal("pending not cleared")
	}
}
func TestInvalidTraffic(t *testing.T) {
	if validateEvent(model.TrafficEvent{Method: "GET", Path: "/", StatusCode: 200, Timestamp: time.Now()}) == nil {
		t.Fatal("missing ID accepted")
	}
}

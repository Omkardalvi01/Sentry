// Package dashboard serves persistent observations and real scanner jobs.
package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/scanner"
	"github.com/Omkardalvi01/sentry/internal/storage"
	"github.com/google/uuid"
)

type Config struct{ DashboardDir, MemgraphURI, MemgraphUser, MemgraphPass, DBPath, DetectorURL string }
type Server struct {
	cfg    Config
	graph  *graph.Client
	store  *storage.TrafficStore
	mu     sync.Mutex
	jobs   map[string]context.CancelFunc
	wg     sync.WaitGroup
	closed bool
}

func New(cfg Config) (*Server, error) {
	g, err := graph.NewClient(cfg.MemgraphURI, cfg.MemgraphUser, cfg.MemgraphPass)
	if err != nil {
		return nil, err
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "traffic.db"
	}
	if cfg.DetectorURL == "" {
		cfg.DetectorURL = os.Getenv("SENTRY_DETECTOR_URL")
		if cfg.DetectorURL == "" {
			cfg.DetectorURL = "http://127.0.0.1:5001"
		}
	}
	store, err := storage.NewTrafficStore(cfg.DBPath)
	if err != nil {
		g.Close(context.Background())
		return nil, err
	}
	s := &Server{cfg: cfg, graph: g, store: store, jobs: map[string]context.CancelFunc{}}
	records, err := store.Documents(context.Background(), "scans")
	if err != nil {
		store.Close()
		g.Close(context.Background())
		return nil, err
	}
	for _, b := range records {
		var scan model.Scan
		if json.Unmarshal(b, &scan) == nil && scan.Status == "running" {
			scan.Status = "cancelled"
			scan.Error = "Dashboard restarted before scan completed"
			scan.CompletedAt = time.Now().UTC()
			if err := store.SaveScan(context.Background(), &scan, nil); err != nil {
				s.Close(context.Background())
				return nil, err
			}
		}
	}
	return s, nil
}
func (s *Server) Close(ctx context.Context) {
	s.mu.Lock()
	s.closed = true
	for _, cancel := range s.jobs {
		cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.graph.Close(ctx)
	s.store.Close()
}
func (s *Server) Handler() (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/explorer/{resource}", s.explorer)
	mux.HandleFunc("GET /api/export/{resource}", s.export)
	mux.HandleFunc("GET /api/scans/{id}/requests", s.requests)
	mux.HandleFunc("GET /api/requests/{id}", s.requestDetail)
	mux.HandleFunc("GET /api/traffic/{id}", s.trafficDetail)
	mux.HandleFunc("POST /api/scans/preview", s.preview)
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/overview", s.overview)
	mux.HandleFunc("GET /api/specs", s.specs)
	mux.HandleFunc("GET /api/findings", s.findings)
	mux.HandleFunc("GET /api/findings/{id}", s.finding)
	mux.HandleFunc("GET /api/traffic", s.traffic)
	mux.HandleFunc("GET /api/anomalies", s.traffic)
	mux.HandleFunc("GET /api/scans", s.scans)
	mux.HandleFunc("POST /api/scans", s.startScan)
	mux.HandleFunc("GET /api/scans/{id}", s.scan)
	mux.HandleFunc("DELETE /api/scans/{id}", s.cancelScan)
	mux.Handle("/", http.FileServer(http.Dir(s.cfg.DashboardDir)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same-origin mutations protect the local dashboard from cross-site scan requests.
		if origin := r.Header.Get("Origin"); origin != "" && (r.Method == "POST" || r.Method == "DELETE") && origin != "http://"+r.Host && origin != "https://"+r.Host {
			writeJSON(w, 403, map[string]string{"error": "cross-origin mutation rejected"})
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	graphErr := s.graph.Ping(ctx)
	counts, storageErr := s.store.Counts(ctx)
	detector := map[string]any{"status": "unavailable"}
	req, _ := http.NewRequestWithContext(ctx, "GET", s.cfg.DetectorURL+"/health", nil)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&detector)
		}
	}
	status := "healthy"
	if graphErr != nil || storageErr != nil || detector["status"] == "unavailable" {
		status = "degraded"
	}
	writeJSON(w, 200, map[string]any{"status": status, "memgraph": graphErr == nil, "storage": storageErr == nil, "counts": counts, "detector": detector, "kafka": "not directly monitored; see persisted traffic", "checkedAt": time.Now().UTC()})
}
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ops, err := s.graph.ReadOperations(r.Context(), r.URL.Query().Get("specTitle"), r.URL.Query().Get("specVersion"))
	counts, dbErr := s.store.Counts(r.Context())
	if dbErr != nil {
		writeJSON(w, 503, map[string]string{"error": dbErr.Error()})
		return
	}
	paths := map[string]bool{}
	for _, op := range ops {
		paths[model.OperationKey(op.SpecTitle, op.SpecVersion, "", op.PathTemplate)] = true
	}
	q, _ := explorerQuery(r.URL.Query())
	q.Limit = 1
	totals := map[string]int{}
	for _, resource := range []string{"findings", "scans", "traffic"} {
		page, queryErr := s.store.Explore(r.Context(), resource, q)
		if queryErr != nil {
			writeJSON(w, 503, map[string]string{"error": queryErr.Error()})
			return
		}
		totals[resource] = page.Total
	}
	writeJSON(w, 200, map[string]any{"operations": len(ops), "paths": len(paths), "findings": totals["findings"], "scans": totals["scans"], "traffic": totals["traffic"], "globalCounts": counts, "graph_connected": err == nil})
}
func (s *Server) specs(w http.ResponseWriter, r *http.Request) {
	ops, err := s.graph.ReadOperations(r.Context(), "", "")
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "inventory unavailable"})
		return
	}
	seen := map[string]bool{}
	out := []map[string]string{}
	for _, op := range ops {
		key := model.OperationKey(op.SpecTitle, op.SpecVersion, "", "")
		if !seen[key] {
			seen[key] = true
			servers, _ := s.graph.ReadServers(r.Context(), op.SpecTitle, op.SpecVersion)
			target := ""
			if len(servers) > 0 {
				target = servers[0].URL
			}
			out = append(out, map[string]string{"title": op.SpecTitle, "version": op.SpecVersion, "target": target})
		}
	}
	writeJSON(w, 200, out)
}
func (s *Server) documents(w http.ResponseWriter, r *http.Request, table, id string) {
	if id != "" {
		record, err := s.store.Document(r.Context(), table, id)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": err.Error()})
			return
		}
		if record == nil {
			writeJSON(w, 404, map[string]string{"error": "record not found"})
			return
		}
		writeJSON(w, 200, record)
		return
	}
	limit, offset := 100, 0
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, _ = strconv.Atoi(value)
	}
	if value := r.URL.Query().Get("offset"); value != "" {
		offset, _ = strconv.Atoi(value)
	}
	if limit < 1 || limit > 500 || offset < 0 {
		writeJSON(w, 400, map[string]string{"error": "limit must be 1–500 and offset nonnegative"})
		return
	}
	records, err := s.store.DocumentPage(r.Context(), table, limit, offset)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, records)
}
func (s *Server) findings(w http.ResponseWriter, r *http.Request) { s.documents(w, r, "findings", "") }
func (s *Server) finding(w http.ResponseWriter, r *http.Request) {
	s.documents(w, r, "findings", r.PathValue("id"))
}
func (s *Server) scans(w http.ResponseWriter, r *http.Request) { s.documents(w, r, "scans", "") }
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	s.documents(w, r, "scans", r.PathValue("id"))
}
func (s *Server) traffic(w http.ResponseWriter, r *http.Request) {
	limit := 100
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, _ = strconv.Atoi(v)
	}
	if limit < 1 || limit > 500 || offset < 0 {
		writeJSON(w, 400, map[string]string{"error": "limit must be 1–500 and offset nonnegative"})
		return
	}
	rows, err := s.store.Traffic(r.Context(), limit, offset, r.URL.Path == "/api/anomalies")
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"items": rows, "limit": limit, "offset": offset})
}

type scanRequest struct {
	Target             string                    `json:"target"`
	SpecTitle          string                    `json:"specTitle"`
	SpecVersion        string                    `json:"specVersion"`
	Strategies         []string                  `json:"strategies"`
	Workers            int                       `json:"workers"`
	RPS                int                       `json:"rps"`
	DryRun             bool                      `json:"dryRun"`
	AllowMutating      bool                      `json:"allowMutating"`
	Headers            map[string]string         `json:"headers"`
	SelectedOperations []model.ObservedOperation `json:"selectedOperations"`
	MaxRequests        int                       `json:"maxRequests"`
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid scan request"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "request must contain one JSON object"})
		return
	}
	if req.Workers == 0 {
		req.Workers = 5
	}
	if req.RPS == 0 {
		req.RPS = 10
	}
	cfg := &model.ScanConfig{ID: uuid.NewString(), Target: strings.TrimRight(req.Target, "/"), SpecTitle: req.SpecTitle, SpecVer: req.SpecVersion, Strategies: req.Strategies, Workers: req.Workers, RPS: req.RPS, DryRun: req.DryRun, AllowMutating: req.AllowMutating, Headers: req.Headers, Timeout: 15 * time.Second, SelectedOperations: req.SelectedOperations, MaxRequests: req.MaxRequests}
	if err := scanner.ValidateConfig(cfg); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	candidates, err := s.store.PassiveCandidates(r.Context(), cfg.SpecTitle, cfg.SpecVer)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	cfg.PassiveCandidates = candidates
	ops, err := s.graph.ReadOperationsWithPaths(r.Context(), cfg.SpecTitle, cfg.SpecVer)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "inventory unavailable"})
		return
	}
	if cfg.SpecTitle == "" || cfg.SpecVer == "" || len(ops) == 0 {
		writeJSON(w, 400, map[string]string{"error": "select an API and version"})
		return
	}
	if err = scanner.ValidateSelection(ops, cfg); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	cfg.RecordRequest = func(record *model.RequestRecord) error { return s.store.SaveRequest(context.Background(), record) }
	cfg.RecordProgress = func(progress *model.Scan) error { return s.store.SaveScan(context.Background(), progress, nil) }
	scan := &model.Scan{ID: cfg.ID, Target: cfg.Target, SpecTitle: cfg.SpecTitle, SpecVersion: cfg.SpecVer, StartedAt: time.Now().UTC(), Status: "running"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.jobs) >= 4 {
		cancel()
		writeJSON(w, 409, map[string]string{"error": "scan capacity unavailable"})
		return
	}
	if err := s.store.SaveScan(r.Context(), scan, nil); err != nil {
		cancel()
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	s.jobs[scan.ID] = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		result, findings, err := scanner.NewEngine(cfg, s.graph).Run(ctx)
		if result == nil {
			result = scan
		}
		if err != nil {
			result.Error = err.Error()
			result.Status = "failed"
			if ctx.Err() != nil {
				result.Status = "cancelled"
			}
		}
		result.CompletedAt = time.Now().UTC()
		if persistErr := s.store.SaveScan(context.Background(), result, findings); persistErr != nil {
			fmt.Fprintf(os.Stderr, "persist scan %s: %v\n", scan.ID, persistErr)
		}
		s.mu.Lock()
		delete(s.jobs, scan.ID)
		s.mu.Unlock()
	}()
	writeJSON(w, 202, scan)
}
func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cancel, ok := s.jobs[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "active scan not found"})
		return
	}
	cancel()
	writeJSON(w, 202, map[string]string{"status": "cancellation_requested"})
}

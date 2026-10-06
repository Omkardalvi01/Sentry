package dashboard

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/scanner"
	"github.com/Omkardalvi01/sentry/internal/storage"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func explorerQuery(v url.Values) (storage.ExplorerQuery, error) {
	q := storage.ExplorerQuery{SpecTitle: v.Get("specTitle"), SpecVersion: v.Get("specVersion"), Target: v.Get("target"), ScanID: v.Get("scanId"), OperationKey: v.Get("operationKey"), Endpoint: v.Get("endpoint"), Path: v.Get("path"), Method: v.Get("method"), Search: v.Get("q"), Status: v.Get("status"), Strategy: v.Get("strategy"), Severity: v.Get("severity"), Confidence: v.Get("confidence"), Verification: v.Get("verification"), Outcome: v.Get("outcome"), Kind: v.Get("kind"), Auth: v.Get("auth"), Schema: v.Get("schema"), From: v.Get("from"), To: v.Get("to"), Sort: v.Get("sort"), Direction: v.Get("direction"), Documented: v.Get("documented"), Deprecated: v.Get("deprecated"), Scanned: v.Get("scanned"), Anomaly: v.Get("anomaly"), Limit: 50}
	var err error
	if raw := v.Get("limit"); raw != "" {
		q.Limit, err = strconv.Atoi(raw)
		if err != nil {
			return q, fmt.Errorf("invalid page size")
		}
	}
	if raw := v.Get("offset"); raw != "" {
		q.Offset, err = strconv.Atoi(raw)
		if err != nil {
			return q, fmt.Errorf("invalid offset")
		}
	}
	if raw := v.Get("snapshot"); raw != "" {
		q.Snapshot, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || q.Snapshot < 0 {
			return q, fmt.Errorf("invalid snapshot")
		}
	}
	if q.Limit < 1 || q.Limit > 500 || q.Offset < 0 {
		return q, fmt.Errorf("limit must be 1–500 and offset nonnegative")
	}
	for _, date := range []string{q.From, q.To} {
		if date != "" {
			if _, err = time.Parse(time.RFC3339, date); err != nil {
				return q, fmt.Errorf("dates must use RFC3339")
			}
		}
	}
	return q, nil
}
func (s *Server) explorer(w http.ResponseWriter, r *http.Request) {
	q, err := explorerQuery(r.URL.Query())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	resource := r.PathValue("resource")
	if resource == "endpoints" {
		s.endpoints(w, r, q)
		return
	}
	page, err := s.store.Explore(r.Context(), resource, q)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, page)
}
func (s *Server) requests(w http.ResponseWriter, r *http.Request) {
	q, err := explorerQuery(r.URL.Query())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	q.ScanID = r.PathValue("id")
	page, err := s.store.Explore(r.Context(), "requests", q)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	scan, _ := s.store.Document(r.Context(), "scans", q.ScanID)
	if scan == nil {
		writeJSON(w, 404, map[string]string{"error": "scan not found"})
		return
	}
	writeJSON(w, 200, page)
}
func (s *Server) requestDetail(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.Request(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	if b == nil {
		writeJSON(w, 404, map[string]string{"error": "request not found"})
		return
	}
	writeJSON(w, 200, b)
}
func (s *Server) trafficDetail(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.TrafficDetail(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	if b == nil {
		writeJSON(w, 404, map[string]string{"error": "traffic event not found"})
		return
	}
	writeJSON(w, 200, b)
}
func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.decodeScan(w, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ops, err := s.graph.ReadOperationsWithPaths(r.Context(), cfg.SpecTitle, cfg.SpecVer)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	if len(ops) == 0 || cfg.SpecTitle == "" || cfg.SpecVer == "" {
		writeJSON(w, 400, map[string]string{"error": "select an API and version"})
		return
	}
	cfg.PassiveCandidates, err = s.store.PassiveCandidates(r.Context(), cfg.SpecTitle, cfg.SpecVer)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	records, err := scanner.NewEngine(cfg, nil).Preview(r.Context(), ops)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"items": records, "total": len(records), "target": cfg.Target})
}
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	q, err := explorerQuery(r.URL.Query())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	resource := r.PathValue("resource")
	items := []json.RawMessage{}
	q.Offset = 0
	q.Limit = 500
	for {
		page, err := s.store.Explore(r.Context(), resource, q)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		q.Snapshot = page.Snapshot
		items = append(items, page.Items...)
		if len(items) >= page.Total {
			break
		}
		q.Offset += q.Limit
	}
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "json" {
		writeJSON(w, 400, map[string]string{"error": "export format must be csv or json"})
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sentry-%s.%s"`, resource, format))
	if format == "json" {
		writeJSON(w, 200, items)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	writer := csv.NewWriter(w)
	defer writer.Flush()
	columns := []string{"id", "specTitle", "specVersion", "target", "scanId", "method", "path", "strategy", "outcome", "statusCode", "severity", "confidence", "timestamp"}
	_ = writer.Write(columns)
	for _, raw := range items {
		var item map[string]any
		_ = json.Unmarshal(raw, &item)
		values := make([]string, len(columns))
		for i, c := range columns {
			if v := item[c]; v != nil {
				values[i] = fmt.Sprint(v)
				if strings.HasPrefix(values[i], "=") || strings.HasPrefix(values[i], "+") || strings.HasPrefix(values[i], "-") || strings.HasPrefix(values[i], "@") {
					values[i] = "'" + values[i]
				}
			}
		}
		_ = writer.Write(values)
	}
}

// Inventory is authoritative for documented operations; observations are grouped
// in SQL so the explorer never depends on the first traffic page.
func (s *Server) endpoints(w http.ResponseWriter, r *http.Request, q storage.ExplorerQuery) {
	ops, err := s.graph.ReadOperationsWithPaths(r.Context(), q.SpecTitle, q.SpecVersion)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "inventory unavailable"})
		return
	}
	rows := map[string]map[string]any{}
	for _, op := range ops {
		key := model.OperationKey(op.SpecTitle, op.SpecVersion, op.Method, op.PathTemplate)
		rows[key] = map[string]any{"id": key, "operation_key": key, "specTitle": op.SpecTitle, "specVersion": op.SpecVersion, "method": op.Method, "path": op.PathTemplate, "documented": true, "deprecated": op.Deprecated, "authentication": map[bool]string{true: "required", false: "public"}[model.RequiresAuth(op.Security)], "requests": 0, "findings": 0, "lastObserved": "", "lastScan": "", "scanStatus": "never scanned"}
	}
	observed, err := s.store.EndpointStats(r.Context(), q)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	for _, o := range observed {
		key := model.OperationKey(o.SpecTitle, o.SpecVersion, o.Method, o.Path)
		if rows[key] == nil {
			rows[key] = map[string]any{"id": key, "operation_key": key, "specTitle": o.SpecTitle, "specVersion": o.SpecVersion, "method": o.Method, "path": o.Path, "documented": false, "deprecated": false, "authentication": "unknown", "requests": 0, "findings": 0, "lastScan": "", "scanStatus": "never scanned"}
		}
		rows[key]["lastObserved"] = o.LastObserved
	}
	scans, err := s.store.EndpointScanStats(r.Context(), q)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	legacy, err := s.store.LegacyEndpointFindings(r.Context(), q)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	for _, o := range append(scans, legacy...) {
		row := rows[o.Key]
		if row == nil {
			var parts []string
			if json.Unmarshal([]byte(o.Key), &parts) != nil || len(parts) != 4 {
				continue
			}
			if q.SpecTitle != "" && parts[0] != q.SpecTitle || q.SpecVersion != "" && parts[1] != q.SpecVersion {
				continue
			}
			row = map[string]any{"id": o.Key, "operation_key": o.Key, "specTitle": parts[0], "specVersion": parts[1], "method": parts[2], "path": parts[3], "documented": false, "deprecated": false, "authentication": "unknown", "requests": 0, "findings": 0, "lastObserved": "", "lastScan": "", "scanStatus": "never scanned"}
			rows[o.Key] = row
		}
		row["requests"] = row["requests"].(int) + o.Requests
		row["findings"] = row["findings"].(int) + o.Findings
		if o.LastScan > fmt.Sprint(row["lastScan"]) {
			row["lastScan"] = o.LastScan
		}
		if row["requests"].(int) > 0 {
			row["scanStatus"] = "scanned"
		} else if row["findings"].(int) > 0 {
			row["scanStatus"] = "legacy findings; request history unavailable"
		}
	}
	items := []map[string]any{}
	for _, row := range rows {
		if q.Method != "" && row["method"] != q.Method {
			continue
		}
		if q.Endpoint != "" && row["path"] != q.Endpoint {
			continue
		}
		if q.Documented != "" && fmt.Sprint(row["documented"]) != q.Documented {
			continue
		}
		if q.Deprecated != "" && fmt.Sprint(row["deprecated"]) != q.Deprecated {
			continue
		}
		if q.Auth != "" && row["authentication"] != q.Auth {
			continue
		}
		if q.Scanned != "" && ((q.Scanned == "true") != (row["scanStatus"] != "never scanned")) {
			continue
		}
		if q.Search != "" && !strings.Contains(strings.ToLower(fmt.Sprint(row["method"], " ", row["path"], " ", row["specTitle"])), strings.ToLower(q.Search)) {
			continue
		}
		items = append(items, row)
	}
	sortField := q.Sort
	if sortField == "" {
		sortField = "endpoint"
	}
	allowed := map[string]string{"endpoint": "path", "method": "method", "findings": "findings", "requests": "requests", "observed": "lastObserved"}
	key := allowed[sortField]
	if key == "" {
		writeJSON(w, 400, map[string]string{"error": "invalid endpoint sort"})
		return
	}
	if q.Direction != "" && q.Direction != "asc" && q.Direction != "desc" {
		writeJSON(w, 400, map[string]string{"error": "invalid sort direction"})
		return
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		less := false
		if key == "findings" || key == "requests" {
			ai, _ := a[key].(int)
			bi, _ := b[key].(int)
			if ai == bi {
				return fmt.Sprint(a["id"]) < fmt.Sprint(b["id"])
			}
			less = ai < bi
		} else {
			av, bv := fmt.Sprint(a[key]), fmt.Sprint(b[key])
			if av == bv {
				return fmt.Sprint(a["id"]) < fmt.Sprint(b["id"])
			}
			less = av < bv
		}
		if q.Direction == "desc" {
			return !less
		}
		return less
	})
	total := len(items)
	start := min(q.Offset, total)
	end := min(start+q.Limit, total)
	writeJSON(w, 200, map[string]any{"items": items[start:end], "total": total, "offset": q.Offset, "limit": q.Limit})
}
func (s *Server) decodeScan(w http.ResponseWriter, r *http.Request) (*model.ScanConfig, error) {
	var req scanRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return nil, fmt.Errorf("invalid scan configuration: %w", err)
	}
	if req.Workers == 0 {
		req.Workers = 5
	}
	if req.RPS == 0 {
		req.RPS = 10
	}
	cfg := &model.ScanConfig{Target: strings.TrimRight(req.Target, "/"), SpecTitle: req.SpecTitle, SpecVer: req.SpecVersion, Strategies: req.Strategies, Workers: req.Workers, RPS: req.RPS, DryRun: req.DryRun, AllowMutating: req.AllowMutating, Headers: req.Headers, Timeout: 15 * time.Second, SelectedOperations: req.SelectedOperations, MaxRequests: req.MaxRequests}
	return cfg, scanner.ValidateConfig(cfg)
}

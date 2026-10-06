package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Omkardalvi01/sentry/internal/model"
	_ "modernc.org/sqlite"
)

//go:embed migrations/001.sql
var schema string

//go:embed migrations/002.sql
var traceSchema string

type TrafficStore struct{ db *sql.DB }

func NewTrafficStore(path string) (*TrafficStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &TrafficStore{db: db}
	if err = s.InitDB(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *TrafficStore) InitDB() error {
	if _, err := s.db.Exec("PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"); err != nil {
		return err
	}
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Upgrade pre-research databases, including the old seed schema.
	cols := map[string]string{"target_origin": "TEXT DEFAULT ''", "graph_path_template": "TEXT", "graph_deprecated": "BOOLEAN", "graph_security": "TEXT", "graph_tag": "TEXT", "graph_dependency_count": "INTEGER DEFAULT 0", "spec_title": "TEXT DEFAULT ''", "spec_version": "TEXT DEFAULT ''", "graph_known": "BOOLEAN", "graph_context_status": "TEXT DEFAULT 'unknown'", "training_eligible": "BOOLEAN DEFAULT 0"}
	rows, err := s.db.Query("PRAGMA table_info(api_traffic)")
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	for rows.Next() {
		var cid, nn, pk int
		var name, typ string
		var def any
		if err = rows.Scan(&cid, &name, &typ, &nn, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	for name, typ := range cols {
		if !existing[name] {
			if _, err = s.db.Exec("ALTER TABLE api_traffic ADD COLUMN " + name + " " + typ); err != nil {
				return err
			}
		}
	}
	_, err = s.db.Exec(traceSchema)
	return err
}

const insertEvent = `INSERT INTO api_traffic (request_id,method,path,query_params,request_headers,request_body,status_code,response_headers,response_body,timestamp,graph_path_template,graph_deprecated,graph_security,graph_tag,graph_dependency_count,spec_title,spec_version,graph_known,graph_context_status,training_eligible,target_origin) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(request_id) DO NOTHING`

func eventArgs(e model.TrafficEvent) []any {
	req, _ := json.Marshal(e.RequestHeaders)
	res, _ := json.Marshal(e.ResponseHeaders)
	return []any{e.RequestID, e.Method, e.Path, e.QueryParams, string(req), e.RequestBody, e.StatusCode, string(res), e.ResponseBody, e.Timestamp.UTC().Format(time.RFC3339Nano), e.GraphPathTemplate, e.GraphDeprecated, e.GraphSecurity, e.GraphTag, 0, e.SpecTitle, e.SpecVersion, e.GraphKnown, e.GraphContextStatus, e.TrainingEligible, e.TargetOrigin}
}

func (s *TrafficStore) InsertBatch(ctx context.Context, events []model.TrafficEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range events {
		if e.RequestID == "" {
			return fmt.Errorf("request_id is required")
		}
		if _, err = tx.ExecContext(ctx, insertEvent, eventArgs(e)...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *TrafficStore) SavePrediction(ctx context.Context, e model.TrafficEvent, status string, result json.RawMessage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, insertEvent, eventArgs(e)...); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE api_traffic SET graph_path_template=?,graph_deprecated=?,graph_security=?,graph_tag=?,spec_title=?,spec_version=?,graph_known=?,graph_context_status=? WHERE request_id=?`, e.GraphPathTemplate, e.GraphDeprecated, e.GraphSecurity, e.GraphTag, e.SpecTitle, e.SpecVersion, e.GraphKnown, e.GraphContextStatus, e.RequestID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO predictions VALUES (?,?,?,?) ON CONFLICT(request_id) DO UPDATE SET status=excluded.status,result=excluded.result,updated_at=excluded.updated_at`, e.RequestID, status, string(result), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *TrafficStore) Reject(ctx context.Context, source, reason string) error {
	_, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO rejected_events VALUES (?,?,?)", source, reason, time.Now().UTC().Format(time.RFC3339))
	return err
}
func (s *TrafficStore) SaveScan(ctx context.Context, scan *model.Scan, findings []*model.Finding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	b, _ := json.Marshal(scan)
	if _, err = tx.ExecContext(ctx, "INSERT INTO scans VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", scan.ID, string(b)); err != nil {
		return err
	}
	for _, f := range findings {
		f.ScanID = scan.ID
		b, _ = json.Marshal(f)
		if _, err = tx.ExecContext(ctx, "INSERT INTO findings VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", f.ID, scan.ID, string(b)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *TrafficStore) Documents(ctx context.Context, table string) ([]json.RawMessage, error) {
	if table != "scans" && table != "findings" {
		return nil, fmt.Errorf("unknown document table")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM "+table+" ORDER BY rowid DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var b string
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(b))
	}
	return out, rows.Err()
}
func (s *TrafficStore) Traffic(ctx context.Context, limit, offset int, anomalies bool) ([]map[string]any, error) {
	filter := ""
	if anomalies {
		filter = " WHERE p.status='evaluated' AND json_extract(p.result,'$.is_anomaly')=1"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT t.request_id,t.method,t.path,t.timestamp,t.graph_path_template,coalesce(p.status,'pending'),coalesce(p.result,'{}') FROM api_traffic t LEFT JOIN predictions p ON t.request_id=p.request_id`+filter+` ORDER BY t.id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, method, path, status, result string
		var ts, tmpl sql.NullString
		if err = rows.Scan(&id, &method, &path, &ts, &tmpl, &status, &result); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"request_id": id, "method": method, "path": path, "timestamp": ts.String, "graph_path_template": tmpl.String, "evaluation_status": status, "prediction": json.RawMessage(result)})
	}
	return out, rows.Err()
}
func (s *TrafficStore) Pending(ctx context.Context) ([]model.TrafficEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT t.request_id,t.method,t.path,t.request_body,t.response_body,t.status_code,t.timestamp,t.graph_path_template,t.graph_deprecated,t.graph_security,t.spec_title,t.spec_version,t.graph_known,t.graph_context_status FROM api_traffic t JOIN predictions p ON p.request_id=t.request_id WHERE p.status='pending' ORDER BY t.id LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.TrafficEvent{}
	for rows.Next() {
		var e model.TrafficEvent
		var ts string
		var known sql.NullBool
		if err = rows.Scan(&e.RequestID, &e.Method, &e.Path, &e.RequestBody, &e.ResponseBody, &e.StatusCode, &ts, &e.GraphPathTemplate, &e.GraphDeprecated, &e.GraphSecurity, &e.SpecTitle, &e.SpecVersion, &known, &e.GraphContextStatus); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		if known.Valid {
			e.GraphKnown = &known.Bool
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (s *TrafficStore) Counts(ctx context.Context) (map[string]int, error) {
	out := map[string]int{}
	for _, table := range []string{"api_traffic", "predictions", "scans", "findings", "rejected_events"} {
		var n int
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			return nil, err
		}
		out[table] = n
	}
	return out, nil
}
func (s *TrafficStore) Close() error { return s.db.Close() }

func (s *TrafficStore) PassiveCandidates(ctx context.Context, title, version string) ([]model.ObservedOperation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT method,path FROM api_traffic WHERE graph_known=0 AND spec_title=? AND spec_version=? ORDER BY method,path LIMIT 500`, title, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ObservedOperation{}
	for rows.Next() {
		var op model.ObservedOperation
		if err = rows.Scan(&op.Method, &op.Path); err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

func (s *TrafficStore) DocumentPage(ctx context.Context, table string, limit, offset int) ([]json.RawMessage, error) {
	if table != "scans" && table != "findings" {
		return nil, fmt.Errorf("unknown document table")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM "+table+" ORDER BY rowid DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(raw))
	}
	return out, rows.Err()
}
func (s *TrafficStore) Document(ctx context.Context, table, id string) (json.RawMessage, error) {
	if table != "scans" && table != "findings" {
		return nil, fmt.Errorf("unknown document table")
	}
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT data FROM "+table+" WHERE id=?", id).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

func (s *TrafficStore) HasEvent(ctx context.Context, id string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM api_traffic WHERE request_id=?", id).Scan(&count)
	return count > 0, err
}

func (s *TrafficStore) SaveRequest(ctx context.Context, r *model.RequestRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO scan_requests VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, r.ID, r.ScanID, string(b)); err != nil {
		return err
	}
	for _, origin := range r.Origins {
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO scan_request_origins VALUES (?,?,?,?)`, r.ID, origin.Key, origin.Method, origin.Path); err != nil {
			return err
		}
	}
	for _, id := range r.BaselineIDs {
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO scan_request_controls VALUES (?,?)`, r.ID, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *TrafficStore) Request(ctx context.Context, id string) (json.RawMessage, error) {
	var b string
	err := s.db.QueryRowContext(ctx, "SELECT data FROM scan_requests WHERE id=?", id).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return json.RawMessage(b), err
}

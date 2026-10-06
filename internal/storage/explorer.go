package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Omkardalvi01/sentry/internal/model"
)

type ExplorerQuery struct {
	SpecTitle, SpecVersion, Target, ScanID, OperationKey, Endpoint, Path, Method, Search, Status, Strategy, Severity, Confidence, Verification, Outcome, Kind, Auth, Schema, From, To, Sort, Direction, Documented, Deprecated, Scanned, Anomaly string
	Limit, Offset                                                                                                                                                                                                                                int
	Snapshot                                                                                                                                                                                                                                     int64
}
type ExplorerPage struct {
	Items    []json.RawMessage `json:"items"`
	Total    int               `json:"total"`
	Limit    int               `json:"limit"`
	Offset   int               `json:"offset"`
	Snapshot int64             `json:"snapshot"`
}

// Every predicate is bound; sort expressions come exclusively from this whitelist.
func (s *TrafficStore) Explore(ctx context.Context, resource string, q ExplorerQuery) (ExplorerPage, error) {
	page := ExplorerPage{Items: []json.RawMessage{}, Limit: q.Limit, Offset: q.Offset, Snapshot: q.Snapshot}
	if q.Limit < 1 || q.Limit > 500 || q.Offset < 0 {
		return page, fmt.Errorf("invalid pagination")
	}
	table, join, document := "", "", "r.data"
	fields := map[string]string{}
	sorts := map[string]string{}
	j := func(name string) string { return "json_extract(r.data,'$." + name + "')" }
	switch resource {
	case "scans":
		table = "scans"
		fields = map[string]string{"specTitle": j("specTitle"), "specVersion": j("specVersion"), "target": j("target"), "status": j("status"), "scanId": "r.id"}
		sorts = map[string]string{"time": "julianday(" + j("startedAt") + ")", "target": j("target"), "status": j("status"), "duration": "julianday(" + j("completedAt") + ")-julianday(" + j("startedAt") + ")", "requests": j("probesSent"), "findings": j("findingsCount")}
	case "findings":
		table = "findings"
		fields = map[string]string{"specTitle": j("specTitle"), "specVersion": j("specVersion"), "target": "json_extract(scan.data,'$.target')", "scanId": "r.scan_id", "endpoint": j("path"), "path": j("path"), "method": j("method"), "strategy": j("strategy"), "severity": j("severity"), "confidence": j("confidence"), "verification": j("verification"), "schema": j("schema_result"), "status": j("statusCode")}
		join = " LEFT JOIN scans scan ON scan.id=r.scan_id"
		sorts = map[string]string{"time": "julianday(" + j("timestamp") + ")", "severity": "CASE " + j("severity") + " WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END", "endpoint": j("path"), "method": j("method"), "status": j("statusCode"), "confidence": "CASE " + j("confidence") + " WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END", "strategy": j("strategy")}
		document = "json_set(r.data,'$.scanTarget',json_extract(scan.data,'$.target'))"
	case "requests":
		table = "scan_requests"
		fields = map[string]string{"specTitle": j("specTitle"), "specVersion": j("specVersion"), "target": j("target"), "scanId": "r.scan_id", "endpoint": j("routeTemplate"), "path": j("path"), "method": j("method"), "strategy": j("strategy"), "outcome": j("outcome"), "kind": j("kind"), "auth": j("authContext"), "schema": j("schemaResult"), "status": j("statusCode")}
		sorts = map[string]string{"time": "CASE WHEN " + j("sent") + "=1 THEN julianday(" + j("startedAt") + ") ELSE 1e12 END", "endpoint": j("path"), "method": j("method"), "status": j("statusCode"), "duration": j("durationMs"), "outcome": j("outcome"), "strategy": j("strategy")}
	case "traffic":
		table = "api_traffic"
		join = " LEFT JOIN predictions p ON p.request_id=r.request_id"
		fields = map[string]string{"specTitle": "r.spec_title", "specVersion": "r.spec_version", "target": "r.target_origin", "endpoint": "coalesce(nullif(r.graph_path_template,''),r.path)", "path": "r.path", "method": "r.method", "status": "r.status_code", "outcome": "coalesce(p.status,'pending')"}
		sorts = map[string]string{"time": "r.id", "endpoint": "r.path", "method": "r.method", "status": "r.status_code", "score": "json_extract(p.result,'$.behavioral_score')", "outcome": "coalesce(p.status,'pending')"}
		document = `json_object('id',r.request_id,'request_id',r.request_id,'specTitle',r.spec_title,'specVersion',r.spec_version,'target',r.target_origin,'method',r.method,'path',r.path,'endpoint',coalesce(nullif(r.graph_path_template,''),r.path),'timestamp',r.timestamp,'statusCode',r.status_code,'evaluation_status',coalesce(p.status,'pending'),'prediction',json(coalesce(p.result,'{}')))`
	default:
		return page, fmt.Errorf("unknown explorer resource")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if page.Snapshot == 0 {
		if err = tx.QueryRowContext(ctx, "SELECT coalesce(max(rowid),0) FROM "+table).Scan(&page.Snapshot); err != nil {
			return page, err
		}
	}
	clauses := []string{"r.rowid<=?"}
	args := []any{page.Snapshot}
	filters := map[string]string{"specTitle": q.SpecTitle, "specVersion": q.SpecVersion, "target": q.Target, "scanId": q.ScanID, "endpoint": q.Endpoint, "path": q.Path, "method": q.Method, "status": q.Status, "strategy": q.Strategy, "severity": q.Severity, "confidence": q.Confidence, "verification": q.Verification, "outcome": q.Outcome, "kind": q.Kind, "auth": q.Auth, "schema": q.Schema}
	for key, value := range filters {
		if value == "" {
			continue
		}
		field := fields[key]
		if field == "" {
			return page, fmt.Errorf("filter %s is unavailable for %s", key, resource)
		}
		if key == "target" && resource == "traffic" && value != "__unknown" {
			value = model.TargetOrigin(value)
		}
		if value == "__unknown" {
			clauses = append(clauses, "coalesce("+field+",'')=''")
		} else if key == "status" && len(value) == 3 && strings.HasSuffix(value, "xx") {
			clauses = append(clauses, "CAST("+field+" AS INTEGER)/100=?")
			args = append(args, string(value[0]))
		} else {
			clauses = append(clauses, field+"=?")
			args = append(args, value)
		}
	}
	if q.OperationKey != "" {
		switch resource {
		case "requests":
			clauses = append(clauses, "EXISTS (SELECT 1 FROM scan_request_origins o WHERE o.request_id=r.id AND o.operation_key=?)")
			args = append(args, q.OperationKey)
		case "findings":
			clauses = append(clauses, "("+j("operation_key")+"=? OR EXISTS (SELECT 1 FROM json_each(r.data,'$.origins') o WHERE json_extract(o.value,'$.key')=?))")
			args = append(args, q.OperationKey, q.OperationKey)
		case "traffic":
			var op []string
			if json.Unmarshal([]byte(q.OperationKey), &op) != nil || len(op) != 4 {
				return page, fmt.Errorf("invalid operation key")
			}
			clauses = append(clauses, "r.spec_title=? AND r.spec_version=? AND r.method=? AND coalesce(nullif(r.graph_path_template,''),r.path)=?")
			args = append(args, op[0], op[1], op[2], op[3])
		default:
			return page, fmt.Errorf("operation filter is unavailable")
		}
	}
	if q.Search != "" {
		parts := []string{}
		for _, field := range fields {
			parts = append(parts, "instr(lower(coalesce("+field+",'')),lower(?))>0")
			args = append(args, q.Search)
		}
		if resource == "findings" {
			parts = append(parts, "instr(lower("+j("title")+"),lower(?))>0")
			args = append(args, q.Search)
		}
		clauses = append(clauses, "("+strings.Join(parts, " OR ")+")")
	}
	dateField := j("timestamp")
	if resource == "scans" {
		dateField = j("startedAt")
	}
	if resource == "requests" {
		dateField = j("completedAt")
	}
	if resource == "traffic" {
		dateField = "r.timestamp"
	}
	if q.From != "" {
		clauses = append(clauses, "julianday("+dateField+")>=julianday(?)")
		args = append(args, q.From)
	}
	if q.To != "" {
		clauses = append(clauses, "julianday("+dateField+")<=julianday(?)")
		args = append(args, q.To)
	}
	if q.Anomaly != "" {
		if resource != "traffic" {
			return page, fmt.Errorf("anomaly filter is only available for traffic")
		}
		switch q.Anomaly {
		case "normal":
			clauses = append(clauses, "p.status='evaluated' AND json_extract(p.result,'$.is_anomaly')=0")
		case "any":
			clauses = append(clauses, "json_extract(p.result,'$.is_anomaly')=1")
		case "behavioral":
			clauses = append(clauses, "json_extract(p.result,'$.behavioral_anomaly')=1")
		case "shadow_candidate", "deprecated_observed":
			clauses = append(clauses, "EXISTS (SELECT 1 FROM json_each(p.result,'$.inventory_signals') sig WHERE sig.value=?)")
			args = append(args, q.Anomaly)
		default:
			return page, fmt.Errorf("invalid anomaly filter")
		}
	}
	sort := q.Sort
	if sort == "" {
		sort = "time"
		if resource == "findings" {
			sort = "severity"
		}
	}
	expr := sorts[sort]
	if expr == "" {
		return page, fmt.Errorf("invalid sort field")
	}
	direction := strings.ToUpper(q.Direction)
	if direction == "" {
		direction = "DESC"
		if resource == "requests" {
			direction = "ASC"
		}
	}
	if direction != "ASC" && direction != "DESC" {
		return page, fmt.Errorf("invalid sort direction")
	}
	from := table + " r" + join + " WHERE " + strings.Join(clauses, " AND ")
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+from, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	order := expr + " " + direction
	if resource == "findings" && sort == "severity" {
		order += ", julianday(" + j("timestamp") + ") DESC"
	}
	order += ", r.rowid " + direction
	queryArgs := append(append([]any{}, args...), q.Limit, q.Offset)
	rows, err := tx.QueryContext(ctx, "SELECT "+document+" FROM "+from+" ORDER BY "+order+" LIMIT ? OFFSET ?", queryArgs...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		var b string
		if err = rows.Scan(&b); err != nil {
			rows.Close()
			return page, err
		}
		page.Items = append(page.Items, json.RawMessage(b))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	return page, tx.Commit()
}

func (s *TrafficStore) TrafficDetail(ctx context.Context, id string) (map[string]any, error) {
	row := s.db.QueryRowContext(ctx, `SELECT spec_title,spec_version,target_origin,method,path,query_params,status_code,timestamp,coalesce(request_headers,'{}'),coalesce(response_headers,'{}'),coalesce(request_body,''),coalesce(response_body,''),coalesce(p.result,'{}'),coalesce(p.status,'pending') FROM api_traffic t LEFT JOIN predictions p ON p.request_id=t.request_id WHERE t.request_id=?`, id)
	var title, version, target, method, path, query, ts, req, res, reqBody, resBody, prediction, state string
	var status int
	if err := row.Scan(&title, &version, &target, &method, &path, &query, &status, &ts, &req, &res, &reqBody, &resBody, &prediction, &state); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	response := map[string]string{}
	_ = json.Unmarshal([]byte(req), &headers)
	_ = json.Unmarshal([]byte(res), &response)
	rb, rt := model.PreviewBody(model.RedactBody(reqBody, nil), 4096)
	sb, st := model.PreviewBody(model.RedactBody(resBody, nil), 16384)
	return map[string]any{"id": id, "specTitle": title, "specVersion": version, "target": target, "method": method, "path": path, "statusCode": status, "timestamp": ts, "requestHeaders": model.RedactHeaders(headers, nil), "responseHeaders": model.RedactHeaders(response, nil), "requestBody": rb, "responseBody": sb, "requestTruncated": rt, "responseTruncated": st, "prediction": json.RawMessage(prediction), "evaluation_status": state}, nil
}

package storage

import (
	"context"
	"github.com/Omkardalvi01/sentry/internal/model"
)

type EndpointStat struct{ SpecTitle, SpecVersion, Method, Path, LastObserved string }

func (s *TrafficStore) EndpointStats(ctx context.Context, q ExplorerQuery) ([]EndpointStat, error) {
	where := " WHERE (?='' OR spec_title=?) AND (?='' OR spec_version=?)"
	args := []any{q.SpecTitle, q.SpecTitle, q.SpecVersion, q.SpecVersion}
	if q.Target != "" {
		where += " AND target_origin=?"
		target := model.TargetOrigin(q.Target)
		if q.Target == "__unknown" {
			target = ""
		}
		args = append(args, target)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT spec_title,spec_version,method,coalesce(nullif(graph_path_template,''),path),max(timestamp) FROM api_traffic`+where+` GROUP BY spec_title,spec_version,method,coalesce(nullif(graph_path_template,''),path)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EndpointStat{}
	for rows.Next() {
		var o EndpointStat
		if err = rows.Scan(&o.SpecTitle, &o.SpecVersion, &o.Method, &o.Path, &o.LastObserved); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

type EndpointScanStat struct {
	Key, LastScan      string
	Requests, Findings int
}

func (s *TrafficStore) EndpointScanStats(ctx context.Context, q ExplorerQuery) ([]EndpointScanStat, error) {
	args := []any{q.Target, q.Target, q.ScanID, q.ScanID}
	rows, err := s.db.QueryContext(ctx, `SELECT o.operation_key,count(*),sum(CASE WHEN json_extract(r.data,'$.outcome')='finding' THEN 1 ELSE 0 END),max(json_extract(scan.data,'$.startedAt')) FROM scan_request_origins o JOIN scan_requests r ON r.id=o.request_id JOIN scans scan ON scan.id=r.scan_id WHERE json_extract(r.data,'$.sent')=1 AND json_extract(r.data,'$.kind')='check' AND (?='' OR json_extract(scan.data,'$.target')=?) AND (?='' OR scan.id=?) GROUP BY o.operation_key`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EndpointScanStat{}
	for rows.Next() {
		var o EndpointScanStat
		if err = rows.Scan(&o.Key, &o.Requests, &o.Findings, &o.LastScan); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *TrafficStore) LegacyEndpointFindings(ctx context.Context, q ExplorerQuery) ([]EndpointScanStat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT json_extract(f.data,'$.operation_key'),count(*),max(json_extract(scan.data,'$.startedAt')) FROM findings f JOIN scans scan ON scan.id=f.scan_id WHERE coalesce(json_extract(f.data,'$.requestId'),'')='' AND (?='' OR json_extract(scan.data,'$.target')=?) AND (?='' OR scan.id=?) GROUP BY json_extract(f.data,'$.operation_key')`, q.Target, q.Target, q.ScanID, q.ScanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EndpointScanStat{}
	for rows.Next() {
		var o EndpointScanStat
		if err = rows.Scan(&o.Key, &o.Findings, &o.LastScan); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

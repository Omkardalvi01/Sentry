CREATE TABLE IF NOT EXISTS scan_requests (
 id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_requests_scan ON scan_requests(scan_id);
CREATE TABLE IF NOT EXISTS scan_request_origins (
 request_id TEXT NOT NULL REFERENCES scan_requests(id) ON DELETE CASCADE,
 operation_key TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
 PRIMARY KEY(request_id,operation_key)
);
CREATE INDEX IF NOT EXISTS idx_request_origins_operation ON scan_request_origins(operation_key);
CREATE TABLE IF NOT EXISTS scan_request_controls (
 request_id TEXT NOT NULL REFERENCES scan_requests(id) ON DELETE CASCADE,
 baseline_id TEXT NOT NULL REFERENCES scan_requests(id),
 PRIMARY KEY(request_id,baseline_id)
);
CREATE INDEX IF NOT EXISTS idx_traffic_scope ON api_traffic(spec_title,spec_version,graph_path_template,method);
INSERT OR IGNORE INTO schema_migrations VALUES (2);

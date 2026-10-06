CREATE TABLE IF NOT EXISTS api_traffic (
 id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT UNIQUE NOT NULL,
 method TEXT, path TEXT, query_params TEXT, request_headers TEXT, request_body TEXT,
 status_code INTEGER, response_headers TEXT, response_body TEXT, timestamp DATETIME,
 graph_path_template TEXT, graph_deprecated BOOLEAN, graph_security TEXT, graph_tag TEXT,
 graph_dependency_count INTEGER DEFAULT 0, spec_title TEXT DEFAULT '', spec_version TEXT DEFAULT '',
 graph_known BOOLEAN, graph_context_status TEXT DEFAULT 'unknown', training_eligible BOOLEAN DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_traffic_path ON api_traffic(path);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON api_traffic(timestamp);
CREATE TABLE IF NOT EXISTS predictions (
 request_id TEXT PRIMARY KEY REFERENCES api_traffic(request_id), status TEXT NOT NULL,
 result TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rejected_events (
 source TEXT PRIMARY KEY, reason TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_migrations VALUES (1);

CREATE TABLE IF NOT EXISTS model_registry (
 id TEXT PRIMARY KEY, created_at TEXT, endpoints_count INTEGER, model_data TEXT
);
CREATE TABLE IF NOT EXISTS model_activation (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), model_id TEXT REFERENCES model_registry(id)
);

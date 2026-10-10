"""The SQL schema is shared with Go. Upgrade old traffic databases in place."""
import sqlite3
from pathlib import Path

SCHEMA = Path(__file__).resolve().parents[1] / 'internal/storage/migrations/001.sql'
COLUMNS = {
    'graph_path_template': 'TEXT', 'graph_deprecated': 'BOOLEAN',
    'graph_security': 'TEXT', 'graph_tag': 'TEXT', 'graph_dependency_count': 'INTEGER DEFAULT 0',
    'spec_title': "TEXT DEFAULT ''", 'spec_version': "TEXT DEFAULT ''",
    'graph_known': 'BOOLEAN', 'graph_context_status': "TEXT DEFAULT 'unknown'",
    'training_eligible': 'BOOLEAN DEFAULT 0', 'target_origin': "TEXT DEFAULT ''",
    'response_time_ms': 'REAL', 'response_size_bytes': 'INTEGER',
    'review_label': 'INTEGER CHECK (review_label IN (0,1) OR review_label IS NULL)',
}

def connect(path):
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def initialize(path):
    with connect(path) as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.executescript(SCHEMA.read_text())
        existing = {row['name'] for row in conn.execute('PRAGMA table_info(api_traffic)')}
        for name, definition in COLUMNS.items():
            if name not in existing:
                conn.execute(f'ALTER TABLE api_traffic ADD COLUMN {name} {definition}')
        conn.execute('''CREATE TABLE IF NOT EXISTS model_registry (
            id TEXT PRIMARY KEY, created_at TEXT, endpoints_count INTEGER, model_data TEXT)''')

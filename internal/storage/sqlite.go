package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "modernc.org/sqlite"

	"github.com/Omkardalvi01/sentry/internal/model"
)

// TrafficStore manages the SQLite database for API traffic.
type TrafficStore struct {
	db *sql.DB
}

// NewTrafficStore opens (or creates) the SQLite database and returns the store.
func NewTrafficStore(dbPath string) (*TrafficStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	store := &TrafficStore{db: db}
	if err := store.InitDB(); err != nil {
		return nil, err
	}

	return store, nil
}

// InitDB ensures the necessary tables and indexes exist.
func (s *TrafficStore) InitDB() error {
	query := `
	CREATE TABLE IF NOT EXISTS api_traffic (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_id TEXT UNIQUE,
		method TEXT,
		path TEXT,
		query_params TEXT,
		request_headers TEXT,
		request_body TEXT,
		status_code INTEGER,
		response_headers TEXT,
		response_body TEXT,
		timestamp DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_traffic_path ON api_traffic(path);
	CREATE INDEX IF NOT EXISTS idx_traffic_method ON api_traffic(method);
	`
	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("initializing db schema: %w", err)
	}
	return nil
}

// InsertBatch inserts multiple traffic events in a single transaction for performance.
func (s *TrafficStore) InsertBatch(ctx context.Context, events []model.TrafficEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO api_traffic (
			request_id, method, path, query_params, request_headers, request_body,
			status_code, response_headers, response_body, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(request_id) DO NOTHING
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("preparing statement: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		reqH, _ := json.Marshal(e.RequestHeaders)
		resH, _ := json.Marshal(e.ResponseHeaders)

		_, err := stmt.ExecContext(ctx,
			e.RequestID,
			e.Method,
			e.Path,
			e.QueryParams,
			string(reqH),
			e.RequestBody,
			e.StatusCode,
			string(resH),
			e.ResponseBody,
			e.Timestamp,
		)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("inserting event %s: %w", e.RequestID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

// Close closes the underlying database connection.
func (s *TrafficStore) Close() error {
	return s.db.Close()
}

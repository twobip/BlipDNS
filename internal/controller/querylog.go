package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// QueryLogStore provides persistent storage for query log events
type QueryLogStore struct {
	db *sql.DB
}

// QueryLogEntry represents a single DNS query event
type QueryLogEntry struct {
	ID        int64
	Timestamp time.Time
	Instance  string
	Client    string
	Domain    string
	Action    string // "BLOCK" or "PASS"
	Upstream  string
}

// NewQueryLogStore creates a new query log store backed by SQLite
func NewQueryLogStore(dbPath string) (*QueryLogStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}

	// Create table
	schema := `
	CREATE TABLE IF NOT EXISTS query_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		instance TEXT NOT NULL,
		client TEXT NOT NULL,
		domain TEXT NOT NULL,
		action TEXT NOT NULL,
		upstream TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_query_log_instance ON query_log(instance);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}

	// Start cleanup goroutine
	store := &QueryLogStore{db: db}
	go store.cleanupLoop()

	return store, nil
}

// Insert adds a new query log entry
func (s *QueryLogStore) Insert(ctx context.Context, e QueryLogEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO query_log (timestamp, instance, client, domain, action, upstream) VALUES (?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Instance, e.Client, e.Domain, e.Action, e.Upstream)
	return err
}

// Query returns entries within the time range
func (s *QueryLogStore) Query(ctx context.Context, instance, filter string, since time.Time, limit int) ([]QueryLogEntry, error) {
	query := `SELECT id, timestamp, instance, client, domain, action, upstream FROM query_log WHERE timestamp >= ?`
	args := []interface{}{since}

	if instance != "" {
		query += " AND instance = ?"
		args = append(args, instance)
	}

	filterLower := ""
	if filter != "" {
		filterLower = "%" + filter + "%"
		query += " AND (LOWER(client) LIKE ? OR LOWER(domain) LIKE ? OR LOWER(action) LIKE ?)"
		args = append(args, filterLower, filterLower, filterLower)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []QueryLogEntry
	for rows.Next() {
		var e QueryLogEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Instance, &e.Client, &e.Domain, &e.Action, &e.Upstream); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		results = append(results, e)
	}
	return results, rows.Err()
}

// cleanupLoop removes entries older than 24 hours
func (s *QueryLogStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		ctx := context.Background()
		cutoff := time.Now().Add(-24 * time.Hour)
		s.db.ExecContext(ctx, `DELETE FROM query_log WHERE timestamp < ?`, cutoff)
	}
}

// Close closes the database connection
func (s *QueryLogStore) Close() error {
	return s.db.Close()
}
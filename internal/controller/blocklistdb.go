package controller

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// BlocklistStore persists the controller's merged blocklist so a restart can
// load it into RAM instantly instead of re-fetching every source. It stores
// the flat set of domains (one per row).
type BlocklistStore struct {
	db *sql.DB
}

// NewBlocklistStore opens (creating if needed) the SQLite database at dbPath.
func NewBlocklistStore(dbPath string) (*BlocklistStore, error) {
	if dir := filepath.Dir(dbPath); dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("create blocklist db dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open blocklist db: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS blocklist (domain TEXT PRIMARY KEY)`); err != nil {
		return nil, fmt.Errorf("create blocklist schema: %w", err)
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS blocklist_source_domains (
	source_url TEXT NOT NULL,
	domain     TEXT NOT NULL,
	PRIMARY KEY (source_url, domain)
);
CREATE TABLE IF NOT EXISTS blocklist_source_meta (
	source_url TEXT PRIMARY KEY,
	domains    INTEGER NOT NULL DEFAULT 0,
	last_update TEXT,
	error      TEXT
);`); err != nil {
		return nil, fmt.Errorf("create blocklist source schema: %w", err)
	}
	return &BlocklistStore{db: db}, nil
}

// ReplaceAll replaces the stored set with domains in a single transaction.
// An empty list clears the persisted set.
func (s *BlocklistStore) ReplaceAll(ctx context.Context, domains []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO blocklist (domain) VALUES (?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, d := range domains {
		if _, err := stmt.ExecContext(ctx, d); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadSet returns the stored domains as a set, ready for FromDomainsMap.
func (s *BlocklistStore) LoadSet(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM blocklist`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out[d] = struct{}{}
	}
	return out, rows.Err()
}

// Count returns the number of stored domains.
func (s *BlocklistStore) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM blocklist`).Scan(&n)
	return n, err
}

// SourceMeta is the persisted per-source download metadata (count, last
// successful update, latest error).
type SourceMeta struct {
	URL        string
	Domains    int
	LastUpdate time.Time
	Error      string
}

// ReplaceSourceDomains stores the parsed domain set for one source, replacing
// any previously stored snapshot for that URL. The snapshot is the fallback
// used when a later refresh of the source fails.
func (s *BlocklistStore) ReplaceSourceDomains(ctx context.Context, url string, domains []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_source_domains WHERE source_url = ?`, url); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO blocklist_source_domains (source_url, domain) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, d := range domains {
		if _, err := stmt.ExecContext(ctx, url, d); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadSourceDomains returns the last successfully downloaded domain set for a
// source. An empty (or absent) snapshot yields an empty set, never an error.
func (s *BlocklistStore) LoadSourceDomains(ctx context.Context, url string) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM blocklist_source_domains WHERE source_url = ?`, url)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out[d] = struct{}{}
	}
	return out, rows.Err()
}

// ReplaceSourceMeta upserts the download metadata for one source.
func (s *BlocklistStore) ReplaceSourceMeta(ctx context.Context, m SourceMeta) error {
	lu := ""
	if !m.LastUpdate.IsZero() {
		lu = m.LastUpdate.Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO blocklist_source_meta (source_url, domains, last_update, error)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(source_url) DO UPDATE SET
			domains = excluded.domains,
			last_update = excluded.last_update,
			error = excluded.error`,
		m.URL, m.Domains, lu, m.Error)
	return err
}

// LoadSourceMeta returns all persisted source metadata keyed by URL.
func (s *BlocklistStore) LoadSourceMeta(ctx context.Context) (map[string]SourceMeta, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source_url, domains, last_update, error FROM blocklist_source_meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]SourceMeta)
	for rows.Next() {
		var m SourceMeta
		var lu sql.NullString
		if err := rows.Scan(&m.URL, &m.Domains, &lu, &m.Error); err != nil {
			return nil, err
		}
		if lu.Valid && lu.String != "" {
			if t, err := time.Parse(time.RFC3339, lu.String); err == nil {
				m.LastUpdate = t
			}
		}
		out[m.URL] = m
	}
	return out, rows.Err()
}

// PruneSources removes snapshots and metadata for sources no longer configured.
func (s *BlocklistStore) PruneSources(ctx context.Context, keep []string) error {
	if s.db == nil {
		return nil
	}
	keepSet := make(map[string]struct{}, len(keep))
	for _, u := range keep {
		keepSet[u] = struct{}{}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT source_url FROM blocklist_source_domains UNION SELECT source_url FROM blocklist_source_meta`)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return err
		}
		if _, ok := keepSet[u]; !ok {
			stale = append(stale, u)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, u := range stale {
		if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_source_domains WHERE source_url = ?`, u); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_source_meta WHERE source_url = ?`, u); err != nil {
			return err
		}
	}
	return tx.Commit()
}

package controller

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

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

package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// BlocklistStore persists the controller's merged blocklist so a restart can
// load it into RAM instantly instead of re-fetching every source. It stores
// the flat set of domains (one per row).
//
// Per-source snapshots are one flat table: blocklist_source_domains holds
// every (source_url, domain) pair, so a failed refresh falls back to the last
// good snapshot and pruning a source is one DELETE.
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
	// NORMAL is crash-safe under WAL (a power loss may drop the last commit,
	// never corrupt) and skips an fsync per transaction during bulk imports.
	// ponytail: the DB is a rebuildable cache; use FULL if it ever holds truth.
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		return nil, fmt.Errorf("set synchronous mode: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS blocklist (domain TEXT PRIMARY KEY)`); err != nil {
		return nil, fmt.Errorf("create blocklist schema: %w", err)
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS blocklist_source_meta (
	source_url TEXT PRIMARY KEY,
	domains    INTEGER NOT NULL DEFAULT 0,
	last_update TEXT,
	error      TEXT
);
CREATE TABLE IF NOT EXISTS blocklist_manual (
	domain TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS blocklist_manual_allow (
	domain TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS blocklist_source_domains (
	source_url TEXT NOT NULL,
	domain     TEXT NOT NULL,
	PRIMARY KEY (source_url, domain)
);
CREATE INDEX IF NOT EXISTS idx_blocklist_source_domains_domain ON blocklist_source_domains(domain);`); err != nil {
		return nil, fmt.Errorf("create blocklist source schema: %w", err)
	}
	s := &BlocklistStore{db: db}
	// One-time migration from the normalized snapshot tables back to the flat
	// (source_url, domain) table; pre-normalization databases already have it.
	if err := s.migrateNormalizedSourceDomains(context.Background()); err != nil {
		log.Printf("blipc: warning: blocklist source migration deferred: %v", err)
	}
	// Best-effort hardening: if the file is not owned by the current user
	// (e.g. it was created by root during install), chmod fails with EPERM but
	// the database is still fully usable. Do not take the blocklist DB down
	// over a defensive chmod.
	if err := os.Chmod(dbPath, 0600); err != nil {
		log.Printf("blipc: warning: chmod blocklist db: %v", err)
	}
	return s, nil
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
	err = insertChunked(ctx, tx, len(domains),
		func(n int) string { return `INSERT INTO blocklist (domain) VALUES ` + placeholders(n, 1) },
		func(start, end int) []interface{} {
			args := make([]interface{}, 0, end-start)
			for _, d := range domains[start:end] {
				args = append(args, d)
			}
			return args
		})
	if err != nil {
		return err
	}
	return tx.Commit()
}

// insertBatch is the max rows per multi-row INSERT (500×2 bind vars stays
// under SQLite's 999-variable limit on older builds).
const insertBatch = 500

// insertChunked runs multi-row INSERTs built by sqlFor in chunks of at most
// insertBatch rows; args returns the row-major bind vars for [start, end).
func insertChunked(ctx context.Context, tx *sql.Tx, n int, sqlFor func(int) string, args func(start, end int) []interface{}) error {
	for start := 0; start < n; start += insertBatch {
		end := min(start+insertBatch, n)
		stmt, err := tx.PrepareContext(ctx, sqlFor(end-start))
		if err != nil {
			return err
		}
		_, err = stmt.ExecContext(ctx, args(start, end)...)
		stmt.Close()
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

// placeholders returns "(?,..),(?,..)" for rows×cols bind vars.
func placeholders(rows, cols int) string {
	one := "(" + strings.TrimSuffix(strings.Repeat("?,", cols), ",") + "),"
	return strings.TrimSuffix(strings.Repeat(one, rows), ",")
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

// replaceDomainSet stores a hand-maintained domain set (manual block or
// allow table). An empty list clears it. Table must be a literal table name.
func (s *BlocklistStore) replaceDomainSet(ctx context.Context, table string, domains []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+table); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO `+table+` (domain) VALUES (?)`)
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

// loadDomainSet returns a hand-maintained domain set. Table must be a literal
// table name.
func (s *BlocklistStore) loadDomainSet(ctx context.Context, table string) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM `+table)
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

	// Batch the inserts so multi-million-domain snapshots (e.g. oisd.big)
	// don't spend minutes in per-row SQLite calls. OR IGNORE covers legacy
	// tables created without the primary key.
	err = insertChunked(ctx, tx, len(domains),
		func(n int) string {
			return `INSERT OR IGNORE INTO blocklist_source_domains (source_url, domain) VALUES ` + placeholders(n, 2)
		},
		func(start, end int) []interface{} {
			args := make([]interface{}, 0, (end-start)*2)
			for _, d := range domains[start:end] {
				args = append(args, url, d)
			}
			return args
		})
	if err != nil {
		return err
	}
	return tx.Commit()
}

// LoadSourceDomains returns the last successfully downloaded domain set for a
// source. An empty (or absent) snapshot yields an empty set, never an error.
func (s *BlocklistStore) LoadSourceDomains(ctx context.Context, url string) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain
		FROM blocklist_source_domains
		WHERE source_url = ?`, url)
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

// checkpoint truncates the WAL so a large snapshot import doesn't leave a
// multi-hundred-MB write-ahead log on disk. Called once per import (not per
// source). Best-effort: a busy checkpoint is harmless and retried later.
func (s *BlocklistStore) checkpoint(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// PruneSources removes snapshots and metadata for sources no longer configured.
func (s *BlocklistStore) PruneSources(ctx context.Context, keep []string) error {
	if s.db == nil {
		return nil
	}
	if len(keep) == 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM blocklist_source_domains`); err != nil {
			return err
		}
		_, err := s.db.ExecContext(ctx, `DELETE FROM blocklist_source_meta`)
		return err
	}
	args := make([]interface{}, 0, len(keep))
	for _, u := range keep {
		args = append(args, u)
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(keep)), ",")
	if _, err := s.db.ExecContext(ctx, `DELETE FROM blocklist_source_domains WHERE source_url NOT IN (`+ph+`)`, args...); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM blocklist_source_meta WHERE source_url NOT IN (`+ph+`)`, args...)
	return err
}

// BlockSourceLabel returns a display label for the list(s) that contain
// domain: "manual" when it was added by hand, else the matching source URLs
// joined with ", ", else "" when the domain is not in any known list.
func (s *BlocklistStore) BlockSourceLabel(ctx context.Context, domain string) (string, error) {
	if s.db == nil {
		return "", nil
	}
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM blocklist_manual WHERE domain = ?`, domain).Scan(&one)
	if err == nil {
		return "manual", nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT source_url
		FROM blocklist_source_domains
		WHERE domain = ?
		ORDER BY source_url`, domain)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	urls := make([]string, 0, 2)
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return "", err
		}
		urls = append(urls, u)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return strings.Join(urls, ", "), nil
}

// migrateNormalizedSourceDomains folds the normalized snapshot tables
// (blocklist_sources/domains/membership) back into the flat
// blocklist_source_domains table, then drops them. No-op on fresh databases
// and on pre-normalization ones that already have the flat table.
// Failure is non-fatal: NewBlocklistStore logs it and the next startup retries.
func (s *BlocklistStore) migrateNormalizedSourceDomains(ctx context.Context) error {
	var name string
	err := s.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'blocklist_membership'`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // nothing to migrate
	}
	if err != nil {
		return err
	}
	log.Printf("blipc: migrating blocklist source snapshots to flat schema (one-time, may take a minute)")
	if _, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO blocklist_source_domains (source_url, domain)
		SELECT src.url, d.domain
		FROM blocklist_membership m
		JOIN blocklist_sources src ON src.source_id = m.source_id
		JOIN blocklist_domains d   ON d.domain_id = m.domain_id`); err != nil {
		return err
	}
	for _, t := range []string{"blocklist_membership", "blocklist_domains", "blocklist_sources"} {
		if _, err := s.db.ExecContext(ctx, `DROP TABLE `+t); err != nil {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		// Space is reclaimed lazily even without VACUUM; not fatal.
		log.Printf("blipc: warning: post-migration VACUUM failed: %v", err)
	}
	return nil
}

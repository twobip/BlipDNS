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
// Per-source snapshots are stored NORMALIZED: blocklist_sources holds the
// source URLs, blocklist_domains holds each distinct domain once, and
// blocklist_membership holds the (source_id, domain_id) pairs. A domain that
// appears in N sources is stored as one text row plus N 2-integer membership
// rows instead of repeating ~80-byte strings per source, which cuts the
// per-source storage by several times on real-world lists.
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
CREATE TABLE IF NOT EXISTS blocklist_sources (
	source_id   INTEGER PRIMARY KEY,
	url         TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS blocklist_domains (
	domain_id   INTEGER PRIMARY KEY,
	domain      TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS blocklist_membership (
	source_id INTEGER NOT NULL,
	domain_id INTEGER NOT NULL,
	PRIMARY KEY (source_id, domain_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_blocklist_membership_domain_id ON blocklist_membership(domain_id);`); err != nil {
		return nil, fmt.Errorf("create blocklist source schema: %w", err)
	}
	s := &BlocklistStore{db: db}
	// One-time migration from the legacy denormalized table (pre-normalization
	// databases carry every (url, domain) pair as text).
	if err := s.migrateLegacySourceDomains(context.Background()); err != nil {
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

// ReplaceManualDomains replaces the stored set of hand-added domains. An empty
// list clears them.
func (s *BlocklistStore) ReplaceManualDomains(ctx context.Context, domains []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_manual`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO blocklist_manual (domain) VALUES (?)`)
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

// LoadManualDomains returns the stored set of hand-added domains.
func (s *BlocklistStore) LoadManualDomains(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM blocklist_manual`)
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

// ReplaceManualAllowed replaces the stored set of hand-added whitelist domains.
// An empty list clears them.
func (s *BlocklistStore) ReplaceManualAllowed(ctx context.Context, domains []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_manual_allow`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO blocklist_manual_allow (domain) VALUES (?)`)
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

// LoadManualAllowed returns the stored set of hand-added whitelist domains.
func (s *BlocklistStore) LoadManualAllowed(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM blocklist_manual_allow`)
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
//
// Domains are stored normalized: each distinct domain gets one row in
// blocklist_domains (shared across sources) and one integer membership row per
// (source, domain) pair.
func (s *BlocklistStore) ReplaceSourceDomains(ctx context.Context, url string, domains []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	srcID, err := upsertSourceID(ctx, tx, url)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_membership WHERE source_id = ?`, srcID); err != nil {
		return err
	}

	// Batch the inserts so multi-million-domain snapshots (e.g. oisd.big)
	// don't spend minutes in per-row SQLite calls. Each statement's placeholder
	// count must match its chunk size, so full-size statements are prepared
	// once and final partial chunks get their own one-off statements.
	const batch = 500
	insertDomain, err := tx.PrepareContext(ctx,
		`INSERT INTO blocklist_domains (domain) VALUES (?) ON CONFLICT(domain) DO NOTHING RETURNING domain_id`)
	if err != nil {
		return err
	}
	defer insertDomain.Close()
	findDomain, err := tx.PrepareContext(ctx,
		`SELECT domain_id FROM blocklist_domains WHERE domain = ?`)
	if err != nil {
		return err
	}
	defer findDomain.Close()
	fullStmt, err := tx.PrepareContext(ctx, membershipInsertSQL(batch))
	if err != nil {
		return err
	}
	defer fullStmt.Close()

	domainIDs := make([]int64, 0, batch)
	flush := func(ids []int64) error {
		if len(ids) == 0 {
			return nil
		}
		stmt := fullStmt
		if len(ids) != batch {
			var perr error
			stmt, perr = tx.PrepareContext(ctx, membershipInsertSQL(len(ids)))
			if perr != nil {
				return perr
			}
			defer stmt.Close()
		}
		args := make([]interface{}, 0, len(ids)*2)
		for _, id := range ids {
			args = append(args, srcID, id)
		}
		_, err := stmt.ExecContext(ctx, args...)
		return err
	}

	for _, d := range domains {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var id int64
		err := insertDomain.QueryRowContext(ctx, d).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			// Already known to another source: look up its id.
			id, err = lookupDomainID(ctx, findDomain, d)
		} else if err != nil {
			return err
		}
		if err != nil {
			return err
		}
		domainIDs = append(domainIDs, id)
		if len(domainIDs) == batch {
			if err := flush(domainIDs); err != nil {
				return err
			}
			domainIDs = domainIDs[:0]
		}
	}
	if err := flush(domainIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.checkpoint(ctx)
}

// checkpoint truncates the WAL so a large snapshot import doesn't leave a
// multi-hundred-MB write-ahead log on disk. Best-effort: a busy checkpoint is
// harmless and retried by SQLite later.
func (s *BlocklistStore) checkpoint(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// upsertSourceID returns the integer id of the source URL, inserting it when
// new. Caller's transaction commits the insert.
func upsertSourceID(ctx context.Context, tx *sql.Tx, url string) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx,
		`INSERT INTO blocklist_sources (url) VALUES (?) ON CONFLICT(url) DO UPDATE SET url = excluded.url RETURNING source_id`,
		url).Scan(&id)
	return id, err
}

func lookupDomainID(ctx context.Context, stmt *sql.Stmt, domain string) (int64, error) {
	var id int64
	err := stmt.QueryRowContext(ctx, domain).Scan(&id)
	return id, err
}

// membershipInsertSQL builds a single-statement multi-row INSERT into
// blocklist_membership with n rows of (source_id, domain_id).
func membershipInsertSQL(n int) string {
	return "INSERT INTO blocklist_membership (source_id, domain_id) VALUES " +
		strings.TrimSuffix(strings.Repeat("(?,?),", n), ",")
}

// LoadSourceDomains returns the last successfully downloaded domain set for a
// source. An empty (or absent) snapshot yields an empty set, never an error.
func (s *BlocklistStore) LoadSourceDomains(ctx context.Context, url string) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.domain
		FROM blocklist_membership m
		JOIN blocklist_sources  src ON src.source_id = m.source_id
		JOIN blocklist_domains  d   ON d.domain_id   = m.domain_id
		WHERE src.url = ?`, url)
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
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT url FROM blocklist_sources UNION SELECT source_url FROM blocklist_source_meta`)
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
		// Delete membership rows first; orphaned domain rows are cleaned up
		// below so a source removal actually shrinks the database.
		if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_membership WHERE source_id = (SELECT source_id FROM blocklist_sources WHERE url = ?)`, u); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_sources WHERE url = ?`, u); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_source_meta WHERE source_url = ?`, u); err != nil {
			return err
		}
	}
	// Drop domains no longer referenced by any source snapshot. The merged
	// blocklist table is independent and is not touched.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM blocklist_domains WHERE NOT EXISTS (
			SELECT 1 FROM blocklist_membership m WHERE m.domain_id = blocklist_domains.domain_id)`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.checkpoint(ctx)
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
		SELECT src.url
		FROM blocklist_domains d
		JOIN blocklist_membership m ON m.domain_id = d.domain_id
		JOIN blocklist_sources src  ON src.source_id = m.source_id
		WHERE d.domain = ?
		ORDER BY src.url`, domain)
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

// migrateLegacySourceDomains converts the pre-normalization
// blocklist_source_domains(source_url, domain) table into the normalized
// sources/domains/membership tables, then drops the legacy table. It is a
// no-op when the legacy table is absent (fresh or already-migrated DB).
// Failure is non-fatal: NewBlocklistStore logs it and the next startup retries.
func (s *BlocklistStore) migrateLegacySourceDomains(ctx context.Context) error {
	var name string
	err := s.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'blocklist_source_domains'`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // nothing to migrate
	}
	if err != nil {
		return err
	}
	log.Printf("blipc: migrating blocklist source snapshots to normalized schema (one-time, may take a minute)")

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO blocklist_sources (url)
		SELECT DISTINCT source_url FROM blocklist_source_domains
		WHERE source_url NOT IN (SELECT url FROM blocklist_sources)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO blocklist_domains (domain)
		SELECT DISTINCT domain FROM blocklist_source_domains
		WHERE domain NOT IN (SELECT domain FROM blocklist_domains)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO blocklist_membership (source_id, domain_id)
		SELECT src.source_id, d.domain_id
		FROM blocklist_source_domains leg
		JOIN blocklist_sources src ON src.url = leg.source_url
		JOIN blocklist_domains d   ON d.domain = leg.domain
		WHERE NOT EXISTS (
			SELECT 1 FROM blocklist_membership m
			WHERE m.source_id = src.source_id AND m.domain_id = d.domain_id)`); err != nil {
		return err
	}
	// Drop the legacy table only after the copy committed cleanly.
	if _, err := tx.ExecContext(ctx, `DROP TABLE blocklist_source_domains`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		// Space is reclaimed lazily even without VACUUM; not fatal.
		log.Printf("blipc: warning: post-migration VACUUM failed: %v", err)
	}
	return s.checkpoint(ctx)
}

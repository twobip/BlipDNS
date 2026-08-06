package controller

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// QueryLogStore provides persistent storage for query log events
type QueryLogStore struct {
	db *sql.DB
}

// QueryLogEntry represents a single DNS query event
type QueryLogEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Instance  string    `json:"instance"`
	Client    string    `json:"client"`
	Name      string    `json:"name,omitempty"` // friendly display name, if set
	Domain    string    `json:"domain"`
	Action    string    `json:"action"`
	Upstream  string    `json:"upstream,omitempty"`
	IPs       []string  `json:"ips,omitempty"`
	// DurationUs is how long the query took to answer, in microseconds.
	// Cached reports whether the answer was served from the response cache.
	DurationUs int64 `json:"duration_us,omitempty"`
	Cached     bool  `json:"cached"`
}

// ClientStat is the per-client summary shown on the Clients tab.
type ClientStat struct {
	Client   string    `json:"client"` // DoH client ID or client IP
	Name     string    `json:"name"`   // friendly display name, if set
	Kind     string    `json:"kind"`   // "client" (DoH ID) or "ip"
	Queries  int       `json:"queries"`
	Blocked  int       `json:"blocked"`
	LastSeen time.Time `json:"last_seen"`
}

// ClientStats aggregates query-log activity by client (DoH client ID or source
// IP), most active first, capped at limit.
func (s *QueryLogStore) ClientStats(ctx context.Context, instance string, since time.Time, limit int) ([]ClientStat, error) {
	query := `SELECT ql.client, COALESCE(MAX(cn.name), ''), COUNT(*), SUM(CASE WHEN ql.action = 'BLOCK' THEN 1 ELSE 0 END), MAX(ql.timestamp) FROM query_log ql LEFT JOIN client_names cn ON cn.client = ql.client WHERE ql.timestamp >= ? AND ql.domain != 'health_check'`
	args := []interface{}{since}
	if instance != "" {
		query += " AND ql.instance = ?"
		args = append(args, instance)
	}
	query += " GROUP BY ql.client ORDER BY COUNT(*) DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ClientStat
	for rows.Next() {
		var c ClientStat
		var blocked sql.NullInt64
		var last string
		if err := rows.Scan(&c.Client, &c.Name, &c.Queries, &blocked, &last); err != nil {
			return nil, err
		}
		c.Blocked = int(blocked.Int64)
		c.LastSeen = parseQueryTS(last)
		if net.ParseIP(c.Client) != nil {
			c.Kind = "ip"
		} else {
			c.Kind = "client"
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TimeSeriesPoint represents a single point in a time series
type TimeSeriesPoint struct {
	Timestamp      time.Time `json:"timestamp"`
	TotalQueries   int       `json:"total_queries"`
	BlockedQueries int       `json:"blocked_queries"`
}

// StatsSample is a periodic snapshot of an instance's cumulative counters.
// Deltas between consecutive samples are computed at query time, so the series
// survives both controller and instance restarts without double counting.
type StatsSample struct {
	ID        int64
	Timestamp time.Time
	Instance  string
	Queries   uint64 // cumulative since instance (re)start
	Blocked   uint64
	Errors    uint64
}

// PerInstanceStats is the aggregate of a single instance over a time range.
type PerInstanceStats struct {
	Queries int `json:"queries"`
	Blocked int `json:"blocked"`
}

// StatsAggregate is the aggregated statistics for a time range.
type StatsAggregate struct {
	TotalQueries   int                          `json:"total_queries"`
	BlockedQueries int                          `json:"blocked_queries"`
	UpstreamErrors int                          `json:"upstream_errors"`
	PerInstance    map[string]*PerInstanceStats `json:"per_instance"`
	Series         []TimeSeriesPoint            `json:"series"`
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
		upstream TEXT,
		ips TEXT,
		duration_us INTEGER,
		cached INTEGER
	);
	CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_query_log_instance ON query_log(instance);
	CREATE TABLE IF NOT EXISTS stats_samples (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		instance TEXT NOT NULL,
		queries INTEGER NOT NULL,
		blocked INTEGER NOT NULL,
		errors INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_stats_samples_timestamp ON stats_samples(timestamp);
	CREATE TABLE IF NOT EXISTS client_names (
		client TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	// Add columns to existing databases (no-ops if already present)
	for _, col := range []string{
		"ALTER TABLE query_log ADD COLUMN ips TEXT",
		"ALTER TABLE query_log ADD COLUMN duration_us INTEGER",
		"ALTER TABLE query_log ADD COLUMN cached INTEGER",
	} {
		_, _ = db.Exec(col)
	}

	// Start cleanup goroutine
	store := &QueryLogStore{db: db}
	go store.cleanupLoop()

	return store, nil
}

// Insert adds a new query log entry
func (s *QueryLogStore) Insert(ctx context.Context, e QueryLogEntry) error {
	ips := strings.Join(e.IPs, ",")
	cached := 0
	if e.Cached {
		cached = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO query_log (timestamp, instance, client, domain, action, upstream, ips, duration_us, cached) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Instance, e.Client, e.Domain, e.Action, e.Upstream, ips, e.DurationUs, cached)
	return err
}

// Query returns entries within the time range
func (s *QueryLogStore) Query(ctx context.Context, instance, filter string, since time.Time, limit int) ([]QueryLogEntry, error) {
	query := `SELECT ql.id, ql.timestamp, ql.instance, ql.client, COALESCE(cn.name, ''), ql.domain, ql.action, ql.upstream, ql.ips, ql.duration_us, ql.cached FROM query_log ql LEFT JOIN client_names cn ON cn.client = ql.client WHERE ql.timestamp >= ? AND ql.domain != 'health_check'`
	args := []interface{}{since}

	if instance != "" {
		query += " AND ql.instance = ?"
		args = append(args, instance)
	}

	filterLower := ""
	if filter != "" {
		filterLower = "%" + filter + "%"
		query += " AND (LOWER(ql.client) LIKE ? OR LOWER(cn.name) LIKE ? OR LOWER(ql.domain) LIKE ? OR LOWER(ql.action) LIKE ?)"
		args = append(args, filterLower, filterLower, filterLower, filterLower)
	}

	query += " ORDER BY ql.timestamp DESC LIMIT ?"
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
		var ips sql.NullString
		var dur, cached sql.NullInt64
		if err := rows.Scan(&e.ID, &ts, &e.Instance, &e.Client, &e.Name, &e.Domain, &e.Action, &e.Upstream, &ips, &dur, &cached); err != nil {
			return nil, err
		}
		e.Timestamp = parseQueryTS(ts)
		if ips.Valid && ips.String != "" {
			e.IPs = strings.Split(ips.String, ",")
		}
		e.DurationUs = dur.Int64
		e.Cached = cached.Valid && cached.Int64 != 0
		results = append(results, e)
	}
	return results, rows.Err()
}

// SetClientName upserts the friendly display name for a client (DoH client ID
// or source IP). An empty name removes the mapping.
func (s *QueryLogStore) SetClientName(ctx context.Context, client, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM client_names WHERE client = ?`, client)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO client_names (client, name, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(client) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at`,
		client, name, time.Now())
	return err
}

// ClientNames returns the full client → friendly-name mapping.
func (s *QueryLogStore) ClientNames(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client, name FROM client_names`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var c, n string
		if err := rows.Scan(&c, &n); err != nil {
			return nil, err
		}
		out[c] = n
	}
	return out, rows.Err()
}

// AddStatsSample records a snapshot of an instance's cumulative counters.
func (s *QueryLogStore) AddStatsSample(ctx context.Context, e StatsSample) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO stats_samples (timestamp, instance, queries, blocked, errors) VALUES (?, ?, ?, ?, ?)`,
		e.Timestamp, e.Instance, e.Queries, e.Blocked, e.Errors)
	return err
}

// AggregateStats returns the totals, per-instance breakdown and per-bucket
// time series for the given range. Deltas are computed between consecutive
// samples per instance, so a counter decrease (instance restart) is treated as
// a reset whose full value counts as new activity.
func (s *QueryLogStore) AggregateStats(ctx context.Context, instance string, bucketSize time.Duration, since time.Time) (*StatsAggregate, error) {
	query := `SELECT timestamp, instance, queries, blocked, errors FROM stats_samples WHERE timestamp >= ?`
	args := []interface{}{since}
	if instance != "" {
		query += " AND instance = ?"
		args = append(args, instance)
	}
	query += " ORDER BY timestamp ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	agg := &StatsAggregate{PerInstance: make(map[string]*PerInstanceStats)}
	last := make(map[string]StatsSample) // last cumulative counters per instance
	buckets := make(map[int64]*TimeSeriesPoint)
	secs := int64(bucketSize.Seconds())
	for rows.Next() {
		var tsStr, inst string
		var q, b, e uint64
		if err := rows.Scan(&tsStr, &inst, &q, &b, &e); err != nil {
			return nil, err
		}
		ts := parseQueryTS(tsStr)

		dq, db, de := uint64(0), uint64(0), uint64(0)
		if prev, ok := last[inst]; ok {
			dq = counterDelta(q, prev.Queries)
			db = counterDelta(b, prev.Blocked)
			de = counterDelta(e, prev.Errors)
		}
		last[inst] = StatsSample{Timestamp: ts, Instance: inst, Queries: q, Blocked: b, Errors: e}

		agg.TotalQueries += int(dq)
		agg.BlockedQueries += int(db)
		agg.UpstreamErrors += int(de)
		pi := agg.PerInstance[inst]
		if pi == nil {
			pi = &PerInstanceStats{}
			agg.PerInstance[inst] = pi
		}
		pi.Queries += int(dq)
		pi.Blocked += int(db)

		bk := ts.Unix() / secs
		pt := buckets[bk]
		if pt == nil {
			pt = &TimeSeriesPoint{Timestamp: time.Unix(bk*secs, 0)}
			buckets[bk] = pt
		}
		pt.TotalQueries += int(dq)
		pt.BlockedQueries += int(db)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, v := range buckets {
		agg.Series = append(agg.Series, *v)
	}
	for i := 0; i < len(agg.Series)-1; i++ {
		for j := i + 1; j < len(agg.Series); j++ {
			if agg.Series[i].Timestamp.After(agg.Series[j].Timestamp) {
				agg.Series[i], agg.Series[j] = agg.Series[j], agg.Series[i]
			}
		}
	}
	return agg, nil
}

// counterDelta returns the increase of a counter between samples, treating a
// decrease as an instance restart: the full new value counts as new activity.
func counterDelta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// ClearQueryLog deletes all query log entries.
func (s *QueryLogStore) ClearQueryLog(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM query_log`)
	return err
}

// ClearStatsSamples deletes all aggregated statistics samples, resetting the
// dashboard totals and charts. The next sample written by an instance becomes
// a fresh baseline (deltas are computed between consecutive samples).
func (s *QueryLogStore) ClearStatsSamples(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM stats_samples`)
	return err
}

// cleanupLoop removes old query log entries (24h) and stats samples (1 month).
func (s *QueryLogStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		ctx := context.Background()
		s.db.ExecContext(ctx, `DELETE FROM query_log WHERE timestamp < ?`, time.Now().Add(-24*time.Hour))
		s.db.ExecContext(ctx, `DELETE FROM stats_samples WHERE timestamp < ?`, time.Now().Add(-31*24*time.Hour))
	}
}

// Close closes the database connection
func (s *QueryLogStore) Close() error {
	return s.db.Close()
}

// parseQueryTS parses the timestamp formats written to SQLite. Entries are
// stored as Go's time.Time.String() text (including a trailing monotonic
// "m=…" reading), but older rows may hold RFC3339Nano or the bare
// "2006-01-02 15:04:05" form, so try each in turn.
func parseQueryTS(s string) time.Time {
	if i := strings.LastIndex(s, " m="); i > 0 {
		s = s[:i]
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

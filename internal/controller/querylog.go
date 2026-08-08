package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// QueryLogStore provides persistent storage for query log events
type QueryLogStore struct {
	db        *sql.DB
	buf       chan QueryLogEntry // async batch buffer for high-frequency events
	stop      chan struct{}
	wg        sync.WaitGroup
	dropped   atomic.Uint64 // entries dropped because the buffer was full
	retention atomic.Int64  // how long query_log entries are kept (time.Duration)
}

// batch limits for the async writer: flushes when a batch fills or the
// interval elapses, whichever comes first.
const (
	batchMax      = 500
	batchInterval = 100 * time.Millisecond
)

// defaultQueryLogRetention is how long query log entries are kept unless the
// operator picks a different retention in the controller settings.
const defaultQueryLogRetention = 24 * time.Hour

// Answer is a single resource record attached to a QueryLogEntry for display.
type Answer struct {
	Type string `json:"type"` // textual RR type, e.g. "A", "AAAA", "TXT", "CNAME", "MX", "SRV"
	Data string `json:"data"` // rendered rdata (owner name omitted)
	TTL  int    `json:"ttl,omitempty"`
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
	// BlockList names the list/policy that blocked this query ("" when the
	// query was not blocked).
	BlockList string `json:"blocklist,omitempty"`
	// QType is the textual RR type of the question (e.g. "A", "TXT", "MX").
	QType string `json:"q_type,omitempty"`
	// IPs holds the A/AAAA rdata (kept for backward compatibility with the
	// Resolved IP column rendering).
	IPs []string `json:"ips,omitempty"`
	// Answers holds every response record in display form (type + data),
	// preserving non-IP answers like TXT/CNAME/MX for the query log.
	Answers []Answer `json:"answers,omitempty"`
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

// TopDomain is one entry of the dashboard's most-queried list.
type TopDomain struct {
	Domain  string `json:"domain"`
	Queries int    `json:"queries"`
	Blocked int    `json:"blocked"`
}

// UpstreamError is a single upstream failure event streamed from an instance.
type UpstreamError struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Instance  string    `json:"instance"` // instance label
	Domain    string    `json:"domain"`
	Message   string    `json:"message"`
}

// UpstreamErrorStat groups identical upstream failures for the errors
// drill-down page: how many times a given error happened, and when.
type UpstreamErrorStat struct {
	Message   string    `json:"message"`
	Domain    string    `json:"domain"`
	Instance  string    `json:"instance"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ClientStats aggregates query-log activity by client (DoH client ID or source
// IP), most active first, capped at limit.
func (s *QueryLogStore) ClientStats(ctx context.Context, instance string, since time.Time, limit int) ([]ClientStat, error) {
	query := `SELECT ql.client, COALESCE(MAX(cn.name), ''), COUNT(*), SUM(CASE WHEN ql.action = 'BLOCK' THEN 1 ELSE 0 END), MAX(ql.timestamp) FROM query_log ql LEFT JOIN client_names cn ON cn.client = ql.client WHERE ql.timestamp >= ? AND ql.domain != 'health_check' AND ql.domain != ''`
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

// TopDomains returns the most-queried domains within the range, by total query
// count, with the blocked subset of each. health_check probes and empty
// (rate-limited before the domain was known) entries are excluded.
func (s *QueryLogStore) TopDomains(ctx context.Context, instance string, since time.Time, limit int) ([]TopDomain, error) {
	query := `SELECT ql.domain, COUNT(*), SUM(CASE WHEN ql.action = 'BLOCK' THEN 1 ELSE 0 END) FROM query_log ql WHERE ql.timestamp >= ? AND ql.domain != 'health_check' AND ql.domain != ''`
	args := []interface{}{since}
	if instance != "" {
		query += " AND ql.instance = ?"
		args = append(args, instance)
	}
	query += " GROUP BY ql.domain ORDER BY COUNT(*) DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TopDomain
	for rows.Next() {
		var td TopDomain
		var blocked sql.NullInt64
		if err := rows.Scan(&td.Domain, &td.Queries, &blocked); err != nil {
			return nil, err
		}
		td.Blocked = int(blocked.Int64)
		out = append(out, td)
	}
	if out == nil {
		out = []TopDomain{}
	}
	return out, rows.Err()
}

// InstanceCacheStat is one instance's cache hit/miss tally for a time range.
type InstanceCacheStat struct {
	Queries       int     `json:"queries"`
	CachedQueries int     `json:"cached_queries"`
	PercentCached float64 `json:"percent_cached"`
	AvgCachedUs   float64 `json:"avg_cached_us"`  // avg latency of cache hits (microseconds, 0 if none)
	AvgFetchedUs  float64 `json:"avg_fetched_us"` // avg latency of cache misses (microseconds, 0 if none)
}

// TopCachedDomain is a domain frequently served from the response cache — the
// domains getting the most cache hits within the window.
type TopCachedDomain struct {
	Domain      string  `json:"domain"`
	CacheHits   int     `json:"cache_hits"`    // cached answers in the window
	CacheMisses int     `json:"cache_misses"`  // uncached (fresh) fetches in the window
	HitRate     float64 `json:"hit_rate"`      // cache_hits / (cache_hits + cache_misses)
	AvgCachedUs float64 `json:"avg_cached_us"` // avg latency of cache hits
}

// TopCachedDomains returns the domains with the most cache hits (i.e. the
// domains most frequently served from cache) within the time window, most
// cached first. Blocked queries and health checks are excluded.
func (s *QueryLogStore) TopCachedDomains(ctx context.Context, instance string, since time.Time, limit int) ([]TopCachedDomain, error) {
	query := `SELECT ql.domain, COALESCE(SUM(CASE WHEN ql.cached = 1 THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN ql.cached = 0 THEN 1 ELSE 0 END), 0), COALESCE(AVG(CASE WHEN ql.cached = 1 AND ql.duration_us > 0 THEN ql.duration_us END), 0) FROM query_log ql WHERE ql.timestamp >= ? AND ql.domain != 'health_check' AND ql.domain != '' AND ql.action = 'PASS'`
	args := []interface{}{since}
	if instance != "" {
		query += " AND ql.instance = ?"
		args = append(args, instance)
	}
	query += " GROUP BY ql.domain ORDER BY SUM(CASE WHEN ql.cached = 1 THEN 1 ELSE 0 END) DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TopCachedDomain
	for rows.Next() {
		var d TopCachedDomain
		if err := rows.Scan(&d.Domain, &d.CacheHits, &d.CacheMisses, &d.AvgCachedUs); err != nil {
			return nil, err
		}
		total := d.CacheHits + d.CacheMisses
		if total > 0 {
			d.HitRate = float64(d.CacheHits) / float64(total) * 100
		}
		out = append(out, d)
	}
	if out == nil {
		out = []TopCachedDomain{}
	}
	return out, rows.Err()
}

// CacheStats returns per-instance cache hit/miss tallies for "pass" (resolved)
// queries in the time range. Blocked queries and health checks never pass
// through the cache and are excluded, so the percentage reflects resolved
// queries only. When instance is non-empty only that instance is returned.
// Average latencies for cached (hit) and fetched (miss) queries are also
// returned in microseconds.
func (s *QueryLogStore) CacheStats(ctx context.Context, instance string, since time.Time) (map[string]InstanceCacheStat, error) {
	query := `SELECT ql.instance, COUNT(*), COALESCE(SUM(CASE WHEN ql.cached = 1 THEN 1 ELSE 0 END), 0), COALESCE(AVG(CASE WHEN ql.cached = 1 AND ql.duration_us > 0 THEN ql.duration_us END), 0), COALESCE(AVG(CASE WHEN ql.cached = 0 AND ql.duration_us > 0 THEN ql.duration_us END), 0) FROM query_log ql WHERE ql.timestamp >= ? AND ql.domain != 'health_check' AND ql.domain != '' AND ql.action = 'PASS'`
	args := []interface{}{since}
	if instance != "" {
		query += " AND ql.instance = ?"
		args = append(args, instance)
	}
	query += " GROUP BY ql.instance ORDER BY ql.instance"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]InstanceCacheStat)
	for rows.Next() {
		var inst string
		var c InstanceCacheStat
		if err := rows.Scan(&inst, &c.Queries, &c.CachedQueries, &c.AvgCachedUs, &c.AvgFetchedUs); err != nil {
			return nil, err
		}
		if c.Queries > 0 {
			c.PercentCached = float64(c.CachedQueries) / float64(c.Queries) * 100
		}
		out[inst] = c
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
	TotalQueries   int `json:"total_queries"`
	BlockedQueries int `json:"blocked_queries"`
	UpstreamErrors int `json:"upstream_errors"`
	// AvgQPS is the fleet-wide average query rate over the sampled span of the
	// range (total queries ÷ elapsed seconds), so it reflects actual coverage
	// rather than the whole requested window.
	AvgQPS      float64                      `json:"avg_qps"`
	PerInstance map[string]*PerInstanceStats `json:"per_instance"`
	Series      []TimeSeriesPoint            `json:"series"`
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
		q_type TEXT,
		ips TEXT,
		answers TEXT,
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
	CREATE TABLE IF NOT EXISTS upstream_errors (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		instance TEXT NOT NULL,
		domain TEXT NOT NULL,
		message TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_upstream_errors_timestamp ON upstream_errors(timestamp);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	// Add columns to existing databases (no-ops if already present)
	for _, col := range []string{
		"ALTER TABLE query_log ADD COLUMN q_type TEXT",
		"ALTER TABLE query_log ADD COLUMN answers TEXT",
		"ALTER TABLE query_log ADD COLUMN ips TEXT",
		"ALTER TABLE query_log ADD COLUMN duration_us INTEGER",
		"ALTER TABLE query_log ADD COLUMN cached INTEGER",
		"ALTER TABLE query_log ADD COLUMN blocklist TEXT",
	} {
		_, _ = db.Exec(col)
	}

	// Start cleanup goroutine
	store := &QueryLogStore{
		db:   db,
		buf:  make(chan QueryLogEntry, 4096),
		stop: make(chan struct{}),
	}
	store.retention.Store(int64(defaultQueryLogRetention))
	store.wg.Add(1)
	go store.batchWriter()
	go store.cleanupLoop()

	return store, nil
}

// Insert adds a new query log entry
func (s *QueryLogStore) Insert(ctx context.Context, e QueryLogEntry) error {
	ips := strings.Join(e.IPs, ",")
	ans, _ := json.Marshal(e.Answers)
	cached := 0
	if e.Cached {
		cached = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO query_log (timestamp, instance, client, domain, action, upstream, q_type, blocklist, ips, answers, duration_us, cached) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Instance, e.Client, e.Domain, e.Action, e.Upstream, e.QType, e.BlockList, ips, string(ans), e.DurationUs, cached)
	return err
}

// Query returns entries within the time range. offset/limit page through the
// results backwards in time (newest first); ordering is stable on (timestamp,
// id) DESC so consecutive pages never duplicate or skip a row. An empty action
// means "any action"; pass "PASS" or "BLOCK" to narrow by query outcome.
// cached is "" (any), "1" (cached only) or "0" (uncached only).
func (s *QueryLogStore) Query(ctx context.Context, instance, filter, action, cached string, since time.Time, offset, limit int) ([]QueryLogEntry, error) {
	query := `SELECT ql.id, ql.timestamp, ql.instance, ql.client, COALESCE(cn.name, ''), ql.domain, ql.action, ql.upstream, ql.q_type, ql.blocklist, ql.ips, ql.answers, ql.duration_us, ql.cached FROM query_log ql LEFT JOIN client_names cn ON cn.client = ql.client WHERE ql.timestamp >= ? AND ql.domain != 'health_check' AND ql.domain != ''`
	args := []interface{}{since}

	if instance != "" {
		query += " AND ql.instance = ?"
		args = append(args, instance)
	}
	if action != "" {
		query += " AND ql.action = ?"
		args = append(args, action)
	}
	if cached != "" {
		query += " AND ql.cached = ?"
		args = append(args, cached)
	}

	filterLower := ""
	if filter != "" {
		filterLower = "%" + filter + "%"
		query += " AND (LOWER(ql.client) LIKE ? OR LOWER(cn.name) LIKE ? OR LOWER(ql.domain) LIKE ? OR LOWER(ql.action) LIKE ?)"
		args = append(args, filterLower, filterLower, filterLower, filterLower)
	}

	query += " ORDER BY ql.timestamp DESC, ql.id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []QueryLogEntry
	for rows.Next() {
		var e QueryLogEntry
		var ts string
		var qType, bl, ips, ans sql.NullString
		var dur, cached sql.NullInt64
		if err := rows.Scan(&e.ID, &ts, &e.Instance, &e.Client, &e.Name, &e.Domain, &e.Action, &e.Upstream, &qType, &bl, &ips, &ans, &dur, &cached); err != nil {
			return nil, err
		}
		e.Timestamp = parseQueryTS(ts)
		if qType.Valid {
			e.QType = qType.String
		}
		if bl.Valid {
			e.BlockList = bl.String
		}
		if ips.Valid && ips.String != "" {
			e.IPs = strings.Split(ips.String, ",")
		}
		if ans.Valid && ans.String != "" {
			_ = json.Unmarshal([]byte(ans.String), &e.Answers)
		}
		e.DurationUs = dur.Int64
		e.Cached = cached.Valid && cached.Int64 != 0
		results = append(results, e)
	}
	return results, rows.Err()
}

// QueryCount returns the total number of query log entries that match the
// (instance, filter, action, cached, since) constraints, regardless of any
// limit/offset paging.
func (s *QueryLogStore) QueryCount(ctx context.Context, instance, filter, action, cached string, since time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM query_log WHERE timestamp >= ? AND domain != 'health_check' AND domain != ''`
	args := []interface{}{since}
	if instance != "" {
		query += " AND instance = ?"
		args = append(args, instance)
	}
	if action != "" {
		query += " AND action = ?"
		args = append(args, action)
	}
	if cached != "" {
		query += " AND cached = ?"
		args = append(args, cached)
	}
	if filter != "" {
		fl := "%" + filter + "%"
		query += " AND (LOWER(client) LIKE ? OR LOWER(domain) LIKE ? OR LOWER(action) LIKE ?)"
		args = append(args, fl, fl, fl)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
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

// RecordUpstreamError inserts a single upstream failure. Errors are low
// frequency so a direct insert is fine; they are grouped at query time.
func (s *QueryLogStore) RecordUpstreamError(ctx context.Context, e UpstreamError) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO upstream_errors (timestamp, instance, domain, message) VALUES (?, ?, ?, ?)`,
		e.Timestamp, e.Instance, e.Domain, e.Message)
	return err
}

// UpstreamErrorStats returns upstream failures within the range, grouped by
// message/domain/instance so the dashboard can show how many times each error
// happened and when. Most frequent (then most recent) first.
func (s *QueryLogStore) UpstreamErrorStats(ctx context.Context, instance string, since time.Time, limit int) ([]UpstreamErrorStat, error) {
	query := `SELECT message, domain, instance, COUNT(*), MIN(timestamp), MAX(timestamp) FROM upstream_errors WHERE timestamp >= ?`
	args := []interface{}{since}
	if instance != "" {
		query += " AND instance = ?"
		args = append(args, instance)
	}
	query += " GROUP BY message, domain, instance ORDER BY COUNT(*) DESC, MAX(timestamp) DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UpstreamErrorStat
	for rows.Next() {
		var st UpstreamErrorStat
		var first, last string
		if err := rows.Scan(&st.Message, &st.Domain, &st.Instance, &st.Count, &first, &last); err != nil {
			return nil, err
		}
		st.FirstSeen = parseQueryTS(first)
		st.LastSeen = parseQueryTS(last)
		out = append(out, st)
	}
	if out == nil {
		out = []UpstreamErrorStat{}
	}
	return out, rows.Err()
}

// UpstreamErrorCount returns how many upstream failures are stored within the
// window. It backs the dashboard stat so the count matches what the Upstream
// Errors page shows (and both drop to zero when errors are cleared).
func (s *QueryLogStore) UpstreamErrorCount(ctx context.Context, instance string, since time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM upstream_errors WHERE timestamp >= ?`
	args := []interface{}{since}
	if instance != "" {
		query += " AND instance = ?"
		args = append(args, instance)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ClearUpstreamErrors removes stored upstream failures. An empty instance
// clears the whole table; otherwise only that instance's errors are dropped.
func (s *QueryLogStore) ClearUpstreamErrors(ctx context.Context, instance string) error {
	if instance == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM upstream_errors`)
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM upstream_errors WHERE instance = ?`, instance)
	return err
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
	var first, lastTS time.Time // earliest / latest sample timestamp in the range
	for rows.Next() {
		var tsStr, inst string
		var q, b, e uint64
		if err := rows.Scan(&tsStr, &inst, &q, &b, &e); err != nil {
			return nil, err
		}
		ts := parseQueryTS(tsStr)
		if first.IsZero() || ts.Before(first) {
			first = ts
		}
		if ts.After(lastTS) {
			lastTS = ts
		}

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

	// Average QPS over the sampled span: the delta sum divided by the elapsed
	// seconds between the earliest and latest sample in the range.
	if agg.TotalQueries > 0 && !lastTS.IsZero() && lastTS.After(first) {
		agg.AvgQPS = float64(agg.TotalQueries) / lastTS.Sub(first).Seconds()
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

// cleanupLoop removes old query log entries (retention window, which also
// covers upstream errors) and stats samples (1 month).
func (s *QueryLogStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		ctx := context.Background()
		s.db.ExecContext(ctx, `DELETE FROM query_log WHERE timestamp < ?`, time.Now().Add(-s.Retention()))
		s.db.ExecContext(ctx, `DELETE FROM upstream_errors WHERE timestamp < ?`, time.Now().Add(-s.Retention()))
		s.db.ExecContext(ctx, `DELETE FROM stats_samples WHERE timestamp < ?`, time.Now().Add(-31*24*time.Hour))
	}
}

// Retention returns how long query log entries are kept.
func (s *QueryLogStore) Retention() time.Duration {
	return time.Duration(s.retention.Load())
}

// SetRetention updates how long query log entries are kept and immediately
// prunes anything older than the new window. Durations shorter than an hour
// are clamped up to an hour.
func (s *QueryLogStore) SetRetention(d time.Duration) {
	if d < time.Hour {
		d = time.Hour
	}
	s.retention.Store(int64(d))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.db.ExecContext(ctx, `DELETE FROM query_log WHERE timestamp < ?`, time.Now().Add(-d))
}

// Enqueue buffers a query-log entry for batched writing. It never blocks the
// caller (the watch-stream consumer): if the buffer is full the entry is
// dropped (and counted) rather than stalling event delivery.
func (s *QueryLogStore) Enqueue(e QueryLogEntry) {
	select {
	case s.buf <- e:
	default:
		s.dropped.Add(1)
	}
}

// DroppedEvents returns how many entries were dropped because the buffer was
// full.
func (s *QueryLogStore) DroppedEvents() uint64 {
	return s.dropped.Load()
}

// batchWriter drains the async buffer into SQLite using batched transactions
// so high-frequency block/pass events do not bottleneck the watch stream.
func (s *QueryLogStore) batchWriter() {
	defer s.wg.Done()
	buf := make([]QueryLogEntry, 0, batchMax)
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()
	for {
		select {
		case e := <-s.buf:
			buf = append(buf, e)
			if len(buf) >= batchMax {
				s.insertBatch(context.Background(), buf)
				buf = buf[:0]
			}
		case <-ticker.C:
			if len(buf) > 0 {
				s.insertBatch(context.Background(), buf)
				buf = buf[:0]
			}
		case <-s.stop:
			if len(buf) > 0 {
				s.insertBatch(context.Background(), buf)
			}
			return
		}
	}
}

// insertBatch writes entries in a single transaction.
func (s *QueryLogStore) insertBatch(ctx context.Context, entries []QueryLogEntry) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO query_log (timestamp, instance, client, domain, action, upstream, q_type, blocklist, ips, answers, duration_us, cached) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return
	}
	defer stmt.Close()
	for _, e := range entries {
		cached := 0
		if e.Cached {
			cached = 1
		}
		ips := strings.Join(e.IPs, ",")
		ans, _ := json.Marshal(e.Answers)
		if _, err := stmt.Exec(e.Timestamp, e.Instance, e.Client, e.Domain, e.Action, e.Upstream, e.QType, e.BlockList, ips, string(ans), e.DurationUs, cached); err != nil {
			_ = tx.Rollback()
			return
		}
	}
	_ = tx.Commit()
}

// Close flushes any buffered entries and closes the database.
func (s *QueryLogStore) Close() error {
	close(s.stop)
	s.wg.Wait()
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

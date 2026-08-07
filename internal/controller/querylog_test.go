package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestQueryLogStoreRoundtrip(t *testing.T) {
	store, err := NewQueryLogStore(filepath.Join(t.TempDir(), "querylog.db"))
	if err != nil {
		t.Fatalf("NewQueryLogStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now()
	want := QueryLogEntry{
		Timestamp:  now,
		Instance:   "a",
		Client:     "1.2.3.4",
		Domain:     "example.com",
		Action:     "PASS",
		IPs:        []string{"9.9.9.9", "::1"},
		DurationUs: 420,
		Cached:     true,
	}
	if err := store.Insert(ctx, want); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	entries, err := store.Query(ctx, "", "", time.Time{}, 100)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Query returned %d entries, want 1", len(entries))
	}
	got := entries[0]
	if got.Domain != want.Domain || got.DurationUs != want.DurationUs || !got.Cached {
		t.Errorf("roundtrip mismatch: duration_us=%d cached=%v, want %d/%v", got.DurationUs, got.Cached, want.DurationUs, want.Cached)
	}
	if len(got.IPs) != 2 || got.IPs[0] != "9.9.9.9" || got.IPs[1] != "::1" {
		t.Errorf("roundtrip IPs = %v, want [9.9.9.9 ::1]", got.IPs)
	}

	// A block entry with no timing info must round-trip with zero values.
	if err := store.Insert(ctx, QueryLogEntry{Timestamp: now.Add(time.Second), Instance: "a", Client: "1.2.3.4", Domain: "ads.test", Action: "BLOCK"}); err != nil {
		t.Fatalf("Insert block: %v", err)
	}
	entries, err = store.Query(ctx, "", "", time.Time{}, 100)
	if err != nil {
		t.Fatalf("Query 2: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Query returned %d entries, want 2", len(entries))
	}
}

func TestQueryLogStoreMaintenance(t *testing.T) {
	store, err := NewQueryLogStore(filepath.Join(t.TempDir(), "querylog.db"))
	if err != nil {
		t.Fatalf("NewQueryLogStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now()
	for i := 0; i < 5; i++ {
		if err := store.Insert(ctx, QueryLogEntry{
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Instance:  "a", Client: "1.2.3.4", Domain: "example.com", Action: "pass",
		}); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
	// Two cumulative samples: 100 then 120 -> delta of 20.
	if err := store.AddStatsSample(ctx, StatsSample{Timestamp: now, Instance: "a", Queries: 100, Blocked: 10, Errors: 1}); err != nil {
		t.Fatalf("AddStatsSample: %v", err)
	}
	if err := store.AddStatsSample(ctx, StatsSample{Timestamp: now.Add(time.Minute), Instance: "a", Queries: 120, Blocked: 12, Errors: 1}); err != nil {
		t.Fatalf("AddStatsSample 2: %v", err)
	}

	// Clear query log: entries gone, stats untouched.
	if err := store.ClearQueryLog(ctx); err != nil {
		t.Fatalf("ClearQueryLog: %v", err)
	}
	entries, err := store.Query(ctx, "", "", time.Time{}, 100)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("Query returned %d entries after clear, want 0", len(entries))
	}
	agg, err := store.AggregateStats(ctx, "", 5*time.Minute, time.Time{})
	if err != nil {
		t.Fatalf("AggregateStats: %v", err)
	}
	if agg.TotalQueries != 20 {
		t.Fatalf("AggregateStats total = %d after query-log clear, want 20", agg.TotalQueries)
	}

	// Reset stats: totals drop to zero; the next sample becomes a new baseline.
	if err := store.ClearStatsSamples(ctx); err != nil {
		t.Fatalf("ClearStatsSamples: %v", err)
	}
	agg, err = store.AggregateStats(ctx, "", 5*time.Minute, time.Time{})
	if err != nil {
		t.Fatalf("AggregateStats 2: %v", err)
	}
	if agg.TotalQueries != 0 {
		t.Fatalf("AggregateStats total after reset = %d, want 0", agg.TotalQueries)
	}
	if err := store.AddStatsSample(ctx, StatsSample{Timestamp: now.Add(2 * time.Minute), Instance: "a", Queries: 130, Blocked: 13, Errors: 1}); err != nil {
		t.Fatalf("AddStatsSample 3: %v", err)
	}
	agg, err = store.AggregateStats(ctx, "", 5*time.Minute, time.Time{})
	if err != nil {
		t.Fatalf("AggregateStats 3: %v", err)
	}
	if agg.TotalQueries != 0 {
		t.Fatalf("AggregateStats total after fresh baseline = %d, want 0", agg.TotalQueries)
	}
}

func TestQueryLogStoreClientStats(t *testing.T) {
	store, err := NewQueryLogStore(filepath.Join(t.TempDir(), "querylog.db"))
	if err != nil {
		t.Fatalf("NewQueryLogStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now()
	entries := []QueryLogEntry{
		{Timestamp: now.Add(-time.Minute), Instance: "a", Client: "laptop", Domain: "example.com", Action: "PASS"},
		{Timestamp: now.Add(-2 * time.Minute), Instance: "a", Client: "laptop", Domain: "ads.test", Action: "BLOCK"},
		{Timestamp: now.Add(-3 * time.Minute), Instance: "a", Client: "laptop", Domain: "health_check", Action: "PASS"},
		{Timestamp: now.Add(-4 * time.Minute), Instance: "b", Client: "1.2.3.4", Domain: "example.com", Action: "PASS"},
		{Timestamp: now.Add(-5 * time.Minute), Instance: "b", Client: "1.2.3.4", Domain: "tracker.test", Action: "BLOCK"},
	}
	for _, e := range entries {
		if err := store.Insert(ctx, e); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	// All instances: health checks excluded, client "laptop" and IP both present.
	stats, err := store.ClientStats(ctx, "", now.Add(-24*time.Hour), 250)
	if err != nil {
		t.Fatalf("ClientStats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("ClientStats returned %d clients, want 2", len(stats))
	}
	var laptop, ip *ClientStat
	for i := range stats {
		switch stats[i].Client {
		case "laptop":
			laptop = &stats[i]
		case "1.2.3.4":
			ip = &stats[i]
		}
	}
	if laptop == nil || laptop.Kind != "client" || laptop.Queries != 2 || laptop.Blocked != 1 {
		t.Errorf("laptop stat = %+v, want kind=client queries=2 blocked=1", laptop)
	}
	if ip == nil || ip.Kind != "ip" || ip.Queries != 2 || ip.Blocked != 1 {
		t.Errorf("ip stat = %+v, want kind=ip queries=2 blocked=1", ip)
	}

	// Instance filter narrows to instance "a" only.
	stats, err = store.ClientStats(ctx, "a", now.Add(-24*time.Hour), 250)
	if err != nil {
		t.Fatalf("ClientStats(a): %v", err)
	}
	if len(stats) != 1 || stats[0].Client != "laptop" || stats[0].Queries != 2 {
		t.Fatalf("ClientStats(a) = %+v, want only laptop with 2 queries", stats)
	}

	// Since window excludes everything.
	stats, err = store.ClientStats(ctx, "", now.Add(time.Hour), 250)
	if err != nil {
		t.Fatalf("ClientStats(since): %v", err)
	}
	if len(stats) != 0 {
		t.Fatalf("ClientStats(since) returned %d clients, want 0", len(stats))
	}
}

func TestClientNames(t *testing.T) {
	store, err := NewQueryLogStore(filepath.Join(t.TempDir(), "querylog.db"))
	if err != nil {
		t.Fatalf("NewQueryLogStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.SetClientName(ctx, "laptop", "Kids Laptop"); err != nil {
		t.Fatalf("SetClientName: %v", err)
	}
	if err := store.SetClientName(ctx, "1.2.3.4", "Living Room TV"); err != nil {
		t.Fatalf("SetClientName 2: %v", err)
	}
	names, err := store.ClientNames(ctx)
	if err != nil {
		t.Fatalf("ClientNames: %v", err)
	}
	if names["laptop"] != "Kids Laptop" || names["1.2.3.4"] != "Living Room TV" {
		t.Fatalf("ClientNames = %v", names)
	}

	// Rename overrides; empty clears.
	if err := store.SetClientName(ctx, "laptop", "Gaming Rig"); err != nil {
		t.Fatalf("SetClientName rename: %v", err)
	}
	if err := store.SetClientName(ctx, "1.2.3.4", ""); err != nil {
		t.Fatalf("SetClientName clear: %v", err)
	}
	names, err = store.ClientNames(ctx)
	if err != nil {
		t.Fatalf("ClientNames 2: %v", err)
	}
	if names["laptop"] != "Gaming Rig" {
		t.Fatalf("renamed laptop = %q, want Gaming Rig", names["laptop"])
	}
	if _, ok := names["1.2.3.4"]; ok {
		t.Fatalf("cleared 1.2.3.4 still present: %v", names)
	}

	// Names propagate into stats and query entries.
	now := time.Now()
	for _, e := range []QueryLogEntry{
		{Timestamp: now, Instance: "a", Client: "laptop", Domain: "example.com", Action: "PASS"},
		{Timestamp: now.Add(time.Second), Instance: "a", Client: "7.7.7.7", Domain: "example.com", Action: "PASS"},
	} {
		if err := store.Insert(ctx, e); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
	stats, err := store.ClientStats(ctx, "", now.Add(-time.Hour), 250)
	if err != nil {
		t.Fatalf("ClientStats: %v", err)
	}
	for _, s := range stats {
		if s.Client == "laptop" && s.Name != "Gaming Rig" {
			t.Errorf("ClientStats name = %q, want Gaming Rig", s.Name)
		}
		if s.Client == "7.7.7.7" && s.Name != "" {
			t.Errorf("ClientStats unnamed got %q", s.Name)
		}
	}
	entries, err := store.Query(ctx, "", "Gaming Rig", now.Add(-time.Hour), 100)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].Client != "laptop" || entries[0].Name != "Gaming Rig" {
		t.Fatalf("Query by name = %+v, want one laptop entry named Gaming Rig", entries)
	}
}

func TestQueryLogStoreCacheStats(t *testing.T) {
	store, err := NewQueryLogStore(filepath.Join(t.TempDir(), "querylog.db"))
	if err != nil {
		t.Fatalf("NewQueryLogStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now()
	entries := []QueryLogEntry{
		{Timestamp: now.Add(-time.Minute), Instance: "a", Client: "c", Domain: "example.com", Action: "PASS", Cached: true},
		{Timestamp: now.Add(-2 * time.Minute), Instance: "a", Client: "c", Domain: "foo.com", Action: "PASS", Cached: false},
		{Timestamp: now.Add(-3 * time.Minute), Instance: "a", Client: "c", Domain: "ads.test", Action: "BLOCK"},
		{Timestamp: now.Add(-4 * time.Minute), Instance: "a", Client: "c", Domain: "health_check", Action: "PASS"},
		{Timestamp: now.Add(-5 * time.Minute), Instance: "b", Client: "c", Domain: "example.com", Action: "PASS", Cached: true},
	}
	for _, e := range entries {
		if err := store.Insert(ctx, e); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	stats, err := store.CacheStats(ctx, "", now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("CacheStats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("CacheStats returned %d instances, want 2: %+v", len(stats), stats)
	}
	// a: 2 resolved (BLOCK + health_check excluded), 1 cached -> 50%.
	// b: 1 resolved, 1 cached -> 100%.
	if a := stats["a"]; a.Queries != 2 || a.CachedQueries != 1 || a.PercentCached != 50 {
		t.Errorf("instance a = %+v, want 2/1/50", a)
	}
	if b := stats["b"]; b.Queries != 1 || b.CachedQueries != 1 || b.PercentCached != 100 {
		t.Errorf("instance b = %+v, want 1/1/100", b)
	}

	// Instance filter narrows to a single instance.
	stats, err = store.CacheStats(ctx, "a", now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("CacheStats(a): %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("CacheStats(a) returned %d instances, want 1", len(stats))
	}

	// Since window excludes everything.
	stats, err = store.CacheStats(ctx, "", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("CacheStats(since): %v", err)
	}
	if len(stats) != 0 {
		t.Fatalf("CacheStats(since) returned %d instances, want 0", len(stats))
	}
}

func TestQueryLogStoreUpstreamErrors(t *testing.T) {
	store, err := NewQueryLogStore(filepath.Join(t.TempDir(), "querylog.db"))
	if err != nil {
		t.Fatalf("NewQueryLogStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now()
	errs := []UpstreamError{
		{Timestamp: now.Add(-time.Minute), Instance: "a", Domain: "example.com", Message: "i/o timeout"},
		{Timestamp: now.Add(-2 * time.Minute), Instance: "a", Domain: "example.com", Message: "i/o timeout"},
		{Timestamp: now.Add(-3 * time.Minute), Instance: "a", Domain: "other.test", Message: "i/o timeout"},
		{Timestamp: now.Add(-4 * time.Minute), Instance: "b", Domain: "example.com", Message: "connection refused"},
		{Timestamp: now.Add(-5 * time.Minute), Instance: "b", Domain: "example.com", Message: "connection refused"},
	}
	for _, e := range errs {
		if err := store.RecordUpstreamError(ctx, e); err != nil {
			t.Fatalf("RecordUpstreamError: %v", err)
		}
	}

	stats, err := store.UpstreamErrorStats(ctx, "", now.Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("UpstreamErrorStats: %v", err)
	}
	if len(stats) != 3 {
		t.Fatalf("UpstreamErrorStats returned %d groups, want 3", len(stats))
	}
	// Most frequent first: "i/o timeout"@example.com (2) beats the singleton groups.
	if stats[0].Count != 2 || stats[0].Message != "i/o timeout" || stats[0].Domain != "example.com" {
		t.Errorf("top group = %+v, want i/o timeout/example.com with count 2", stats[0])
	}
	if stats[0].FirstSeen.After(stats[0].LastSeen) {
		t.Errorf("first_seen %v after last_seen %v", stats[0].FirstSeen, stats[0].LastSeen)
	}
	for _, st := range stats {
		if st.Count <= 0 {
			t.Errorf("group %+v has non-positive count", st)
		}
	}

	// Instance filter narrows to one instance.
	stats, err = store.UpstreamErrorStats(ctx, "b", now.Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("UpstreamErrorStats(b): %v", err)
	}
	if len(stats) != 1 || stats[0].Instance != "b" || stats[0].Count != 2 {
		t.Fatalf("UpstreamErrorStats(b) = %+v, want one b group with count 2", stats)
	}

	// Since window excludes everything.
	stats, err = store.UpstreamErrorStats(ctx, "", now.Add(time.Hour), 100)
	if err != nil {
		t.Fatalf("UpstreamErrorStats(since): %v", err)
	}
	if len(stats) != 0 {
		t.Fatalf("UpstreamErrorStats(since) returned %d groups, want 0", len(stats))
	}

	// Clear only instance "a"; "b" must survive.
	if err := store.ClearUpstreamErrors(ctx, "a"); err != nil {
		t.Fatalf("ClearUpstreamErrors(a): %v", err)
	}
	stats, err = store.UpstreamErrorStats(ctx, "", now.Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("UpstreamErrorStats after clear: %v", err)
	}
	if len(stats) != 1 || stats[0].Instance != "b" || stats[0].Count != 2 {
		t.Fatalf("after clear(a) = %+v, want only the b group with count 2", stats)
	}

	// Clearing everything empties the table.
	if err := store.ClearUpstreamErrors(ctx, ""); err != nil {
		t.Fatalf("ClearUpstreamErrors(all): %v", err)
	}
	stats, err = store.UpstreamErrorStats(ctx, "", now.Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("UpstreamErrorStats after clear-all: %v", err)
	}
	if len(stats) != 0 {
		t.Fatalf("after clear-all = %+v, want no groups", stats)
	}
}

func TestQueryLogStoreBatchWriter(t *testing.T) {
	store, err := NewQueryLogStore(filepath.Join(t.TempDir(), "querylog.db"))
	if err != nil {
		t.Fatalf("NewQueryLogStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now()
	const n = 2000
	for i := 0; i < n; i++ {
		store.Enqueue(QueryLogEntry{
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
			Instance:  "a", Client: "batch-client", Domain: "example.com", Action: "PASS",
			DurationUs: int64(i),
			Cached:     i%2 == 0,
		})
	}

	// The async writer should flush everything shortly after the last enqueue.
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := store.Query(ctx, "", "", time.Time{}, 10000)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) == n {
			if entries[0].Client != "batch-client" || entries[0].DurationUs != int64(n-1) {
				t.Fatalf("batch roundtrip mismatch: first=%+v", entries[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("batch writer flushed %d/%d entries before deadline", len(entries), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

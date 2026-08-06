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

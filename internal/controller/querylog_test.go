package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

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

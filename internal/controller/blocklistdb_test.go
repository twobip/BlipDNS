package controller

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestBlocklistStoreRoundtrip(t *testing.T) {
	store, err := NewBlocklistStore(filepath.Join(t.TempDir(), "blocklist.db"))
	if err != nil {
		t.Fatalf("NewBlocklistStore: %v", err)
	}
	defer store.db.Close()

	ctx := context.Background()
	if err := store.ReplaceAll(ctx, []string{"ads.example.com", "*.tracker.net", "b.example.com"}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	set, err := store.LoadSet(ctx)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if len(set) != 3 {
		t.Fatalf("LoadSet returned %d domains, want 3", len(set))
	}
	if _, ok := set["ads.example.com"]; !ok {
		t.Error("ads.example.com missing from loaded set")
	}
	if _, ok := set["*.tracker.net"]; !ok {
		t.Error("*.tracker.net missing from loaded set")
	}

	// ReplaceAll with a smaller set must drop the rest.
	if err := store.ReplaceAll(ctx, []string{"only.example.com"}); err != nil {
		t.Fatalf("ReplaceAll smaller: %v", err)
	}
	set, err = store.LoadSet(ctx)
	if err != nil {
		t.Fatalf("LoadSet 2: %v", err)
	}
	if !reflect.DeepEqual(set, map[string]struct{}{"only.example.com": {}}) {
		t.Errorf("unexpected set after replace: %v", set)
	}

	// Empty list clears.
	if err := store.ReplaceAll(ctx, nil); err != nil {
		t.Fatalf("ReplaceAll empty: %v", err)
	}
	n, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Errorf("Count after clear = %d, want 0", n)
	}
}

func TestBlocklistStoreSourceSnapshots(t *testing.T) {
	store, err := NewBlocklistStore(filepath.Join(t.TempDir(), "blocklist.db"))
	if err != nil {
		t.Fatalf("NewBlocklistStore: %v", err)
	}
	defer store.db.Close()

	ctx := context.Background()
	u1 := "https://example.invalid/a.txt"
	u2 := "https://example.invalid/b.txt"

	if err := store.ReplaceSourceDomains(ctx, u1, []string{"a.example.com", "b.example.net"}); err != nil {
		t.Fatalf("ReplaceSourceDomains: %v", err)
	}
	// Replacing the same source must drop the previous snapshot.
	if err := store.ReplaceSourceDomains(ctx, u1, []string{"a.example.com", "c.example.org"}); err != nil {
		t.Fatalf("ReplaceSourceDomains 2: %v", err)
	}
	if err := store.ReplaceSourceDomains(ctx, u2, []string{"d.example.io"}); err != nil {
		t.Fatalf("ReplaceSourceDomains u2: %v", err)
	}

	set, err := store.LoadSourceDomains(ctx, u1)
	if err != nil {
		t.Fatalf("LoadSourceDomains: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("LoadSourceDomains returned %d, want 2", len(set))
	}
	if _, ok := set["c.example.org"]; !ok {
		t.Error("c.example.org missing; snapshot was not replaced")
	}
	if _, ok := set["b.example.net"]; ok {
		t.Error("b.example.net should have been dropped by replace")
	}

	lu := time.Now().UTC().Truncate(time.Second)
	if err := store.ReplaceSourceMeta(ctx, SourceMeta{URL: u1, Domains: 2, LastUpdate: lu, Error: ""}); err != nil {
		t.Fatalf("ReplaceSourceMeta: %v", err)
	}
	if err := store.ReplaceSourceMeta(ctx, SourceMeta{URL: u2, Domains: 1, LastUpdate: time.Time{}, Error: "boom"}); err != nil {
		t.Fatalf("ReplaceSourceMeta u2: %v", err)
	}

	meta, err := store.LoadSourceMeta(ctx)
	if err != nil {
		t.Fatalf("LoadSourceMeta: %v", err)
	}
	if meta[u1].Domains != 2 || !meta[u1].LastUpdate.Equal(lu) || meta[u1].Error != "" {
		t.Errorf("meta[u1] = %+v, want domains=2 / last_update=%v / no error", meta[u1], lu)
	}
	if meta[u2].Error != "boom" || !meta[u2].LastUpdate.IsZero() {
		t.Errorf("meta[u2] = %+v, want error=boom / zero last_update", meta[u2])
	}

	// Pruning keeps only configured sources.
	if err := store.PruneSources(ctx, []string{u2}); err != nil {
		t.Fatalf("PruneSources: %v", err)
	}
	set, err = store.LoadSourceDomains(ctx, u1)
	if err != nil {
		t.Fatalf("LoadSourceDomains after prune: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("pruned source snapshot still present (%d domains)", len(set))
	}
	meta, err = store.LoadSourceMeta(ctx)
	if err != nil {
		t.Fatalf("LoadSourceMeta after prune: %v", err)
	}
	if _, ok := meta[u1]; ok {
		t.Error("pruned source meta still present")
	}
	if meta[u2].Domains != 1 {
		t.Errorf("kept source meta lost: %+v", meta[u2])
	}
}

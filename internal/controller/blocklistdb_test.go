package controller

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
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

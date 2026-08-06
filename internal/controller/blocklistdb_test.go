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

func TestBlocklistStoreManualDomains(t *testing.T) {
	store, err := NewBlocklistStore(filepath.Join(t.TempDir(), "blocklist.db"))
	if err != nil {
		t.Fatalf("NewBlocklistStore: %v", err)
	}
	defer store.db.Close()

	ctx := context.Background()
	if err := store.ReplaceManualDomains(ctx, []string{"ads.example.com", "manual.net"}); err != nil {
		t.Fatalf("ReplaceManualDomains: %v", err)
	}
	set, err := store.LoadManualDomains(ctx)
	if err != nil {
		t.Fatalf("LoadManualDomains: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("LoadManualDomains returned %d, want 2", len(set))
	}
	if _, ok := set["ads.example.com"]; !ok {
		t.Error("ads.example.com missing from manual set")
	}

	// Replacing must drop the previous set.
	if err := store.ReplaceManualDomains(ctx, []string{"new.example.org"}); err != nil {
		t.Fatalf("ReplaceManualDomains 2: %v", err)
	}
	set, err = store.LoadManualDomains(ctx)
	if err != nil {
		t.Fatalf("LoadManualDomains 2: %v", err)
	}
	if !reflect.DeepEqual(set, map[string]struct{}{"new.example.org": {}}) {
		t.Errorf("unexpected manual set: %v", set)
	}

	// Empty clears.
	if err := store.ReplaceManualDomains(ctx, nil); err != nil {
		t.Fatalf("ReplaceManualDomains empty: %v", err)
	}
	set, err = store.LoadManualDomains(ctx)
	if err != nil {
		t.Fatalf("LoadManualDomains empty: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("manual set not cleared: %v", set)
	}
}

func TestFleetManualDomainsSurviveImport(t *testing.T) {
	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))

	fleet.AddManualDomain("custom.example.com")
	fleet.AddManualDomain("ALSO.example.com") // normalized on insert
	if got := fleet.ManualDomains(); !reflect.DeepEqual(got, []string{"also.example.com", "custom.example.com"}) {
		t.Fatalf("ManualDomains() = %v, want sorted normalized list", got)
	}

	// An import seeds the manual set into the merged list.
	merged := fleet.manualDomainSet()
	for _, d := range []string{"src.example.net", "src2.example.net"} {
		merged[d] = struct{}{}
	}
	fleet.Blocklist().FromDomainsMap(merged)
	if !fleet.Blocklist().IsBlocked("custom.example.com") {
		t.Error("manual domain missing after simulated import merge")
	}
	if !fleet.Blocklist().IsBlocked("also.example.com") {
		t.Error("normalized manual domain missing after import merge")
	}
	if !fleet.Blocklist().IsBlocked("src.example.net") {
		t.Error("source domain missing after import merge")
	}

	// Removing a manual domain keeps source domains intact.
	fleet.RemoveManualDomain("custom.example.com")
	if got := fleet.ManualDomains(); !reflect.DeepEqual(got, []string{"also.example.com"}) {
		t.Fatalf("ManualDomains after remove = %v", got)
	}
	if fleet.Blocklist().IsBlocked("custom.example.com") {
		t.Error("removed manual domain still blocked")
	}
	if !fleet.Blocklist().IsBlocked("also.example.com") {
		t.Error("remaining manual domain lost")
	}
	if !fleet.Blocklist().IsBlocked("src.example.net") {
		t.Error("source domain lost on manual remove")
	}

	// Removing a domain that was never manual is a no-op.
	fleet.RemoveManualDomain("src.example.net")
	if !fleet.Blocklist().IsBlocked("src.example.net") {
		t.Error("non-manual domain was removed")
	}

	// Clear wipes only the manual subset from the merged list.
	fleet.ClearManualDomains()
	if got := fleet.ManualDomains(); len(got) != 0 {
		t.Fatalf("manual set not cleared: %v", got)
	}
	if fleet.Blocklist().IsBlocked("also.example.com") {
		t.Error("manual domain survived clear")
	}
	if !fleet.Blocklist().IsBlocked("src2.example.net") {
		t.Error("source domain lost on manual clear")
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

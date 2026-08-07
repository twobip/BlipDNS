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

func TestBlocklistStoreManualAllowed(t *testing.T) {
	store, err := NewBlocklistStore(filepath.Join(t.TempDir(), "blocklist.db"))
	if err != nil {
		t.Fatalf("NewBlocklistStore: %v", err)
	}
	defer store.db.Close()

	ctx := context.Background()
	if err := store.ReplaceManualAllowed(ctx, []string{"keep.example.com", "wildcard.example.org"}); err != nil {
		t.Fatalf("ReplaceManualAllowed: %v", err)
	}
	set, err := store.LoadManualAllowed(ctx)
	if err != nil {
		t.Fatalf("LoadManualAllowed: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("LoadManualAllowed returned %d, want 2", len(set))
	}
	if _, ok := set["keep.example.com"]; !ok {
		t.Error("keep.example.com missing from allowed set")
	}

	// Replacing must drop the previous set.
	if err := store.ReplaceManualAllowed(ctx, []string{"other.example.io"}); err != nil {
		t.Fatalf("ReplaceManualAllowed 2: %v", err)
	}
	set, err = store.LoadManualAllowed(ctx)
	if err != nil {
		t.Fatalf("LoadManualAllowed 2: %v", err)
	}
	if !reflect.DeepEqual(set, map[string]struct{}{"other.example.io": {}}) {
		t.Errorf("unexpected allowed set: %v", set)
	}

	// Empty clears.
	if err := store.ReplaceManualAllowed(ctx, nil); err != nil {
		t.Fatalf("ReplaceManualAllowed empty: %v", err)
	}
	set, err = store.LoadManualAllowed(ctx)
	if err != nil {
		t.Fatalf("LoadManualAllowed empty: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("allowed set not cleared: %v", set)
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

func TestFleetManualAllowedSurviveImport(t *testing.T) {
	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))

	fleet.AddAllowedDomain("ads.example.com")
	fleet.AddAllowedDomain("TRACKER.net") // normalized on insert
	if got := fleet.AllowedDomains(); !reflect.DeepEqual(got, []string{"ads.example.com", "tracker.net"}) {
		t.Fatalf("AllowedDomains() = %v, want sorted normalized list", got)
	}

	// Simulate a source import whose list blocks the whitelisted domains.
	merged := map[string]struct{}{
		"ads.example.com": {},
		"tracker.net":     {},
		"*.tracker.net":   {},
		"src.example.net": {},
	}
	fleet.Blocklist().FromDomainsMap(merged)
	fleet.syncAllowed()
	if fleet.Blocklist().IsBlocked("ads.example.com") {
		t.Error("whitelisted domain blocked after import merge")
	}
	if fleet.Blocklist().IsBlocked("sub.tracker.net") {
		t.Error("subdomain of whitelisted root blocked after import merge")
	}
	if !fleet.Blocklist().IsBlocked("src.example.net") {
		t.Error("source domain missing after import merge")
	}

	// Removing a whitelist entry restores the block for that domain only.
	fleet.RemoveAllowedDomain("ads.example.com")
	if got := fleet.AllowedDomains(); !reflect.DeepEqual(got, []string{"tracker.net"}) {
		t.Fatalf("AllowedDomains after remove = %v", got)
	}
	if !fleet.Blocklist().IsBlocked("ads.example.com") {
		t.Error("removed whitelist domain still allowed")
	}
	if fleet.Blocklist().IsBlocked("tracker.net") {
		t.Error("remaining whitelist domain lost")
	}
	if !fleet.Blocklist().IsBlocked("src.example.net") {
		t.Error("source domain lost on whitelist remove")
	}

	// Clearing wipes the whole whitelist.
	fleet.ClearAllowedDomains()
	if got := fleet.AllowedDomains(); len(got) != 0 {
		t.Fatalf("allowed set not cleared: %v", got)
	}
	if !fleet.Blocklist().IsBlocked("tracker.net") {
		t.Error("whitelist domain survived clear")
	}
	if !fleet.Blocklist().IsBlocked("src.example.net") {
		t.Error("source domain lost on whitelist clear")
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

func TestBlocklistStoreBlockSourceLabel(t *testing.T) {
	store, err := NewBlocklistStore(filepath.Join(t.TempDir(), "blocklist.db"))
	if err != nil {
		t.Fatalf("NewBlocklistStore: %v", err)
	}
	ctx := context.Background()
	u1 := "https://example.com/list1.txt"
	u2 := "https://example.com/list2.txt"
	if err := store.ReplaceSourceDomains(ctx, u1, []string{"ads.example.com", "tracker.net"}); err != nil {
		t.Fatalf("ReplaceSourceDomains u1: %v", err)
	}
	if err := store.ReplaceSourceDomains(ctx, u2, []string{"ads.example.com"}); err != nil {
		t.Fatalf("ReplaceSourceDomains u2: %v", err)
	}

	// Domain in two sources -> both URLs, sorted.
	got, err := store.BlockSourceLabel(ctx, "ads.example.com")
	if err != nil {
		t.Fatalf("BlockSourceLabel: %v", err)
	}
	want := u1 + ", " + u2
	if got != want {
		t.Errorf("BlockSourceLabel(ads.example.com) = %q, want %q", got, want)
	}

	// Manual domains take precedence over source URLs.
	if err := store.ReplaceManualDomains(ctx, []string{"ads.example.com", "hand.added.net"}); err != nil {
		t.Fatalf("ReplaceManualDomains: %v", err)
	}
	got, err = store.BlockSourceLabel(ctx, "ads.example.com")
	if err != nil {
		t.Fatalf("BlockSourceLabel manual: %v", err)
	}
	if got != "manual" {
		t.Errorf("BlockSourceLabel(ads.example.com) = %q, want manual", got)
	}

	// Unknown domain -> empty label.
	got, err = store.BlockSourceLabel(ctx, "nope.test")
	if err != nil {
		t.Fatalf("BlockSourceLabel unknown: %v", err)
	}
	if got != "" {
		t.Errorf("BlockSourceLabel(nope.test) = %q, want empty", got)
	}
}

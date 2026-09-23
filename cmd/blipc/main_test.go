package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/twobip/BlipDNS/internal/controller"
)

// TestStartupRestorePreservesBlocklistSources guards the startup ordering
// bug where save-capable Fleet calls (SetRecords, Add) ran before the
// persisted blocklist settings were restored: saveConfig writes the source
// list from memory, so every restart clobbered blocklist_sources on disk,
// and a second restart before any save lost the sources permanently while
// the SQLite snapshot kept blocking, masking the loss.
func TestStartupRestorePreservesBlocklistSources(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "blipc.yaml")
	seed := "listen: \"127.0.0.1:8500\"\n" +
		"blocklist_sources:\n" +
		"  - https://example.com/list.txt\n" +
		"  - https://example.com/other.txt\n" +
		"blocklist_update_hours: 4\n"
	if err := os.WriteFile(cfgPath, []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.BlocklistSources) != 2 {
		t.Fatalf("seeded sources = %v", cfg.BlocklistSources)
	}

	fleet := controller.NewFleet(cfgPath)
	// Mirrors main(): restore first, then the startup calls that persist.
	restoreBlocklistSettings(fleet, cfg.BlocklistSources, cfg.BlocklistDisabled, cfg.BlocklistUpdateHours)
	fleet.SetRecords(context.Background(), cfg.Records)

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"https://example.com/list.txt", "https://example.com/other.txt", "blocklist_update_hours: 4"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config after startup saves is missing %q:\n%s", want, raw)
		}
	}
}

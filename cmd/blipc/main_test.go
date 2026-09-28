package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/twobip/BlipDNS/internal/controller"
)

// TestRefusePlainRemote pins the fail-closed matrix: directly-exposed
// plaintext is fatal, while loopback, TLS, explicit ack, or a configured
// TLS-terminating proxy (trusted_proxies) start with at most a warning.
func TestRefusePlainRemote(t *testing.T) {
	for _, tc := range []struct {
		name    string
		listen  string
		tls     bool
		allow   bool
		proxies []string
		want    bool
	}{
		{"loopback plain", "127.0.0.1:8500", false, false, nil, false},
		{"direct plain refused", "0.0.0.0:8500", false, false, nil, true},
		{"direct tls ok", "0.0.0.0:8500", true, false, nil, false},
		{"direct acked ok", "0.0.0.0:8500", false, true, nil, false},
		{"proxy plain warns only", "0.0.0.0:8500", false, false, []string{"192.168.30.149/32"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := refusePlainRemote(tc.listen, tc.tls, tc.allow, tc.proxies); got != tc.want {
				t.Fatalf("refusePlainRemote(%q)=%v, want %v", tc.listen, got, tc.want)
			}
		})
	}
}

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

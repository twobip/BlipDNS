package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "blipd.yaml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBlocklistUpdateHoursValidation(t *testing.T) {
	if _, err := Load(writeCfg(t, "blocklist_update_hours: -1\n")); err == nil {
		t.Fatal("negative hours: expected error, got nil")
	}
	c, err := Load(writeCfg(t, "blocklist_update_hours: 99999999\n"))
	if err != nil {
		t.Fatalf("absurd hours: unexpected error: %v", err)
	}
	if c.BlocklistUpdateHours != 0 {
		t.Fatalf("absurd hours: got %d, want default 0", c.BlocklistUpdateHours)
	}
	c, err = Load(writeCfg(t, "blocklist_update_hours: 24\n"))
	if err != nil {
		t.Fatalf("sane hours: unexpected error: %v", err)
	}
	if c.BlocklistUpdateHours != 24 {
		t.Fatalf("sane hours: got %d, want 24", c.BlocklistUpdateHours)
	}
}

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

func TestRateLimitDefaultOn(t *testing.T) {
	// Stock installs shed load out of the box (2026-10-02 audit): omitted
	// means 20, explicit 0 still disables.
	c, err := Load(writeCfg(t, "dns_addr: 127.0.0.1:5353\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.RateLimitQPS != DefaultRateLimitQPS {
		t.Fatalf("omitted rate_limit_qps = %d, want default %d", c.RateLimitQPS, DefaultRateLimitQPS)
	}
	c, err = Load(writeCfg(t, "dns_addr: 127.0.0.1:5353\nrate_limit_qps: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.RateLimitQPS != 0 {
		t.Fatalf("explicit rate_limit_qps = %d, want 0 (disabled)", c.RateLimitQPS)
	}
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

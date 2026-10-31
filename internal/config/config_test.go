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

func TestDNSSECConfig(t *testing.T) {
	c, err := Load(writeCfg(t, "dns_addr: 127.0.0.1:5353\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.DNSSEC {
		t.Fatal("dnssec defaults to true; want false (validation is opt-in)")
	}
	c, err = Load(writeCfg(t, "dns_addr: 127.0.0.1:5353\ndnssec: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.DNSSEC {
		t.Fatal("dnssec: true was not parsed")
	}
}

func TestUpstreamTrustAD(t *testing.T) {
	c, err := Load(writeCfg(t, `
upstream_servers:
  - name: unbound
    address: "udp://127.0.0.1:53"
    priority: 1
    trust_ad: true
  - name: doh
    address: "https://1.1.1.1/dns-query"
    priority: 2
    trust_ad: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.UpstreamServers) != 2 {
		t.Fatalf("upstream_servers = %d, want 2", len(c.UpstreamServers))
	}
	if v := c.UpstreamServers[0].TrustAD; v == nil || !*v {
		t.Fatalf("unbound trust_ad = %v, want true", v)
	}
	if v := c.UpstreamServers[1].TrustAD; v == nil || *v {
		t.Fatalf("doh trust_ad = %v, want false", v)
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

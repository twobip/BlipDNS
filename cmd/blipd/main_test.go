package main

import (
	"net"
	"testing"

	"github.com/twobip/BlipDNS/internal/config"
	"github.com/twobip/BlipDNS/internal/filter"
)

func testAddrs(ss ...string) []net.Addr {
	var out []net.Addr
	for _, s := range ss {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, &net.IPNet{IP: ip})
		}
	}
	return out
}

func TestPickBundleHost(t *testing.T) {
	lan := testAddrs("127.0.0.1", "10.0.0.5", "fe80::1", "169.254.169.254")
	for _, tc := range []struct {
		admin, want string
		addrs       []net.Addr
	}{
		{"10.0.0.5", "10.0.0.5", lan},        // configured LAN host kept
		{"blipd.lan", "blipd.lan", lan},      // hostname kept as-is
		{"127.0.0.1", "10.0.0.5", lan},       // loopback -> LAN guess
		{"localhost", "10.0.0.5", lan},       // localhost -> LAN guess
		{"::1", "10.0.0.5", lan},             // v6 loopback -> LAN guess
		{"127.0.0.1", "127.0.0.1", nil},      // nothing else: loopback stays
		{"", "10.0.0.5", lan},                // empty: LAN guess
		{"", "127.0.0.1", nil},               // empty + no ifaces: loopback
		{"169.254.169.254", "10.0.0.5", lan}, // link-local never baked in
		{"0.0.0.0", "10.0.0.5", lan},         // unspecified -> LAN guess
		{"::", "10.0.0.5", lan},              // v6 unspecified -> LAN guess
	} {
		if got := pickBundleHost(tc.admin, tc.addrs); got != tc.want {
			t.Errorf("pickBundleHost(%q) = %q, want %q", tc.admin, got, tc.want)
		}
	}
}

func TestCheckBootConfig(t *testing.T) {
	base := func() (*config.Config, *filter.Store) {
		cfg := config.Default()
		cfg.DNSAddr = "127.0.0.1:53535"
		cfg.DoHAddr = "127.0.0.1:18443"
		cfg.AdminAddr = "127.0.0.1:18444"
		return cfg, filter.NewStore(nil)
	}
	cfg, store := base()
	if err := checkBootConfig(cfg, store); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cfg, store = base()
	cfg.Upstream = "bogus://x"
	if err := checkBootConfig(cfg, store); err == nil {
		t.Errorf("bad upstream accepted, want error")
	}
	cfg, store = base()
	cfg.DNSAddr = "999.999.0.1:53"
	if err := checkBootConfig(cfg, store); err == nil {
		t.Errorf("unresolvable bind accepted, want error")
	}
	cfg, store = base()
	cfg.AllowedNetworks = []string{"0.0.0.0/0"}
	if err := checkBootConfig(cfg, store); err == nil {
		t.Errorf("/0 ACL accepted, want error")
	}
	cfg, store = base()
	cfg.CertFile, cfg.KeyFile = "/nonexistent-cert.pem", "/nonexistent-key.pem"
	if err := checkBootConfig(cfg, store); err == nil {
		t.Errorf("missing cert files accepted, want error")
	}
}

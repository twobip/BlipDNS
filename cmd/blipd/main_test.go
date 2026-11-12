package main

import (
	"net"
	"strings"
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

// A static admin_token has no claim-code step, so the management API cannot
// pin itself to a controller. On a non-loopback bind that means anyone who
// learns the token has full control, which is why blipd refuses to open the
// listener without an explicit ack. An empty or wildcard host binds every
// interface and must never count as loopback.
func TestAdminListenIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8444": true,
		"localhost:8444": true,
		"[::1]:8444":     true,
		":8444":          false,
		"":               false,
		"0.0.0.0:8444":   false,
		"[::]:8444":      false,
		"10.0.0.5:8444":  false,
		"garbage":        false,
	}
	for addr, want := range cases {
		if got := adminListenIsLoopback(addr); got != want {
			t.Errorf("adminListenIsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

// The management listener must distinguish "token on the wire" from "token
// protected but unpinned". A real deployment (admin_addr 0.0.0.0:8443 with the
// DoH certificate reused) was taken offline by the earlier, blunter rule: it
// refused every non-loopback static token, cleartext or not.
func TestPlanAdminListener(t *testing.T) {
	const (
		warnUnpinned  = "UNPINNED"
		warnCleartext = "CLEARTEXT"
		errCleartext  = "cleartext"
	)
	cases := []struct {
		name       string
		addr       string
		static     bool
		tls        bool
		allow      bool
		wantServe  bool
		wantWarn   string // substring, "" = no warning
		wantErrSub string // substring, "" = no error
	}{
		{"loopback cleartext", "127.0.0.1:8444", true, false, false, true, "", ""},
		{"loopback tls", "127.0.0.1:8444", true, true, false, true, "", ""},
		{"no static token", "0.0.0.0:8444", false, false, false, true, "", ""},
		{"remote tls seeks no ack", "0.0.0.0:8443", true, true, false, true, warnUnpinned, ""},
		{"remote cleartext refused", "0.0.0.0:8444", true, false, false, false, "", errCleartext},
		{"remote cleartext acked", "0.0.0.0:8444", true, false, true, true, warnCleartext, ""},
		{"remote tls acked", "10.0.0.5:8444", true, true, true, true, warnUnpinned, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := planAdminListener(c.addr, c.static, c.tls, c.allow)
			if p.Serve != c.wantServe {
				t.Fatalf("Serve = %v, want %v (err=%q)", p.Serve, c.wantServe, p.Err)
			}
			if c.wantWarn == "" && p.Warn != "" {
				t.Errorf("unexpected warning: %q", p.Warn)
			}
			if c.wantWarn != "" && !strings.Contains(p.Warn, c.wantWarn) {
				t.Errorf("warning %q does not contain %q", p.Warn, c.wantWarn)
			}
			if c.wantErrSub == "" && p.Err != "" {
				t.Errorf("unexpected error: %q", p.Err)
			}
			if c.wantErrSub != "" && !strings.Contains(p.Err, c.wantErrSub) {
				t.Errorf("error %q does not contain %q", p.Err, c.wantErrSub)
			}
			if p.Serve && p.Err != "" {
				t.Error("serving plan carries an error message")
			}
		})
	}
}

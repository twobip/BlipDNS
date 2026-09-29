package main

import (
	"net"
	"testing"
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
	} {
		if got := pickBundleHost(tc.admin, tc.addrs); got != tc.want {
			t.Errorf("pickBundleHost(%q) = %q, want %q", tc.admin, got, tc.want)
		}
	}
}

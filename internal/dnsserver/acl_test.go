package dnsserver

import (
	"slices"
	"testing"

	"github.com/twobip/BlipDNS/internal/control"
)

func TestIsLoopbackBind(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:53", true},
		{"127.0.0.2:53", true}, // whole 127/8 is loopback
		{"[::1]:53", true},
		{"localhost:53", true},
		{"0.0.0.0:53", false},
		{"[::]:53", false},
		{":53", false}, // empty host binds all interfaces
		{"192.168.1.1:53", false},
		{"", false},
		{"garbage", false},
	} {
		if got := isLoopbackBind(tc.addr); got != tc.want {
			t.Errorf("isLoopbackBind(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestNewDefaultsClosedOnEmptyACL(t *testing.T) {
	mk := func(dnsAddr string, nets []string, open bool) (*Server, error) {
		return New(Config{
			DNSAddr:         dnsAddr,
			Upstream:        "udp://127.0.0.1:53",
			AllowedNetworks: nets,
			OpenRecursion:   open,
		})
	}
	// Wildcard bind with no ACL boots closed on the safe default, not open.
	s, err := mk("0.0.0.0:53", nil, false)
	if err != nil {
		t.Fatalf("wildcard+empty refused: %v", err)
	}
	if got := s.AllowedNetworks(); !slices.Equal(got, control.DefaultAllowedNetworks()) {
		t.Errorf("wildcard+empty ACL = %v, want default %v", got, control.DefaultAllowedNetworks())
	}
	if s.OpenRecursion() {
		t.Errorf("defaulted server reports OpenRecursion, want false")
	}
	s, err = mk(":53", nil, false)
	if err != nil {
		t.Fatalf("empty-host bind+empty refused: %v", err)
	}
	if got := s.AllowedNetworks(); !slices.Equal(got, control.DefaultAllowedNetworks()) {
		t.Errorf("empty-host+empty ACL = %v, want default", got)
	}
	// Explicit ack starts truly open (empty stays empty).
	s, err = mk("0.0.0.0:53", nil, true)
	if err != nil {
		t.Fatalf("wildcard+empty+open_recursion refused: %v", err)
	}
	if got := s.AllowedNetworks(); len(got) != 0 {
		t.Errorf("acked-open ACL = %v, want empty", got)
	}
	// Loopback binds keep the old warn-and-allow behavior.
	if _, err := mk("127.0.0.1:5353", nil, false); err != nil {
		t.Errorf("loopback+empty refused: %v", err)
	}
	// A configured ACL binds anywhere.
	if _, err := mk("0.0.0.0:53", []string{"192.168.0.0/16"}, false); err != nil {
		t.Errorf("wildcard+ACL refused: %v", err)
	}
	// A /0 catch-all is a config error, not an ACL.
	if _, err := mk("0.0.0.0:53", []string{"0.0.0.0/0"}, true); err == nil {
		t.Errorf("wildcard+/0 accepted, want rejection")
	}
}

func TestSetAllowedNetworks(t *testing.T) {
	s := &Server{}
	if err := s.SetAllowedNetworks([]string{"10.0.0.0/8", "fd00::/8"}); err != nil {
		t.Fatal(err)
	}
	if got := s.AllowedNetworks(); len(got) != 2 {
		t.Fatalf("AllowedNetworks = %v, want 2 entries", got)
	}
	// /0 and garbage are rejected without changing the ACL.
	for _, bad := range [][]string{{"0.0.0.0/0"}, {"::/0"}, {"bogus"}} {
		if err := s.SetAllowedNetworks(bad); err == nil {
			t.Errorf("SetAllowedNetworks(%v) accepted, want rejection", bad)
		}
	}
	if got := s.AllowedNetworks(); len(got) != 2 {
		t.Errorf("ACL changed by rejected push: %v", got)
	}
	// Empty clears back to open (with warning).
	if err := s.SetAllowedNetworks(nil); err != nil {
		t.Fatal(err)
	}
	if got := s.AllowedNetworks(); len(got) != 0 {
		t.Errorf("AllowedNetworks after clear = %v, want empty", got)
	}
}

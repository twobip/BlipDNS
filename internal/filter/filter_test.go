package filter

import (
	"net"
	"testing"
)

func mustIP(s string) net.IP { return net.ParseIP(s) }

func TestSuffixAndWildcard(t *testing.T) {
	p := &Policy{
		ID:       "p",
		Networks: []string{"10.0.0.0/8"},
		Block:    []string{"ads.example.com", "*.tracker.net"},
		Allow:    []string{"good.tracker.net"},
	}
	s := NewStore(nil)
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		ip   string
		name string
		want bool
	}{
		{"10.1.2.3", "ads.example.com", true},
		{"10.1.2.3", "sub.ads.example.com", true}, // subdomain of blocked root
		{"10.1.2.3", "tracker.net", false},        // *. only matches subdomains
		{"10.1.2.3", "a.tracker.net", true},       // wildcard subdomain
		{"10.1.2.3", "good.tracker.net", false},   // allowlist overrides block
		{"192.168.1.1", "ads.example.com", false}, // outside policy network -> default (none) = allow
	}
	for _, c := range cases {
		blocked, _, _, _ := s.Classify(mustIP(c.ip), "", c.name)
		if blocked != c.want {
			t.Errorf("Classify(%s,%s)=%v want %v", c.ip, c.name, blocked, c.want)
		}
	}
}

func TestClientIDRequiresNetwork(t *testing.T) {
	p := &Policy{
		ID:       "kids",
		Networks: []string{"10.0.0.0/8"},
		Clients:  []string{"kid"},
		Block:    []string{"games.example.com"},
	}
	s := NewStore(nil)
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	if blocked, _, _, _ := s.Classify(mustIP("10.1.2.3"), "kid", "games.example.com"); !blocked {
		t.Error("in-network client-ID should match its policy")
	}
	// A self-asserted DoH client-ID from outside the policy's networks must
	// not select it — otherwise anyone could claim a permissive ID to escape
	// their network's policy.
	if blocked, _, _, _ := s.Classify(mustIP("192.168.1.1"), "kid", "games.example.com"); blocked {
		t.Error("out-of-network client-ID must not select the policy")
	}
}

func TestAllowed(t *testing.T) {
	p := &Policy{
		ID:       "p",
		Networks: []string{"10.0.0.0/8"},
		Allow:    []string{"good.example.com", "*.trusted.net", "sub.allow.com"},
		Block:    []string{"bad.example.com"},
	}
	s := NewStore(nil)
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip     string
		client string
		name   string
		want   bool
	}{
		{"10.1.2.3", "", "good.example.com", true},
		{"10.1.2.3", "", "sub.good.example.com", true}, // suffix match
		{"10.1.2.3", "", "a.trusted.net", true},        // wildcard subdomain
		{"10.1.2.3", "", "trusted.net", false},         // *. doesn't match the root itself
		{"10.1.2.3", "", "sub.allow.com", true},
		{"10.1.2.3", "", "bad.example.com", false},           // blocked, not allowed
		{"192.168.1.1", "", "good.example.com", false},       // outside the policy network
		{"10.1.2.3", "any-client", "good.example.com", true}, // network-only policy applies regardless of client ID
	}
	for _, c := range cases {
		if got := s.Allowed(mustIP(c.ip), c.client, c.name); got != c.want {
			t.Errorf("Allowed(%s,%q,%s)=%v want %v", c.ip, c.client, c.name, got, c.want)
		}
	}

	// A client-ID-scoped policy's allowlist applies only to its clients.
	cp := &Policy{
		ID:      "phone",
		Clients: []string{"phone", "tablet"},
		Allow:   []string{"time.nist.gov"},
	}
	if err := s.SetPolicy(cp); err != nil {
		t.Fatal(err)
	}
	if got := s.Allowed(mustIP("10.1.2.3"), "phone", "time.nist.gov"); !got {
		t.Errorf("Allowed(client=phone, time.nist.gov)=false, want true")
	}
	if got := s.Allowed(mustIP("10.1.2.3"), "other", "time.nist.gov"); got {
		t.Errorf("Allowed(client=other, time.nist.gov)=true, want false")
	}
}

func TestClientIDPolicy(t *testing.T) {
	p := &Policy{
		ID:      "phone",
		Clients: []string{"phone", "tablet"},
		Block:   []string{"ads.example.com"},
	}
	s := NewStore(nil)
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	// The client ID selects the policy regardless of the source IP.
	if blocked, _, _, _ := s.Classify(mustIP("203.0.113.7"), "phone", "ads.example.com"); !blocked {
		t.Error("client 'phone' should be blocked")
	}
	if blocked, _, _, _ := s.Classify(mustIP("203.0.113.7"), "tablet", "ads.example.com"); !blocked {
		t.Error("client 'tablet' should be blocked")
	}
	// An unknown client ID falls back to the default (no block).
	if blocked, _, _, _ := s.Classify(mustIP("203.0.113.7"), "", "ads.example.com"); blocked {
		t.Error("unknown client should not be blocked")
	}
	if blocked, _, _, _ := s.Classify(mustIP("203.0.113.7"), "desktop", "ads.example.com"); blocked {
		t.Error("unknown client id should not be blocked")
	}
}

func TestClientIDBeatsNetwork(t *testing.T) {
	netp := &Policy{ID: "lan", Networks: []string{"192.168.1.0/24"}, Allow: []string{"ads.example.com"}}
	idp := &Policy{ID: "kids", Clients: []string{"kids"}, Block: []string{"ads.example.com"}}
	s := NewStore(nil)
	if err := s.SetPolicy(netp); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPolicy(idp); err != nil {
		t.Fatal(err)
	}
	// Same IP: the network policy allows, but the client-ID policy blocks.
	if blocked, _, _, _ := s.Classify(mustIP("192.168.1.5"), "kids", "ads.example.com"); !blocked {
		t.Error("client ID should take precedence over network policy")
	}
	if blocked, _, _, _ := s.Classify(mustIP("192.168.1.5"), "", "ads.example.com"); blocked {
		t.Error("network policy should allow without client ID")
	}
}

func TestLongestPrefixWins(t *testing.T) {
	wide := &Policy{ID: "wide", Networks: []string{"10.0.0.0/8"}, Block: []string{"evil.com"}}
	narrow := &Policy{ID: "narrow", Networks: []string{"10.1.0.0/16"}, Allow: []string{"evil.com"}}
	s := NewStore(nil)
	if err := s.SetPolicy(wide); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPolicy(narrow); err != nil {
		t.Fatal(err)
	}
	// 10.1.x.x should hit narrow (allow) -> not blocked
	if blocked, _, _, _ := s.Classify(mustIP("10.1.2.3"), "", "evil.com"); blocked {
		t.Error("10.1.2.3 should be allowed by narrow policy")
	}
	// 10.2.x.x hits wide (block)
	if blocked, _, _, _ := s.Classify(mustIP("10.2.2.3"), "", "evil.com"); !blocked {
		t.Error("10.2.2.3 should be blocked by wide policy")
	}
}

func TestDefaultPolicy(t *testing.T) {
	def := &Policy{ID: "default", Block: []string{"malware.test"}}
	s := NewStore(def)
	// no per-client policy; default applies
	if blocked, _, _, _ := s.Classify(mustIP("172.16.0.1"), "", "malware.test"); !blocked {
		t.Error("default policy should block")
	}
	if blocked, _, _, _ := s.Classify(mustIP("172.16.0.1"), "", "ok.test"); blocked {
		t.Error("default policy should allow ok.test")
	}
}

func TestBlockAction(t *testing.T) {
	p := &Policy{ID: "p", Networks: []string{"10.0.0.0/8"}, Block: []string{"x.com"}, BlockAction: ActionRefused}
	s := NewStore(nil)
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	_, action, _, _ := s.Classify(mustIP("10.0.0.1"), "", "x.com")
	if action != ActionRefused {
		t.Errorf("action=%s want refused", action)
	}
}

func TestInvalidNetwork(t *testing.T) {
	s := NewStore(nil)
	if err := s.SetPolicy(&Policy{ID: "p", Networks: []string{"not-a-cidr"}}); err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestBlockSource(t *testing.T) {
	p := &Policy{
		ID:       "kids",
		Networks: []string{"192.168.1.0/24"},
		Block:    []string{"ads.example.com"},
		Allow:    []string{"allowed.example.com"},
	}
	s := NewStore(nil)
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}

	if got := s.BlockSource(mustIP("192.168.1.5"), "", "ads.example.com"); got != "policy:kids" {
		t.Errorf("BlockSource(blocked) = %q, want policy:kids", got)
	}
	if got := s.BlockSource(mustIP("192.168.1.5"), "", "allowed.example.com"); got != "" {
		t.Errorf("BlockSource(allowlisted) = %q, want empty", got)
	}
	if got := s.BlockSource(mustIP("192.168.1.5"), "", "plain.example.org"); got != "" {
		t.Errorf("BlockSource(not blocked) = %q, want empty", got)
	}
	if got := s.BlockSource(mustIP("10.9.9.9"), "", "ads.example.com"); got != "" {
		t.Errorf("BlockSource(outside network) = %q, want empty", got)
	}
}

package dnsserver

import (
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/filter"
)

// TestChainBlockedNinthTarget proves CNAME inspection is not truncated: a
// blocked domain hiding as the 9th (or later) CNAME target must still block
// the response instead of being served and cached.
func TestChainBlockedNinthTarget(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("start.example.", dns.TypeA)
	for i := 0; i < 8; i++ {
		m.Answer = append(m.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: fmt.Sprintf("c%d.example.", i), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: fmt.Sprintf("c%d.example.", i+1),
		})
	}
	m.Answer = append(m.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "c8.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: "blocked.example.",
	})
	blocked := map[string]bool{"blocked.example": true}
	if !chainBlocked(m, func(target string) bool {
		name := dns.Fqdn(target)
		// normalize trailing dot for the map lookup
		if len(name) > 0 && name[len(name)-1] == '.' {
			name = name[:len(name)-1]
		}
		return blocked[name]
	}) {
		t.Fatal("9th CNAME target evaded chain inspection")
	}
}

// TestChainBlockedOverlongFailsClosed proves absurd chains fail closed rather
// than being silently allowed.
func TestChainBlockedOverlongFailsClosed(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("start.example.", dns.TypeA)
	for i := 0; i < maxChainInspect+10; i++ {
		m.Answer = append(m.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: fmt.Sprintf("c%d.example.", i), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: fmt.Sprintf("c%d.example.", i+1),
		})
	}
	if !chainBlocked(m, func(string) bool { return false }) {
		t.Fatal("over-long CNAME chain was allowed instead of failing closed")
	}
}

// TestInspectChainAttribution proves the fused walk classifies once and
// returns the first blocked target with its action (the old two-pass
// chainBlocked+findBlockedTarget did two full evaluations per response).
func TestInspectChainAttribution(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("start.example.", dns.TypeA)
	m.Answer = append(m.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "start.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: "blocked.example.",
	})
	calls := 0
	blocked, target, act, src, lg := inspectChain(m, func(s string) (bool, filter.BlockAction, string, bool) {
		calls++
		if s == "blocked.example." {
			return true, filter.ActionRefused, "test", true
		}
		return false, "", "", false
	})
	if !blocked || target != "blocked.example" || act != filter.ActionRefused || src != "test" || !lg {
		t.Fatalf("inspectChain = %v %q %q %q %v, want attribution to blocked.example", blocked, target, act, src, lg)
	}
	if calls != 1 {
		t.Fatalf("classify calls = %d, want 1 (single walk)", calls)
	}
	// Over-long chains fail closed with an empty target (caller attributes
	// those to the qname).
	big := new(dns.Msg)
	big.SetQuestion("start.example.", dns.TypeA)
	for i := 0; i < maxChainInspect+10; i++ {
		big.Answer = append(big.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: fmt.Sprintf("c%d.example.", i), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: fmt.Sprintf("c%d.example.", i+1),
		})
	}
	if blocked, target, _, _, _ := inspectChain(big, func(string) (bool, filter.BlockAction, string, bool) {
		return false, "", "", false
	}); !blocked || target != "" {
		t.Fatalf("overlong inspectChain = %v %q, want (true, \"\")", blocked, target)
	}
}

// TestClassifyNameGlobalBlockRespectsLogOff proves a global-blocklist chain
// target inherits the matching policy's log flag instead of always logging:
// with log disabled the block still fires but must not log.
func TestClassifyNameGlobalBlockRespectsLogOff(t *testing.T) {
	for _, logOn := range []bool{false, true} {
		store := filter.NewStore(nil)
		if err := store.SetPolicy(&filter.Policy{
			ID: "p", Networks: []string{"10.0.0.0/8"}, Log: logOn,
		}); err != nil {
			t.Fatal(err)
		}
		srv := &Server{cfg: Config{Store: store, Blocklist: blocklist.New()}}
		srv.cfg.Blocklist.FromDomains([]string{"chain-target.example"})
		ok, _, src, shouldLog := srv.classifyName(net.ParseIP("10.0.0.1"), "", "chain-target.example.")
		if !ok || src != "global" {
			t.Fatalf("log=%v: blocked=%v src=%q, want true/global", logOn, ok, src)
		}
		if shouldLog != logOn {
			t.Errorf("log=%v: shouldLog=%v, want %v", logOn, shouldLog, logOn)
		}
	}
}

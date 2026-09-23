package dnsserver

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
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

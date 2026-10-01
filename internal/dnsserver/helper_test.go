package dnsserver

import (
	"net/http"
	"testing"

	"github.com/miekg/dns"
)

func TestClientIPFromReqIgnoresUntrustedForwardedHeader(t *testing.T) {
	r := httptestRequest("203.0.113.10:1234", "198.51.100.7")
	got := clientIPFromReq(r, nil)
	if got == nil || got.String() != "203.0.113.10" {
		t.Fatalf("client IP = %v, want peer IP", got)
	}
}

func TestClientIPFromReqUsesTrustedForwardedHeader(t *testing.T) {
	r := httptestRequest("127.0.0.1:1234", "198.51.100.7")
	trusted, err := parseTrustedProxies([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	got := clientIPFromReq(r, trusted)
	if got == nil || got.String() != "198.51.100.7" {
		t.Fatalf("client IP = %v, want forwarded IP", got)
	}
}

func TestClientIPFromReqPrefersForwardedOverCF(t *testing.T) {
	r := httptestRequest("127.0.0.1:1234", "198.51.100.7")
	r.Header.Set("CF-Connecting-IP", "203.0.113.99")
	trusted, err := parseTrustedProxies([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	got := clientIPFromReq(r, trusted)
	if got == nil || got.String() != "198.51.100.7" {
		t.Fatalf("client IP = %v, want X-Forwarded-For (XFF wins over CF-Connecting-IP)", got)
	}
}

func TestClientIPFromReqIgnoresCFConnectingIPWhenUntrusted(t *testing.T) {
	r := httptestRequest("203.0.113.10:1234", "198.51.100.7")
	r.Header.Set("CF-Connecting-IP", "203.0.113.99")
	got := clientIPFromReq(r, nil)
	if got == nil || got.String() != "203.0.113.10" {
		t.Fatalf("client IP = %v, want peer IP", got)
	}
}

func httptestRequest(remote, forwarded string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://example.test/dns-query", nil)
	r.RemoteAddr = remote
	r.Header.Set("X-Forwarded-For", forwarded)
	return r
}

// TestDohMaxAgeNegativeUsesSOAMinimum proves dohMaxAge mirrors cache.minTTL
// (RFC 2308 §3): an NXDOMAIN SOA with TTL 3600 / minimum 60 advertises 60,
// never 3600.
func TestDohMaxAgeNegativeUsesSOAMinimum(t *testing.T) {
	m := new(dns.Msg)
	m.SetRcode(new(dns.Msg).SetQuestion("nx.test.", dns.TypeA), dns.RcodeNameError)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}, Minttl: 60}
	m.Ns = []dns.RR{soa}
	if got := dohMaxAge(m); got != 60 {
		t.Fatalf("dohMaxAge(NXDOMAIN) = %d, want 60", got)
	}
}

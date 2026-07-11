package dnsserver

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/twobip/BlipDNS/internal/upstream"
	"github.com/miekg/dns"
)

// recUp is a controllable upstream for end-to-end tests.
type recUp struct {
	mu     sync.Mutex
	calls  int
	answer map[string]string
}

// Resolve implements upstream.Resolver.
func (r *recUp) Resolve(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	m := new(dns.Msg)
	m.SetReply(q)
	if len(q.Question) == 0 {
		return m, nil
	}
	name := q.Question[0].Name
	if ip, ok := r.answer[name]; ok {
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip),
		}}
	}
	return m, nil
}

func newTestServer(t *testing.T) (*Server, *recUp) {
	t.Helper()
	store := filter.NewStore(nil)
	if err := store.SetPolicy(&filter.Policy{
		ID: "p", Networks: []string{"10.0.0.0/8"}, Block: []string{"blocked.test"},
	}); err != nil {
		t.Fatal(err)
	}
	up := &recUp{answer: map[string]string{"allowed.test.": "9.9.9.9"}}
	srv := &Server{
		cfg:   Config{Store: store, Upstream: ""},
		cache: cache.New(0),
		up:    up,
	}
	return srv, up
}

func TestServeBlocks(t *testing.T) {
	srv, _ := newTestServer(t)
	q := new(dns.Msg)
	q.SetQuestion("blocked.test.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), q)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("blocked query rc=%d want NXDOMAIN", resp.Rcode)
	}
}

func TestServeResolvesAndCaches(t *testing.T) {
	srv, up := newTestServer(t)
	q := new(dns.Msg)
	q.SetQuestion("allowed.test.", dns.TypeA)
	q.Id = 0x1234

	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("allowed query rc=%d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "9.9.9.9" {
		t.Errorf("unexpected answer: %v", resp.Answer[0])
	}
	if resp.Id != 0x1234 {
		t.Errorf("response id should echo request id, got %#x", resp.Id)
	}

	// second identical query must be served from cache (no extra upstream call)
	q2 := new(dns.Msg)
	q2.SetQuestion("allowed.test.", dns.TypeA)
	_ = srv.serve(context.Background(), net.ParseIP("10.0.0.1"), q2)
	if up.calls != 1 {
		t.Errorf("expected 1 upstream call (2nd cached), got %d", up.calls)
	}
}

func TestServeDefaultAllowsUnknownClient(t *testing.T) {
	srv, _ := newTestServer(t)
	// client outside 10.0.0.0/8 -> default policy (none) -> allowed
	q := new(dns.Msg)
	q.SetQuestion("blocked.test.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("non-policy client should be allowed, rc=%d", resp.Rcode)
	}
}

// ensure upstream import is used (multi-resolver construction sanity)
func TestUpstreamMultiConstruct(t *testing.T) {
	_, err := upstream.FromSpec("https://1.1.1.1/dns-query https://8.8.8.8/dns-query")
	if err != nil {
		t.Fatal(err)
	}
}

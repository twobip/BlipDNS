package dnsserver

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/twobip/BlipDNS/internal/blocklist"
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
		cache: cache.New(0, 0),
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

// blSrv returns a server whose global blocklist blocks the given domain,
// configured with the given block action.
func blSrv(t *testing.T, action string) *Server {
	t.Helper()
	srv, _ := newTestServer(t)
	srv.cfg.Blocklist = blocklist.New()
	srv.cfg.Blocklist.FromDomains([]string{"ads.example.net"})
	srv.cfg.BlockAction = filter.BlockAction(action)
	return srv
}

func TestServeBlocklistZeroAction(t *testing.T) {
	srv := blSrv(t, "zero")

	q := new(dns.Msg)
	q.SetQuestion("ads.example.net.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("zero-action A rc=%d want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 synthesized answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.IPv4zero) {
		t.Errorf("zero-action A answer = %v, want 0.0.0.0", resp.Answer[0])
	}

	q.SetQuestion("ads.example.net.", dns.TypeAAAA)
	resp = srv.serve(context.Background(), net.ParseIP("192.168.1.5"), q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("zero-action AAAA rc=%d want NOERROR", resp.Rcode)
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok || !aaaa.AAAA.Equal(net.IPv6zero) {
		t.Errorf("zero-action AAAA answer = %v, want ::", resp.Answer[0])
	}

	// Non-address queries get an empty NOERROR.
	q.SetQuestion("ads.example.net.", dns.TypeMX)
	resp = srv.serve(context.Background(), net.ParseIP("192.168.1.5"), q)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Errorf("zero-action MX rc=%d answers=%d, want NOERROR with no records", resp.Rcode, len(resp.Answer))
	}
}

func TestServeBlocklistRefusedAction(t *testing.T) {
	srv := blSrv(t, "refused")
	q := new(dns.Msg)
	q.SetQuestion("ads.example.net.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), q)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("refused-action rc=%d want REFUSED", resp.Rcode)
	}
}

func TestServeBlocklistDefaultIsNXDOMAIN(t *testing.T) {
	srv := blSrv(t, "")
	q := new(dns.Msg)
	q.SetQuestion("ads.example.net.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), q)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("default-action rc=%d want NXDOMAIN", resp.Rcode)
	}
}

// The store (per-client policy) path shares the same zero-action answer.
func TestServeStoreZeroActionSynthesizesZero(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.cfg.Store.SetPolicy(&filter.Policy{
		ID: "z", Networks: []string{"192.168.77.0/24"}, Block: []string{"zp.test"}, BlockAction: filter.ActionZero,
	}); err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("zp.test.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.77.5"), q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rc=%d want NOERROR", resp.Rcode)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.IPv4zero) {
		t.Errorf("answer = %v, want 0.0.0.0", resp.Answer[0])
	}
}

// The wire format carries the root dot ("google.com."); logs and watch events
// must show the bare domain.
func TestServeStripsRootDotFromLoggedDomain(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.cfg.Blocklist = blocklist.New()
	srv.cfg.Blocklist.FromDomains([]string{"blocked.test"})
	var got string
	srv.logfn = func(_client, domain string) { got = domain }

	q := new(dns.Msg)
	q.SetQuestion("blocked.test.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), q)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked query rc=%d want NXDOMAIN", resp.Rcode)
	}
	if got != "blocked.test" {
		t.Errorf("logged domain = %q, want %q (root dot must be stripped)", got, "blocked.test")
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

func TestRefreshPopularRefreshesStale(t *testing.T) {
	srv, up := newTestServer(t)

	// warm the cache from the live path (recUp answers carry TTL 60)
	q := new(dns.Msg)
	q.SetQuestion("allowed.test.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rc=%d", resp.Rcode)
	}
	up.mu.Lock()
	before := up.calls
	up.mu.Unlock()
	resp = srv.serve(context.Background(), net.ParseIP("10.0.0.1"), q)
	if up.calls != before {
		t.Fatal("expected second serve to hit cache")
	}

	// a generous lookahead makes the (fresh) entry count as stale
	srv.cfg.CacheWarmAhead = 2 * time.Minute
	srv.refreshPopular()

	// refreshPopular re-resolved via the default upstream and re-cached
	up.mu.Lock()
	refreshed := up.calls > before
	up.mu.Unlock()
	if !refreshed {
		t.Fatal("expected refreshPopular to re-resolve the stale entry")
	}
	k := cache.Key(q)
	if srv.cache.Stale(k, 0) {
		t.Error("expected refreshed entry to no longer be stale")
	}
}

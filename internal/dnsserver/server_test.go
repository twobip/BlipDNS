package dnsserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/twobip/BlipDNS/internal/upstream"
)

// recUp is a controllable upstream for end-to-end tests.
type recUp struct {
	mu     sync.Mutex
	calls  int
	answer map[string]string
	txt    map[string][]string
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
	switch q.Question[0].Qtype {
	case dns.TypeA:
		if ip, ok := r.answer[name]; ok {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			}}
		}
	case dns.TypeTXT:
		if txt, ok := r.txt[name]; ok {
			m.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: txt,
			}}
		}
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
		pool:  upstream.NewPoolWithAuto(up),
	}
	return srv, up
}

func TestServeBlocks(t *testing.T) {
	srv, _ := newTestServer(t)
	q := new(dns.Msg)
	q.SetQuestion("blocked.test.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", q)
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
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
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
	resp = srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("zero-action AAAA rc=%d want NOERROR", resp.Rcode)
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok || !aaaa.AAAA.Equal(net.IPv6zero) {
		t.Errorf("zero-action AAAA answer = %v, want ::", resp.Answer[0])
	}

	// Non-address queries get an empty NOERROR.
	q.SetQuestion("ads.example.net.", dns.TypeMX)
	resp = srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Errorf("zero-action MX rc=%d answers=%d, want NOERROR with no records", resp.Rcode, len(resp.Answer))
	}
}

func TestServeBlocklistRefusedAction(t *testing.T) {
	srv := blSrv(t, "refused")
	q := new(dns.Msg)
	q.SetQuestion("ads.example.net.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("refused-action rc=%d want REFUSED", resp.Rcode)
	}
}

func TestServeBlocklistDefaultIsNXDOMAIN(t *testing.T) {
	srv := blSrv(t, "")
	q := new(dns.Msg)
	q.SetQuestion("ads.example.net.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("default-action rc=%d want NXDOMAIN", resp.Rcode)
	}
}

// TestServePolicyAllowlistBeatsGlobalBlocklist verifies a domain whitelisted by
// the client's policy is never blocked by the global blocklist: it falls
// through to the upstream instead.
func TestServePolicyAllowlistBeatsGlobalBlocklist(t *testing.T) {
	srv := blSrv(t, "nxdomain")
	// Policy p (10.0.0.0/8) allowlists ads.example.net even though the global
	// blocklist blocks it.
	if err := srv.cfg.Store.SetPolicy(&filter.Policy{
		ID:       "p",
		Networks: []string{"10.0.0.0/8"},
		Allow:    []string{"ads.example.net"},
	}); err != nil {
		t.Fatal(err)
	}
	up := srv.pool.Auto().(*recUp)

	// Same global-blocklisted domain, allowed by the policy -> resolved.
	q := new(dns.Msg)
	q.SetQuestion("ads.example.net.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.9"), "", q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("allowlisted query rc=%d want NOERROR (blocked=%v)", resp.Rcode, resp.Rcode == dns.RcodeNameError)
	}
	if up.calls == 0 {
		t.Error("allowlisted query did not reach the upstream")
	}

	// Same domain, client outside the policy network -> still global-blocked.
	up.calls = 0
	resp = srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("non-allowlisted query rc=%d want NXDOMAIN", resp.Rcode)
	}
	if up.calls != 0 {
		t.Error("non-allowlisted query reached the upstream")
	}
}

// TestServePolicyAllowlistBeatsGlobalBlocklistByClientID is the DoH client-ID
// variant of the above: an allowlist keyed to a client ID overrides the global
// blocklist for that client only.
func TestServePolicyAllowlistBeatsGlobalBlocklistByClientID(t *testing.T) {
	srv := blSrv(t, "")
	if err := srv.cfg.Store.SetPolicy(&filter.Policy{
		ID:      "phone",
		Clients: []string{"phone"},
		Allow:   []string{"ads.example.net"},
	}); err != nil {
		t.Fatal(err)
	}
	up := srv.pool.Auto().(*recUp)

	q := new(dns.Msg)
	q.SetQuestion("ads.example.net.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "phone", q)
	if resp.Rcode != dns.RcodeSuccess || up.calls == 0 {
		t.Fatalf("client-ID allowlisted query rc=%d upstream=%d, want NOERROR+resolved", resp.Rcode, up.calls)
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
	resp := srv.serve(context.Background(), net.ParseIP("192.168.77.5"), "", q)
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
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", q)
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

	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", q)
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
	_ = srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", q2)
	if up.calls != 1 {
		t.Errorf("expected 1 upstream call (2nd cached), got %d", up.calls)
	}
}

func TestServeDefaultAllowsUnknownClient(t *testing.T) {
	srv, _ := newTestServer(t)
	// client outside 10.0.0.0/8 -> default policy (none) -> allowed
	q := new(dns.Msg)
	q.SetQuestion("blocked.test.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
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

// A DoH client ID selects a per-client policy and becomes the log identity.
func TestServeClientIDPolicyAndIdentity(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.cfg.Store.SetPolicy(&filter.Policy{
		ID: "kids", Clients: []string{"kids-tablet"}, Block: []string{"cid.test"}, Log: true,
	}); err != nil {
		t.Fatal(err)
	}
	var got string
	srv.logfn = func(client, _ string) { got = client }

	q := new(dns.Msg)
	q.SetQuestion("cid.test.", dns.TypeA)
	// With the client ID the policy blocks and logs the client ID.
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "kids-tablet", q)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("client-id block rc=%d want NXDOMAIN", resp.Rcode)
	}
	if got != "kids-tablet" {
		t.Errorf("logged client = %q, want %q", got, "kids-tablet")
	}
	// Without the client ID the same IP is not blocked.
	resp = srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", q)
	if resp.Rcode == dns.RcodeNameError {
		t.Error("expected query without client id to pass")
	}
}

func TestClientIDFromPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/dns-query", ""},
		{"/dns-query/", ""},
		{"/dns-query/client1", "client1"},
		{"/dns-query/kids-tablet", "kids-tablet"},
		{"/dns-query/phone/extra", ""},
		{"/dns-query/" + strings.Repeat("x", 65), ""},
	}
	for _, c := range cases {
		if got := clientIDFromPath(c.in); got != c.want {
			t.Errorf("clientIDFromPath(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// The DoH handler resolves /dns-query/{client-id} and applies the matching
// policy to the query.
func TestDoHHandlerClientIDRouting(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.cfg.Store.SetPolicy(&filter.Policy{
		ID: "kids", Clients: []string{"kids-tablet"}, Block: []string{"cid.test"},
	}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	msg := new(dns.Msg)
	msg.SetQuestion("cid.test.", dns.TypeA)
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	dnsQ := base64.RawURLEncoding.EncodeToString(wire)

	// /dns-query/kids-tablet -> blocked (policy matched by client ID).
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/dns-query/kids-tablet?dns="+dnsQ, nil))
	resp := new(dns.Msg)
	if err := resp.Unpack(w.Body.Bytes()); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("doh client-id rc=%d want NXDOMAIN", resp.Rcode)
	}

	// Plain /dns-query -> not blocked.
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, httptest.NewRequest("GET", "/dns-query?dns="+dnsQ, nil))
	resp2 := new(dns.Msg)
	if err := resp2.Unpack(w2.Body.Bytes()); err != nil {
		t.Fatalf("unpack 2: %v", err)
	}
	if resp2.Rcode == dns.RcodeNameError {
		t.Error("expected plain /dns-query not to be blocked")
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "127.0.0.1:" + port
}

// dnsMsgB64 packs a query for name into base64url for the ?dns= param.
func dnsMsgB64(t *testing.T, name string, qtype uint16) string {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name+".", qtype)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(wire)
}

func TestSetDoHHTTPAddrStartStop(t *testing.T) {
	srv, up := newTestServer(t)

	addr := freePort(t)
	if err := srv.SetDoHHTTPAddr(addr); err != nil {
		t.Fatalf("start plain listener: %v", err)
	}
	if got := srv.DoHHTTPAddr(); got != addr {
		t.Errorf("DoHHTTPAddr = %q, want %q", got, addr)
	}

	// A real DoH query over plain HTTP is answered (allowed.test resolves).
	url := fmt.Sprintf("http://%s/dns-query?dns=%s", addr, dnsMsgB64(t, "allowed.test", dns.TypeA))
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plain DoH query status = %d", resp.StatusCode)
	}
	var out dns.Msg
	if err := out.Unpack(body); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if up.calls != 1 {
		t.Errorf("expected 1 upstream call, got %d", up.calls)
	}

	// Stopping the listener flips the reported address to "".
	if err := srv.SetDoHHTTPAddr(""); err != nil {
		t.Fatalf("stop plain listener: %v", err)
	}
	if got := srv.DoHHTTPAddr(); got != "" {
		t.Errorf("DoHHTTPAddr after stop = %q, want empty", got)
	}

	// A second start/stop toggles cleanly (no port/stale-handle leak).
	if err := srv.SetDoHHTTPAddr(addr); err != nil {
		t.Fatalf("restart plain listener: %v", err)
	}
	if got := srv.DoHHTTPAddr(); got != addr {
		t.Errorf("DoHHTTPAddr after restart = %q, want %q", got, addr)
	}
	if err := srv.SetDoHHTTPAddr(""); err != nil {
		t.Fatalf("second stop: %v", err)
	}
}

func TestSetDoHHTTPAddrRejectsBadAddr(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.SetDoHHTTPAddr("not-a-host"); err == nil {
		t.Fatal("expected error for bad address, got nil")
	}
	if got := srv.DoHHTTPAddr(); got != "" {
		t.Errorf("DoHHTTPAddr after failed set = %q, want empty", got)
	}
}

func TestSetDoHHTTPAddrIdempotent(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.SetDoHHTTPAddr(""); err != nil {
		t.Fatal(err)
	}
	if err := srv.SetDoHHTTPAddr(""); err != nil {
		t.Fatal(err)
	}
}

func TestServeRecordsServed(t *testing.T) {
	srv, up := newTestServer(t)
	srv.rec = NewRecordStore()
	srv.rec.SetRecords([]control.RecordEntry{
		{Domain: "recorded.test.", Type: "A", Value: "10.10.10.10", TTL: 60},
	})

	q := new(dns.Msg)
	q.SetQuestion("recorded.test.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rc=%d want NOERROR", resp.Rcode)
	}
	if up.calls != 0 {
		t.Errorf("upstream calls = %d, want 0 (record should be served directly)", up.calls)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", resp.Answer[0])
	}
	if !a.A.Equal(net.ParseIP("10.10.10.10")) {
		t.Errorf("A = %v, want 10.10.10.10", a.A)
	}
}

func TestServeRecordsFallthroughToUpstream(t *testing.T) {
	srv, up := newTestServer(t)
	srv.rec = NewRecordStore()
	srv.rec.SetRecords([]control.RecordEntry{
		{Domain: "recorded.test.", Type: "A", Value: "10.10.10.10", TTL: 60},
	})

	up.calls = 0
	q := new(dns.Msg)
	q.SetQuestion("other.test.", dns.TypeA)
	srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	// upstream was called (no matching record)
	if up.calls != 1 {
		t.Errorf("upstream calls = %d, want 1", up.calls)
	}
}

func TestUpstreamErrText(t *testing.T) {
	// Real DoH timeout shape: wrapped context.DeadlineExceeded.
	wrapped := fmt.Errorf("Post %q: %w", "https://dns.mullvad.net/dns-query", context.DeadlineExceeded)
	if got := upstreamErrText("auto (Quad9)", wrapped); got != "timeout talking to auto (Quad9)" {
		t.Errorf("wrapped timeout = %q", got)
	}
	if got := upstreamErrText("", context.DeadlineExceeded); got != "upstream timeout" {
		t.Errorf("bare timeout = %q", got)
	}
	// Non-timeouts pass through verbatim.
	if got := upstreamErrText("auto (Quad9)", fmt.Errorf("boom")); got != "boom" {
		t.Errorf("passthrough = %q", got)
	}
}

func TestServeRecordsNodataForMissingType(t *testing.T) {
	srv, up := newTestServer(t)
	srv.rec = NewRecordStore()
	srv.rec.SetRecords([]control.RecordEntry{
		{Domain: "galaxy.lan.", Type: "A", Value: "192.168.30.154", TTL: 60},
		{Domain: "*.apps.lan.", Type: "A", Value: "192.168.30.155", TTL: 60},
	})

	// AAAA for an A-only name (and its wildcard sibling) is NODATA: NOERROR
	// with no answers, served locally — never upstream NXDOMAIN.
	for _, name := range []string{"galaxy.lan.", "www.apps.lan."} {
		up.calls = 0
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeAAAA)
		resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || !resp.RecursionAvailable {
			t.Errorf("%s AAAA: rc=%d answers=%d ra=%v, want NOERROR with 0 (NODATA) + RA", name, resp.Rcode, len(resp.Answer), resp.RecursionAvailable)
		}
		if up.calls != 0 {
			t.Errorf("%s AAAA: upstream calls = %d, want 0", name, up.calls)
		}
	}
}

func TestServeRecordsTypeSpecificMatch(t *testing.T) {
	srv, up := newTestServer(t)
	srv.rec = NewRecordStore()
	srv.rec.SetRecords([]control.RecordEntry{
		{Domain: "dual.test.", Type: "A", Value: "10.0.0.1", TTL: 60},
		{Domain: "dual.test.", Type: "AAAA", Value: "2001:db8::1", TTL: 60},
	})

	// A query -> A record
	q := new(dns.Msg)
	q.SetQuestion("dual.test.", dns.TypeA)
	resp := srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	if len(resp.Answer) != 1 {
		t.Fatalf("A answers = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("A answer = %v, want 10.0.0.1", resp.Answer[0])
	}

	// AAAA query -> AAAA record
	up.calls = 0
	q.SetQuestion("dual.test.", dns.TypeAAAA)
	resp = srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	if up.calls != 0 {
		t.Errorf("upstream calls after AAAA = %d, want 0", up.calls)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("AAAA answers = %d, want 1", len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok || !aaaa.AAAA.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("AAAA answer = %v, want 2001:db8::1", resp.Answer[0])
	}

	// CNAME query for "dual.test." (A+AAAA only) is NODATA: NOERROR with
	// no answers, served locally — never upstream.
	up.calls = 0
	q.SetQuestion("dual.test.", dns.TypeCNAME)
	resp = srv.serve(context.Background(), net.ParseIP("192.168.1.5"), "", q)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Errorf("CNAME rc=%d answers=%d, want NOERROR with 0 (NODATA)", resp.Rcode, len(resp.Answer))
	}
	if up.calls != 0 {
		t.Errorf("upstream calls for CNAME = %d, want 0", up.calls)
	}
}

func TestServeCachedTXTResponse(t *testing.T) {
	srv, up := newTestServer(t)
	up.txt = map[string][]string{"_dmarc.test.": {"v=DMARC1; p=none"}}

	q := new(dns.Msg)
	q.SetQuestion("_dmarc.test.", dns.TypeTXT)

	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first rc=%d want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.TXT", resp.Answer[0])
	}
	if got := strings.Join(a.Txt, ""); got != "v=DMARC1; p=none" {
		t.Errorf("TXT data = %q, want %q", got, "v=DMARC1; p=none")
	}
	callsAfterFirst := up.calls

	resp = srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", q)
	if up.calls != callsAfterFirst {
		t.Fatalf("expected second serve to hit cache (up.calls=%d, want %d)", up.calls, callsAfterFirst)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("cached: expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok = resp.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("cached: answer type = %T, want *dns.TXT", resp.Answer[0])
	}
	if got := strings.Join(a.Txt, ""); got != "v=DMARC1; p=none" {
		t.Errorf("cached: TXT data = %q, want %q", got, "v=DMARC1; p=none")
	}
}

// The per-client rate limiter keys on the source IP, so rotating the DoH
// /dns-query/{client-id} path segment cannot mint fresh buckets.
func TestServeRateLimitKeyedByIP(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.rl = newRateLimiter()
	srv.rl.set(1, 1) // 1 QPS, burst 1
	q := new(dns.Msg)
	q.SetQuestion("allowed.test.", dns.TypeA)
	ip := net.ParseIP("198.51.100.7")

	// First query consumes the single token.
	if resp := srv.serve(context.Background(), ip, "client-a", q); resp.Rcode == dns.RcodeRefused {
		t.Fatalf("first query should be allowed")
	}
	// Same IP, different client-id -> still rate-limited (bucket keyed by IP).
	if resp := srv.serve(context.Background(), ip, "client-b", q); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("second query from same IP must be refused regardless of client-id")
	}
	// Different IP -> its own bucket.
	if resp := srv.serve(context.Background(), net.ParseIP("198.51.100.8"), "client-a", q); resp.Rcode == dns.RcodeRefused {
		t.Fatalf("different IP should have its own bucket")
	}
}

// An oversized POST body must be rejected (413), not silently truncated.
func TestDoHHandlerPostTooLarge(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()
	body := make([]byte, maxDoHMessage+1)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized POST status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

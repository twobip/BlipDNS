package dnsserver

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/twobip/BlipDNS/internal/upstream"
)

// The UDP listener must read the DNS flag-day 1232, not the vendored 512
// default that FORMERR'd every padded query (audit #5).
func TestClassicServersUDPSize(t *testing.T) {
	mux := dns.NewServeMux()
	udp, tcp := newClassicServers("127.0.0.1:0", mux)
	if udp.UDPSize != 1232 {
		t.Errorf("UDP UDPSize=%d want 1232", udp.UDPSize)
	}
	if tcp.UDPSize != 0 {
		t.Errorf("TCP UDPSize=%d want 0 (stream, no datagram buffer)", tcp.UDPSize)
	}
}

// End-to-end: a ~1000-byte padded query over real UDP must be answered, not
// FORMERR'd (audit #5).
func TestUDPListenerAcceptsPaddedQuery(t *testing.T) {
	srv, _ := newTestServer(t)
	mux := dns.NewServeMux()
	mux.Handle(".", srv)
	udp, _ := newClassicServers("127.0.0.1:0", mux)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp.PacketConn = pc
	go udp.ActivateAndServe() //nolint:errcheck
	defer udp.Shutdown()      //nolint:errcheck

	q := new(dns.Msg)
	q.SetQuestion("allowed.test.", dns.TypeA)
	q.SetEdns0(4096, false)
	opt := q.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, 900)})
	if q.Len() < 900 {
		t.Fatalf("padded query too small: %d", q.Len())
	}
	c := new(dns.Client)
	resp, _, err := c.Exchange(q, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("padded query exchange: %v", err)
	}
	if resp.Rcode == dns.RcodeFormatError {
		t.Fatalf("padded (%dB) query FORMERR'd", q.Len())
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("padded query rc=%d answers=%d, want NOERROR+answer",
			resp.Rcode, len(resp.Answer))
	}
}

// TCP responses honor the advertised EDNS0 bufsize capped at 1232, defaulting
// to 512 + TC with no OPT (RFC 8659 §6.1, audit #6).
func TestTCPResponseCap(t *testing.T) {
	newBigServer := func(t *testing.T) *Server {
		t.Helper()
		store := filter.NewStore(nil)
		if err := store.SetPolicy(&filter.Policy{
			ID: "p", Networks: []string{"10.0.0.0/8"},
		}); err != nil {
			t.Fatal(err)
		}
		up := &recUp{txt: map[string][]string{"big.test.": {strings.Repeat("x", 2000)}}}
		return &Server{
			cfg:   Config{Store: store, Upstream: ""},
			cache: cache.New(0, 0),
			pool:  upstream.NewPoolWithAuto(up),
		}
	}
	query := func(withOpt bool, bufsize uint16) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("big.test.", dns.TypeTXT)
		if withOpt {
			q.SetEdns0(bufsize, false)
		}
		return q
	}
	// No OPT over TCP: 512 + TC.
	srv := newBigServer(t)
	resp, _ := srv.serveInner(context.Background(), net.ParseIP("10.0.0.1"), "", control.ProtoDNS, false, query(false, 0))
	if resp.Len() > 512 {
		t.Errorf("TCP no-OPT len=%d want <=512", resp.Len())
	}
	if !resp.Truncated {
		t.Errorf("TCP no-OPT TC=0 want 1")
	}
	// OPT 4096 over TCP: capped at 1232.
	srv = newBigServer(t)
	resp, _ = srv.serveInner(context.Background(), net.ParseIP("10.0.0.1"), "", control.ProtoDNS, false, query(true, 4096))
	if resp.Len() > 1232 {
		t.Errorf("TCP OPT-4096 len=%d want <=1232", resp.Len())
	}
	// OPT 512 over TCP: capped at 512.
	srv = newBigServer(t)
	resp, _ = srv.serveInner(context.Background(), net.ParseIP("10.0.0.1"), "", control.ProtoDNS, false, query(true, 512))
	if resp.Len() > 512 {
		t.Errorf("TCP OPT-512 len=%d want <=512", resp.Len())
	}
	// UDP still caps at 1232 even with a large OPT.
	srv = newBigServer(t)
	resp, _ = srv.serveInner(context.Background(), net.ParseIP("10.0.0.1"), "", control.ProtoDNS, true, query(true, 4096))
	if resp.Len() > 1232 {
		t.Errorf("UDP OPT-4096 len=%d want <=1232", resp.Len())
	}
	// UDP honors a small advertised buffer (audit #10): OPT 512 truncates.
	srv = newBigServer(t)
	resp, _ = srv.serveInner(context.Background(), net.ParseIP("10.0.0.1"), "", control.ProtoDNS, true, query(true, 512))
	if resp.Len() > 512 {
		t.Errorf("UDP OPT-512 len=%d want <=512", resp.Len())
	}
	if !resp.Truncated {
		t.Errorf("UDP OPT-512 TC=0 want 1")
	}
}

func TestResponseCapTable(t *testing.T) {
	noOpt := new(dns.Msg)
	noOpt.SetQuestion("x.test.", dns.TypeA)
	withOpt := new(dns.Msg)
	withOpt.SetQuestion("x.test.", dns.TypeA)
	withOpt.SetEdns0(4096, false)
	smallOpt := new(dns.Msg)
	smallOpt.SetQuestion("x.test.", dns.TypeA)
	smallOpt.SetEdns0(100, false) // below floor: treated as 512
	medOpt := new(dns.Msg)
	medOpt.SetQuestion("x.test.", dns.TypeA)
	medOpt.SetEdns0(512, false)
	for _, tc := range []struct {
		name  string
		req   *dns.Msg
		isUDP bool
		want  int
	}{
		{"udp-noopt", noOpt, true, 1232},
		{"udp-opt", withOpt, true, 1232},
		{"udp-opt512", medOpt, true, 512},
		{"udp-opt100", smallOpt, true, 512},
		{"tcp-noopt", noOpt, false, 512},
		{"tcp-nil", nil, false, 512},
		{"tcp-opt4096", withOpt, false, 1232},
		{"tcp-opt100", smallOpt, false, 512},
	} {
		if got := responseCap(tc.req, tc.isUDP); got != tc.want {
			t.Errorf("%s: cap=%d want %d", tc.name, got, tc.want)
		}
	}
}

// Every name-bearing rdata type must be inspected (audit #13); TXT strings
// carrying a blocked name must not block, and NAPTR "." is not a name.
func TestChainBlockedNameBearingRdata(t *testing.T) {
	blocked := "blocked.test."
	classify := func(target string) bool {
		return filter.NormalizeName(target) == "blocked.test"
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: "q.test.", Rrtype: rrtype, Class: dns.ClassINET, Ttl: 60}
	}
	withAnswer := func(rr dns.RR) *dns.Msg {
		m := new(dns.Msg)
		m.Answer = []dns.RR{rr}
		return m
	}
	cases := []struct {
		name string
		rr   dns.RR
		want bool
	}{
		{"cname", &dns.CNAME{Hdr: hdr(dns.TypeCNAME), Target: blocked}, true},
		{"mx", &dns.MX{Hdr: hdr(dns.TypeMX), Mx: blocked}, true},
		{"srv", &dns.SRV{Hdr: hdr(dns.TypeSRV), Target: blocked}, true},
		{"ns", &dns.NS{Hdr: hdr(dns.TypeNS), Ns: blocked}, true},
		{"soa", &dns.SOA{Hdr: hdr(dns.TypeSOA), Ns: blocked, Mbox: "admin.q.test."}, true},
		{"svcb", &dns.SVCB{Hdr: hdr(dns.TypeSVCB), Target: blocked}, true},
		{"https", &dns.HTTPS{SVCB: dns.SVCB{Hdr: hdr(dns.TypeHTTPS), Target: blocked}}, true},
		{"naptr", &dns.NAPTR{Hdr: hdr(dns.TypeNAPTR), Replacement: blocked}, true},
		{"naptr-root", &dns.NAPTR{Hdr: hdr(dns.TypeNAPTR), Replacement: "."}, false},
		{"caa", &dns.CAA{Hdr: hdr(dns.TypeCAA), Tag: "issue", Value: "blocked.test; validationmethods=dns-01"}, true},
		{"rp", &dns.RP{Hdr: hdr(dns.TypeRP), Mbox: blocked, Txt: "more.q.test."}, true},
		{"a-owner", &dns.A{Hdr: dns.RR_Header{Name: blocked, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("9.9.9.9")}, true},
		{"txt-ignored", &dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: []string{blocked}}, false},
	}
	for _, tc := range cases {
		if got := chainBlocked(withAnswer(tc.rr), classify); got != tc.want {
			t.Errorf("%s: chainBlocked=%v want %v", tc.name, got, tc.want)
		}
	}
}

// Non-QUERY opcodes are NOTIMP'd locally and never forwarded: proxying
// UPDATE to an upstream that trusts blipd's IP is a zone-write primitive
// (2026-10-02 audit).
func TestNonQueryOpcodeNotImplemented(t *testing.T) {
	srv, up := newTestServer(t)
	q := new(dns.Msg)
	q.SetQuestion("allowed.test.", dns.TypeA)
	q.Opcode = dns.OpcodeUpdate
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", "dns", q)
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Errorf("UPDATE opcode rcode=%d want NOTIMP", resp.Rcode)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.calls != 0 {
		t.Errorf("UPDATE forwarded upstream (%d calls), want 0", up.calls)
	}
}

// Zero or several questions are FORMERR, never answered from Question[0]
// while the full message goes upstream (2026-10-02 audit).
func TestMultiQuestionFormerr(t *testing.T) {
	srv, up := newTestServer(t)
	q := new(dns.Msg)
	q.SetQuestion("allowed.test.", dns.TypeA)
	q.Question = append(q.Question, dns.Question{Name: "allowed.test.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", "dns", q)
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("QDCOUNT=2 rcode=%d want FORMERR", resp.Rcode)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.calls != 0 {
		t.Errorf("multi-question forwarded upstream (%d calls), want 0", up.calls)
	}
}

// IXFR is a zone transfer like AXFR: refused, never forwarded
// (2026-10-02 audit).
func TestIXFRRefused(t *testing.T) {
	srv, up := newTestServer(t)
	q := new(dns.Msg)
	q.SetQuestion("allowed.test.", dns.TypeIXFR)
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", "dns", q)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("IXFR rcode=%d want REFUSED", resp.Rcode)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.calls != 0 {
		t.Errorf("IXFR forwarded upstream (%d calls), want 0", up.calls)
	}
}

// DoH answers ride HTTPS framing: a >512B answer without OPT must NOT carry
// a spurious TC bit (2026-10-02 audit).
func TestDoHSkipsTruncate(t *testing.T) {
	store := filter.NewStore(nil)
	if err := store.SetPolicy(&filter.Policy{
		ID: "p", Networks: []string{"10.0.0.0/8"},
	}); err != nil {
		t.Fatal(err)
	}
	up := &recUp{txt: map[string][]string{"big.test.": {strings.Repeat("x", 2000)}}}
	srv := &Server{
		cfg:   Config{Store: store, Upstream: ""},
		cache: cache.New(0, 0),
		pool:  upstream.NewPoolWithAuto(up),
	}
	q := new(dns.Msg)
	q.SetQuestion("big.test.", dns.TypeTXT)
	resp := srv.serve(context.Background(), net.ParseIP("10.0.0.1"), "", control.ProtoDoH, q)
	if resp.Truncated {
		t.Errorf("DoH answer TC=1 want 0 (HTTPS needs no truncation)")
	}
	if resp.Len() <= 512 {
		t.Errorf("DoH answer len=%d want >512 (sanity: fixture must exceed the TCP cap)", resp.Len())
	}
}

// Pre-routing sheds (rate limit, ACL, nil source) drop UDP instead of
// reflecting REFUSED at a spoofable source (2026-10-02 audit). TCP still
// gets an answer: the peer is real.
func TestShedDropsUDP(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.rl = newRateLimiter()
	if err := srv.SetRateLimit(1, 1); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("10.0.0.1")
	q := new(dns.Msg)
	q.SetQuestion("allowed.test.", dns.TypeA)
	if _, drop := srv.serveInner(context.Background(), ip, "", control.ProtoDNS, true, q); drop {
		t.Fatalf("first query dropped, want served (burns the single token)")
	}
	resp, drop := srv.serveInner(context.Background(), ip, "", control.ProtoDNS, true, q)
	if !drop {
		t.Errorf("over-limit serveInner drop=false want true")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("over-limit rcode=%d want REFUSED body (dropped only on UDP)", resp.Rcode)
	}
	// Through the live socket (peer 127.0.0.1, its own bucket): first query
	// served, second shed into silence.
	w1 := &stubWriter{}
	srv.ServeDNS(w1, q)
	if w1.wrote == nil {
		t.Fatalf("first socket query shed, want served (burns the peer token)")
	}
	w := &stubWriter{}
	srv.ServeDNS(w, q)
	if w.wrote != nil {
		t.Errorf("shed UDP reply written (rcode=%d): reflector, want silence", w.wrote.Rcode)
	}
	// ACL shed drops UDP too.
	srvACL, _ := newTestServer(t)
	if err := srvACL.SetAllowedNetworks([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	respACL, dropACL := srvACL.serveInner(context.Background(), net.ParseIP("192.0.2.1"), "", control.ProtoDNS, true, q)
	if !dropACL {
		t.Errorf("ACL-denied serveInner drop=false want true")
	}
	if respACL.Rcode != dns.RcodeRefused {
		t.Errorf("ACL-denied rcode=%d want REFUSED body", respACL.Rcode)
	}
	// TCP still gets its answer body: the peer is real, not spoofable.
	// (127.0.0.1's token is spent above, so this is over-limit → REFUSED.)
	wTCP := &tcpStubWriter{}
	srv.ServeDNS(wTCP, q)
	if wTCP.wrote == nil {
		t.Fatalf("shed TCP reply dropped, want REFUSED body")
	}
	if wTCP.wrote.Rcode != dns.RcodeRefused {
		t.Errorf("shed TCP rcode=%d want REFUSED", wTCP.wrote.Rcode)
	}
	// Nil source is always shed, even without a limiter.
	srv2, _ := newTestServer(t)
	if _, drop := srv2.serveInner(context.Background(), nil, "", control.ProtoDNS, true, q); !drop {
		t.Errorf("nil-source serveInner drop=false want true")
	}
}

// tcpStubWriter reports TCP networks so shed paths treat it as a real
// (non-spoofable) peer that must still get a reply body.
type tcpStubWriter struct{ stubWriter }

func (s *tcpStubWriter) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")} }
func (s *tcpStubWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

// Zero questions are FORMERR without drop (nothing was asked, nothing to
// reflect); this also locks in the old Question[0] panic fix.
func TestZeroQuestionFormerr(t *testing.T) {
	srv, up := newTestServer(t)
	resp, drop := srv.serveInner(context.Background(), net.ParseIP("10.0.0.1"), "", control.ProtoDNS, true, new(dns.Msg))
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("QDCOUNT=0 rcode=%d want FORMERR", resp.Rcode)
	}
	if drop {
		t.Errorf("QDCOUNT=0 drop=true want false")
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.calls != 0 {
		t.Errorf("zero-question forwarded upstream (%d calls), want 0", up.calls)
	}
}

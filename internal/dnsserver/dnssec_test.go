package dnsserver

import (
	"context"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/twobip/BlipDNS/internal/upstream"
)

// adUp claims AD=1 and returns one A, one DNSKEY and one RRSIG for every
// query, whatever its type. It records the DO bit it received.
type adUp struct {
	mu    sync.Mutex
	calls int
	sawDO bool
}

func (u *adUp) Resolve(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	u.mu.Lock()
	u.calls++
	opt := q.IsEdns0()
	u.sawDO = opt != nil && opt.Do()
	u.mu.Unlock()

	m := new(dns.Msg)
	m.SetReply(q)
	m.AuthenticatedData = true
	name := q.Question[0].Name
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: 60}
	}
	m.Answer = []dns.RR{
		&dns.A{Hdr: hdr(dns.TypeA), A: net.ParseIP("192.0.2.1").To4()},
		&dns.DNSKEY{
			Hdr: hdr(dns.TypeDNSKEY), Flags: 257, Protocol: 3,
			Algorithm: dns.RSASHA256, PublicKey: "AwEAAc==",
		},
		&dns.RRSIG{
			Hdr: hdr(dns.TypeRRSIG), TypeCovered: dns.TypeA,
			Algorithm: dns.RSASHA256, Labels: 2, OrigTtl: 60,
			Expiration: 2000000000, Inception: 1700000000,
			KeyTag: 1, SignerName: "example.", Signature: "AA==",
		},
	}
	// A real validating upstream echoes an OPT with DO=1 when the query had
	// DO (including the DO=1 blipd forces for a DO=0 client).
	m.SetEdns0(1232, true)
	return m, nil
}

func (u *adUp) sawDOBit() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sawDO
}

func (u *adUp) callCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

func dnssecTestServer(t *testing.T, enabled bool) (*Server, *adUp) {
	t.Helper()
	up := &adUp{}
	srv := &Server{
		cfg:   Config{Store: filter.NewStore(nil)},
		cache: cache.New(0, 0),
		pool:  upstream.NewPoolWithAuto(up),
	}
	srv.dnssec.Store(enabled)
	t.Cleanup(func() {
		srv.cache.Stop()
	})
	return srv, up
}

func dnssecQuery(name string, qtype uint16, do, ad, cd bool) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	if do || ad {
		q.SetEdns0(1232, do)
	}
	q.AuthenticatedData = ad
	q.CheckingDisabled = cd
	return q
}

func countType(m *dns.Msg, t uint16) int {
	n := 0
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == t {
			n++
		}
	}
	return n
}

func TestDNSSECDelegatedValidation(t *testing.T) {
	cases := []struct {
		name       string
		enabled    bool
		do         bool
		ad         bool
		cd         bool
		qtype      uint16
		wantDO     bool // DO bit the upstream actually received
		wantAD     bool // AD bit in the client response
		wantRRSIG  bool
		wantDNSKEY bool
		wantOPT    bool // client sent EDNS, so the response may carry an OPT
		wantRespDO bool // DO bit echoed to an EDNS client
	}{
		{"enabled DO=1", true, true, false, false, dns.TypeA, true, true, true, true, true, true},
		{"enabled DO=0 AD=0", true, false, false, false, dns.TypeA, true, false, false, false, false, false},
		{"enabled DO=0 AD=1", true, false, true, false, dns.TypeA, true, true, false, false, true, false},
		{"enabled DO=1 CD=1", true, true, false, true, dns.TypeA, true, false, true, true, true, true},
		{"enabled DO=0 explicit DNSKEY", true, false, false, false, dns.TypeDNSKEY, true, false, false, true, false, false},
		{"disabled DO=1", false, true, false, false, dns.TypeA, true, false, true, true, true, true},
		{"disabled DO=0", false, false, false, false, dns.TypeA, false, false, false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, up := dnssecTestServer(t, tc.enabled)
			q := dnssecQuery("example.com.", tc.qtype, tc.do, tc.ad, tc.cd)
			resp := srv.serve(context.Background(), net.ParseIP("127.0.0.1"), "", control.ProtoDNS, q)

			if got := up.sawDOBit(); got != tc.wantDO {
				t.Errorf("upstream DO = %v, want %v", got, tc.wantDO)
			}
			if got := resp.AuthenticatedData; got != tc.wantAD {
				t.Errorf("response AD = %v, want %v", got, tc.wantAD)
			}
			if got := countType(resp, dns.TypeRRSIG) > 0; got != tc.wantRRSIG {
				t.Errorf("response has RRSIG = %v, want %v", got, tc.wantRRSIG)
			}
			if got := countType(resp, dns.TypeDNSKEY) > 0; got != tc.wantDNSKEY {
				t.Errorf("response has DNSKEY = %v, want %v", got, tc.wantDNSKEY)
			}
			opt := resp.IsEdns0()
			if got := opt != nil; got != tc.wantOPT {
				t.Errorf("response has OPT = %v, want %v", got, tc.wantOPT)
			}
			if opt != nil && opt.Do() != tc.wantRespDO {
				t.Errorf("response OPT DO = %v, want %v", opt.Do(), tc.wantRespDO)
			}
		})
	}
}

// TestDNSSECRuntimeToggle proves SetDNSSEC switches AD handling live and
// purges cached answers so a mode change cannot serve a stale AD bit.
func TestDNSSECRuntimeToggle(t *testing.T) {
	srv, up := dnssecTestServer(t, false)
	q := dnssecQuery("toggle.example.", dns.TypeA, true, false, false)

	if resp := srv.serve(context.Background(), net.ParseIP("127.0.0.1"), "", control.ProtoDNS, q); resp.AuthenticatedData {
		t.Fatal("disabled: response AD=1, want cleared")
	}
	srv.SetDNSSEC(true)
	if resp := srv.serve(context.Background(), net.ParseIP("127.0.0.1"), "", control.ProtoDNS, q); !resp.AuthenticatedData {
		t.Fatal("enabled after toggle: response AD=0, want upstream AD")
	}
	if got := up.callCount(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2 (toggle must purge the cache)", got)
	}
	srv.SetDNSSEC(false)
	if resp := srv.serve(context.Background(), net.ParseIP("127.0.0.1"), "", control.ProtoDNS, q); resp.AuthenticatedData {
		t.Fatal("disabled after toggle: response AD=1, want cleared")
	}
}

// TestDNSSECWatchEventMarksVerified proves the pass event carries the
// upstream validation status (AD) independently of the client-facing AD gate,
// so the controller can render the query-log padlock even for DO=0 clients.
func TestDNSSECWatchEventMarksVerified(t *testing.T) {
	ctrl := control.NewServerWithBlocklist("tok", filter.NewStore(nil), cache.New(0, 0), &control.Counters{}, "test", nil)
	ts := httptest.NewServer(ctrl.Handler())
	defer ts.Close()
	c := control.NewClient(ts.URL, "tok")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan control.WatchEvent, 1)
	go func() {
		_ = c.Watch(ctx, func(e control.WatchEvent) {
			if e.Type != "pass" {
				return
			}
			select {
			case events <- e:
			default:
			}
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for !ctrl.HasWatchers() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !ctrl.HasWatchers() {
		t.Fatal("watch client did not register")
	}

	srv, _ := dnssecTestServer(t, true)
	srv.ctrl = ctrl
	// DO=0/AD=0: the served response must clear AD, but the event should still
	// report the upstream validation status.
	q := dnssecQuery("verified.example.", dns.TypeA, false, false, false)
	resp := srv.serve(context.Background(), net.ParseIP("127.0.0.1"), "", control.ProtoDNS, q)
	if resp.AuthenticatedData {
		t.Fatal("client response AD=1, want gated to 0")
	}
	select {
	case e := <-events:
		if !e.DNSSEC {
			t.Fatal("pass event DNSSEC=false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no pass event received")
	}
}

// TestDNSSECStripsBeforeCache proves the DO=0 answer is sanitized before it is
// cached: the second identical query is a cache hit and still has no RRSIGs.
func TestDNSSECStripsBeforeCache(t *testing.T) {
	srv, up := dnssecTestServer(t, true)
	q := dnssecQuery("cached.example.", dns.TypeA, false, false, false)
	for i := 0; i < 2; i++ {
		resp := srv.serve(context.Background(), net.ParseIP("127.0.0.1"), "", control.ProtoDNS, q)
		if countType(resp, dns.TypeRRSIG) != 0 {
			t.Fatalf("query %d: cached DO=0 response leaked RRSIG", i)
		}
	}
	if got := up.callCount(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 (second query must be a cache hit)", got)
	}
}

// TestDNSSECCachePartitionsByDO proves DO=1 and DO=0 answers do not share an
// entry: the DO=1 client keeps RRSIGs, the DO=0 client gets them stripped.
func TestDNSSECCachePartitionsByDO(t *testing.T) {
	srv, up := dnssecTestServer(t, true)
	doQ := dnssecQuery("split.example.", dns.TypeA, true, false, false)
	noQ := dnssecQuery("split.example.", dns.TypeA, false, false, false)

	doResp := srv.serve(context.Background(), net.ParseIP("127.0.0.1"), "", control.ProtoDNS, doQ)
	noResp := srv.serve(context.Background(), net.ParseIP("127.0.0.1"), "", control.ProtoDNS, noQ)

	if countType(doResp, dns.TypeRRSIG) == 0 {
		t.Error("DO=1 response lost RRSIG")
	}
	if countType(noResp, dns.TypeRRSIG) != 0 {
		t.Error("DO=0 response leaked RRSIG")
	}
	if got := up.callCount(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2 (DO=1 and DO=0 are separate keys)", got)
	}
}

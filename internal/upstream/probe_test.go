package upstream

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestProbeServerInvalidDomain(t *testing.T) {
	res := ProbeServer(context.Background(), UpstreamServer{Name: "x", Address: "udp://127.0.0.1:1"}, "not a domain!!")
	if res.OK {
		t.Fatal("invalid domain should not probe OK")
	}
	if res.Error == "" {
		t.Fatal("invalid domain should set Error")
	}
}

func TestProbeServerInvalidSpec(t *testing.T) {
	// No network involved: spec parsing fails before any dial.
	res := ProbeServer(context.Background(), UpstreamServer{Name: "bogus", Address: "bogus://example"}, "example.com")
	if res.OK {
		t.Fatal("invalid spec should not probe OK")
	}
	if res.Error == "" {
		t.Fatal("invalid spec should set Error")
	}
	if res.Name != "bogus" || res.Address != "bogus://example" {
		t.Fatalf("result should echo name/address, got %+v", res)
	}
}

func TestProbeServerUnreachable(t *testing.T) {
	// Discard-port UDP on loopback refuses fast without external network.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := ProbeServer(ctx, UpstreamServer{Name: "dead", Address: "udp://127.0.0.1:1", TimeoutSec: 2}, "example.com")
	if res.OK {
		t.Fatalf("unreachable server should not probe OK: %+v", res)
	}
	if res.Error == "" {
		t.Fatal("unreachable server should set Error")
	}
}

func TestProbeWarmsBootstrapBeforeQueryTimeout(t *testing.T) {
	// A DoH endpoint whose hostname resolves via a slow bootstrap: warm-up
	// must run on the caller's context and pin the result, so the timed query
	// never consults the slow bootstrap again. Bootstrap answers after 3s;
	// per-server timeout is 2s — without pinning, the query would die.
	slow := &slowBootstrap{ips: []net.IP{net.ParseIP("127.0.0.1")}, delay: 3 * time.Second}
	r, err := fromServerSpecWithBootstrap("doh://doh.test:443/dns-query", 2*time.Second, slow)
	if err != nil {
		t.Fatal(err)
	}
	doh := r.(*DoHResolver)
	pinned, werr := warmDoHEndpoint(context.Background(), doh, 2*time.Second, "doh.test")
	if werr != nil {
		t.Fatalf("warm-up failed: %v", werr)
	}
	if pinned == nil {
		t.Fatal("warm-up should pin slow-but-working bootstrap")
	}
	if got := slow.calls.Load(); got != 2 {
		t.Fatalf("warm-up bootstrap calls = %d, want 2 (A+AAAA once)", got)
	}
	// The pinned resolver's bootstrap must answer instantly from the warmed
	// IPs without touching the slow bootstrap again.
	start := time.Now()
	ips := bootstrapLookupIP(context.Background(), pinned.(*DoHResolver).bootstrap, "doh.test")
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("pinned lookup took %v, want instant", elapsed)
	}
	if len(ips) == 0 {
		t.Fatal("pinned lookup returned no IPs")
	}
	if got := slow.calls.Load(); got != 2 {
		t.Fatalf("pinned lookup hit slow bootstrap: calls = %d, want 2", got)
	}
}

func TestProbeDeadBootstrapSurfacesBootstrapError(t *testing.T) {
	// Caller context already expired: the pre-warm must blame bootstrap, not
	// the query's "context deadline exceeded".
	dead := &failBootstrap{}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	sv := UpstreamServer{Name: "doh", Address: "doh://doh.test:443/dns-query", TimeoutSec: 2}
	res := ProbeServerWithBootstrap(ctx, sv, "example.com", dead)
	if res.OK {
		t.Fatal("expired context should not probe OK")
	}
	if !strings.Contains(res.Error, "bootstrap resolve") {
		t.Errorf("error = %q, want bootstrap blame", res.Error)
	}
}

// slowBootstrap answers the bootstrap lookup after delay, simulating a
// sluggish bootstrap server that would previously eat the probe's query budget.
type slowBootstrap struct {
	ips   []net.IP
	delay time.Duration
	calls atomic.Int64
}

func (s *slowBootstrap) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	s.calls.Add(1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(s.delay):
	}
	m := new(dns.Msg)
	m.SetReply(q)
	if len(q.Question) != 1 {
		return m, nil
	}
	hdr := dns.RR_Header{Name: q.Question[0].Name, Rrtype: q.Question[0].Qtype, Class: dns.ClassINET, Ttl: 60}
	for _, ip := range s.ips {
		switch q.Question[0].Qtype {
		case dns.TypeA:
			if ip.To4() != nil {
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip.To4()})
			}
		case dns.TypeAAAA:
			if ip.To4() == nil {
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
			}
		}
	}
	return m, nil
}

// failBootstrap never answers, simulating a dead bootstrap server.
type failBootstrap struct{}

func (f *failBootstrap) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestIsConnReset(t *testing.T) {
	if isConnReset(nil) {
		t.Error("nil must not be a reset")
	}
	if !isConnReset(&simpleErr{"Post \"https://x/dns-query\": read tcp 1.2.3.4:1->5.6.7.8:443: read: connection reset by peer"}) {
		t.Error("RST error should retry")
	}
	for _, msg := range []string{
		"Post \"https://x/dns-query\": context deadline exceeded",
		"Post \"https://x/dns-query\": doh: upstream returned 403",
		"boom",
	} {
		if isConnReset(&simpleErr{msg}) {
			t.Errorf("%q must not retry", msg)
		}
	}
}

// flakyOnce fails its first Resolve with a mid-connection RST, then answers
// like a healthy DoH endpoint — the probe must retry once and succeed.
type flakyOnce struct {
	mu    sync.Mutex
	calls int
	msg   *dns.Msg
}

func (f *flakyOnce) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if n == 1 {
		return nil, &simpleErr{"Post \"https://x/dns-query\": read tcp 1.2.3.4:1->5.6.7.8:443: read: connection reset by peer"}
	}
	m := f.msg.Copy()
	m.Id = q.Id
	m.Question = q.Question
	return m, nil
}

func TestProbeRetriesConnReset(t *testing.T) {
	// A stub resolver that RSTs once then answers, driven through the real
	// probe retry path (single shared retry helper, no network).
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.2.3.4")})
	f := &flakyOnce{msg: m}
	resp, err := resolveWithRetry(context.Background(), f, "example.com.")
	if err != nil {
		t.Fatalf("retry should succeed, got %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %+v", resp.Answer)
	}
	if f.calls != 2 {
		t.Fatalf("calls = %d, want exactly 2 (fail once, retry once)", f.calls)
	}
	// A non-reset error must NOT retry.
	always := &failResolver{}
	if _, err := resolveWithRetry(context.Background(), always, "example.com."); err == nil {
		t.Fatal("expected error from failing resolver")
	}
}

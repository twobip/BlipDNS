package upstream

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeResolver struct{ msg *dns.Msg }

func (f *fakeResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m := f.msg.Copy()
	m.Id = q.Id
	m.Question = q.Question
	return m, nil
}

func TestErrUpstreamStripsEphemeralSocket(t *testing.T) {
	// Address labeling + stripping combined: the ephemeral local socket is
	// removed so identical failures share one message.
	got := errUpstream("127.0.0.1:1", &simpleErr{"read udp 127.0.0.1:50791->127.0.0.1:1: read: connection refused"}).Error()
	if got != "127.0.0.1:1: read: connection refused" {
		t.Errorf("errUpstream = %q, want %q", got, "127.0.0.1:1: read: connection refused")
	}
	// IPv6 local sockets are stripped too.
	got = errUpstream("[::1]:53", &simpleErr{"read udp [::1]:45000->[::1]:53: i/o timeout"}).Error()
	if got != "[::1]:53: i/o timeout" {
		t.Errorf("errUpstream ipv6 = %q, want %q", got, "[::1]:53: i/o timeout")
	}
	// Dial errors have no local socket; only the address label is added.
	got = errUpstream("1.1.1.1:53", &simpleErr{"dial tcp 1.1.1.1:53: connect: network is unreachable"}).Error()
	if got != "1.1.1.1:53: dial tcp 1.1.1.1:53: connect: network is unreachable" {
		t.Errorf("errUpstream dial = %q", got)
	}
	// Non-network errors pass through with just the address label.
	if got := errUpstream("https://1.1.1.1/dns-query", &simpleErr{"doh: upstream returned 500"}).Error(); got != "https://1.1.1.1/dns-query: doh: upstream returned 500" {
		t.Errorf("errUpstream doh = %q", got)
	}
}

// TestDoHResolveLabelsEndpoint verifies DoH failures name the endpoint, so the
// errors page shows which upstream returned the status (e.g. Quad9 403s).
func TestDoHResolveLabelsEndpoint(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer ts.Close()
	r := NewDoH(ts.URL+"/dns-query", time.Second)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err := r.Resolve(context.Background(), q)
	if err == nil {
		t.Fatal("expected 403 error, got nil")
	}
	if !strings.Contains(err.Error(), ts.URL+"/dns-query") || !strings.Contains(err.Error(), "403") {
		t.Errorf("DoH error = %q, want endpoint and 403", err.Error())
	}
}

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }

func TestFromSpec(t *testing.T) {
	r, err := FromSpec("udp://1.1.1.1:53 https://8.8.8.8/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*MultiResolver); !ok {
		t.Errorf("expected MultiResolver, got %T", r)
	}
	if _, err := FromSpec("garbage://x"); err == nil {
		t.Error("expected error for bad spec")
	}
}

func TestMultiFailover(t *testing.T) {
	ok := &fakeResolver{msg: new(dns.Msg)}
	fail := failResolver{}
	m := NewMulti(fail, ok)
	q := new(dns.Msg)
	q.SetQuestion("a.test.", dns.TypeA)
	resp, err := m.Resolve(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response from second resolver")
	}
}

type failResolver struct{}

func (failResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	return nil, errBoom{}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

func TestDoHURLSpec(t *testing.T) {
	r, err := FromSpec("doh://dns.google/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*DoHResolver); !ok {
		t.Errorf("expected DoHResolver, got %T", r)
	}
}

func TestParseSpec(t *testing.T) {
	got, err := ParseSpec("udp://8.8.8.8:53|2 https://1.1.1.1/dns-query|1")
	if err != nil {
		t.Fatal(err)
	}
	want := []Spec{
		{Type: "doh", Address: "1.1.1.1/dns-query", Priority: 1},
		{Type: "udp", Address: "8.8.8.8:53", Priority: 2},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d specs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("spec[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseSpecPositionalPriority(t *testing.T) {
	got, err := ParseSpec("udp://1.1.1.1:53 udp://8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Address != "1.1.1.1:53" || got[0].Priority != 1 {
		t.Errorf("first spec = %+v, want priority 1", got[0])
	}
	if got[1].Address != "8.8.8.8:53" || got[1].Priority != 2 {
		t.Errorf("second spec = %+v, want priority 2", got[1])
	}
}

func TestParseSpecNoTrailingPrioritySuffix(t *testing.T) {
	got, err := ParseSpec("https://1.1.1.1/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != "doh" || got[0].Address != "1.1.1.1/dns-query" {
		t.Errorf("unexpected parse: %+v", got)
	}
}

func TestParseSpecDefaultUDPPort(t *testing.T) {
	got, err := ParseSpec("udp://192.168.30.221|1 udp://8.8.8.8:53 udp://[::1]|2")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.30.221:53", "8.8.8.8:53", "[::1]:53"}
	if len(got) != len(want) {
		t.Fatalf("got %d specs, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Address != w {
			t.Errorf("spec[%d].Address = %q, want %q", i, got[i].Address, w)
		}
	}
}

func TestParseSpecBareUDPAssumption(t *testing.T) {
	got, err := ParseSpec("192.168.30.221 9.9.9.9:53 https://dns.mullvad.net/dns-query [::1]")
	if err != nil {
		t.Fatal(err)
	}
	want := []Spec{
		{Type: "udp", Address: "192.168.30.221:53", Priority: 1},
		{Type: "udp", Address: "9.9.9.9:53", Priority: 2},
		{Type: "doh", Address: "dns.mullvad.net/dns-query", Priority: 3},
		{Type: "udp", Address: "[::1]:53", Priority: 4},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d specs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("spec[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseSpecRejectsAmbiguousBareHost(t *testing.T) {
	_, err := ParseSpec("dns.google")
	if err == nil {
		t.Fatal("bare hostname without a port or scheme should be rejected")
	}
}

// TestNewPoolDisabledRoutes verifies a disabled route is kept in the config
// (readback) but never matches queries, and is exempt from validation (so the
// default local-ptr rule can exist with no server picked yet).
func TestNewPoolDisabledRoutes(t *testing.T) {
	servers := []UpstreamServer{{Name: "local", Address: "udp://192.168.30.221", Priority: 0}}
	p, err := NewPool(servers, []UpstreamRoute{
		{Name: "local-ptr", QnameSuffix: ".in-addr.arpa.", Server: "ghost", Disabled: true},
		{Name: "corp", QnameSuffix: ".corp.", Server: "local"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if r := p.Match("4.30.168.192.in-addr.arpa.", net.IPv4(192, 168, 1, 10)); r != nil {
		t.Errorf("disabled route matched: %v", r)
	}
	if r := p.Match("host.corp.", net.IPv4(192, 168, 1, 10)); r == nil {
		t.Error("enabled route did not match")
	}
	if got := p.Routes(); len(got) != 2 || !got[0].Disabled {
		t.Errorf("routes readback = %+v, want disabled route preserved", got)
	}
}

func TestFromSpecPriorityOrder(t *testing.T) {
	r, err := FromSpec("udp://8.8.8.8:53|2 udp://1.1.1.1:53|1")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := r.(*MultiResolver)
	if !ok {
		t.Fatalf("expected MultiResolver, got %T", r)
	}
	if got := m.resolvers[0].(*UDPResolver).addr; got != "1.1.1.1:53" {
		t.Errorf("priority 1 resolver = %s, want 1.1.1.1:53", got)
	}
	if got := m.resolvers[1].(*UDPResolver).addr; got != "8.8.8.8:53" {
		t.Errorf("priority 2 resolver = %s, want 8.8.8.8:53", got)
	}
}

// countFailResolver records calls and fails a set number of times.
type countFailResolver struct {
	fail    int // fail the first N calls, then succeed
	calls   int
	resp    *dns.Msg
	succeed bool
}

func (c *countFailResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	c.calls++
	if c.calls <= c.fail {
		return nil, errBoom{}
	}
	c.succeed = true
	return c.resp.Copy(), nil
}

func TestMultiFailoverBreaker(t *testing.T) {
	down := &countFailResolver{fail: 1, resp: new(dns.Msg)}
	ok := &fakeResolver{msg: new(dns.Msg)}
	m := NewMulti(down, ok)
	q := new(dns.Msg)
	q.SetQuestion("a.test.", dns.TypeA)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := m.Resolve(ctx, q); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	// The failed resolver must have been skipped on calls 2 and 3 while in
	// cooldown, otherwise it would have been tried and failed again.
	if down.calls != 1 {
		t.Errorf("down resolver tried %d times, want 1 (circuit breaker)", down.calls)
	}
}

func TestPoolLabelFor(t *testing.T) {
	servers := []UpstreamServer{
		{Name: "DoH", Address: "https://dns.example.com/dns-query", Priority: 1},
		{Name: "Local", Address: "udp://192.168.30.1:53", Priority: 0},
	}
	p, err := NewPool(servers, []UpstreamRoute{
		{Name: "local-ptr", QnameSuffix: ".in-addr.arpa.", Server: "Local"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	// Route match is attributed to the named server it points at.
	if r := p.Match("4.30.168.192.in-addr.arpa.", net.IPv4(192, 168, 1, 10)); r == nil {
		t.Fatal("route did not match")
	} else if got := p.LabelFor(r); got != "Local (udp://192.168.30.1:53)" {
		t.Errorf("LabelFor(route resolver) = %q", got)
	}
	// The automatic rotation is labeled with its priority>0 members.
	if got := p.LabelFor(p.Auto()); got != "auto (DoH)" {
		t.Errorf("LabelFor(auto) = %q, want auto (DoH)", got)
	}
	// Resolvers not owned by the pool (e.g. per-policy overrides) get "".
	if got := p.LabelFor(NewUDP("9.9.9.9:53", 0)); got != "" {
		t.Errorf("LabelFor(unrelated resolver) = %q, want empty", got)
	}
}

func TestPoolServerTimeout(t *testing.T) {
	servers := []UpstreamServer{
		{Name: "fast", Address: "udp://1.2.3.4:53", Priority: 1, TimeoutSec: 2},
		{Name: "slow", Address: "udp://5.6.7.8:53", Priority: 2, TimeoutSec: 0},
	}
	p, err := NewPool(servers, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// fast: explicit 2s
	fast := p.named["fast"].(*UDPResolver)
	if fast.timeout != 2*time.Second {
		t.Errorf("fast timeout = %v, want 2s", fast.timeout)
	}
	// slow: TimeoutSec 0 -> 5s default
	slow := p.named["slow"].(*UDPResolver)
	if slow.timeout != 5*time.Second {
		t.Errorf("slow timeout = %v, want 5s default", slow.timeout)
	}
}

func TestDoHTimeout(t *testing.T) {
	servers := []UpstreamServer{
		{Name: "doh1", Address: "https://dns.example.com/dns-query", Priority: 1, TimeoutSec: 3},
	}
	p, err := NewPool(servers, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	r := p.named["doh1"].(*DoHResolver)
	if r.client.Timeout != 3*time.Second {
		t.Errorf("doh timeout = %v, want 3s", r.client.Timeout)
	}
}

func TestPoolWithBootstrap(t *testing.T) {
	servers := []UpstreamServer{
		{Name: "doh", Address: "https://dns.example.com/dns-query", Priority: 1},
	}
	bootstrap := []UpstreamServer{
		{Address: "https://1.1.1.1/dns-query"},
		{Address: "8.8.8.8"},
	}
	p, err := NewPoolWithBootstrap(servers, nil, "", bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Bootstrap(), bootstrap) {
		t.Errorf("pool.Bootstrap() = %+v, want %+v", p.Bootstrap(), bootstrap)
	}
	r := p.named["doh"].(*DoHResolver)
	if r.bootstrap == nil {
		t.Fatal("DoH resolver missing bootstrap resolver")
	}
	if tr, ok := r.client.Transport.(*http.Transport); !ok || tr.DialContext == nil {
		t.Error("DoH transport must use a bootstrap DialContext")
	}
	// A bad bootstrap spec is rejected at pool build time.
	if _, err := NewPoolWithBootstrap(servers, nil, "", []UpstreamServer{{Address: "wibble://x"}}); err == nil {
		t.Error("invalid bootstrap spec accepted")
	}
	// Empty bootstrap keeps historical behavior (system resolver dialing).
	p2, err := NewPoolWithBootstrap(servers, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	r2 := p2.named["doh"].(*DoHResolver)
	if r2.bootstrap != nil {
		t.Error("nil bootstrap should leave no bootstrap resolver")
	}
	if tr, ok := r2.client.Transport.(*http.Transport); ok && tr.DialContext != nil {
		t.Error("nil bootstrap should not install a DialContext")
	}
}

// stubBootstrapResolver answers A/AAAA for a fixed host so a DoH endpoint can
// be reached over the loopback without touching the real system resolver.
type stubBootstrapResolver struct {
	host  string
	ips   []net.IP
	mu    sync.Mutex
	asked []string
}

func (s *stubBootstrapResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetReply(q)
	if len(q.Question) != 1 {
		return m, nil
	}
	s.mu.Lock()
	s.asked = append(s.asked, q.Question[0].Name)
	s.mu.Unlock()
	if q.Question[0].Name != dns.Fqdn(s.host) {
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

func TestDoHBootstrapResolve(t *testing.T) {
	// A plain-HTTP DoH endpoint ("doh.test:PORT"): TLS is not involved, so the
	// only hostname handling that must happen is the bootstrap resolution.
	done := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(b); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.2.3.4")})
		out, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
		close(done)
	}))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())

	bs := &stubBootstrapResolver{host: "doh.test", ips: []net.IP{net.ParseIP("127.0.0.1")}}
	r := NewDoHWithBootstrap("http://doh.test:"+port+"/dns-query", 2*time.Second, bs)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	resp, err := r.Resolve(context.Background(), q)
	if err != nil {
		t.Fatalf("resolve via bootstrap: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DoH endpoint never reached")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %+v", resp.Answer)
	}
	if a := resp.Answer[0].(*dns.A); !a.A.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("answer A = %v, want 1.2.3.4", a.A)
	}
	// The bootstrap resolver must have been queried for the endpoint hostname.
	bs.mu.Lock()
	defer bs.mu.Unlock()
	found := false
	for _, n := range bs.asked {
		if n == dns.Fqdn("doh.test") {
			found = true
		}
	}
	if !found {
		t.Errorf("bootstrap was never asked to resolve the DoH host; asked = %v", bs.asked)
	}
}

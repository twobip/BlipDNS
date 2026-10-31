package upstream

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func boolPtr(b bool) *bool { return &b }

// fakeADUDP starts a local UDP resolver that claims AD=1 and returns one A
// record. It returns the dialable address.
func fakeADUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.AuthenticatedData = true
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name: r.Question[0].Name, Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 60,
				},
				A: net.ParseIP("192.0.2.1").To4(),
			}}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// fakeADDoH starts a TLS DoH endpoint that claims AD=1.
func fakeADDoH(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var q dns.Msg
		if err := q.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(&q)
		m.AuthenticatedData = true
		buf, err := m.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(buf)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func aQuery() *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	return q
}

// TestUDPResolverClearsAD proves plain UDP/TCP is untrusted by default: even a
// response that claims AD=1 reaches the caller with AD cleared.
func TestUDPResolverClearsAD(t *testing.T) {
	r := NewUDP(fakeADUDP(t), time.Second)
	got, err := r.Resolve(context.Background(), aQuery())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.AuthenticatedData {
		t.Fatal("plain UDP response kept AD=1; want cleared")
	}
}

// TestUDPResolverTrustAD proves trust_ad: true lets a plaintext validator
// (e.g. a local Unbound) assert AD, and trust_ad: false overrides the default.
func TestUDPResolverTrustAD(t *testing.T) {
	addr := "udp://" + fakeADUDP(t)
	cases := []struct {
		name  string
		trust *bool
		want  bool
	}{
		{"default", nil, false},
		{"trust_ad true", boolPtr(true), true},
		{"trust_ad false", boolPtr(false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPool([]UpstreamServer{{
				Name: "fake", Address: addr, Priority: 1, TrustAD: tc.trust,
			}}, nil, "")
			if err != nil {
				t.Fatalf("NewPool: %v", err)
			}
			got, err := p.Auto().Resolve(context.Background(), aQuery())
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got.AuthenticatedData != tc.want {
				t.Fatalf("AD = %v, want %v", got.AuthenticatedData, tc.want)
			}
		})
	}
}

// TestDoHResolverKeepsAD proves DoH is trusted by default (the TLS channel
// authenticates the endpoint) so the server layer can gate on AD.
func TestDoHResolverKeepsAD(t *testing.T) {
	srv := fakeADDoH(t)
	r := NewDoH(srv.URL+"/dns-query", time.Second)
	tr, ok := r.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("DoH transport is %T, want *http.Transport", r.client.Transport)
	}
	// httptest uses a self-signed cert; the real client verifies against the
	// system roots (TestDoHUpstreamUsesTLS covers that path).
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	got, err := r.Resolve(context.Background(), aQuery())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.AuthenticatedData {
		t.Fatal("DoH response dropped upstream AD=1; want preserved")
	}
}

// TestDoHResolverTrustADOff proves a per-server trust_ad: false opts even a
// TLS upstream out of AD propagation.
func TestDoHResolverTrustADOff(t *testing.T) {
	srv := fakeADDoH(t)
	p, err := NewPool([]UpstreamServer{{
		Name: "doh", Address: srv.URL + "/dns-query", Priority: 1, TrustAD: boolPtr(false),
	}}, nil, "")
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	r, ok := p.Auto().(*DoHResolver)
	if !ok {
		t.Fatalf("auto resolver is %T, want *DoHResolver", p.Auto())
	}
	tr, ok := r.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("DoH transport is %T, want *http.Transport", r.client.Transport)
	}
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	got, err := r.Resolve(context.Background(), aQuery())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.AuthenticatedData {
		t.Fatal("DoH response kept AD=1 despite trust_ad=false")
	}
}

func TestAnyTrusted(t *testing.T) {
	udp := NewUDP("1.1.1.1:53", time.Second)
	doh := NewDoH("https://1.1.1.1/dns-query", time.Second)
	if NewPoolWithAuto(udp).AnyTrusted() {
		t.Fatal("UDP-only pool reported a trusted upstream")
	}
	if !NewPoolWithAuto(doh).AnyTrusted() {
		t.Fatal("DoH pool reported no trusted upstream")
	}
	if !NewPoolWithAuto(NewMulti(udp, doh)).AnyTrusted() {
		t.Fatal("mixed DoH+UDP pool reported no trusted upstream")
	}
	if (*ResolverPool)(nil).AnyTrusted() {
		t.Fatal("nil pool reported a trusted upstream")
	}

	trustedUDP, err := NewPool([]UpstreamServer{{
		Name: "unbound", Address: "udp://127.0.0.1:53", Priority: 1, TrustAD: boolPtr(true),
	}}, nil, "")
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if !trustedUDP.AnyTrusted() {
		t.Fatal("trust_ad=true on UDP was not honored")
	}
	untrustedDoH, err := NewPool([]UpstreamServer{{
		Name: "doh", Address: "https://1.1.1.1/dns-query", Priority: 1, TrustAD: boolPtr(false),
	}}, nil, "")
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if untrustedDoH.AnyTrusted() {
		t.Fatal("trust_ad=false on DoH was not honored")
	}
}

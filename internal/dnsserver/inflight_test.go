package dnsserver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// stubWriter is the smallest dns.ResponseWriter that captures the reply.
type stubWriter struct{ wrote *dns.Msg }

func (s *stubWriter) RemoteAddr() net.Addr { return &net.UDPAddr{IP: net.ParseIP("127.0.0.1")} }
func (s *stubWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}
func (s *stubWriter) WriteMsg(m *dns.Msg) error   { s.wrote = m; return nil }
func (s *stubWriter) Write(b []byte) (int, error) { return len(b), nil }
func (s *stubWriter) Close() error                { return nil }
func (s *stubWriter) TsigStatus() error           { return nil }
func (s *stubWriter) TsigTimersOnly(bool)         {}
func (s *stubWriter) Hijack()                     {}

func TestServeDNSShedsPastInflightCap(t *testing.T) {
	srv, err := New(Config{
		DNSAddr:         "127.0.0.1:0",
		Upstream:        "udp://127.0.0.1:53",
		AllowedNetworks: []string{"127.0.0.1/32"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < maxInflightQueries; i++ {
		srv.inflight <- struct{}{}
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	w := &stubWriter{}
	srv.ServeDNS(w, req)
	// Overload shed on UDP is silence, not SERVFAIL: replying to a
	// spoofable source is reflection (2026-10-02 audit).
	if w.wrote != nil {
		t.Fatalf("saturated ServeDNS over UDP wrote rcode=%d, want silence", w.wrote.Rcode)
	}
}

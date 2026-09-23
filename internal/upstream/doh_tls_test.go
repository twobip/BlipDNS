package upstream

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestDoHUpstreamUsesTLS proves the DoH client performs a real TLS handshake
// (with system certificate verification) against https:// upstreams: the
// first bytes on the wire must be a TLS ClientHello, never a plaintext HTTP
// request. Regression test for the DialTLSContext defect that sent DoH as
// cleartext HTTP (no encryption, no cert verification, upstream breakage).
func TestDoHUpstreamUsesTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 5)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	r := NewDoH("https://"+ln.Addr().String()+"/dns-query", 3*time.Second)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_, _ = r.Resolve(ctx, q)
	select {
	case b := <-got:
		if len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 {
			return // TLS ClientHello
		}
		t.Fatalf("first bytes %q: not a TLS ClientHello (plaintext leak?)", b)
	case <-time.After(6 * time.Second):
		t.Fatal("no connection received")
	}
}

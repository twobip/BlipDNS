package dnsserver

import (
	"bytes"
	"context"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/upstream"
)

// slowUp answers every A query after a fixed delay, so a query is guaranteed
// to cross a slow_query_ms threshold of 1ms.
type slowUp struct{}

func (slowUp) Resolve(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	time.Sleep(5 * time.Millisecond)
	m := new(dns.Msg)
	m.SetReply(q)
	if len(q.Question) == 1 {
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("9.9.9.9"),
		}}
	}
	return m, nil
}

// captureLog redirects the stdlib logger for the duration of fn.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

func TestSlowQueryLog(t *testing.T) {
	newSrv := func(threshold time.Duration) *Server {
		srv := &Server{cache: cache.New(0, 0), pool: upstream.NewPoolWithAuto(slowUp{})}
		srv.SetSlowQueryThreshold(threshold)
		return srv
	}
	q := new(dns.Msg)
	q.SetQuestion("slow.test.", dns.TypeA)

	// Threshold above the fake's latency: silent.
	out := captureLog(func() {
		newSrv(time.Hour).serve(context.Background(), net.ParseIP("10.0.0.1"), "", "dns", q)
	})
	if strings.Contains(out, "slow query") {
		t.Fatalf("threshold above latency still logged: %q", out)
	}

	// 1ms threshold: exactly one line naming the query and the miss.
	out = captureLog(func() {
		newSrv(time.Millisecond).serve(context.Background(), net.ParseIP("10.0.0.1"), "dev1", "doh", q)
	})
	for _, want := range []string{"slow query", "slow.test.", "client=10.0.0.1 id=dev1", "proto=doh", "cache=miss", "rcode=NOERROR", "total_ms="} {
		if !strings.Contains(out, want) {
			t.Errorf("slow-query line missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "slow query"); n != 1 {
		t.Errorf("logged %d lines, want 1:\n%s", n, out)
	}

	// Cache hits are fast, so they only surface with a sub-microsecond
	// threshold — the second query must still be reported as a hit.
	out = captureLog(func() {
		s := newSrv(time.Nanosecond)
		s.serve(context.Background(), net.ParseIP("10.0.0.2"), "", "dns", q)
		s.serve(context.Background(), net.ParseIP("10.0.0.2"), "", "dns", q)
	})
	if !strings.Contains(out, "cache=hit") {
		t.Errorf("cached query not reported as hit:\n%s", out)
	}
}

package upstream

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

type fakeResolver struct{ msg *dns.Msg }

func (f *fakeResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m := f.msg.Copy()
	m.Id = q.Id
	m.Question = q.Question
	return m, nil
}

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

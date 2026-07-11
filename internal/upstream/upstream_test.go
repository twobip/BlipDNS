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

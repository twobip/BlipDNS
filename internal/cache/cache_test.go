package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func mkMsg(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   []byte{1, 2, 3, 4},
	}}
	return m
}

func TestSetGetDecrementsTTL(t *testing.T) {
	c := New(time.Hour)
	k := Key(mkMsg("a.test", 60))
	c.Set(k, mkMsg("a.test", 60))
	got, ok := c.Get(k)
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Answer[0].Header().Ttl == 60 {
		t.Error("expected TTL to be decremented below 60")
	}
}

func TestExpiry(t *testing.T) {
	c := New(time.Hour)
	c.now = func() time.Time { return time.Unix(1000, 0) }
	// inject an entry expiring at 1010
	k := Key(mkMsg("a.test", 5))
	m := mkMsg("a.test", 5)
	c.Set(k, m)
	// before expiry
	c.now = func() time.Time { return time.Unix(1004, 0) }
	if _, ok := c.Get(k); !ok {
		t.Fatal("expected hit before expiry")
	}
	// after expiry
	c.now = func() time.Time { return time.Unix(1011, 0) }
	if _, ok := c.Get(k); ok {
		t.Fatal("expected miss after expiry")
	}
}

func TestCoalesce(t *testing.T) {
	c := New(time.Hour)
	var calls int
	var mu sync.Mutex
	fn := func() (*dns.Msg, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		return mkMsg("a.test", 60), nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Do(context.Background(), "k", fn)
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Errorf("expected single upstream call, got %d", calls)
	}
}

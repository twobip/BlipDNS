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
	c := New(time.Hour, 0)
	k := KeyOf(mkMsg("a.test", 60))
	c.Set(k, mkMsg("a.test", 60))
	got, ok := c.Get(k)
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Answer[0].Header().Ttl == 60 {
		t.Error("expected TTL to be decremented below 60")
	}
}

func TestSetCapsAtRecordTTL(t *testing.T) {
	c := New(time.Hour, 0)
	c.now = func() time.Time { return time.Unix(1000, 0) }
	k := KeyOf(mkMsg("a.test", 60))
	c.Set(k, mkMsg("a.test", 60))
	// Past the record TTL the entry is gone: the cache never serves
	// records past the TTL their owner published.
	c.now = func() time.Time { return time.Unix(1061, 0) }
	if _, ok := c.Get(k); ok {
		t.Error("expected miss past the record TTL")
	}
}

func TestPurge(t *testing.T) {
	c := New(time.Hour, 0)
	c.Set(KeyOf(mkMsg("a.test", 60)), mkMsg("a.test", 60))
	c.Set(KeyOf(mkMsg("b.test", 60)), mkMsg("b.test", 60))
	if c.Len() != 2 {
		t.Fatalf("precondition: Len = %d, want 2", c.Len())
	}
	c.Purge()
	if c.Len() != 0 {
		t.Fatalf("Len after purge = %d, want 0", c.Len())
	}
	if _, ok := c.Get(KeyOf(mkMsg("a.test", 60))); ok {
		t.Error("expected miss after purge")
	}
	// cache must remain usable after purge
	k := KeyOf(mkMsg("a.test", 60))
	c.Set(k, mkMsg("a.test", 60))
	if _, ok := c.Get(k); !ok {
		t.Error("expected hit after re-insertion post-purge")
	}
}

func TestExpiry(t *testing.T) {
	c := New(time.Hour, 0)
	c.now = func() time.Time { return time.Unix(1000, 0) }
	// inject an entry expiring at 1005
	k := KeyOf(mkMsg("a.test", 5))
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
	c := New(time.Hour, 0)
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
			_, _, _ = c.DoHit(context.Background(), Key{Name: "k"}, fn)
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Errorf("expected single upstream call, got %d", calls)
	}
}

func TestDoHitReportsCacheSource(t *testing.T) {
	c := New(time.Hour, 0)
	calls := 0
	fn := func() (*dns.Msg, error) {
		calls++
		return mkMsg("a.test", 60), nil
	}
	// First call must miss and fetch.
	_, cached, err := c.DoHit(context.Background(), Key{Name: "k"}, fn)
	if err != nil || cached {
		t.Errorf("first DoHit: cached=%v err=%v, want miss", cached, err)
	}
	// Second call must be served from cache.
	_, cached, err = c.DoHit(context.Background(), Key{Name: "k"}, fn)
	if err != nil || !cached {
		t.Errorf("second DoHit: cached=%v err=%v, want hit", cached, err)
	}
	if calls != 1 {
		t.Errorf("expected 1 upstream call, got %d", calls)
	}
}

func TestDoHitCoalescedWaiterIsHit(t *testing.T) {
	c := New(time.Hour, 0)
	calls := 0
	fn := func() (*dns.Msg, error) {
		calls++
		time.Sleep(20 * time.Millisecond)
		return mkMsg("a.test", 60), nil
	}
	var cacheds []bool
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, cached, _ := c.DoHit(context.Background(), Key{Name: "k"}, fn)
			mu.Lock()
			cacheds = append(cacheds, cached)
			mu.Unlock()
		}()
	}
	wg.Wait()
	for _, cached := range cacheds {
		if !cached {
			t.Error("coalesced waiter reported as cache miss, want hit")
		}
	}
	if calls != 1 {
		t.Errorf("expected 1 upstream call, got %d", calls)
	}
}

func TestEvictLeastRecentlyUsed(t *testing.T) {
	c := New(time.Hour, 2)
	c.Set(Key{Name: "k1"}, mkMsg("a.test", 60))
	c.Set(Key{Name: "k2"}, mkMsg("b.test", 60))
	// promote k1 to most-recently-used; hits are promoted every
	// promoteEvery-th hit, so hit it that many times to guarantee promotion.
	for i := 0; i < promoteEvery; i++ {
		if _, ok := c.Get(Key{Name: "k1"}); !ok {
			t.Fatal("expected k1 hit")
		}
	}
	c.Set(Key{Name: "k3"}, mkMsg("c.test", 60)) // k2 is now LRU -> evicted
	if _, ok := c.Get(Key{Name: "k2"}); ok {
		t.Error("expected k2 to be evicted")
	}
	if _, ok := c.Get(Key{Name: "k1"}); !ok {
		t.Error("expected k1 to survive (it was used most recently)")
	}
	if _, ok := c.Get(Key{Name: "k3"}); !ok {
		t.Error("expected k3 present")
	}
	if c.Len() != 2 {
		t.Errorf("len = %d, want 2", c.Len())
	}
}

func TestSetPreservesHits(t *testing.T) {
	c := New(time.Hour, 0)
	k := KeyOf(mkMsg("a.test", 60))
	c.Set(k, mkMsg("a.test", 60))
	_, _ = c.Get(k)
	_, _ = c.Get(k)
	c.Set(k, mkMsg("a.test", 60)) // refresh, must keep hit count
	if got := c.items[k].hits.Load(); got != 2 {
		t.Errorf("expected refreshed entry to keep 2 hits, got %d", got)
	}
}

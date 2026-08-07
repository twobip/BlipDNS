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

func TestPurge(t *testing.T) {
	c := New(time.Hour, 0)
	c.Set(Key(mkMsg("a.test", 60)), mkMsg("a.test", 60))
	c.Set(Key(mkMsg("b.test", 60)), mkMsg("b.test", 60))
	if c.Len() != 2 {
		t.Fatalf("precondition: Len = %d, want 2", c.Len())
	}
	c.Purge()
	if c.Len() != 0 {
		t.Fatalf("Len after purge = %d, want 0", c.Len())
	}
	if _, ok := c.Get(Key(mkMsg("a.test", 60))); ok {
		t.Error("expected miss after purge")
	}
	// cache must remain usable after purge
	k := Key(mkMsg("a.test", 60))
	c.Set(k, mkMsg("a.test", 60))
	if _, ok := c.Get(k); !ok {
		t.Error("expected hit after re-insertion post-purge")
	}
}

func TestExpiry(t *testing.T) {
	c := New(time.Hour, 0)
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
			_, _ = c.Do(context.Background(), "k", fn)
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
	_, cached, err := c.DoHit(context.Background(), "k", fn)
	if err != nil || cached {
		t.Errorf("first DoHit: cached=%v err=%v, want miss", cached, err)
	}
	// Second call must be served from cache.
	_, cached, err = c.DoHit(context.Background(), "k", fn)
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
			_, cached, _ := c.DoHit(context.Background(), "k", fn)
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
	c.Set("k1", mkMsg("a.test", 60))
	c.Set("k2", mkMsg("b.test", 60))
	// promote k1 to most-recently-used
	if _, ok := c.Get("k1"); !ok {
		t.Fatal("expected k1 hit")
	}
	c.Set("k3", mkMsg("c.test", 60)) // k2 is now LRU -> evicted
	if _, ok := c.Get("k2"); ok {
		t.Error("expected k2 to be evicted")
	}
	if _, ok := c.Get("k1"); !ok {
		t.Error("expected k1 to survive (it was used most recently)")
	}
	if _, ok := c.Get("k3"); !ok {
		t.Error("expected k3 present")
	}
	if c.Len() != 2 {
		t.Errorf("len = %d, want 2", c.Len())
	}
}

func TestSetPreservesHits(t *testing.T) {
	c := New(time.Hour, 0)
	k := Key(mkMsg("a.test", 60))
	c.Set(k, mkMsg("a.test", 60))
	_, _ = c.Get(k)
	_, _ = c.Get(k)
	c.Set(k, mkMsg("a.test", 60)) // refresh, must keep hit count
	if got := c.Popular(0); len(got) != 1 || c.items[k].hits != 2 {
		t.Errorf("expected refreshed entry to keep 2 hits, got %d", c.items[k].hits)
	}
}

func TestPopularOrdering(t *testing.T) {
	c := New(time.Hour, 0)
	c.Set("k1", mkMsg("a.test", 60))
	c.Set("k2", mkMsg("b.test", 60))
	c.Set("k3", mkMsg("c.test", 60))
	_, _ = c.Get("k1")
	_, _ = c.Get("k1")
	_, _ = c.Get("k1")
	_, _ = c.Get("k2")
	got := c.Popular(2)
	if len(got) != 2 || got[0] != "k1" || got[1] != "k2" {
		t.Errorf("expected [k1 k2], got %v", got)
	}
}

func TestStaleLookahead(t *testing.T) {
	c := New(time.Hour, 0)
	c.now = func() time.Time { return time.Unix(1000, 0) }
	k := Key(mkMsg("a.test", 5)) // expires at 1005
	c.Set(k, mkMsg("a.test", 5))
	if c.Stale(k, time.Second) {
		t.Error("not stale yet: 4s left, lookahead 1s")
	}
	if !c.Stale(k, 10*time.Second) {
		t.Error("should be stale: 4s left, lookahead 10s")
	}
	c.now = func() time.Time { return time.Unix(1010, 0) } // expired
	if !c.Stale(k, 0) {
		t.Error("should be stale once expired")
	}
	if c.Stale("missing", 0) {
		t.Error("missing key is not stale")
	}
}

func TestParseKey(t *testing.T) {
	name, qtype, qclass, ok := ParseKey("example.com.|1|1")
	if !ok || name != "example.com." || qtype != dns.TypeA || qclass != dns.ClassINET {
		t.Errorf("bad ParseKey result: %q %d %d %v", name, qtype, qclass, ok)
	}
	if _, _, _, ok := ParseKey("garbage"); ok {
		t.Error("expected parse failure on malformed key")
	}
}

func TestTwoTierHold(t *testing.T) {
	c := New(time.Hour, 0)
	c.SetHold(2, time.Hour) // keep top-2 at record TTL, everyone else 1h
	c.now = func() time.Time { return time.Unix(1000, 0) }

	// Seed some entries with record TTL 5s.
	for _, n := range []string{"a.test", "b.test", "c.test", "d.test"} {
		c.Set(Key(mkMsg(n, 5)), mkMsg(n, 5))
	}
	// Make a and b clearly more popular than the rest (2 >= warm=2 higher-hit
	// entries), so they rank in the top tier.
	for i := 0; i < 5; i++ {
		_, _ = c.Get(Key(mkMsg("a.test", 5)))
		_, _ = c.Get(Key(mkMsg("b.test", 5)))
	}
	// Re-set a low-hit entry now that 2 others are more popular: it must fall
	// into the regular-hold tier (1h), not its record TTL.
	c.Set(Key(mkMsg("e.test", 5)), mkMsg("e.test", 5))

	// 20s later: past every record TTL (5s).
	c.now = func() time.Time { return time.Unix(1020, 0) }

	// The non-top entry e stays cached for regularHold (may serve stale).
	if _, ok := c.Get(Key(mkMsg("e.test", 5))); !ok {
		t.Error("non-top entry should still be cached within regularHold")
	}
	// Top entries a,b expire at their own record TTL.
	if _, ok := c.Get(Key(mkMsg("a.test", 5))); ok {
		t.Error("top-2 entry should expire at its record TTL")
	}
	if _, ok := c.Get(Key(mkMsg("b.test", 5))); ok {
		t.Error("top-2 entry should expire at its record TTL")
	}
}

func TestTwoTierDefaultUsesRecordTTL(t *testing.T) {
	c := New(time.Hour, 0)
	c.SetHold(0, 0) // two-tier off -> record TTL everywhere
	c.now = func() time.Time { return time.Unix(1000, 0) }
	c.Set(Key(mkMsg("a.test", 5)), mkMsg("a.test", 5))
	c.now = func() time.Time { return time.Unix(1006, 0) }
	if _, ok := c.Get(Key(mkMsg("a.test", 5))); ok {
		t.Error("without regularHold, entry should expire at its record TTL")
	}
}

func TestServeTTLCappedAtSource(t *testing.T) {
	c := New(time.Hour, 0)
	c.SetHold(0, time.Hour) // non-top held 1h but source TTL is 60s
	c.Set(Key(mkMsg("a.test", 60)), mkMsg("a.test", 60))
	got, ok := c.Get(Key(mkMsg("a.test", 60)))
	if !ok {
		t.Fatal("expected hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 60 {
		t.Errorf("served TTL %d should not exceed source TTL 60", ttl)
	}
}

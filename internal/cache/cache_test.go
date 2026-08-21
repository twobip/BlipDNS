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

// testKey builds a cache key for an A/IN query for name.
func testKey(name string) Key {
	return Key{Name: dns.Fqdn(name), QType: dns.TypeA, QClass: dns.ClassINET}
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
	// inject an entry expiring at 1010
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
			_, _ = c.Do(context.Background(), testKey("a.test."), fn)
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
	_, cached, err := c.DoHit(context.Background(), testKey("a.test."), fn)
	if err != nil || cached {
		t.Errorf("first DoHit: cached=%v err=%v, want miss", cached, err)
	}
	// Second call must be served from cache.
	_, cached, err = c.DoHit(context.Background(), testKey("a.test."), fn)
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
			_, cached, _ := c.DoHit(context.Background(), testKey("a.test."), fn)
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
	c.Set(testKey("a.test."), mkMsg("a.test", 60))
	c.Set(testKey("b.test."), mkMsg("b.test", 60))
	// promote k1 to most-recently-used; hits are promoted every
	// promoteEvery-th hit, so hit it that many times to guarantee promotion.
	for i := 0; i < promoteEvery; i++ {
		if _, ok := c.Get(testKey("a.test.")); !ok {
			t.Fatal("expected k1 hit")
		}
	}
	c.Set(testKey("c.test."), mkMsg("c.test", 60)) // b.test. is now LRU -> evicted
	if _, ok := c.Get(testKey("b.test.")); ok {
		t.Error("expected k2 to be evicted")
	}
	if _, ok := c.Get(testKey("a.test.")); !ok {
		t.Error("expected k1 to survive (it was used most recently)")
	}
	if _, ok := c.Get(testKey("c.test.")); !ok {
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
	if got := c.Popular(0); len(got) != 1 || c.items[k].hits.Load() != 2 {
		t.Errorf("expected refreshed entry to keep 2 hits, got %d", c.items[k].hits.Load())
	}
}

func TestPopularOrdering(t *testing.T) {
	c := New(time.Hour, 0)
	c.Set(testKey("a.test."), mkMsg("a.test", 60))
	c.Set(testKey("b.test."), mkMsg("b.test", 60))
	c.Set(testKey("c.test."), mkMsg("c.test", 60))
	_, _ = c.Get(testKey("a.test."))
	_, _ = c.Get(testKey("a.test."))
	_, _ = c.Get(testKey("a.test."))
	_, _ = c.Get(testKey("b.test."))
	got := c.Popular(2)
	wantA, wantB := testKey("a.test."), testKey("b.test.")
	if len(got) != 2 || got[0] != wantA || got[1] != wantB {
		t.Errorf("expected [a.test. b.test.], got %v %v", got[0], got[1])
	}
}

func TestStaleLookahead(t *testing.T) {
	c := New(time.Hour, 0)
	c.now = func() time.Time { return time.Unix(1000, 0) }
	k := KeyOf(mkMsg("a.test", 5)) // expires at 1005
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
	if c.Stale(testKey("missing."), 0) {
		t.Error("missing key is not stale")
	}
}

func TestTwoTierHold(t *testing.T) {
	c := New(time.Hour, 0)
	c.SetHold(2, time.Hour) // keep top-2 at record TTL, everyone else 1h
	c.now = func() time.Time { return time.Unix(1000, 0) }

	// Seed some entries with record TTL 5s.
	for _, n := range []string{"a.test.", "b.test.", "c.test.", "d.test."} {
		c.Set(testKey(n), mkMsg(n, 5))
	}
	// Make a and b clearly more popular than the rest (2 >= warm=2 higher-hit
	// entries), so they rank in the top tier.
	for i := 0; i < 5; i++ {
		_, _ = c.Get(testKey("a.test."))
		_, _ = c.Get(testKey("b.test."))
	}
	// Re-set a low-hit entry now that 2 others are more popular: it must fall
	// into the regular-hold tier (1h), not its record TTL.
	c.Set(testKey("e.test."), mkMsg("e.test", 5))

	// 20s later: past every record TTL (5s).
	c.now = func() time.Time { return time.Unix(1020, 0) }

	// The non-top entry e stays cached for regularHold (may serve stale).
	if _, ok := c.Get(testKey("e.test.")); !ok {
		t.Error("non-top entry should still be cached within regularHold")
	}
	// Top entries a,b expire at their own record TTL.
	if _, ok := c.Get(testKey("a.test.")); ok {
		t.Error("top-2 entry should expire at its record TTL")
	}
	if _, ok := c.Get(testKey("b.test.")); ok {
		t.Error("top-2 entry should expire at its record TTL")
	}
}

func TestTwoTierDefaultUsesRecordTTL(t *testing.T) {
	c := New(time.Hour, 0)
	c.SetHold(0, 0) // two-tier off -> record TTL everywhere
	c.now = func() time.Time { return time.Unix(1000, 0) }
	c.Set(testKey("a.test."), mkMsg("a.test", 5))
	c.now = func() time.Time { return time.Unix(1006, 0) }
	if _, ok := c.Get(testKey("a.test.")); ok {
		t.Error("without regularHold, entry should expire at its record TTL")
	}
}

func TestServeTTLCappedAtSource(t *testing.T) {
	c := New(time.Hour, 0)
	c.SetHold(0, time.Hour) // non-top held 1h but source TTL is 60s
	c.Set(testKey("a.test."), mkMsg("a.test", 60))
	got, ok := c.Get(testKey("a.test."))
	if !ok {
		t.Fatal("expected hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 60 {
		t.Errorf("served TTL %d should not exceed source TTL 60", ttl)
	}
}

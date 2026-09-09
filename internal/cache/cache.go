// Package cache provides a TTL-aware DNS response cache with request
// coalescing (singleflight) to suppress cache stampedes. The cache is
// size-bounded (LRU eviction). Entries expire at their record TTL, capped
// by the configured maximum — the cache never serves records past the TTL
// their owner published.
package cache

import (
	"container/list"
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// promoteEvery controls how often a cache hit promotes its entry to the front
// of the LRU. Promoting on every hit would force every concurrent reader to
// take the exclusive lock (list mutation is not safe under RLock); promoting
// on 1-in-N hits keeps an approximate-LRU ordering while the common hit path
// stays entirely on shared locks + atomics.
const promoteEvery = 16

type entry struct {
	key    string
	msg    *dns.Msg
	expire time.Time
	hits   atomic.Uint64
	elem   *list.Element
}

// Cache stores DNS responses keyed by (name, type, class). When maxEntries
// is exceeded the least-recently-used entry is evicted. Each entry records
// how often it has been served (hits) to drive approximate-LRU promotion.
type Cache struct {
	mu         sync.RWMutex
	items      map[string]*entry
	lru        *list.List
	ttlCap     time.Duration
	maxEntries int
	group      singleflight.Group
	now        func() time.Time
}

// New creates a Cache. ttlCap is the maximum time a response may be cached
// regardless of its record TTL. maxEntries bounds the number of cached
// responses in memory; 0 disables the limit (entries are then dropped only
// on expiry).
func New(ttlCap time.Duration, maxEntries int) *Cache {
	if ttlCap <= 0 {
		ttlCap = time.Hour
	}
	return &Cache{
		items:      make(map[string]*entry),
		lru:        list.New(),
		ttlCap:     ttlCap,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// Key returns a stable cache key for the first question of m.
func Key(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return ""
	}
	q := m.Question[0]
	return q.Name + "|" + strconv.Itoa(int(q.Qtype)) + "|" + strconv.Itoa(int(q.Qclass))
}

func minTTL(m *dns.Msg) time.Duration {
	min := uint32(0)
	seen := false
	for _, rr := range m.Answer {
		t := rr.Header().Ttl
		if !seen || t < min {
			min = t
			seen = true
		}
	}
	for _, rr := range m.Ns {
		t := rr.Header().Ttl
		if !seen || t < min {
			min = t
			seen = true
		}
	}
	if !seen {
		return 30 * time.Second
	}
	if min < 1 {
		min = 1
	}
	return time.Duration(min) * time.Second
}

// Get returns a fresh copy of a cached response with decremented TTLs, or
// (nil, false) on miss/expiry. A hit bumps the entry's popularity count and
// (every promoteEvery-th hit) marks it most-recently-used so it survives LRU
// eviction.
//
// The entire hit path runs on the shared lock: the lookup and expiry check
// take c.mu.RLock, the popularity bump is an atomic add, and LRU promotion is
// skipped for all but every promoteEvery-th hit. Only expiry cleanup and the
// occasional promotion take the exclusive lock. The message Copy happens
// outside the lock so a slow Copy can't block other readers or writers.
func (c *Cache) Get(k string) (*dns.Msg, bool) {
	if k == "" {
		return nil, false
	}
	c.mu.RLock()
	e, ok := c.items[k]
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}
	now := c.now()
	if now.After(e.expire) {
		c.mu.RUnlock()
		// Expired: take the exclusive lock to delete it (or use a value a
		// concurrent Set refreshed in the meantime).
		c.mu.Lock()
		var fresh *entry
		if e2, ok2 := c.items[k]; ok2 && !c.now().After(e2.expire) {
			fresh = e2
		}
		if fresh != nil {
			e = fresh
			now = c.now()
			c.mu.Unlock()
			goto copy
		}
		if e2, ok2 := c.items[k]; ok2 {
			delete(c.items, k)
			c.lru.Remove(e2.elem)
		}
		c.mu.Unlock()
		return nil, false
	}
	e.hits.Add(1)
	// Approximate LRU: promote only every promoteEvery-th hit. The counter is
	// per-entry, so promotion is probabilistic under concurrency — good
	// enough to keep hot entries at the front without exclusive locking.
	if e.hits.Load()%promoteEvery == 0 {
		c.mu.RUnlock()
		c.mu.Lock()
		// Re-check: the entry may have been evicted or replaced meanwhile.
		if e2, ok2 := c.items[k]; ok2 && e2 == e {
			c.lru.MoveToFront(e.elem)
		}
		c.mu.Unlock()
	} else {
		c.mu.RUnlock()
	}

copy:
	remaining := e.expire.Sub(now)
	ttl := uint32(remaining.Seconds())
	if ttl < 1 {
		ttl = 1
	}
	out := e.msg.Copy()
	for _, rr := range out.Answer {
		rr.Header().Ttl = ttl
	}
	return out, true
}

// Set stores a response for its record TTL (capped at ttlCap), evicting the
// least-recently-used entry if the cache is over its size limit. Setting an
// existing key refreshes its value and TTL but preserves its hit count.
func (c *Cache) Set(k string, m *dns.Msg) {
	if k == "" || m == nil {
		return
	}
	now := c.now()
	ttl := minTTL(m)
	if ttl > c.ttlCap {
		ttl = c.ttlCap
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		e.msg = m.Copy()
		e.expire = now.Add(ttl)
		c.lru.MoveToFront(e.elem)
		return
	}
	e := &entry{key: k, msg: m.Copy()}
	e.expire = now.Add(ttl)
	e.elem = c.lru.PushFront(e)
	c.items[k] = e
	c.evictLocked()
}

func (c *Cache) evictLocked() {
	for c.maxEntries > 0 && c.lru.Len() > c.maxEntries {
		last := c.lru.Back()
		if last == nil {
			return
		}
		e := last.Value.(*entry)
		delete(c.items, e.key)
		c.lru.Remove(last)
	}
}

// SetMaxEntries adjusts the in-memory size limit at runtime (0 = unlimited).
// The cache is trimmed immediately if the new limit is below the current size.
// This lets the controller tune the cache without a blipd restart.
func (c *Cache) SetMaxEntries(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n < 0 {
		n = 0
	}
	c.maxEntries = n
	c.evictLocked()
}

// Do returns a cached response if present, otherwise runs fn (coalescing
// concurrent identical requests) and caches the result.
func (c *Cache) Do(ctx context.Context, k string, fn func() (*dns.Msg, error)) (*dns.Msg, error) {
	m, _, err := c.DoHit(ctx, k, fn)
	return m, err
}

// DoHit is like Do but also reports whether the response was served from a
// cache hit rather than fetched just now. Requests coalesced behind a
// concurrent identical fetch count as cache hits: they were answered from
// in-memory state (the in-flight singleflight result) without a fresh
// upstream round trip.
func (c *Cache) DoHit(ctx context.Context, k string, fn func() (*dns.Msg, error)) (*dns.Msg, bool, error) {
	if m, ok := c.Get(k); ok {
		return m, true, nil
	}
	v, err, shared := c.group.Do(k, func() (interface{}, error) {
		m, ferr := fn()
		if ferr != nil {
			return nil, ferr
		}
		c.Set(k, m)
		return m, nil
	})
	if err != nil {
		return nil, false, err
	}
	m := v.(*dns.Msg)
	if shared {
		// Coalesced callers share one result pointer; serve() mutates the
		// returned message (Id, Question), so give each sharer its own copy
		// instead of racing on a shared one. The cache stored its own copy
		// in Set, so this does not touch cached state.
		m = m.Copy()
	}
	return m, shared, nil
}

// Purge drops every cached response. It is used when the blocklist changes so
// answers cached while a domain was allowed are not served after it is (re)
// blocked, and vice versa.
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*entry)
	c.lru.Init()
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

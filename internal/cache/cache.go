// Package cache provides a TTL-aware DNS response cache with request
// coalescing (singleflight) to suppress cache stampedes. The cache is
// size-bounded (LRU eviction) and tracks how often each response is served
// so the most popular entries can be refreshed before they go stale.
package cache

import (
	"container/list"
	"context"
	"sort"
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

// Key identifies a cached response by (name, qtype, qclass). It is a
// comparable struct so it can be used directly as a map key: building it
// allocates nothing (unlike a formatted string) and lookups hash a few fixed
// words instead of re-hashing the whole encoded name on every query.
type Key struct {
	Name   string // FQDN, exactly as queried (case preserved)
	QType  uint16
	QClass uint16
}

// KeyOf returns the cache key for the first question of m.
func KeyOf(m *dns.Msg) Key {
	if len(m.Question) == 0 {
		return Key{}
	}
	q := m.Question[0]
	return Key{Name: q.Name, QType: q.Qtype, QClass: q.Qclass}
}

type entry struct {
	key    Key
	msg    *dns.Msg
	expire time.Time
	hits   atomic.Uint64
	elem   *list.Element
	srcTTL uint32 // source record min TTL in seconds (caps the TTL served)
}

// Cache stores DNS responses keyed by (name, type, class). When maxEntries
// is exceeded the least-recently-used entry is evicted. Each entry records
// the number of times it has been served (hits) for popularity tracking.
//
// Two-tier retention: the warmCount most-popular entries stay cached at their
// record TTL (so the controller's warm loop can auto-refresh them before they
// go stale), while every other entry is held for regularHold — a fixed
// duration, possibly longer than the record's own TTL (serving possibly-stale
// data). With regularHold == 0 every entry simply uses its record TTL.
type Cache struct {
	mu          sync.RWMutex
	items       map[Key]*entry
	lru         *list.List
	ttlCap      time.Duration
	maxEntries  int
	warmCount   int           // top-N most-popular entries kept at their record TTL
	regularHold time.Duration // how long non-top entries stay cached (0 = use record TTL)
	group       singleflight.Group
	now         func() time.Time
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
		items:      make(map[Key]*entry),
		lru:        list.New(),
		ttlCap:     ttlCap,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// SetHold tunes the two-tier cache retention at runtime: warm is the number
// of most-popular entries kept at their record TTL for auto-refresh (0 = off),
// and regular is how long every other entry stays cached (0 = use record TTL).
func (c *Cache) SetHold(warm int, regular time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if warm < 0 {
		warm = 0
	}
	if regular < 0 {
		regular = 0
	}
	c.warmCount = warm
	c.regularHold = regular
}

// String renders the key as "name|qtype|qclass". Not used on the cache read
// path — it exists for the singleflight coalescing key (string-keyed) and
// for logs.
func (k Key) String() string {
	return k.Name + "|" + strconv.Itoa(int(k.QType)) + "|" + strconv.Itoa(int(k.QClass))
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
func (c *Cache) Get(k Key) (*dns.Msg, bool) {
	if k.Name == "" {
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
	if h := e.hits.Load(); h%promoteEvery == 0 {
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
	if sTTL := e.srcTTL; sTTL > 0 && ttl > sTTL {
		ttl = sTTL
	}
	if ttl < 1 {
		ttl = 1
	}
	out := e.msg.Copy()
	for _, rr := range out.Answer {
		rr.Header().Ttl = ttl
	}
	return out, true
}

// Set stores a response, capping its lifetime at ttlCap and evicting the
// least-recently-used entry if the cache is over its size limit. Setting an
// existing key refreshes its value and TTL but preserves its hit count.
//
// The retention time depends on the two-tier configuration: if a non-zero
// regularHold is set, entries rank among the warmCount most-popular keep their
// record TTL while the rest are held for regularHold (possibly stale).
func (c *Cache) Set(k Key, m *dns.Msg) {
	if k.Name == "" || m == nil {
		return
	}
	now := c.now()
	srcTTL := uint32(minTTL(m).Seconds())
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		e.msg = m.Copy()
		e.srcTTL = srcTTL
		e.expire = now.Add(c.lifetimeForLocked(k, e.hits.Load(), srcTTL))
		c.lru.MoveToFront(e.elem)
		return
	}
	e := &entry{key: k, msg: m.Copy(), srcTTL: srcTTL}
	e.expire = now.Add(c.lifetimeForLocked(k, 0, srcTTL))
	e.elem = c.lru.PushFront(e)
	c.items[k] = e
	c.evictLocked()
}

// lifetimeForLocked returns how long the entry for k should be cached, given
// its current hit count and the source record's min TTL. Caller holds c.mu.
func (c *Cache) lifetimeForLocked(k Key, hits uint64, srcTTL uint32) time.Duration {
	dnsTTL := time.Duration(srcTTL) * time.Second
	if dnsTTL > c.ttlCap {
		dnsTTL = c.ttlCap
	}
	if c.regularHold <= 0 {
		return dnsTTL
	}
	if c.warmCount > 0 && c.isTopLocked(k, hits, c.warmCount) {
		return dnsTTL
	}
	return c.regularHold
}

// isTopLocked reports whether an entry with the given hit count ranks within
// the n most-popular cached entries. Caller holds c.mu.
func (c *Cache) isTopLocked(k Key, hits uint64, n int) bool {
	ahead := 0
	for key, other := range c.items {
		if key == k {
			continue
		}
		if other.hits.Load() > hits {
			ahead++
			if ahead >= n {
				return false
			}
		}
	}
	return true
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
func (c *Cache) Do(ctx context.Context, k Key, fn func() (*dns.Msg, error)) (*dns.Msg, error) {
	m, _, err := c.DoHit(ctx, k, fn)
	return m, err
}

// DoHit is like Do but also reports whether the response was served from a
// cache hit rather than fetched just now. Requests coalesced behind a
// concurrent identical fetch count as cache hits: they were answered from
// in-memory state (the in-flight singleflight result) without a fresh
// upstream round trip.
func (c *Cache) DoHit(ctx context.Context, k Key, fn func() (*dns.Msg, error)) (*dns.Msg, bool, error) {
	if m, ok := c.Get(k); ok {
		return m, true, nil
	}
	v, err, shared := c.group.Do(k.String(), func() (interface{}, error) {
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
	c.items = make(map[Key]*entry)
	c.lru.Init()
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lru.Len()
}

// Popular returns the keys of the n most-served cached responses, most
// popular first. Pass 0 or a negative n to get all keys.
func (c *Cache) Popular(n int) []Key {
	c.mu.RLock()
	type kv struct {
		k    Key
		hits uint64
	}
	pairs := make([]kv, 0, len(c.items))
	for k, e := range c.items {
		pairs = append(pairs, kv{k, e.hits.Load()})
	}
	c.mu.RUnlock()
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].hits > pairs[j].hits })
	if n > 0 && n < len(pairs) {
		pairs = pairs[:n]
	}
	keys := make([]Key, len(pairs))
	for i, p := range pairs {
		keys[i] = p.k
	}
	return keys
}

// Stale reports whether the entry for k is missing, already expired, or will
// expire within lookahead — i.e. it should be refreshed now. It does not
// count as a hit.
func (c *Cache) Stale(k Key, lookahead time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.items[k]
	if !ok {
		return false
	}
	return c.now().Add(lookahead).After(e.expire)
}

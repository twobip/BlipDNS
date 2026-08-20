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
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

type entry struct {
	key    string
	msg    *dns.Msg
	expire time.Time
	hits   uint64
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
	items       map[string]*entry
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
		items:      make(map[string]*entry),
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

// Key returns a stable cache key for the first question of m.
func Key(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return ""
	}
	q := m.Question[0]
	return q.Name + "|" + strconv.Itoa(int(q.Qtype)) + "|" + strconv.Itoa(int(q.Qclass))
}

// ParseKey reconstructs the (name, qtype, qclass) triple from a Key string.
func ParseKey(k string) (name string, qtype, qclass uint16, ok bool) {
	parts := strings.Split(k, "|")
	if len(parts) != 3 {
		return "", 0, 0, false
	}
	t, errT := strconv.ParseUint(parts[1], 10, 16)
	cl, errC := strconv.ParseUint(parts[2], 10, 16)
	if errT != nil || errC != nil {
		return "", 0, 0, false
	}
	return parts[0], uint16(t), uint16(cl), true
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
// marks it most-recently-used so it survives LRU eviction.
//
// The common hit path takes a shared lock first (to avoid blocking concurrent
// readers on the map lookup), then briefly escalates to an exclusive lock to
// bump the hit counter and move the entry to the front of the LRU. The actual
// message Copy happens outside the lock so a slow Copy can't block other
// readers or writers.
func (c *Cache) Get(k string) (*dns.Msg, bool) {
	if k == "" {
		return nil, false
	}
	// Fast path: shared lock for the lookup and expiry check.
	c.mu.RLock()
	e, ok := c.items[k]
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}
	now := c.now()
	if now.After(e.expire) {
		c.mu.RUnlock()
		// Expired: escalate to exclusive lock to delete it.
		c.mu.Lock()
		// Re-check: a concurrent Set may have refreshed it.
		var fresh *entry
		if e2, ok2 := c.items[k]; ok2 && !c.now().After(e2.expire) {
			// Refreshed by a concurrent Set; use the fresh entry.
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
	c.mu.RUnlock()

	// Common hit path: escalate to exclusive lock for the mutations.
	c.mu.Lock()
	// Re-check existence: a concurrent Purge may have removed it.
	if _, ok := c.items[k]; !ok {
		c.mu.Unlock()
		return nil, false
	}
	e.hits++
	c.lru.MoveToFront(e.elem)
	c.mu.Unlock()

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
func (c *Cache) Set(k string, m *dns.Msg) {
	if k == "" || m == nil {
		return
	}
	now := c.now()
	srcTTL := uint32(minTTL(m).Seconds())
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		e.msg = m.Copy()
		e.srcTTL = srcTTL
		e.expire = now.Add(c.lifetimeForLocked(k, e.hits, srcTTL))
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
func (c *Cache) lifetimeForLocked(k string, hits uint64, srcTTL uint32) time.Duration {
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
func (c *Cache) isTopLocked(k string, hits uint64, n int) bool {
	ahead := 0
	for key, other := range c.items {
		if key == k {
			continue
		}
		if other.hits > hits {
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
	return v.(*dns.Msg), shared, nil
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
	return c.lru.Len()
}

// Popular returns the keys of the n most-served cached responses, most
// popular first. Pass 0 or a negative n to get all keys.
func (c *Cache) Popular(n int) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make([]string, 0, len(c.items))
	for k := range c.items {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return c.items[keys[i]].hits > c.items[keys[j]].hits
	})
	if n > 0 && n < len(keys) {
		keys = keys[:n]
	}
	return keys
}

// Stale reports whether the entry for k is missing, already expired, or will
// expire within lookahead — i.e. it should be refreshed now. It does not
// count as a hit.
func (c *Cache) Stale(k string, lookahead time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.items[k]
	if !ok {
		return false
	}
	return c.now().Add(lookahead).After(e.expire)
}

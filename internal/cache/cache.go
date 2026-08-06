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
}

// Cache stores DNS responses keyed by (name, type, class). When maxEntries
// is exceeded the least-recently-used entry is evicted. Each entry records
// the number of times it has been served (hits) for popularity tracking.
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
func (c *Cache) Get(k string) (*dns.Msg, bool) {
	if k == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[k]
	if !ok {
		return nil, false
	}
	now := c.now()
	if now.After(e.expire) {
		delete(c.items, k)
		c.lru.Remove(e.elem)
		return nil, false
	}
	e.hits++
	c.lru.MoveToFront(e.elem)
	remaining := e.expire.Sub(now)
	out := e.msg.Copy()
	for _, rr := range out.Answer {
		ttl := uint32(remaining.Seconds())
		if ttl < 1 {
			ttl = 1
		}
		rr.Header().Ttl = ttl
	}
	return out, true
}

// Set stores a response, capping its lifetime at ttlCap and evicting the
// least-recently-used entry if the cache is over its size limit. Setting an
// existing key refreshes its value and TTL but preserves its hit count.
func (c *Cache) Set(k string, m *dns.Msg) {
	if k == "" || m == nil {
		return
	}
	ttl := minTTL(m)
	if ttl > c.ttlCap {
		ttl = c.ttlCap
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if e, ok := c.items[k]; ok {
		e.msg = m.Copy()
		e.expire = now.Add(ttl)
		c.lru.MoveToFront(e.elem)
		return
	}
	e := &entry{key: k, msg: m.Copy(), expire: now.Add(ttl)}
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

// Do returns a cached response if present, otherwise runs fn (coalescing
// concurrent identical requests) and caches the result.
func (c *Cache) Do(ctx context.Context, k string, fn func() (*dns.Msg, error)) (*dns.Msg, error) {
	if m, ok := c.Get(k); ok {
		return m, nil
	}
	v, err, _ := c.group.Do(k, func() (interface{}, error) {
		m, ferr := fn()
		if ferr != nil {
			return nil, ferr
		}
		c.Set(k, m)
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*dns.Msg), nil
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

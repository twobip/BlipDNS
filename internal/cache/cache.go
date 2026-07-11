// Package cache provides a TTL-aware DNS response cache with request
// coalescing (singleflight) to suppress cache stampedes.
package cache

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

type entry struct {
	msg    *dns.Msg
	expire time.Time
}

// Cache stores DNS responses keyed by (name, type, class).
type Cache struct {
	mu      sync.RWMutex
	items   map[string]entry
	ttlCap  time.Duration
	group   singleflight.Group
	now     func() time.Time
}

// New creates a Cache. ttlCap is the maximum time a response may be cached
// regardless of its record TTL.
func New(ttlCap time.Duration) *Cache {
	if ttlCap <= 0 {
		ttlCap = time.Hour
	}
	return &Cache{
		items:  make(map[string]entry),
		ttlCap: ttlCap,
		now:    time.Now,
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
// (nil, false) on miss/expiry.
func (c *Cache) Get(k string) (*dns.Msg, bool) {
	if k == "" {
		return nil, false
	}
	c.mu.RLock()
	e, ok := c.items[k]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	now := c.now()
	if now.After(e.expire) {
		return nil, false
	}
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

// Set stores a response, capping its lifetime at ttlCap.
func (c *Cache) Set(k string, m *dns.Msg) {
	if k == "" || m == nil {
		return
	}
	ttl := minTTL(m)
	if ttl > c.ttlCap {
		ttl = c.ttlCap
	}
	c.mu.Lock()
	c.items[k] = entry{msg: m.Copy(), expire: c.now().Add(ttl)}
	c.mu.Unlock()
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

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

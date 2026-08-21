package control

import (
	"sync"
	"sync/atomic"
	"time"
)

// Counters tracks server metrics. The scalar counters are atomics so the
// per-query hot path never contends on a mutex; only the (optional)
// per-client map takes the lock.
type Counters struct {
	mu          sync.Mutex // guards perClient only
	perClient   map[string]uint64
	queries     atomic.Uint64
	blocked     atomic.Uint64
	upErr       atomic.Uint64
	rateLimited atomic.Uint64
}

// AddQuery records a query from a client.
func (c *Counters) AddQuery(client ...string) {
	if c == nil {
		return
	}
	c.queries.Add(1)
	if len(client) > 0 && client[0] != "" {
		c.mu.Lock()
		if c.perClient == nil {
			c.perClient = make(map[string]uint64)
		}
		c.perClient[client[0]]++
		c.mu.Unlock()
	}
}

// AddBlocked records a blocked query.
func (c *Counters) AddBlocked() {
	if c == nil {
		return
	}
	c.blocked.Add(1)
}

// AddUpErr records an upstream failure.
func (c *Counters) AddUpErr() {
	if c == nil {
		return
	}
	c.upErr.Add(1)
}

// AddRateLimited records a query dropped for exceeding the per-client limit.
func (c *Counters) AddRateLimited() {
	if c == nil {
		return
	}
	c.rateLimited.Add(1)
}

// RateLimited returns the count of queries dropped for rate limiting.
func (c *Counters) RateLimited() uint64 {
	if c == nil {
		return 0
	}
	return c.rateLimited.Load()
}

// Stats returns a snapshot for the management API.
func (c *Counters) Stats() *StatsResponse {
	c.mu.Lock()
	per := make(map[string]uint64, len(c.perClient))
	for k, v := range c.perClient {
		per[k] = v
	}
	c.mu.Unlock()
	return &StatsResponse{
		Cached:       0, // filled by caller (cache length)
		QueriesTotal: c.queries.Load(),
		BlockedTotal: c.blocked.Load(),
		UpstreamErr:  c.upErr.Load(),
		RateLimited:  c.rateLimited.Load(),
		PerClient:    per,
	}
}

// SetToken enables authentication with the given bearer token.
func (s *Server) SetToken(tok string) {
	s.mu.Lock()
	s.token = tok
	s.mu.Unlock()
}

var _ = time.Now

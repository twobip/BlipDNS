package control

import "sync/atomic"

// Counters tracks server metrics. Every counter is an atomic so the per-query
// hot path never contends on a mutex.
type Counters struct {
	queries     atomic.Uint64
	blocked     atomic.Uint64
	upErr       atomic.Uint64
	rateLimited atomic.Uint64
}

// AddQuery records a query.
func (c *Counters) AddQuery() {
	if c == nil {
		return
	}
	c.queries.Add(1)
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
	return &StatsResponse{
		Cached:       0, // filled by caller (cache length)
		QueriesTotal: c.queries.Load(),
		BlockedTotal: c.blocked.Load(),
		UpstreamErr:  c.upErr.Load(),
		RateLimited:  c.rateLimited.Load(),
	}
}

// SetToken enables authentication with the given bearer token.
func (s *Server) SetToken(tok string) {
	s.mu.Lock()
	s.token = tok
	s.mu.Unlock()
}

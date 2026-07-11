package control

import (
	"sync"
	"time"
)

// Counters tracks server metrics and implements StatsCollector.
type Counters struct {
	mu         sync.Mutex
	queries    uint64
	blocked    uint64
	upErr      uint64
	perClient  map[string]uint64
}

// AddQuery records a query from a client.
func (c *Counters) AddQuery(client ...string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.queries++
	if len(client) > 0 && client[0] != "" {
		if c.perClient == nil {
			c.perClient = make(map[string]uint64)
		}
		c.perClient[client[0]]++
	}
	c.mu.Unlock()
}

// AddBlocked records a blocked query.
func (c *Counters) AddBlocked() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.blocked++
	c.mu.Unlock()
}

// AddUpErr records an upstream failure.
func (c *Counters) AddUpErr() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.upErr++
	c.mu.Unlock()
}

// Stats returns a snapshot for the management API.
func (c *Counters) Stats() *StatsResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	per := make(map[string]uint64, len(c.perClient))
	for k, v := range c.perClient {
		per[k] = v
	}
	return &StatsResponse{
		Cached:       0, // filled by caller (cache length)
		QueriesTotal: c.queries,
		BlockedTotal: c.blocked,
		UpstreamErr:  c.upErr,
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

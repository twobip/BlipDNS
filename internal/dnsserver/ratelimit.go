package dnsserver

import (
	"sync"
	"sync/atomic"
	"time"
)

// tokenBucket is a simple per-client token bucket (leaky refill). It is NOT a
// general-purpose limiter — it exists so blipd can shed abusive clients at the
// DNS layer, configurable live by the controller.
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter enforces a per-client QPS limit. A qps of 0 disables limiting.
// Clients are keyed by their identity (DoH client-id if present, else IP).
// Buckets are evicted after they go idle to bound memory against spoofed/
// rotating source IPs.
type rateLimiter struct {
	mu      sync.Mutex
	qpsVal  float64 // 0 = disabled
	burst   int
	buckets map[string]*tokenBucket
	maxLive int // cap on tracked clients to avoid memory exhaustion

	// off mirrors qpsVal == 0 as an atomic so the (default) unlimited case
	// never takes mu on the per-query hot path.
	off atomic.Bool
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{maxLive: 1 << 14}
}

// set updates the limit. A non-positive burst defaults to qps (min 1) so a
// single query is never denied. Existing buckets are reset so the new rate
// takes effect immediately.
func (rl *rateLimiter) set(qps int, burst int) {
	if qps < 0 {
		qps = 0
	}
	if burst <= 0 {
		burst = qps
		if burst < 1 {
			burst = 1
		}
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.qpsVal = float64(qps)
	rl.burst = burst
	rl.buckets = make(map[string]*tokenBucket)
	rl.off.Store(qps == 0)
}

// qps returns the current per-client QPS limit (0 = disabled).
func (rl *rateLimiter) qps() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return int(rl.qpsVal)
}

// allow reports whether a query from client may proceed, refilling its bucket.
func (rl *rateLimiter) allow(client string) bool {
	if client == "" || rl.off.Load() {
		return true // disabled (atomic fast path: no lock when unlimited)
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.qpsVal <= 0 {
		return true // disabled (set() may have flipped it between the load and here)
	}
	now := time.Now()
	b, ok := rl.buckets[client]
	if !ok {
		// bound tracked clients; if saturated, allow (fail-open) rather than DoS.
		if len(rl.buckets) >= rl.maxLive {
			// evict an idle entry to make room
			for k, v := range rl.buckets {
				if now.Sub(v.last) > time.Minute {
					delete(rl.buckets, k)
					break
				}
			}
			if len(rl.buckets) >= rl.maxLive {
				return true
			}
		}
		b = &tokenBucket{tokens: float64(rl.burst), last: now}
		rl.buckets[client] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * rl.qpsVal
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

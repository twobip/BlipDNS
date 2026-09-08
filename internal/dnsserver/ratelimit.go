package dnsserver

import (
	"hash/fnv"
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

// rlShards splits the bucket map so concurrent queries from different clients
// don't serialize on one mutex. 16 shards is plenty: beyond that the per-
// query FNV hash costs more than the contention it removes.
// ponytail: fixed shard count; grow only if profiles show shard collisions.
const rlShards = 16

// maxLiveClients caps tracked clients per limiter to avoid memory exhaustion
// against spoofed/rotating source IPs.
const maxLiveClients = 1 << 14

type rlShard struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

// rateLimiter enforces a per-client QPS limit. A qps of 0 disables limiting.
// Clients are keyed by their identity (DoH client-id if present, else IP).
// Buckets are evicted after they go idle to bound memory against spoofed/
// rotating source IPs.
type rateLimiter struct {
	qpsVal   atomic.Int64 // 0 = disabled
	burstVal atomic.Int64
	shards   [rlShards]rlShard

	// off mirrors qps == 0 as an atomic so the (default) unlimited case
	// never takes a lock on the per-query hot path.
	off atomic.Bool
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{}
	for i := range rl.shards {
		rl.shards[i].buckets = make(map[string]*tokenBucket)
	}
	return rl
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
	rl.qpsVal.Store(int64(qps))
	rl.burstVal.Store(int64(burst))
	for i := range rl.shards {
		sh := &rl.shards[i]
		sh.mu.Lock()
		sh.buckets = make(map[string]*tokenBucket)
		sh.mu.Unlock()
	}
	rl.off.Store(qps == 0)
}

// qps returns the current per-client QPS limit (0 = disabled).
func (rl *rateLimiter) qps() int {
	return int(rl.qpsVal.Load())
}

func rlShardFor(client string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(client))
	return int(h.Sum32() & (rlShards - 1))
}

// allow reports whether a query from client may proceed, refilling its bucket.
func (rl *rateLimiter) allow(client string) bool {
	if client == "" || rl.off.Load() {
		return true // disabled (atomic fast path: no lock when unlimited)
	}
	qps := float64(rl.qpsVal.Load())
	burst := int(rl.burstVal.Load())
	if qps <= 0 {
		return true // set() flipped it between the load and here
	}
	sh := &rl.shards[rlShardFor(client)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := time.Now()
	b, ok := sh.buckets[client]
	if !ok {
		// bound tracked clients; if saturated, allow (fail-open) rather than DoS.
		if len(sh.buckets) >= maxLiveClients/rlShards {
			// evict an idle entry to make room
			for k, v := range sh.buckets {
				if now.Sub(v.last) > time.Minute {
					delete(sh.buckets, k)
					break
				}
			}
			if len(sh.buckets) >= maxLiveClients/rlShards {
				return true
			}
		}
		b = &tokenBucket{tokens: float64(burst), last: now}
		sh.buckets[client] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * qps
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

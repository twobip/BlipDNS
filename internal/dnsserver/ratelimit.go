package dnsserver

import (
	"net"
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

// rlIdleEvict is how idle a bucket must be before it becomes an eviction
// victim when the table is saturated. Fail-closed under an active spoof flood
// (fresh buckets keep the table full), but once the flood stops the oldest
// entries age out and legitimate new clients are admitted again — without
// this a transient flood would deny new clients forever until the next
// SetRateLimit push reset the table.
const rlIdleEvict = 60 * time.Second

type rlShard struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

// rateLimiter enforces a per-client QPS limit. A qps of 0 disables limiting.
// Clients are keyed by their source IP (post trusted-proxy resolution), never
// by the self-asserted DoH client-id: an attacker could rotate the id to mint
// fresh buckets. When the table saturates, idle buckets (no query for
// rlIdleEvict) are evicted to admit new clients; when every bucket is fresh
// the limiter fails closed (denies) rather than evict-then-admit, so an
// attacker rotating source IPs gets no free pass. set() resets all buckets.
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
// takes effect immediately. Fresh maps are allocated before locking so the
// fleet-push path never stalls queries across 16 sequential allocations.
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
	fresh := make([]map[string]*tokenBucket, rlShards)
	for i := range fresh {
		fresh[i] = make(map[string]*tokenBucket)
	}
	for i := range rl.shards {
		sh := &rl.shards[i]
		sh.mu.Lock()
		sh.buckets = fresh[i]
		sh.mu.Unlock()
	}
	rl.qpsVal.Store(int64(qps))
	rl.burstVal.Store(int64(burst))
	rl.off.Store(qps == 0)
}

// qps returns the current per-client QPS limit (0 = disabled).
func (rl *rateLimiter) qps() int {
	return int(rl.qpsVal.Load())
}

func rlShardFor(client string) int {
	// Inline zero-alloc FNV-1a over the key bytes: avoids the fnv.New32a heap
	// object plus the string->[]byte copy that cost 2 allocs per query.
	h := uint32(2166136261)
	for i := 0; i < len(client); i++ {
		h ^= uint32(client[i])
		h *= 16777619
	}
	return int(h & (rlShards - 1))
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
	now := time.Now()
	b, ok := sh.buckets[client]
	if !ok {
		// Bound tracked clients. When saturated, evict the oldest entry if
		// it has been idle long enough; otherwise fail closed (deny) rather
		// than evict-then-admit: an attacker rotating source IPs must not get
		// a free pass once the table is full, but a transient flood must not
		// deny legitimate new clients forever either.
		if len(sh.buckets) >= maxLiveClients/rlShards {
			var victim string
			var oldest time.Time
			first := true
			for k, v := range sh.buckets {
				if first || v.last.Before(oldest) {
					victim, oldest, first = k, v.last, false
				}
			}
			if first || now.Sub(oldest) <= rlIdleEvict {
				sh.mu.Unlock()
				return false
			}
			delete(sh.buckets, victim)
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
		sh.mu.Unlock()
		return true
	}
	sh.mu.Unlock()
	return false
}

// rateLimitKey returns the rate-limiter bucket key for ip: the full address
// for IPv4, the /64 prefix for IPv6 (one /64 is typically one LAN/host, so
// bucketing the full /128 would let a single host mint 2^64 buckets while
// bucketing coarser than /64 would throttle unrelated customers sharing a
// prefix). Callers must keep the full IP for policy lookup; only the bucket
// key is masked.
func rateLimitKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return ip.String()
	}
	masked := make(net.IP, net.IPv6len)
	copy(masked, ip16)
	for i := 8; i < net.IPv6len; i++ {
		masked[i] = 0
	}
	return masked.String()
}

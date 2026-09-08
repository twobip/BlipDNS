package dnsserver

import (
	"fmt"
	"testing"
)

// BenchmarkAllowParallel hammers the limiter from all cores with distinct
// clients (the fan-in shape of a busy resolver) to expose bucket-map
// contention. Limit set high so every query passes and measures overhead,
// not drops.
func BenchmarkAllowParallel(b *testing.B) {
	rl := newRateLimiter()
	rl.set(1<<20, 1<<20)
	clients := make([]string, 4096)
	for i := range clients {
		clients[i] = fmt.Sprintf("10.0.%d.%d", (i>>8)&0xff, i&0xff)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			rl.allow(clients[i&(len(clients)-1)])
			i++
		}
	})
}

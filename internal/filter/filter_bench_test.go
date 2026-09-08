package filter

import "testing"

// BenchmarkClassify drives the per-query filter path: one RLock lookup plus
// the allow/block matcher walks over a mixed-case name (includes the
// normalize cost). Run with -benchmem -cpu=1,8 to see allocs/contention.
func BenchmarkClassify(b *testing.B) {
	s := NewStore(nil)
	p := &Policy{
		ID:       "p",
		Networks: []string{"10.0.0.0/8", "192.168.0.0/16"},
		Block:    []string{"ads.example.com", "*.tracker.net"},
		Allow:    []string{"good.tracker.net"},
	}
	if err := s.SetPolicy(p); err != nil {
		b.Fatal(err)
	}
	ip := mustIP("10.1.2.3")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Classify(ip, "", "WWW.Ads.Example.COM.")
	}
}

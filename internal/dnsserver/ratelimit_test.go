package dnsserver

import "testing"

// TestRateLimiterRefusalsByClient covers the dashboard's refused-queries
// breakdown: denied queries are tallied per client, only clients with
// refusals are listed, order is worst-first, and the top-n cap holds.
func TestRateLimiterRefusalsByClient(t *testing.T) {
	rl := newRateLimiter()
	rl.set(1, 2) // 1 qps, burst 2: the third immediate query is refused

	for i := 0; i < 7; i++ { // 2 allowed, 5 refused
		rl.allow("10.0.0.1")
	}
	for i := 0; i < 4; i++ { // 2 allowed, 2 refused
		rl.allow("10.0.0.2")
	}
	for i := 0; i < 2; i++ { // 2 allowed, none refused
		rl.allow("10.0.0.3")
	}

	got := rl.refusals(10)
	if len(got) != 2 {
		t.Fatalf("refusals = %+v, want 2 entries (clients with refusals only)", got)
	}
	if got[0].Client != "10.0.0.1" || got[0].Refused != 5 {
		t.Errorf("worst client = %+v, want 10.0.0.1 with 5", got[0])
	}
	if got[1].Client != "10.0.0.2" || got[1].Refused != 2 {
		t.Errorf("second client = %+v, want 10.0.0.2 with 2", got[1])
	}
	if top := rl.refusals(1); len(top) != 1 || top[0].Client != "10.0.0.1" {
		t.Errorf("top-1 = %+v, want just 10.0.0.1", top)
	}

	// Re-applying the limit resets buckets, and with them the breakdown.
	rl.set(1, 2)
	if got := rl.refusals(10); len(got) != 0 {
		t.Errorf("refusals after set() = %+v, want none", got)
	}
}

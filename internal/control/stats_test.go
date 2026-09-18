package control

import (
	"testing"
	"time"
)

// TestCountersDuration pins the cumulative duration counter the dashboard's
// average response time is derived from, including the µs truncation.
func TestCountersDuration(t *testing.T) {
	var c Counters
	c.AddQuery()
	c.AddDuration(1500 * time.Microsecond)
	c.AddDuration(500 * time.Microsecond)
	st := c.Stats()
	if st.DurationTotalUs != 2000 || st.QueriesTotal != 1 {
		t.Errorf("stats = %d µs / %d queries, want 2000 / 1", st.DurationTotalUs, st.QueriesTotal)
	}
}

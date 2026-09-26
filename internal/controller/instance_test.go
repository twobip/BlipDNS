package controller

import (
	"testing"
	"time"
)

func TestPushPingWindow(t *testing.T) {
	now := time.Now()
	var hist []pingSample
	var mean float64
	// An old sample outside the window, then two inside it.
	hist, _ = pushPing(hist, now.Add(-25*time.Hour), 100)
	hist, _ = pushPing(hist, now.Add(-time.Hour), 1)
	hist, mean = pushPing(hist, now, 3)
	if len(hist) != 2 {
		t.Fatalf("retained %d samples, want 2 (old one pruned)", len(hist))
	}
	if mean != 2 {
		t.Fatalf("mean = %v, want 2", mean)
	}
	if _, mean := pushPing(nil, now, 0); mean != 0 {
		t.Fatalf("empty mean = %v, want 0", mean)
	}
}

func TestStatusPingAvg24h(t *testing.T) {
	fleet := NewFleet("")
	now := time.Now()
	fleet.now = func() time.Time { return now }
	inst := &Instance{Config: InstanceConfig{ID: "s1"}, fleet: fleet}
	hist, _ := pushPing(nil, now.Add(-time.Hour), 1)
	inst.pingHist, inst.pingAvg24h = pushPing(hist, now, 3)
	st := inst.status()
	if st.PingAvg24h != 2 {
		t.Fatalf("PingAvg24h = %v, want 2", st.PingAvg24h)
	}
}

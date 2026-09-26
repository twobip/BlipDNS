package controller

import (
	"net/http"
	"net/http/httptest"
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

func TestHTTPSCandidate(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http://10.0.0.5:8444", "https://10.0.0.5:8444"},
		{"http://10.0.0.5:8444/", "https://10.0.0.5:8444/"},
		{"https://10.0.0.5:8444", ""},
		{"http://", ""},
		{"not a url", ""},
		{"", ""},
	} {
		if got := httpsCandidate(tc.in); got != tc.want {
			t.Errorf("httpsCandidate(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestProbeMgmtTLS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/adopt/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"adopted":true}`))
	})
	tlsSrv := httptest.NewTLSServer(mux)
	defer tlsSrv.Close()
	if !probeMgmtTLS(tlsSrv.Client(), tlsSrv.URL) {
		t.Fatal("probe of a live TLS management API failed")
	}
	plain := httptest.NewServer(mux)
	defer plain.Close()
	if probeMgmtTLS(tlsSrv.Client(), httpsCandidate(plain.URL)) {
		t.Fatal("probe of a plaintext endpoint as https succeeded")
	}
	if probeMgmtTLS(&http.Client{Timeout: time.Second}, "https://127.0.0.1:9") {
		t.Fatal("probe of a closed port succeeded")
	}
}

func TestMgmtInsecureFlag(t *testing.T) {
	fleet := NewFleet("")
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://10.0.0.5:8444", false},
		{"http://10.0.0.5:8444", true},
		{"http://127.0.0.1:8444", false},
		{"http://[::1]:8444", false},
	} {
		inst := &Instance{Config: InstanceConfig{ID: "s1", URL: tc.url}, fleet: fleet}
		if got := inst.status().MgmtInsecure; got != tc.want {
			t.Errorf("MgmtInsecure(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

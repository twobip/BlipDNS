package controller

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/twobip/BlipDNS/internal/certgen"
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

func TestMaybeMigrateMgmtTLS(t *testing.T) {
	certPEM, keyPEM, err := certgen.Generate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", caFile)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/adopt/status", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"adopted":true}`))
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	fleet := NewFleet("")
	httpURL := "http://" + ln.Addr().String()
	inst := &Instance{Config: InstanceConfig{ID: "s1", URL: httpURL, Token: "t"}, fleet: fleet}
	fleet.maybeMigrateMgmtTLS(inst, "s1", httpURL)
	if got := inst.Config.URL; got != "https://"+ln.Addr().String() {
		t.Fatalf("URL = %q, want the https equivalent", got)
	}
	if hits.Load() != 1 {
		t.Fatalf("probe hits = %d, want 1", hits.Load())
	}
	// Already https: no probe, no change.
	fleet.maybeMigrateMgmtTLS(inst, "s1", inst.Config.URL)
	if hits.Load() != 1 {
		t.Fatalf("re-probed an https URL (hits = %d)", hits.Load())
	}
	// Recent probe timestamp suppresses re-probes: still http, no new hit.
	inst2 := &Instance{Config: InstanceConfig{ID: "s2", URL: httpURL, Token: "t"}, fleet: fleet}
	inst2.lastTLSProbe = fleet.now()
	fleet.maybeMigrateMgmtTLS(inst2, "s2", inst2.Config.URL)
	if got := inst2.Config.URL; got != httpURL {
		t.Fatalf("URL = %q, want unchanged (probe suppressed)", got)
	}
	if hits.Load() != 1 {
		t.Fatalf("probed despite fresh timestamp (hits = %d)", hits.Load())
	}
	// Stale timestamp re-probes and migrates.
	inst2.lastTLSProbe = time.Time{}
	fleet.maybeMigrateMgmtTLS(inst2, "s2", inst2.Config.URL)
	if got := inst2.Config.URL; got != "https://"+ln.Addr().String() {
		t.Fatalf("URL = %q, want the https equivalent", got)
	}
	// No TLS there: closed port stays http.
	inst3 := &Instance{Config: InstanceConfig{ID: "s3", URL: "http://127.0.0.1:9", Token: "t"}, fleet: fleet}
	fleet.maybeMigrateMgmtTLS(inst3, "s3", inst3.Config.URL)
	if got := inst3.Config.URL; got != "http://127.0.0.1:9" {
		t.Fatalf("URL = %q, want unchanged (no TLS there)", got)
	}
}

// TestMaybeMigrateMgmtTLSTOFU proves migration works against a self-signed
// instance with NO system trust: the leaf is pinned on first sight, the
// pinned client can actually poll through it, and a changed cert afterwards
// refuses instead of silently re-pinning.
func TestMaybeMigrateMgmtTLSTOFU(t *testing.T) {
	certPEM, keyPEM, err := certgen.Generate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/adopt/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"adopted":true}`))
	})
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"version":"test"}`))
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	fleet := NewFleet("")
	httpURL := "http://" + ln.Addr().String()
	inst := &Instance{Config: InstanceConfig{ID: "s1", URL: httpURL, Token: "t"}, fleet: fleet}
	fleet.maybeMigrateMgmtTLS(inst, "s1", httpURL)
	wantURL := "https://" + ln.Addr().String()
	if got := inst.Config.URL; got != wantURL {
		t.Fatalf("URL = %q, want %q (TOFU migrate without system trust)", got, wantURL)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.Raw)
	if want := hex.EncodeToString(sum[:]); inst.Config.MgmtCertFP != want {
		t.Fatalf("pinned FP = %q, want %q", inst.Config.MgmtCertFP, want)
	}
	// The pinned client really polls through the pin (would fail TLS
	// verification without it: self-signed, no system trust).
	if _, err := inst.client.Health(context.Background()); err != nil {
		t.Fatalf("pinned client health poll failed: %v", err)
	}
	// Same cert again: pin matches, migration holds.
	fleet.maybeMigrateMgmtTLS(inst, "s1", httpURL)
	if got := inst.Config.URL; got != wantURL {
		t.Fatalf("URL = %q, want %q (pin re-match)", got, wantURL)
	}
	// Rotated cert under the same URL: refuse, never silently re-pin.
	// (Close the first server so the same port can be rebound.)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	rotPEM, rotKey, err := certgen.Generate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	rotCert, err := tls.X509KeyPair(rotPEM, rotKey)
	if err != nil {
		t.Fatal(err)
	}
	ln2, err := tls.Listen("tcp", ln.Addr().String(), &tls.Config{Certificates: []tls.Certificate{rotCert}})
	if err != nil {
		t.Skipf("cannot rebind %s for rotation test: %v", ln.Addr(), err)
	}
	srv2 := &http.Server{Handler: mux}
	go func() { _ = srv2.Serve(ln2) }()
	defer srv2.Close()
	inst2 := &Instance{Config: InstanceConfig{ID: "s2", URL: httpURL, Token: "t", MgmtCertFP: inst.Config.MgmtCertFP}, fleet: fleet}
	inst2.lastTLSProbe = time.Time{}
	fleet.maybeMigrateMgmtTLS(inst2, "s2", httpURL)
	if got := inst2.Config.URL; got != httpURL {
		t.Fatalf("URL = %q, want unchanged %q (rotated cert must refuse)", got, httpURL)
	}
}

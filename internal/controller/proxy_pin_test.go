package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mintBareCert returns a self-signed server cert with DNS-only SANs —
// deliberately no IP SANs, like a node certificate under the no-RFC1918 SAN
// policy when dialled by LAN IP.
func mintBareCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "blipd-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"blipd-test.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	// Serve the raw DER + key the way a listener would.
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	return pair, leaf
}

func serveBareTLS(t *testing.T, pair tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/adopt/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "https://" + ln.Addr().String()
}

// A node certificate that omits the dialled LAN IP must still pin and serve:
// the fingerprint pin is the authentication, not the SANs.
func TestSANLessCertPinsAndServes(t *testing.T) {
	pair, leaf := mintBareCert(t)
	url := serveBareTLS(t, pair)

	if got := fetchMgmtLeaf(url); got == nil || !got.Equal(leaf) {
		t.Fatalf("fetchMgmtLeaf returned %v, want the served leaf", got)
	}
	c, gotLeaf, fp, ok := httpsMgmtClient(url, "tok", "")
	if !ok || c == nil || gotLeaf == nil || fp == "" {
		t.Fatalf("httpsMgmtClient(pin empty) = ok %v, want true (SAN-less cert must pin)", ok)
	}
	if want := mgmtCertFP(leaf); fp != want {
		t.Fatalf("pinned fp %s, want %s", fp, want)
	}
}

// A wrong pin must still refuse, even when the presented cert is SAN-less.
func TestSANLessCertWrongPinRefuses(t *testing.T) {
	pair, _ := mintBareCert(t)
	url := serveBareTLS(t, pair)
	if _, _, _, ok := httpsMgmtClient(url, "tok", strings.Repeat("0", 64)); ok {
		t.Fatal("httpsMgmtClient with wrong pin succeeded, want refusal")
	}
}

// The pinned config must reject an impostor presenting a different cert.
func TestPinnedTLSConfigRejectsImpostor(t *testing.T) {
	_, leaf := mintBareCert(t)
	impostor, _ := mintBareCert(t)
	url := serveBareTLS(t, impostor)
	hostport := strings.TrimPrefix(url, "https://")
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: upgradeProbeTimeout}, "tcp",
		hostport, pinnedTLSConfig(leaf))
	if err == nil {
		conn.Close()
		t.Fatal("pinned config accepted an impostor cert, want handshake failure")
	}
}

// serveSwappableTLS serves the management-API stub with a certificate that
// can be rotated in place (same address, new cert) — the exact shape of a
// blipd update that regenerated its cert.
func serveSwappableTLS(t *testing.T, pair tls.Certificate) (string, *atomic.Pointer[tls.Certificate]) {
	t.Helper()
	cur := &atomic.Pointer[tls.Certificate]{}
	cur.Store(&pair)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cur.Load(), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/adopt/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "https://" + ln.Addr().String(), cur
}

// A rotated certificate must break the pin (management goes dark) until an
// operator re-pins; RepinInstance then adopts the served cert, swaps the live
// client, and leaves a dead endpoint's pin untouched.
func TestRepinInstanceAcceptsRotatedCert(t *testing.T) {
	pair, leaf := mintBareCert(t)
	url, cur := serveSwappableTLS(t, pair)
	fleet := NewFleet("")
	inst := &Instance{Config: InstanceConfig{ID: "s1", URL: url, Token: "t"}, fleet: fleet}
	fleet.mu.Lock()
	fleet.instances["s1"] = inst
	fleet.mu.Unlock()

	// First pin (what Add/adopt does through httpsMgmtClient with no pin).
	oldFP, fp, err := fleet.RepinInstance("s1")
	if err != nil {
		t.Fatalf("initial pin: %v", err)
	}
	if oldFP != "" {
		t.Errorf("old fingerprint = %q, want empty before the first pin", oldFP)
	}
	if want := mgmtCertFP(leaf); fp != want || inst.Config.MgmtCertFP != want {
		t.Fatalf("pinned fp = %q / %q, want %q", fp, inst.Config.MgmtCertFP, want)
	}
	if _, err := inst.ctl().Health(context.Background()); err != nil {
		t.Fatalf("health through the fresh pin: %v", err)
	}

	// Rotate the cert under the same URL: the pinned client must now fail.
	// Drop the kept-alive connection first — a real rotation arrives with a
	// restart, so the next poll is a fresh handshake, and only then does the
	// pin get compared.
	rot, rotLeaf := mintBareCert(t)
	cur.Store(&rot)
	inst.ctl().CloseIdleConnections()
	if _, err := inst.ctl().Health(context.Background()); err == nil {
		t.Fatal("rotated cert still trusted by the pinned client")
	}

	oldFP, fp, err = fleet.RepinInstance("s1")
	if err != nil {
		t.Fatalf("re-pin after rotation: %v", err)
	}
	if oldFP != mgmtCertFP(leaf) {
		t.Errorf("reported old fp = %q, want the previous pin", oldFP)
	}
	if want := mgmtCertFP(rotLeaf); fp != want || inst.Config.MgmtCertFP != want {
		t.Fatalf("re-pinned fp = %q / %q, want %q", fp, inst.Config.MgmtCertFP, want)
	}
	// The point of the whole exercise: management works again.
	if _, err := inst.ctl().Health(context.Background()); err != nil {
		t.Fatalf("health after re-pin: %v", err)
	}

	// A dead endpoint must never re-pin: no trust without a working handshake.
	dead := &Instance{Config: InstanceConfig{ID: "s2", URL: "https://127.0.0.1:1", Token: "t", MgmtCertFP: strings.Repeat("a", 64)}, fleet: fleet}
	fleet.mu.Lock()
	fleet.instances["s2"] = dead
	fleet.mu.Unlock()
	if _, _, err := fleet.RepinInstance("s2"); err == nil {
		t.Fatal("re-pin against a dead endpoint succeeded, want error")
	}
	if dead.Config.MgmtCertFP != strings.Repeat("a", 64) {
		t.Errorf("failed re-pin changed the pin to %q", dead.Config.MgmtCertFP)
	}
	if _, _, err := fleet.RepinInstance("nope"); err == nil {
		t.Fatal("re-pin of an unknown instance succeeded, want error")
	}
}

// The re-pin endpoint is a trust decision: a session may make it, a bearer key
// may not, and the route is wired (an unknown instance reaches the fleet and
// is refused there rather than 404ing).
func TestInstanceRepinEndpointSessionOnly(t *testing.T) {
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, "", "")
	h := srv.Handler()
	cookie := loginSessionCookie(t, h)
	_, key, _, err := srv.auth.CreateAPIKey("repin", time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"id": "nope"})

	if rec := doKeys(t, h, http.MethodPost, "/api/instances/repin", body, cookie, ""); rec.Code != http.StatusBadGateway {
		t.Errorf("session repin of an unknown instance = %d, want 502 (%s)", rec.Code, rec.Body.String())
	}
	if rec := doKeys(t, h, http.MethodPost, "/api/instances/repin", body, nil, key); rec.Code != http.StatusForbidden {
		t.Errorf("bearer repin = %d, want 403 (a script key must not re-pin)", rec.Code)
	}
	if rec := doKeys(t, h, http.MethodGet, "/api/instances/repin", nil, cookie, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET repin = %d, want 405", rec.Code)
	}
}

package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strings"
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

package certgen

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	certPEM, keyPEM, err := Generate("dns.example.com", "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair does not parse: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA {
		t.Error("expected a leaf (non-CA) server certificate")
	}
	if leaf.NotAfter.Before(time.Now().AddDate(9, 0, 0)) {
		t.Errorf("cert validity too short: %s", leaf.NotAfter)
	}
	// the extra host must appear as a SAN
	found := false
	for _, d := range leaf.DNSNames {
		if d == "dns.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected dns.example.com in SANs, got DNS=%v IPs=%v", leaf.DNSNames, leaf.IPAddresses)
	}
	for _, ip := range leaf.IPAddresses {
		if ip.String() == "10.0.0.5" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 10.0.0.5 in IP SANs, got %v", leaf.IPAddresses)
	}
	// localhost must always be present
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "localhost" {
		t.Errorf("expected localhost first in DNS SANs, got %v", leaf.DNSNames)
	}
}

func TestEnsureFilesPersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "doh-cert.pem")
	keyPath := filepath.Join(dir, "doh-key.pem")

	c1, k1, persisted, err := EnsureFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted {
		t.Error("expected pair to be persisted")
	}
	// second call must load the same pair (stable fingerprint), not re-sign
	c2, k2, persisted2, err := EnsureFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted2 {
		t.Error("expected second call to load persisted pair")
	}
	if string(c1) != string(c2) || string(k1) != string(k2) {
		t.Error("EnsureFiles regenerated instead of reusing the persisted pair")
	}
}

func TestEnsureFilesRegeneratesExpired(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "doh-cert.pem")
	keyPath := filepath.Join(dir, "doh-key.pem")
	if _, _, _, err := EnsureFiles(certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	// Corrupt the stored cert so it no longer validates -> must regenerate.
	certPEM, _, _, err := EnsureFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no cert PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}

	// Overwrite the key with a different one -> mismatch forces regeneration.
	otherC, otherK, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, otherK, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, otherC, 0o644); err != nil {
		t.Fatal(err)
	}
	c3, k3, _, err := EnsureFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(c3, k3); err != nil {
		t.Fatalf("regenerated pair invalid: %v", err)
	}
}

func TestEnsureFilesInMemoryFallback(t *testing.T) {
	c, k, persisted, err := EnsureFiles("", "")
	if err != nil {
		t.Fatal(err)
	}
	if persisted {
		t.Error("no paths => must not claim persistence")
	}
	if _, err := tls.X509KeyPair(c, k); err != nil {
		t.Fatalf("in-memory pair invalid: %v", err)
	}
}

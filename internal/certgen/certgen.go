// Package certgen creates self-signed TLS certificates for blipd's DoH
// listener, so it can serve DNS over HTTPS out of the box without an operator
// supplying certs. The certificate is persisted (when a directory is given) so
// restarts keep the same fingerprint instead of re-signing every boot.
package certgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// validity is how long generated certificates are good for (10 years).
const validity = 10 * 365 * 24 * time.Hour

// Generate creates a self-signed ECDSA (P-256) server certificate. The
// certificate names localhost plus every non-loopback address on the host, so
// DoH clients can connect via any hostname/IP the machine actually has.
// extraHosts may add explicit DNS names or IP addresses.
func Generate(extraHosts ...string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	hostname := hostname()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "blipd", Organization: []string{"BlipDNS"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", hostname},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if hostname == "" {
		tmpl.DNSNames = []string{"localhost"}
	}
	for _, h := range extraHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, localIPs()...)
	tmpl.DNSNames = dedupeStrings(tmpl.DNSNames)
	tmpl.IPAddresses = dedupeIPs(tmpl.IPAddresses)

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// EnsureFiles returns a usable certificate/key pair, loading them from disk
// when both paths exist and are valid, and otherwise generating a fresh pair
// and persisting it (key written with 0600). persisted reports whether the
// returned pair survives a restart. err is nil unless the pair is unusable
// even after generation; a write failure returns the error alongside valid
// in-memory PEMs so the caller can serve ephemerally instead of dying.
func EnsureFiles(certPath, keyPath string) (certPEM, keyPEM []byte, persisted bool, err error) {
	if certPath != "" && keyPath != "" {
		if c, k, lerr := load(certPath, keyPath); lerr == nil {
			return c, k, true, nil
		}
	}
	certPEM, keyPEM, gerr := Generate()
	if gerr != nil {
		return nil, nil, false, gerr
	}
	if certPath == "" || keyPath == "" {
		return certPEM, keyPEM, false, nil
	}
	dir := filepath.Dir(certPath)
	if mkerr := os.MkdirAll(dir, 0o750); mkerr != nil {
		return certPEM, keyPEM, false, fmt.Errorf("self-signed cert: mkdir %s: %w", dir, mkerr)
	}
	if werr := os.WriteFile(certPath, certPEM, 0o644); werr != nil {
		return certPEM, keyPEM, false, fmt.Errorf("self-signed cert: write %s: %w", certPath, werr)
	}
	if werr := os.WriteFile(keyPath, keyPEM, 0o600); werr != nil {
		return certPEM, keyPEM, false, fmt.Errorf("self-signed key: write %s: %w", keyPath, werr)
	}
	return certPEM, keyPEM, true, nil
}

// load reads a persisted pair and validates it: both PEMs parse, the private
// key matches the certificate, and the certificate is not expired.
func load(certPath, keyPath string) ([]byte, []byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("self-signed cert: no certificate PEM in %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("self-signed cert: parse %s: %w", certPath, err)
	}
	if time.Now().After(cert.NotAfter) {
		return nil, nil, fmt.Errorf("self-signed cert: expired")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("self-signed key: no key PEM in %s", keyPath)
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("self-signed key: %w", err)
	}
	if !reflect.DeepEqual(key.Public(), cert.PublicKey) {
		return nil, nil, fmt.Errorf("self-signed cert: key does not match certificate")
	}
	return certPEM, keyPEM, nil
}

// parsePrivateKey accepts EC encodings. blipd only ever writes EC keys
// (see Generate), so that is the only form we need to reload from disk.
type privateKey interface {
	Public() crypto.PublicKey
}

func parsePrivateKey(der []byte) (privateKey, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if pk, ok := k.(privateKey); ok {
			return pk, nil
		}
		return nil, fmt.Errorf("unsupported private key type %T", k)
	}
	return nil, fmt.Errorf("unsupported private key encoding")
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// localIPs returns the machine's non-loopback IPv4/IPv6 addresses, so the
// generated certificate stays valid for clients that reach blipd by LAN IP.
func localIPs() []net.IP {
	out := []net.IP{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := networkIP(a)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}

func networkIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func dedupeIPs(in []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(in))
	out := make([]net.IP, 0, len(in))
	for _, ip := range in {
		if ip == nil {
			continue
		}
		k := ip.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, ip)
	}
	return out
}

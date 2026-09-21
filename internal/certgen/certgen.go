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
	"crypto/tls"
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
	"sync"
	"time"
)

// validity is how long generated certificates are good for (398 days, the
// longest widely-accepted lifetime). A decade-long self-signed cert turns a
// key compromise into a decade-long impersonation with no revocation channel.
const validity = 398 * 24 * time.Hour

// renewAfter is the age at which a persisted certificate is regenerated even
// though it has not expired yet (2/3 of validity), so fingerprints rotate
// before the hard expiry instead of all at once on expiry day.
const renewAfter = validity * 2 / 3

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
	dnsNames, ipAddrs := expectedSANs(extraHosts)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "blipd", Organization: []string{"BlipDNS"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}

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

// EnsurePair is EnsureFiles plus the parsed key pair, ready for a TLS listener.
// Callers that must re-derive the certificate while running (an HA VIP that
// only arrives from the controller after startup) call it again and swap the
// result in.
func EnsurePair(certPath, keyPath string, extraHosts ...string) (*tls.Certificate, error) {
	certPEM, keyPEM, _, err := EnsureFiles(certPath, keyPath, extraHosts...)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

// expectedSANs returns the identities a self-signed DoH certificate must
// cover: localhost, loopback IPs, the machine hostname, and any
// operator-configured extra hosts (e.g. an HA VIP). Deliberately NOT every
// interface address: embedding LAN/link-local/docker IPs discloses topology
// to anyone completing a handshake and churns the fingerprint on every DHCP
// change. Operators that serve by LAN IP should list it in doh_san.
func expectedSANs(extraHosts []string) ([]string, []net.IP) {
	names := []string{"localhost"}
	if hn := hostname(); hn != "" {
		names = append(names, hn)
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, h := range extraHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			names = append(names, h)
		}
	}
	ips = append(ips, stableLocalIPs()...)
	return dedupeStrings(names), dedupeIPs(ips)
}

// EnsureFiles returns a usable certificate/key pair, loading them from disk
// when both paths exist and are valid, and otherwise generating a fresh pair
// and persisting it (key written with 0600). persisted reports whether the
// returned pair survives a restart. err is nil unless the pair is unusable
// even after generation; a write failure returns the error alongside valid
// in-memory PEMs so the caller can serve ephemerally instead of dying.
func EnsureFiles(certPath, keyPath string, extraHosts ...string) (certPEM, keyPEM []byte, persisted bool, err error) {
	if certPath != "" && keyPath != "" {
		if c, k, lerr := load(certPath, keyPath, extraHosts); lerr == nil {
			return c, k, true, nil
		}
	}
	certPEM, keyPEM, gerr := Generate(extraHosts...)
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
	// Atomic writes (tmp+rename, 0600 directly) so a crash never leaves a
	// half-written PEM.
	if werr := writeFileAtomic(certPath, certPEM, 0o644); werr != nil {
		return certPEM, keyPEM, false, fmt.Errorf("self-signed cert: write %s: %w", certPath, werr)
	}
	if werr := writeFileAtomic(keyPath, keyPEM, 0o600); werr != nil {
		return certPEM, keyPEM, false, fmt.Errorf("self-signed key: write %s: %w", keyPath, werr)
	}
	return certPEM, keyPEM, true, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cert-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// load reads a persisted pair and validates it: both PEMs parse, the private
// key matches the certificate, the certificate is not expired, and it covers
// the identity blipd serves today (hostname, own addresses, configured extra
// hosts).
func load(certPath, keyPath string, extraHosts []string) ([]byte, []byte, error) {
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
	// Rotate before the hard expiry so clients see a planned renewal, not a
	// flag-day fingerprint change. Regeneration also picks up SAN changes.
	if time.Now().After(cert.NotBefore.Add(renewAfter)) {
		return nil, nil, fmt.Errorf("self-signed cert: past renewal age")
	}
	if missing := missingSANs(cert, extraHosts); missing != "" {
		return nil, nil, fmt.Errorf("self-signed cert: does not cover %s", missing)
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

// missingSANs reports the first identity the persisted certificate fails to
// cover, or "" when it covers them all. Without this check a cert generated
// before an address existed (e.g. an HA VIP that only a master node holds)
// would be served unverifiable for its entire multi-year lifetime. Membership
// is via maps (was O(N·M) slices.Contains/nested Equal per check) and the
// want-lists are computed once (load called expectedSANs twice before).
func missingSANs(cert *x509.Certificate, extraHosts []string) string {
	wantNames, wantIPs := expectedSANs(extraHosts)
	return missingSANsWithWant(cert, wantNames, wantIPs)
}

func missingSANsWithWant(cert *x509.Certificate, wantNames []string, wantIPs []net.IP) string {
	haveNames := make(map[string]struct{}, len(cert.DNSNames))
	for _, n := range cert.DNSNames {
		haveNames[n] = struct{}{}
	}
	for _, n := range wantNames {
		if _, ok := haveNames[n]; !ok {
			return n
		}
	}
	haveIPs := make(map[string]struct{}, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		haveIPs[ip.String()] = struct{}{}
	}
	for _, ip := range wantIPs {
		if _, ok := haveIPs[ip.String()]; !ok {
			return ip.String()
		}
	}
	return ""
}

// hostCache memoizes hostname()+localIPs() (net.Interfaces syscalls) for 5m:
// every cert check (startup + every HA VIP refresh) enumerated interfaces.
var hostCache = struct {
	sync.Mutex
	host   string
	ips    []net.IP
	expire time.Time
}{}

func hostname() string {
	hostCache.Lock()
	defer hostCache.Unlock()
	if time.Now().Before(hostCache.expire) && hostCache.expire.Unix() != 0 {
		return hostCache.host
	}
	h, err := os.Hostname()
	if err != nil {
		h = ""
	}
	// Refresh IPs under the same lock to keep one syscall burst per 5m.
	ips := localIPsUncached()
	hostCache.host = h
	hostCache.ips = ips
	hostCache.expire = time.Now().Add(5 * time.Minute)
	return h
}

// stableLocalIPs returns the machine's LAN addresses for the SAN set,
// excluding ephemeral/disclosing ones: link-local (fe80::/10, 169.254/16),
// multicast, and unspecified. Global-unicast and private (RFC1918) addresses
// stay covered so clients reaching blipd by LAN IP keep verifying; operators
// with stricter needs should list exact names in doh_san.
func stableLocalIPs() []net.IP {
	out := []net.IP{}
	for _, ip := range localIPs() {
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// localIPs returns the machine's non-loopback IPv4/IPv6 addresses. Kept for
// diagnostics/tests; NOT part of the certificate SAN set (see
// stableLocalIPs). Cached 5m alongside hostname() (was net.Interfaces
// syscalls per check).
func localIPs() []net.IP {
	hostCache.Lock()
	defer hostCache.Unlock()
	if time.Now().Before(hostCache.expire) && hostCache.expire.Unix() != 0 && hostCache.ips != nil {
		out := make([]net.IP, len(hostCache.ips))
		copy(out, hostCache.ips)
		return out
	}
	ips := localIPsUncached()
	// Refresh hostname too if expired (one burst per 5m).
	if h, err := os.Hostname(); err == nil {
		hostCache.host = h
	}
	hostCache.ips = ips
	hostCache.expire = time.Now().Add(5 * time.Minute)
	out := make([]net.IP, len(ips))
	copy(out, ips)
	return out
}

func localIPsUncached() []net.IP {
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
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}

func dedupeStrings(in []string) []string {
	return dedupe(in, func(s string) (string, bool) {
		if s == "" {
			return "", false
		}
		return s, true
	})
}

func dedupeIPs(in []net.IP) []net.IP {
	return dedupe(in, func(ip net.IP) (string, bool) {
		if ip == nil {
			return "", false
		}
		return ip.String(), true
	})
}

// dedupe keeps the first occurrence of each key while dropping empties.
func dedupe[T any](in []T, key func(T) (string, bool)) []T {
	seen := make(map[string]struct{}, len(in))
	out := make([]T, 0, len(in))
	for _, v := range in {
		k, ok := key(v)
		if !ok {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	return out
}

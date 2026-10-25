package controller

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

// ProxyTrust gates which immediate peers may supply X-Forwarded-* headers.
// Empty/nil means forwarded headers are never trusted (direct-access default).
// A catch-all CIDR (0.0.0.0/0, ::/0) is never a valid trust entry: it would
// honor attacker-controlled X-Forwarded-For/Proto/Host on every request
// (client-IP spoofing, Secure-cookie downgrade, CSRF origin bypass), so
// ParseTrustedProxies rejects it. To accept direct internet clients, leave
// trusted_proxies empty — forwarded headers are then ignored entirely.
type ProxyTrust struct {
	nets []*net.IPNet
}

// ParseTrustedProxies parses CIDRs or bare IPs ("127.0.0.1", "10.0.0.0/8").
// Catch-all CIDRs (a /0 mask: 0.0.0.0/0, ::/0) are rejected outright, because
// trusting the whole internet as a proxy would let any client spoof the
// forwarded headers (IP, scheme, host) the controller bases auth-adjacent
// decisions on.
func ParseTrustedProxies(values []string) (*ProxyTrust, error) {
	out := &ProxyTrust{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !strings.Contains(v, "/") {
			ip := net.ParseIP(v)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy %q", v)
			}
			if ip4 := ip.To4(); ip4 != nil {
				out.nets = append(out.nets, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
			} else {
				out.nets = append(out.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
			continue
		}
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", v, err)
		}
		if ones, _ := n.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("invalid trusted proxy %q: catch-all CIDR would trust the whole internet; leave trusted_proxies empty instead", v)
		}
		out.nets = append(out.nets, n)
	}
	// F-17: split CIDRs (e.g. 0.0.0.0/1 + 128.0.0.0/1) cover the whole space
	// without any single /0 entry. Shared check in control (dnsserver's
	// parseTrustedProxies still needs the same call — owned by another agent).
	if control.FullSpaceCovered(out.nets) {
		return nil, fmt.Errorf("invalid trusted_proxies: entries collectively cover the whole internet; list explicit proxy IPs instead")
	}
	return out, nil
}

// IsTrustedPeer reports whether r arrived from a configured trusted proxy.
func (t *ProxyTrust) IsTrustedPeer(r *http.Request) bool {
	if t == nil || len(t.nets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(strings.TrimSpace(host))
	if peer == nil {
		return false
	}
	for _, n := range t.nets {
		if n.Contains(peer) {
			return true
		}
	}
	return false
}

// lastForwardedToken returns the rightmost token of a forwarded-header value.
// F-09: trusting the first token lets a client spoof its address whenever the
// trusted proxy appends (nginx `$proxy_add_x_forwarded_for`). The last token
// is the address the trusted peer appended, so it is the only one honored.
func lastForwardedToken(s string) string {
	parts := strings.Split(s, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(parts[i]); t != "" {
			if f := strings.Fields(t); len(f) > 0 {
				return f[len(f)-1]
			}
			return t
		}
	}
	return ""
}

// ClientIP returns the real client IP: the last X-Forwarded-For token when
// the peer is trusted, else the direct peer. A present-but-unusable XFF
// falls back to the direct peer, never to CF-Connecting-IP/X-Real-IP: a
// generic trusted proxy forwards client headers verbatim, letting the
// client dictate those directly (F-4). CF/X-Real-IP are only consulted when
// no XFF was sent at all.
func (t *ProxyTrust) ClientIP(r *http.Request) string {
	if t != nil && t.IsTrustedPeer(r) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if ip := net.ParseIP(lastForwardedToken(fwd)); ip != nil {
				return ip.String()
			}
			return ClientIP(r)
		}
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			if ip := net.ParseIP(lastForwardedToken(cf)); ip != nil {
				return ip.String()
			}
		}
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			if ip := net.ParseIP(lastForwardedToken(real)); ip != nil {
				return ip.String()
			}
		}
	}
	return ClientIP(r)
}

// IsSecure reports whether the client-facing connection is TLS: direct TLS,
// or http behind a trusted TLS-terminating proxy (X-Forwarded-Proto=https).
func (t *ProxyTrust) IsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if t != nil && t.IsTrustedPeer(r) {
		if proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); proto != "" {
			// Rightmost token: the value the trusted proxy appended.
			proto = lastForwardedToken(proto)
			return proto == "https"
		}
	}
	return false
}

// RequestHost returns the client-facing host: X-Forwarded-Host when trusted,
// else r.Host. Used for CSRF Origin checks behind a reverse proxy.
func (t *ProxyTrust) RequestHost(r *http.Request) string {
	if t != nil && t.IsTrustedPeer(r) {
		if h := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); h != "" {
			h = lastForwardedToken(h)
			if h != "" {
				return h
			}
		}
	}
	return r.Host
}

// upgradeProbeTimeout bounds the HTTPS upgrade probe per instance add.
const upgradeProbeTimeout = 3 * time.Second

// httpsCandidate rewrites an http:// management URL to its https://
// equivalent ("" when already https or unparsable).
func httpsCandidate(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return ""
	}
	u.Scheme = "https"
	return u.String()
}

// probeMgmtTLS reports whether url serves the management API over TLS. Any
// HTTP response (even 4xx) proves the handshake; only transport failures
// count as unavailable. The unauthenticated adopt/status endpoint keeps
// bearer tokens out of the probe.
func probeMgmtTLS(client *http.Client, url string) bool {
	resp, err := client.Get(strings.TrimSuffix(url, "/") + "/api/v1/adopt/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return true
}

// fetchMgmtLeaf dials httpsURL with chain verification disabled and returns
// the presented leaf certificate, or nil. Disabling verification here is
// safe: the caller never trusts the leaf on sight — it is pinned on first
// use (TOFU) and compared against the persisted pin afterwards, and the
// probe endpoint carries no bearer token. The leaf is NOT required to name
// the dialled host: node certificates deliberately omit dialled LAN IPs
// (no-RFC1918 SAN policy), so the fingerprint pin — exact-cert match — is
// the authentication, not the SANs. A SAN mismatch is logged loudly so an
// unexpected middlebox cert is visible instead of silent.
func fetchMgmtLeaf(httpsURL string) *x509.Certificate {
	u, err := url.Parse(strings.TrimSpace(httpsURL))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	// ponytail: gosec G402 would flag InsecureSkipVerify — the pin-then-
	// compare in httpsMgmtClient is the mitigation, not an accident.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: upgradeProbeTimeout}, "tcp",
		net.JoinHostPort(host, port), &tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		return nil
	}
	defer conn.Close()
	pcs := conn.ConnectionState().PeerCertificates
	if len(pcs) == 0 {
		return nil
	}
	if err := pcs[0].VerifyHostname(host); err != nil {
		log.Printf("blipc: management cert for %s does not name the dialled host (%v); pinning by fingerprint — confirm this fingerprint out-of-band if unexpected: %s", httpsURL, err, mgmtCertFP(pcs[0]))
	}
	return pcs[0]
}

// mgmtCertFP is the hex SHA256 pin of a management leaf certificate.
func mgmtCertFP(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:])
}

// pinnedTLSConfig trusts exactly the certificate whose SHA-256 matches fp and
// nothing else. Hostname/SAN checks are skipped — node certificates
// deliberately omit dialled LAN IPs, so the fingerprint pin is the
// authentication, not the SANs. The pin is compared on every handshake (not
// once at load) so a client stays valid across a peer restart. Resumed
// sessions skip the check: resumption is cryptographically bound to the
// originally verified session via the server's ticket keys, and carries no
// certificates.
// (ponytail: gosec G402 would flag InsecureSkipVerify — the exact-cert
// VerifyConnection below is the mitigation, not an accident.)
func pinnedTLSConfig(fp string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.DidResume {
				return nil
			}
			if len(cs.PeerCertificates) == 0 || subtle.ConstantTimeCompare([]byte(mgmtCertFP(cs.PeerCertificates[0])), []byte(fp)) != 1 {
				return fmt.Errorf("blipc: management certificate does not match pinned fingerprint")
			}
			return nil
		},
	}
}

// pinnedMgmtClient returns a control client trusting only the cert with
// fingerprint fp (TOFU pin).
func pinnedMgmtClient(httpsURL, token, fp string) *control.Client {
	return control.NewClientWithTLS(httpsURL, token, pinnedTLSConfig(fp))
}

// httpsMgmtClient returns a control client for an https management URL.
// System-trusted servers (CA-signed or operator-installed roots) use a
// standard client and no pin. Otherwise the served leaf is pinned on first
// sight and matched against pinnedFP afterwards: a changed cert refuses
// loudly (possible MITM or legit rotation — clear mgmt_cert_fp in
// controller.yaml to re-pin) instead of silently re-pinning.
//
// A persisted pin needs no dial: the pin is verified per handshake, so a node
// that is still restarting must not latch the instance onto an unverifiable
// plain client for the whole run.
func httpsMgmtClient(httpsURL, token, pinnedFP string) (client *control.Client, leaf *x509.Certificate, fp string, ok bool) {
	if pinnedFP != "" {
		return pinnedMgmtClient(httpsURL, token, pinnedFP), nil, pinnedFP, true
	}
	if probeMgmtTLS(&http.Client{Timeout: upgradeProbeTimeout}, httpsURL) {
		return control.NewClient(httpsURL, token), nil, "", true
	}
	leaf = fetchMgmtLeaf(httpsURL)
	if leaf == nil {
		return nil, nil, "", false
	}
	fp = mgmtCertFP(leaf)
	probe := &http.Client{Transport: &http.Transport{TLSClientConfig: pinnedTLSConfig(fp)}, Timeout: upgradeProbeTimeout}
	if !probeMgmtTLS(probe, httpsURL) {
		return nil, nil, "", false
	}
	log.Printf("blipc: pinned self-signed management cert for %s (fingerprint %s)", httpsURL, fp)
	return pinnedMgmtClient(httpsURL, token, fp), leaf, fp, true
}

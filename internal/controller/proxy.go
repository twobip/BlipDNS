package controller

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ProxyTrust gates which immediate peers may supply X-Forwarded-* headers.
// Empty/nil means forwarded headers are never trusted (direct-access default).
type ProxyTrust struct {
	nets []*net.IPNet
}

// ParseTrustedProxies parses CIDRs or bare IPs ("127.0.0.1", "10.0.0.0/8").
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
		out.nets = append(out.nets, n)
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

func firstForwardedToken(s string) string {
	if i := strings.Index(s, ","); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// ClientIP returns the real client IP: the first X-Forwarded-For /
// CF-Connecting-IP token when the peer is trusted, else the direct peer.
func (t *ProxyTrust) ClientIP(r *http.Request) string {
	if t != nil && t.IsTrustedPeer(r) {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			if ip := net.ParseIP(firstForwardedToken(cf)); ip != nil {
				return ip.String()
			}
		}
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if ip := net.ParseIP(firstForwardedToken(fwd)); ip != nil {
				return ip.String()
			}
		}
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			if ip := net.ParseIP(firstForwardedToken(real)); ip != nil {
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
			if i := strings.Index(proto, ","); i >= 0 {
				proto = strings.TrimSpace(proto[:i])
			}
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
			if i := strings.Index(h, ","); i >= 0 {
				h = strings.TrimSpace(h[:i])
			}
			if h != "" {
				return h
			}
		}
	}
	return r.Host
}

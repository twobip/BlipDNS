package dnsserver

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// clientIDFromPath extracts an optional DoH client identity from a request
// path of the form "/dns-query/{client-id}". The bare "/dns-query" path (or a
// malformed one) yields "". The identifier must match
// ^[A-Za-z0-9._-]{1,64}$: control characters, CR/LF, spaces and /?# are
// rejected (the latter also prevents path traversal into extra segments).
func clientIDFromPath(p string) string {
	p = strings.TrimPrefix(p, "/dns-query")
	p = strings.Trim(p, "/")
	if p == "" || len(p) > 64 {
		return ""
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c >= 'A' && c <= 'Z' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '.' || c == '_' || c == '-' {
			continue
		}
		return ""
	}
	return p
}

// clientIPFromReq trusts Cloudflare/forwarded headers only when the immediate
// peer belongs to an explicitly configured trusted proxy network. An empty
// list means that forwarded headers are never trusted. CF-Connecting-IP (set
// authoritatively by Cloudflare Tunnel) wins over X-Forwarded-For when both
// are present.
func clientIPFromReq(r *http.Request, trusted []*net.IPNet) net.IP {
	if len(trusted) == 0 {
		// Fast path (default): headers are never trusted, so parse RemoteAddr
		// once and skip header lookups entirely.
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return ip
			}
		}
		return net.ParseIP(r.RemoteAddr)
	}
	if isTrustedPeer(r, trusted) {
		if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
			if ip := net.ParseIP(firstToken(cf)); ip != nil {
				return ip
			}
		}
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if ip := net.ParseIP(firstToken(fwd)); ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func isTrustedPeer(r *http.Request, trusted []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(peer) {
			return true
		}
	}
	return false
}

func parseTrustedProxies(values []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy %q", value)
			}
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			} else {
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
			continue
		}
		_, n, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", value, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func firstToken(s string) string {
	if i := strings.IndexAny(s, ", "); i >= 0 {
		return s[:i]
	}
	return s
}

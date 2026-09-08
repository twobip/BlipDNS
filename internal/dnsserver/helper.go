package dnsserver

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// clientIDFromPath extracts an optional DoH client identity from a request
// path of the form "/dns-query/{client-id}". The bare "/dns-query" path (or a
// malformed one) yields "". The identifier may be a DNS label, IP, or any
// short printable token up to 64 characters.
func clientIDFromPath(p string) string {
	p = strings.TrimPrefix(p, "/dns-query")
	p = strings.Trim(p, "/")
	if p == "" || len(p) > 64 || strings.ContainsAny(p, "/?# \t") {
		return ""
	}
	return p
}

// clientIPFromReq trusts X-Forwarded-For only when the immediate peer belongs
// to an explicitly configured trusted proxy network. An empty list means that
// forwarded headers are never trusted.
func clientIPFromReq(r *http.Request, trusted []*net.IPNet) net.IP {
	if isTrustedPeer(r, trusted) {
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

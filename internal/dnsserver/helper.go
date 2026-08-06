package dnsserver

import (
	"encoding/base64"
	"net"
	"net/http"
	"strings"
)

func base64urlDecode(s string) ([]byte, error) {
	// RFC 4648 URL-safe base64, no padding.
	if len(s)%4 != 0 {
		s += string("===="[:4-len(s)%4])
	}
	return base64.URLEncoding.DecodeString(s)
}

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

func clientIPFromReq(r *http.Request) net.IP {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if ip := net.ParseIP(firstToken(fwd)); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func firstToken(s string) string {
	for i, r := range s {
		if r == ',' || r == ' ' {
			return s[:i]
		}
	}
	return s
}

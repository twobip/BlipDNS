package dnsserver

import (
	"encoding/base64"
	"net"
	"net/http"
)

func base64urlDecode(s string) ([]byte, error) {
	// RFC 4648 URL-safe base64, no padding.
	if len(s)%4 != 0 {
		s += string("===="[:4-len(s)%4])
	}
	return base64.URLEncoding.DecodeString(s)
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

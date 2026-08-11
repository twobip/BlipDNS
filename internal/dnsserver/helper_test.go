package dnsserver

import (
	"net/http"
	"testing"
)

func TestClientIPFromReqIgnoresUntrustedForwardedHeader(t *testing.T) {
	r := httptestRequest("203.0.113.10:1234", "198.51.100.7")
	got := clientIPFromReq(r, nil)
	if got == nil || got.String() != "203.0.113.10" {
		t.Fatalf("client IP = %v, want peer IP", got)
	}
}

func TestClientIPFromReqUsesTrustedForwardedHeader(t *testing.T) {
	r := httptestRequest("127.0.0.1:1234", "198.51.100.7")
	trusted, err := parseTrustedProxies([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	got := clientIPFromReq(r, trusted)
	if got == nil || got.String() != "198.51.100.7" {
		t.Fatalf("client IP = %v, want forwarded IP", got)
	}
}

func httptestRequest(remote, forwarded string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://example.test/dns-query", nil)
	r.RemoteAddr = remote
	r.Header.Set("X-Forwarded-For", forwarded)
	return r
}

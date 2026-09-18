package controller

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoHMobileConfig(t *testing.T) {
	srv := &Server{}
	get := func(query string) (int, string, http.Header) {
		req := httptest.NewRequest(http.MethodGet, "/api/doh-mobileconfig"+query, nil)
		rec := httptest.NewRecorder()
		srv.handleDoHMobileConfig(rec, req)
		return rec.Code, rec.Body.String(), rec.Header()
	}
	// Full options: host + non-default port + client ID.
	code, body, hdr := get("?host=dns.example.com&port=8443&client_id=iphone")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/x-apple-aspen-config" {
		t.Errorf("content-type = %q", ct)
	}
	if cd := hdr.Get("Content-Disposition"); !strings.Contains(cd, "doh.mobileconfig") {
		t.Errorf("content-disposition = %q", cd)
	}
	if !strings.Contains(body, "<string>https://dns.example.com:8443/dns-query/iphone</string>") {
		t.Error("ServerURL missing or wrong")
	}
	// Defaults: port omitted, no client ID.
	_, body, _ = get("?host=192.168.30.99")
	if !strings.Contains(body, "<string>https://192.168.30.99/dns-query</string>") {
		t.Error("default ServerURL wrong")
	}
	// The output must be well-formed XML (iOS rejects malformed profiles);
	// Unmarshal parses the entire document, DOCTYPE included.
	var root struct {
		XMLName xml.Name `xml:"plist"`
		Version string   `xml:"version,attr"`
	}
	if err := xml.Unmarshal([]byte(body), &root); err != nil {
		t.Errorf("profile is not well-formed XML: %v", err)
	} else if root.Version != "1.0" {
		t.Errorf("plist version = %q, want 1.0", root.Version)
	}
	// Rejects: missing host, scheme/path injection, bad port, bad client ID.
	for _, q := range []string{
		"", "?host=",
		"?host=https://dns.example.com/dns-query",
		"?host=dns.example.com:8443",
		"?host=dns.example.com&port=0",
		"?host=dns.example.com&port=99999",
		"?host=dns.example.com&port=abc",
		"?host=dns.example.com&client_id=a/b",
		"?host=dns.example.com&client_id=" + strings.Repeat("x", 65),
	} {
		if code, _, _ := get(q); code != http.StatusBadRequest {
			t.Errorf("query %q status = %d, want 400", q, code)
		}
	}
}

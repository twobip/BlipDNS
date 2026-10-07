package control

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// decodeBlocklistPush must accept exactly what Client.SetBlocklist sends
// (including null for nil slices) and abort oversized pushes mid-stream.
func TestDecodeBlocklistPush(t *testing.T) {
	// Wire shape, as marshalled by Client.SetBlocklist.
	body, _ := json.Marshal(SetBlocklistRequest{Domains: []string{"a.test", "b.test"}})
	req, err := decodeBlocklistPush(strings.NewReader(string(body)))
	if err != nil || len(req.Domains) != 2 || req.Domains[0] != "a.test" {
		t.Fatalf("wire body -> %+v, err=%v", req, err)
	}
	// Nil slices marshal as null: clearing a list must still decode.
	body, _ = json.Marshal(SetBlocklistRequest{})
	if req, err = decodeBlocklistPush(strings.NewReader(string(body))); err != nil || len(req.Domains) != 0 {
		t.Fatalf("null lists -> %+v, err=%v", req, err)
	}
	// Over-cap aborts with the sentinel, not a generic error.
	big := `{"domains":[` + strings.Repeat(`"a.test",`, maxPushDomains+1) + `"z.test"]}`
	if _, err = decodeBlocklistPush(strings.NewReader(big)); err != errBlocklistTooLarge {
		t.Fatalf("over-cap err = %v, want sentinel", err)
	}
	// Oversize element and non-object are plain bad requests.
	if _, err = decodeBlocklistPush(strings.NewReader(`{"domains":["` + strings.Repeat("x", maxPushEntryLen+1) + `"]}`)); err == nil || err == errBlocklistTooLarge {
		t.Fatalf("oversize element err = %v", err)
	}
	if _, err = decodeBlocklistPush(strings.NewReader(`[1,2]`)); err == nil {
		t.Fatal("non-object accepted")
	}
	// Unknown fields are ignored, matching encoding/json into the struct.
	if req, err = decodeBlocklistPush(strings.NewReader(`{"domains":[],"zzz":123}`)); err != nil {
		t.Fatalf("unknown field err = %v", err)
	}
}

// EncodeBlocklistPayload + decodeBlocklistBody must round-trip: the gzipped
// wire form the client sends decodes identically to plain, at a fraction of
// the bytes. Corrupt gzip must error, not panic.
func TestBlocklistPushGzipRoundTrip(t *testing.T) {
	domains := make([]string, 0, 2000)
	for i := range 2000 {
		domains = append(domains, fmt.Sprintf("host-%d.ads.example.com", i))
	}
	plain, gzipped, err := EncodeBlocklistPayload(domains, []string{"ok.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(gzipped)*2 >= len(plain) {
		t.Fatalf("gzip ratio too poor: plain=%d gz=%d", len(plain), len(gzipped))
	}
	// Gunzip must byte-match the plain body.
	zr, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		t.Fatal(err)
	}
	unzipped, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unzipped, plain) {
		t.Fatal("gunzip(encode(x)) != encode(x)")
	}
	// Handler path decodes gzipped and plain identically.
	for _, tc := range []struct {
		name string
		body []byte
		enc  string
	}{
		{"plain", plain, ""},
		{"gzip", gzipped, "gzip"},
	} {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/blocklist", bytes.NewReader(tc.body))
		if tc.enc != "" {
			req.Header.Set("Content-Encoding", tc.enc)
		}
		got, err := decodeBlocklistBody(httptest.NewRecorder(), req)
		if err != nil {
			t.Fatalf("%s: err=%v", tc.name, err)
		}
		if len(got.Domains) != len(domains) || len(got.Allowed) != 1 || got.Allowed[0] != "ok.test" {
			t.Fatalf("%s: decoded %d domains %d allowed", tc.name, len(got.Domains), len(got.Allowed))
		}
	}
	// Corrupt gzip errors.
	bad := httptest.NewRequest(http.MethodPut, "/api/v1/blocklist", strings.NewReader("not-gzip-bytes"))
	bad.Header.Set("Content-Encoding", "gzip")
	if _, err := decodeBlocklistBody(httptest.NewRecorder(), bad); err == nil {
		t.Fatal("corrupt gzip accepted")
	}
}

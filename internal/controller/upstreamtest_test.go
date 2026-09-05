package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/twobip/BlipDNS/internal/upstream"
)

// authedUpstreamTestServer logs in and returns a client request helper carrying
// the session cookie.
func authedUpstreamTestServer(t *testing.T) (string, func(method, path, body string) *http.Response) {
	t.Helper()
	srv := NewServer("admin", "hunter2", NewFleet(""), nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	login, err := http.Post(ts.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"hunter2"}`))
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", login.StatusCode)
	}
	jar := login.Cookies()
	do := func(method, path, body string) *http.Response {
		var rdr *strings.Reader
		if body == "" {
			rdr = strings.NewReader("")
		} else {
			rdr = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		for _, c := range jar {
			req.AddCookie(c)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	return ts.URL, do
}

func TestUpstreamTestEndpoint(t *testing.T) {
	url, do := authedUpstreamTestServer(t)

	// Unauthenticated: rejected.
	resp, err := http.Post(url+"/api/upstream/test", "application/json",
		strings.NewReader(`{"servers":[{"address":"udp://9.9.9.9:53"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", resp.StatusCode)
	}

	// Wrong method.
	resp = do(http.MethodGet, "/api/upstream/test", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", resp.StatusCode)
	}

	// Empty server list.
	resp = do(http.MethodPost, "/api/upstream/test", `{"servers":[]}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty status = %d, want 400", resp.StatusCode)
	}

	// Bad-spec server probes offline: 200 with ok=false, no network touched.
	resp = do(http.MethodPost, "/api/upstream/test",
		`{"servers":[{"name":"bogus","address":"bogus://example"}],"domain":"example.com"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("probe status = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Domain  string                 `json:"domain"`
		Results []upstream.ProbeResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Domain != "example.com" {
		t.Fatalf("domain = %q, want example.com", out.Domain)
	}
	if len(out.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(out.Results))
	}
	if out.Results[0].OK || out.Results[0].Error == "" {
		t.Fatalf("bad spec should fail with error, got %+v", out.Results[0])
	}
}

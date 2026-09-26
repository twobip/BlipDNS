package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An empty source list must not clear the blocklist unless the caller opts in
// with clear:true. A UI whose source list was lost from the config PUTs its
// empty view on an unrelated save (auto-update hours) and used to wipe every
// source and domain fleet-wide.
func TestBlocklistSourcesEmptyPutRequiresClear(t *testing.T) {
	fleet := NewFleet("")
	fleet.Blocklist().FromDomains([]string{"wipe-me.example", "keep-me.example"})
	srv := NewServer("admin", "hunter2", fleet, nil)
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

	put := func(body string) int {
		req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/blocklist/sources", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		for _, c := range login.Cookies() {
			req.AddCookie(c)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := put(`{"urls":[],"auto_update_hours":4}`); got != http.StatusBadRequest {
		t.Errorf("empty source list without clear = %d, want 400", got)
	}
	if n := fleet.Blocklist().Count(); n != 2 {
		t.Errorf("blocklist after refused save = %d domains, want 2 (untouched)", n)
	}

	// A populated list still saves and replaces the sources.
	if got := put(`{"urls":["https://example.invalid/list.txt"]}`); got != http.StatusOK {
		t.Errorf("source list save = %d, want 200", got)
	}

	// clear:true is the explicit path and still empties the merged list.
	if got := put(`{"urls":[],"clear":true}`); got != http.StatusOK {
		t.Errorf("explicit clear = %d, want 200", got)
	}
	if n := fleet.Blocklist().Count(); n != 0 {
		t.Errorf("blocklist after clear = %d domains, want 0", n)
	}
}

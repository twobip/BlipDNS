package controller

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSelfUpdateEndpointAuthAndChannel(t *testing.T) {
	srv := NewServer("admin", "hunter2", NewFleet(""), nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Unauthenticated: rejected.
	resp, err := http.Post(ts.URL+"/api/update?channel=stable", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", resp.StatusCode)
	}

	// Authenticate with the session cookie.
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
	if len(jar) == 0 {
		t.Fatal("login did not set a session cookie")
	}
	client := &http.Client{}

	// Authenticated with an invalid channel: rejected before starting.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/update?channel=evil", nil)
	for _, c := range jar {
		req.AddCookie(c)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid channel status = %d, want 400", resp.StatusCode)
	}

	// GET reports the controller version without starting anything.
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/update", nil)
	for _, c := range jar {
		req.AddCookie(c)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf), "blipc/0.1.0") {
		t.Fatalf("GET body missing controller version: %s", string(buf))
	}
}

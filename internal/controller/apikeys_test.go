package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func loginSessionCookie(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "test-password-123"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("login: no session cookie")
	return nil
}

func doKeys(t *testing.T, h http.Handler, method, target string, body []byte, cookie *http.Cookie, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body == nil {
		rdr = bytes.NewReader(nil)
	} else {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestAPIKeys covers the debug-key lifecycle: create (session-only), use as
// bearer on /api/*, list hides the secret, revoke kills it, expiry kills it.
func TestAPIKeys(t *testing.T) {
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, "", "")
	h := srv.Handler()

	if rec := doKeys(t, h, http.MethodGet, "/api/keys", nil, nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth list: status=%d, want 401", rec.Code)
	}
	cookie := loginSessionCookie(t, h)

	if rec := doKeys(t, h, http.MethodGet, "/api/keys", nil, nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-cookie list: status=%d, want 401", rec.Code)
	}

	createBody, _ := json.Marshal(map[string]interface{}{"label": "ai-debug", "ttl_hours": 24})
	rec := doKeys(t, h, http.MethodPost, "/api/keys", createBody, cookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID        string    `json:"id"`
		Key       string    `json:"key"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("create: bad json: %v", err)
	}
	if created.ID == "" || !strings.HasPrefix(created.Key, "blip_") {
		t.Fatalf("create: bad id/key shape: %+v", created)
	}
	if time.Until(created.ExpiresAt) < 23*time.Hour {
		t.Fatalf("create: expiry too soon: %v", created.ExpiresAt)
	}

	// Bearer key grants API access …
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("Authorization", "Bearer "+created.Key)
	health := httptest.NewRecorder()
	h.ServeHTTP(health, req)
	if health.Code != http.StatusOK {
		t.Fatalf("bearer health: status=%d body=%s", health.Code, health.Body.String())
	}
	// … but not key management (a key must not mint keys).
	if rec := doKeys(t, h, http.MethodGet, "/api/keys", nil, nil, created.Key); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bearer list: status=%d, want 401", rec.Code)
	}

	// List shows metadata, never the secret.
	rec = doKeys(t, h, http.MethodGet, "/api/keys", nil, cookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status=%d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), created.Key) {
		t.Fatal("list leaks the secret")
	}
	var listed struct {
		Keys []APIKeyInfo `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed.Keys) != 1 || listed.Keys[0].Label != "ai-debug" {
		t.Fatalf("list: unexpected body: %s", rec.Body.String())
	}

	// Validation.
	for _, tc := range []map[string]interface{}{
		{"label": "", "ttl_hours": 24},
		{"label": "x", "ttl_hours": 0},
		{"label": "x", "ttl_hours": 721},
		{"label": strings.Repeat("x", 65), "ttl_hours": 24},
	} {
		b, _ := json.Marshal(tc)
		if rec := doKeys(t, h, http.MethodPost, "/api/keys", b, cookie, ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("create %+v: status=%d, want 400", tc, rec.Code)
		}
	}

	// Revoke kills the bearer immediately.
	if rec := doKeys(t, h, http.MethodDelete, "/api/keys?id="+created.ID, nil, cookie, ""); rec.Code != http.StatusOK {
		t.Fatalf("revoke: status=%d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("Authorization", "Bearer "+created.Key)
	health = httptest.NewRecorder()
	h.ServeHTTP(health, req)
	if health.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer: status=%d, want 401", health.Code)
	}
	if rec := doKeys(t, h, http.MethodDelete, "/api/keys?id="+created.ID, nil, cookie, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("re-revoke: status=%d, want 404", rec.Code)
	}

	// Expiry kills the bearer and Sweep purges it.
	_, short, _, err := srv.auth.CreateAPIKey("short", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if srv.auth.validAPIKey(short) {
		t.Fatal("expired key still valid")
	}
	srv.auth.Sweep()
	if got := srv.auth.ListAPIKeys(); len(got) != 0 {
		t.Fatalf("sweep left %d keys", len(got))
	}
}

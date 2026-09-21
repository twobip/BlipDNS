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

	createBody, _ := json.Marshal(map[string]interface{}{"label": "ai-debug", "ttl_hours": 24, "scope": "admin"})
	rec := doKeys(t, h, http.MethodPost, "/api/keys", createBody, cookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID        string    `json:"id"`
		Key       string    `json:"key"`
		Scope     string    `json:"scope"`
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
	// Admin bearer can mutate (settings needs no DB, so it works in any env) …
	mutReq := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader([]byte(`{}`)))
	mutReq.Header.Set("Authorization", "Bearer "+created.Key)
	mutReq.Header.Set("Content-Type", "application/json")
	mutRec := httptest.NewRecorder()
	h.ServeHTTP(mutRec, mutReq)
	// 403/401 would mean scope auth blocked us; 400 is fine (empty settings
	// body rejected by the handler, but scope passed).
	if mutRec.Code == http.StatusForbidden || mutRec.Code == http.StatusUnauthorized {
		t.Fatalf("admin bearer settings: status=%d body=%s", mutRec.Code, mutRec.Body.String())
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
	_, short, _, err := srv.auth.CreateAPIKey("short", time.Millisecond, "admin")
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

// TestAPIKeyScopes verifies read-scoped keys can read but cannot mutate, while
// admin keys keep full access.
func TestAPIKeyScopes(t *testing.T) {
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, "", "")
	h := srv.Handler()
	cookie := loginSessionCookie(t, h)

	mkKey := func(label, scope string) string {
		t.Helper()
		b, _ := json.Marshal(map[string]interface{}{"label": label, "ttl_hours": 24, "scope": scope})
		rec := doKeys(t, h, http.MethodPost, "/api/keys", b, cookie, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("create %s key: status=%d body=%s", scope, rec.Code, rec.Body.String())
		}
		var out struct {
			Key   string `json:"key"`
			Scope string `json:"scope"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Key == "" {
			t.Fatalf("create %s key: bad json: %s", scope, rec.Body.String())
		}
		if out.Scope != scope {
			t.Fatalf("create %s key: scope=%q", scope, out.Scope)
		}
		return out.Key
	}

	adminKey := mkKey("admin-key", "admin")
	readKey := mkKey("read-key", "read")

	// Invalid scope is rejected.
	b, _ := json.Marshal(map[string]interface{}{"label": "bad", "ttl_hours": 24, "scope": "root"})
	if rec := doKeys(t, h, http.MethodPost, "/api/keys", b, cookie, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad scope: status=%d, want 400", rec.Code)
	}

	doBearer := func(method, target string, body []byte, key string) *httptest.ResponseRecorder {
		t.Helper()
		var rdr *bytes.Reader
		if body == nil {
			rdr = bytes.NewReader(nil)
		} else {
			rdr = bytes.NewReader(body)
		}
		req := httptest.NewRequest(method, target, rdr)
		req.Header.Set("Authorization", "Bearer "+key)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Read key: GET allowed.
	if rec := doBearer(http.MethodGet, "/api/health", nil, readKey); rec.Code != http.StatusOK {
		t.Fatalf("read bearer GET: status=%d, want 200", rec.Code)
	}
	// Read key: POST/PUT/DELETE denied (settings needs no DB).
	if rec := doBearer(http.MethodPut, "/api/settings", []byte(`{}`), readKey); rec.Code != http.StatusForbidden {
		t.Fatalf("read bearer PUT: status=%d, want 403", rec.Code)
	}
	if rec := doBearer(http.MethodDelete, "/api/keys?id=x", nil, readKey); rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
		t.Fatalf("read bearer DELETE: status=%d, want 403/401", rec.Code)
	}
	// Admin key: PUT passes scope auth (any non-403/401 proves it; handler
	// may 400 on the empty body, which is fine).
	if rec := doBearer(http.MethodPut, "/api/settings", []byte(`{}`), adminKey); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("admin bearer PUT: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// List shows scopes, never secrets.
	rec := doKeys(t, h, http.MethodGet, "/api/keys", nil, cookie, "")
	var listed struct {
		Keys []APIKeyInfo `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed.Keys) != 2 {
		t.Fatalf("list: unexpected body: %s", rec.Body.String())
	}
	for _, k := range listed.Keys {
		if k.Scope != "admin" && k.Scope != "read" {
			t.Fatalf("list: bad scope %q", k.Scope)
		}
	}
}

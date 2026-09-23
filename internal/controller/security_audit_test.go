package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAPIKeysCSRF proves /api/keys enforces the same session CSRF checks as
// the wrapped routes: a cross-site Origin or Sec-Fetch-Site on a mutating
// call is rejected even with a valid session cookie.
func TestAPIKeysCSRF(t *testing.T) {
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, "", "")
	h := srv.Handler()
	cookie := loginSessionCookie(t, h)

	b, _ := json.Marshal(map[string]interface{}{"label": "x", "ttl_hours": 24})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(b))
	req.AddCookie(cookie)
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site Origin POST: status=%d, want 403", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(b))
	req2.AddCookie(cookie)
	req2.Header.Set("Sec-Fetch-Site", "cross-site")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("cross-site fetch POST: status=%d, want 403", rec2.Code)
	}

	// Same-origin (no Origin header, like the dashboard fetch) still works.
	req3 := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(b))
	req3.AddCookie(cookie)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("same-origin POST: status=%d body=%s, want 200", rec3.Code, rec3.Body.String())
	}
}

// TestReadKeyDeniedQueryHistory proves a read-scoped API key cannot export
// query history, client metadata, live events or upstream-error details.
func TestReadKeyDeniedQueryHistory(t *testing.T) {
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, "", "")
	h := srv.Handler()
	cookie := loginSessionCookie(t, h)

	b, _ := json.Marshal(map[string]interface{}{"label": "r", "ttl_hours": 24, "scope": "read"})
	rec := doKeys(t, h, http.MethodPost, "/api/keys", b, cookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("create read key: status=%d", rec.Code)
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Key == "" {
		t.Fatalf("create read key: bad json %s", rec.Body.String())
	}

	for _, path := range []string{"/api/queries", "/api/clients", "/api/client-names", "/api/events", "/api/upstream-errors"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+out.Key)
		r := httptest.NewRecorder()
		h.ServeHTTP(r, req)
		if r.Code != http.StatusForbidden {
			t.Errorf("read key GET %s: status=%d, want 403", path, r.Code)
		}
	}
	// Health (non-sensitive) stays readable.
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("Authorization", "Bearer "+out.Key)
	r := httptest.NewRecorder()
	h.ServeHTTP(r, req)
	if r.Code != http.StatusOK {
		t.Errorf("read key GET /api/health: status=%d, want 200", r.Code)
	}
}

// TestValidateInstanceURLRemoteHTTP proves remote management URLs are
// accepted (blipd's management API is HTTP-only, so rejecting cleartext
// would strand remote fleets with no working transport) while
// isInsecureInstanceURL flags exactly the remote-cleartext ones for the
// F-05 journal warning.
func TestValidateInstanceURLRemoteHTTP(t *testing.T) {
	for _, okURL := range []string{
		"http://127.0.0.1:8444",
		"http://localhost:8444",
		"http://[::1]:8444",
		"http://192.168.1.5:8444",
		"https://192.168.1.5:8444",
		"https://blipd.example.com:8444",
	} {
		if err := validateInstanceURL(okURL); err != nil {
			t.Errorf("validate %q: unexpected error %v", okURL, err)
		}
	}
	for _, badURL := range []string{
		"",
		"gopher://192.168.1.5:70",
		"file:///etc/passwd",
		"http://user:pass@192.168.1.5:8444",
		"http:///no-host",
	} {
		if err := validateInstanceURL(badURL); err == nil {
			t.Errorf("validate %q: expected error, got nil", badURL)
		}
	}
	insecure := map[string]bool{
		"http://127.0.0.1:8444":     false,
		"http://localhost:8444":     false,
		"http://[::1]:8444":         false,
		"https://192.168.1.5:8444":  false,
		"http://192.168.1.5:8444":   true,
		"http://10.0.0.5:8444":      true,
		"http://blipd.example:8444": true,
	}
	for raw, want := range insecure {
		if got := isInsecureInstanceURL(raw); got != want {
			t.Errorf("isInsecureInstanceURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

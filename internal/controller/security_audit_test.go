package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/twobip/BlipDNS/internal/control"
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

	for _, path := range []string{"/api/queries", "/api/clients", "/api/client-names", "/api/events", "/api/upstream-errors",
		"/api/settings", "/api/instances", "/api/records", "/api/blocklist", "/api/blocklist/export", "/api/doh-mobileconfig",
		"/api/instances/demo/policies"} {
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

// TestLoginCSRF proves /api/login enforces the same Origin check as logout:
// a cross-site POST is rejected even before credentials are examined, while
// a headerless API-style POST still reaches authentication (401, not 403)
// when StrictCSRF is off — but is rejected (403) under StrictCSRF, where a
// headerless POST is indistinguishable from a forged legacy-browser post.
func TestLoginCSRF(t *testing.T) {
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, "", "")
	h := srv.Handler()

	bad, _ := json.Marshal(map[string]interface{}{"username": "admin", "password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(bad))
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site Origin login: status=%d, want 403", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(bad))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("headerless login: status=%d, want 401", rec2.Code)
	}

	// Under StrictCSRF the same headerless POST must fail closed.
	srv.StrictCSRF = true
	req3 := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(bad))
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("strict headerless login: status=%d, want 403", rec3.Code)
	}
}

// TestStartupSeedingNeverPersists guards the prod data-loss incident where a
// startup saveConfig with a still-empty fleet overwrote controller.yaml and
// permanently wiped the configured instances. All startup seeding paths must
// touch memory only; persistence happens on explicit Add/UI actions once the
// fleet is loaded.
func TestStartupSeedingNeverPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.yaml")
	fleet := NewFleet(path)
	fleet.SetRecordsDefault([]control.RecordEntry{{Domain: "x.test", Type: "A", Value: "1.2.3.4"}})
	fleet.SetAutoUpdateHoursDefault(24)
	fleet.SetCacheDefault(100)
	fleet.SetRateLimitQPSDefault(10)
	fleet.SetDoHDefault("")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("startup seeding wrote %s (must not persist before Adds)", path)
	}
	// Seeding still takes effect in memory (reconcile distributes it later).
	if got := fleet.Records(); len(got) != 1 || got[0].Domain != "x.test" {
		t.Fatalf("seeded records not in memory: %+v", got)
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
		"http://169.254.169.254/",
		"http://169.254.169.254:80/latest/meta-data/",
		"http://[fe80::1]/",
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

// Audit 2026-10-01 #5: the instance bearer token is write-only over JSON —
// accepted on add, never serialized back in any API read.
func TestInstanceTokenNeverSerialized(t *testing.T) {
	b, err := json.Marshal(InstanceConfig{ID: "n1", URL: "http://127.0.0.1:8444", Token: "s3cr3t-token", Label: "site1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "s3cr3t-token") {
		t.Fatalf("InstanceConfig JSON discloses the token: %s", b)
	}

	// Intake still works: a token-bearing add is stored (adopted), so the
	// dashboard's manual-token flow survives json:"-".
	fake := fakeBlipd(t, "tok-1", "CODE-1",
		&control.HealthResponse{OK: true, Version: "blipd/0.1.0"},
		&control.StatsResponse{},
		&control.ListResponse{},
	)
	defer fake.Close()
	cfg := filepath.Join(t.TempDir(), "blipc.yaml")
	if err := os.WriteFile(cfg, []byte("listen: \"127.0.0.1:8500\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(cfg), nil, cfg, "")
	code, res := postInstances(t, srv, `{"id":"nt","url":"`+fake.URL+`","token":"tok-1"}`)
	if code != http.StatusOK {
		t.Fatalf("token-bearing add: status=%d (%v)", code, res)
	}
	if !srv.fleet.Adopted("nt") {
		t.Fatal("token-bearing add lost its token (intake broken by json:\"-\")")
	}
}

package controller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The setup wizard bind step persists `listen` without touching other keys.
func TestSetupListenPersistsOnlyListenKey(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "blipc.yaml")
	if err := os.WriteFile(cfg, []byte("listen: \"127.0.0.1:8500\"\nusername: \"admin\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, cfg, "")

	body := strings.NewReader(`{"listen":"0.0.0.0:8600"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/setup/listen", body)
	rec := httptest.NewRecorder()
	srv.handleSetupListen(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "0.0.0.0:8600") || !strings.Contains(rec.Body.String(), "restart_required") {
		t.Fatalf("unexpected response: %s", rec.Body.String())
	}
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `0.0.0.0:8600`) {
		t.Fatalf("listen not persisted: %s", raw)
	}
	if !strings.Contains(string(raw), "admin") {
		t.Fatalf("unrelated keys clobbered: %s", raw)
	}
}

func TestSetupListenRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "blipc.yaml")
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, cfg, "")
	for _, tc := range []struct {
		name string
		body string
	}{
		{"no port", `{"listen":"127.0.0.1"}`},
		{"bad port", `{"listen":"127.0.0.1:abc"}`},
		{"port zero", `{"listen":"127.0.0.1:0"}`},
		{"port huge", `{"listen":"127.0.0.1:99999"}`},
		{"empty host", `{"listen":":8500"}`},
		{"not json", `nope`},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/setup/listen", strings.NewReader(tc.body))
		rec := httptest.NewRecorder()
		srv.handleSetupListen(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", tc.name, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/setup/listen", nil)
	rec := httptest.NewRecorder()
	srv.handleSetupListen(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: expected 405, got %d", rec.Code)
	}
}

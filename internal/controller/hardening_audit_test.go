package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/twobip/BlipDNS/internal/upstream"
)

// TestUpstreamTestSessionOnly proves the probe oracle is not reachable with a
// bearer API key (scripts): the interactive Test button rides the session.
func TestUpstreamTestSessionOnly(t *testing.T) {
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, "", "")
	h := srv.Handler()
	cookie := loginSessionCookie(t, h)

	b, _ := json.Marshal(map[string]interface{}{"label": "a", "ttl_hours": 24, "scope": "admin"})
	rec := doKeys(t, h, http.MethodPost, "/api/keys", b, cookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("create admin key: status=%d", rec.Code)
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Key == "" {
		t.Fatalf("create admin key: bad json %s", rec.Body.String())
	}

	pb, _ := json.Marshal(map[string]interface{}{
		"servers": []upstream.UpstreamServer{{Name: "x", Address: "udp://127.0.0.1:53", Priority: 1}},
		"domain":  "example.com",
	})
	if rec := doKeys(t, h, http.MethodPost, "/api/upstream/test", pb, nil, out.Key); rec.Code != http.StatusForbidden {
		t.Fatalf("bearer probe: status=%d, want 403", rec.Code)
	}

	// Session callers still get the normal validation (cap enforced first,
	// before any network probe runs).
	many := make([]upstream.UpstreamServer, 9)
	for i := range many {
		many[i] = upstream.UpstreamServer{Address: "udp://127.0.0.1:53", Priority: 1}
	}
	mb, _ := json.Marshal(map[string]interface{}{"servers": many})
	req := httptest.NewRequest(http.MethodPost, "/api/upstream/test", bytes.NewReader(mb))
	req.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusBadRequest || !strings.Contains(rec2.Body.String(), "max 8") {
		t.Fatalf("9-server probe: status=%d body=%s, want 400 max 8", rec2.Code, rec2.Body.String())
	}
}

// TestBlocklistSourcesRejectBadURL proves invalid/internal URLs are rejected
// at save time and never persist.
func TestBlocklistSourcesRejectBadURL(t *testing.T) {
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(""), nil, "", "")
	h := srv.Handler()
	cookie := loginSessionCookie(t, h)

	for _, raw := range []string{
		`{"urls":["file:///etc/passwd"]}`,
		`{"urls":["http://169.254.169.254/latest"]}`,
		`{"urls":["ftp://example.com/list.txt"]}`,
	} {
		req := httptest.NewRequest(http.MethodPut, "/api/blocklist/sources", strings.NewReader(raw))
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("PUT %s: status=%d, want 400", raw, rec.Code)
		}
	}
	if got := srv.fleet.BlocklistSources(); len(got) != 0 {
		t.Fatalf("rejected URLs persisted: %v", got)
	}
}

// TestReadKeyDeniedHA proves HA topology is admin-only.
func TestReadKeyDeniedHA(t *testing.T) {
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

	if rec := doKeys(t, h, http.MethodGet, "/api/high-availability", nil, nil, out.Key); rec.Code != http.StatusForbidden {
		t.Fatalf("read key GET ha: status=%d, want 403", rec.Code)
	}
}

// TestSetInstanceOverrideUnknown proves overrides for unknown instances are
// rejected without persisting.
func TestSetInstanceOverrideUnknown(t *testing.T) {
	f := NewFleet("")
	qps := 50
	res := f.SetInstanceOverride(context.Background(), "ghost", &InstanceOverride{RateLimitQPS: &qps})
	if res["ghost"] != "unknown instance" {
		t.Fatalf("override ghost: %v, want unknown instance", res)
	}
	if got := f.InstanceOverrides(); len(got) != 0 {
		t.Fatalf("orphan override persisted: %v", got)
	}
}

// TestRemovePrunesOverride proves removing an instance drops its override so
// a future instance with the same id starts clean.
func TestRemovePrunesOverride(t *testing.T) {
	f := NewFleet("")
	qps := 50
	f.SetOverride("ghost", &InstanceOverride{RateLimitQPS: &qps})
	if got := f.InstanceOverrides(); len(got) != 1 {
		t.Fatalf("seeded override missing: %v", got)
	}
	f.Remove("ghost")
	if got := f.InstanceOverrides(); len(got) != 0 {
		t.Fatalf("override survived remove: %v", got)
	}
}

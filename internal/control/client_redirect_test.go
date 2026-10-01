package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Audit 2026-10-01 #6: the management client sends the admin bearer token, so
// it must never follow redirects (a following client resends Authorization
// to the target, handing the token to a sibling subdomain).
func TestClientDoesNotFollowRedirects(t *testing.T) {
	var targetHits int
	var targetAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		targetAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"version":"x"}`))
	}))
	defer target.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/health", http.StatusFound)
	}))
	defer src.Close()

	c := NewClient(src.URL, "s3cr3t")
	if _, err := c.Health(context.Background()); err == nil {
		t.Error("redirected health check should surface, not be followed silently")
	}
	if targetHits != 0 {
		t.Errorf("redirect target hit %d times (auth=%q): token would leak", targetHits, targetAuth)
	}
}

// All three transports share the no-follow policy, including the blocklist
// upload and SSE watch paths.
func TestClientRedirectPolicyOnAllTransports(t *testing.T) {
	c := NewClient("http://localhost", "s3cr3t")
	for name, hc := range map[string]*http.Client{"http": c.http, "slow": c.slow, "watch": c.watch} {
		if hc.CheckRedirect == nil {
			t.Fatalf("%s client has no redirect policy", name)
		}
		if err := hc.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
			t.Errorf("%s client follows redirects (err=%v)", name, err)
		}
	}
}

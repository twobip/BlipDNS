package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
)

// Adopting with the correct code must answer promptly. A self-deadlock here
// (handler holding adoptMu while calling a path helper that re-locks it)
// hangs until the controller's client timeout with zero server-side logs.
func TestHandleAdoptResponds(t *testing.T) {
	store := filter.NewStore(nil)
	srv := NewServerWithBlocklist("", store, cache.New(0, 0), &Counters{}, "blipd/test", blocklist.New())
	srv.ConfigureAdoption(filepath.Join(t.TempDir(), "adopted.json"), "test-1")
	srv.adoptMu.Lock()
	code := srv.claimCode
	srv.adoptMu.Unlock()
	if code == "" {
		t.Fatal("no claim code generated")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(ts.URL+"/api/v1/adopt", "application/json",
		strings.NewReader(`{"code":`+strconv.Quote(code)+`}`))
	if err != nil {
		t.Fatalf("adopt call failed: %v", err)
	}
	defer resp.Body.Close()
	var out AdoptResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !out.Adopted || out.Token == "" {
		t.Fatalf("status=%d response=%+v", resp.StatusCode, out)
	}
	if !srv.IsAdopted() {
		t.Fatal("server not marked adopted")
	}
}

// A successful adopt clears the peer's bearer brute-force failures, so
// pre-adopt tokenless polls don't 429 for minutes after adoption succeeds.
func TestHandleAdoptClearsPeerFailures(t *testing.T) {
	store := filter.NewStore(nil)
	srv := NewServerWithBlocklist("", store, cache.New(0, 0), &Counters{}, "blipd/test", blocklist.New())
	srv.ConfigureAdoption(filepath.Join(t.TempDir(), "adopted.json"), "test-1")
	srv.adoptMu.Lock()
	code := srv.claimCode
	srv.adoptMu.Unlock()
	srv.authMu.Lock()
	srv.authFails = map[string]*adoptFail{"127.0.0.1": {count: 4, until: time.Now().Add(5 * time.Minute)}}
	srv.authMu.Unlock()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(ts.URL+"/api/v1/adopt", "application/json",
		strings.NewReader(`{"code":`+strconv.Quote(code)+`}`))
	if err != nil {
		t.Fatalf("adopt call failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	srv.authMu.Lock()
	defer srv.authMu.Unlock()
	if f, ok := srv.authFails["127.0.0.1"]; ok && time.Now().Before(f.until) {
		t.Fatal("peer failure state survived a successful adopt")
	}
}

// A claim code older than claimCodeTTL must not be redeemable: leaked adopt
// bundles used to stay valid forever, and the first redeemer is pinned as the
// controller and handed the management token. Redeeming an expired code must
// rotate it (and say where the fresh one is) rather than dead-end, or a
// tokenless instance becomes unadoptable until the service restarts.
func TestHandleAdoptExpiredCodeRotates(t *testing.T) {
	store := filter.NewStore(nil)
	srv := NewServerWithBlocklist("", store, cache.New(0, 0), &Counters{}, "blipd/test", blocklist.New())
	srv.ConfigureAdoption(filepath.Join(t.TempDir(), "adopted.json"), "test-1")
	srv.adoptMu.Lock()
	old := srv.claimCode
	srv.claimIssuedAt = time.Now().Add(-claimCodeTTL - time.Minute)
	srv.adoptMu.Unlock()
	if old == "" {
		t.Fatal("no claim code generated")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := &http.Client{Timeout: 10 * time.Second}

	post := func(code string) AdoptResponse {
		t.Helper()
		resp, err := client.Post(ts.URL+"/api/v1/adopt", "application/json",
			strings.NewReader(`{"code":`+strconv.Quote(code)+`}`))
		if err != nil {
			t.Fatalf("adopt call failed: %v", err)
		}
		defer resp.Body.Close()
		var out AdoptResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	out := post(old)
	if out.Adopted {
		t.Fatal("expired code was accepted")
	}
	if !strings.Contains(out.Message, "expired") {
		t.Fatalf("message = %q, want an expiry explanation", out.Message)
	}
	if srv.IsAdopted() {
		t.Fatal("server adopted on an expired code")
	}
	fresh := srv.CurrentClaimCode()
	if fresh == "" || fresh == old {
		t.Fatalf("claim code not rotated (old=%q new=%q)", old, fresh)
	}
	if out := post(fresh); !out.Adopted || out.Token == "" {
		t.Fatalf("rotated code rejected: %+v", out)
	}
}

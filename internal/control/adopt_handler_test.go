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

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

// fakeBlipd is a minimal blipd management API for controller tests. It
// supports the claim-code adoption handshake: unauthenticated /adopt/status,
// POST /adopt with the code returns a token once, then rejects re-adopt.
func fakeBlipd(t *testing.T, token, claimCode string, health *control.HealthResponse, stats *control.StatsResponse, policies *control.ListResponse) *httptest.Server {
	t.Helper()
	var (
		mu      sync.Mutex
		adopted bool
		curCode = claimCode
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSONH(w, health)
	})
	mux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSONH(w, stats)
	})
	mux.HandleFunc("/api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		writeJSONH(w, policies)
	})
	mux.HandleFunc("/api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		var req control.SetPolicyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSONH(w, map[string]string{"ok": "set", "id": req.Policy.ID})
	})
	mux.HandleFunc("/api/v1/adopt/status", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSONH(w, control.AdoptStatus{Adopted: adopted, InstanceID: "fake", Version: "blipd/0.1.0"})
	})
	mux.HandleFunc("/api/v1/adopt", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if adopted {
			writeJSONH(w, control.AdoptResponse{Adopted: true})
			return
		}
		var req control.AdoptRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Code != curCode {
			writeJSONH(w, control.AdoptResponse{Adopted: false, Message: "invalid code"})
			return
		}
		adopted = true
		curCode = ""
		writeJSONH(w, control.AdoptResponse{Adopted: true, Token: token})
	})
	return httptest.NewServer(mux)
}

func writeJSONH(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestFleetAddAndPoll(t *testing.T) {
	tok := "test-token"
	srv := fakeBlipd(t, "test-token", "",
		&control.HealthResponse{OK: true, Version: "blipd/0.1.0"},
		&control.StatsResponse{QueriesTotal: 7, BlockedTotal: 2, Cached: 3},
		&control.ListResponse{},
	)
	defer srv.Close()

	fleet := NewFleet("/tmp/blip-test-config.yaml")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := fleet.Add(ctx, InstanceConfig{ID: "s1", URL: srv.URL, Token: tok, Label: "site1"}); err != nil {
		t.Fatal(err)
	}
	// give poll loop time
	time.Sleep(150 * time.Millisecond)

	list := fleet.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(list))
	}
	st := list[0]
	if !st.Online {
		t.Error("instance should be online")
	}
	if st.Stats == nil || st.Stats.QueriesTotal != 7 {
		t.Errorf("expected stats queries=7, got %+v", st.Stats)
	}
	if st.Health == nil || !st.Health.OK {
		t.Error("expected healthy")
	}
}

func TestFleetSetPolicy(t *testing.T) {
	tok := "t"
	srv := fakeBlipd(t, tok, "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{})
	defer srv.Close()
	fleet := NewFleet("/tmp/blip-test-config.yaml")
	ctx := context.Background()
	fleet = NewFleet("/tmp/blip-test-config.yaml")
	if err := fleet.Add(ctx, InstanceConfig{ID: "s1", URL: srv.URL, Token: tok}); err != nil {
		t.Fatal(err)
	}
	p := &control.Policy{ID: "kids", Networks: []string{"192.168.0.0/16"}, Block: []string{"ads.net"}}
	if err := fleet.SetPolicy(ctx, "s1", p); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	// the policy event is published synchronously; a subscriber receives it
	// via the backlog (live SSE clients get backlog first).
	ch, backlog := fleet.Bus().Subscribe()
	for _, e := range backlog {
		if e.Type == "policy" && e.InstanceID == "s1" {
			fleet.Bus().Unsubscribe(ch)
			return
		}
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case e := <-ch:
			if e.Type == "policy" && e.InstanceID == "s1" {
				fleet.Bus().Unsubscribe(ch)
				return
			}
		case <-deadline:
			t.Error("no policy event published")
			fleet.Bus().Unsubscribe(ch)
			return
		}
	}
}

func TestBusRingBuffer(t *testing.T) {
	b := NewBus(3)
	for i := 0; i < 5; i++ {
		b.Publish(Event{Type: "block", Domain: "x", At: time.Now()})
	}
	recent := b.Recent()
	if len(recent) != 3 {
		t.Fatalf("expected 3 buffered, got %d", len(recent))
	}
	if recent[0].Domain != "x" {
		t.Error("buffer should retain newest")
	}
	// subscribe gets backlog then live
	ch, backlog := b.Subscribe()
	if len(backlog) != 3 {
		t.Fatalf("expected 3 backlog, got %d", len(backlog))
	}
	b.Publish(Event{Type: "block", Domain: "y", At: time.Now()})
	select {
	case e := <-ch:
		if e.Domain != "y" {
			t.Errorf("expected live event, got %+v", e)
		}
	case <-time.After(time.Second):
		t.Error("no live event")
	}
	b.Unsubscribe(ch)
}

func TestServerAuth(t *testing.T) {
	fleet := NewFleet("/tmp/blip-test-config.yaml")
	srv := NewServer("admin", "secret", fleet, nil)
	// unauthenticated -> 401
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/instances", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 unauth, got %d", rec.Code)
	}
	// old Bearer token must NOT work anymore (token removed)
	req := httptest.NewRequest("GET", "/api/instances", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for Bearer token, got %d", rec2.Code)
	}
	// correct login -> 200 + session cookie
	good, _ := json.Marshal(map[string]string{"username": "admin", "password": "secret"})
	req = httptest.NewRequest("POST", "/api/login", bytes.NewReader(good))
	rec4 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec4, req)
	if rec4.Code != http.StatusOK {
		t.Fatalf("expected 200 login, got %d", rec4.Code)
	}
	cookies := rec4.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}
	var sid string
	for _, c := range cookies {
		if c.Name == sessionCookie {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no session cookie set")
	}
	// session cookie -> 200 on protected API
	req = httptest.NewRequest("GET", "/api/instances", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	rec5 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec5, req)
	if rec5.Code != http.StatusOK {
		t.Errorf("expected 200 with session cookie, got %d", rec5.Code)
	}
	// logout -> cookie invalidated
	lout := httptest.NewRequest("POST", "/api/logout", nil)
	lout.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	rec6 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec6, lout)
	req = httptest.NewRequest("GET", "/api/instances", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	rec7 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec7, req)
	if rec7.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 after logout, got %d", rec7.Code)
	}
}

// TestServerBruteForce verifies the per-IP login lockout after repeated failures.
func TestServerBruteForce(t *testing.T) {
	fleet := NewFleet("/tmp/blip-test-config.yaml")
	srv := NewServer("admin", "secret", fleet, nil)
	bad, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	for i := 0; i < maxLoginFails; i++ {
		req := httptest.NewRequest("POST", "/api/login", bytes.NewReader(bad))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 wrong login %d, got %d", i, rec.Code)
		}
	}
	// rate-limited after maxLoginFails
	req := httptest.NewRequest("POST", "/api/login", bytes.NewReader(bad))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after %d fails, got %d", maxLoginFails, rec.Code)
	}
	// even a correct password is rejected while locked out
	good, _ := json.Marshal(map[string]string{"username": "admin", "password": "secret"})
	req = httptest.NewRequest("POST", "/api/login", bytes.NewReader(good))
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for correct creds while locked, got %d", rec.Code)
	}
}

// TestServerOpenAuthClosed verifies an unconfigured (empty password) controller
// rejects all logins instead of opening the control plane.
func TestServerOpenAuthClosed(t *testing.T) {
	fleet := NewFleet("/tmp/blip-test-config.yaml")
	srv := NewServer("", "", fleet, nil)
	good, _ := json.Marshal(map[string]string{"username": "admin", "password": "secret"})
	req := httptest.NewRequest("POST", "/api/login", bytes.NewReader(good))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unconfigured auth, got %d", rec.Code)
	}
	// and the API stays locked
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, httptest.NewRequest("GET", "/api/instances", nil))
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec2.Code)
	}
}

// TestFleetAdopt verifies the claim-code bootstrap: a request-scoped Add (as
// the HTTP API does) must still leave the long-lived poll loop running on a
// background context, so the instance becomes online after adopting. It also
// checks the code is one-time (re-adopt returns no token).
func TestFleetAdopt(t *testing.T) {
	pollInterval = 100 * time.Millisecond
	defer func() { pollInterval = 5 * time.Second }()
	tok := "adopt-token"
	code := "ABCD-1234"
	srv := fakeBlipd(t, tok, code,
		&control.HealthResponse{OK: true, Version: "blipd/0.1.0"},
		&control.StatsResponse{QueriesTotal: 3},
		&control.ListResponse{},
	)
	defer srv.Close()

	fleet := NewFleet("/tmp/blip-test-config.yaml")
	// Simulate the HTTP API path: Add is invoked with a context that is
	// cancelled immediately afterwards (as r.Context() is on request return).
	addCtx, cancel := context.WithCancel(context.Background())
	err := fleet.Add(addCtx, InstanceConfig{ID: "s1", URL: srv.URL, Claim: code, Label: "site1"})
	cancel() // request ends -> ctx cancelled
	if err != nil {
		t.Fatal(err)
	}
	// The goroutine must survive the cancelled addCtx (background context).
	deadline := time.After(3 * time.Second)
	for {
		st := fleet.List()[0]
		if st.Online && st.Adopted {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("instance never came online/adopted: %+v", st)
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Re-adopt must not re-issue a token (one-time) and is idempotent: a
	// wrong code after adoption returns "already adopted", not an error.
	if err := fleet.Adopt(context.Background(), "s1", code); err != nil {
		t.Fatalf("re-adopt returned error: %v", err)
	}
	if err := fleet.Adopt(context.Background(), "s1", "WRON-G000"); err != nil {
		t.Fatalf("post-adoption re-adopt with wrong code should be idempotent, got: %v", err)
	}
	if !fleet.List()[0].Adopted {
		t.Error("instance should remain adopted")
	}
}

// TestFleetAdoptRejectsWrongCode ensures an invalid code never yields a token
// and the instance stays unadopted.
func TestFleetAdoptRejectsWrongCode(t *testing.T) {
	tok := "t2"
	code := "GOOD-0000"
	srv := fakeBlipd(t, tok, code, &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{})
	defer srv.Close()
	fleet := NewFleet("/tmp/blip-test-config.yaml")
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "s1", URL: srv.URL, Claim: "BAD-1111", Label: "site1"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	st := fleet.List()[0]
	if st.Adopted {
		t.Error("instance should NOT be adopted with a wrong code")
	}
}

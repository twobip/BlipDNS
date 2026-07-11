package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

// fakeBlipd is a minimal blipd management API for controller tests.
func fakeBlipd(t *testing.T, token string, health *control.HealthResponse, stats *control.StatsResponse, policies *control.ListResponse) *httptest.Server {
	t.Helper()
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
	return httptest.NewServer(mux)
}

func writeJSONH(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestFleetAddAndPoll(t *testing.T) {
	tok := "test-token"
	srv := fakeBlipd(t, tok,
		&control.HealthResponse{OK: true, Version: "blipd/0.1.0"},
		&control.StatsResponse{QueriesTotal: 7, BlockedTotal: 2, Cached: 3},
		&control.ListResponse{},
	)
	defer srv.Close()

	fleet := NewFleet()
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
	srv := fakeBlipd(t, tok, &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{})
	defer srv.Close()
	fleet := NewFleet()
	ctx := context.Background()
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
	fleet := NewFleet()
	srv := NewServer("secret", fleet, nil)
	// unauthenticated
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/instances", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	// with token
	req := httptest.NewRequest("GET", "/api/instances", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 with token, got %d", rec2.Code)
	}
	// token via query
	req3 := httptest.NewRequest("GET", "/api/instances?token=secret", nil)
	rec3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("expected 200 with ?token, got %d", rec3.Code)
	}
	_ = strings.TrimSpace
}

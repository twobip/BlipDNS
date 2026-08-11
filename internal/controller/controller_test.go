package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/upstream"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// policyRec records every policy pushed to a fake blipd.
type policyRec struct {
	mu      sync.Mutex
	applied []*control.Policy
}

func (r *policyRec) snapshot() []*control.Policy {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*control.Policy, len(r.applied))
	copy(out, r.applied)
	return out
}

// dohRec records every plain-HTTP DoH address pushed to a fake blipd and
// reports it back from /api/v1/stats so the controller can converge it.
type dohRec struct {
	mu    sync.Mutex
	addr  string
	calls []string
}

func (r *dohRec) applied(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addr = addr
	r.calls = append(r.calls, addr)
}

func (r *dohRec) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

// upstreamCall is one upstream pool+routes push observed by upstreamRec.
type upstreamCall struct {
	servers []upstream.UpstreamServer
	routes  []upstream.UpstreamRoute
}

// upstreamRec records every upstream pool+routes push to a fake blipd and
// reports the current set back from /api/v1/stats so the controller can
// converge a restarted instance (mirroring dohRec).
type upstreamRec struct {
	mu      sync.Mutex
	servers []upstream.UpstreamServer
	routes  []upstream.UpstreamRoute
	calls   []upstreamCall
}

func (r *upstreamRec) applied(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.servers = make([]upstream.UpstreamServer, len(servers))
	copy(r.servers, servers)
	r.routes = make([]upstream.UpstreamRoute, len(routes))
	copy(r.routes, routes)
	r.calls = append(r.calls, upstreamCall{servers, routes})
}

func (r *upstreamRec) snapshot() []upstreamCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]upstreamCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// lastUpstream returns the most recent upstream push an instance received.
func lastUpstream(r *upstreamRec) ([]upstream.UpstreamServer, []upstream.UpstreamRoute) {
	sn := r.snapshot()
	if len(sn) == 0 {
		return nil, nil
	}
	return sn[len(sn)-1].servers, sn[len(sn)-1].routes
}

// cacheCall is one cache-config push observed by cacheRec.
type cacheCall struct {
	size    int
	warm    int
	regular int
}

// recCall is one records push observed by recRec.
type recCall struct {
	records []control.RecordEntry
}

// recRec records every records push to a fake blipd, and reports the current
// set back from /api/v1/stats so the controller can converge a restarted
// instance (mirroring cacheRec/dohRec).
type recRec struct {
	mu      sync.Mutex
	records []control.RecordEntry
	calls   []recCall
}

func (r *recRec) applied(records []control.RecordEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = make([]control.RecordEntry, len(records))
	copy(r.records, records)
	r.calls = append(r.calls, recCall{records: append([]control.RecordEntry(nil), records...)})
}

func (r *recRec) snapshot() []control.RecordEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]control.RecordEntry, len(r.records))
	copy(out, r.records)
	return out
}

func (r *recRec) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// cacheRec records every cache config (size + auto-refresh) pushed to a fake
// blipd, reports the current values back from /api/v1/stats (for reconcile),
// and mirrors what an explicit purge would drop (fixed, so it is immune to
// reconcile pushes rewriting the size/warm).
type cacheRec struct {
	mu      sync.Mutex
	size    int
	warm    int
	regular int
	drop    int
	calls   []cacheCall
	purged  int
}

func (r *cacheRec) applied(size, warm, regular int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.size = size
	r.warm = warm
	r.regular = regular
	r.calls = append(r.calls, cacheCall{size, warm, regular})
}

func (r *cacheRec) snapshot() []cacheCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]cacheCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// fakeBlipd is a minimal blipd management API for controller tests. It
// supports the claim-code adoption handshake: unauthenticated /adopt/status,
// POST /adopt with the code returns a token once, then rejects re-adopt.
func fakeBlipd(t *testing.T, token, claimCode string, health *control.HealthResponse, stats *control.StatsResponse, policies *control.ListResponse) *httptest.Server {
	return fakeBlipdWithRec(t, token, claimCode, health, stats, policies, nil, nil)
}

func fakeBlipdWithRec(t *testing.T, token, claimCode string, health *control.HealthResponse, stats *control.StatsResponse, policies *control.ListResponse, rec *policyRec, doh *dohRec, recs ...interface{}) *httptest.Server {
	t.Helper()
	var (
		mu        sync.Mutex
		adopted   bool
		curCode   = claimCode
		appliedRL []int
	)
	var up *upstreamRec
	var cache *cacheRec
	var recCtrl *recRec
	for _, r := range recs {
		switch rv := r.(type) {
		case *upstreamRec:
			up = rv
		case *cacheRec:
			cache = rv
		case *recRec:
			recCtrl = rv
		}
	}
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
		st := *stats
		// Model a real blipd: the store default reflects the last pushed policy.
		if rec != nil {
			rec.mu.Lock()
			if n := len(rec.applied); n > 0 {
				st.Upstream = rec.applied[n-1].Upstream
			}
			rec.mu.Unlock()
		}
		if doh != nil {
			st.DohHTTPAddr = doh.addr
		}
		if up != nil {
			up.mu.Lock()
			st.UpstreamServers = up.servers
			st.UpstreamRoutes = up.routes
			up.mu.Unlock()
		}
		if cache != nil {
			cache.mu.Lock()
			st.CacheSize = cache.size
			st.CacheWarm = cache.warm
			st.CacheRegular = cache.regular
			cache.mu.Unlock()
		}
		if recCtrl != nil {
			st.RecordsHash = control.RecordsHash(recCtrl.snapshot())
		}
		writeJSONH(w, &st)
	})
	mux.HandleFunc("/api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		writeJSONH(w, policies)
	})
	mux.HandleFunc("/api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		var req control.SetPolicyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if rec != nil {
			rec.mu.Lock()
			rec.applied = append(rec.applied, &req.Policy)
			rec.mu.Unlock()
		}
		writeJSONH(w, map[string]string{"ok": "set", "id": req.Policy.ID})
	})
	mux.HandleFunc("/api/v1/doh", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			addr := ""
			if doh != nil {
				doh.mu.Lock()
				addr = doh.addr
				doh.mu.Unlock()
			}
			writeJSONH(w, map[string]string{"http_addr": addr})
		case http.MethodPut, http.MethodPost:
			var req control.SetDoHRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if doh != nil {
				doh.applied(req.HTTPAddr)
			}
			writeJSONH(w, map[string]string{"ok": "set", "addr": req.HTTPAddr})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/ratelimit", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			q := 0
			if len(appliedRL) > 0 {
				q = appliedRL[len(appliedRL)-1]
			}
			writeJSONH(w, map[string]int{"qps": q})
		case http.MethodPut, http.MethodPost:
			var req control.SetRateLimitRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			appliedRL = append(appliedRL, req.QPS)
			writeJSONH(w, map[string]int{"qps": req.QPS, "burst": req.Burst})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/upstream", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			servers, routes := []upstream.UpstreamServer{}, []upstream.UpstreamRoute{}
			if up != nil {
				up.mu.Lock()
				servers, routes = up.servers, up.routes
				up.mu.Unlock()
			}
			writeJSONH(w, map[string]interface{}{"servers": servers, "routes": routes})
		case http.MethodPut, http.MethodPost:
			var req control.SetUpstreamRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if up != nil {
				up.applied(req.Servers, req.Routes)
			}
			writeJSONH(w, map[string]bool{"ok": true})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/cache", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			size, warm, regular := 0, 0, 0
			if cache != nil {
				cache.mu.Lock()
				size, warm, regular = cache.size, cache.warm, cache.regular
				cache.mu.Unlock()
			}
			writeJSONH(w, map[string]int{"size": size, "warm": warm, "regular": regular})
		case http.MethodPut, http.MethodPost:
			var req control.SetCacheRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if cache != nil {
				cache.applied(req.Size, req.Warm, req.Regular)
			}
			writeJSONH(w, map[string]int{"size": req.Size, "warm": req.Warm, "regular": req.Regular})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/cache/purge", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		purged := 0
		if cache != nil {
			cache.mu.Lock()
			purged = cache.drop
			cache.mu.Unlock()
		}
		writeJSONH(w, control.PurgeCacheResponse{Purged: purged})
	})
	mux.HandleFunc("/api/v1/records", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			var current []control.RecordEntry
			if recCtrl != nil {
				current = recCtrl.snapshot()
			}
			writeJSONH(w, control.RecordsResponse{Records: current})
		case http.MethodPut, http.MethodPost:
			var req control.SetRecordsRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if recCtrl != nil {
				recCtrl.applied(req.Records)
			}
			writeJSONH(w, map[string]bool{"ok": true})
		case http.MethodDelete:
			if recCtrl != nil {
				recCtrl.applied(nil)
			}
			writeJSONH(w, map[string]bool{"ok": true})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
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

func TestParseQueryTS(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"2026-08-05 23:03:06.93714156 +0100 BST m=+90.005342660", 1785967386},
		{"2026-08-05 21:00:00", 1785963600},
		{"2026-08-05T20:00:00.123456+01:00", 1785956400},
		{"garbage", time.Time{}.Unix()},
	}
	for _, c := range cases {
		if got := parseQueryTS(c.in).Unix(); got != c.want {
			t.Errorf("parseQueryTS(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestFleetSetDefaultPolicy(t *testing.T) {
	recA, recB := &policyRec{}, &policyRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, recA, nil)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, recB, nil)
	defer srvB.Close()

	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	fleet := NewFleet(cfgPath)
	ctx := context.Background()
	if err := fleet.Add(ctx, InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(ctx, InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	up := "udp://8.8.8.8:53|2 https://1.1.1.1/dns-query|1"
	res := fleet.SetDefaultPolicy(ctx, &control.Policy{Upstream: up, BlockAction: "nxdomain"})
	if res["a"] != "ok" || res["b"] != "ok" {
		t.Fatalf("expected both instances ok, got %+v", res)
	}
	// both instances must have received the fleet default policy. The exact
	// count may exceed 1 if a poll races the synchronous push, so check that
	// every recorded push carries the fleet config.
	for name, rec := range map[string]*policyRec{"a": recA, "b": recB} {
		got := rec.snapshot()
		if len(got) < 1 {
			t.Fatalf("instance %s: expected at least 1 policy push, got %d", name, len(got))
		}
		for _, p := range got {
			if p.Upstream != up {
				t.Errorf("instance %s: upstream = %q, want %q", name, p.Upstream, up)
			}
		}
	}
	// policy must have been persisted to the controller config
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("default_policy:")) || !bytes.Contains(b, []byte(up)) {
		t.Errorf("default policy not persisted in %s:\n%s", cfgPath, b)
	}
}

func TestFleetSetDefaultPolicyReconcileOnAdd(t *testing.T) {
	rec := &policyRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, rec, nil)
	defer srv.Close()

	fleet := NewFleet("/tmp/blip-test-config.yaml")
	fleet.SetDefault(&control.Policy{Upstream: "udp://1.1.1.1:53", BlockAction: "nxdomain"})
	// instance is added AFTER the fleet config exists; it must be pushed
	// immediately (and stay applied so the poll loop doesn't duplicate it).
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // let any poll-driven re-push happen
	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 push (no duplicate from poll), got %d", len(got))
	}
	if got[0].Upstream != "udp://1.1.1.1:53" {
		t.Errorf("pushed upstream = %q", got[0].Upstream)
	}
}

func TestFleetSetDefaultPolicyRoundTrip(t *testing.T) {
	fleet := NewFleet("/tmp/blip-test-config.yaml")
	if d := fleet.DefaultPolicy(); d != nil {
		t.Fatal("expected no default policy initially")
	}
	fleet.SetDefault(&control.Policy{Upstream: "https://1.1.1.1/dns-query|1", BlockAction: "refused", Log: true})
	d := fleet.DefaultPolicy()
	if d == nil || d.Upstream != "https://1.1.1.1/dns-query|1" {
		t.Fatalf("unexpected default policy: %+v", d)
	}
	if d.ID != "default" {
		t.Errorf("expected ID normalized to default, got %q", d.ID)
	}
}

// TestFleetReconcileRestartRevert simulates a blipd restart: the instance's
// store reverts to its own (empty) config, so the controller must re-push the
// fleet default on a subsequent poll.
func TestFleetReconcileRestartRevert(t *testing.T) {
	pollInterval = 100 * time.Millisecond
	defer func() { pollInterval = 5 * time.Second }()
	rec := &policyRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, rec, nil)
	defer srv.Close()

	fleet := NewFleet("/tmp/blip-test-config.yaml")
	fleet.SetDefault(&control.Policy{Upstream: "udp://1.1.1.1:53"})
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	waitFor := func(n int, msg string) []*control.Policy {
		deadline := time.After(3 * time.Second)
		for {
			got := rec.snapshot()
			if len(got) >= n {
				return got
			}
			select {
			case <-deadline:
				t.Fatal(msg)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	waitFor(1, "initial push never happened")

	// Simulate restart revert: blipd's store loses the pushed policy.
	rec.mu.Lock()
	rec.applied = nil
	rec.mu.Unlock()

	got := waitFor(1, "no re-push after simulated restart revert")
	if got[0].Upstream != "udp://1.1.1.1:53" {
		t.Fatalf("unexpected re-push content: %+v", got[0])
	}
}

// TestFleetInstanceOverride verifies a sparse per-instance config is merged
// over the fleet default, pushed only to that instance, persisted, and that
// clearing it reverts the instance to the default.
func TestFleetInstanceOverride(t *testing.T) {
	recA, recB := &policyRec{}, &policyRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, recA, nil)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, recB, nil)
	defer srvB.Close()

	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	fleet := NewFleet(cfgPath)
	ctx := context.Background()
	if err := fleet.Add(ctx, InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(ctx, InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	defUp := "udp://1.1.1.1:53"
	ovrUp := "https://9.9.9.9/dns-query|1"
	res := fleet.SetDefaultPolicy(ctx, &control.Policy{Upstream: defUp, BlockAction: "nxdomain", Log: true})
	if res["a"] != "ok" || res["b"] != "ok" {
		t.Fatalf("expected both ok, got %+v", res)
	}
	recA.mu.Lock()
	recA.applied = nil
	recA.mu.Unlock()
	recB.mu.Lock()
	recB.applied = nil
	recB.mu.Unlock()

	// sparse override: only upstream differs; everything else falls through
	// to the default.
	res = fleet.SetInstanceOverride(ctx, "a", &InstanceOverride{Upstream: &ovrUp})
	if res["a"] != "ok" {
		t.Fatalf("expected instance a ok, got %+v", res)
	}
	got := recA.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 push to a, got %d", len(got))
	}
	if got[0].Upstream != ovrUp {
		t.Errorf("instance a upstream = %q, want override %q", got[0].Upstream, ovrUp)
	}
	if got[0].BlockAction != "nxdomain" || !got[0].Log {
		t.Errorf("override must merge default fields, got %+v", got[0])
	}
	if got[0].ID != "default" {
		t.Errorf("merged policy ID = %q, want default (store default)", got[0].ID)
	}
	if n := len(recB.snapshot()); n != 0 {
		t.Errorf("instance b must NOT receive the override, got %d pushes", n)
	}
	if o := fleet.InstanceOverrideOf("a"); o == nil || o.Upstream == nil || *o.Upstream != ovrUp {
		t.Errorf("unexpected override for a: %+v", o)
	}

	// override persisted as a sparse diff
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("instance_overrides:")) || !bytes.Contains(b, []byte(ovrUp)) {
		t.Errorf("instance override not persisted:\n%s", b)
	}

	// clearing the override reverts the instance to the fleet default
	res = fleet.SetInstanceOverride(ctx, "a", &InstanceOverride{})
	if res["a"] != "ok" {
		t.Fatalf("expected clear ok, got %+v", res)
	}
	if o := fleet.InstanceOverrideOf("a"); o != nil {
		t.Errorf("override should be removed after clear, got %+v", o)
	}
	got = recA.snapshot()
	if len(got) != 2 {
		t.Fatalf("expected 1 push after clear (back to default), got %d", len(got))
	}
	if got[1].Upstream != defUp {
		t.Errorf("instance a upstream after clear = %q, want default %q", got[1].Upstream, defUp)
	}
}

// TestFleetConfigSynced verifies the ConfigSynced status flag: false until the
// first poll pushes the effective config, then true and stable.
func TestFleetConfigSynced(t *testing.T) {
	pollInterval = 100 * time.Millisecond
	defer func() { pollInterval = 5 * time.Second }()
	rec := &policyRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, rec, nil)
	defer srv.Close()

	fleet := NewFleet("/tmp/blip-test-config.yaml")
	fleet.SetDefault(&control.Policy{Upstream: "udp://1.1.1.1:53", BlockAction: "nxdomain"})
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	// not synced until the first reconcile push lands
	if st := fleet.List()[0]; st.ConfigSynced {
		t.Error("expected not synced before first push")
	}
	deadline := time.After(3 * time.Second)
	for {
		if st := fleet.List()[0]; st.ConfigSynced {
			break
		}
		select {
		case <-deadline:
			t.Fatal("instance never reported synced")
		case <-time.After(20 * time.Millisecond):
		}
	}
	// stable across further polls
	time.Sleep(150 * time.Millisecond)
	if st := fleet.List()[0]; !st.ConfigSynced {
		t.Error("expected still synced after subsequent polls")
	}
}

// TestAggregateStats verifies persisted stats survive restarts: deltas between
// consecutive samples are summed, and a counter decrease (instance restart) is
// treated as a fresh baseline rather than a negative delta.
func TestAggregateStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.db")
	store, err := NewQueryLogStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	// base on a 30s boundary so bucket grouping is deterministic
	base := time.Unix(time.Now().Unix()/30*30, 0).Add(-2 * time.Hour)
	add := func(off time.Duration, q, b, e uint64) {
		if err := store.AddStatsSample(ctx, StatsSample{Timestamp: base.Add(off), Instance: "a", Queries: q, Blocked: b, Errors: e}); err != nil {
			t.Fatal(err)
		}
	}
	add(0, 100, 5, 1)
	add(10*time.Second, 130, 7, 2)
	add(20*time.Second, 200, 20, 5)
	add(30*time.Second, 40, 2, 1) // instance restarted: counters dropped
	add(40*time.Second, 70, 4, 2)

	agg, err := store.AggregateStats(ctx, "", 30*time.Second, base)
	if err != nil {
		t.Fatal(err)
	}
	if agg.TotalQueries != 170 {
		t.Errorf("total_queries = %d, want 170", agg.TotalQueries)
	}
	if agg.BlockedQueries != 19 {
		t.Errorf("blocked_queries = %d, want 19", agg.BlockedQueries)
	}
	if agg.UpstreamErrors != 6 {
		t.Errorf("upstream_errors = %d, want 6", agg.UpstreamErrors)
	}
	// Samples span 40s (t=0 → t=40) with 170 queries: avg = 170/40 = 4.25 qps.
	if want := 170.0 / 40.0; agg.AvgQPS != want {
		t.Errorf("avg_qps = %v, want %v", agg.AvgQPS, want)
	}
	if pi := agg.PerInstance["a"]; pi == nil || pi.Queries != 170 {
		t.Errorf("per-instance a = %+v, want queries 170", pi)
	}
	if len(agg.Series) != 2 {
		t.Fatalf("expected 2 buckets, got %d: %+v", len(agg.Series), agg.Series)
	}
	// series must be sorted and sum back to the totals
	var sumQ, sumB int
	for i, p := range agg.Series {
		sumQ += p.TotalQueries
		sumB += p.BlockedQueries
		if i > 0 && agg.Series[i-1].Timestamp.After(p.Timestamp) {
			t.Error("series not sorted by timestamp")
		}
	}
	if sumQ != agg.TotalQueries || sumB != agg.BlockedQueries {
		t.Errorf("series sums %d/%d != totals %d/%d", sumQ, sumB, agg.TotalQueries, agg.BlockedQueries)
	}

	// A window starting at the last sample must produce zero (no baseline yet).
	agg2, err := store.AggregateStats(ctx, "", time.Minute, base.Add(50*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if agg2.TotalQueries != 0 {
		t.Errorf("expected empty window totals, got %d", agg2.TotalQueries)
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

func TestServerFirstRunUI(t *testing.T) {
	fleet := NewFleet("")
	unconfigured := NewServerWithConfig("", "", fleet, UI(), "", "ui-setup-token")
	rec := httptest.NewRecorder()
	unconfigured.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("Set up your BlipDNS console")) {
		t.Fatalf("unconfigured root: status=%d body=%s", rec.Code, rec.Body.String())
	}
	asset := httptest.NewRecorder()
	unconfigured.Handler().ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/setup.js", nil))
	if asset.Code != http.StatusOK || !bytes.Contains(asset.Body.Bytes(), []byte("/api/setup")) {
		t.Fatalf("setup asset: status=%d body=%s", asset.Code, asset.Body.String())
	}
	configured := NewServerWithConfig("admin", "correct horse", fleet, UI(), "", "")
	redirect := httptest.NewRecorder()
	configured.Handler().ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "/", nil))
	if redirect.Code != http.StatusFound || redirect.Header().Get("Location") != "/login" {
		t.Fatalf("configured root: status=%d location=%q", redirect.Code, redirect.Header().Get("Location"))
	}
}

func TestServerFirstRunSetup(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	initial := []byte("listen: \"127.0.0.1:8500\"\ndefault_policy:\n  id: default\n  block_action: nxdomain\n")
	if err := os.WriteFile(cfgPath, initial, 0600); err != nil {
		t.Fatal(err)
	}
	fleet := NewFleet(cfgPath)
	setupToken := "test-setup-token"
	srv := NewServerWithConfig("", "", fleet, nil, cfgPath, setupToken)
	body, _ := json.Marshal(map[string]string{
		"token":    setupToken,
		"username": "admin",
		"password": "correct horse",
		"confirm":  "correct horse",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, body=%s", rec.Code, rec.Body.String())
	}
	cookie := rec.Result().Cookies()[0]
	if cookie.Name != sessionCookie || cookie.Value == "" {
		t.Fatalf("expected setup session cookie, got %+v", cookie)
	}
	protected := httptest.NewRequest(http.MethodGet, "/api/instances", nil)
	protected.AddCookie(cookie)
	protectedRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(protectedRec, protected)
	if protectedRec.Code != http.StatusOK {
		t.Fatalf("setup session status = %d", protectedRec.Code)
	}
	again := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(body))
	againRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(againRec, again)
	if againRec.Code != http.StatusForbidden {
		t.Fatalf("second setup status = %d, want 403", againRec.Code)
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Username     string `yaml:"username"`
		Password     string `yaml:"password"`
		PasswordHash string `yaml:"password_hash"`
	}
	if err := yaml.Unmarshal(b, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Username != "admin" || saved.Password != "" || saved.PasswordHash == "" {
		t.Fatalf("saved credentials = %+v", saved)
	}
	if bcrypt.CompareHashAndPassword([]byte(saved.PasswordHash), []byte("correct horse")) != nil {
		t.Fatal("saved password hash does not validate")
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

// TestFleetSetDoHHTTPAddr verifies the fleet-wide plain-HTTP DoH address is
// pushed to every instance, then persisted to the controller config.
func TestFleetSetDoHHTTPAddr(t *testing.T) {
	dohA, dohB := &dohRec{}, &dohRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, dohA)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, dohB)
	defer srvB.Close()

	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	fleet := NewFleet(cfgPath)
	ctx := context.Background()
	if err := fleet.Add(ctx, InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(ctx, InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	res := fleet.SetDoHHTTPAddr(ctx, "0.0.0.0:8445")
	if res["a"] != "ok" || res["b"] != "ok" {
		t.Fatalf("expected both ok, got %+v", res)
	}
	// Each instance must have received the address (possibly twice: once from
	// the initial poll reconcile and once from the explicit fleet-wide push).
	lastDoh := func(r *dohRec) string {
		s := r.snapshot()
		if len(s) == 0 {
			t.Helper()
			return ""
		}
		return s[len(s)-1]
	}
	if last := lastDoh(dohA); last != "0.0.0.0:8445" {
		t.Errorf("instance a last doh push = %q, want 0.0.0.0:8445 (history=%v)", last, dohA.snapshot())
	}
	if last := lastDoh(dohB); last != "0.0.0.0:8445" {
		t.Errorf("instance b last doh push = %q, want 0.0.0.0:8445 (history=%v)", last, dohB.snapshot())
	}
	if fleet.DoHHTTPAddr() != "0.0.0.0:8445" {
		t.Errorf("fleet DoHHTTPAddr = %q", fleet.DoHHTTPAddr())
	}
	// persisted to the controller config
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("doh_http_addr:")) || !bytes.Contains(b, []byte("0.0.0.0:8445")) {
		t.Errorf("doh_http_addr not persisted:\n%s", b)
	}
}

// TestFleetDoHReconcileRestartRevert simulates a blipd restart that reverts the
// plain-HTTP DoH listener to off; the controller must re-push the fleet value.
func TestFleetDoHReconcileRestartRevert(t *testing.T) {
	pollInterval = 100 * time.Millisecond
	defer func() { pollInterval = 5 * time.Second }()
	doh := &dohRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, doh)
	defer srv.Close()

	fleet := NewFleet("/tmp/blip-test-config.yaml")
	fleet.SetDoHDefault("0.0.0.0:8445")
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	// initial push from Add (via poll reconcile) lands the fleet value.
	waitForDoh := func(n int, msg string) {
		deadline := time.After(3 * time.Second)
		for {
			if len(doh.snapshot()) >= n {
				return
			}
			select {
			case <-deadline:
				t.Fatal(msg)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	waitForDoh(1, "initial doh push never happened")

	// Simulate restart revert: blipd forgot the address.
	doh.mu.Lock()
	doh.addr = ""
	doh.mu.Unlock()

	waitForDoh(2, "no re-push after simulated restart revert")
	if got := doh.snapshot(); got[len(got)-1] != "0.0.0.0:8445" {
		t.Errorf("last doh push = %q, want 0.0.0.0:8445", got[len(got)-1])
	}
}

// TestFleetDoHOverride verifies a per-instance DoH override is pushed to that
// instance only; other instances keep the fleet value.
func TestFleetDoHOverride(t *testing.T) {
	dohA, dohB := &dohRec{}, &dohRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, dohA)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, dohB)
	defer srvB.Close()

	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	fleet := NewFleet(cfgPath)
	ctx := context.Background()
	if err := fleet.Add(ctx, InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(ctx, InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	addr := "0.0.0.0:9999"
	aOvr := addr
	res := fleet.SetInstanceOverride(ctx, "a", &InstanceOverride{DoHHTTPAddr: &aOvr})
	if res["a"] != "ok" {
		t.Fatalf("expected a ok, got %+v", res)
	}
	// Instance a must have received its override address at least once; other
	// instances keep the fleet value ("" here) and receive no address.
	lastDoh := func(r *dohRec) string {
		sn := r.snapshot()
		if len(sn) == 0 {
			return ""
		}
		return sn[len(sn)-1]
	}
	if last := lastDoh(dohA); last != addr {
		t.Errorf("instance a last doh = %q, want %q (history=%v)", last, addr, dohA.snapshot())
	}
	if len(dohB.snapshot()) != 0 {
		t.Errorf("instance b should receive no doh push, got %v", dohB.snapshot())
	}
	if o := fleet.InstanceOverrideOf("a"); o == nil || o.DoHHTTPAddr == nil || *o.DoHHTTPAddr != addr {
		t.Errorf("override for a = %+v", o)
	}
	// clearing the override reverts the instance to the fleet default
	if res := fleet.SetInstanceOverride(ctx, "a", &InstanceOverride{}); res["a"] != "ok" {
		t.Fatalf("expected clear ok, got %+v", res)
	}
	if o := fleet.InstanceOverrideOf("a"); o != nil && !o.IsEmpty() {
		t.Errorf("override should be removed after clear, got %+v", o)
	}
}

// TestFleetSetCache verifies the fleet-wide response-cache config (max size +
// auto-refresh count) is pushed to every instance and persisted to the
// controller config.
func TestFleetSetCache(t *testing.T) {
	cacheA, cacheB := &cacheRec{}, &cacheRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, cacheA)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, cacheB)
	defer srvB.Close()

	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	fleet := NewFleet(cfgPath)
	ctx := context.Background()
	if err := fleet.Add(ctx, InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(ctx, InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	res := fleet.SetCache(ctx, 5000, 10, 3600)
	if res["a"] != "ok" || res["b"] != "ok" {
		t.Fatalf("expected both ok, got %+v", res)
	}
	last := func(r *cacheRec) cacheCall {
		sn := r.snapshot()
		if len(sn) == 0 {
			return cacheCall{}
		}
		return sn[len(sn)-1]
	}
	if got := last(cacheA); got.size != 5000 || got.warm != 10 || got.regular != 3600 {
		t.Errorf("instance a last cache push = %+v, want 5000/10/3600 (history=%v)", got, cacheA.snapshot())
	}
	if got := last(cacheB); got.size != 5000 || got.warm != 10 || got.regular != 3600 {
		t.Errorf("instance b last cache push = %+v, want 5000/10/3600 (history=%v)", got, cacheB.snapshot())
	}
	if s, w, reg := fleet.CacheConfig(); s != 5000 || w != 10 || reg != 3600 {
		t.Errorf("fleet CacheConfig = %d/%d/%d, want 5000/10/3600", s, w, reg)
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("cache_size:")) || !bytes.Contains(b, []byte("5000")) || !bytes.Contains(b, []byte("cache_warm:")) || !bytes.Contains(b, []byte("10")) || !bytes.Contains(b, []byte("cache_regular:")) || !bytes.Contains(b, []byte("3600")) {
		t.Errorf("cache config not persisted:\n%s", b)
	}
}

// TestFleetCacheReconcileRestartRevert simulates a blipd restart that reverts
// the cache config to 0/off; the controller must re-push the fleet default on a
// subsequent poll.
func TestFleetCacheReconcileRestartRevert(t *testing.T) {
	pollInterval = 100 * time.Millisecond
	defer func() { pollInterval = 5 * time.Second }()
	cache := &cacheRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, cache)
	defer srv.Close()

	fleet := NewFleet("/tmp/blip-test-config.yaml")
	fleet.SetCacheDefault(5000, 10, 3600)
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	waitFor := func(n int, msg string) []cacheCall {
		deadline := time.After(3 * time.Second)
		for {
			got := cache.snapshot()
			if len(got) >= n {
				return got
			}
			select {
			case <-deadline:
				t.Fatal(msg)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	waitFor(1, "initial cache push never happened")

	// Simulate restart revert: blipd's cache reverts to default (0/off).
	cache.mu.Lock()
	cache.size, cache.warm, cache.regular = 0, 0, 0
	cache.mu.Unlock()

	got := waitFor(2, "no re-push after simulated restart revert")
	last := got[len(got)-1]
	if last.size != 5000 || last.warm != 10 || last.regular != 3600 {
		t.Fatalf("unexpected re-push content: %+v", last)
	}
}

// TestFleetCacheNotConfiguredDefersToInstance verifies that when the operator
// hasn't configured any cache setting in the controller (neither fleet-wide via
// SetCacheDefault nor a per-instance override), the reconcile loop does NOT push
// 0/0/0 to the instance — blipd keeps its own YAML defaults (e.g. 10000/100).
func TestFleetCacheNotConfiguredDefersToInstance(t *testing.T) {
	pollInterval = 100 * time.Millisecond
	defer func() { pollInterval = 5 * time.Second }()
	// Simulate blipd's own config defaults persisted from its YAML.
	cache := &cacheRec{size: 10000, warm: 100, regular: 0}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, cache)
	defer srv.Close()

	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))
	// NOTE: deliberately NOT calling SetCacheDefault — no fleet-wide cache config.
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	// Give the poll/reconcile loop time to run. It should NOT push cache config.
	time.Sleep(500 * time.Millisecond)
	if got := cache.snapshot(); len(got) != 0 {
		t.Fatalf("expected no cache push when unconfigured, got %d calls: %+v", len(got), got)
	}
	cache.mu.Lock()
	if cache.size != 10000 || cache.warm != 100 || cache.regular != 0 {
		t.Errorf("instance cache overridden to %d/%d/%d, want 10000/100/0 (blipd defaults preserved)", cache.size, cache.warm, cache.regular)
	}
	cache.mu.Unlock()
}

// TestFleetCacheOverride verifies a sparse per-instance cache config is merged
// over the fleet default, pushed only to that instance, and that clearing it
// reverts the instance to the fleet default.
func TestFleetCacheOverride(t *testing.T) {
	cacheA, cacheB := &cacheRec{}, &cacheRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, cacheA)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, cacheB)
	defer srvB.Close()

	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))
	fleet.SetCacheDefault(5000, 10, 3600)
	ctx := context.Background()
	if err := fleet.Add(ctx, InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(ctx, InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	last := func(r *cacheRec) cacheCall {
		sn := r.snapshot()
		if len(sn) == 0 {
			return cacheCall{}
		}
		return sn[len(sn)-1]
	}
	// Give the initial push a moment to land so the per-instance one is last.
	deadline := time.After(3 * time.Second)
	for len(cacheA.snapshot()) < 1 || len(cacheB.snapshot()) < 1 {
		select {
		case <-deadline:
			t.Fatal("initial cache push never happened")
		case <-time.After(20 * time.Millisecond):
		}
	}

	size, warm := 1000, 3
	res := fleet.SetInstanceOverride(ctx, "a", &InstanceOverride{CacheSize: &size, CacheWarm: &warm})
	if res["a"] != "ok" {
		t.Fatalf("expected a ok, got %+v", res)
	}
	if got := last(cacheA); got.size != 1000 || got.warm != 3 {
		t.Errorf("instance a last cache push = %+v, want 1000/3 (history=%v)", got, cacheA.snapshot())
	}
	// instance b keeps the fleet default
	if got := last(cacheB); got.size != 5000 || got.warm != 10 {
		t.Errorf("instance b last cache push = %+v, want 5000/10", got)
	}
	if o := fleet.InstanceOverrideOf("a"); o == nil || o.CacheSize == nil || *o.CacheSize != 1000 {
		t.Errorf("override for a = %+v", o)
	}
	// clearing the override reverts the instance to the fleet default
	if res := fleet.SetInstanceOverride(ctx, "a", &InstanceOverride{}); res["a"] != "ok" {
		t.Fatalf("expected clear ok, got %+v", res)
	}
	if o := fleet.InstanceOverrideOf("a"); o != nil && !o.IsEmpty() {
		t.Errorf("override should be removed after clear, got %+v", o)
	}
}

// TestFleetPurgeCache verifies a fleet-wide cache purge is sent to every
// instance and the total count of dropped entries is summed.
func TestFleetPurgeCache(t *testing.T) {
	cacheA, cacheB := &cacheRec{drop: 40}, &cacheRec{drop: 12}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, cacheA)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, cacheB)
	defer srvB.Close()

	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	applied, total := fleet.PurgeCache(context.Background())
	if applied["a"] != "ok" || applied["b"] != "ok" {
		t.Fatalf("expected both ok, got %+v", applied)
	}
	if total != 42+10 {
		t.Errorf("total purged = %d, want 52", total)
	}
}

// TestServerSettingsCacheFleet exercises the /api/settings GET+PUT round trip
// for the fleet-wide cache config (size + auto-refresh) with a live instance.
func TestServerSettingsCacheFleet(t *testing.T) {
	cacheA := &cacheRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, cacheA)
	defer srv.Close()

	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer("admin", "secret", fleet, nil)
	c := newAuthedClient(t, s)

	resp, err := c.Get("/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d["cache_size"] != float64(0) || d["cache_warm"] != float64(0) {
		t.Errorf("initial cache config = %v/%v, want 0/0", d["cache_size"], d["cache_warm"])
	}

	body, _ := json.Marshal(map[string]int{"cache_size": 5000, "cache_warm": 10})
	req, _ := http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ack map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ack["ok"] != true {
		t.Fatalf("PUT ok = %v", ack["ok"])
	}
	applied := ack["applied"].(map[string]interface{})
	if applied["a"] != "ok" {
		t.Errorf("applied a = %v", applied["a"])
	}
	hist := cacheA.snapshot()
	if len(hist) == 0 || hist[len(hist)-1].size != 5000 || hist[len(hist)-1].warm != 10 {
		t.Errorf("cache pushes = %v, want last 5000/10", hist)
	}
	resp, _ = c.Get("/api/settings")
	json.NewDecoder(resp.Body).Decode(&d)
	resp.Body.Close()
	if d["cache_size"] != float64(5000) || d["cache_warm"] != float64(10) {
		t.Errorf("read-back cache config = %v/%v, want 5000/10", d["cache_size"], d["cache_warm"])
	}

	// negative values are rejected
	body, _ = json.Marshal(map[string]int{"cache_size": -1, "cache_warm": 0})
	req, _ = http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("negative cache status = %d, want 400", resp.StatusCode)
	}
}

// TestFleetSetUpstream verifies a fleet-wide upstream pool + conditional
// forwarding routes are pushed to every instance and persisted to the
// controller config.
func TestFleetSetUpstream(t *testing.T) {
	upA, upB := &upstreamRec{}, &upstreamRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, upA)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, upB)
	defer srvB.Close()

	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	fleet := NewFleet(cfgPath)
	ctx := context.Background()
	if err := fleet.Add(ctx, InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(ctx, InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	servers := []upstream.UpstreamServer{
		{Name: "quad9", Address: "udp://9.9.9.9:53", Priority: 1},
		{Name: "rr", Address: "udp://10.1.1.1:53"},
	}
	routes := []upstream.UpstreamRoute{
		{Name: "corp", QnameSuffix: ".corp.", Server: "rr", ClientCIDR: "10.0.0.0/8"},
	}
	res := fleet.SetUpstream(ctx, servers, routes)
	if res["a"] != "ok" || res["b"] != "ok" {
		t.Fatalf("expected both ok, got %+v", res)
	}
	// Each instance must have received the pool (possibly twice: once from the
	// initial poll reconcile and once from the explicit fleet-wide push).
	if gotS, gotR := lastUpstream(upA); !reflect.DeepEqual(gotS, servers) || !reflect.DeepEqual(gotR, routes) {
		t.Errorf("instance a upstream = %+v / %+v, want %+v / %+v", gotS, gotR, servers, routes)
	}
	if gotS, gotR := lastUpstream(upB); !reflect.DeepEqual(gotS, servers) || !reflect.DeepEqual(gotR, routes) {
		t.Errorf("instance b upstream = %+v / %+v, want %+v / %+v", gotS, gotR, servers, routes)
	}
	gotS, gotR := fleet.Upstream()
	if !reflect.DeepEqual(gotS, servers) || !reflect.DeepEqual(gotR, routes) {
		t.Errorf("fleet.Upstream = %+v / %+v", gotS, gotR)
	}
	// persisted to the controller config
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("upstream_servers:")) || !bytes.Contains(b, []byte("udp://9.9.9.9:53")) {
		t.Errorf("upstream_servers not persisted:\n%s", b)
	}
	if !bytes.Contains(b, []byte("upstream_routes:")) || !bytes.Contains(b, []byte(".corp.")) {
		t.Errorf("upstream_routes not persisted:\n%s", b)
	}
}

// TestFleetUpstreamReconcileRestartRevert simulates a blipd restart that
// reverts the upstream pool to off; the controller must re-push the fleet value.
func TestFleetUpstreamReconcileRestartRevert(t *testing.T) {
	pollInterval = 100 * time.Millisecond
	defer func() { pollInterval = 5 * time.Second }()
	up := &upstreamRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, up)
	defer srv.Close()

	servers := []upstream.UpstreamServer{{Name: "quad9", Address: "udp://9.9.9.9:53", Priority: 1}}
	fleet := NewFleet("/tmp/blip-test-config.yaml")
	fleet.SetUpstreamDefault(servers, nil)
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	// initial push from Add (via poll reconcile) lands the fleet value.
	waitForUp := func(n int, msg string) {
		deadline := time.After(3 * time.Second)
		for {
			if len(up.snapshot()) >= n {
				return
			}
			select {
			case <-deadline:
				t.Fatal(msg)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	waitForUp(1, "initial upstream push never happened")

	// Simulate restart revert: blipd forgot the pushed pool.
	up.mu.Lock()
	up.servers = nil
	up.routes = nil
	up.mu.Unlock()

	waitForUp(2, "no re-push after simulated restart revert")
	if gotS, _ := lastUpstream(up); !reflect.DeepEqual(gotS, servers) {
		t.Errorf("last upstream push = %+v, want %+v", gotS, servers)
	}
}

// TestFleetUpstreamOverride verifies a per-instance upstream override is pushed
// to that instance only; other instances keep the fleet value.
func TestFleetUpstreamOverride(t *testing.T) {
	upA, upB := &upstreamRec{}, &upstreamRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, upA)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, upB)
	defer srvB.Close()

	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	fleet := NewFleet(cfgPath)
	ctx := context.Background()
	if err := fleet.Add(ctx, InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(ctx, InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	servers := []upstream.UpstreamServer{{Name: "cloudflare", Address: "udp://1.1.1.1:53", Priority: 1}}
	if res := fleet.SetInstanceOverride(ctx, "a", &InstanceOverride{UpstreamServers: &servers}); res["a"] != "ok" {
		t.Fatalf("expected a ok, got %+v", res)
	}
	// Instance a must have received its override pool; b (fleet default empty)
	// receives no upstream push.
	if gotS, _ := lastUpstream(upA); !reflect.DeepEqual(gotS, servers) {
		t.Errorf("instance a upstream = %+v, want %+v", gotS, servers)
	}
	if len(upB.snapshot()) != 0 {
		t.Errorf("instance b should receive no upstream push, got %v", upB.snapshot())
	}
	if o := fleet.InstanceOverrideOf("a"); o == nil || !reflect.DeepEqual(*o.UpstreamServers, servers) {
		t.Errorf("override for a = %+v", o)
	}
	// clearing the override removes it entirely.
	if res := fleet.SetInstanceOverride(ctx, "a", &InstanceOverride{}); res["a"] != "ok" {
		t.Fatalf("expected clear ok, got %+v", res)
	}
	if o := fleet.InstanceOverrideOf("a"); o != nil && !o.IsEmpty() {
		t.Errorf("override should be removed after clear, got %+v", o)
	}
}

// newAuthedClient logs in to a controller Server and returns a client whose
// requests carry the resulting session cookie (mirrors TestServerAuth's flow).
func newAuthedClient(t *testing.T, s *Server) *http.Client {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "secret"})
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d", rec.Code)
	}
	cookie := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("no session cookie")
	}
	return &http.Client{Transport: &sessionRoundTripper{base: s.Handler(), cookie: cookie}}
}

// sessionRoundTripper injects the session cookie into every request so tests can
// call the token-gated controller API through a real *http.Client.
type sessionRoundTripper struct {
	base   http.Handler
	cookie string
}

func (rt *sessionRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: rt.cookie})
	rec := httptest.NewRecorder()
	rt.base.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func TestServerSettingsDoHFleet(t *testing.T) {
	dohA := &dohRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, dohA)
	defer srv.Close()

	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer("admin", "secret", fleet, nil)
	c := newAuthedClient(t, s)

	// GET surfaces the fleet-wide (empty) default.
	resp, err := c.Get("/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d["doh_http_addr"] != "" {
		t.Errorf("initial doh_http_addr = %v, want empty", d["doh_http_addr"])
	}

	// PUT a fleet-wide plain-HTTP DoH address -> pushed to instances.
	body, _ := json.Marshal(map[string]string{"doh_http_addr": "0.0.0.0:8445"})
	req, _ := http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ack map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ack["ok"] != true {
		t.Fatalf("PUT ok = %v", ack["ok"])
	}
	applied := ack["applied"].(map[string]interface{})
	if applied["a"] != "ok" {
		t.Errorf("applied a = %v", applied["a"])
	}
	hist := dohA.snapshot()
	if len(hist) == 0 || hist[len(hist)-1] != "0.0.0.0:8445" {
		t.Errorf("doh pushes = %v, want last 0.0.0.0:8445", hist)
	}
	// persisted + readable back.
	resp, _ = c.Get("/api/settings")
	json.NewDecoder(resp.Body).Decode(&d)
	resp.Body.Close()
	if d["doh_http_addr"] != "0.0.0.0:8445" {
		t.Errorf("read-back doh_http_addr = %v", d["doh_http_addr"])
	}

	// a bad address is rejected (400) and never pushed.
	body, _ = json.Marshal(map[string]string{"doh_http_addr": "nope"})
	req, _ = http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad addr status = %d, want 400", resp.StatusCode)
	}
}

func TestServerSettingsDoHInstanceOverride(t *testing.T) {
	dohA, dohB := &dohRec{}, &dohRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, dohA)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, dohB)
	defer srvB.Close()

	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	fleet := NewFleet(cfgPath)
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if res := fleet.SetDoHHTTPAddr(context.Background(), "0.0.0.0:8445"); res["a"] != "ok" || res["b"] != "ok" {
		t.Fatalf("fleet doh push: %+v", res)
	}
	time.Sleep(150 * time.Millisecond) // let poll reconcile settle

	s := NewServer("admin", "secret", fleet, nil)
	c := newAuthedClient(t, s)

	// First give instance b a per-instance upstream override.
	upBody, _ := json.Marshal(map[string]interface{}{"scope": "instance", "instance": "b", "override": map[string]string{"upstream": "udp://9.9.9.9:53"}})
	req, _ := http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(upBody)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upstream override PUT status = %d", resp.StatusCode)
	}

	// Then override b's plain-HTTP DoH address. The upstream must survive.
	body, _ := json.Marshal(map[string]interface{}{"scope": "instance", "instance": "b", "doh_http_addr": "0.0.0.0:9999"})
	req, _ = http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("instance doh PUT status = %d", resp.StatusCode)
	}

	// The saved GET must keep both override fields for b.
	resp, _ = c.Get("/api/settings")
	var d map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	o := d["instance_overrides"].(map[string]interface{})["b"].(map[string]interface{})
	if o["doh_http_addr"] != "0.0.0.0:9999" {
		t.Errorf("b override doh = %v, want 0.0.0.0:9999", o["doh_http_addr"])
	}
	if o["upstream"] != "udp://9.9.9.9:53" {
		t.Errorf("b override upstream = %v, want udp://9.9.9.9:53 (merge must preserve it)", o["upstream"])
	}
}

func TestServerSettingsUpstreamFleet(t *testing.T) {
	upA := &upstreamRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, upA)
	defer srv.Close()

	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer("admin", "secret", fleet, nil)
	c := newAuthedClient(t, s)

	// GET surfaces the empty fleet-wide default.
	resp, err := c.Get("/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		UpstreamServers []upstream.UpstreamServer `json:"upstream_servers"`
		UpstreamRoutes  []upstream.UpstreamRoute  `json:"upstream_routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(got.UpstreamServers) != 0 || len(got.UpstreamRoutes) != 0 {
		t.Errorf("initial upstream = %+v / %+v, want empty", got.UpstreamServers, got.UpstreamRoutes)
	}

	// PUT a fleet-wide upstream pool + conditional-forwarding route.
	servers := []upstream.UpstreamServer{{Name: "quad9", Address: "udp://9.9.9.9:53", Priority: 1}}
	routes := []upstream.UpstreamRoute{{Name: "corp", QnameSuffix: ".corp.", Server: "quad9"}}
	body, _ := json.Marshal(map[string]interface{}{
		"upstream_servers": servers,
		"upstream_routes":  routes,
	})
	req, _ := http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ack map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ack["ok"] != true {
		t.Fatalf("PUT ok = %v", ack["ok"])
	}
	if applied := ack["applied"].(map[string]interface{}); applied["a"] != "ok" {
		t.Errorf("applied a = %v", applied["a"])
	}
	if gotS, gotR := lastUpstream(upA); !reflect.DeepEqual(gotS, servers) || !reflect.DeepEqual(gotR, routes) {
		t.Errorf("instance a upstream = %+v / %+v, want %+v / %+v", gotS, gotR, servers, routes)
	}

	// Persisted + readable back.
	resp, _ = c.Get("/api/settings")
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !reflect.DeepEqual(got.UpstreamServers, servers) || !reflect.DeepEqual(got.UpstreamRoutes, routes) {
		t.Errorf("read-back upstream = %+v / %+v", got.UpstreamServers, got.UpstreamRoutes)
	}
}

// TestServerSettingsUpstreamFleetPartialSave verifies a fleet-wide save that
// touches only one of the two upstream fields preserves the other (a routes-only
// save must not wipe the fleet servers and vice-versa).
func TestServerSettingsUpstreamFleetPartialSave(t *testing.T) {
	upA := &upstreamRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, upA)
	defer srv.Close()

	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer("admin", "secret", fleet, nil)
	c := newAuthedClient(t, s)

	put := func(body map[string]interface{}) int {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	getUpstream := func() ([]upstream.UpstreamServer, []upstream.UpstreamRoute) {
		resp, err := c.Get("/api/settings")
		if err != nil {
			t.Fatal(err)
		}
		var d struct {
			UpstreamServers []upstream.UpstreamServer `json:"upstream_servers"`
			UpstreamRoutes  []upstream.UpstreamRoute  `json:"upstream_routes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return d.UpstreamServers, d.UpstreamRoutes
	}

	servers := []upstream.UpstreamServer{{Name: "quad9", Address: "udp://9.9.9.9:53", Priority: 1}}
	routes := []upstream.UpstreamRoute{{Name: "corp", QnameSuffix: ".corp.", Server: "quad9"}}
	if st := put(map[string]interface{}{"upstream_servers": servers, "upstream_routes": routes}); st != http.StatusOK {
		t.Fatalf("seed PUT status = %d", st)
	}

	// A routes-only save must keep the fleet servers.
	newRoutes := []upstream.UpstreamRoute{{Name: "corp", QnameSuffix: ".corp.", Server: "quad9", ClientCIDR: "10.0.0.0/8"}}
	if st := put(map[string]interface{}{"upstream_routes": newRoutes}); st != http.StatusOK {
		t.Fatalf("routes-only PUT status = %d", st)
	}
	if gotS, gotR := getUpstream(); !reflect.DeepEqual(gotS, servers) || !reflect.DeepEqual(gotR, newRoutes) {
		t.Errorf("after routes-only save = %+v / %+v, want %+v / %+v", gotS, gotR, servers, newRoutes)
	}

	// And a servers-only save must keep the fleet routes (the route must still
	// reference a defined server, so the pool stays valid).
	newServers := []upstream.UpstreamServer{{Name: "quad9", Address: "udp://1.1.1.1:53", Priority: 1}}
	if st := put(map[string]interface{}{"upstream_servers": newServers}); st != http.StatusOK {
		t.Fatalf("servers-only PUT status = %d", st)
	}
	if gotS, gotR := getUpstream(); !reflect.DeepEqual(gotS, newServers) || !reflect.DeepEqual(gotR, newRoutes) {
		t.Errorf("after servers-only save = %+v / %+v, want %+v / %+v", gotS, gotR, newServers, newRoutes)
	}
}

// TestServerSettingsUpstreamRejectsInvalidPool verifies the controller refuses
// to persist an invalid upstream pool (bad server spec, or a route referencing
// an unknown server) — for both the fleet-wide and per-instance scope — instead
// of saving it and failing every push to the instances.
func TestServerSettingsUpstreamRejectsInvalidPool(t *testing.T) {
	upA := &upstreamRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, upA)
	defer srv.Close()

	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer("admin", "secret", fleet, nil)
	c := newAuthedClient(t, s)

	put := func(body map[string]interface{}) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// A server with an unrecognized spec is rejected and nothing is persisted.
	resp := put(map[string]interface{}{"upstream_servers": []upstream.UpstreamServer{{Name: "bad", Address: "wibble://x", Priority: 1}}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad spec status = %d, want 400", resp.StatusCode)
	}
	if gotS, _ := fleet.Upstream(); len(gotS) != 0 {
		t.Errorf("invalid pool was persisted: %+v", gotS)
	}
	if len(upA.snapshot()) != 0 {
		t.Errorf("instance received a push despite rejected pool: %v", upA.snapshot())
	}

	// A route referencing an unknown server is rejected too.
	resp = put(map[string]interface{}{
		"upstream_servers": []upstream.UpstreamServer{{Name: "quad9", Address: "udp://9.9.9.9:53", Priority: 1}},
		"upstream_routes":  []upstream.UpstreamRoute{{Name: "r", QnameSuffix: ".corp.", Server: "ghost"}},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown-route-server status = %d, want 400", resp.StatusCode)
	}
	if gotS, _ := fleet.Upstream(); len(gotS) != 0 {
		t.Errorf("invalid pool was persisted: %+v", gotS)
	}

	// The per-instance path rejects a bad pool the same way.
	resp = put(map[string]interface{}{"scope": "instance", "instance": "a", "upstream_servers": []upstream.UpstreamServer{{Name: "bad", Address: "wibble://x", Priority: 1}}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("instance bad spec status = %d, want 400", resp.StatusCode)
	}
	if o := fleet.InstanceOverrideOf("a"); o != nil && !o.IsEmpty() {
		t.Errorf("invalid instance override was persisted: %+v", o)
	}
}

// TestServerSettingsUpstreamDisabledRoute verifies the default local-ptr rule
// (disabled, no server picked yet) is accepted, persisted, and pushed.
func TestServerSettingsUpstreamDisabledRoute(t *testing.T) {
	upA := &upstreamRec{}
	srv := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, nil, upA)
	defer srv.Close()

	fleet := NewFleet(filepath.Join(t.TempDir(), "blipc.yaml"))
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer("admin", "secret", fleet, nil)
	c := newAuthedClient(t, s)

	put := func(body map[string]interface{}) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := put(map[string]interface{}{
		"upstream_servers": []upstream.UpstreamServer{{Name: "local", Address: "udp://192.168.30.221", Priority: 0}},
		"upstream_routes": []upstream.UpstreamRoute{
			{Name: "local-ptr", QnameSuffix: ".in-addr.arpa.", Disabled: true},
		},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotS, gotR := fleet.Upstream(); len(gotS) != 1 || len(gotR) != 1 || !gotR[0].Disabled {
		t.Errorf("persisted = %+v / %+v, want disabled route kept", gotS, gotR)
	}
	sn := upA.snapshot()
	if len(sn) != 1 || len(sn[0].routes) != 1 || !sn[0].routes[0].Disabled {
		t.Errorf("pushed = %+v, want the disabled route", sn)
	}

	// Enabling the same route but referencing a server that does not exist in
	// the pool is still rejected (validation applies to active rules only).
	resp = put(map[string]interface{}{
		"upstream_servers": []upstream.UpstreamServer{{Name: "local", Address: "udp://192.168.30.221", Priority: 0}},
		"upstream_routes": []upstream.UpstreamRoute{
			{Name: "local-ptr", QnameSuffix: ".in-addr.arpa.", Server: "ghost"},
		},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("enabled route to unknown server status = %d, want 400", resp.StatusCode)
	}
}

// TestServerSettingsUpstreamInstanceOverride verifies a per-instance upstream
// override set through the API survives a later DoH save, and that a
// routes-only save does not wipe a previously saved per-instance server pool.
func TestServerSettingsUpstreamInstanceOverride(t *testing.T) {
	upA, upB := &upstreamRec{}, &upstreamRec{}
	dohA, dohB := &dohRec{}, &dohRec{}
	srvA := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, dohA, upA)
	defer srvA.Close()
	srvB := fakeBlipdWithRec(t, "t", "", &control.HealthResponse{OK: true}, &control.StatsResponse{}, &control.ListResponse{}, nil, dohB, upB)
	defer srvB.Close()

	cfgPath := filepath.Join(t.TempDir(), "blipc.yaml")
	fleet := NewFleet(cfgPath)
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srvA.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "b", URL: srvB.URL, Token: "t"}); err != nil {
		t.Fatal(err)
	}

	// Give the fleet a baseline default so both instances have one.
	fleetServers := []upstream.UpstreamServer{{Name: "quad9", Address: "udp://9.9.9.9:53", Priority: 1}}
	if res := fleet.SetUpstream(context.Background(), fleetServers, nil); res["a"] != "ok" || res["b"] != "ok" {
		t.Fatalf("fleet upstream push: %+v", res)
	}
	time.Sleep(150 * time.Millisecond) // let poll reconcile settle

	s := NewServer("admin", "secret", fleet, nil)
	c := newAuthedClient(t, s)

	// First give instance b a per-instance upstream override.
	ovrServers := []upstream.UpstreamServer{{Name: "cloudflare", Address: "udp://1.1.1.1:53", Priority: 1}}
	body, _ := json.Marshal(map[string]interface{}{"scope": "instance", "instance": "b", "upstream_servers": ovrServers, "upstream_routes": []upstream.UpstreamRoute{}})
	req, _ := http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upstream override PUT status = %d", resp.StatusCode)
	}

	// A routes-only save must not clobber b's per-instance server pool.
	routes := []upstream.UpstreamRoute{{Name: "corp", QnameSuffix: ".corp.", Server: "cloudflare"}}
	body, _ = json.Marshal(map[string]interface{}{"scope": "instance", "instance": "b", "upstream_routes": routes})
	req, _ = http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("routes-only PUT status = %d", resp.StatusCode)
	}

	// Then override b's plain-HTTP DoH address; the upstream must survive.
	body, _ = json.Marshal(map[string]interface{}{"scope": "instance", "instance": "b", "doh_http_addr": "0.0.0.0:9999"})
	req, _ = http.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("instance doh PUT status = %d", resp.StatusCode)
	}

	// The saved GET must keep both upstream override fields plus the DoH one.
	resp, _ = c.Get("/api/settings")
	var d struct {
		InstanceOverrides map[string]*InstanceOverride `json:"instance_overrides"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	o := d.InstanceOverrides["b"]
	if o == nil {
		t.Fatal("no override for b")
	}
	if o.DoHHTTPAddr == nil || *o.DoHHTTPAddr != "0.0.0.0:9999" {
		t.Errorf("b override doh = %v, want 0.0.0.0:9999", o.DoHHTTPAddr)
	}
	if !reflect.DeepEqual(*o.UpstreamServers, ovrServers) {
		t.Errorf("b override servers = %+v, want %+v (routes-only save must preserve it)", *o.UpstreamServers, ovrServers)
	}
	if !reflect.DeepEqual(*o.UpstreamRoutes, routes) {
		t.Errorf("b override routes = %+v, want %+v", *o.UpstreamRoutes, routes)
	}
	// b's fake instance received the full merged pool + routes; a kept the fleet default.
	if gotS, gotR := lastUpstream(upB); !reflect.DeepEqual(gotS, ovrServers) || !reflect.DeepEqual(gotR, routes) {
		t.Errorf("instance b upstream = %+v / %+v, want %+v / %+v", gotS, gotR, ovrServers, routes)
	}
	if gotS, _ := lastUpstream(upA); !reflect.DeepEqual(gotS, fleetServers) {
		t.Errorf("instance a upstream = %+v, want fleet default %+v", gotS, fleetServers)
	}
}

// TestAuthPasswordHash verifies a pre-bcrypt-hashed password in the config is
// accepted as-is (D2), and that plaintext passwords still hash+verify.
func TestAuthPasswordHash(t *testing.T) {
	// Pre-hash a password so the config never stores plaintext.
	hashed, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	// NewAuth must detect the bcrypt hash and use it verbatim (no double-hash).
	a := NewAuth("admin", string(hashed))
	if !a.configured {
		t.Fatal("auth not configured from hash")
	}
	if id, err := a.Login("admin", "secret", "127.0.0.1"); err != nil || id == "" {
		t.Errorf("login with hashed password failed: id=%q err=%v", id, err)
	}
	if _, err := a.Login("admin", "wrong", "127.0.0.1"); err == nil {
		t.Error("wrong password accepted against hash")
	}

	// Plaintext password still works (hashed at startup by NewAuth).
	b := NewAuth("admin", "secret")
	if id, err := b.Login("admin", "secret", "127.0.0.1"); err != nil || id == "" {
		t.Errorf("login with plaintext password failed: id=%q err=%v", id, err)
	}

	// Garbage hash string is rejected (not configured).
	if c := NewAuth("admin", "$2b$not-a-real-hash"); c.configured {
		t.Error("garbage bcrypt hash should not configure auth")
	}
}

// TestResolveTokenFile verifies the @/path expansion feature and that path
// traversal is refused (F3).
func TestResolveTokenFile(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "token")
	if err := os.WriteFile(secret, []byte("real-token"), 0600); err != nil {
		t.Fatal(err)
	}
	// @file path is expanded.
	cfg := ResolveTokenFile(InstanceConfig{ID: "i", Token: "@" + secret})
	if cfg.Token != "real-token" {
		t.Errorf("token expansion = %q, want real-token", cfg.Token)
	}
	// A literal token is untouched.
	if cfg := ResolveTokenFile(InstanceConfig{ID: "i", Token: "literal"}); cfg.Token != "literal" {
		t.Error("literal token was modified")
	}
	// Path traversal is refused (token left as-is, file not read).
	got := ResolveTokenFile(InstanceConfig{ID: "i", Token: "@/../../etc/passwd"})
	if got.Token != "@/../../etc/passwd" {
		t.Errorf("traversal token was modified: %q", got.Token)
	}
}

// TestWarnOrphanPolicyUpstreams verifies that a policy (fleet default or
// per-instance override) whose upstream points at a removed/unknown server is
// reported, and that an override matching a configured pool server is not.
func TestWarnOrphanPolicyUpstreams(t *testing.T) {
	fleet := NewFleet("")
	fleet.SetDefault(&control.Policy{ID: "default", Upstream: "udp://192.168.30.221|1"})
	override := "udp://192.168.30.221"
	fleet.SetOverride("inst1", &InstanceOverride{Upstream: &override})
	ext := "https://1.1.1.1/dns-query"
	fleet.SetOverride("inst2", &InstanceOverride{Upstream: &ext})

	pool := []upstream.UpstreamServer{
		{Name: "DoH", Address: "https://dns.mullvad.net/dns-query", Priority: 1},
	}
	// 192.168.30.221 was in the pool and is now gone: default + inst1 flagged.
	removed := removedServerRefs([]upstream.UpstreamServer{
		{Name: "old", Address: "udp://192.168.30.221|1"},
	}, pool)
	got := fleet.orphanPolicyUpstreams(func(ref string) bool { return removed[ref] })
	if len(got) != 2 {
		t.Fatalf("removed-scan flagged %d policies, want 2: %v", len(got), got)
	}
	for _, w := range got {
		if !strings.Contains(w, "192.168.30.221") {
			t.Errorf("warning missing removed address: %q", w)
		}
	}
	// Startup scan: inst2's external override is not in the pool either, so all
	// three non-empty overrides are flagged.
	all := fleet.orphanPolicyUpstreams(func(ref string) bool { return !serverRefs(pool)[ref] })
	if len(all) != 3 {
		t.Fatalf("startup scan flagged %d policies, want 3: %v", len(all), all)
	}
}

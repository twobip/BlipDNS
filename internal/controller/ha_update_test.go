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

// haUpdaterNode models a blipd node that participates in HA and supports
// remote updates. It records every HA config pushed and every update
// triggered, so tests can assert on priority changes during updates.
type haUpdaterNode struct {
	mu        sync.Mutex
	token     string
	haConfigs []control.HAConfig
	started   int
	running   bool
	stop      chan struct{}
	// autoFinish makes the update complete before the POST /update response
	// returns, modelling a node whose updater is never observed running.
	autoFinish bool
}

func newHAUpdaterNode(token string) *haUpdaterNode {
	return &haUpdaterNode{token: token}
}

func (n *haUpdaterNode) start() {
	n.mu.Lock()
	n.started++
	n.running = true
	n.stop = make(chan struct{})
	n.mu.Unlock()
}

func (n *haUpdaterNode) finish() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.running = false
	if n.stop != nil {
		close(n.stop)
		n.stop = nil
	}
}

func (n *haUpdaterNode) server(t *testing.T) *httptest.Server {
	t.Helper()
	mu := http.NewServeMux()
	auth := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+n.token }

	mu.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSONH(w, &control.HealthResponse{OK: true})
	})
	mu.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSONH(w, &control.StatsResponse{})
	})
	mu.HandleFunc("/api/v1/ha/status", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		n.mu.Lock()
		running := n.running
		n.mu.Unlock()
		writeJSONH(w, control.HAStatus{State: "MASTER", Active: true, VIPOwned: true, Updating: running})
	})
	mu.HandleFunc("/api/v1/ha", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var cfg control.HAConfig
		_ = json.NewDecoder(r.Body).Decode(&cfg)
		n.mu.Lock()
		n.haConfigs = append(n.haConfigs, cfg)
		n.mu.Unlock()
		writeJSONH(w, map[string]bool{"ok": true})
	})
	mu.HandleFunc("/api/v1/ha/apply", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSONH(w, map[string]bool{"ok": true})
	})
	mu.HandleFunc("/api/v1/update", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPost:
			n.mu.Lock()
			af := n.autoFinish
			n.mu.Unlock()
			n.start()
			if af {
				n.finish()
			}
			writeJSONH(w, map[string]bool{"ok": true})
		case http.MethodGet:
			n.mu.Lock()
			status := control.UpdateStatus{Running: n.running}
			n.mu.Unlock()
			writeJSONH(w, status)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return httptest.NewServer(mu)
}

func (n *haUpdaterNode) snapshot() ([]control.HAConfig, int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]control.HAConfig, len(n.haConfigs))
	copy(out, n.haConfigs)
	return out, n.started
}

// TestUpdateFastCompletion ensures a node whose update completes before the
// controller's first status poll does not stall the serialized job: the
// phase machine must fall through to the health gate. Regression: it once
// sat in the "start" phase until the full 10-minute timeout.
func TestUpdateFastCompletion(t *testing.T) {
	node := newHAUpdaterNode("tok")
	node.autoFinish = true
	srv := node.server(t)
	defer srv.Close()

	fleet := NewFleet("")
	originalWait := haFailoverWait
	haFailoverWait = 100 * time.Millisecond
	defer func() { haFailoverWait = originalWait }()
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	fleet.SetReleaseChannelDefault("stable")
	if _, err := fleet.StartUpdates(context.Background(), "stable"); err != nil {
		t.Fatalf("StartUpdates: %v", err)
	}
	waitFor(t, 30*time.Second, func() bool {
		st := fleet.UpdateJob()
		return !st.Running && st.Completed == 1
	}, "instant-completion update stalled the job")
}

// TestUpdateDegradesHAPriority verifies that when an HA-enabled update starts
// on a node, the controller pushes a lower VRRP priority to that node while
// keeping the peer's priority unchanged, and restores the original priority
// after the update completes.
func TestUpdateDegradesHAPriority(t *testing.T) {
	nodeA := newHAUpdaterNode("tok-a")
	nodeB := newHAUpdaterNode("tok-b")
	srvA := nodeA.server(t)
	srvB := nodeB.server(t)
	defer srvA.Close()
	defer srvB.Close()

	fleet := NewFleet("")
	// Shorten the failover wait for tests.
	originalWait := haFailoverWait
	haFailoverWait = 100 * time.Millisecond
	defer func() { haFailoverWait = originalWait }()
	ctx := context.Background()
	if err := fleet.Add(ctx, InstanceConfig{ID: "a", URL: srvA.URL, Token: "tok-a"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(ctx, InstanceConfig{ID: "b", URL: srvB.URL, Token: "tok-b"}); err != nil {
		t.Fatal(err)
	}
	fleet.SetReleaseChannelDefault("stable")

	// Configure a two-node HA cluster with distinct priorities.
	cluster := control.HACluster{
		Enabled:           true,
		PrimaryInstance:   "a",
		SecondaryInstance: "b",
		Primary: control.HAConfig{
			Enabled:           true,
			Mode:              "unicast",
			NodeRole:          "primary",
			Interface:         "eth0",
			SourceIP:          "192.0.2.10",
			PeerIP:            "192.0.2.11",
			VirtualIP:         "192.0.2.100/24",
			VirtualRouterID:   51,
			Priority:          101,
			AdvertIntervalSec: 1,
		},
		Secondary: control.HAConfig{
			Enabled:           true,
			Mode:              "unicast",
			NodeRole:          "secondary",
			Interface:         "eth0",
			SourceIP:          "192.0.2.11",
			PeerIP:            "192.0.2.10",
			VirtualIP:         "192.0.2.100/24",
			VirtualRouterID:   51,
			Priority:          100,
			AdvertIntervalSec: 1,
		},
	}
	if err := fleet.SetHACluster(ctx, cluster); err != nil {
		t.Fatalf("SetHACluster: %v", err)
	}

	// Start the serialized update (node a first, then b).
	if _, err := fleet.StartUpdates(ctx, "stable"); err != nil {
		t.Fatalf("StartUpdates: %v", err)
	}

	// Wait for node a's update to start (priority should have been degraded).
	waitFor(t, 30*time.Second, func() bool {
		cfgs, _ := nodeA.snapshot()
		if len(cfgs) == 0 {
			return false
		}
		// The last config pushed to node a should have a reduced priority.
		last := cfgs[len(cfgs)-1]
		return last.Priority <= 101-haPriorityDelta
	}, "node a priority was not degraded before update")

	// Node b's priority should remain at full value.
	bCfgs, _ := nodeB.snapshot()
	if len(bCfgs) > 0 {
		lastB := bCfgs[len(bCfgs)-1]
		if lastB.Priority != 100 {
			t.Errorf("node b priority = %d, want 100 (unchanged)", lastB.Priority)
		}
	}

	// Wait for the update to actually start on node a before finishing it.
	waitFor(t, 30*time.Second, func() bool {
		_, started := nodeA.snapshot()
		return started >= 1
	}, "node a update did not start")

	// Complete node a's update.
	nodeA.finish()

	// After node a's update finishes, its priority should be restored.
	waitFor(t, 30*time.Second, func() bool {
		cfgs, _ := nodeA.snapshot()
		if len(cfgs) == 0 {
			return false
		}
		// The last config should have the original priority back.
		last := cfgs[len(cfgs)-1]
		return last.Priority == 101
	}, "node a priority was not restored after update")

	// Wait for node b's update to start.
	waitFor(t, 30*time.Second, func() bool {
		_, started := nodeB.snapshot()
		return started >= 1
	}, "node b update did not start")

	// Complete node b's update too.
	nodeB.finish()

	// Wait for the overall job to finish.
	waitFor(t, 30*time.Second, func() bool {
		status := fleet.UpdateJob()
		return !status.Running && status.Completed == 2
	}, "serialized update did not complete")
}

func TestReducePriorityYieldsToPeer(t *testing.T) {
	for _, tc := range []struct{ p, peer, want int }{
		{101, 100, 81}, // normal gap: flat delta
		{150, 100, 99}, // wide gap: clamped strictly below peer
		{30, 100, 10},  // updating node already lower stays low
		{10, 1, 1},     // degenerate: peer at 1 ties at floor
		{0, 100, 0},    // unset priority untouched
	} {
		if got := reducePriority(tc.p, tc.peer); got != tc.want {
			t.Errorf("reducePriority(%d, %d) = %d, want %d", tc.p, tc.peer, got, tc.want)
		}
	}
}

// Validating or applying before anything is saved (disabled, no member
// instances) must be a vacuous pass, not "controller: unknown instance ".
func TestHAValidateApplyDisabledEmpty(t *testing.T) {
	fleet := NewFleet("")
	ctx := context.Background()
	if err := fleet.ValidateHA(ctx, control.HACluster{}); err != nil {
		t.Fatalf("ValidateHA(disabled) = %v, want nil", err)
	}
	if err := fleet.ApplyHA(ctx, control.HACluster{}); err != nil {
		t.Fatalf("ApplyHA(disabled) = %v, want nil", err)
	}
}

// POST validate must check the unsaved draft body when one is sent (the UI
// validates what you typed before saving), keep working body-less for older
// callers, and never wipe anything: it changes no stored state.
func TestHAValidateDraftBody(t *testing.T) {
	fleet := NewFleet("")
	srv := NewServer("admin", "secret", fleet, nil)
	h := srv.Handler()

	good, _ := json.Marshal(map[string]string{"username": "admin", "password": "secret"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/login", bytes.NewReader(good)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200", rec.Code)
	}
	var sid string
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no session cookie")
	}
	doValidate := func(body string) *httptest.ResponseRecorder {
		var rdr *bytes.Reader
		if body == "" {
			rdr = bytes.NewReader(nil)
		} else {
			rdr = bytes.NewReader([]byte(body))
		}
		req := httptest.NewRequest("POST", "/api/high-availability?action=validate", rdr)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		return out
	}

	// No body (older callers): stored cluster is disabled/empty -> vacuous pass.
	if rec := doValidate(""); rec.Code != http.StatusOK {
		t.Errorf("validate body-less = %d (%s), want 200", rec.Code, rec.Body.String())
	}

	validDraft := func(primary, secondary string) string {
		raw, _ := json.Marshal(map[string]any{"cluster": map[string]any{
			"enabled": true, "primary_instance": primary, "secondary_instance": secondary,
			"primary": map[string]any{"enabled": true, "mode": "unicast", "node_role": "primary",
				"interface": "eth0", "source_ip": "192.0.2.10", "peer_ip": "192.0.2.11",
				"virtual_ip": "192.0.2.100/24", "virtual_router_id": 51, "priority": 101,
				"advert_interval_sec": 1, "auth_pass": "x"},
			"secondary": map[string]any{"enabled": true, "mode": "unicast", "node_role": "secondary",
				"interface": "eth0", "source_ip": "192.0.2.11", "peer_ip": "192.0.2.10",
				"virtual_ip": "192.0.2.100/24", "virtual_router_id": 51, "priority": 100,
				"advert_interval_sec": 1, "auth_pass": "x"},
		}})
		return string(raw)
	}

	// Unknown member instances in the draft must be reported, proving the
	// body (not stored state) was validated.
	if rec := doValidate(validDraft("nope", "nope2")); rec.Code != http.StatusBadRequest {
		t.Errorf("validate unknown draft = %d, want 400", rec.Code)
	} else if got := rec.Body.String(); !bytes.Contains([]byte(got), []byte("unknown instance nope")) {
		t.Errorf("validate unknown draft = %q, want unknown-instance error", got)
	}

	// Structurally invalid draft (no members picked yet) is a 400, not a pass.
	if rec := doValidate(validDraft("", "")); rec.Code != http.StatusBadRequest {
		t.Errorf("validate empty draft = %d, want 400", rec.Code)
	}
}

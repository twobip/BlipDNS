package controller

import (
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
			n.start()
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
	waitFor(t, 5*time.Second, func() bool {
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
	waitFor(t, 5*time.Second, func() bool {
		_, started := nodeA.snapshot()
		return started >= 1
	}, "node a update did not start")

	// Complete node a's update.
	nodeA.finish()

	// After node a's update finishes, its priority should be restored.
	waitFor(t, 5*time.Second, func() bool {
		cfgs, _ := nodeA.snapshot()
		if len(cfgs) == 0 {
			return false
		}
		// The last config should have the original priority back.
		last := cfgs[len(cfgs)-1]
		return last.Priority == 101
	}, "node a priority was not restored after update")

	// Wait for node b's update to start.
	waitFor(t, 5*time.Second, func() bool {
		_, started := nodeB.snapshot()
		return started >= 1
	}, "node b update did not start")

	// Complete node b's update too.
	nodeB.finish()

	// Wait for the overall job to finish.
	waitFor(t, 5*time.Second, func() bool {
		status := fleet.UpdateJob()
		return !status.Running && status.Completed == 2
	}, "serialized update did not complete")
}

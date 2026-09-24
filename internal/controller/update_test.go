package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

// fakeUpdaterNode models a blipd that can be remotely updated: it tracks how
// often it was asked to start an update, is "down" while the update runs, and
// comes back with health OK once the updater finishes.
type fakeUpdaterNode struct {
	mu      sync.Mutex
	token   string
	started int
	running bool
	stop    chan struct{}
	// failMsg, once set with failAfter, makes update-status GETs report a
	// failure after failAfter successful Running reports: models an updater
	// that starts fine then fails (e.g. root install refused).
	failMsg   string
	failAfter int
	gets      int
}

func newFakeUpdaterNode(token string) *fakeUpdaterNode {
	return &fakeUpdaterNode{token: token}
}

func (n *fakeUpdaterNode) start() {
	n.mu.Lock()
	n.started++
	n.running = true
	n.stop = make(chan struct{})
	n.mu.Unlock()
}

func (n *fakeUpdaterNode) finish() {
	n.mu.Lock()
	n.running = false
	close(n.stop)
	n.stop = nil
	n.mu.Unlock()
}

func (n *fakeUpdaterNode) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	auth := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+n.token }
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSONH(w, &control.HealthResponse{OK: true})
	})
	mux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSONH(w, &control.StatsResponse{})
	})
	mux.HandleFunc("/api/v1/update", func(w http.ResponseWriter, r *http.Request) {
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
			n.gets++
			status := control.UpdateStatus{Running: n.running}
			if n.failMsg != "" && n.gets > n.failAfter {
				status = control.UpdateStatus{LastError: n.failMsg}
			}
			n.mu.Unlock()
			writeJSONH(w, status)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return httptest.NewServer(mux)
}

func (n *fakeUpdaterNode) counts() (int, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.started, n.running
}

// TestSerializedUpdateWaitsForEachNode ensures that with two adopted nodes,
// the second node's update is not started until the first node has returned
// online (health OK after its updater finished), and that a failing node stops
// the job before the next node is touched.
func TestSerializedUpdateWaitsForEachNode(t *testing.T) {
	nodeA := newFakeUpdaterNode("tok-a")
	nodeB := newFakeUpdaterNode("tok-b")
	srvA := nodeA.server(t)
	srvB := nodeB.server(t)
	defer srvA.Close()
	defer srvB.Close()

	fleet := NewFleet("")
	// Shorten the failover wait for tests.
	originalWait := haFailoverWait
	haFailoverWait = 100 * time.Millisecond
	defer func() { haFailoverWait = originalWait }()
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srvA.URL, Token: "tok-a"}); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "b", URL: srvB.URL, Token: "tok-b"}); err != nil {
		t.Fatal(err)
	}
	fleet.SetReleaseChannelDefault("stable")

	job, err := fleet.StartUpdates(context.Background(), "stable")
	if err != nil {
		t.Fatal(err)
	}
	if !job.Running || job.Total != 2 {
		t.Fatalf("job = %+v, want running with 2 nodes", job)
	}

	// The update starts on the first node immediately.
	waitFor(t, 30*time.Second, func() bool {
		n, _ := nodeA.counts()
		return n == 1
	}, "node a update was not started")
	if n, running := nodeB.counts(); n != 0 || running {
		t.Fatalf("node b touched before node a finished: started=%d running=%v", n, running)
	}

	// While node a is still updating, node b must never be started.
	nodeA.finish()
	waitFor(t, 30*time.Second, func() bool {
		_, running := nodeA.counts()
		return !running
	}, "node a did not come back online")
	waitFor(t, 30*time.Second, func() bool {
		n, _ := nodeB.counts()
		return n == 1
	}, "node b update was not started after node a returned")

	nodeB.finish()
	waitFor(t, 30*time.Second, func() bool {
		status := fleet.UpdateJob()
		return !status.Running && status.Completed == 2
	}, "serialized update did not complete")
}

// An updater that fails after reporting running must fail the node update:
// the health gate alone cannot tell "restarted" from "never restarted"
// (the old process still answers), so LastError has to win over phase.
func TestUpdateFailAfterRunning(t *testing.T) {
	node := newFakeUpdaterNode("tok")
	node.failMsg = "cannot open lock /run/lock/blipd-install.lock"
	node.failAfter = 1
	srv := node.server(t)
	defer srv.Close()
	fleet := NewFleet("")
	if err := fleet.Add(context.Background(), InstanceConfig{ID: "a", URL: srv.URL, Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	inst := fleet.get("a")
	if inst == nil {
		t.Fatal("missing instance")
	}
	err := fleet.updateOne(inst, "stable")
	if err == nil {
		t.Fatal("updateOne = nil, want remote updater error")
	} else if !strings.Contains(err.Error(), "cannot open lock") {
		t.Fatalf("updateOne = %v, want lock failure", err)
	}
}

// waitFor polls cond until it holds or the deadline passes. Deadlines on
// flows driven by the update loop's 2s status ticker are deliberately
// generous: a parallel `go test ./...` starves timers and a tight cap
// red-lights unrelated runs, while polling exits as soon as cond holds, so
// the slack costs nothing.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

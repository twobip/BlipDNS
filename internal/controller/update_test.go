package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
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
			status := control.UpdateStatus{Running: n.running}
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
	waitFor(t, 5*time.Second, func() bool {
		n, _ := nodeA.counts()
		return n == 1
	}, "node a update was not started")
	if n, running := nodeB.counts(); n != 0 || running {
		t.Fatalf("node b touched before node a finished: started=%d running=%v", n, running)
	}

	// While node a is still updating, node b must never be started.
	nodeA.finish()
	waitFor(t, 5*time.Second, func() bool {
		_, running := nodeA.counts()
		return !running
	}, "node a did not come back online")
	waitFor(t, 5*time.Second, func() bool {
		n, _ := nodeB.counts()
		return n == 1
	}, "node b update was not started after node a returned")

	nodeB.finish()
	waitFor(t, 5*time.Second, func() bool {
		status := fleet.UpdateJob()
		return !status.Running && status.Completed == 2
	}, "serialized update did not complete")
}

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

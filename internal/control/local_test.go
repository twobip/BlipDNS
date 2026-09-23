package control

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
)

func testLocalServer(token string) *Server {
	store := filter.NewStore(nil)
	c := cache.New(0, 0)
	return NewServerWithBlocklist(token, store, c, &Counters{}, "blipd/test", nil)
}

func getStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // test-only local request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// The TCP handler must keep requiring the bearer token.
func TestHandlerStillRequiresToken(t *testing.T) {
	srv := testLocalServer("secret")
	ts := &http.Server{Handler: srv.Handler()}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ts.Serve(ln) //nolint:errcheck
	defer ts.Close()
	if got := getStatus(t, "http://"+ln.Addr().String()+"/api/v1/health"); got != http.StatusUnauthorized {
		t.Errorf("TCP health without token = %d, want 401", got)
	}
}

// The local handler serves the same routes with no token: socket file
// permissions are the auth boundary.
func TestLocalHandlerNeedsNoToken(t *testing.T) {
	srv := testLocalServer("secret")
	// Exercise via real HTTP over a Unix socket, end to end with NewClientUnix.
	dir := t.TempDir()
	sock := filepath.Join(dir, "blipd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	us := &http.Server{Handler: srv.LocalHandler()}
	go us.Serve(ln) //nolint:errcheck
	defer us.Close()

	cli := NewClientUnix(sock, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h, err := cli.Health(ctx)
	if err != nil {
		t.Fatalf("local Health without token: %v", err)
	}
	if !h.OK {
		t.Error("local Health.OK = false, want true")
	}
}

// Local admin works even when no token is configured at all (ephemeral boot
// or a lost token): socket access already proves local privilege. The TCP
// handler stays disabled in that state.
func TestLocalHandlerWorksWithoutConfiguredToken(t *testing.T) {
	srv := testLocalServer("")
	dir := t.TempDir()
	sock := filepath.Join(dir, "blipd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	us := &http.Server{Handler: srv.LocalHandler()}
	go us.Serve(ln) //nolint:errcheck
	defer us.Close()

	cli := NewClientUnix(sock, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cli.Health(ctx); err != nil {
		t.Fatalf("local Health with empty server token: %v", err)
	}

	// TCP with an empty token stays disabled (503), not open.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	ts := &http.Server{Handler: srv.Handler()}
	go ts.Serve(tcpLn) //nolint:errcheck
	defer ts.Close()
	if got := getStatus(t, "http://"+tcpLn.Addr().String()+"/api/v1/health"); got != http.StatusServiceUnavailable {
		t.Errorf("TCP health with empty token = %d, want 503", got)
	}
}

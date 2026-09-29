package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/twobip/BlipDNS/internal/control"
)

func postInstances(t *testing.T, srv *Server, body string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/instances", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleInstances(rec, req)
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Adding with a correct claim adopts server-side in the same call and the
// response reports it, so the UI needs no second adopt POST.
func TestInstancesAddReportsAdoption(t *testing.T) {
	fake := fakeBlipd(t, "tok-1", "CODE-1",
		&control.HealthResponse{OK: true, Version: "blipd/0.1.0"},
		&control.StatsResponse{},
		&control.ListResponse{},
	)
	defer fake.Close()
	cfg := filepath.Join(t.TempDir(), "blipc.yaml")
	if err := os.WriteFile(cfg, []byte("listen: \"127.0.0.1:8500\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(cfg), nil, cfg, "")

	code, res := postInstances(t, srv, `{"id":"n1","url":"`+fake.URL+`","claim":"CODE-1"}`)
	if code != http.StatusOK {
		t.Fatalf("add status = %d (%v)", code, res)
	}
	if res["adopted"] != true {
		t.Fatalf("expected adopted=true, got %v", res)
	}
	if !srv.fleet.Adopted("n1") {
		t.Fatal("fleet does not report n1 adopted")
	}
	if srv.fleet.Adopted("nope") {
		t.Fatal("unknown instance reports adopted")
	}
}

// A wrong claim still saves the instance (reachable later via the row Adopt
// action) but reports adopted=false instead of failing silently.
func TestInstancesAddWrongClaimReportsPending(t *testing.T) {
	fake := fakeBlipd(t, "tok-1", "CODE-1",
		&control.HealthResponse{OK: true, Version: "blipd/0.1.0"},
		&control.StatsResponse{},
		&control.ListResponse{},
	)
	defer fake.Close()
	cfg := filepath.Join(t.TempDir(), "blipc.yaml")
	if err := os.WriteFile(cfg, []byte("listen: \"127.0.0.1:8500\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := NewServerWithConfig("admin", "test-password-123", NewFleet(cfg), nil, cfg, "")

	code, res := postInstances(t, srv, `{"id":"n2","url":"`+fake.URL+`","claim":"WRONG"}`)
	if code != http.StatusOK {
		t.Fatalf("add status = %d (%v)", code, res)
	}
	if res["adopted"] != false {
		t.Fatalf("expected adopted=false, got %v", res)
	}
	if srv.fleet.Adopted("n2") {
		t.Fatal("wrong-claim instance reports adopted")
	}
}

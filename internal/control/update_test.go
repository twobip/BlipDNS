package control

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
)

type fakeUpdateController struct {
	started bool
	status  UpdateStatus
}

func (f *fakeUpdateController) StartUpdate(channel string) error {
	f.started = true
	f.status.Channel = channel
	return nil
}

func (f *fakeUpdateController) UpdateStatus() UpdateStatus { return f.status }

func TestUpdateEndpointStartsAndReportsUpdate(t *testing.T) {
	ctrl := &fakeUpdateController{status: UpdateStatus{Running: true, Message: "building"}}
	srv := NewServerWithBlocklist("tok", filter.NewStore(nil), cache.New(0, 0), &Counters{}, "test", blocklist.New())
	srv.SetUpdateController(ctrl)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/update?channel=stable", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", resp.StatusCode)
	}
	if !ctrl.started {
		t.Fatal("update controller was not started")
	}

	get, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/update", nil)
	if err != nil {
		t.Fatal(err)
	}
	get.Header.Set("Authorization", "Bearer tok")
	resp, err = http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
}

func TestUpdateEndpointRejectsUnknownChannel(t *testing.T) {
	ctrl := &fakeUpdateController{}
	srv := NewServerWithBlocklist("tok", filter.NewStore(nil), cache.New(0, 0), &Counters{}, "test", blocklist.New())
	srv.SetUpdateController(ctrl)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/update?channel=feature-x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if ctrl.started {
		t.Fatal("unknown channel started an update")
	}
}

func TestUpdateEndpointRequiresController(t *testing.T) {
	srv := NewServerWithBlocklist("tok", filter.NewStore(nil), cache.New(0, 0), &Counters{}, "test", blocklist.New())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/update?channel=stable", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestUpdateEndpointRequiresAuth(t *testing.T) {
	srv := NewServerWithBlocklist("tok", filter.NewStore(nil), cache.New(0, 0), &Counters{}, "test", blocklist.New())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/update", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

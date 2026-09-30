package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
)

func TestParseAllowedNetworks(t *testing.T) {
	// Valid mix: CIDRs, bare IPs, blanks (includes the shipped defaults).
	nets, err := ParseAllowedNetworks([]string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "10.1.2.3", "fd00::1", "", "  "})
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 8 {
		t.Fatalf("len = %d, want 8", len(nets))
	}
	if _, err := ParseAllowedNetworks(nil); err != nil {
		t.Fatalf("empty must parse (open recursion), got %v", err)
	}
	// Catch-alls must be rejected, not silently opened.
	for _, bad := range []string{"0.0.0.0/0", "::/0", "not-a-cidr", "10.0.0.0/33"} {
		if _, err := ParseAllowedNetworks([]string{bad}); err == nil {
			t.Errorf("ParseAllowedNetworks(%q) accepted, want rejection", bad)
		}
	}
}

// fakeACLController validates with the shared parser, like dnsserver does.
type fakeACLController struct {
	mu   sync.Mutex
	nets []string
	open bool
}

func (f *fakeACLController) SetAllowedNetworks(networks []string) error {
	if _, err := ParseAllowedNetworks(networks); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nets = append([]string(nil), networks...)
	return nil
}

func (f *fakeACLController) AllowedNetworks() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.nets...)
}

func (f *fakeACLController) OpenRecursion() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open
}

func TestACLEndpoint(t *testing.T) {
	bl := blocklist.New()
	store := filter.NewStore(nil)
	ac := &fakeACLController{}
	srv := NewServerWithBlocklist("tok", store, cache.New(0, 0), &Counters{}, "blipd/test", bl)
	srv.SetACLController(ac)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	authReq := func(method, body string) *http.Response {
		req, _ := http.NewRequest(method, ts.URL+"/api/v1/acl", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// Unauthenticated -> 401.
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/acl", strings.NewReader(`{"networks":["10.0.0.0/8"]}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", resp.StatusCode)
	}

	// Valid PUT round-trips through GET and stats.
	resp = authReq(http.MethodPut, `{"networks":["10.0.0.0/8","fc00::/7"]}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
	}
	resp = authReq(http.MethodGet, "")
	var got map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(got["networks"]) != 2 {
		t.Fatalf("GET networks = %v, want 2 entries", got["networks"])
	}

	// Catch-all and garbage are rejected without changing the ACL.
	for _, bad := range []string{`{"networks":["0.0.0.0/0"]}`, `{"networks":["::/0"]}`, `{"networks":["bogus"]}`} {
		resp = authReq(http.MethodPut, bad)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PUT %s status = %d, want 400", bad, resp.StatusCode)
		}
	}
	if cur := ac.AllowedNetworks(); len(cur) != 2 {
		t.Errorf("ACL changed by rejected push: %v", cur)
	}

	// Unwired instance -> 503, not a silent no-op.
	srv2 := NewServerWithBlocklist("tok", store, cache.New(0, 0), &Counters{}, "blipd/test", bl)
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()
	req, _ = http.NewRequest(http.MethodPut, ts2.URL+"/api/v1/acl", strings.NewReader(`{"networks":["10.0.0.0/8"]}`))
	req.Header.Set("Authorization", "Bearer tok")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("unwired status = %d, want 503", resp.StatusCode)
	}
}

func TestStatsReportsOpenRecursion(t *testing.T) {
	bl := blocklist.New()
	store := filter.NewStore(nil)
	ac := &fakeACLController{open: true}
	srv := NewServerWithBlocklist("tok", store, cache.New(0, 0), &Counters{}, "blipd/test", bl)
	srv.SetACLController(ac)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/stats", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats status = %d, want 200", resp.StatusCode)
	}
	var st map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st["open_recursion"] != true {
		t.Errorf("stats open_recursion = %v, want true", st["open_recursion"])
	}
}

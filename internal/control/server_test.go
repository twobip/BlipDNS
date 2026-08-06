package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/miekg/dns"
)

func TestSetBlocklistEndpoint(t *testing.T) {
	bl := blocklist.New()
	bl.FromDomains([]string{"seed.example.com"})
	store := filter.NewStore(nil)
	c := cache.New(0, 0)
	srv := NewServerWithBlocklist("tok", store, c, &Counters{}, "blipd/test", bl)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body, _ := json.Marshal(SetBlocklistRequest{Domains: []string{"a.com", "*.ads.net", "b.com"}})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/blocklist", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")

	// A populated cache must be dropped by the blocklist update.
	m := new(dns.Msg)
	m.SetQuestion("a.com.", dns.TypeA)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "a.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{1, 2, 3, 4}}}
	k := cache.Key(m)
	c.Set(k, m)
	if c.Len() != 1 {
		t.Fatalf("precondition: cache Len = %d, want 1", c.Len())
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !bl.IsBlocked("a.com") || !bl.IsBlocked("sub.ads.net") {
		t.Error("blocklist not replaced by endpoint")
	}
	if bl.IsBlocked("seed.example.com") {
		t.Error("old entries should have been replaced")
	}
	if c.Len() != 0 {
		t.Errorf("cache Len after blocklist update = %d, want 0 (stale responses must be purged)", c.Len())
	}

	// stats should now report the active blocklist.
	sreq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/stats", nil)
	sreq.Header.Set("Authorization", "Bearer tok")
	sresp, err := http.DefaultClient.Do(sreq)
	if err != nil {
		t.Fatal(err)
	}
	defer sresp.Body.Close()
	var st StatsResponse
	if err := json.NewDecoder(sresp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.BlocklistCount != 3 {
		t.Errorf("blocklist_count = %d, want 3", st.BlocklistCount)
	}
	if st.BlocklistHash != bl.Checksum() {
		t.Errorf("blocklist_hash mismatch")
	}
}

func TestSetBlocklistRequiresAuth(t *testing.T) {
	bl := blocklist.New()
	store := filter.NewStore(nil)
	srv := NewServerWithBlocklist("tok", store, cache.New(0, 0), &Counters{}, "blipd/test", bl)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/blocklist", strings.NewReader(`{"domains":["x.com"]}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// fakeDoHController records every plain-HTTP DoH address it is asked to run.
type fakeDoHController struct {
	mu    sync.Mutex
	addr  string
	calls []string
}

func (f *fakeDoHController) SetDoHHTTPAddr(addr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addr = addr
	f.calls = append(f.calls, addr)
	return nil
}

func (f *fakeDoHController) DoHHTTPAddr() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addr
}

func (f *fakeDoHController) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func TestDoHEndpoint(t *testing.T) {
	bl := blocklist.New()
	store := filter.NewStore(nil)
	dc := &fakeDoHController{}
	srv := NewServerWithBlocklist("tok", store, cache.New(0, 0), &Counters{}, "blipd/test", bl)
	srv.SetDoHController(dc)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// unauthenticated -> 401
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/doh", strings.NewReader(`{"http_addr":"0.0.0.0:8445"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", resp.StatusCode)
	}

	authReq := func(method, body string) *http.Response {
		req, _ := http.NewRequest(method, ts.URL+"/api/v1/doh", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// GET reports the (empty) current address.
	resp = authReq(http.MethodGet, "")
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got["http_addr"] != "" {
		t.Errorf("initial http_addr = %q, want empty", got["http_addr"])
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", resp.StatusCode)
	}

	// PUT enables plain HTTP DoH.
	resp = authReq(http.MethodPut, `{"http_addr":"0.0.0.0:8445"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if got := dc.snapshot(); len(got) != 1 || got[0] != "0.0.0.0:8445" {
		t.Errorf("controller calls = %v, want [0.0.0.0:8445]", got)
	}

	// stats now report the address.
	sreq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/stats", nil)
	sreq.Header.Set("Authorization", "Bearer tok")
	sresp, err := http.DefaultClient.Do(sreq)
	if err != nil {
		t.Fatal(err)
	}
	var st StatsResponse
	if err := json.NewDecoder(sresp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	sresp.Body.Close()
	if st.DohHTTPAddr != "0.0.0.0:8445" {
		t.Errorf("stats doh_http_addr = %q, want 0.0.0.0:8445", st.DohHTTPAddr)
	}

	// PUT with a bad address is rejected; the controller is left unchanged.
	resp = authReq(http.MethodPut, `{"http_addr":"not-a-host"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad addr status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

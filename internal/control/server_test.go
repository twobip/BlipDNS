package control

import (
	"bytes"
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

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/twobip/BlipDNS/internal/upstream"
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

	srv.SetDoHController(nil)
}

// fakeLocalResolver records every upstream pool+routes it is asked to run,
// validating specs the way the real dnsserver.Server.SetUpstream does (via
// upstream.NewPool).
type fakeLocalResolver struct {
	mu      sync.Mutex
	servers []upstream.UpstreamServer
	routes  []upstream.UpstreamRoute
}

func (f *fakeLocalResolver) SetUpstream(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute) error {
	if _, err := upstream.NewPool(servers, routes, ""); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.servers = servers
	f.routes = routes
	return nil
}

func (f *fakeLocalResolver) Upstream() ([]upstream.UpstreamServer, []upstream.UpstreamRoute) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.servers, f.routes
}

func TestUpstreamEndpoint(t *testing.T) {
	bl := blocklist.New()
	store := filter.NewStore(nil)
	uc := &fakeLocalResolver{}
	srv := NewServerWithBlocklist("tok", store, cache.New(0, 0), &Counters{}, "blipd/test", bl)
	srv.SetLocalResolverController(uc)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// unauthenticated -> 401
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/upstream", strings.NewReader(`{"servers":[]}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", resp.StatusCode)
	}

	authReq := func(method, body string) *http.Response {
		req, _ := http.NewRequest(method, ts.URL+"/api/v1/upstream", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// GET reports the (empty) current pool.
	resp = authReq(http.MethodGet, "")
	var got struct {
		Servers []upstream.UpstreamServer `json:"servers"`
		Routes  []upstream.UpstreamRoute  `json:"routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", resp.StatusCode)
	}
	if len(got.Servers) != 0 || len(got.Routes) != 0 {
		t.Errorf("initial upstream = %+v / %+v, want empty", got.Servers, got.Routes)
	}

	// PUT installs the pool + routes.
	servers := []upstream.UpstreamServer{{Name: "quad9", Address: "udp://9.9.9.9:53", Priority: 1}}
	routes := []upstream.UpstreamRoute{{Name: "corp", QnameSuffix: ".corp.", Server: "quad9"}}
	body, _ := json.Marshal(map[string]interface{}{"servers": servers, "routes": routes})
	resp = authReq(http.MethodPut, string(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if gotS, gotR := uc.Upstream(); len(gotS) != 1 || gotS[0].Name != "quad9" || !reflect.DeepEqual(gotR, routes) {
		t.Errorf("controller upstream = %+v / %+v", gotS, gotR)
	}

	// stats now report the pool so the controller can detect drift.
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
	if !reflect.DeepEqual(st.UpstreamServers, servers) || !reflect.DeepEqual(st.UpstreamRoutes, routes) {
		t.Errorf("stats upstream = %+v / %+v, want %+v / %+v", st.UpstreamServers, st.UpstreamRoutes, servers, routes)
	}

	// An invalid server spec is rejected; the pool is left unchanged.
	resp = authReq(http.MethodPut, `{"servers":[{"name":"bad","address":"wibble://x"}]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad server status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
	if gotS, _ := uc.Upstream(); len(gotS) != 1 || gotS[0].Name != "quad9" {
		t.Errorf("controller upstream changed after rejected PUT: %+v", gotS)
	}

	srv.SetLocalResolverController(nil)
}

// TestAdoptStatusMasking verifies the unauthenticated adopt/status endpoint
// does not leak instance_id/version to casual callers — only the operator
// (valid bearer token) sees them.
func TestAdoptStatusMasking(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "blipd-state.json")
	if err := os.WriteFile(tmp, []byte(`{"adopted":true,"instance_id":"prod-42","token":"tok"}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := filter.NewStore(nil)
	srv := NewServerWithBlocklist("", store, cache.New(0, 0), &Counters{}, "blipd/1.2.3", blocklist.New())
	srv.ConfigureAdoption(tmp, "prod-42")

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Unauthenticated: adopted only, instance_id/version masked.
	body, _ := http.Get(ts.URL + "/api/v1/adopt/status")
	if body.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", body.StatusCode)
	}
	var anon AdoptStatus
	json.NewDecoder(body.Body).Decode(&anon)
	body.Body.Close()
	if anon.InstanceID != "" {
		t.Errorf("unauth instance_id = %q, want masked", anon.InstanceID)
	}
	if anon.Version != "" {
		t.Errorf("unauth version = %q, want masked", anon.Version)
	}

	// Authenticated operator sees the real values.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/adopt/status", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var authed AdoptStatus
	json.NewDecoder(resp.Body).Decode(&authed)
	resp.Body.Close()
	if authed.InstanceID != "prod-42" {
		t.Errorf("auth instance_id = %q, want prod-42", authed.InstanceID)
	}
	if authed.Version != "blipd/1.2.3" {
		t.Errorf("auth version = %q, want blipd/1.2.3", authed.Version)
	}
}

// TestClaimCodeEntropy verifies the claim code is wide enough (~80 bits) and
// one-time use is still gated by rate limiting.
func TestClaimCodeEntropy(t *testing.T) {
	c := genClaimCode()
	// 16 symbols from a 32-symbol alphabet, grouped as 8-8.
	if len(c) != 8+1+8 {
		t.Errorf("claim code length = %d (%q), want 17 chars", len(c), c)
	}
	for i := 0; i < 50; i++ {
		if genClaimCode() == c {
			t.Fatalf("claim code collision on %d-th draw", i)
		}
	}
}

type fakeCacheCtrl struct {
	mu      sync.Mutex
	size    int
	warm    int
	regular int // seconds
	purged  int
	counter int
	c       *cache.Cache
}

func (f *fakeCacheCtrl) SetCacheConfig(size, warm int, regular time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counter++
	f.size = size
	f.warm = warm
	f.regular = int(regular.Seconds())
	return nil
}

func (f *fakeCacheCtrl) CacheSize() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.size
}

func (f *fakeCacheCtrl) CacheWarm() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.warm
}

func (f *fakeCacheCtrl) CacheRegular() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return time.Duration(f.regular) * time.Second
}

func (f *fakeCacheCtrl) PurgeCache() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purged++
	if f.c != nil {
		f.c.Purge()
	}
}

// TestCacheEndpoint exercises GET /api/v1/cache, PUT /api/v1/cache and
// POST /api/v1/cache/purge with a wired cache controller.
func TestCacheEndpoint(t *testing.T) {
	cc := &fakeCacheCtrl{size: 123, warm: 4}
	store := filter.NewStore(nil)
	c := cache.New(0, 0)
	cc.c = c
	srv := NewServerWithBlocklist("tok", store, c, &Counters{}, "blipd/test", blocklist.New())
	srv.SetCacheController(cc)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	authReq := func(method, path, body string) *http.Response {
		var rd *strings.Reader
		if body == "" {
			rd = strings.NewReader("")
		} else {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rd)
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// unauth -> 401
	ureq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/cache", strings.NewReader(`{"size":500,"warm":10}`))
	uresp, err := http.DefaultClient.Do(ureq)
	if err != nil {
		t.Fatal(err)
	}
	uresp.Body.Close()
	if uresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", uresp.StatusCode)
	}

	// GET reports the wired cache controller's config
	resp := authReq(http.MethodGet, "/api/v1/cache", "")
	var got struct {
		Size int `json:"size"`
		Warm int `json:"warm"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.Size != 123 || got.Warm != 4 {
		t.Errorf("GET cache = %+v, want size=123 warm=4", got)
	}

	// PUT tunes it and reports in stats (for controller reconcile)
	resp = authReq(http.MethodPut, "/api/v1/cache", `{"size":500,"warm":10}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if cc.CacheSize() != 500 || cc.CacheWarm() != 10 {
		t.Errorf("controller cache = %d/%d, want 500/10", cc.CacheSize(), cc.CacheWarm())
	}
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
	if st.CacheSize != 500 || st.CacheWarm != 10 {
		t.Errorf("stats cache = %d/%d, want 500/10", st.CacheSize, st.CacheWarm)
	}

	// negative values are rejected
	resp = authReq(http.MethodPut, "/api/v1/cache", `{"size":-1,"warm":0}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("negative size status = %d, want 400", resp.StatusCode)
	}
	if cc.CacheSize() != 500 {
		t.Errorf("cache size changed after rejected PUT: %d", cc.CacheSize())
	}

	// purge drops entries and reports the count
	m := new(dns.Msg)
	m.SetQuestion("a.com.", dns.TypeA)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "a.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{1, 2, 3, 4}}}
	c.Set(cache.Key(m), m)
	if c.Len() != 1 {
		t.Fatalf("precondition: cache Len = %d, want 1", c.Len())
	}
	resp = authReq(http.MethodPost, "/api/v1/cache/purge", "")
	var pr PurgeCacheResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if pr.Purged != 1 {
		t.Errorf("purged = %d, want 1", pr.Purged)
	}
	if c.Len() != 0 {
		t.Errorf("cache Len after purge = %d, want 0", c.Len())
	}
	if cc.purged != 1 {
		t.Errorf("controller PurgeCache called %d times, want 1", cc.purged)
	}

	// without a wired controller the endpoints are unavailable
	srv.SetCacheController(nil)
	resp = authReq(http.MethodGet, "/api/v1/cache", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("nil controller status = %d, want 503", resp.StatusCode)
	}
}

// fakeRecordController records every record push and serves reads from it,
// mirroring the contract the real dnsserver.RecordStore implements.
type fakeRecordController struct {
	mu      sync.Mutex
	records []RecordEntry
}

func (f *fakeRecordController) SetRecords(records []RecordEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = make([]RecordEntry, len(records))
	copy(f.records, records)
	return nil
}

func (f *fakeRecordController) GetRecords() ([]RecordEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]RecordEntry, len(f.records))
	copy(out, f.records)
	return out, nil
}

func (f *fakeRecordController) ClearRecords() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = nil
	return nil
}

func TestRecordsEndpoint(t *testing.T) {
	rc := &fakeRecordController{}
	store := filter.NewStore(nil)
	srv := NewServerWithBlocklist("tok", store, cache.New(0, 0), &Counters{}, "blipd/test", blocklist.New())
	srv.SetRecordController(rc)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	authReq := func(method, body string) *http.Response {
		var rd *strings.Reader
		if body == "" {
			rd = strings.NewReader("")
		} else {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+"/api/v1/records", rd)
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// unauthenticated -> 401
	ureq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/records", nil)
	uresp, err := http.DefaultClient.Do(ureq)
	if err != nil {
		t.Fatal(err)
	}
	uresp.Body.Close()
	if uresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", uresp.StatusCode)
	}

	// GET reports empty initially.
	resp := authReq(http.MethodGet, "")
	var got RecordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(got.Records) != 0 {
		t.Fatalf("initial records = %d, want 0", len(got.Records))
	}

	// PUT installs records.
	recs := []RecordEntry{
		{Domain: "server.lan", Type: "A", Value: "192.168.1.100", TTL: 60},
		{Domain: "server.lan", Type: "AAAA", Value: "2001:db8::1", TTL: 60},
		{Domain: "alias.lan", Type: "CNAME", Value: "server.lan", TTL: 0},
	}
	body, _ := json.Marshal(SetRecordsRequest{Records: recs})
	resp = authReq(http.MethodPut, string(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// GET reports the pushed records.
	resp = authReq(http.MethodGet, "")
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(got.Records) != 3 {
		t.Fatalf("records after PUT = %d, want 3", len(got.Records))
	}

	// stats now report the records hash so the controller can converge.
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
	if st.RecordsHash != RecordsHash(recs) {
		t.Errorf("stats records_hash = %d, want %d", st.RecordsHash, RecordsHash(recs))
	}

	// PUT with empty records clears.
	authReq(http.MethodPut, `{"records":[]}`)
	got2, _ := rc.GetRecords()
	if len(got2) != 0 {
		t.Errorf("records after empty PUT = %d, want 0", len(got2))
	}

	// DELETE clears.
	authReq(http.MethodPut, string(body))
	resp = authReq(http.MethodDelete, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	got3, _ := rc.GetRecords()
	if len(got3) != 0 {
		t.Errorf("records after DELETE = %d, want 0", len(got3))
	}

	// without a wired controller the endpoints are unavailable
	srv.SetRecordController(nil)
	resp = authReq(http.MethodGet, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("nil controller status = %d, want 503", resp.StatusCode)
	}
}

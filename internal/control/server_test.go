package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

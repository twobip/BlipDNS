// Copyright 2025 The BlipDNS Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package blocklist

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestMain disables the SSRF guard for the test suite, since the LoadFromURLs
// tests fetch from httptest servers bound to 127.0.0.1. A dedicated test
// (TestSSRFProtection) re-enables it to confirm private/metadata hosts are
// blocked.
func TestMain(m *testing.M) {
	saved := ssrfEnabled
	ssrfEnabled = false
	code := m.Run()
	ssrfEnabled = saved
	os.Exit(code)
}

func TestSSRFProtection(t *testing.T) {
	ssrfEnabled = true
	defer func() { ssrfEnabled = false }()
	for _, u := range []string{
		"http://127.0.0.1/x", "http://localhost/x", "http://169.254.169.254/latest/x",
		"http://10.0.0.1/x", "http://192.168.1.1/x", "ftp://example.com/x",
		"http://100.64.0.1/x", "http://100.100.100.200/latest/x",
	} {
		if _, err := FetchSource(context.Background(), u, Validators{}); err == nil {
			t.Errorf("FetchSource(%q) should have been blocked", u)
		}
	}
}

func TestIsCGNAT(t *testing.T) {
	for _, s := range []string{"100.64.0.1", "100.100.100.200", "100.127.255.255"} {
		if !IsCGNAT(net.ParseIP(s)) {
			t.Errorf("IsCGNAT(%s) = false, want true", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "10.0.0.1", "169.254.169.254", "101.64.0.1", "99.64.0.1"} {
		if IsCGNAT(net.ParseIP(s)) {
			t.Errorf("IsCGNAT(%s) = true, want false", s)
		}
	}
}

func TestIsBlocked(t *testing.T) {
	b := New()
	b.Add("ads.example.com")
	tests := []struct {
		host string
		want bool
		desc string
	}{
		{"ads.example.com", true, "exact match"},
		{"sub.ads.example.com", true, "subdomain"},
		{"a.b.ads.example.com", true, "deep subdomain"},
		{"example.com", false, "parent domain not blocked"},
		{"ads.example.com.", true, "trailing dot"},
		{"ADS.EXAMPLE.COM", true, "case insensitive"},
		{"notads.example.com", false, "similar but not subdomain"},
		{"", false, "empty host"},
	}
	for _, tt := range tests {
		if got := b.IsBlocked(tt.host); got != tt.want {
			t.Errorf("%s: IsBlocked(%q) = %v, want %v", tt.desc, tt.host, got, tt.want)
		}
	}
}

func TestIsBlockedNormalized(t *testing.T) {
	b := New()
	b.Add("ads.example.com")
	for _, h := range []string{"ads.example.com", "sub.ads.example.com"} {
		if !b.IsBlockedNormalized(h) {
			t.Errorf("IsBlockedNormalized(%q) = false, want true", h)
		}
		if !b.IsBlocked(h) {
			t.Errorf("precondition: IsBlocked(%q) = false", h)
		}
	}
	for _, h := range []string{"", ".", "..", "example.com"} {
		if b.IsBlockedNormalized(h) {
			t.Errorf("IsBlockedNormalized(%q) = true, want false", h)
		}
	}
	// Normalized path skips case-folding by contract (callers pass
	// filter.NormalizeName output); IsBlocked still folds.
	if b.IsBlockedNormalized("ADS.EXAMPLE.COM") {
		t.Error("IsBlockedNormalized must not fold case (precondition: lowercased input)")
	}
	if !b.IsBlocked("ADS.EXAMPLE.COM") {
		t.Error("precondition: IsBlocked folds case")
	}
}

func TestAddRemove(t *testing.T) {
	b := New()
	b.Add("bad.com")
	if !b.IsBlocked("bad.com") {
		t.Error("expected bad.com to be blocked after Add")
	}
	b.Remove("bad.com")
	if b.IsBlocked("bad.com") {
		t.Error("expected bad.com not blocked after Remove")
	}
}

func TestList(t *testing.T) {
	b := New()
	b.Add("z.com")
	b.Add("a.com")
	list := b.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 items, got %d: %v", len(list), list)
	}
	// List order is undefined (map iteration), just check both are present.
	seen := make(map[string]bool)
	for _, d := range list {
		seen[d] = true
	}
	if !seen["a.com"] || !seen["z.com"] {
		t.Errorf("expected a.com and z.com in list, got %v", list)
	}
}

func TestFromDomainsAndReplace(t *testing.T) {
	b := New()
	b.FromDomains([]string{"evil.com", "*.ads.net", ""})
	if !b.IsBlocked("evil.com") {
		t.Error("expected evil.com blocked")
	}
	if !b.IsBlocked("sub.ads.net") {
		t.Error("expected sub.ads.net blocked")
	}
	if b.IsBlocked("ads.net") {
		t.Error("expected ads.net NOT blocked (wildcard only matches subdomains)")
	}
	// Replace list
	b.FromDomains([]string{"only.com"})
	if !b.IsBlocked("only.com") {
		t.Error("expected only.com blocked after replace")
	}
	if b.IsBlocked("evil.com") {
		t.Error("expected evil.com not blocked after replace")
	}
	// Clear
	b.FromDomains([]string{})
	if b.IsBlocked("anything") {
		t.Error("expected nothing blocked after clear")
	}
}

func TestNormalize(t *testing.T) {
	b := New()
	b.Add("Ads.Example.COM.")
	if !b.IsBlocked("ads.example.com") {
		t.Error("should match after normalize")
	}
	if !b.IsBlocked("SUB.ADS.EXAMPLE.COM.") {
		t.Error("suffix match should ignore case/trailing dot")
	}
}

// TestLoadFromURL is skipped because it requires network.
// To test manually, you can uncomment and run with -run TestLoadFromURL.
// func TestLoadFromURL(t *testing.T) {
// 	b := New()
// 	// Use a known public adblock list (small one for testing)
// 	const testURL = "https://easylist.to/easylist/easylist.txt"
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()
// 	if err := b.LoadFromURL(ctx, testURL); err != nil {
// 		t.Fatalf("LoadFromURL failed: %v", err)
// 	}

// 	// Check that we got some domains
// 	if len(b.List()) == 0 {
// 		t.Error("expected at least one domain from the list")
// 	}

// 	// Check a known domain from EasyList (as of time of writing)
// 	if !b.IsBlocked("ad.doubleclick.net") {
// 		t.Error("expected to block a known ad domain")
// 	}
// }

func TestConcurrentAccess(t *testing.T) {
	b := New()
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				b.Add("test.domain.com")
				_ = b.IsBlocked("test.domain.com")
				_ = b.List()
				b.Remove("test.domain.com")
			}
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestWildcardSemantics(t *testing.T) {
	b := New()
	b.FromDomains([]string{"*.ads.net"})
	for host, want := range map[string]bool{
		"sub.ads.net":     true,
		"a.b.ads.net":     true,
		"ads.net":         false,
		"notads.net":      false,
		"x.ads.net.other": false,
	} {
		if got := b.IsBlocked(host); got != want {
			t.Errorf("IsBlocked(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestChecksumOrderIndependent(t *testing.T) {
	b := New()
	b.FromDomains([]string{"a.com", "b.com", "c.net"})
	base := b.Checksum()
	b2 := New()
	b2.FromDomains([]string{"c.net", "a.com", "b.com"})
	if base != b2.Checksum() {
		t.Errorf("checksums differ for same set in different order: %d vs %d", base, b2.Checksum())
	}
	b.Add("d.org")
	b.Remove("d.org")
	if base != b.Checksum() {
		t.Errorf("checksum changed after add+remove of same domain")
	}
}

func TestFromDomainsMap(t *testing.T) {
	b := New()
	b.FromDomainsMap(map[string]struct{}{"evil.com": {}, "*.wild.net": {}, "com": {}})
	if !b.IsBlocked("evil.com") || !b.IsBlocked("x.wild.net") || b.IsBlocked("wild.net") {
		t.Error("FromDomainsMap normalization failed")
	}
	// Audit 2026-10-01 #7: a bare single label must be dropped at ingest, so
	// it can never block a whole TLD via the ancestor walk.
	if b.IsBlocked("com") || b.IsBlocked("anything.com") {
		t.Error("bare TLD entry must be rejected, not stored")
	}
}

// Audit 2026-10-01 #7: no ingest path may store a bare single label — one
// feed line "com" previously NXDOMAIN'd every .com lookup fleet-wide.
func TestSingleLabelRejected(t *testing.T) {
	for _, s := range []string{"com", "localhost", "lan", "COM", "com.", ".com"} {
		if got := normalizeDomain(s); got != "" {
			t.Errorf("normalizeDomain(%q) = %q, want empty", s, got)
		}
	}
	merged := map[string]struct{}{}
	allowed := map[string]struct{}{}
	for _, line := range []string{"com", "localhost", "||com^", "0.0.0.0 localhost", "*.bad..label", "*."} {
		if parseLine(line, merged, allowed) {
			t.Errorf("parseLine(%q) accepted a single-label entry", line)
		}
	}
	if len(merged) != 0 {
		t.Errorf("parseLine stored single-label entries: %v", merged)
	}
	b := New()
	b.Add("com")
	b.Add("localhost")
	b.AddAllowed("com")
	if b.IsBlocked("example.com") || b.IsBlocked("com") || b.IsBlocked("localhost") {
		t.Error("stored single label blocks lookups it must not")
	}
	// Explicit "*.<tld>" wildcards keep working: unlike a bare feed line,
	// they state TLD-wide intent (pinned by TestDenyallowExceptionsAllowlisted).
	w := New()
	w.FromDomains([]string{"*.lol"})
	if !w.IsBlocked("evil.lol") {
		t.Error("explicit *.lol wildcard must still block its subdomains")
	}
}

func TestFetchSourceNotModified(t *testing.T) {
	var sawValidators string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			sawValidators = r.Header.Get("If-None-Match")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")
		io.WriteString(w, "||ads.example.com^\n")
	}))
	defer srv.Close()

	ctx := context.Background()
	first, err := FetchSource(ctx, srv.URL, Validators{})
	if err != nil {
		t.Fatalf("FetchSource: %v", err)
	}
	if first.NotModified || len(first.Domains) != 1 {
		t.Fatalf("first fetch = %+v, want 1 domain", first)
	}
	if first.Validators.ETag != `"v1"` || first.Validators.LastModified == "" {
		t.Errorf("validators not captured: %+v", first.Validators)
	}

	second, err := FetchSource(ctx, srv.URL, first.Validators)
	if err != nil {
		t.Fatalf("conditional FetchSource: %v", err)
	}
	if !second.NotModified || len(second.Domains) != 0 {
		t.Fatalf("second fetch = %+v, want NotModified", second)
	}
	if sawValidators != `"v1"` {
		t.Errorf("server saw If-None-Match %q, want %q", sawValidators, `"v1"`)
	}
}

func TestLoadFromURLsMixedFormats(t *testing.T) {
	abp := `! Title: test
## ad-slot
||ads.example.com^$script
|http://tracker.example.net^
plain.example.org
||banner.example.com^
`
	hosts := `127.0.0.1 localhost
0.0.0.0 hostfile.example.io
# comment
0.0.0.0 hostfile.example.io
`
	var progressed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abp.txt":
			io.WriteString(w, abp)
		case "/hosts":
			io.WriteString(w, hosts)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	b := New()
	res, err := b.LoadFromURLs(context.Background(), []string{srv.URL + "/abp.txt", srv.URL + "/hosts"}, &LoadOptions{
		Progress: func(Progress) { progressed = true },
	})
	if err != nil {
		t.Fatalf("LoadFromURLs: %v", err)
	}
	if res.Failed != 0 || res.Domains != 5 {
		t.Fatalf("result = %+v, want 0 failed / 5 domains", res)
	}
	if !progressed {
		t.Error("progress callback was not invoked")
	}
	for _, d := range []string{"ads.example.com", "tracker.example.net", "plain.example.org", "banner.example.com", "hostfile.example.io"} {
		if !b.IsBlocked(d) {
			t.Errorf("expected %q blocked", d)
		}
	}
	// Audit 2026-10-01 #7: the hosts-file "localhost" line is a bare single
	// label and must be dropped, not stored.
	if b.IsBlocked("localhost") {
		t.Error("single-label hosts entry must not be blocked")
	}
	if b.IsBlocked("example.com") {
		t.Error("unexpected entries blocked")
	}
}

func TestLoadFromURLsPartialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "||good.example.com^\n")
	}))
	defer srv.Close()

	b := New()
	res, err := b.LoadFromURLs(context.Background(), []string{srv.URL + "/ok", srv.URL + "/missing"}, nil)
	if err != nil {
		t.Fatalf("LoadFromURLs with partial failure: %v", err)
	}
	if res.Failed != 1 || res.Domains != 1 {
		t.Fatalf("result = %+v, want 1 failed / 1 domain", res)
	}
	if !b.IsBlocked("good.example.com") {
		t.Error("expected good.example.com blocked despite one failed source")
	}
}

func TestLoadFromURLsAllFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	b := New()
	if _, err := b.LoadFromURLs(context.Background(), []string{srv.URL + "/x", srv.URL + "/y"}, nil); err == nil {
		t.Fatal("expected error when all sources fail")
	}
	if b.Count() != 0 {
		t.Error("expected empty blocklist after all sources failed")
	}
}

func TestCacheRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.cache")
	b := New()
	b.Add("ads.example.com")
	b.Add("*.tracker.net")

	if err := b.SaveCache(path); err != nil {
		t.Fatalf("SaveCache: %v", err)
	}
	if !b.IsBlocked("ads.example.com") {
		t.Error("original list lost its entry after SaveCache")
	}

	restored, err := LoadCache(path)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if restored == nil || restored.Count() != 2 {
		t.Fatalf("restored count = %v, want 2", restored.Count())
	}
	if !restored.IsBlocked("ads.example.com") || !restored.IsBlocked("sub.tracker.net") {
		t.Error("restored list does not block expected hosts")
	}
	if restored.Checksum() != b.Checksum() {
		t.Error("restored checksum differs from original")
	}

	// A missing cache is not an error.
	missing, err := LoadCache(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("LoadCache missing file: %v", err)
	}
	if missing != nil {
		t.Error("expected nil blocklist for missing cache file")
	}
}

func TestAllowlistOverridesBlocklist(t *testing.T) {
	bl := New()
	bl.FromDomains([]string{"ads.example.com", "tracker.net", "*.tracker.net", "blocked.org"})

	// Exact allow beats exact/suffix block for the host and its subdomains.
	bl.SetAllowed([]string{"ads.example.com"})
	if bl.IsBlocked("ads.example.com") {
		t.Error("allowed root must not be blocked")
	}
	if bl.IsBlocked("sub.ads.example.com") {
		t.Error("subdomain of allowed root must not be blocked")
	}

	// A narrow exact allow only covers that host.
	bl.SetAllowed([]string{"ok.ads.example.com"})
	if bl.IsBlocked("ok.ads.example.com") {
		t.Error("exactly allowed host must not be blocked")
	}
	if !bl.IsBlocked("ads.example.com") {
		t.Error("other host under the blocked root must stay blocked")
	}

	// Wildcard allow covers strict subdomains but not the root itself.
	bl.SetAllowed([]string{"*.tracker.net"})
	if bl.IsBlocked("sub.tracker.net") {
		t.Error("subdomain allowed by *.root must not be blocked")
	}
	if !bl.IsBlocked("tracker.net") {
		t.Error("root must stay blocked: *.root allow does not cover the root")
	}

	// Unrelated domains are unaffected.
	if !bl.IsBlocked("blocked.org") {
		t.Error("blocked.org must stay blocked")
	}
	if bl.IsBlocked("nothing.example.com") {
		t.Error("unlisted domain must not be blocked")
	}

	// Clearing the allow set restores the block.
	bl.SetAllowed(nil)
	if !bl.IsBlocked("sub.tracker.net") {
		t.Error("sub.tracker.net must be blocked again after allow cleared")
	}

	// Checksum changes when the allow set changes (drives re-push convergence).
	sum1 := bl.Checksum()
	bl.AddAllowed("new-allow.example.com")
	sum2 := bl.Checksum()
	bl.RemoveAllowed("new-allow.example.com")
	if sum1 == sum2 || sum2 == bl.Checksum() {
		t.Error("checksum must reflect allow-set changes")
	}
}

func TestCacheRoundtripWithAllowed(t *testing.T) {
	bl := New()
	bl.FromDomains([]string{"a.example.com", "*.wild.net"})
	bl.SetAllowed([]string{"keep.example.com", "*.tracker.net"})

	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	if err := bl.SaveCache(path); err != nil {
		t.Fatalf("SaveCache: %v", err)
	}
	got, err := LoadCache(path)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if !got.IsBlocked("a.example.com") || !got.IsBlocked("x.wild.net") {
		t.Error("blocked set not restored from cache")
	}
	if got.IsBlocked("keep.example.com") || got.IsBlocked("x.tracker.net") {
		t.Error("allowed set not restored from cache (domains still blocked)")
	}

	// Legacy cache (bare array) must still load, with no allow set.
	legacy := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(legacy, []byte(`["old.example.com","*.legacy.net"]`), 0640); err != nil {
		t.Fatal(err)
	}
	l, err := LoadCache(legacy)
	if err != nil {
		t.Fatalf("LoadCache legacy: %v", err)
	}
	if !l.IsBlocked("old.example.com") || !l.IsBlocked("sub.legacy.net") {
		t.Error("legacy cache blocked set not restored")
	}
}

func TestHashStringVectors(t *testing.T) {
	// Pinned against hash/fnv FNV-1a 32 (recorded 2026-09-21): the hand-rolled
	// loop must stay bit-identical so checksums never flap across versions.
	for in, want := range map[string]uint64{
		"":                       0x811c9dc5,
		"foobar":                 0xbf9cf968,
		"a.com":                  0x60f68a87,
		"*.ads.net":              0xbed21764,
		"allow:keep.example.com": 0x3627a336,
		"host-42.example-42.com": 0xa8a535ee,
	} {
		if got := hashString(in); got != want {
			t.Errorf("hashString(%q) = 0x%08x, want 0x%08x", in, got, want)
		}
	}
}

func TestParseHostsAnyIP(t *testing.T) {
	set := make(map[string]struct{})
	allowed := make(map[string]struct{})
	for _, line := range []string{
		"127.0.0.2 evil.example.com",
		"8.8.8.8 ads.example.net",
		"::ffff:1.2.3.4 v6.example.org",
		"0.0.0.0 dup.example.com",
		"0.0.0.0 dup.example.com",
	} {
		if !parseLine(line, set, allowed) && line != "0.0.0.0 dup.example.com" {
			t.Errorf("parseLine(%q) = false, want true", line)
		}
	}
	for _, d := range []string{"evil.example.com", "ads.example.net", "v6.example.org", "dup.example.com"} {
		if _, ok := set[d]; !ok {
			t.Errorf("expected %q in set %v", d, set)
		}
	}
	if len(set) != 4 {
		t.Errorf("set = %v, want 4 unique domains (no garbage keys)", set)
	}
	// Digit-leading domains must still parse as domains, not hosts lines.
	set2 := make(map[string]struct{})
	if !parseLine("123movies.example.com", set2, allowed) {
		t.Error("parseLine(123movies.example.com) = false, want true")
	}
	if _, ok := set2["123movies.example.com"]; !ok {
		t.Errorf("digit-leading domain missing from %v", set2)
	}
}

// TestParseSkipsNonDNSFilters pins the fix for a fleet-wide outage class:
// uBlock Origin's IP-scoped filters ("||com^$doc,ipaddress=...") can't be
// evaluated at DNS level and carry a bare TLD fragment as their hostname
// part, while cosmetic filters ("top##body > center") carry an injection
// scope instead of a domain. After a badware.txt refresh, parsing either
// class into the block set NXDOMAIN'd every .com lookup (and blocked .top,
// .cc, .at, .icu, ...) on all resolvers. Both must be skipped entirely.
func TestParseSkipsNonDNSFilters(t *testing.T) {
	set := make(map[string]struct{})
	allowed := make(map[string]struct{})
	for _, line := range []string{
		"||com^$doc,ipaddress=206.82.7.123",
		"||com^$doc,ipaddress=38.114.120.167",
		"||top^$doc,ipaddress=15.207.81.128",
		"||at^$script,xhr,3p,ipaddress=185.215.113.111",
		"||sbs^$doc,ipaddress=166.117.237.67",
		`app##center#yangchen > iframe#external-frame[src="https://im136.mom/"]:not([class])`,
		"top##body > center + .A + .post",
		`monster###bw-rc-host[style="position: fixed !important; inset: 0px !important;"]`,
		"example.com#?#div.ad",
		"example#@#rule",
		"example#$#rule",
	} {
		if parseLine(line, set, allowed) {
			t.Errorf("parseLine(%q) = true, want skipped", line)
		}
	}
	if len(set) != 0 {
		t.Fatalf("set = %v, want empty: none of these lines may block a domain", set)
	}
	if len(allowed) != 0 {
		t.Fatalf("allowed = %v, want empty: skipped lines must not contribute exceptions", allowed)
	}
	// Options without ipaddress= must parse as before.
	if !parseLine("||evil.example.com^$doc,domain=~good.example.com", set, allowed) {
		t.Error("plain $doc filter no longer parses")
	}
	if _, ok := set["evil.example.com"]; !ok {
		t.Errorf("evil.example.com missing from %v", set)
	}
	if len(allowed) != 0 {
		t.Errorf("allowed = %v, want empty: $doc/$domain= carry no exceptions", allowed)
	}
	// A "#" after whitespace is a hosts-style trailing comment, not a
	// cosmetic scope: the domain before it must still be picked up.
	if !parseLine("0.0.0.0 ads.example.net ## comment", set, allowed) {
		t.Error("hosts line with ##-style trailing comment no longer parses")
	}
	if _, ok := set["ads.example.net"]; !ok {
		t.Errorf("ads.example.net missing from %v", set)
	}
}

// TestDenyallowExceptionsAllowlisted pins the handling of "$denyallow=" — the
// gesture hagezi's spam-tlds uses to block a whole TLD except its named sites
// ("||*.lol^$denyallow=adsb.lol|ags.lol", "||*.wiki^$denyallow=...", 164 of
// its 460 entries carry the option). The block entry must survive and the
// exceptions must land in the allow set; before this, the option was dropped
// and every listed site (adsb.lol's re-api included) NXDOMAIN'd fleet-wide.
func TestDenyallowExceptionsAllowlisted(t *testing.T) {
	body := `! Title: hagezi spam-tlds (abridged)
||*.lol^$denyallow=adsb.lol|ags.lol
||*.wiki^$doc,denyallow=minecraft.wiki|osrs.wiki
||*.rest^$doc,domain=~good.rest
||*.bad^$denyallow=also..broken|
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	defer srv.Close()

	fr, err := FetchSource(context.Background(), srv.URL, Validators{})
	if err != nil {
		t.Fatalf("FetchSource: %v", err)
	}
	for _, d := range []string{"*.lol", "*.wiki", "*.rest", "*.bad"} {
		if _, ok := fr.Domains[d]; !ok {
			t.Errorf("block entry %q missing from %v", d, fr.Domains)
		}
	}
	for _, d := range []string{"adsb.lol", "ags.lol", "minecraft.wiki", "osrs.wiki"} {
		if _, ok := fr.Allowed[d]; !ok {
			t.Errorf("denyallow exception %q missing from %v", d, fr.Allowed)
		}
		if _, ok := fr.Domains[d]; ok {
			t.Errorf("exception %q leaked into the block set", d)
		}
	}
	if len(fr.Allowed) != 4 {
		t.Errorf("Allowed = %v, want exactly the 4 valid exceptions", fr.Allowed)
	}

	// End to end: an exception beats the whole-TLD block (subdomains too),
	// while everything else under the TLD stays blocked.
	bl := New()
	bl.FromDomainsMap(fr.Domains)
	allowed := make([]string, 0, len(fr.Allowed))
	for d := range fr.Allowed {
		allowed = append(allowed, d)
	}
	bl.SetAllowed(allowed)
	if bl.IsBlocked("re-api.adsb.lol") || bl.IsBlocked("adsb.lol") {
		t.Error("adsb.lol blocked: denyallow must exempt the listed domain and its subdomains")
	}
	if !bl.IsBlocked("evil.lol") {
		t.Error("evil.lol not blocked: the *.lol entry must stay effective")
	}
	if bl.IsBlocked("minecraft.wiki") || !bl.IsBlocked("random.wiki") {
		t.Error("*.wiki handling wrong: exception must pass, other subdomains stay blocked")
	}

	// LoadFromURLs (standalone blipd) applies the source's exceptions too.
	b2 := New()
	if _, err := b2.LoadFromURLs(context.Background(), []string{srv.URL}, nil); err != nil {
		t.Fatalf("LoadFromURLs: %v", err)
	}
	if b2.IsBlocked("re-api.adsb.lol") {
		t.Error("LoadFromURLs did not apply denyallow exceptions")
	}
	if !b2.IsBlocked("spam.lol") {
		t.Error("LoadFromURLs lost the *.lol block")
	}
}

func TestLoadFromURLsPerSourceCounts(t *testing.T) {
	listA := "||a.example.com^\n||b.example.com^\n"
	listB := "||b.example.com^\n||c.example.com^\n||d.example.org^\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a.txt":
			io.WriteString(w, listA)
		case "/b.txt":
			io.WriteString(w, listB)
		case "/bad":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	urls := []string{srv.URL + "/a.txt", srv.URL + "/b.txt", srv.URL + "/bad"}
	b := New()
	res, err := b.LoadFromURLs(context.Background(), urls, nil)
	if err != nil {
		t.Fatalf("LoadFromURLs: %v", err)
	}
	if res.Failed != 1 {
		t.Fatalf("failed = %d, want 1", res.Failed)
	}
	// a.txt has 2 domains, b.txt has 3 (b.example.com overlaps), bad fails.
	if len(res.PerSource) != 3 {
		t.Fatalf("PerSource length = %d, want 3", len(res.PerSource))
	}
	if res.PerSource[0].Domains != 2 || res.PerSource[0].Err != "" {
		t.Errorf("PerSource[0] = %+v, want 2 domains / no error", res.PerSource[0])
	}
	if res.PerSource[1].Domains != 3 || res.PerSource[1].Err != "" {
		t.Errorf("PerSource[1] = %+v, want 3 domains / no error", res.PerSource[1])
	}
	if res.PerSource[2].Err == "" {
		t.Errorf("PerSource[2] = %+v, want an error recorded", res.PerSource[2])
	}
	// Merged total dedupes the shared b.example.com: a(2)+b(3)-overlap(1) = 4.
	if res.Domains != 4 {
		t.Errorf("merged domains = %d, want 4", res.Domains)
	}
}

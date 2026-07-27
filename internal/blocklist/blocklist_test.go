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
	"testing"
)

func TestIsBlocked(t *testing.T) {
	b := New()
	b.Add("ads.example.com")
	tests := []struct {
		host   string
		want   bool
		desc   string
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
	// List should be sorted (by implementation)
	if list[0] != "a.com" || list[1] != "z.com" {
		t.Errorf("unexpected list order: %v", list)
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
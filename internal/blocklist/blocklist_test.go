package blocklist

import (
	"testing"
)

func TestExactMatch(t *testing.T) {
	b := New()
	b.Add("ads.example.com")
	tests := []struct{ name string; want bool }{
		{"ads.example.com", true},
		{"sub.ads.example.com", true}, // suffix match: ads.example.com is a suffix root
		{"other.com", false},
		{"", false},
	}
	for _, tt := range tests {
		got := b.Match(tt.name)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSuffixMatch(t *testing.T) {
	b := New()
	b.Add("example.com")
	tests := []struct{ name string; want bool }{
		{"example.com", true},
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
		{"notexample.com", false},
		{"example.com.", true}, // trailing dot stripped
	}
	for _, tt := range tests {
		got := b.Match(tt.name)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestWildcardMatch(t *testing.T) {
	b := New()
	b.Add("*.tracker.net")
	tests := []struct{ name string; want bool }{
		{"sub.tracker.net", true},
		{"deep.sub.tracker.net", true},
		{"tracker.net", false}, // wildcard doesn't match the root itself
		{"nottracker.net", false},
		{"ads.example.com", false},
	}
	for _, tt := range tests {
		got := b.Match(tt.name)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestRemove(t *testing.T) {
	b := New()
	b.Add("ads.example.com")
	b.Add("*.tracker.net")
	if !b.Match("ads.example.com") {
		t.Error("ads.example.com should be blocked before remove")
	}
	b.Remove("ads.example.com")
	if b.Match("ads.example.com") {
		t.Error("ads.example.com should NOT be blocked after remove")
	}
	b.Remove("*.tracker.net")
	if b.Match("sub.tracker.net") {
		t.Error("sub.tracker.net should NOT be blocked after wildcard remove")
	}
}

func TestList(t *testing.T) {
	b := New()
	b.Add("ads.example.com")
	b.Add("*.tracker.net")
	list := b.List()
	if len(list) != 2 {
		t.Errorf("expected 2 entries, got %d: %v", len(list), list)
	}
	// List is sorted
	if list[0] != "*.tracker.net" || list[1] != "ads.example.com" {
		t.Errorf("List not sorted: %v", list)
	}
}

func TestFromDomainsAndReplace(t *testing.T) {
	b := FromDomains([]string{"evil.com", "*.ads.net", ""})
	if b.Len() != 2 {
		t.Fatalf("Len()=%d want 2", b.Len())
	}
	if !b.Match("evil.com") || !b.Match("sub.ads.net") {
		t.Fatal("FromDomains should seed matches")
	}
	b.Replace([]string{"only.com"})
	if b.Len() != 1 || !b.Match("only.com") || b.Match("evil.com") {
		t.Fatalf("Replace failed: list=%v", b.List())
	}
	b.Clear()
	if b.Len() != 0 || b.Match("only.com") {
		t.Fatal("Clear should empty the list")
	}
}

func TestNormalizeTrailingDotAndCase(t *testing.T) {
	b := New()
	b.Add("Ads.Example.COM.")
	if !b.Match("ads.example.com") {
		t.Error("should match after normalize")
	}
	if !b.Match("SUB.ADS.EXAMPLE.COM.") {
		t.Error("suffix match should ignore case/trailing dot")
	}
}

func TestConcurrentAccess(t *testing.T) {
	b := New()
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				b.Add("test.domain.com")
				_ = b.Match("test.domain.com")
				_ = b.List()
				_ = b.Len()
				b.Remove("test.domain.com")
			}
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

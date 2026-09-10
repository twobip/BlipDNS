package blocklist

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func genDomains(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("host-%d.example-%d.com", i, i%1000))
	}
	return out
}

func BenchmarkFromDomainsMap(b *testing.B) {
	set := make(map[string]struct{})
	for _, d := range genDomains(100000) {
		set[d] = struct{}{}
	}
	bl := New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bl.FromDomainsMap(set)
	}
}

func BenchmarkIsBlocked(b *testing.B) {
	bl := New()
	set := make(map[string]struct{})
	for _, d := range genDomains(100000) {
		set[d] = struct{}{}
	}
	bl.FromDomainsMap(set)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bl.IsBlocked("host-42.example-42.com")
		bl.IsBlocked("nope-nothing.invalid-name-xyz.com")
	}
}

func BenchmarkSetAllowed(b *testing.B) {
	bl := New()
	set := make(map[string]struct{})
	for _, d := range genDomains(100000) {
		set[d] = struct{}{}
	}
	bl.FromDomainsMap(set)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bl.SetAllowed([]string{"allow-me.example.com"})
	}
}

func BenchmarkFetchSource(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&sb, "||bench-%d.example.com^\n", i)
		fmt.Fprintf(&sb, "0.0.0.0 hosts-%d.example.net\n", i)
	}
	body := sb.String()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	defer srv.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := FetchSource(b.Context(), srv.URL); err != nil {
			b.Fatal(err)
		}
	}
}

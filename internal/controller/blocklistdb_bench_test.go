package controller

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

func genBenchDomains(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("bench-%d.example-%d.com", i, i%500))
	}
	return out
}

func BenchmarkReplaceAll(b *testing.B) {
	store, err := NewBlocklistStore(filepath.Join(b.TempDir(), "blocklist.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer store.db.Close()
	domains := genBenchDomains(20000)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.ReplaceAll(ctx, domains); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReplaceSourceDomains(b *testing.B) {
	store, err := NewBlocklistStore(filepath.Join(b.TempDir(), "blocklist.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer store.db.Close()
	domains := genBenchDomains(20000)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.ReplaceSourceDomains(ctx, "https://example.invalid/list.txt", domains); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadSourceDomains(b *testing.B) {
	store, err := NewBlocklistStore(filepath.Join(b.TempDir(), "blocklist.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer store.db.Close()
	ctx := context.Background()
	if err := store.ReplaceSourceDomains(ctx, "https://example.invalid/list.txt", genBenchDomains(20000)); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.LoadSourceDomains(ctx, "https://example.invalid/list.txt"); err != nil {
			b.Fatal(err)
		}
	}
}

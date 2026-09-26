package control

import (
	"fmt"
	"strings"
	"testing"
)

func TestLogRingKeepsTail(t *testing.T) {
	r := NewLogRing(3)
	if _, err := fmt.Fprintf(r, "a\nb\nc\nd\n"); err != nil {
		t.Fatal(err)
	}
	got := r.Snapshot(0)
	want := []string{"b", "c", "d"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tail = %q, want %q", got, want)
	}
	if got := r.Snapshot(2); strings.Join(got, ",") != "c,d" {
		t.Fatalf("snapshot(2) = %q, want [c d]", got)
	}
	if got := r.Snapshot(99); len(got) != 3 {
		t.Fatalf("oversized snapshot = %d lines, want 3", len(got))
	}
}

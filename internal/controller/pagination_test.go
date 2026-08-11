package controller

import (
	"net/http"
	"testing"
	"time"
)

func TestBoundedPageValues(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/?limit=-1&offset=-5", nil)
	if got := boundedLimit(r, 100, 500); got != 100 {
		t.Fatalf("negative limit = %d, want fallback 100", got)
	}
	if got := boundedOffset(r); got != 0 {
		t.Fatalf("negative offset = %d, want 0", got)
	}

	r, _ = http.NewRequest(http.MethodGet, "/?limit=999999&offset=999999999", nil)
	if got := boundedLimit(r, 100, 500); got != 500 {
		t.Fatalf("large limit = %d, want 500", got)
	}
	if got := boundedOffset(r); got != maxPageOffset {
		t.Fatalf("large offset = %d, want %d", got, maxPageOffset)
	}
}

func TestBoundedDuration(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/?since=999999h", nil)
	if got := boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour); got != 24*time.Hour {
		t.Fatalf("out-of-range duration = %s, want fallback", got)
	}
}

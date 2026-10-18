package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
)

// deadlineSpy records deadline calls so the SSE handler's write deadlines
// are observable without waiting out a real server timeout.
type deadlineSpy struct {
	http.ResponseWriter
	writeAt, readAt       time.Time
	writeCalls, readCalls int
}

func (s *deadlineSpy) SetWriteDeadline(t time.Time) error { s.writeCalls++; s.writeAt = t; return nil }
func (s *deadlineSpy) SetReadDeadline(t time.Time) error  { s.readCalls++; s.readAt = t; return nil }
func (s *deadlineSpy) Flush()                             {}

// The watch stream must outlive the API server's absolute ReadTimeout
// (10 minutes): it used to die at exactly 10:00, making the controller
// reconnect on a timer and lose the events that fell in the gap.
func TestWatchClearsReadDeadline(t *testing.T) {
	srv := NewServerWithBlocklist("tok", filter.NewStore(nil), cache.New(0, 0), &Counters{}, "blipd/test", blocklist.New())
	spy := &deadlineSpy{ResponseWriter: httptest.NewRecorder()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the handler's first select returns immediately on a done context
	req := httptest.NewRequest(http.MethodGet, "/api/v1/watch", nil).WithContext(ctx)

	srv.handleWatch(spy, req)

	if spy.readCalls == 0 || !spy.readAt.IsZero() {
		t.Errorf("read deadline = %v (%d calls), want the zero time (cleared)", spy.readAt, spy.readCalls)
	}
	// F-11: the write deadline must never be cleared — each write carries
	// its own deadline instead, so a slow reader cannot stall the stream
	// writer forever.
	if spy.writeCalls != 0 && spy.writeAt.IsZero() {
		t.Errorf("write deadline cleared (%d calls), want per-write deadlines", spy.writeCalls)
	}
}

// Each SSE write arms a bounded deadline so a zero-window reader trips it
// instead of pinning the handler goroutine until the 30-minute stream cap.
func TestWatchSetsPerWriteDeadline(t *testing.T) {
	srv := NewServerWithBlocklist("tok", filter.NewStore(nil), cache.New(0, 0), &Counters{}, "blipd/test", blocklist.New())
	spy := &deadlineSpy{ResponseWriter: httptest.NewRecorder()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/watch", nil).WithContext(ctx)

	done := make(chan struct{})
	go func() { defer close(done); srv.handleWatch(spy, req) }()

	// Wait for the handler to subscribe before notifying (else the
	// non-blocking Notify drops the event and no write ever happens).
	subDeadline := time.Now().Add(2 * time.Second)
	for !srv.HasWatchers() && time.Now().Before(subDeadline) {
		time.Sleep(5 * time.Millisecond)
	}
	before := time.Now()
	srv.Notify(WatchEvent{Type: "test"})
	deadline := time.Now().Add(2 * time.Second)
	for spy.writeCalls == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if spy.writeCalls == 0 {
		t.Fatal("no write deadline set for the SSE event write")
	}
	if spy.writeAt.IsZero() {
		t.Fatal("write deadline is the zero time (cleared), want a bounded per-write deadline")
	}
	if spy.writeAt.Before(before) || spy.writeAt.After(before.Add(sseWriteTimeout+time.Minute)) {
		t.Fatalf("write deadline = %v, want ~%v after the write", spy.writeAt, sseWriteTimeout)
	}
}

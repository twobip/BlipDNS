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

// deadlineSpy records deadline clears so the SSE handler's clearing is
// observable without waiting out a real server timeout.
type deadlineSpy struct {
	http.ResponseWriter
	writeAt, readAt       time.Time
	writeCalls, readCalls int
}

func (s *deadlineSpy) SetWriteDeadline(t time.Time) error { s.writeCalls++; s.writeAt = t; return nil }
func (s *deadlineSpy) SetReadDeadline(t time.Time) error  { s.readCalls++; s.readAt = t; return nil }
func (s *deadlineSpy) Flush()                             {}

// The watch stream must outlive the API server's absolute Read/WriteTimeout
// (10 minutes each): it used to die at exactly 10:00, making the controller
// reconnect on a timer and lose the events that fell in the gap.
func TestWatchClearsDeadlines(t *testing.T) {
	srv := NewServerWithBlocklist("tok", filter.NewStore(nil), cache.New(0, 0), &Counters{}, "blipd/test", blocklist.New())
	spy := &deadlineSpy{ResponseWriter: httptest.NewRecorder()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the handler's first select returns immediately on a done context
	req := httptest.NewRequest(http.MethodGet, "/api/v1/watch", nil).WithContext(ctx)

	srv.handleWatch(spy, req)

	if spy.writeCalls == 0 || !spy.writeAt.IsZero() {
		t.Errorf("write deadline = %v (%d calls), want the zero time (cleared)", spy.writeAt, spy.writeCalls)
	}
	if spy.readCalls == 0 || !spy.readAt.IsZero() {
		t.Errorf("read deadline = %v (%d calls), want the zero time (cleared)", spy.readAt, spy.readCalls)
	}
}

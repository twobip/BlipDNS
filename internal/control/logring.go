package control

import (
	"strings"
	"sync"
)

// defaultLogRingCap bounds retained process-log lines. blipd logs startup,
// config, and upstream-failover events (no per-query logging), so 500 lines
// covers hours of operation in well under 100 KiB.
const defaultLogRingCap = 500

// maxLogLineLen bounds a single retained line: handler errors can echo
// large operator-supplied input, and a handful of unbounded lines could
// otherwise retain hundreds of MB.
const maxLogLineLen = 4 << 10 // 4 KiB

// LogRing is a mutex-guarded in-memory tail of process log lines, oldest
// first. It implements io.Writer so blipd can tee its standard logger into
// it; GET /api/v1/logs serves the tail to the controller.
type LogRing struct {
	mu    sync.Mutex
	lines []string
	cap   int
}

// NewLogRing returns a ring retaining the last cap lines (<=0 = default).
func NewLogRing(cap int) *LogRing {
	if cap <= 0 {
		cap = defaultLogRingCap
	}
	return &LogRing{cap: cap}
}

// Write implements io.Writer, splitting p on newlines and dropping empty
// fragments (the logger terminates every line with \n).
func (r *LogRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ln := range strings.Split(string(p), "\n") {
		if ln == "" {
			continue
		}
		if len(ln) > maxLogLineLen {
			ln = ln[:maxLogLineLen]
		}
		r.lines = append(r.lines, ln)
		if len(r.lines) > r.cap {
			n := len(r.lines) - r.cap
			copy(r.lines, r.lines[n:])
			r.lines = r.lines[:r.cap]
		}
	}
	return len(p), nil
}

// Snapshot returns up to the last n retained lines, oldest first
// (n <= 0 = everything retained).
func (r *LogRing) Snapshot(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.lines) {
		n = len(r.lines)
	}
	out := make([]string, n)
	copy(out, r.lines[len(r.lines)-n:])
	return out
}

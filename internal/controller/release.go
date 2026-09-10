package controller

import (
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"

	"github.com/twobip/BlipDNS/internal/control"
)

// releaseCheck polls the repository's VERSION file for the configured release
// channel so instances can be badged "update available" without asking each
// node or the browser to reach GitHub.
type releaseCheck struct {
	mu          sync.Mutex
	versions    map[string]string // channel -> latest release version
	lastOK      time.Time
	lastChannel string
}

func newReleaseCheck() *releaseCheck {
	return &releaseCheck{versions: make(map[string]string)}
}

func branchForChannel(channel string) string {
	if channel == string(control.ChannelDev) {
		return "dev"
	}
	return "master"
}

// version returns the cached latest release version for a channel ("" = unknown yet).
func (r *releaseCheck) version(channel string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.versions[channel]
}

// refresh fetches the VERSION file from the channel's branch on GitHub and
// caches it. Failures are logged and keep the previous value, so a transient
// network issue never flips badges.
func (r *releaseCheck) refresh(channel string) {
	branch := branchForChannel(channel)
	url := "https://raw.githubusercontent.com/twobip/BlipDNS/" + branch + "/VERSION"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("blipc: release check (%s): %v", branch, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("blipc: release check (%s): status %d", branch, resp.StatusCode)
		return
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		log.Printf("blipc: release check (%s): read: %v", branch, err)
		return
	}
	latest := strings.TrimSpace(string(b))
	if !validVersion(latest) {
		log.Printf("blipc: release check (%s): malformed VERSION %q", branch, latest)
		return
	}
	r.mu.Lock()
	r.versions[channel] = latest
	r.lastOK = time.Now()
	r.mu.Unlock()
}

// start begins periodic refresh and runs once immediately for the channel in
// use. A later channel change triggers an immediate refresh of the new branch.
func (r *releaseCheck) start(channel string) {
	r.mu.Lock()
	first := r.lastChannel == ""
	if r.lastChannel == channel {
		r.mu.Unlock()
		return
	}
	r.lastChannel = channel
	r.mu.Unlock()

	r.refresh(channel)
	if first {
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for range t.C {
				r.refresh(r.currentChannel())
			}
		}()
	}
}

func (r *releaseCheck) currentChannel() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastChannel
}

// available reports whether the given running version is behind the channel's
// latest release. An unknown instance version or an unknown latest version
// yields no badge.
func (r *releaseCheck) available(channel, runningVersion string) bool {
	running := extractVersion(runningVersion)
	if running == "" {
		return false
	}
	latest := r.version(channel)
	if latest == "" {
		return false
	}
	return semverLess(running, latest)
}

// extractVersion pulls a "major.minor.patch" version out of a version string
// such as "blipd/0.2.0" or a bare "0.2.0".
func extractVersion(v string) string {
	if i := strings.LastIndex(v, "/"); i >= 0 {
		v = v[i+1:]
	}
	v = strings.TrimSpace(v)
	// CI stamps SemVer build metadata ("+a29f043") onto release builds so the
	// dashboard badge can show the exact commit. Strip the plus-hex form the
	// badge recognises before validating; anything else (e.g. "-rc1") still
	// fails below.
	if i := strings.IndexByte(v, '+'); i >= 0 && isHexSHA(v[i+1:]) {
		v = v[:i]
	}
	if !validVersion(v) {
		return ""
	}
	return v
}

// isHexSHA reports whether s looks like a git short SHA (7+ lowercase hex
// digits) — the only build-metadata form the dashboard badge recognises.
func isHexSHA(s string) bool {
	if len(s) < 7 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validVersion reports whether v is a well-formed "major.minor.patch" string.
func validVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// semverLess reports whether version a is strictly older than b ("1.2.3"
// form, validated by extractVersion before comparing).
func semverLess(a, b string) bool {
	return semver.Compare("v"+a, "v"+b) < 0
}

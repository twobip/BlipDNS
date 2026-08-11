package controller

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

// releaseCheck polls the repository branch head for the configured release
// channel so instances can be badged "update available" without asking each
// node or the browser to reach GitHub.
type releaseCheck struct {
	mu          sync.Mutex
	heads       map[string]string // channel -> head commit SHA (short)
	lastOK      time.Time
	lastChannel string
}

func newReleaseCheck() *releaseCheck {
	return &releaseCheck{heads: make(map[string]string)}
}

func branchForChannel(channel string) string {
	if channel == string(control.ChannelDev) {
		return "dev"
	}
	return "master"
}

func shortSHA(s string) string {
	if s == "" {
		return ""
	}
	if len(s) >= 12 {
		return s[:12]
	}
	return s
}

// head returns the cached branch head for a channel ("" = unknown yet).
func (r *releaseCheck) head(channel string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.heads[channel]
}

// refresh fetches the head commit of the channel's branch from the GitHub API
// and caches it. Failures are logged and keep the previous value, so a
// transient network issue never flips badges.
func (r *releaseCheck) refresh(channel string) {
	branch := branchForChannel(channel)
	url := "https://api.github.com/repos/twobip/BlipDNS/commits/" + branch
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
	var out struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		log.Printf("blipc: release check (%s): decode: %v", branch, err)
		return
	}
	r.mu.Lock()
	r.heads[channel] = shortSHA(out.SHA)
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

// available reports whether the given running version is behind the channel
// head. An unknown instance version or an unknown branch head yields no badge.
func (r *releaseCheck) available(channel, runningVersion string) bool {
	running := extractSHA(runningVersion)
	if running == "" {
		return false
	}
	head := r.head(channel)
	if head == "" {
		return false
	}
	return running != head
}

// extractSHA pulls a commit SHA out of a version string such as
// "blipd/0.1.0+abcdef12" or a bare SHA.
func extractSHA(version string) string {
	if version == "" {
		return ""
	}
	if i := strings.LastIndex(version, "+"); i >= 0 {
		version = version[i+1:]
	}
	version = strings.TrimSpace(version)
	if len(version) < 7 || len(version) > 40 {
		return ""
	}
	for _, c := range version {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return ""
		}
	}
	return shortSHA(strings.ToLower(version))
}

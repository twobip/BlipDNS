package controller

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/twobip/BlipDNS/internal/control"
)

// version is the controller release version, stamped at build time from the
// repo's VERSION file: -ldflags "-X github.com/twobip/BlipDNS/internal/
// controller.version=$(cat VERSION)". It defaults to "0.0.0" for local,
// unstamped builds.
var version = "0.0.0"

// ControllerVersion returns the controller's release version, used by the
// Settings page to badge the controller's update state.
func ControllerVersion() string {
	return "blipc/" + version
}

// SelfUpdater starts the controller's own update. It is deliberately minimal:
// the build runs as the blipc service user via /usr/local/sbin/blipc-update,
// which escalates for a single fixed root install/restart helper.
type SelfUpdater struct {
	mu     sync.Mutex
	status control.UpdateStatus
}

func NewSelfUpdater() *SelfUpdater {
	return &SelfUpdater{}
}

func (u *SelfUpdater) StartUpdate(channel string) error {
	if !control.ValidUpdateChannel(channel) {
		return fmt.Errorf("channel must be stable or dev")
	}
	u.mu.Lock()
	if u.status.Running {
		u.mu.Unlock()
		return fmt.Errorf("update already running")
	}
	u.status = control.UpdateStatus{Running: true, Channel: channel, Message: "cloning and building blipc"}
	u.mu.Unlock()
	go u.run(channel)
	return nil
}

func (u *SelfUpdater) UpdateStatus() control.UpdateStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

func (u *SelfUpdater) run(channel string) {
	cmd := exec.Command("/usr/local/sbin/blipc-update", channel)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		u.finishRun(fmt.Errorf("open updater output: %w", err))
		return
	}
	if err := cmd.Start(); err != nil {
		u.finishRun(fmt.Errorf("start updater: %w", err))
		return
	}
	// Stream phase markers ("phase: cloning", "phase: built", ...) so the UI
	// shows progress instead of a static message.
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "phase: ") {
			u.setMessage(strings.TrimPrefix(line, "phase: ") + "…")
		}
	}
	if err := scanner.Err(); err != nil {
		u.finishRun(fmt.Errorf("read updater output: %w", err))
		return
	}
	u.finishRun(cmd.Wait())
}

func (u *SelfUpdater) setMessage(msg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status.Message = msg
}

func (u *SelfUpdater) finishRun(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status.Running = false
	if err != nil {
		u.status.LastError = err.Error()
		return
	}
	u.status.Message = "controller updated"
}

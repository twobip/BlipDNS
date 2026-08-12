package controller

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/twobip/BlipDNS/internal/control"
)

// buildSHA is stamped at build time with the source commit so the controller
// can report its own build. Use -ldflags "-X github.com/twobip/BlipDNS/
// internal/controller.buildSHA=$(git rev-parse HEAD)".
var buildSHA string

// ControllerVersion returns the controller's own build identity, used by the
// Settings page to badge the controller's update state.
func ControllerVersion() string {
	if buildSHA != "" {
		return "blipc/0.1.0+" + buildSHA
	}
	return "blipc/0.1.0"
}

// SelfUpdater starts the controller's own update. It is deliberately minimal:
// the actual work is delegated to the root-owned /usr/local/sbin/blipc-update
// via sudo, with only the allowlisted channel forwarded.
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
	cmd := exec.Command("sudo", "-n", "/usr/local/sbin/blipc-update", channel)
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

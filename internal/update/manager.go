// Package update runs the narrowly scoped, root-owned blipd updater.
package update

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/twobip/BlipDNS/internal/control"
)

// Manager starts the installed helper. The helper owns all privileged work;
// blipd only asks sudo for this single fixed command.
type Manager struct {
	mu     sync.RWMutex
	status control.UpdateStatus
}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) StartUpdate(channel string) error {
	if !control.ValidUpdateChannel(channel) {
		return fmt.Errorf("channel must be stable or dev")
	}
	m.mu.Lock()
	if m.status.Running {
		m.mu.Unlock()
		return fmt.Errorf("update already running")
	}
	m.status = control.UpdateStatus{Running: true, Channel: channel, Message: "cloning and building blipd"}
	m.mu.Unlock()
	go m.run()
	return nil
}

func (m *Manager) UpdateStatus() control.UpdateStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Manager) run() {
	cmd := exec.Command("sudo", "-n", "/usr/local/sbin/blipd-update", m.UpdateStatus().Channel)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.finish(fmt.Errorf("open updater output: %w", err))
		return
	}
	if err := cmd.Start(); err != nil {
		m.finish(fmt.Errorf("start updater: %w", err))
		return
	}
	// Stream phase markers so the status shows live progress.
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "phase: ") {
			m.setMessage(strings.TrimPrefix(line, "phase: ") + "…")
		}
	}
	m.finish(cmd.Wait())
}

func (m *Manager) setMessage(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.Message = msg
}

func (m *Manager) finish(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.Running = false
	if err != nil {
		m.status.LastError = err.Error()
		m.status.Message = "update failed"
		return
	}
	m.status.LastError = ""
	m.status.Message = "update completed; blipd is restarting"
}

var _ control.UpdateController = (*Manager)(nil)

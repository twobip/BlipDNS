// Package update runs the blipd self-updater: an unprivileged build (clone +
// compile) followed by a minimal root install/restart helper. The build and
// network run as the 'blip' service user; only the final install elevates.
package update

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/twobip/BlipDNS/internal/control"
)

// Manager runs the installed build script as the blip service user; the script
// itself escalates for exactly one fixed root helper (install + restart).
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
	cmd := exec.Command("/usr/local/sbin/blipd-update", m.UpdateStatus().Channel)
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
	if err := scanner.Err(); err != nil {
		m.finish(fmt.Errorf("read updater output: %w", err))
		return
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

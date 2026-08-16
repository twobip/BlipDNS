package ha

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/twobip/BlipDNS/internal/control"
)

func TestValidateRejectsUnsafeAuthPass(t *testing.T) {
	cfg := control.HAConfig{
		Enabled:           true,
		Mode:              "unicast",
		NodeRole:          "primary",
		Interface:         "eth0",
		SourceIP:          "192.0.2.10",
		PeerIP:            "192.0.2.11",
		VirtualIP:         "192.0.2.1/24",
		VirtualRouterID:   51,
		Priority:          101,
		AdvertIntervalSec: 1,
		AuthPass:          "safe\npass",
	}
	if err := validate(cfg); err == nil || err.Error() != "auth_pass must be 1-8 letters or numbers" {
		t.Fatalf("validate() error = %v, want unsafe auth_pass error", err)
	}
}

func TestManagerPersistsAndRestoresConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "keepalived.conf")
	cfg := control.HAConfig{Enabled: false}

	m := NewManager(configPath)
	if err := m.SetHAConfig(cfg); err != nil {
		t.Fatalf("SetHAConfig() error = %v", err)
	}
	statePath := configPath + ".state"
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file was not written: %v", err)
	}

	restored := NewManager(configPath)
	restored.mu.RLock()
	got := restored.cfg
	restored.mu.RUnlock()
	if got != cfg {
		t.Fatalf("restored config = %+v, want %+v", got, cfg)
	}
}

func TestRenderDoesNotContainRawUnsafeAuth(t *testing.T) {
	cfg := control.HAConfig{
		Enabled:           true,
		Mode:              "multicast",
		NodeRole:          "primary",
		Interface:         "eth0",
		SourceIP:          "192.0.2.10",
		VirtualIP:         "192.0.2.1/24",
		VirtualRouterID:   51,
		Priority:          101,
		AdvertIntervalSec: 1,
		AuthPass:          "safe1234",
	}
	if got := render(cfg); got == "" || !strings.Contains(got, "auth_pass safe1234") {
		t.Fatalf("render() did not include safe auth password: %q", got)
	}
}

func TestRenderSpecifiesScriptUser(t *testing.T) {
	// enable_script_security makes keepalived run scripts as a non-root user;
	// without an explicit `user` directive keepalived falls back to the
	// keepalived_script user, which does not exist on BlipDNS hosts, so it
	// drops the check script and the track_script reference fails validation.
	cfg := control.HAConfig{
		Enabled:           true,
		Mode:              "unicast",
		NodeRole:          "primary",
		Interface:         "eth0",
		SourceIP:          "192.0.2.10",
		PeerIP:            "192.0.2.11",
		VirtualIP:         "192.0.2.1/24",
		VirtualRouterID:   51,
		Priority:          101,
		AdvertIntervalSec: 1,
	}
	if got := render(cfg); !strings.Contains(got, "user blip") {
		t.Fatalf("render() missing script user directive; keepalived would drop chk_blipd:\n%s", got)
	}
}

// fakeUpdateCtrl implements control.UpdateStatusReporter for testing.
type fakeUpdateCtrl struct {
	running bool
	mu      sync.Mutex
}

func (f *fakeUpdateCtrl) UpdateStatus() control.UpdateStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return control.UpdateStatus{Running: f.running}
}

func (f *fakeUpdateCtrl) setRunning(v bool) {
	f.mu.Lock()
	f.running = v
	f.mu.Unlock()
}

func TestHAStatusReportsUpdating(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "keepalived.conf")
	mgr := NewManager(configPath)

	// Without an update controller wired, Updating should be false.
	st := mgr.HAStatus()
	if st.Updating {
		t.Fatal("expected Updating=false with no update controller")
	}

	// Wire a fake update controller that is not updating.
	fc := &fakeUpdateCtrl{}
	mgr.SetUpdateController(fc)
	st = mgr.HAStatus()
	if st.Updating {
		t.Fatal("expected Updating=false when update not running")
	}

	// Simulate an in-flight update.
	fc.setRunning(true)
	st = mgr.HAStatus()
	if !st.Updating {
		t.Fatal("expected Updating=true when update is running")
	}

	// Simulate the update completing.
	fc.setRunning(false)
	st = mgr.HAStatus()
	if st.Updating {
		t.Fatal("expected Updating=false after update completed")
	}
}

package ha

import (
	"os"
	"path/filepath"
	"strings"
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

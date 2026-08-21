package controller

// Regression tests for the HA-config erase bug: saveConfig used to overwrite
// the on-disk high_availability block with the (empty) in-memory state when
// blipc never successfully loaded it, silently disarming update-time VRRP
// priority degradation.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/twobip/BlipDNS/internal/control"
	"gopkg.in/yaml.v3"
)

// writeConfig writes content to a temp YAML and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "blipc.yaml")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// diskHACluster reads back just the high_availability block from a YAML file.
func diskHACluster(t *testing.T, path string) control.HACluster {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var shim struct {
		HACluster control.HACluster `yaml:"high_availability"`
	}
	if err := yaml.Unmarshal(b, &shim); err != nil {
		t.Fatal(err)
	}
	return shim.HACluster
}

// TestSaveConfigPreservesUnloadableHAConfig is the regression test for the
// silent HA erase: the on-disk cluster config fails startup validation, the
// operator later saves any unrelated setting, and saveConfig must NOT replace
// the on-disk block with the empty in-memory state.
func TestSaveConfigPreservesUnloadableHAConfig(t *testing.T) {
	cfgPath := writeConfig(t, invalidHAYAML())
	f := NewFleet(cfgPath)

	// Simulate the failed startup load.
	cluster := validCluster()
	cluster.Primary.Priority = 50 // now <= secondary: invalid
	if err := f.SetHAClusterDefault(cluster); err == nil {
		t.Fatal("expected startup validation to fail")
	}
	if f.HALoadError() == "" {
		t.Fatal("load error should be recorded for the UI")
	}

	// An unrelated settings save must not erase the on-disk HA config.
	if err := f.saveConfig(); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	got := diskHACluster(t, cfgPath)
	// The invalid on-disk values are preserved verbatim (priority 50), not
	// replaced by the empty in-memory state — the operator fixes them via the
	// UI, and the warning banner tells them why updates aren't protected.
	if !got.Enabled || got.Primary.Priority != 50 || got.PrimaryInstance != "blip1" {
		t.Fatalf("on-disk HA config was erased/changed: %+v", got)
	}
}

// TestSaveConfigWritesOperatorSetHAConfig verifies the normal path still
// persists what the operator saved via the UI.
func TestSaveConfigWritesOperatorSetHAConfig(t *testing.T) {
	cfgPath := writeConfig(t, "instances: []\n")
	f := NewFleet(cfgPath)
	cluster := validCluster()
	if err := f.SetHAClusterDefault(cluster); err != nil {
		t.Fatalf("SetHAClusterDefault: %v", err)
	}
	if err := f.saveConfig(); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	got := diskHACluster(t, cfgPath)
	if !got.Enabled || got.Primary.Priority != 101 || got.Secondary.Priority != 100 {
		t.Fatalf("operator-set HA config not persisted: %+v", got)
	}
}

// TestSaveConfigPreservesHAWhenNeverLoaded covers a config written by hand (or
// by a newer binary) that blipc never attempted to load because the feature
// gate at startup didn't fire.
func TestSaveConfigPreservesHAWhenNeverLoaded(t *testing.T) {
	cfgPath := writeConfig(t, validHAYAML())
	f := NewFleet(cfgPath) // SetHAClusterDefault never called
	if f.HALoadError() != "" {
		t.Fatal("no load error expected when load was never attempted")
	}
	if err := f.saveConfig(); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	got := diskHACluster(t, cfgPath)
	if !got.Enabled || got.PrimaryInstance != "blip1" {
		t.Fatalf("on-disk HA config was erased: %+v", got)
	}
}

// TestHALoadErrorClearedAfterSave verifies the UI banner clears once the
// operator fixes and saves a valid cluster.
func TestHALoadErrorClearedAfterSave(t *testing.T) {
	cfgPath := writeConfig(t, invalidHAYAML())
	f := NewFleet(cfgPath)
	cluster := validCluster()
	cluster.Primary.Priority = 1 // invalid: <= secondary
	if err := f.SetHAClusterDefault(cluster); err == nil {
		t.Fatal("expected validation failure")
	}

	// Operator fixes the form and saves through the UI path.
	good := validCluster()
	if err := f.setHAClusterPersisted(good); err != nil {
		t.Fatalf("setHAClusterPersisted: %v", err)
	}
	if f.HALoadError() != "" {
		t.Fatalf("load error should clear after a valid save, got %q", f.HALoadError())
	}
	got := diskHACluster(t, cfgPath)
	if got.Primary.Priority != 101 {
		t.Fatalf("fixed priority not persisted: %+v", got)
	}
}

func validCluster() control.HACluster {
	return control.HACluster{
		Enabled:           true,
		PrimaryInstance:   "blip1",
		SecondaryInstance: "blip2",
		Primary: control.HAConfig{
			Enabled: true, Mode: "unicast", NodeRole: "primary", Interface: "eth0",
			SourceIP: "192.0.2.10", PeerIP: "192.0.2.11", VirtualIP: "192.0.2.100/24",
			VirtualRouterID: 51, Priority: 101, AdvertIntervalSec: 1,
		},
		Secondary: control.HAConfig{
			Enabled: true, Mode: "unicast", NodeRole: "secondary", Interface: "eth0",
			SourceIP: "192.0.2.11", PeerIP: "192.0.2.10", VirtualIP: "192.0.2.100/24",
			VirtualRouterID: 51, Priority: 100, AdvertIntervalSec: 1,
		},
	}
}

func invalidHAYAML() string {
	return `instances: []
high_availability:
    enabled: true
    primary_instance: blip1
    secondary_instance: blip2
    primary:
        enabled: true
        mode: unicast
        node_role: primary
        interface: eth0
        source_ip: 192.0.2.10
        peer_ip: 192.0.2.11
        virtual_ip: 192.0.2.100/24
        virtual_router_id: 51
        priority: 50
        advert_interval_sec: 1
    secondary:
        enabled: true
        mode: unicast
        node_role: secondary
        interface: eth0
        source_ip: 192.0.2.11
        peer_ip: 192.0.2.10
        virtual_ip: 192.0.2.100/24
        virtual_router_id: 51
        priority: 100
        advert_interval_sec: 1
`
}

func validHAYAML() string {
	return `instances:
    - id: blip1
      url: http://127.0.0.1:8443
      token: t
high_availability:
    enabled: true
    primary_instance: blip1
    secondary_instance: blip2
    primary:
        enabled: true
        mode: unicast
        node_role: primary
        interface: eth0
        source_ip: 192.0.2.10
        peer_ip: 192.0.2.11
        virtual_ip: 192.0.2.100/24
        virtual_router_id: 51
        priority: 101
        advert_interval_sec: 1
    secondary:
        enabled: true
        mode: unicast
        node_role: secondary
        interface: eth0
        source_ip: 192.0.2.11
        peer_ip: 192.0.2.10
        virtual_ip: 192.0.2.100/24
        virtual_router_id: 51
        priority: 100
        advert_interval_sec: 1
`
}

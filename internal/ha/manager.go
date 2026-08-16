// Package ha manages a narrowly scoped, LAN-focused keepalived configuration.
package ha

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/twobip/BlipDNS/internal/control"
)

const (
	// Keepalived reads the config via a one-time symlink:
	//   ln -s /var/lib/blipd/keepalived.conf /etc/keepalived/keepalived.conf
	// This keeps the API writing only inside blipd's own state dir, which the
	// service user can always write regardless of ProtectSystem settings.
	defaultConfigPath = "/var/lib/blipd/keepalived.conf"
	defaultStatePath  = "/var/lib/blipd/ha.json"
)

var (
	interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,32}$`)
	rolePattern      = regexp.MustCompile(`^(primary|secondary)$`)
	authPassPattern  = regexp.MustCompile(`^[A-Za-z0-9]{1,8}$`)
)

// Manager implements control.HAController for the local host.
type Manager struct {
	mu        sync.RWMutex
	opMu      sync.Mutex
	cfg       control.HAConfig
	path      string
	statePath string
	lastError string
	// updateController is checked by HAStatus() to report whether the local
	// node is mid-self-update; nil-safe (no update controller wired).
	updateController control.UpdateStatusReporter
}

// NewManager creates a manager using the default persistent state path only
// when the caller supplies one through NewManagerWithState. It is retained for
// API compatibility and is useful for API-only/test callers.
func NewManager(path string) *Manager {
	return NewManagerWithState(path, "")
}

// NewManagerWithState creates a manager and restores its node-local HA
// configuration from statePath. The state file is separate from the adoption
// state file; if statePath is empty, a default under /var/lib/blipd is used.
func NewManagerWithState(path, adoptionStatePath string) *Manager {
	if path == "" {
		path = defaultConfigPath
	}
	statePath := defaultStatePath
	if adoptionStatePath != "" {
		statePath = filepath.Join(filepath.Dir(adoptionStatePath), "ha.json")
	} else if path != defaultConfigPath {
		// A non-default config path is commonly used by tests or an explicitly
		// sandboxed deployment; keep its state beside that config.
		statePath = path + ".state"
	}
	m := &Manager{path: path, statePath: statePath}
	m.loadState()
	return m
}

func (m *Manager) SetHAConfig(cfg control.HAConfig) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if err := validate(cfg); err != nil {
		return err
	}
	if err := m.persistState(cfg); err != nil {
		return fmt.Errorf("save high availability configuration: %w", err)
	}
	m.mu.Lock()
	m.cfg = cfg
	m.lastError = ""
	m.mu.Unlock()
	return nil
}

func (m *Manager) HAStatus() control.HAStatus {
	m.mu.RLock()
	cfg, path, lastErr := m.cfg, m.path, m.lastError
	m.mu.RUnlock()
	_, statErr := os.Stat(path)
	installed := commandAvailable("keepalived")
	active := installed && commandSucceeds("systemctl", "is-active", "--quiet", "keepalived")
	vipOwned := false
	if ip, _, err := net.ParseCIDR(cfg.VirtualIP); err == nil {
		vipOwned = hostOwnsIP(ip)
	}
	state := "DISABLED"
	if active {
		state = "BACKUP"
		if vipOwned {
			state = "MASTER"
		}
	} else if cfg.Enabled {
		state = "FAULT"
	}
	msg := ""
	if cfg.Enabled && !installed {
		msg = "keepalived is not installed"
	} else if cfg.Enabled && statErr != nil {
		msg = "keepalived configuration has not been applied"
	}
	return control.HAStatus{
		Installed:  installed,
		Configured: statErr == nil,
		Active:     active,
		VIPOwned:   vipOwned,
		State:      state,
		Message:    msg,
		LastError:  lastErr,
		Updating:   m.isUpdating(),
	}
}

// isUpdating reports whether the local node's update controller has a
// self-update in flight. Returns false if no update controller is wired.
func (m *Manager) isUpdating() bool {
	if m.updateController == nil {
		return false
	}
	return m.updateController.UpdateStatus().Running
}

func (m *Manager) InstallHA() error {
	return fmt.Errorf("keepalived installation is intentionally not performed through the API; install it with the host package manager")
}

// SetUpdateController wires the local update manager so HAStatus() can report
// whether the node is mid-self-update. Safe to call at any time.
func (m *Manager) SetUpdateController(c control.UpdateStatusReporter) {
	m.mu.Lock()
	m.updateController = c
	m.mu.Unlock()
}

// ValidateHA validates fields, the selected local interface/address, and the
// rendered keepalived configuration with keepalived's own parser. It never
// writes the live config or starts a service.
func (m *Manager) ValidateHA() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()
	if err := validate(cfg); err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	if !commandAvailable("keepalived") {
		return fmt.Errorf("keepalived is not installed; install it first")
	}
	return m.validateRendered(cfg)
}

func (m *Manager) ApplyHA() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.RLock()
	cfg, path := m.cfg, m.path
	m.mu.RUnlock()
	if err := validate(cfg); err != nil {
		return err
	}
	if !cfg.Enabled {
		return fmt.Errorf("disabling keepalived is intentionally not performed through the API; stop it with the host service manager")
	}
	if !commandAvailable("keepalived") {
		return fmt.Errorf("keepalived is not installed; install it first")
	}
	if err := m.validateRendered(cfg); err != nil {
		m.recordError(err)
		return err
	}
	text := render(cfg)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".keepalived-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(text); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	// Reload keepalived so it picks up the new config. keepalived handles
	// SIGHUP by re-reading its config and doing a graceful restart of VRRP
	// advertisements. We use systemctl reload when available (so the service
	// manager tracks the operation) and fall back to pkill -HUP.
	if commandSucceeds("systemctl", "reload", "keepalived") {
		m.clearError()
		return nil
	}
	if err := runCommand("pkill", "-HUP", "keepalived"); err != nil {
		m.recordError(err)
		return err
	}
	m.clearError()
	return nil
}

func (m *Manager) DisableHA() error {
	return fmt.Errorf("disabling keepalived is intentionally not performed through the API; stop it with the host service manager")
}

func (m *Manager) disableHA() error {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()
	cfg.Enabled = false
	if err := m.persistState(cfg); err != nil {
		m.recordError(err)
		return fmt.Errorf("save disabled high availability configuration: %w", err)
	}
	if err := os.Remove(m.path); err != nil && !os.IsNotExist(err) {
		m.recordError(err)
		return fmt.Errorf("remove keepalived configuration: %w", err)
	}
	m.mu.Lock()
	m.cfg = cfg
	m.lastError = ""
	m.mu.Unlock()
	return nil
}

func validate(cfg control.HAConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Mode != "unicast" && cfg.Mode != "multicast" {
		return fmt.Errorf("mode must be unicast or multicast")
	}
	if !rolePattern.MatchString(cfg.NodeRole) {
		return fmt.Errorf("node_role must be primary or secondary")
	}
	if !interfacePattern.MatchString(cfg.Interface) {
		return fmt.Errorf("invalid network interface")
	}
	if cfg.AuthPass != "" && !authPassPattern.MatchString(cfg.AuthPass) {
		return fmt.Errorf("auth_pass must be 1-8 letters or numbers")
	}
	if net.ParseIP(cfg.SourceIP) == nil {
		return fmt.Errorf("source_ip must be an IP address")
	}
	if cfg.Mode == "unicast" && net.ParseIP(cfg.PeerIP) == nil {
		return fmt.Errorf("peer_ip must be an IP address in unicast mode")
	}
	vip, network, err := net.ParseCIDR(cfg.VirtualIP)
	if err != nil || vip == nil || network == nil {
		return fmt.Errorf("virtual_ip must be an IP address with CIDR prefix")
	}
	source := net.ParseIP(cfg.SourceIP)
	if source == nil || source.To4() != nil != (vip.To4() != nil) {
		return fmt.Errorf("source_ip and virtual_ip must use the same address family")
	}
	if !network.Contains(source) {
		return fmt.Errorf("source_ip must be on the virtual IP network")
	}
	if cfg.Mode == "unicast" {
		peer := net.ParseIP(cfg.PeerIP)
		if peer == nil || peer.To4() != nil != (vip.To4() != nil) {
			return fmt.Errorf("peer_ip and virtual_ip must use the same address family")
		}
		if !network.Contains(peer) {
			return fmt.Errorf("peer_ip must be on the virtual IP network")
		}
		if peer.Equal(source) {
			return fmt.Errorf("peer_ip must differ from source_ip")
		}
	}
	if err := interfaceHasIP(cfg.Interface, source); err != nil {
		return err
	}
	if cfg.VirtualRouterID < 1 || cfg.VirtualRouterID > 255 {
		return fmt.Errorf("virtual_router_id must be between 1 and 255")
	}
	if cfg.Priority < 1 || cfg.Priority > 254 {
		return fmt.Errorf("priority must be between 1 and 254")
	}
	if cfg.AdvertIntervalSec < 1 || cfg.AdvertIntervalSec > 60 {
		return fmt.Errorf("advert_interval_sec must be between 1 and 60")
	}
	return nil
}

func interfaceHasIP(name string, want net.IP) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("network interface %q was not found", name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("read addresses for interface %q: %w", name, err)
	}
	for _, addr := range addrs {
		var ip net.IP
		switch a := addr.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		if ip != nil && ip.Equal(want) {
			return nil
		}
	}
	return fmt.Errorf("source_ip %s is not assigned to interface %q", want, name)
}

func (m *Manager) validateRendered(cfg control.HAConfig) error {
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".keepalived-validate-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(render(cfg)); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := runCommand("keepalived", "-t", "-f", name); err != nil {
		return fmt.Errorf("keepalived configuration validation failed: %w", err)
	}
	return nil
}

func render(cfg control.HAConfig) string {
	state := "BACKUP"
	if cfg.NodeRole == "primary" {
		state = "MASTER"
	}
	var b strings.Builder
	b.WriteString("global_defs {\n    router_id blipd-ha\n    enable_script_security\n}\n\n")
	b.WriteString("vrrp_script chk_blipd {\n    script \"/usr/bin/systemctl is-active --quiet blipd\"\n    user blip\n    interval 2\n    fall 2\n    rise 2\n    weight -20\n}\n\n")
	fmt.Fprintf(&b, "vrrp_instance BLIPDNS {\n    state %s\n    interface %s\n    virtual_router_id %d\n    priority %d\n    advert_int %d\n", state, cfg.Interface, cfg.VirtualRouterID, cfg.Priority, cfg.AdvertIntervalSec)
	if cfg.Mode == "unicast" {
		fmt.Fprintf(&b, "    unicast_src_ip %s\n    unicast_peer {\n        %s\n    }\n", cfg.SourceIP, cfg.PeerIP)
	}
	if cfg.AuthPass != "" {
		fmt.Fprintf(&b, "    authentication {\n        auth_type PASS\n        auth_pass %s\n    }\n", cfg.AuthPass)
	}
	fmt.Fprintf(&b, "    virtual_ipaddress {\n        %s dev %s\n    }\n    track_script {\n        chk_blipd\n    }\n}\n", cfg.VirtualIP, cfg.Interface)
	return b.String()
}

func (m *Manager) loadState() {
	if m.statePath == "" {
		return
	}
	b, err := os.ReadFile(m.statePath)
	if err != nil {
		return
	}
	var cfg control.HAConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return
	}
	if err := validateStoredConfig(cfg); err != nil {
		return
	}
	m.cfg = cfg
}

func validateStoredConfig(cfg control.HAConfig) error {
	if !cfg.Enabled {
		return nil
	}
	// Stored state can be loaded before the host's interface is available during
	// boot, so validate syntax and ranges here; runtime ValidateHA checks the
	// actual interface/address assignment.
	if cfg.Mode != "unicast" && cfg.Mode != "multicast" {
		return fmt.Errorf("invalid mode")
	}
	if !rolePattern.MatchString(cfg.NodeRole) || !interfacePattern.MatchString(cfg.Interface) {
		return fmt.Errorf("invalid node role or interface")
	}
	if net.ParseIP(cfg.SourceIP) == nil {
		return fmt.Errorf("invalid source address")
	}
	if _, _, err := net.ParseCIDR(cfg.VirtualIP); err != nil {
		return fmt.Errorf("invalid virtual address")
	}
	if cfg.Mode == "unicast" && net.ParseIP(cfg.PeerIP) == nil {
		return fmt.Errorf("invalid peer")
	}
	if cfg.VirtualRouterID < 1 || cfg.VirtualRouterID > 255 || cfg.Priority < 1 || cfg.Priority > 254 || cfg.AdvertIntervalSec < 1 || cfg.AdvertIntervalSec > 60 {
		return fmt.Errorf("invalid VRRP range")
	}
	if cfg.AuthPass != "" && !authPassPattern.MatchString(cfg.AuthPass) {
		return fmt.Errorf("invalid auth pass")
	}
	return nil
}

func (m *Manager) persistState(cfg control.HAConfig) error {
	if m.statePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0750); err != nil {
		return err
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.statePath), ".ha-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, m.statePath)
}

func (m *Manager) recordError(err error) {
	m.mu.Lock()
	m.lastError = err.Error()
	m.mu.Unlock()
}
func (m *Manager) clearError() {
	m.mu.Lock()
	m.lastError = ""
	m.mu.Unlock()
}
func commandAvailable(name string) bool { _, err := exec.LookPath(name); return err == nil }
func commandSucceeds(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s: %s: %w", name, msg, err)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func hostOwnsIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var candidate net.IP
		switch a := addr.(type) {
		case *net.IPNet:
			candidate = a.IP
		case *net.IPAddr:
			candidate = a.IP
		}
		if candidate != nil && candidate.Equal(ip) {
			return true
		}
	}
	return false
}

package control

import (
	"os"
	"path/filepath"
)

// HAConfig is the validated, node-local keepalived configuration sent by the
// controller. It intentionally contains structured fields only; raw
// keepalived.conf text is never accepted from the UI or management API.
type HAConfig struct {
	Enabled           bool   `json:"enabled" yaml:"enabled"`
	Mode              string `json:"mode" yaml:"mode"` // unicast or multicast
	NodeRole          string `json:"node_role" yaml:"node_role"`
	Interface         string `json:"interface" yaml:"interface"`
	SourceIP          string `json:"source_ip" yaml:"source_ip"`
	PeerIP            string `json:"peer_ip,omitempty" yaml:"peer_ip,omitempty"`
	VirtualIP         string `json:"virtual_ip" yaml:"virtual_ip"` // CIDR notation
	VirtualRouterID   int    `json:"virtual_router_id" yaml:"virtual_router_id"`
	Priority          int    `json:"priority" yaml:"priority"`
	AdvertIntervalSec int    `json:"advert_interval_sec" yaml:"advert_interval_sec"`
	AuthPass          string `json:"auth_pass,omitempty" yaml:"auth_pass,omitempty"`
}

// HACluster is the controller's two-node LAN VRRP configuration. The two node
// configs must describe the same VIP/router ID while using different roles and
// priorities.
type HACluster struct {
	Enabled           bool     `json:"enabled" yaml:"enabled"`
	PrimaryInstance   string   `json:"primary_instance" yaml:"primary_instance"`
	SecondaryInstance string   `json:"secondary_instance" yaml:"secondary_instance"`
	Primary           HAConfig `json:"primary" yaml:"primary"`
	Secondary         HAConfig `json:"secondary" yaml:"secondary"`
}

// HAStatus reports the local keepalived state and configuration health.
type HAStatus struct {
	Installed  bool   `json:"installed"`
	Configured bool   `json:"configured"`
	Active     bool   `json:"active"`
	VIPOwned   bool   `json:"vip_owned"`
	State      string `json:"state"`
	Message    string `json:"message,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	Updating   bool   `json:"updating,omitempty"` // true while blipd is mid-self-update
}

// HAController is implemented by the local blipd host. Operations are
// deliberately narrow so the controller cannot execute arbitrary shell code.
type HAController interface {
	SetHAConfig(HAConfig) error
	HAStatus() HAStatus
	ValidateHA() error
	ApplyHA() error
	DisableHA() error
}

// DefaultAdoptCodeFile is where the one-time adoption secret is exposed
// box-locally (M9). The file holds an adopt bundle (id + management URL +
// code, one opaque line) when the embedder set a bundle URL, else the bare
// code as before. Mode 0600, so journal exposure is not needed to claim an
// instance. Operators read it with sudo; the code is single-use and
// invalidated immediately on successful adoption.
const DefaultAdoptCodeFile = "/var/lib/blipd/adopt-code"

// CurrentClaimCode returns the active one-time claim code ("", when adopted
// or not yet generated). Caller must treat the value as a secret: print once
// to stdout for the box-local operator, never log it.
func (s *Server) CurrentClaimCode() string {
	s.adoptMu.Lock()
	defer s.adoptMu.Unlock()
	return s.claimCode
}

// IsAdopted reports whether the instance has completed the claim-code
// handshake (no active code expected).
func (s *Server) IsAdopted() bool {
	s.adoptMu.Lock()
	defer s.adoptMu.Unlock()
	return s.adopted
}

// InstanceID returns the adoption identity (hostname fallback applied in
// ConfigureAdoption).
func (s *Server) InstanceID() string {
	s.adoptMu.Lock()
	defer s.adoptMu.Unlock()
	return s.instanceID
}

// SetAdoptBundleURL records the management URL baked into adopt bundles.
// Called once by the embedder (which owns listen-address knowledge) before
// serving; empty leaves the legacy bare-code file.
func (s *Server) SetAdoptBundleURL(mgmtURL string) {
	s.adoptMu.Lock()
	defer s.adoptMu.Unlock()
	s.bundleURL = mgmtURL
}

// AdoptBundleString builds the one-opaque-line bundle for the active code
// ("", when adopted or unset). Same secret-handling as CurrentClaimCode.
func (s *Server) AdoptBundleString() string {
	s.adoptMu.Lock()
	defer s.adoptMu.Unlock()
	if s.adopted || s.claimCode == "" || s.bundleURL == "" {
		return ""
	}
	b, err := MakeAdoptBundle(s.instanceID, s.bundleURL, s.claimCode)
	if err != nil {
		return ""
	}
	return b
}

// WriteAdoptCodeFile persists the active claim code to path with mode 0600
// for box-local retrieval (M9: file + one-time stdout instead of
// journal-only). When already adopted (no active code) it removes any stale
// file and returns nil. Parent dirs are created 0700.
func (s *Server) WriteAdoptCodeFile(path string) error {
	if path == "" {
		path = s.AdoptCodePath()
	}
	s.adoptMu.Lock()
	code := s.claimCode
	adopted := s.adopted
	instanceID := s.instanceID
	bundleURL := s.bundleURL
	s.adoptMu.Unlock()
	if adopted || code == "" {
		_ = os.Remove(path)
		return nil
	}
	secret := code
	if bundleURL != "" {
		if b, err := MakeAdoptBundle(instanceID, bundleURL, code); err == nil {
			secret = b
		}
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, []byte(secret+"\n"), 0600); err != nil {
		return err
	}
	// WriteFile does not chmod existing files; enforce 0600.
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	return nil
}

// AdoptCodePath is the 0600 adopt-code file: next to the adoption state file
// when one is configured, else the default. Parallel instances with separate
// state dirs therefore get separate code files instead of sharing (and
// failing to write) the default.
func (s *Server) AdoptCodePath() string {
	s.adoptMu.Lock()
	defer s.adoptMu.Unlock()
	return s.adoptCodePathLocked()
}

func (s *Server) adoptCodePathLocked() string {
	if s.stateFile != "" {
		if dir := filepath.Dir(s.stateFile); dir != "" && dir != "." {
			return filepath.Join(dir, "adopt-code")
		}
	}
	return DefaultAdoptCodeFile
}

// ClearAdoptCodeFile removes the claim-code file best-effort (called after a
// successful adoption or a reset that replaces the code).
func ClearAdoptCodeFile(path string) {
	if path == "" {
		path = DefaultAdoptCodeFile
	}
	_ = os.Remove(path)
}

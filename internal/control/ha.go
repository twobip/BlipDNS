package control

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
	InstallHA() error
	ValidateHA() error
	ApplyHA() error
	DisableHA() error
}

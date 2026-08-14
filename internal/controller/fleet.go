// Package controller implements the blipc Unifi-style management controller.
// It connects to one or more blipd instances over their management API,
// aggregates stats/health/block events into a single feed, and exposes a
// token-gated HTTP API plus an embedded web dashboard.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/upstream"
	"gopkg.in/yaml.v3"
)

// Event is a fleet-wide event (federated from instances).
type Event struct {
	InstanceID string                  `json:"instance_id"`
	Instance   string                  `json:"instance"` // human label
	Type       string                  `json:"type"`     // stats|block|health|policy|status
	At         time.Time               `json:"at"`
	Health     *control.HealthResponse `json:"health,omitempty"`
	Stats      *control.StatsResponse  `json:"stats,omitempty"`
	Client     string                  `json:"client,omitempty"`
	Domain     string                  `json:"domain,omitempty"`
	Msg        string                  `json:"msg,omitempty"`
	// QType is the queried RR-type mnemonic for pass/block events.
	QType string `json:"q_type,omitempty"`
	// IPs holds A/AAAA rdata for resolved queries (kept for backward compat).
	IPs []string `json:"ips,omitempty"`
	// Answers carries every response record so non-IP answers (TXT, CNAME, etc.)
	// are visible in the live event stream, not just in the persisted query log.
	Answers []Answer `json:"answers,omitempty"`
	// Cached reports whether a "pass" event was served from the response cache.
	Cached bool `json:"cached,omitempty"`
	// Upstream names the resolver that answered a pass event.
	Upstream string `json:"upstream,omitempty"`
	// DurationUs is the query latency in microseconds.
	DurationUs int64 `json:"duration_us,omitempty"`
}

// InstanceConfig is one managed blipd entry (from controller config).
type InstanceConfig struct {
	ID    string `yaml:"id" json:"id"`
	URL   string `yaml:"url" json:"url"` // http://host:8444
	Token string `yaml:"token" json:"token"`
	Label string `yaml:"label" json:"label"`
	Claim string `yaml:"claim" json:"claim"` // one-time claim code (optional bootstrap)
}

// InstanceOverride is a partial per-instance config: only fields that are set
// differ from the fleet default; everything else falls through to it. Stored
// on blipc and pushed (merged with the default) to that instance only.
type InstanceOverride struct {
	Upstream    *string `json:"upstream,omitempty" yaml:"upstream,omitempty"`
	BlockAction *string `json:"block_action,omitempty" yaml:"block_action,omitempty"`
	Log         *bool   `json:"log,omitempty" yaml:"log,omitempty"`
	// DoHHTTPAddr, when set, makes this instance accept plain-HTTP DoH on the
	// given addr ("" = off) instead of inheriting the fleet-wide setting.
	DoHHTTPAddr *string `json:"doh_http_addr,omitempty" yaml:"doh_http_addr,omitempty"`
	// RateLimitQPS, when set, overrides the fleet-wide DNS query rate limit
	// (QPS per client) for this instance. 0 disables rate limiting.
	RateLimitQPS *int `json:"rate_limit_qps,omitempty" yaml:"rate_limit_qps,omitempty"`
	// UpstreamServers, when set, overrides the fleet-wide upstream server pool
	// for this instance. nil = inherit the fleet default.
	UpstreamServers *[]upstream.UpstreamServer `json:"upstream_servers,omitempty" yaml:"upstream_servers,omitempty"`
	// UpstreamRoutes, when set, overrides the fleet-wide upstream routes
	// (conditional forwarding) for this instance. nil = inherit the fleet default.
	UpstreamRoutes *[]upstream.UpstreamRoute `json:"upstream_routes,omitempty" yaml:"upstream_routes,omitempty"`
	// CacheSize, when set, overrides the fleet-wide max cached responses for
	// this instance. nil = inherit the fleet default.
	CacheSize *int `json:"cache_size,omitempty" yaml:"cache_size,omitempty"`
	// CacheWarm, when set, overrides the fleet-wide auto-refresh count for this
	// instance. nil = inherit the fleet-wide default.
	CacheWarm *int `json:"cache_warm,omitempty" yaml:"cache_warm,omitempty"`
	// CacheRegular, when set, overrides the fleet-wide regular-hold duration
	// (seconds) for entries outside the top-N. nil = inherit the fleet default.
	CacheRegular *int `json:"cache_regular,omitempty" yaml:"cache_regular,omitempty"`
	// Records, when set, overrides the fleet-wide local DNS records for this
	// instance. nil = inherit the fleet-wide default.
	Records *[]control.RecordEntry `json:"records,omitempty" yaml:"records,omitempty"`
}

// IsEmpty reports whether the override changes nothing.
func (o *InstanceOverride) IsEmpty() bool {
	return o == nil || (o.Upstream == nil && o.BlockAction == nil && o.Log == nil && o.DoHHTTPAddr == nil && o.RateLimitQPS == nil && o.UpstreamServers == nil && o.UpstreamRoutes == nil && o.CacheSize == nil && o.CacheWarm == nil && o.CacheRegular == nil && o.Records == nil)
}

// Fleet holds all instances, the event bus, and the global blocklist.
type Fleet struct {
	mu               sync.RWMutex
	instances        map[string]*Instance
	bus              *Bus
	http             *http.Client
	now              func() time.Time
	logfn            func(Event)
	queryLog         *QueryLogStore       // persistent query log
	blocklistDB      *BlocklistStore      // persisted copy of the merged blocklist
	blocklist        *blocklist.Blocklist // global DNS blocklist
	blocklistSources []string             // Pi-hole style source URLs (AdBlock Plus / hosts)
	blMu             sync.Mutex           // guards blocklist status + import job
	blRunning        bool
	blGen            int
	blCancel         context.CancelFunc
	blStatus         BlocklistStatus
	blLoading        atomic.Bool                  // true while the startup cache load is in flight
	sourceStats      []SourceStat                 // per-source download stats, refreshed on import
	importLog        []string                     // recent import output lines (capped ring buffer)
	manualDomains    map[string]struct{}          // hand-added domains, kept apart from sources
	manualAllowed    map[string]struct{}          // hand-added whitelist domains
	autoUpdateHours  int                          // hours between automatic refreshes; 0 = manual only
	configPath       string                       // path to controller config YAML (for persisting tokens)
	defaultPolicy    *control.Policy              // fleet-wide default policy (source of truth)
	overrides        map[string]*InstanceOverride // per-instance partial configs (diff vs default)
	dohHTTPAddr      string                       // fleet-wide plain-HTTP DoH address ("", off)
	rateLimitQPS     int                          // fleet-wide DNS per-client QPS limit (0 = disabled)
	cacheSize        int                          // fleet-wide max cached responses (0 = unlimited)
	cacheWarm        int                          // fleet-wide auto-refresh count (0 = off)
	cacheRegular     int                          // fleet-wide regular-hold seconds for non-top entries (0 = use record TTL)
	cacheConfigured  bool                         // true once the operator explicitly set a fleet-wide cache value
	upstreamServers  []upstream.UpstreamServer    // fleet-wide default upstream pool
	upstreamRoutes   []upstream.UpstreamRoute     // fleet-wide default upstream routes
	qlRetentionHours int                          // how long query log entries are kept (0 = 24h default)
	records          []control.RecordEntry        // fleet-wide local DNS records
	haCluster        control.HACluster            // LAN two-node VRRP desired state
	releaseChannel   string                       // stable or dev
	updateMu         sync.Mutex
	updateJob        UpdateJobStatus
	release          *releaseCheck
}

func (f *Fleet) ReleaseChannel() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if control.ValidUpdateChannel(f.releaseChannel) {
		return f.releaseChannel
	}
	return string(control.ChannelStable)
}

func (f *Fleet) SetReleaseChannelDefault(channel string) error {
	if !control.ValidUpdateChannel(channel) {
		return fmt.Errorf("release channel must be stable or dev")
	}
	f.mu.Lock()
	f.releaseChannel = channel
	f.mu.Unlock()
	return nil
}

// StartReleaseCheck begins background polling of the channel's branch head.
func (f *Fleet) StartReleaseCheck() { f.startReleaseCheck() }

// startReleaseCheck begins background polling of the channel's branch head.
func (f *Fleet) startReleaseCheck() {
	f.mu.RLock()
	r, channel := f.release, f.releaseChannel
	f.mu.RUnlock()
	if r != nil {
		r.start(channel)
	}
}

// UpdateAvailable reports whether the instance's running build is behind the
// current branch head of the configured release channel.
func (f *Fleet) UpdateAvailable(version string) bool {
	f.mu.RLock()
	r, channel := f.release, f.releaseChannel
	f.mu.RUnlock()
	if r == nil {
		return false
	}
	return r.available(channel, version)
}

// LatestVersion returns the latest release version for the configured release
// channel ("" when unknown, e.g. before the first refresh completes).
func (f *Fleet) LatestVersion() string {
	f.mu.RLock()
	r, channel := f.release, f.releaseChannel
	f.mu.RUnlock()
	if r == nil {
		return ""
	}
	return r.version(channel)
}

func (f *Fleet) SetReleaseChannel(channel string) error {
	if err := f.SetReleaseChannelDefault(channel); err != nil {
		return err
	}
	return f.saveConfig()
}

// HACluster returns the desired LAN VRRP pair configuration.
func (f *Fleet) HACluster() control.HACluster {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.haCluster
}

// SetHAClusterDefault loads the desired LAN VRRP configuration without
// persisting it. Used while blipc is starting from controller.yaml.
func (f *Fleet) SetHAClusterDefault(cluster control.HACluster) error {
	if err := validateHACluster(cluster); err != nil {
		return err
	}
	f.mu.Lock()
	f.haCluster = cluster
	f.mu.Unlock()
	return nil
}

func validateHACluster(c control.HACluster) error {
	if !c.Enabled {
		return nil
	}
	if c.Primary.AuthPass != c.Secondary.AuthPass {
		return fmt.Errorf("both nodes must use the same VRRP authentication password")
	}
	if c.PrimaryInstance == "" || c.SecondaryInstance == "" || c.PrimaryInstance == c.SecondaryInstance {
		return fmt.Errorf("high availability requires two different instances")
	}
	if c.Primary.VirtualIP == "" || c.Primary.VirtualIP != c.Secondary.VirtualIP {
		return fmt.Errorf("both nodes must use the same virtual IP")
	}
	if c.Primary.VirtualRouterID < 1 || c.Primary.VirtualRouterID > 255 || c.Primary.VirtualRouterID != c.Secondary.VirtualRouterID {
		return fmt.Errorf("both nodes must use the same virtual router ID from 1 to 255")
	}
	if c.Primary.NodeRole != "primary" || c.Secondary.NodeRole != "secondary" {
		return fmt.Errorf("node roles must be primary and secondary")
	}
	if c.Primary.Priority <= c.Secondary.Priority {
		return fmt.Errorf("primary priority must be higher than secondary priority")
	}
	if c.Primary.Mode != c.Secondary.Mode {
		return fmt.Errorf("both nodes must use the same VRRP mode")
	}
	return nil
}

// HAStatuses reads the local keepalived status from every managed node.
func (f *Fleet) HAStatuses(ctx context.Context) map[string]*control.HAStatus {
	f.mu.RLock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, inst := range f.instances {
		insts = append(insts, inst)
	}
	f.mu.RUnlock()
	out := make(map[string]*control.HAStatus, len(insts))
	for _, inst := range insts {
		st, err := inst.ctl().HAStatus(ctx)
		if err != nil {
			out[inst.Config.ID] = &control.HAStatus{State: "UNAVAILABLE", LastError: err.Error()}
			continue
		}
		out[inst.Config.ID] = st
	}
	return out
}

func (f *Fleet) haNode(id string) (*Instance, error) {
	inst := f.get(id)
	if inst == nil {
		return nil, fmt.Errorf("controller: unknown instance %s", id)
	}
	if !inst.hasToken() {
		return nil, fmt.Errorf("controller: instance %s is not adopted", id)
	}
	return inst, nil
}

// SetHACluster sends the structured node-local configs to both members and
// persists the desired cluster only after both writes succeed.
func (f *Fleet) SetHACluster(ctx context.Context, cluster control.HACluster) error {
	if err := validateHACluster(cluster); err != nil {
		return err
	}
	if !cluster.Enabled {
		// Unchecking HA is a real lifecycle operation: stop both services and
		// persist the disabled desired state rather than leaving keepalived
		// running with a stale configuration.
		current := f.HACluster()
		if cluster.PrimaryInstance == "" {
			cluster.PrimaryInstance = current.PrimaryInstance
		}
		if cluster.SecondaryInstance == "" {
			cluster.SecondaryInstance = current.SecondaryInstance
		}
		return f.DisableHA(ctx, cluster)
	}
	primary, err := f.haNode(cluster.PrimaryInstance)
	if err != nil {
		return err
	}
	secondary, err := f.haNode(cluster.SecondaryInstance)
	if err != nil {
		return err
	}
	if err := primary.ctl().SetHAConfig(ctx, cluster.Primary); err != nil {
		return fmt.Errorf("primary: %w", err)
	}
	if err := secondary.ctl().SetHAConfig(ctx, cluster.Secondary); err != nil {
		return fmt.Errorf("secondary: %w", err)
	}
	return f.setHAClusterPersisted(cluster)
}

func (f *Fleet) setHAClusterPersisted(cluster control.HACluster) error {
	if err := validateHACluster(cluster); err != nil {
		return err
	}
	f.mu.Lock()
	f.haCluster = cluster
	f.mu.Unlock()
	if f.configPath != "" {
		return f.saveConfig()
	}
	return nil
}

func (f *Fleet) InstallHA(ctx context.Context, cluster control.HACluster) error {
	if err := validateHACluster(cluster); err != nil {
		return err
	}
	for _, id := range []string{cluster.PrimaryInstance, cluster.SecondaryInstance} {
		inst, err := f.haNode(id)
		if err != nil {
			return err
		}
		if err := inst.ctl().InstallHA(ctx); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
	}
	return nil
}

func (f *Fleet) ValidateHA(ctx context.Context, cluster control.HACluster) error {
	if err := validateHACluster(cluster); err != nil {
		return err
	}
	for _, id := range []string{cluster.PrimaryInstance, cluster.SecondaryInstance} {
		inst, err := f.haNode(id)
		if err != nil {
			return err
		}
		if err := inst.ctl().ValidateHA(ctx); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
	}
	return nil
}

func (f *Fleet) ApplyHA(ctx context.Context, cluster control.HACluster) error {
	if err := f.ValidateHA(ctx, cluster); err != nil {
		return err
	}
	for _, id := range []string{cluster.PrimaryInstance, cluster.SecondaryInstance} {
		inst, err := f.haNode(id)
		if err != nil {
			return err
		}
		if err := inst.ctl().ApplyHA(ctx); err != nil {
			return fmt.Errorf("%s apply failed after earlier node(s) may have applied: %w", id, err)
		}
	}
	return nil
}

func (f *Fleet) DisableHA(ctx context.Context, cluster control.HACluster) error {
	if cluster.PrimaryInstance == "" && cluster.SecondaryInstance == "" {
		cluster.Enabled = false
		return f.setHAClusterPersisted(cluster)
	}
	for _, id := range []string{cluster.PrimaryInstance, cluster.SecondaryInstance} {
		if id == "" {
			continue
		}
		inst, err := f.haNode(id)
		if err != nil {
			return err
		}
		if err := inst.ctl().DisableHA(ctx); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
	}
	cluster.Enabled = false
	return f.setHAClusterPersisted(cluster)
}

// BlocklistStatus is a point-in-time view of the controller's blocklist
// sources, the current import job (if any), and the merged list state.
type BlocklistStatus struct {
	Running         bool         `json:"running"`
	SourceTotal     int          `json:"source_total"`
	SourceDone      int          `json:"source_done"`
	CurrentURL      string       `json:"current_url"`
	Domains         int          `json:"domains"`
	LastUpdate      time.Time    `json:"last_update"`
	Errors          []string     `json:"errors,omitempty"`
	Sources         []string     `json:"sources"`
	SourceStats     []SourceStat `json:"source_stats,omitempty"`
	Log             []string     `json:"log,omitempty"`
	AutoUpdateHours int          `json:"auto_update_hours"`
	NextUpdate      time.Time    `json:"next_update,omitempty"`
}

// SourceStat is the per-source download result: how many domains the source
// contributes (last good count when the latest refresh failed), when it last
// succeeded, and any error from the most recent attempt.
type SourceStat struct {
	URL        string    `json:"url"`
	Domains    int       `json:"domains"`
	LastUpdate time.Time `json:"last_update,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// NewFleet creates an empty fleet with a default event buffer.
func NewFleet(configPath string) *Fleet {
	queryLog, err := NewQueryLogStore("/var/lib/blipc/querylog.db")
	if err != nil {
		log.Printf("blipc: query log unavailable: %v", err)
	}
	blocklistDB, err := NewBlocklistStore("/var/lib/blipc/blocklist.db")
	if err != nil {
		log.Printf("blipc: blocklist database unavailable: %v", err)
	}
	return &Fleet{
		instances:     make(map[string]*Instance),
		bus:           NewBus(500),
		http:          &http.Client{Timeout: 10 * time.Second},
		now:           time.Now,
		queryLog:      queryLog,
		blocklistDB:   blocklistDB,
		blocklist:     blocklist.New(),
		configPath:    configPath,
		overrides:     make(map[string]*InstanceOverride),
		manualDomains: make(map[string]struct{}),
		manualAllowed: make(map[string]struct{}),
		release:       newReleaseCheck(),
	}
}

func (f *Fleet) OnEvent(fn func(Event)) { f.logfn = fn }

// Add registers an instance and starts its poll/watch loops.
func (f *Fleet) Add(ctx context.Context, cfg InstanceConfig) error {
	if cfg.ID == "" {
		return fmt.Errorf("controller: instance requires id")
	}
	if cfg.URL == "" {
		return fmt.Errorf("controller: instance %s requires url", cfg.ID)
	}
	if cfg.Label == "" {
		cfg.Label = cfg.ID
	}
	inst := &Instance{Config: cfg, client: control.NewClient(cfg.URL, cfg.Token), fleet: f, last: f.now()}
	f.mu.Lock()
	f.instances[cfg.ID] = inst
	f.mu.Unlock()
	// Use a background context for the long-lived poll/watch loops: the caller's
	// ctx (e.g. an HTTP request) is cancelled when the request returns, which
	// would kill the goroutines after the first poll.
	inst.start(context.Background())
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist instance: %v", err)
		}
	}
	if cfg.Claim != "" {
		// Adopt is a network call; run it on a background context so it isn't
		// cut short when the caller's request context is cancelled.
		if err := f.Adopt(context.Background(), cfg.ID, cfg.Claim); err != nil {
			f.bus.Publish(Event{InstanceID: cfg.ID, Instance: cfg.Label, Type: "status", At: f.now(), Msg: "adopt failed: " + err.Error()})
		}
	}
	return nil
}

// Remove stops and forgets an instance.
func (f *Fleet) Remove(id string) {
	f.mu.Lock()
	inst := f.instances[id]
	delete(f.instances, id)
	f.mu.Unlock()
	if inst != nil {
		inst.stop()
	}
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist after remove: %v", err)
		}
	}
}

// List returns a snapshot of instances with their current status.
func (f *Fleet) List() []*InstanceStatus {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]*InstanceStatus, 0, len(f.instances))
	for _, inst := range f.instances {
		out = append(out, inst.status())
	}
	return out
}

// DefaultPolicy returns the fleet-wide default policy (may be nil).
func (f *Fleet) DefaultPolicy() *control.Policy {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.defaultPolicy
}

// SetDefault records the fleet-wide default policy without distributing it.
// Used at startup (config load); instances pick it up via the poll reconcile.
func (f *Fleet) SetDefault(p *control.Policy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p != nil {
		p.ID = "default"
	}
	f.defaultPolicy = p
}

// SetDefaultPolicy records the fleet-wide default policy, persists it to the
// controller config, and pushes every instance's effective config to it. It
// returns the per-instance outcome ("ok" or an error message).
func (f *Fleet) SetDefaultPolicy(ctx context.Context, p *control.Policy) map[string]string {
	f.SetDefault(p)
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist default policy: %v", err)
		}
	}
	return f.pushConfigs(ctx)
}

// effectivePolicy merges the fleet default with the per-instance override:
// every set override field wins, everything else falls through to the default.
// If there is no override and no default it returns nil.
func (f *Fleet) effectivePolicy(instID string) (*control.Policy, string) {
	p := f.defaultPolicy
	o := f.overrides[instID]
	if o == nil {
		if p == nil {
			return nil, ""
		}
		return p, effectiveHash(p)
	}
	// Sparse override: start from the default and apply the set fields.
	merged := clonePolicy(p)
	if merged == nil {
		merged = &control.Policy{ID: "default"}
	}
	if o.Upstream != nil {
		merged.Upstream = *o.Upstream
	}
	if o.BlockAction != nil {
		merged.BlockAction = *o.BlockAction
	}
	if o.Log != nil {
		merged.Log = *o.Log
	}
	return merged, effectiveHash(merged)
}

// wantConfig returns the config a given instance should currently have applied:
// the effective (merged) policy hash plus its upstream. ok is false when there
// is no config at all, in which case synced is undefined.
type wantConfigResult struct {
	hash     string
	upstream string
}

func (f *Fleet) wantConfig(instID string) (wantConfigResult, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	eff, hash := f.effectivePolicy(instID)
	if eff == nil || hash == "" {
		return wantConfigResult{}, false
	}
	return wantConfigResult{hash: hash, upstream: eff.Upstream}, true
}

// effectiveHash returns a stable fingerprint of the config an instance should
// have right now. Instances are synced iff their applied hash matches.
func effectiveHash(p *control.Policy) string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// clonePolicy deep-copies a policy so overriding doesn't mutate the shared default.
func clonePolicy(p *control.Policy) *control.Policy {
	if p == nil {
		return nil
	}
	out := *p
	out.Networks = append([]string(nil), p.Networks...)
	out.Clients = append([]string(nil), p.Clients...)
	out.Block = append([]string(nil), p.Block...)
	out.Allow = append([]string(nil), p.Allow...)
	return &out
}

// SetOverride records a sparse per-instance config without persisting or
// pushing. Used at startup (config load); the poll reconcile distributes it.
func (f *Fleet) SetOverride(id string, o *InstanceOverride) {
	if o == nil || o.IsEmpty() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.overrides[id] = o
}

// SetInstanceOverride records a sparse per-instance config (only fields that
// differ from the fleet default), persists it, and pushes it to the instance.
// If the override is empty the override is removed entirely.
func (f *Fleet) SetInstanceOverride(ctx context.Context, id string, o *InstanceOverride) map[string]string {
	f.mu.Lock()
	if o.IsEmpty() {
		delete(f.overrides, id)
	} else {
		f.overrides[id] = o
	}
	f.mu.Unlock()
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist instance override: %v", err)
		}
	}
	return f.pushInstance(ctx, id)
}

// InstanceOverrideOf returns the sparse override for an instance (may be nil).
func (f *Fleet) InstanceOverrideOf(id string) *InstanceOverride {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.overrides[id]
}

// InstanceOverrides returns a copy of all per-instance overrides.
func (f *Fleet) InstanceOverrides() map[string]*InstanceOverride {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]*InstanceOverride, len(f.overrides))
	for id, o := range f.overrides {
		cp := *o
		out[id] = &cp
	}
	return out
}

// DoHHTTPAddr returns the fleet-wide plain-HTTP DoH listener address ("" = off).
func (f *Fleet) DoHHTTPAddr() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.dohHTTPAddr
}

// SetDoHDefault records the fleet-wide plain-HTTP DoH address without
// distributing it. Used at startup from the controller config.
func (f *Fleet) SetDoHDefault(addr string) {
	f.mu.Lock()
	f.dohHTTPAddr = addr
	f.mu.Unlock()
}

// effectiveDoHHTTPAddr returns the plain-HTTP DoH address an instance should
// run: its own override if set, otherwise the fleet-wide default.
func (f *Fleet) effectiveDoHHTTPAddr(id string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if o := f.overrides[id]; o != nil && o.DoHHTTPAddr != nil {
		return *o.DoHHTTPAddr
	}
	return f.dohHTTPAddr
}

// RateLimitQPS returns the fleet-wide DNS per-client QPS limit (0 = disabled).
func (f *Fleet) RateLimitQPS() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.rateLimitQPS
}

// SetRateLimitQPSDefault records the fleet-wide DNS per-client QPS limit
// without pushing it. Used at startup from the controller config.
func (f *Fleet) SetRateLimitQPSDefault(qps int) {
	if qps < 0 {
		qps = 0
	}
	f.mu.Lock()
	f.rateLimitQPS = qps
	f.mu.Unlock()
}

// effectiveRateLimitQPS returns the per-client QPS limit an instance should
// report: its own override if set, otherwise the fleet-wide default.
func (f *Fleet) effectiveRateLimitQPS(id string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if o := f.overrides[id]; o != nil && o.RateLimitQPS != nil {
		return *o.RateLimitQPS
	}
	return f.rateLimitQPS
}

// Upstream returns the fleet-wide default upstream pool and routes.
func (f *Fleet) Upstream() ([]upstream.UpstreamServer, []upstream.UpstreamRoute) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.upstreamServers, f.upstreamRoutes
}

// SetUpstreamDefault records the fleet-wide default upstream pool and routes
// without distributing it. Used at startup from the controller config.
func (f *Fleet) SetUpstreamDefault(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute) {
	f.mu.Lock()
	f.upstreamServers = servers
	f.upstreamRoutes = routes
	f.mu.Unlock()
}

// SetUpstream sets the fleet-wide default upstream pool and routes, persists it,
// and pushes the effective value (default or per-instance override) to every
// adopted instance.
func (f *Fleet) SetUpstream(ctx context.Context, servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute) map[string]string {
	prev, _ := f.Upstream()
	f.SetUpstreamDefault(servers, routes)
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist upstream setting: %v", err)
		}
	}
	f.warnRemovedPolicyUpstreams(prev, servers)
	return f.pushUpstream(ctx)
}

// serverRefs normalizes a server pool into "type:address" references (UDP
// specs gain ":53", DoH specs keep their path) so policy upstream overrides
// can be compared against them.
func serverRefs(servers []upstream.UpstreamServer) map[string]bool {
	refs := make(map[string]bool, len(servers))
	for _, sv := range servers {
		specs, err := upstream.ParseSpec(sv.Address)
		if err != nil {
			continue
		}
		for _, s := range specs {
			refs[s.Type+":"+s.Address] = true
		}
	}
	return refs
}

// removedServerRefs returns the normalized references present in prev but not
// in cur (i.e. the servers that just disappeared from the pool), or nil when
// nothing was removed.
func removedServerRefs(prev, cur []upstream.UpstreamServer) map[string]bool {
	prevRefs := serverRefs(prev)
	if len(prevRefs) == 0 {
		return nil
	}
	curRefs := serverRefs(cur)
	out := make(map[string]bool)
	for ref := range prevRefs {
		if !curRefs[ref] {
			out[ref] = true
		}
	}
	return out
}

// warnRemovedPolicyUpstreams logs a warning for each policy (fleet default or
// per-instance override) whose upstream override points at a server that was
// just removed from the pool. Deleting a server does not stop queries routed
// by a policy override, so this tells the operator what still references it.
func (f *Fleet) warnRemovedPolicyUpstreams(prev, cur []upstream.UpstreamServer) {
	removed := removedServerRefs(prev, cur)
	if len(removed) == 0 {
		return
	}
	for _, w := range f.orphanPolicyUpstreams(func(ref string) bool { return removed[ref] }) {
		log.Printf("blipc: warning: %s", w)
	}
}

// WarnOrphanPolicyUpstreams logs a warning for every policy whose upstream
// override is not one of the configured server-pool addresses. Called at
// startup so a hand-edited config — a policy still pointing at a deleted
// server — is caught without waiting for the next server deletion.
func (f *Fleet) WarnOrphanPolicyUpstreams(servers []upstream.UpstreamServer) {
	pool := serverRefs(servers)
	for _, w := range f.orphanPolicyUpstreams(func(ref string) bool { return !pool[ref] }) {
		log.Printf("blipc: warning: %s", w)
	}
}

// orphanPolicyUpstreams returns one warning per policy whose upstream spec
// references an endpoint for which match reports true (refs are normalized
// "type:address" strings). Policies without an upstream override are skipped.
func (f *Fleet) orphanPolicyUpstreams(match func(ref string) bool) []string {
	if match == nil {
		return nil
	}
	f.mu.RLock()
	def := f.defaultPolicy
	overs := make(map[string]*InstanceOverride, len(f.overrides))
	for k, v := range f.overrides {
		overs[k] = v
	}
	f.mu.RUnlock()
	var out []string
	check := func(owner, spec string) {
		if spec == "" {
			return
		}
		specs, err := upstream.ParseSpec(spec)
		if err != nil {
			return
		}
		for _, s := range specs {
			if match(s.Type + ":" + s.Address) {
				out = append(out, fmt.Sprintf(
					"policy %s: upstream %q routes to %q which is not in the configured server pool (deleted or never configured); clear the policy's upstream override to stop queries going there",
					owner, spec, s.Address))
				return
			}
		}
	}
	if def != nil {
		check("default ("+def.ID+")", def.Upstream)
	}
	for id, o := range overs {
		if o.Upstream != nil {
			check("instance "+id, *o.Upstream)
		}
	}
	return out
}

// effectiveUpstream returns the upstream pool + routes an instance should have:
// its own override if set, otherwise the fleet-wide default.
func (f *Fleet) effectiveUpstream(instID string) ([]upstream.UpstreamServer, []upstream.UpstreamRoute) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	servers := f.upstreamServers
	routes := f.upstreamRoutes
	if o := f.overrides[instID]; o != nil {
		if o.UpstreamServers != nil {
			servers = *o.UpstreamServers
		}
		if o.UpstreamRoutes != nil {
			routes = *o.UpstreamRoutes
		}
	}
	return servers, routes
}

// upstreamHash returns a stable fingerprint of the upstream pool + routes so
// the controller can detect drift after a restart (mirroring the DoH and
// rate-limit reconcilers).
func upstreamHash(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute) string {
	if servers == nil {
		servers = []upstream.UpstreamServer{}
	}
	if routes == nil {
		routes = []upstream.UpstreamRoute{}
	}
	b, err := json.Marshal(struct {
		Servers []upstream.UpstreamServer `json:"servers"`
		Routes  []upstream.UpstreamRoute  `json:"routes"`
	}{servers, routes})
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// pushUpstream distributes the effective upstream pool + routes to every
// adopted instance. Instances whose effective upstream is empty (neither the
// fleet default nor a per-instance override sets any servers or routes) are
// skipped: the fleet is not managing upstream for them, so they keep whatever
// they currently have (config-file or previously pushed).
func (f *Fleet) pushUpstream(ctx context.Context) map[string]string {
	f.mu.RLock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, i := range f.instances {
		insts = append(insts, i)
	}
	f.mu.RUnlock()
	results := make(map[string]string, len(insts))
	for _, i := range insts {
		if !i.hasToken() {
			results[i.Config.ID] = "not adopted"
			continue
		}
		wantServers, wantRoutes := f.effectiveUpstream(i.Config.ID)
		if len(wantServers) == 0 && len(wantRoutes) == 0 {
			results[i.Config.ID] = "no upstream configured"
			continue
		}
		if err := i.ctl().SetUpstream(ctx, wantServers, wantRoutes); err != nil {
			results[i.Config.ID] = err.Error()
			continue
		}
		results[i.Config.ID] = "ok"
	}
	return results
}

// maybePushUpstream converges an instance's upstream pool + routes to its fleet
// default (or per-instance override) when the instance reports a divergent set —
// e.g. after a restart it reverted to its own config-file pool. Skips instances
// whose effective upstream is empty (the fleet is not managing upstream for
// them).
func (f *Fleet) maybePushUpstream(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	wantServers, wantRoutes := f.effectiveUpstream(i.Config.ID)
	if len(wantServers) == 0 && len(wantRoutes) == 0 {
		return
	}
	wantHash := upstreamHash(wantServers, wantRoutes)
	repHash := ""
	if reported != nil {
		repHash = upstreamHash(reported.UpstreamServers, reported.UpstreamRoutes)
	}
	if wantHash == repHash || !i.hasToken() {
		return
	}
	if err := i.ctl().SetUpstream(ctx, wantServers, wantRoutes); err != nil {
		log.Printf("blipc: reconcile upstream for %s: %v", i.Config.ID, err)
	}
}

// on top of the existing one, preserving fields the caller did not send. This
// keeps saving the upstream editor from wiping a previously saved DoH override
// and vice-versa.
func mergeOverride(existing, partial *InstanceOverride) *InstanceOverride {
	if partial == nil {
		return existing
	}
	if existing == nil {
		return partial
	}
	merged := *existing
	if partial.Upstream != nil {
		merged.Upstream = partial.Upstream
	}
	if partial.BlockAction != nil {
		merged.BlockAction = partial.BlockAction
	}
	if partial.Log != nil {
		merged.Log = partial.Log
	}
	if partial.DoHHTTPAddr != nil {
		merged.DoHHTTPAddr = partial.DoHHTTPAddr
	}
	if partial.RateLimitQPS != nil {
		merged.RateLimitQPS = partial.RateLimitQPS
	}
	if partial.UpstreamServers != nil {
		merged.UpstreamServers = partial.UpstreamServers
	}
	if partial.UpstreamRoutes != nil {
		merged.UpstreamRoutes = partial.UpstreamRoutes
	}
	if partial.CacheSize != nil {
		merged.CacheSize = partial.CacheSize
	}
	if partial.CacheWarm != nil {
		merged.CacheWarm = partial.CacheWarm
	}
	if partial.CacheRegular != nil {
		merged.CacheRegular = partial.CacheRegular
	}
	if partial.Records != nil {
		merged.Records = partial.Records
	}
	return &merged
}

// SetDoHHTTPAddr records the fleet-wide plain-HTTP DoH address, persists it and
// pushes it to every instance. Returns the per-instance outcome.
func (f *Fleet) SetDoHHTTPAddr(ctx context.Context, addr string) map[string]string {
	f.SetDoHDefault(addr)
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist doh setting: %v", err)
		}
	}
	return f.pushDoH(ctx)
}

// SetRateLimitQPS sets the fleet-wide DNS per-client QPS limit, persists it,
// and pushes the effective value (default or per-instance override) to every
// adopted instance.
func (f *Fleet) SetRateLimitQPS(ctx context.Context, qps int) map[string]string {
	f.SetRateLimitQPSDefault(qps)
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist rate limit setting: %v", err)
		}
	}
	return f.pushRateLimit(ctx)
}

// pushRateLimit distributes the effective DNS rate limit to every instance.
func (f *Fleet) pushRateLimit(ctx context.Context) map[string]string {
	f.mu.RLock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, i := range f.instances {
		insts = append(insts, i)
	}
	f.mu.RUnlock()
	results := make(map[string]string, len(insts))
	for _, i := range insts {
		if !i.hasToken() {
			results[i.Config.ID] = "not adopted"
			continue
		}
		qps := f.effectiveRateLimitQPS(i.Config.ID)
		if err := i.ctl().SetRateLimit(ctx, qps, 0); err != nil {
			results[i.Config.ID] = err.Error()
			continue
		}
		results[i.Config.ID] = "ok"
	}
	return results
}

// pushDoH distributes the effective plain-HTTP DoH address to every instance.
func (f *Fleet) pushDoH(ctx context.Context) map[string]string {
	f.mu.RLock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, i := range f.instances {
		insts = append(insts, i)
	}
	f.mu.RUnlock()
	results := make(map[string]string, len(insts))
	for _, i := range insts {
		if !i.hasToken() {
			results[i.Config.ID] = "not adopted"
			continue
		}
		want := f.effectiveDoHHTTPAddr(i.Config.ID)
		if err := i.ctl().SetDoHHTTPAddr(ctx, want); err != nil {
			results[i.Config.ID] = err.Error()
			continue
		}
		qps := f.effectiveRateLimitQPS(i.Config.ID)
		if err := i.ctl().SetRateLimit(ctx, qps, 0); err != nil {
			results[i.Config.ID] = err.Error()
			continue
		}
		results[i.Config.ID] = "ok"
	}
	return results
}

// maybePushDoH converges an instance's plain-HTTP DoH listener to its fleet
// default (or per-instance override) when the instance reports a divergent
// value — e.g. after a restart it reverted to its own YAML.
func (f *Fleet) maybePushDoH(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	want := f.effectiveDoHHTTPAddr(i.Config.ID)
	rep := ""
	if reported != nil {
		rep = reported.DohHTTPAddr
	}
	if rep == want || !i.hasToken() {
		return
	}
	if err := i.ctl().SetDoHHTTPAddr(ctx, want); err != nil {
		log.Printf("blipc: reconcile doh for %s: %v", i.Config.ID, err)
	}
}

// maybePushRateLimit converges an instance's DNS rate limit to its fleet default
// (or per-instance override) when the instance reports a divergent value — e.g
// after a restart it reverted to its own YAML.
func (f *Fleet) maybePushRateLimit(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	want := f.effectiveRateLimitQPS(i.Config.ID)
	rep := -1
	if reported != nil {
		rep = reported.RateLimitQPS
	}
	if rep == want || !i.hasToken() {
		return
	}
	if err := i.ctl().SetRateLimit(ctx, want, 0); err != nil {
		log.Printf("blipc: reconcile rate limit for %s: %v", i.Config.ID, err)
	}
}

// QueryLogRetentionHours returns how long query log entries are kept on blipc.
// 0 in the field means "unset": the 24h default applies.
func (f *Fleet) QueryLogRetentionHours() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.qlRetentionHours <= 0 {
		return 24
	}
	return f.qlRetentionHours
}

// queryLogRetentionChoices are the accepted query log retention options, in
// hours (1 day, 1 week, 1 month, 6 months, 1 year).
var queryLogRetentionChoices = []int{24, 168, 720, 4320, 8760}

// ValidQueryLogRetentionHours reports whether h is an accepted retention value.
func ValidQueryLogRetentionHours(h int) bool {
	for _, c := range queryLogRetentionChoices {
		if c == h {
			return true
		}
	}
	return false
}

// SetQueryLogRetentionDefault records the query log retention without
// persisting it. Used at startup from the controller config; 0 resets to the
// 24h default.
func (f *Fleet) SetQueryLogRetentionDefault(hours int) {
	f.mu.Lock()
	f.qlRetentionHours = hours
	f.mu.Unlock()
	if f.queryLog != nil {
		f.queryLog.SetRetention(time.Duration(f.QueryLogRetentionHours()) * time.Hour)
	}
}

// SetQueryLogRetention persists the query log retention and applies it to the
// store immediately. The log lives on blipc, so nothing is pushed to the
// instances.
func (f *Fleet) SetQueryLogRetention(ctx context.Context, hours int) map[string]string {
	f.SetQueryLogRetentionDefault(hours)
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist query log retention: %v", err)
		}
	}
	return map[string]string{}
}

// CacheConfig returns the fleet-wide cache size limit, auto-refresh count, and
// regular-hold seconds (0 = unlimited / off / use record TTL).
func (f *Fleet) CacheConfig() (size, warm, regular int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.cacheSize, f.cacheWarm, f.cacheRegular
}

// SetCacheDefault records the fleet-wide cache size + auto-refresh count +
// regular-hold without distributing it. Used at startup from the controller
// config.
func (f *Fleet) SetCacheDefault(size, warm, regular int) {
	if size < 0 {
		size = 0
	}
	if warm < 0 {
		warm = 0
	}
	if regular < 0 {
		regular = 0
	}
	f.mu.Lock()
	f.cacheSize = size
	f.cacheWarm = warm
	f.cacheRegular = regular
	f.cacheConfigured = true
	f.mu.Unlock()
}

// effectiveCacheConfig returns the cache size + auto-refresh count + regular-hold
// an instance should run: its own override if set, otherwise the fleet default.
func (f *Fleet) effectiveCacheConfig(id string) (size, warm, regular int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	size, warm, regular = f.cacheSize, f.cacheWarm, f.cacheRegular
	if o := f.overrides[id]; o != nil {
		if o.CacheSize != nil {
			size = *o.CacheSize
		}
		if o.CacheWarm != nil {
			warm = *o.CacheWarm
		}
		if o.CacheRegular != nil {
			regular = *o.CacheRegular
		}
	}
	return size, warm, regular
}

// cacheConfiguredFor reports whether the operator has explicitly set any
// cache configuration — either fleet-wide or for the given instance's
// per-instance override. When false, reconcile skips pushing cache config so
// blipd keeps its own YAML defaults.
func (f *Fleet) cacheConfiguredFor(id string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.cacheConfigured {
		return true
	}
	if o := f.overrides[id]; o != nil {
		return o.CacheSize != nil || o.CacheWarm != nil || o.CacheRegular != nil
	}
	return false
}

// SetCache records the fleet-wide cache size + auto-refresh count + regular-hold,
// persists it, and pushes the effective value (default or per-instance override)
// to every adopted instance. Returns the per-instance outcome.
func (f *Fleet) SetCache(ctx context.Context, size, warm, regular int) map[string]string {
	f.SetCacheDefault(size, warm, regular)
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist cache setting: %v", err)
		}
	}
	return f.pushCache(ctx)
}

// pushCache distributes the effective cache config (size + auto-refresh +
// regular-hold) to every adopted instance.
func (f *Fleet) pushCache(ctx context.Context) map[string]string {
	f.mu.RLock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, i := range f.instances {
		insts = append(insts, i)
	}
	f.mu.RUnlock()
	results := make(map[string]string, len(insts))
	for _, i := range insts {
		if !i.hasToken() {
			results[i.Config.ID] = "not adopted"
			continue
		}
		size, warm, regular := f.effectiveCacheConfig(i.Config.ID)
		if err := i.ctl().SetCacheConfig(ctx, size, warm, regular); err != nil {
			results[i.Config.ID] = err.Error()
			continue
		}
		results[i.Config.ID] = "ok"
	}
	return results
}

// maybePushCache converges an instance's cache size + auto-refresh count +
// regular-hold to its fleet default (or per-instance override) when the instance
// reports a divergent value — e.g. after a restart it reverted to its own YAML.
// If the operator hasn't configured any cache setting (neither fleet-wide nor
// per-instance), the instance's own blipd YAML defaults are left in place.
func (f *Fleet) maybePushCache(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	if !f.cacheConfiguredFor(i.Config.ID) {
		return
	}
	wantSize, wantWarm, wantRegular := f.effectiveCacheConfig(i.Config.ID)
	repSize, repWarm, repRegular := -1, -1, -1
	if reported != nil {
		repSize, repWarm, repRegular = reported.CacheSize, reported.CacheWarm, reported.CacheRegular
	}
	if (repSize == wantSize && repWarm == wantWarm && repRegular == wantRegular) || !i.hasToken() {
		return
	}
	if err := i.ctl().SetCacheConfig(ctx, wantSize, wantWarm, wantRegular); err != nil {
		log.Printf("blipc: reconcile cache for %s: %v", i.Config.ID, err)
	}
}

// PurgeCache drops every cached response on every adopted instance and returns
// the per-instance outcome, including how many entries were purged.
func (f *Fleet) PurgeCache(ctx context.Context) (map[string]string, int) {
	f.mu.RLock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, i := range f.instances {
		insts = append(insts, i)
	}
	f.mu.RUnlock()
	results := make(map[string]string, len(insts))
	total := 0
	for _, i := range insts {
		if !i.hasToken() {
			results[i.Config.ID] = "not adopted"
			continue
		}
		n, err := i.ctl().PurgeCache(ctx)
		if err != nil {
			results[i.Config.ID] = err.Error()
			continue
		}
		total += n
		results[i.Config.ID] = "ok"
	}
	return results, total
}

// Records returns the fleet-wide local DNS records.
func (f *Fleet) Records() []control.RecordEntry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]control.RecordEntry(nil), f.records...)
}

// SetRecords records the fleet-wide local DNS records, persists them, and pushes
// the effective value (default or per-instance override) to every adopted
// instance. Returns the per-instance outcome.
func (f *Fleet) SetRecords(ctx context.Context, recs []control.RecordEntry) map[string]string {
	f.mu.Lock()
	f.records = append([]control.RecordEntry(nil), recs...)
	f.mu.Unlock()
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist records: %v", err)
		}
	}
	return f.pushRecords(ctx)
}

// recordsHash returns a stable checksum of the fleet-wide records for
// reconciliation (an empty list hashes to 0).
func (f *Fleet) recordsHash() uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return control.RecordsHash(f.records)
}

// effectiveRecords returns the records an instance should have: its own override
// if set, otherwise the fleet-wide default.
func (f *Fleet) effectiveRecords(instID string) []control.RecordEntry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if o := f.overrides[instID]; o != nil && o.Records != nil {
		return append([]control.RecordEntry(nil), *o.Records...)
	}
	return append([]control.RecordEntry(nil), f.records...)
}

// pushRecords distributes the effective local DNS records to every adopted
// instance.
func (f *Fleet) pushRecords(ctx context.Context) map[string]string {
	f.mu.RLock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, i := range f.instances {
		insts = append(insts, i)
	}
	f.mu.RUnlock()
	results := make(map[string]string, len(insts))
	for _, i := range insts {
		if !i.hasToken() {
			results[i.Config.ID] = "not adopted"
			continue
		}
		want := f.effectiveRecords(i.Config.ID)
		if err := i.ctl().SetRecords(ctx, want); err != nil {
			results[i.Config.ID] = err.Error()
			continue
		}
		results[i.Config.ID] = "ok"
	}
	return results
}

// maybePushRecords converges an instance's local DNS records to its fleet
// default (or per-instance override) when the instance reports a divergent hash
// — e.g. after a restart it reverted to its own (empty) config.
func (f *Fleet) maybePushRecords(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	wantHash := f.recordsHash()
	repHash := uint64(0)
	if reported != nil {
		repHash = reported.RecordsHash
	}
	if repHash == wantHash || !i.hasToken() {
		return
	}
	want := f.effectiveRecords(i.Config.ID)
	if err := i.ctl().SetRecords(ctx, want); err != nil {
		log.Printf("blipc: reconcile records for %s: %v", i.Config.ID, err)
	}
}

// pushInstance sends one instance's effective config to it.
func (f *Fleet) pushConfigs(ctx context.Context) map[string]string {
	f.mu.RLock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, i := range f.instances {
		insts = append(insts, i)
	}
	f.mu.RUnlock()
	results := make(map[string]string, len(insts))
	for _, i := range insts {
		f.mu.RLock()
		eff, _ := f.effectivePolicy(i.Config.ID)
		f.mu.RUnlock()
		if eff == nil {
			results[i.Config.ID] = "no config"
			continue
		}
		if err := i.ctl().SetPolicy(ctx, eff); err != nil {
			results[i.Config.ID] = err.Error()
			continue
		}
		i.markConfigAppliedWith(f.appliedHashFor(i.Config.ID), eff.Upstream)
		results[i.Config.ID] = "ok"
	}
	return results
}

// pushInstance sends one instance's effective config to it. Used when a
// per-instance override is saved. Returns a single-entry result map. The DoH
// address is always pushed (it can override even with no policy set); the
// policy is pushed only when an effective one exists.
func (f *Fleet) pushInstance(ctx context.Context, id string) map[string]string {
	i := f.get(id)
	if i == nil {
		return map[string]string{id: "unknown instance"}
	}
	f.mu.RLock()
	eff, _ := f.effectivePolicy(id)
	wantDoH := f.effectiveDoHHTTPAddr(id)
	wantSize, wantWarm, wantRegular := f.effectiveCacheConfig(id)
	f.mu.RUnlock()
	res := map[string]string{id: "ok"}
	if !i.hasToken() {
		res[id] = "not adopted"
		return res
	}
	if err := i.ctl().SetDoHHTTPAddr(ctx, wantDoH); err != nil {
		res[id] = "doh: " + err.Error()
	}
	if err := i.ctl().SetCacheConfig(ctx, wantSize, wantWarm, wantRegular); err != nil {
		res[id] = "cache: " + err.Error()
	}
	if eff != nil {
		if err := i.ctl().SetPolicy(ctx, eff); err != nil {
			res[id] = err.Error()
			return res
		}
		i.markConfigAppliedWith(f.appliedHashFor(id), eff.Upstream)
	}
	// Push the effective upstream pool + routes when the fleet is managing
	// upstream for this instance (non-empty server pool or routes).
	wantServers, wantRoutes := f.effectiveUpstream(id)
	if len(wantServers) > 0 || len(wantRoutes) > 0 {
		if err := i.ctl().SetUpstream(ctx, wantServers, wantRoutes); err != nil {
			res[id] = "upstream: " + err.Error()
		}
	}
	return res
}

// appliedHashFor returns the hash an instance should have applied right now.
func (f *Fleet) appliedHashFor(instID string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, h := f.effectivePolicy(instID)
	return h
}

// maybePushConfig converges an instance to its effective config. It pushes
// when the instance has not yet applied the current config hash (newly
// added/adopted, or the fleet config changed) or when its reported default
// upstream diverges from the effective config (it restarted and reverted to
// its own config). Called from the instance poll loop.
func (f *Fleet) maybePushConfig(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	f.mu.RLock()
	eff, hash := f.effectivePolicy(i.Config.ID)
	f.mu.RUnlock()
	if eff == nil || hash == "" || !i.hasToken() {
		return
	}
	rep := ""
	if reported != nil {
		rep = reported.Upstream
	}
	if i.configApplied(hash) && rep == eff.Upstream {
		return
	}
	if err := i.ctl().SetPolicy(ctx, eff); err == nil {
		i.markConfigAppliedWith(hash, eff.Upstream)
	}
}

func (f *Fleet) get(id string) *Instance {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.instances[id]
}

// RestartInstance asks one adopted node to restart its blipd service.
func (f *Fleet) RestartInstance(id string) error {
	inst := f.get(id)
	if inst == nil {
		return fmt.Errorf("instance %q not found", id)
	}
	if err := inst.ctl().Restart(context.Background()); err != nil {
		return fmt.Errorf("restart %s: %w", id, err)
	}
	return nil
}

// SetPolicy pushes a policy to a managed instance via the controller client.
func (f *Fleet) SetPolicy(ctx context.Context, id string, p *control.Policy) error {
	inst := f.get(id)
	if inst == nil {
		return fmt.Errorf("controller: unknown instance %s", id)
	}
	if err := inst.client.SetPolicy(ctx, p); err != nil {
		return err
	}
	f.bus.Publish(Event{InstanceID: id, Instance: inst.Config.Label, Type: "policy", At: f.now(), Msg: "set " + p.ID, Domain: p.ID})
	return nil
}

// Adopt presents a claim code to an instance and, on success, stores the
// returned admin token on the instance so subsequent calls use it.
func (f *Fleet) Adopt(ctx context.Context, id, code string) error {
	inst := f.get(id)
	if inst == nil {
		return fmt.Errorf("controller: unknown instance %s", id)
	}
	if code == "" && inst.claimCode != "" {
		code = inst.claimCode // controller was pre-seeded with the code
	}
	resp, err := inst.client.Adopt(ctx, code)
	if err != nil {
		return err
	}
	if !resp.Adopted {
		return fmt.Errorf("controller: adoption rejected: %s", resp.Message)
	}
	if resp.Token != "" {
		inst.mu.Lock()
		inst.Config.Token = resp.Token
		inst.claimCode = ""
		inst.client = control.NewClient(inst.Config.URL, resp.Token)
		inst.mu.Unlock()
		if f.configPath != "" {
			if err := f.saveConfig(); err != nil {
				log.Printf("blipc: warning: failed to persist adopted token: %v", err)
			}
		}
		// Newly adopted instance: hand it the fleet config and blocklist.
		f.maybePushConfig(context.Background(), inst, nil)
		f.maybePushBlocklist(context.Background(), inst, nil)
	}
	f.bus.Publish(Event{InstanceID: id, Instance: inst.Config.Label, Type: "status", At: f.now(), Msg: "adopted"})
	return nil
}

// SetClaimCode records a claim code for an instance.
func (f *Fleet) SetClaimCode(id, code string) {
	inst := f.get(id)
	if inst == nil {
		return
	}
	inst.mu.Lock()
	inst.claimCode = code
	inst.mu.Unlock()
}

// GetAdoptStatus returns the instance's adoption state from blipd (unauthenticated).
func (f *Fleet) GetAdoptStatus(id string) (*control.AdoptStatus, error) {
	inst := f.get(id)
	if inst == nil {
		return nil, fmt.Errorf("controller: unknown instance %s", id)
	}
	return inst.client.AdoptStatus(context.Background())
}

// ResetAdoption resets a managed instance's adoption state.
func (f *Fleet) ResetAdoption(ctx context.Context, id string) error {
	inst := f.get(id)
	if inst == nil {
		return fmt.Errorf("controller: unknown instance %s", id)
	}
	if err := inst.client.ResetAdoption(ctx); err != nil {
		return err
	}
	f.bus.Publish(Event{InstanceID: id, Instance: inst.Config.Label, Type: "status", At: f.now(), Msg: "adoption reset"})
	return nil
}

// SetLabel updates the label of a managed instance.
func (f *Fleet) SetLabel(ctx context.Context, id, label string) error {
	inst := f.get(id)
	if inst == nil {
		return fmt.Errorf("controller: unknown instance %s", id)
	}
	inst.mu.Lock()
	inst.Config.Label = label
	inst.mu.Unlock()
	f.bus.Publish(Event{InstanceID: id, Instance: label, Type: "status", At: f.now(), Msg: "label updated"})
	return nil
}

// DeletePolicy removes a policy on a managed instance.
func (f *Fleet) DeletePolicy(ctx context.Context, id, policyID string) error {
	inst := f.get(id)
	if inst == nil {
		return fmt.Errorf("controller: unknown instance %s", id)
	}
	return inst.client.DeletePolicy(ctx, policyID)
}

// ListPolicies returns policies from a managed instance.
func (f *Fleet) ListPolicies(ctx context.Context, id string) (*control.ListResponse, error) {
	inst := f.get(id)
	if inst == nil {
		return nil, fmt.Errorf("controller: unknown instance %s", id)
	}
	return inst.client.ListPolicies(ctx)
}

// Health returns aggregated fleet health.
func (f *Fleet) Health() map[string]*control.HealthResponse {
	out := make(map[string]*control.HealthResponse)
	for _, s := range f.List() {
		out[s.ID] = s.Health
	}
	return out
}

// Bus returns the event bus (for SSE streaming to UIs).
func (f *Fleet) Bus() *Bus { return f.bus }

// Blocklist returns the global blocklist.
func (f *Fleet) Blocklist() *blocklist.Blocklist {
	return f.blocklist
}

// resolveBlockList turns a block event's source marker into a display label
// for the query log. "global" (or an empty marker) is resolved against the
// persisted per-source snapshots so the block is attributed to the actual
// source URL(s); anything else (e.g. "policy:default") is used verbatim.
func (f *Fleet) resolveBlockList(ctx context.Context, src, domain string) string {
	if src == "" || src == "global" {
		if f.blocklistDB != nil {
			if label, err := f.blocklistDB.BlockSourceLabel(ctx, domain); err == nil && label != "" {
				return label
			}
		}
		return "global blocklist"
	}
	return src
}

// BlocklistSources returns the configured source URLs.
func (f *Fleet) BlocklistSources() []string {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	return append([]string(nil), f.blocklistSources...)
}

// BlocklistStatus returns the current source list and import job state.
func (f *Fleet) BlocklistStatus() BlocklistStatus {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	st := f.blStatus
	st.Sources = append([]string(nil), f.blocklistSources...)
	st.SourceStats = append([]SourceStat(nil), f.sourceStats...)
	st.Log = append([]string(nil), f.importLog...)
	st.AutoUpdateHours = f.autoUpdateHours
	if !st.Running && f.blocklist != nil {
		st.Domains = f.blocklist.Count()
	}
	if st.AutoUpdateHours > 0 && !st.LastUpdate.IsZero() {
		st.NextUpdate = st.LastUpdate.Add(time.Duration(st.AutoUpdateHours) * time.Hour)
	}
	return st
}

// SetBlocklistSources replaces the source URLs, persists them to the config,
// and starts a background import job. The HTTP caller returns immediately;
// progress is visible via BlocklistStatus.
func (f *Fleet) SetBlocklistSources(ctx context.Context, urls []string) {
	f.blMu.Lock()
	f.blocklistSources = cleanURLs(urls)
	f.blMu.Unlock()
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist blocklist sources: %v", err)
		}
	}
	f.startBlocklistImport()
}

// ImportBlocklist starts a background import of the current sources. No-op if
// one is already running.
func (f *Fleet) ImportBlocklist() {
	f.startBlocklistImport()
}

// AutoUpdateHours returns the configured refresh interval in hours (0 = off).
func (f *Fleet) AutoUpdateHours() int {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	return f.autoUpdateHours
}

// SetAutoUpdateHours configures the interval (hours) between automatic source
// refreshes and persists it to the controller config. 0 disables auto-updates.
func (f *Fleet) SetAutoUpdateHours(h int) {
	if h < 0 {
		h = 0
	}
	f.blMu.Lock()
	f.autoUpdateHours = h
	f.blMu.Unlock()
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist blocklist auto-update hours: %v", err)
		}
	}
}

// StartAutoUpdater runs a background loop that refreshes the blocklist sources
// on the configured interval. It never cancels an in-flight import and skips
// while one is running, so manual and automatic refreshes can't collide.
func (f *Fleet) StartAutoUpdater() {
	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for range t.C {
			due := false
			f.blMu.Lock()
			if f.autoUpdateHours > 0 && len(f.blocklistSources) > 0 && !f.blRunning {
				last := f.blStatus.LastUpdate
				if last.IsZero() || time.Since(last) >= time.Duration(f.autoUpdateHours)*time.Hour {
					due = true
				}
			}
			f.blMu.Unlock()
			if due {
				f.startBlocklistImport()
			}
		}
	}()
}

// LoadSourceStats restores the persisted per-source download metadata into
// memory so the UI can show counts, errors and last-updates immediately after
// a restart, before the background import finishes.
func (f *Fleet) LoadSourceStats(ctx context.Context) {
	if f.blocklistDB == nil {
		return
	}
	m, err := f.blocklistDB.LoadSourceMeta(ctx)
	if err != nil {
		log.Printf("blipc: warning: load blocklist source stats: %v", err)
		return
	}
	f.blMu.Lock()
	ordered := make([]SourceStat, 0, len(m))
	for _, u := range f.blocklistSources {
		if meta, ok := m[u]; ok {
			ordered = append(ordered, SourceStat{URL: meta.URL, Domains: meta.Domains, LastUpdate: meta.LastUpdate, Error: meta.Error})
			delete(m, u)
		}
	}
	for url, meta := range m {
		ordered = append(ordered, SourceStat{URL: url, Domains: meta.Domains, LastUpdate: meta.LastUpdate, Error: meta.Error})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].URL < ordered[j].URL })
	f.sourceStats = ordered
	f.blMu.Unlock()
}

// LoadManualDomains restores the hand-added domains at startup so they survive
// both restarts and the fresh source import that follows one.
func (f *Fleet) LoadManualDomains(ctx context.Context) {
	if f.blocklistDB == nil {
		return
	}
	m, err := f.blocklistDB.LoadManualDomains(ctx)
	if err != nil {
		log.Printf("blipc: warning: load manual blocklist: %v", err)
		return
	}
	f.blMu.Lock()
	f.manualDomains = m
	f.blMu.Unlock()
}

// AddManualDomain blocks a domain entered by hand in the UI. It takes effect
// immediately on the in-memory list (so the next reconcile pushes it to the
// instances) and is persisted separately, so future source imports keep it.
func (f *Fleet) AddManualDomain(domain string) {
	d := blocklist.NormalizeDomain(domain)
	if d == "" {
		return
	}
	f.blMu.Lock()
	f.manualDomains[d] = struct{}{}
	f.blMu.Unlock()
	f.blocklist.Add(d)
	f.persistManual()
	f.persistBlocklist()
}

// RemoveManualDomain unblocks a hand-entered domain. A domain that was never
// added by hand is left untouched in the merged list.
func (f *Fleet) RemoveManualDomain(domain string) {
	d := blocklist.NormalizeDomain(domain)
	if d == "" {
		return
	}
	f.blMu.Lock()
	if _, ok := f.manualDomains[d]; !ok {
		f.blMu.Unlock()
		return
	}
	delete(f.manualDomains, d)
	f.blMu.Unlock()
	f.blocklist.Remove(d)
	f.persistManual()
	f.persistBlocklist()
}

// ManualDomains returns the sorted list of hand-added domains.
func (f *Fleet) ManualDomains() []string {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	out := make([]string, 0, len(f.manualDomains))
	for d := range f.manualDomains {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// manualDomainSet returns a copy of the manual set, so an import can merge the
// hand-added domains with fresh source data without racing the map.
func (f *Fleet) manualDomainSet() map[string]struct{} {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	out := make(map[string]struct{}, len(f.manualDomains))
	for d := range f.manualDomains {
		out[d] = struct{}{}
	}
	return out
}

// ClearManualDomains removes every hand-added domain.
func (f *Fleet) ClearManualDomains() {
	f.blMu.Lock()
	manual := make([]string, 0, len(f.manualDomains))
	for d := range f.manualDomains {
		manual = append(manual, d)
	}
	f.manualDomains = make(map[string]struct{})
	f.blMu.Unlock()
	for _, d := range manual {
		f.blocklist.Remove(d)
	}
	f.persistManual()
	f.persistBlocklist()
}

// persistManual snapshots the hand-added domains to the local DB in the
// background.
func (f *Fleet) persistManual() {
	if f.blocklistDB == nil {
		return
	}
	go func() {
		if err := f.blocklistDB.ReplaceManualDomains(context.Background(), f.ManualDomains()); err != nil {
			log.Printf("blipc: warning: persist manual blocklist: %v", err)
		}
	}()
}

// LoadAllowedDomains restores the hand-added whitelist at startup so allowed
// domains survive both restarts and the fresh source import that follows one.
func (f *Fleet) LoadAllowedDomains(ctx context.Context) {
	if f.blocklistDB == nil {
		return
	}
	m, err := f.blocklistDB.LoadManualAllowed(ctx)
	if err != nil {
		log.Printf("blipc: warning: load allowed blocklist: %v", err)
		return
	}
	f.blMu.Lock()
	f.manualAllowed = m
	f.blMu.Unlock()
	f.syncAllowed()
}

// AddAllowedDomain whitelists a domain entered by hand in the UI. Allowed
// domains are never blocked, even if a source list contains them. The change
// lands on the instances via the next push / reconcile.
func (f *Fleet) AddAllowedDomain(domain string) {
	d := blocklist.NormalizeDomain(domain)
	if d == "" {
		return
	}
	f.blMu.Lock()
	f.manualAllowed[d] = struct{}{}
	f.blMu.Unlock()
	f.blocklist.AddAllowed(d)
	f.persistAllowed()
}

// RemoveAllowedDomain removes a hand-entered whitelist entry.
func (f *Fleet) RemoveAllowedDomain(domain string) {
	d := blocklist.NormalizeDomain(domain)
	if d == "" {
		return
	}
	f.blMu.Lock()
	if _, ok := f.manualAllowed[d]; !ok {
		f.blMu.Unlock()
		return
	}
	delete(f.manualAllowed, d)
	f.blMu.Unlock()
	f.blocklist.RemoveAllowed(d)
	f.persistAllowed()
}

// AllowedDomains returns the sorted list of hand-added whitelist domains.
func (f *Fleet) AllowedDomains() []string {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	out := make([]string, 0, len(f.manualAllowed))
	for d := range f.manualAllowed {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// syncAllowed mirrors the manual whitelist into the merged in-memory list so
// the checksum (and therefore the hash distributed to instances) covers both
// blocked and allowed domains.
func (f *Fleet) syncAllowed() {
	f.blocklist.SetAllowed(f.AllowedDomains())
}

// ClearAllowedDomains removes every hand-added whitelist entry.
func (f *Fleet) ClearAllowedDomains() {
	f.blMu.Lock()
	f.manualAllowed = make(map[string]struct{})
	f.blMu.Unlock()
	f.blocklist.SetAllowed(nil)
	f.persistAllowed()
}

// persistAllowed snapshots the hand-added whitelist to the local DB in the
// background.
func (f *Fleet) persistAllowed() {
	if f.blocklistDB == nil {
		return
	}
	go func() {
		if err := f.blocklistDB.ReplaceManualAllowed(context.Background(), f.AllowedDomains()); err != nil {
			log.Printf("blipc: warning: persist allowed blocklist: %v", err)
		}
	}()
}

// LoadBlocklistCache asynchronously restores the last persisted merged list
// into RAM. The slow SQLite read + set rebuild run in the background so the
// HTTP listener binds immediately. f.blLoading holds off the per-instance
// reconcile until the load finishes, so a node with its own cached list is
// never cleared by a transient empty in-memory list.
func (f *Fleet) LoadBlocklistCache(ctx context.Context) {
	if f.blocklistDB == nil {
		return
	}
	f.blLoading.Store(true)
	go func() {
		defer f.blLoading.Store(false)
		set, err := f.blocklistDB.LoadSet(ctx)
		if err != nil {
			log.Printf("blipc: blocklist cache: %v", err)
			return
		}
		// Apply only if the in-memory list is still empty: a fresh source import
		// may have already populated it while we were reading SQLite, and the
		// cached snapshot is stale by definition — don't clobber fresh data.
		if len(set) > 0 && f.blocklist.Count() == 0 {
			f.blocklist.FromDomainsMap(set)
			log.Printf("blipc: restored %d blocklist domains from local cache", len(set))
		}
		f.blMu.Lock()
		f.blStatus.Domains = f.blocklist.Count()
		f.blMu.Unlock()
	}()
}

// persistBlocklist snapshots the current in-memory list to the local DB in the
// background, so the next restart can load it without re-fetching sources.
func (f *Fleet) persistBlocklist() {
	if f.blocklistDB == nil {
		return
	}
	go func() {
		if err := f.blocklistDB.ReplaceAll(context.Background(), f.blocklist.List()); err != nil {
			log.Printf("blipc: warning: failed to persist blocklist: %v", err)
		}
	}()
}

// cancelBlocklistImport stops any in-flight import.
func (f *Fleet) cancelBlocklistImport() {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	if f.blCancel != nil {
		f.blCancel()
		f.blCancel = nil
	}
}

func (f *Fleet) startBlocklistImport() {
	f.blMu.Lock()
	f.blGen++
	gen := f.blGen
	if f.blCancel != nil {
		f.blCancel() // cancel any in-flight import; the new one supersedes it
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.blCancel = cancel
	f.blRunning = true
	f.blStatus = BlocklistStatus{Running: true, SourceTotal: len(f.blocklistSources)}
	f.importLog = nil
	f.blMu.Unlock()
	f.logImport("starting import of %d source(s)", len(f.blocklistSources))
	go f.runBlocklistImport(ctx, gen)
}

// logImport appends a timestamped line to the in-memory import log surfaced in
// the web UI. The buffer is capped so a long-running sync can't grow forever.
func (f *Fleet) logImport(format string, args ...interface{}) {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	f.importLog = append(f.importLog, fmt.Sprintf("%s %s", f.now().Format("15:04:05"), fmt.Sprintf(format, args...)))
	if len(f.importLog) > 300 {
		f.importLog = append([]string(nil), f.importLog[len(f.importLog)-300:]...)
	}
}

// ClearImportLog drops all buffered import output.
func (f *Fleet) ClearImportLog() {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	f.importLog = nil
}

// runBlocklistImport fetches and merges all sources, then distributes the
// merged list to every instance. Runs in the background so a huge list (e.g.
// oisd.big) never blocks the web UI. gen lets a superseding import claim the
// status while an older one winds down. A source that fails to download falls
// back to its last good snapshot in the local DB, so a flaky source never
// wipes its domains out of the merged list.
func (f *Fleet) runBlocklistImport(ctx context.Context, gen int) {
	started := f.now()
	applied := false
	current := func() bool {
		f.blMu.Lock()
		defer f.blMu.Unlock()
		return f.blGen == gen
	}
	defer func() {
		if !current() {
			return // a newer import owns the status now
		}
		f.blMu.Lock()
		f.blRunning = false
		f.blCancel = nil
		f.blStatus.Running = false
		f.blStatus.Domains = f.blocklist.Count()
		if applied {
			f.blStatus.LastUpdate = f.now()
		}
		errs := len(f.blStatus.Errors)
		f.blMu.Unlock()
		fin := fmt.Sprintf("finished in %s", time.Since(started).Round(time.Millisecond))
		if errs > 0 {
			fin += fmt.Sprintf(" · %d error(s)", errs)
		}
		f.logImport("%s", fin)
		f.bus.Publish(Event{Type: "status", At: f.now(), Msg: "blocklist update finished"})
	}()

	urls := f.BlocklistSources()
	if len(urls) == 0 {
		f.blMu.Lock()
		f.blStatus.Errors = []string{"no blocklist sources configured"}
		f.sourceStats = nil
		f.blMu.Unlock()
		f.logImport("no blocklist sources configured — list cleared")
		// Clear the list and the stored source snapshots on every instance too.
		if f.blocklistDB != nil {
			_ = f.blocklistDB.PruneSources(context.Background(), nil)
		}
		f.pushBlocklist(context.Background())
		f.persistBlocklist()
		return
	}

	prevMeta := map[string]SourceMeta{}
	if f.blocklistDB != nil {
		if m, err := f.blocklistDB.LoadSourceMeta(ctx); err == nil {
			prevMeta = m
		}
	}

	merged := f.manualDomainSet()
	if len(merged) > 0 {
		f.logImport("seeding %d manually added domain(s)", len(merged))
	}
	stats := make([]SourceStat, 0, len(urls))
	failed := 0
	for i, u := range urls {
		if !current() {
			return
		}
		st := SourceStat{URL: u}
		t0 := f.now()
		f.logImport("[%d/%d] fetching %s", i+1, len(urls), u)
		set, ferr := blocklist.FetchSource(ctx, u)
		if ferr != nil {
			failed++
			st.Error = ferr.Error()
			f.logImport("[%d/%d] failed: %s", i+1, len(urls), ferr)
			// Fall back to the last good snapshot from the local DB.
			if f.blocklistDB != nil {
				if dbSet, derr := f.blocklistDB.LoadSourceDomains(ctx, u); derr == nil && len(dbSet) > 0 {
					for d := range dbSet {
						merged[d] = struct{}{}
					}
					st.Domains = len(dbSet)
				}
			}
			if prev, ok := prevMeta[u]; ok {
				st.LastUpdate = prev.LastUpdate
				if st.Domains == 0 {
					st.Domains = prev.Domains
				}
			}
			if st.Domains > 0 {
				f.logImport("[%d/%d] keeping previous snapshot (%d domains)", i+1, len(urls), st.Domains)
			} else {
				f.logImport("[%d/%d] no fallback snapshot available", i+1, len(urls))
			}
		} else {
			f.logImport("[%d/%d] ok: %d domains in %s", i+1, len(urls), len(set), time.Since(t0).Round(time.Millisecond))
			for d := range set {
				merged[d] = struct{}{}
			}
			st.Domains = len(set)
			st.LastUpdate = f.now()
			if f.blocklistDB != nil {
				domains := make([]string, 0, len(set))
				for d := range set {
					domains = append(domains, d)
				}
				if err := f.blocklistDB.ReplaceSourceDomains(ctx, u, domains); err != nil {
					log.Printf("blipc: warning: persist blocklist source snapshot: %v", err)
				}
			}
		}
		if f.blocklistDB != nil {
			if err := f.blocklistDB.ReplaceSourceMeta(ctx, SourceMeta{
				URL:        u,
				Domains:    st.Domains,
				LastUpdate: st.LastUpdate,
				Error:      st.Error,
			}); err != nil {
				log.Printf("blipc: warning: persist blocklist source meta: %v", err)
			}
		}
		stats = append(stats, st)
		if !current() {
			return
		}
		f.blMu.Lock()
		f.blStatus.CurrentURL = u
		f.blStatus.SourceDone = i + 1
		f.blStatus.SourceTotal = len(urls)
		f.blStatus.Domains = len(merged)
		f.sourceStats = append([]SourceStat(nil), stats...)
		f.blMu.Unlock()
	}

	if !current() {
		return
	}
	f.blMu.Lock()
	if len(merged) == 0 {
		f.blStatus.Errors = append(f.blStatus.Errors, fmt.Sprintf("no domains fetched from any source (%d failed)", failed))
		f.sourceStats = append([]SourceStat(nil), stats...)
		f.blMu.Unlock()
		f.logImport("no domains fetched from any source (%d failed) — keeping previous merged list", failed)
		return // keep the last good merged list untouched
	}
	f.blMu.Unlock()
	f.logImport("merged %d domains from %d source(s)", len(merged), len(urls))

	f.blocklist.FromDomainsMap(merged)
	applied = true
	// Drop snapshots/metadata for sources that are no longer configured.
	if f.blocklistDB != nil {
		if err := f.blocklistDB.PruneSources(ctx, urls); err != nil {
			log.Printf("blipc: warning: prune blocklist source data: %v", err)
		}
	}
	// Persist the merged list so a controller restart loads it into RAM
	// instantly instead of re-fetching every source.
	f.persistBlocklist()
	f.logImport("persisted merged list to local cache")
	// Distribute the merged list to instances (background; a large list takes
	// a while to ship over the management API).
	f.logImport("distributing %d domains to instances", len(merged))
	if results := f.pushBlocklist(context.Background()); results != nil {
		if !current() {
			return
		}
		f.blMu.Lock()
		msgs := make([]string, 0, len(results))
		ok := 0
		for id, r := range results {
			if r != "ok" {
				msgs = append(msgs, id+": "+r)
			} else {
				ok++
			}
		}
		if len(msgs) > 0 {
			f.blStatus.Errors = append(f.blStatus.Errors, "distribution: "+strings.Join(msgs, "; "))
		}
		f.blMu.Unlock()
		f.logImport("distributed to %d/%d instance(s)", ok, len(results))
		if len(msgs) > 0 {
			f.logImport("distribution errors: %s", strings.Join(msgs, "; "))
		}
	}
}

// pushBlocklist sends the controller's merged blocklist (plus whitelist) to
// every instance and records the applied checksum on success. An empty list
// clears the instances.
func (f *Fleet) pushBlocklist(ctx context.Context) map[string]string {
	f.syncAllowed()
	domains := f.blocklist.List()
	allowed := f.blocklist.Allowed()
	hash := f.blocklist.Checksum()

	f.mu.RLock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, i := range f.instances {
		insts = append(insts, i)
	}
	f.mu.RUnlock()

	results := make(map[string]string, len(insts))
	for _, i := range insts {
		if !i.hasToken() {
			results[i.Config.ID] = "not adopted"
			continue
		}
		if err := i.ctl().SetBlocklist(ctx, domains, allowed); err != nil {
			results[i.Config.ID] = err.Error()
			continue
		}
		i.markBlocklistApplied(hash)
		results[i.Config.ID] = "ok"
	}
	return results
}

// maybePushBlocklist converges an instance's blocklist, trusting what the
// instance reports (via stats) over our own bookkeeping: it re-pushes whenever
// the reported checksum differs from the fleet's, which covers restarts (a
// freshly started blipd has an empty list) and clears (an empty fleet list
// must be distributed to un-block on the instance).
func (f *Fleet) maybePushBlocklist(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	if !i.hasToken() {
		return
	}
	// Hold off until the startup cache load finishes; otherwise an empty
	// in-memory list would be pushed at a node that already has its cache.
	if f.blLoading.Load() {
		return
	}
	f.syncAllowed()
	hash := f.blocklist.Checksum()
	rep := uint64(0)
	if reported != nil {
		rep = reported.BlocklistHash
	}
	if rep == hash {
		i.markBlocklistApplied(hash)
		return
	}
	if err := i.ctl().SetBlocklist(ctx, f.blocklist.List(), f.blocklist.Allowed()); err == nil {
		i.markBlocklistApplied(hash)
	}
}

// cleanURLs trims whitespace and drops empty entries, preserving order.
func cleanURLs(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

// LoadConfig adds instances from a YAML config file (instances: section).
func (f *Fleet) LoadConfig(ctx context.Context, path string) error {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc struct {
		Instances []InstanceConfig `yaml:"instances"`
	}
	if err := yamlUnmarshal(b, &doc); err != nil {
		return err
	}
	for _, ic := range doc.Instances {
		if err := f.Add(ctx, ic); err != nil {
			return err
		}
	}
	return nil
}

// saveConfig writes the current fleet config (including updated tokens) to the config file.
func (f *Fleet) saveConfig() error {
	if f.configPath == "" {
		return nil
	}

	b, err := os.ReadFile(f.configPath)
	if err != nil {
		b = []byte{}
	}

	type fullConfig struct {
		Listen                 string                       `yaml:"listen"`
		Username               string                       `yaml:"username"`
		Password               string                       `yaml:"password"`
		PasswordHash           string                       `yaml:"password_hash"`
		DefaultPolicy          *control.Policy              `yaml:"default_policy"`
		InstancePolicies       map[string]*InstanceOverride `yaml:"instance_overrides"`
		DoHHTTPAddr            string                       `yaml:"doh_http_addr"`
		RateLimitQPS           int                          `yaml:"rate_limit_qps"`
		UpstreamServers        []upstream.UpstreamServer    `yaml:"upstream_servers"`
		UpstreamRoutes         []upstream.UpstreamRoute     `yaml:"upstream_routes"`
		CacheSize              int                          `yaml:"cache_size"`
		CacheWarm              int                          `yaml:"cache_warm"`
		CacheRegular           int                          `yaml:"cache_regular"`
		QueryLogRetentionHours int                          `yaml:"query_log_retention_hours"`
		BlocklistSources       []string                     `yaml:"blocklist_sources"`
		BlocklistUpdateHours   int                          `yaml:"blocklist_update_hours"`
		Instances              []InstanceConfig             `yaml:"instances"`
		Records                []control.RecordEntry        `yaml:"records"`
		HACluster              control.HACluster            `yaml:"high_availability"`
		ReleaseChannel         string                       `yaml:"release_channel"`
	}

	var cfg fullConfig
	if len(b) > 0 {
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return err
		}
	}

	f.mu.RLock()
	instances := make([]InstanceConfig, 0, len(f.instances))
	for _, inst := range f.instances {
		inst.mu.RLock()
		instances = append(instances, inst.Config)
		inst.mu.RUnlock()
	}
	def := f.defaultPolicy
	overs := f.overrides
	f.mu.RUnlock()
	blSources := f.BlocklistSources()
	autoHours := f.AutoUpdateHours()
	cfg.Instances = instances
	cfg.DefaultPolicy = def
	cfg.InstancePolicies = overs
	cfg.DoHHTTPAddr = f.DoHHTTPAddr()
	cfg.RateLimitQPS = f.RateLimitQPS()
	upstreamServers, upstreamRoutes := f.Upstream()
	cfg.UpstreamServers = upstreamServers
	cfg.UpstreamRoutes = upstreamRoutes
	cfg.CacheSize, cfg.CacheWarm, cfg.CacheRegular = f.CacheConfig()
	cfg.QueryLogRetentionHours = f.QueryLogRetentionHours()
	cfg.BlocklistSources = blSources
	cfg.BlocklistUpdateHours = autoHours
	cfg.Records = f.Records()
	cfg.HACluster = f.HACluster()
	cfg.ReleaseChannel = f.ReleaseChannel()

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	// 0600: config holds admin tokens for every instance, so no group/world access.
	return os.WriteFile(f.configPath, out, 0600)
}

// ResolveTokenFile expands token paths like "@/path" or an absolute file path
// (no-op if the token isn't a path reference). This is a deliberate feature:
// operators can keep instance management tokens in a separate file (e.g. a
// file populated by a secret manager / init container) instead of inlining them
// in the YAML config.
//
// Security note: the config file is trusted (it is loaded once at startup and
// controls which instances blipc talks to). If an attacker can tamper with the
// config they already have far greater leverage, so expansion is not treated as
// a privilege boundary. As defense-in-depth, path traversal (`..`) is rejected
// before any file is read.
func ResolveTokenFile(cfg InstanceConfig) InstanceConfig {
	if len(cfg.Token) <= 1 || (cfg.Token[0] != '@' && cfg.Token[0] != '/') {
		return cfg
	}
	p := cfg.Token
	if p[0] == '@' {
		p = p[1:]
	}
	// Reject path-traversal attempts (e.g. "@/../../etc/shadow").
	if hasTraversal(p) {
		log.Printf("blipc: refusing token path with traversal: %q", cfg.Token)
		return cfg
	}
	if b, err := os.ReadFile(p); err == nil {
		cfg.Token = string(b)
	}
	return cfg
}

// hasTraversal reports whether p contains a ".." path component.
func hasTraversal(p string) bool {
	for _, el := range strings.Split(p, string(filepath.Separator)) {
		if el == ".." {
			return true
		}
	}
	return false
}

// ConfigDir returns the controller config directory hint.
func ConfigDir() string { return filepath.Dir(os.Args[0]) }

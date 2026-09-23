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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	Answers []control.Answer `json:"answers,omitempty"`
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
	// UpstreamBootstrap, when set, overrides the fleet-wide bootstrap DNS
	// servers (used to resolve DoH upstream hostnames) for this instance.
	// nil = inherit the fleet default.
	UpstreamBootstrap *[]upstream.UpstreamServer `json:"upstream_bootstrap,omitempty" yaml:"upstream_bootstrap,omitempty"`
	// CacheSize, when set, overrides the fleet-wide max cached responses for
	// this instance. nil = inherit the fleet default.
	CacheSize *int `json:"cache_size,omitempty" yaml:"cache_size,omitempty"`
	// Records, when set, overrides the fleet-wide local DNS records for this
	// instance. nil = inherit the fleet-wide default.
	Records *[]control.RecordEntry `json:"records,omitempty" yaml:"records,omitempty"`
}

// IsEmpty reports whether the override changes nothing.
func (o *InstanceOverride) IsEmpty() bool {
	return o == nil || (o.Upstream == nil && o.BlockAction == nil && o.Log == nil && o.DoHHTTPAddr == nil && o.RateLimitQPS == nil && o.UpstreamServers == nil && o.UpstreamRoutes == nil && o.UpstreamBootstrap == nil && o.CacheSize == nil && o.Records == nil)
}

// Fleet holds all instances, the event bus, and the global blocklist.
type Fleet struct {
	mu                sync.RWMutex
	instances         map[string]*Instance
	bus               *Bus
	saveMu            sync.Mutex    // serializes saveConfig (atomic tmp+rename)
	allowGen          atomic.Uint64 // bumps on manual allow edits; gates syncAllowed
	allowSyncedGen    atomic.Uint64 // last allowGen mirrored into blocklist
	now               func() time.Time
	logfn             func(Event)
	queryLog          *QueryLogStore       // persistent query log
	blocklistDB       *BlocklistStore      // persisted copy of the merged blocklist
	blocklist         *blocklist.Blocklist // global DNS blocklist
	blocklistSources  []string             // Pi-hole style source URLs (AdBlock Plus / hosts)
	blocklistDisabled map[string]bool      // source URLs the operator has disabled (skipped on import)
	blMu              sync.Mutex           // guards blocklist status + import job
	blRunning         bool
	blGen             int
	blCancel          context.CancelFunc
	blStatus          BlocklistStatus
	blLastStart       time.Time
	blLoading         atomic.Bool                  // true while the startup cache load is in flight
	sourceStats       []SourceStat                 // per-source download stats, refreshed on import
	importLog         []string                     // recent import output lines (capped ring buffer)
	manualDomains     map[string]struct{}          // hand-added domains, kept apart from sources
	manualAllowed     map[string]struct{}          // hand-added whitelist domains
	autoUpdateHours   int                          // hours between automatic refreshes; 0 = manual only
	configPath        string                       // path to controller config YAML (for persisting tokens)
	defaultPolicy     *control.Policy              // fleet-wide default policy (source of truth)
	overrides         map[string]*InstanceOverride // per-instance partial configs (diff vs default)
	dohHTTPAddr       string                       // fleet-wide plain-HTTP DoH address ("", off)
	rateLimitQPS      int                          // fleet-wide DNS per-client QPS limit (0 = disabled)
	cacheSize         int                          // fleet-wide max cached responses (0 = unlimited)
	cacheConfigured   bool                         // true once the operator explicitly set a fleet-wide cache value
	upstreamServers   []upstream.UpstreamServer    // fleet-wide default upstream pool
	upstreamRoutes    []upstream.UpstreamRoute     // fleet-wide default upstream routes
	upstreamBootstrap []upstream.UpstreamServer    // fleet-wide bootstrap DNS servers for resolving DoH hostnames
	probeBootMu       sync.Mutex                   // guards probeBoot below
	probeBootKey      string                       // fleet bootstrap spec the cached probe resolver was built from
	probeBoot         upstream.Resolver            // reused probe bootstrap resolver: keeps its DoH keep-alive conns across Test clicks
	qlRetentionHours  int                          // how long query log entries are kept (0 = 24h default)
	trustedProxies    []string                     // reverse-proxy CIDRs/IPs trusted for X-Forwarded-* (controller-local)
	records           []control.RecordEntry        // fleet-wide local DNS records
	haCluster         control.HACluster            // LAN two-node VRRP desired state
	releaseChannel    string                       // stable or dev
	updateMu          sync.Mutex
	updateJob         UpdateJobStatus
	release           *releaseCheck
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

// HAStatuses reads the local keepalived status from every managed node in
// parallel (was Σ RTTs serially).
func (f *Fleet) HAStatuses(ctx context.Context) map[string]*control.HAStatus {
	insts := f.snapshotInstances()
	out := make(map[string]*control.HAStatus, len(insts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, inst := range insts {
		wg.Add(1)
		go func(in *Instance) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				out[in.id()] = &control.HAStatus{State: "UNAVAILABLE", LastError: ctx.Err().Error()}
				mu.Unlock()
				return
			}
			ictx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			st, err := in.ctl().HAStatus(ictx)
			mu.Lock()
			if err != nil {
				out[in.id()] = &control.HAStatus{State: "UNAVAILABLE", LastError: err.Error()}
			} else {
				out[in.id()] = st
			}
			mu.Unlock()
		}(inst)
	}
	wg.Wait()
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
	if err := f.pushHAConfigToCluster(ctx, cluster); err != nil {
		return err
	}
	return f.setHAClusterPersisted(cluster)
}

// haPriorityDelta is subtracted from the updating node's VRRP priority when it
// is mid-self-update, so its peer (which keeps full priority) takes over the
// VIP and traffic stays served while blipd restarts.
const haPriorityDelta = 20

// pushHAConfigToCluster pushes the given HA cluster config to both member nodes
// without persisting it (used for transient priority changes during updates).
func (f *Fleet) pushHAConfigToCluster(ctx context.Context, cluster control.HACluster) error {
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
	return nil
}

// setAndApplyHA pushes a config to the given instance and applies it (writes
// keepalived.conf + reloads keepalived so the new priority takes effect).
func (f *Fleet) setAndApplyHA(ctx context.Context, inst *Instance, cfg control.HAConfig) error {
	if err := inst.ctl().SetHAConfig(ctx, cfg); err != nil {
		return err
	}
	return inst.ctl().ApplyHA(ctx)
}

// degradeHAPriority lowers the VRRP priority of the given instance so its
// HA peer takes over the VIP while the node is restarting. It pushes and
// applies the modified config to the updating node only; the peer is
// untouched. The desired cluster config in f.haCluster is left unchanged
// so it can be restored after the update.
func (f *Fleet) degradeHAPriority(ctx context.Context, instanceID string) error {
	cluster := f.HACluster()
	if !cluster.Enabled || instanceID == "" {
		return nil
	}
	if cluster.PrimaryInstance == instanceID {
		cluster.Primary.Priority = reducePriority(cluster.Primary.Priority, cluster.Secondary.Priority)
		inst, err := f.haNode(cluster.PrimaryInstance)
		if err != nil {
			return err
		}
		if err := f.setAndApplyHA(ctx, inst, cluster.Primary); err != nil {
			return fmt.Errorf("degrade HA priority: %w", err)
		}
		inst.markHAApplied(haConfigHash(&cluster.Primary))
		f.bus.Publish(Event{InstanceID: instanceID, Type: "status", At: f.now(), Msg: "HA priority degraded for update"})
		return nil
	}
	if cluster.SecondaryInstance == instanceID {
		cluster.Secondary.Priority = reducePriority(cluster.Secondary.Priority, cluster.Primary.Priority)
		inst, err := f.haNode(cluster.SecondaryInstance)
		if err != nil {
			return err
		}
		if err := f.setAndApplyHA(ctx, inst, cluster.Secondary); err != nil {
			return fmt.Errorf("degrade HA priority: %w", err)
		}
		inst.markHAApplied(haConfigHash(&cluster.Secondary))
		f.bus.Publish(Event{InstanceID: instanceID, Type: "status", At: f.now(), Msg: "HA priority degraded for update"})
		return nil
	}
	return nil
}

// restoreHAPriority pushes the full desired HA config (with original
// priority) back to the named node and applies it, undoing a prior
// degradeHAPriority call.
func (f *Fleet) restoreHAPriority(ctx context.Context, instanceID string) error {
	cluster := f.HACluster()
	if !cluster.Enabled || instanceID == "" {
		return nil
	}
	if cluster.PrimaryInstance == instanceID {
		inst, err := f.haNode(cluster.PrimaryInstance)
		if err != nil {
			return err
		}
		if err := f.setAndApplyHA(ctx, inst, cluster.Primary); err != nil {
			return fmt.Errorf("restore HA priority: %w", err)
		}
		inst.markHAApplied(haConfigHash(&cluster.Primary))
		f.bus.Publish(Event{InstanceID: instanceID, Type: "status", At: f.now(), Msg: "HA priority restored"})
		return nil
	}
	if cluster.SecondaryInstance == instanceID {
		inst, err := f.haNode(cluster.SecondaryInstance)
		if err != nil {
			return err
		}
		if err := f.setAndApplyHA(ctx, inst, cluster.Secondary); err != nil {
			return fmt.Errorf("restore HA priority: %w", err)
		}
		inst.markHAApplied(haConfigHash(&cluster.Secondary))
		f.bus.Publish(Event{InstanceID: instanceID, Type: "status", At: f.now(), Msg: "HA priority restored"})
		return nil
	}
	return nil
}

// reducePriority lowers a VRRP priority by haPriorityDelta, clamped to a
// minimum of 1 — and always strictly below the peer, so the VIP actually
// moves even when the configured priorities differ by more than the delta.
// (A peer at 1 ties at 1: a degenerate config with no room to yield.)
func reducePriority(p, peer int) int {
	if p <= 0 {
		return p
	}
	p -= haPriorityDelta
	if q := peer - 1; q < p {
		p = q
	}
	if p < 1 {
		p = 1
	}
	return p
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

func (f *Fleet) ValidateHA(ctx context.Context, cluster control.HACluster) error {
	if err := validateHACluster(cluster); err != nil {
		return err
	}
	ids := []string{cluster.PrimaryInstance, cluster.SecondaryInstance}
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for idx, id := range ids {
		wg.Add(1)
		go func(k int, nodeID string) {
			defer wg.Done()
			inst, err := f.haNode(nodeID)
			if err != nil {
				errs[k] = err
				return
			}
			ictx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := inst.ctl().ValidateHA(ictx); err != nil {
				errs[k] = fmt.Errorf("%s: %w", nodeID, err)
			}
		}(idx, id)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *Fleet) ApplyHA(ctx context.Context, cluster control.HACluster) error {
	if err := f.ValidateHA(ctx, cluster); err != nil {
		return err
	}
	ids := []string{cluster.PrimaryInstance, cluster.SecondaryInstance}
	type res struct {
		id  string
		cfg control.HAConfig
		err error
	}
	out := make([]res, len(ids))
	var wg sync.WaitGroup
	for idx, id := range ids {
		wg.Add(1)
		go func(k int, nodeID string) {
			defer wg.Done()
			inst, err := f.haNode(nodeID)
			if err != nil {
				out[k] = res{id: nodeID, err: err}
				return
			}
			var nodeCfg control.HAConfig
			if nodeID == cluster.PrimaryInstance {
				nodeCfg = cluster.Primary
			} else {
				nodeCfg = cluster.Secondary
			}
			ictx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := inst.ctl().ApplyHA(ictx); err != nil {
				out[k] = res{id: nodeID, cfg: nodeCfg, err: fmt.Errorf("%s apply failed after earlier node(s) may have applied: %w", nodeID, err)}
				return
			}
			out[k] = res{id: nodeID, cfg: nodeCfg}
		}(idx, id)
	}
	wg.Wait()
	for _, r := range out {
		if r.err != nil {
			return r.err
		}
	}
	for _, r := range out {
		if inst := f.get(r.id); inst != nil {
			inst.markHAApplied(haConfigHash(&r.cfg))
		}
	}
	return nil
}

func (f *Fleet) DisableHA(ctx context.Context, cluster control.HACluster) error {
	if cluster.PrimaryInstance == "" && cluster.SecondaryInstance == "" {
		cluster.Enabled = false
		return f.setHAClusterPersisted(cluster)
	}
	ids := []string{}
	for _, id := range []string{cluster.PrimaryInstance, cluster.SecondaryInstance} {
		if id != "" {
			ids = append(ids, id)
		}
	}
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for idx, id := range ids {
		wg.Add(1)
		go func(k int, nodeID string) {
			defer wg.Done()
			inst, err := f.haNode(nodeID)
			if err != nil {
				errs[k] = err
				return
			}
			ictx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := inst.ctl().DisableHA(ictx); err != nil {
				errs[k] = fmt.Errorf("%s: %w", nodeID, err)
				return
			}
			inst.markHAApplied("")
		}(idx, id)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
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
	Disabled        []string     `json:"disabled,omitempty"`
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

// Controller-side resource caps.
const (
	// maxBlocklistSources caps how many source URLs an operator can configure.
	// Each source is a full download + parse; unbounded lists serialize into
	// very long imports and unbounded RAM during the merge. 32 comfortably
	// covers large multi-feed setups (the merged-domain cap below remains the
	// binding resource guard); the API rejects anything above this.
	maxBlocklistSources = 32
	// maxMergedBlocklistDomains caps the merged in-memory blocklist. Beyond
	// this the import is refused with a clear error instead of OOMing the
	// controller or shipping a multi-hundred-MB payload to every instance.
	// Per-import budget: the merge holds one map entry per domain plus one
	// snapshot row per (source, domain) in SQLite; keep imports under this.
	maxMergedBlocklistDomains = 5_000_000
	// maxInstanceLabelLen caps instance display labels (UI + events + config).
	maxInstanceLabelLen = 128
)

// NewFleet creates an empty fleet with a default event buffer.
func NewFleet(configPath string) *Fleet {
	// Defense-in-depth: controller files (config YAML with instance tokens,
	// SQLite DBs) must never be group/world-readable, even if created through
	// a path that ignores the mode argument. Best-effort; logs nothing.
	syscall.Umask(0o077)
	queryLog, err := NewQueryLogStore("/var/lib/blipc/querylog.db")
	if err != nil {
		log.Printf("blipc: query log unavailable: %v", err)
	}
	blocklistDB, err := NewBlocklistStore("/var/lib/blipc/blocklist.db")
	if err != nil {
		log.Printf("blipc: blocklist database unavailable: %v", err)
	}
	return &Fleet{
		instances:         make(map[string]*Instance),
		bus:               NewBus(500),
		now:               time.Now,
		queryLog:          queryLog,
		blocklistDB:       blocklistDB,
		blocklist:         blocklist.New(),
		configPath:        configPath,
		overrides:         make(map[string]*InstanceOverride),
		manualDomains:     make(map[string]struct{}),
		manualAllowed:     make(map[string]struct{}),
		blocklistDisabled: make(map[string]bool),
		release:           newReleaseCheck(),
	}
}

func (f *Fleet) OnEvent(fn func(Event)) { f.logfn = fn }

// validateInstanceURL rejects non-HTTP(S) URLs, URLs with userinfo, and URLs
// with an empty host, so a malicious or mistyped instance entry cannot turn
// blipc into an open proxy / credential leak (e.g. file://, gopher://, or
// http://user:pass@host). F-05: remote cleartext HTTP is accepted (blipd's
// management API is HTTP-only, so rejecting it would leave remote fleets
// with no working transport), but it is flagged by isInsecureInstanceURL
// and warned about loudly at Add time: bearer tokens cross the network in
// cleartext, so keep remote management on an isolated VLAN, a WireGuard
// tunnel, or the same host (Unix socket preferred).
func validateInstanceURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("instance url required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid instance url: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid instance url: scheme must be http or https")
	}
	if u.User != nil {
		return fmt.Errorf("invalid instance url: userinfo not allowed")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("invalid instance url: host required")
	}
	return nil
}

// isInsecureInstanceURL reports whether raw is a cleartext HTTP URL to a
// non-loopback host (F-05): the blipd bearer token traverses the network
// unencrypted. Same-host http (loopback) is fine; https is fine anywhere.
func isInsecureInstanceURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "http" && !isLoopbackHost(u.Hostname())
}

// warnInsecureInstanceURL logs the F-05 warning for a remote cleartext
// management URL: tokens, policies and query history cross the wire
// unprotected. Emitted at Add time (startup and UI/API adds alike) so the
// risk is visible in the journal on every configure, not buried in docs.
func warnInsecureInstanceURL(id, raw string) {
	if isInsecureInstanceURL(raw) {
		log.Printf("blipc: WARNING instance %q uses cleartext http management to %q: bearer tokens are sniffable on the network path; isolate the management network (VLAN/WireGuard) or co-locate via Unix socket", id, raw)
	}
}

// isLoopbackHost reports whether host is a loopback address or name: 127/8,
// ::1, or localhost. Remote HTTP management is rejected; these stay allowed
// for same-host setups (prefer the Unix socket where possible).
func isLoopbackHost(host string) bool {
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (f *Fleet) Add(ctx context.Context, cfg InstanceConfig) error {
	if cfg.ID == "" {
		return fmt.Errorf("controller: instance requires id")
	}
	if cfg.URL == "" {
		return fmt.Errorf("controller: instance %s requires url", cfg.ID)
	}
	if err := validateInstanceURL(cfg.URL); err != nil {
		return err
	}
	warnInsecureInstanceURL(cfg.ID, cfg.URL)
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

// cloneInstanceOverride deep-copies an override so saveConfig can marshal it
// after releasing f.mu without aliasing live state (F-11). Pointer fields get
// fresh pointees; slice fields get fresh backing arrays.
func cloneInstanceOverride(o *InstanceOverride) *InstanceOverride {
	if o == nil {
		return nil
	}
	out := *o
	if o.Upstream != nil {
		v := *o.Upstream
		out.Upstream = &v
	}
	if o.BlockAction != nil {
		v := *o.BlockAction
		out.BlockAction = &v
	}
	if o.Log != nil {
		v := *o.Log
		out.Log = &v
	}
	if o.DoHHTTPAddr != nil {
		v := *o.DoHHTTPAddr
		out.DoHHTTPAddr = &v
	}
	if o.RateLimitQPS != nil {
		v := *o.RateLimitQPS
		out.RateLimitQPS = &v
	}
	if o.UpstreamServers != nil {
		v := append([]upstream.UpstreamServer(nil), *o.UpstreamServers...)
		out.UpstreamServers = &v
	}
	if o.UpstreamRoutes != nil {
		v := append([]upstream.UpstreamRoute(nil), *o.UpstreamRoutes...)
		out.UpstreamRoutes = &v
	}
	if o.UpstreamBootstrap != nil {
		v := append([]upstream.UpstreamServer(nil), *o.UpstreamBootstrap...)
		out.UpstreamBootstrap = &v
	}
	if o.CacheSize != nil {
		v := *o.CacheSize
		out.CacheSize = &v
	}
	if o.Records != nil {
		v := append([]control.RecordEntry(nil), *o.Records...)
		out.Records = &v
	}
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

// UpstreamBootstrap returns the fleet-wide bootstrap DNS servers.
func (f *Fleet) UpstreamBootstrap() []upstream.UpstreamServer {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.upstreamBootstrap
}

// ProbeBootstrap returns a cached bootstrap resolver for the upstream Test
// endpoint, rebuilt only when the fleet bootstrap config changes. Reusing it
// keeps DoH keep-alive connections warm across Test clicks: a fresh resolver
// per click pays a new TLS handshake every time, which is both slow and the
// most RST-triggering pattern against rate-limiting upstreams like Quad9.
// A nil bootstrap config returns (nil, nil): probes resolve DoH hostnames via
// the system resolver, as before.
func (f *Fleet) ProbeBootstrap() (upstream.Resolver, error) {
	servers := f.UpstreamBootstrap()
	key := bootstrapKey(servers)
	f.probeBootMu.Lock()
	defer f.probeBootMu.Unlock()
	if f.probeBootKey == key && (f.probeBoot != nil || key == "") {
		return f.probeBoot, nil
	}
	r, err := upstream.BuildBootstrapResolver(servers)
	if err != nil {
		return nil, err
	}
	f.probeBootKey = key
	f.probeBoot = r
	return r, nil
}

// bootstrapKey fingerprints a bootstrap server list for cache comparison.
func bootstrapKey(servers []upstream.UpstreamServer) string {
	var sb strings.Builder
	for _, sv := range servers {
		sb.WriteString(sv.Name)
		sb.WriteByte(0)
		sb.WriteString(sv.Address)
		sb.WriteByte(0)
		sb.WriteString(strconv.Itoa(sv.TimeoutSec))
		sb.WriteByte(0)
	}
	return sb.String()
}

// SetUpstreamDefault records the fleet-wide default upstream pool, routes and
// bootstrap servers without distributing them. Used at startup from the
// controller config.
func (f *Fleet) SetUpstreamDefault(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute, bootstrap []upstream.UpstreamServer) {
	f.mu.Lock()
	f.upstreamServers = servers
	f.upstreamRoutes = routes
	f.upstreamBootstrap = bootstrap
	f.mu.Unlock()
}

// SetUpstream sets the fleet-wide default upstream pool, routes and bootstrap
// servers, persists them, and pushes the effective value (default or
// per-instance override) to every adopted instance.
func (f *Fleet) SetUpstream(ctx context.Context, servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute, bootstrap []upstream.UpstreamServer) map[string]string {
	prev, _ := f.Upstream()
	f.SetUpstreamDefault(servers, routes, bootstrap)
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

// effectiveUpstream returns the upstream pool + routes + bootstrap an instance
// should have: its own override if set, otherwise the fleet-wide default.
func (f *Fleet) effectiveUpstream(instID string) ([]upstream.UpstreamServer, []upstream.UpstreamRoute, []upstream.UpstreamServer) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	servers := f.upstreamServers
	routes := f.upstreamRoutes
	bootstrap := f.upstreamBootstrap
	if o := f.overrides[instID]; o != nil {
		if o.UpstreamServers != nil {
			servers = *o.UpstreamServers
		}
		if o.UpstreamRoutes != nil {
			routes = *o.UpstreamRoutes
		}
		if o.UpstreamBootstrap != nil {
			bootstrap = *o.UpstreamBootstrap
		}
	}
	return servers, routes, bootstrap
}

// upstreamHash returns a stable fingerprint of the upstream pool + routes +
// bootstrap so the controller can detect drift after a restart (mirroring the
// DoH and rate-limit reconcilers).
func upstreamHash(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute, bootstrap []upstream.UpstreamServer) string {
	if servers == nil {
		servers = []upstream.UpstreamServer{}
	}
	if routes == nil {
		routes = []upstream.UpstreamRoute{}
	}
	if bootstrap == nil {
		bootstrap = []upstream.UpstreamServer{}
	}
	b, err := json.Marshal(struct {
		Servers   []upstream.UpstreamServer `json:"servers"`
		Routes    []upstream.UpstreamRoute  `json:"routes"`
		Bootstrap []upstream.UpstreamServer `json:"bootstrap"`
	}{servers, routes, bootstrap})
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// pushUpstream distributes the effective upstream pool + routes + bootstrap to
// every adopted instance. Instances whose effective upstream is empty (neither
// the fleet default nor a per-instance override sets any servers or routes) are
// skipped: the fleet is not managing upstream for them, so they keep whatever
// they currently have (config-file or previously pushed).
func (f *Fleet) snapshotInstances() []*Instance {
	f.mu.RLock()
	defer f.mu.RUnlock()
	insts := make([]*Instance, 0, len(f.instances))
	for _, i := range f.instances {
		insts = append(insts, i)
	}
	return insts
}

// fanOut runs fn against every instance with bounded parallelism (8) and a
// per-instance timeout, so one slow/offline node never head-of-line-blocks the
// fleet. Results map instance ID -> "ok" or error text.
func (f *Fleet) fanOut(ctx context.Context, fn func(ctx context.Context, inst *Instance) string) map[string]string {
	insts := f.snapshotInstances()
	results := make(map[string]string, len(insts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, inst := range insts {
		instID := inst.id()
		if !inst.hasToken() {
			results[instID] = "not adopted"
			continue
		}
		wg.Add(1)
		go func(in *Instance) {
			defer wg.Done()
			inID := in.id()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				results[inID] = ctx.Err().Error()
				mu.Unlock()
				return
			}
			ictx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			res := fn(ictx, in)
			mu.Lock()
			results[inID] = res
			mu.Unlock()
		}(inst)
	}
	wg.Wait()
	return results
}

func (f *Fleet) pushUpstream(ctx context.Context) map[string]string {
	return f.fanOut(ctx, func(ictx context.Context, i *Instance) string {
		wantServers, wantRoutes, wantBootstrap := f.effectiveUpstream(i.id())
		if len(wantServers) == 0 && len(wantRoutes) == 0 {
			return "no upstream configured"
		}
		if err := i.ctl().SetUpstream(ictx, wantServers, wantRoutes, wantBootstrap); err != nil {
			return err.Error()
		}
		return "ok"
	})
}

// maybePushUpstream converges an instance's upstream pool + routes + bootstrap
// to its fleet default (or per-instance override) when the instance reports a
// divergent set — e.g. after a restart it reverted to its own config-file pool.
// Skips instances whose effective upstream is empty (the fleet is not managing
// upstream for them).
func (f *Fleet) maybePushUpstream(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	wantServers, wantRoutes, wantBootstrap := f.effectiveUpstream(i.id())
	if len(wantServers) == 0 && len(wantRoutes) == 0 {
		return
	}
	wantHash := upstreamHash(wantServers, wantRoutes, wantBootstrap)
	repHash := ""
	if reported != nil {
		repHash = upstreamHash(reported.UpstreamServers, reported.UpstreamRoutes, reported.BootstrapServers)
	}
	if wantHash == repHash || !i.hasToken() {
		return
	}
	if err := i.ctl().SetUpstream(ctx, wantServers, wantRoutes, wantBootstrap); err != nil {
		log.Printf("blipc: reconcile upstream for %s: %v", i.id(), err)
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
		existing = &InstanceOverride{}
	}
	merged := *existing
	// Empty-string string fields mean "clear back to fleet default" so a
	// stuck BlockAction:allow / Upstream override can be removed without
	// deleting the whole per-instance override (other categories preserved).
	if partial.Upstream != nil {
		if *partial.Upstream == "" {
			merged.Upstream = nil
		} else {
			merged.Upstream = partial.Upstream
		}
	}
	if partial.BlockAction != nil {
		if *partial.BlockAction == "" {
			merged.BlockAction = nil
		} else {
			merged.BlockAction = partial.BlockAction
		}
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
	if partial.UpstreamBootstrap != nil {
		merged.UpstreamBootstrap = partial.UpstreamBootstrap
	}
	if partial.CacheSize != nil {
		merged.CacheSize = partial.CacheSize
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
	return f.fanOut(ctx, func(ictx context.Context, i *Instance) string {
		qps := f.effectiveRateLimitQPS(i.id())
		if err := i.ctl().SetRateLimit(ictx, qps, 0); err != nil {
			return err.Error()
		}
		return "ok"
	})
}

// pushDoH distributes the effective plain-HTTP DoH address to every instance.
func (f *Fleet) pushDoH(ctx context.Context) map[string]string {
	return f.fanOut(ctx, func(ictx context.Context, i *Instance) string {
		want := f.effectiveDoHHTTPAddr(i.id())
		if err := i.ctl().SetDoHHTTPAddr(ictx, want); err != nil {
			return err.Error()
		}
		return "ok"
	})
}

// maybePushDoH converges an instance's plain-HTTP DoH listener to its fleet
// default (or per-instance override) when the instance reports a divergent
// value — e.g. after a restart it reverted to its own YAML.
func (f *Fleet) maybePushDoH(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	want := f.effectiveDoHHTTPAddr(i.id())
	rep := ""
	if reported != nil {
		rep = reported.DohHTTPAddr
	}
	if rep == want || !i.hasToken() {
		return
	}
	if err := i.ctl().SetDoHHTTPAddr(ctx, want); err != nil {
		log.Printf("blipc: reconcile doh for %s: %v", i.id(), err)
	}
}

// maybePushRateLimit converges an instance's DNS rate limit to its fleet default
// (or per-instance override) when the instance reports a divergent value — e.g
// after a restart it reverted to its own YAML.
func (f *Fleet) maybePushRateLimit(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	want := f.effectiveRateLimitQPS(i.id())
	rep := -1
	if reported != nil {
		rep = reported.RateLimitQPS
	}
	if rep == want || !i.hasToken() {
		return
	}
	if err := i.ctl().SetRateLimit(ctx, want, 0); err != nil {
		log.Printf("blipc: reconcile rate limit for %s: %v", i.id(), err)
	}
}

// effectiveHABConfig returns the desired HAConfig for the given instance, or
// nil if the instance is not a member of an HA cluster. ok is false when there
// is no HA cluster configured at all.
func (f *Fleet) effectiveHABConfig(instID string) (cfg *control.HAConfig, ok bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.haCluster.Enabled {
		return nil, false
	}
	if f.haCluster.PrimaryInstance == instID {
		c := f.haCluster.Primary
		return &c, true
	}
	if f.haCluster.SecondaryInstance == instID {
		c := f.haCluster.Secondary
		return &c, true
	}
	return nil, false
}

// haHashFor returns a stable fingerprint of the desired HA config for the
// given instance ("" when the instance is not HA-enabled). Used by the poll
// loop to detect drift and retry a failed keepalived reload.
func (f *Fleet) haHashFor(instID string) string {
	cfg, ok := f.effectiveHABConfig(instID)
	if !ok {
		return ""
	}
	return haConfigHash(cfg)
}

// haConfigHash returns a stable SHA-256 fingerprint of an HA config.
func haConfigHash(cfg *control.HAConfig) string {
	b, _ := json.Marshal(cfg)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// maybePushHA converges an instance's HA/keepalived configuration to the
// controller's desired cluster config. It is the HA equivalent of the other
// maybePush* reconcilers: when ApplyHA failed to reload keepalived (e.g. a
// sudoers misconfiguration), the live keepalived process still runs with a
// stale priority and there is no other mechanism to retry. The periodic poll
// calls this so a transient reload failure is corrected on the next tick.
func (f *Fleet) maybePushHA(ctx context.Context, i *Instance) {
	cfg, ok := f.effectiveHABConfig(i.id())
	if !ok || !i.hasToken() {
		return
	}
	// Skip reconciliation for the node currently being self-updated: the
	// update job deliberately degrades and restores its VRRP priority. If the
	// poll loop re-applied the desired config mid-update, it would undo the
	// degradation and the peer wouldn't take over the VIP.
	f.updateMu.Lock()
	updating := f.updateJob.Running && f.updateJob.Current == i.id()
	f.updateMu.Unlock()
	if updating {
		return
	}
	if i.haConfigApplied(f.haHashFor(i.id())) {
		return
	}
	if err := f.setAndApplyHA(ctx, i, *cfg); err != nil {
		log.Printf("blipc: reconcile HA for %s: %v", i.id(), err)
		return
	}
	i.markHAApplied(f.haHashFor(i.id()))
}

// QueryLogRetentionHours returns how long query log entries are kept on blipc.
// 0 in the field means "unset": the 7-day (168h) privacy-preserving default
// applies. Longer windows are opt-in via the controller settings.
func (f *Fleet) QueryLogRetentionHours() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.qlRetentionHours <= 0 {
		return 168
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
// 7-day default.
func (f *Fleet) SetQueryLogRetentionDefault(hours int) {
	f.mu.Lock()
	f.qlRetentionHours = hours
	f.mu.Unlock()
	if f.queryLog != nil {
		f.queryLog.SetRetention(time.Duration(f.QueryLogRetentionHours()) * time.Hour)
	}
}

// TrustedProxies returns the reverse-proxy CIDRs/IPs trusted for
// X-Forwarded-For/Proto/Host (controller-local, empty = trust none).
func (f *Fleet) TrustedProxies() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, len(f.trustedProxies))
	copy(out, f.trustedProxies)
	return out
}

// SetTrustedProxiesDefault records trusted proxies without persisting.
// Used at startup from the controller config.
func (f *Fleet) SetTrustedProxiesDefault(proxies []string) {
	f.mu.Lock()
	f.trustedProxies = append([]string(nil), proxies...)
	f.mu.Unlock()
}

// SetTrustedProxies validates, records and persists trusted proxies.
func (f *Fleet) SetTrustedProxies(proxies []string) error {
	if _, err := ParseTrustedProxies(proxies); err != nil {
		return err
	}
	clean := make([]string, 0, len(proxies))
	for _, v := range proxies {
		if v = trimSpace(v); v != "" {
			clean = append(clean, v)
		}
	}
	f.mu.Lock()
	f.trustedProxies = clean
	f.mu.Unlock()
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			return err
		}
	}
	return nil
}

func trimSpace(s string) string {
	// local helper to avoid importing strings here (already imported).
	return strings.TrimSpace(s)
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

// CacheConfig returns the fleet-wide cache size limit (0 = unlimited).
func (f *Fleet) CacheConfig() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.cacheSize
}

// SetCacheDefault records the fleet-wide cache size without distributing it.
// Used at startup from the controller config.
func (f *Fleet) SetCacheDefault(size int) {
	if size < 0 {
		size = 0
	}
	f.mu.Lock()
	f.cacheSize = size
	f.cacheConfigured = true
	f.mu.Unlock()
}

// effectiveCacheConfig returns the cache size an instance should run: its own
// override if set, otherwise the fleet default.
func (f *Fleet) effectiveCacheConfig(id string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	size := f.cacheSize
	if o := f.overrides[id]; o != nil {
		if o.CacheSize != nil {
			size = *o.CacheSize
		}
	}
	return size
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
		return o.CacheSize != nil
	}
	return false
}

// SetCache records the fleet-wide cache size, persists it, and pushes the
// effective value (default or per-instance override) to every adopted
// instance. Returns the per-instance outcome.
func (f *Fleet) SetCache(ctx context.Context, size int) map[string]string {
	f.SetCacheDefault(size)
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist cache setting: %v", err)
		}
	}
	return f.pushCache(ctx)
}

// pushCache distributes the effective cache size to every adopted instance.
func (f *Fleet) pushCache(ctx context.Context) map[string]string {
	return f.fanOut(ctx, func(ictx context.Context, i *Instance) string {
		size := f.effectiveCacheConfig(i.id())
		if err := i.ctl().SetCacheConfig(ictx, size); err != nil {
			return err.Error()
		}
		return "ok"
	})
}

// maybePushCache converges an instance's cache size to its fleet default (or
// per-instance override) when the instance reports a divergent value — e.g.
// after a restart it reverted to its own YAML. If the operator hasn't
// configured any cache setting (neither fleet-wide nor per-instance), the
// instance's own blipd YAML defaults are left in place.
func (f *Fleet) maybePushCache(ctx context.Context, i *Instance, reported *control.StatsResponse) {
	if !f.cacheConfiguredFor(i.id()) {
		return
	}
	wantSize := f.effectiveCacheConfig(i.id())
	repSize := -1
	if reported != nil {
		repSize = reported.CacheSize
	}
	if repSize == wantSize || !i.hasToken() {
		return
	}
	if err := i.ctl().SetCacheConfig(ctx, wantSize); err != nil {
		log.Printf("blipc: reconcile cache for %s: %v", i.id(), err)
	}
}

// PurgeCache drops every cached response on every adopted instance and returns
// the per-instance outcome, including how many entries were purged.
func (f *Fleet) PurgeCache(ctx context.Context) (map[string]string, int) {
	var total atomic.Int64
	results := f.fanOut(ctx, func(ictx context.Context, i *Instance) string {
		n, err := i.ctl().PurgeCache(ictx)
		if err != nil {
			return err.Error()
		}
		total.Add(int64(n))
		return "ok"
	})
	return results, int(total.Load())
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
	return f.fanOut(ctx, func(ictx context.Context, i *Instance) string {
		want := f.effectiveRecords(i.id())
		if err := i.ctl().SetRecords(ictx, want); err != nil {
			return err.Error()
		}
		return "ok"
	})
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
	want := f.effectiveRecords(i.id())
	if err := i.ctl().SetRecords(ctx, want); err != nil {
		log.Printf("blipc: reconcile records for %s: %v", i.id(), err)
	}
}

// pushInstance sends one instance's effective config to it.
func (f *Fleet) pushConfigs(ctx context.Context) map[string]string {
	// Snapshot effective policies once under a single RLock instead of per
	// instance inside the loop (which blocked Set* writers across N hashes).
	type want struct {
		id  string
		eff *control.Policy
	}
	f.mu.RLock()
	wants := make([]want, 0, len(f.instances))
	for _, i := range f.instances {
		eff, _ := f.effectivePolicy(i.id())
		wants = append(wants, want{id: i.id(), eff: eff})
	}
	f.mu.RUnlock()
	byID := make(map[string]*control.Policy, len(wants))
	for _, w := range wants {
		byID[w.id] = w.eff
	}
	return f.fanOut(ctx, func(ictx context.Context, i *Instance) string {
		eff := byID[i.id()]
		if eff == nil {
			return "no config"
		}
		if err := i.ctl().SetPolicy(ictx, eff); err != nil {
			return err.Error()
		}
		i.markConfigAppliedWith(f.appliedHashFor(i.id()), eff.Upstream)
		return "ok"
	})
}

// pushInstance sends one instance's effective config to it. Used when a
// per-instance override is saved. Returns a single-entry result map. The DoH
// address is always pushed (it can override even with no policy set); the
// policy is pushed only when an effective one exists. Independent scopes push
// concurrently (was 6 serial RTTs).
func (f *Fleet) pushInstance(ctx context.Context, id string) map[string]string {
	i := f.get(id)
	if i == nil {
		return map[string]string{id: "unknown instance"}
	}
	f.mu.RLock()
	eff, _ := f.effectivePolicy(id)
	wantDoH := f.effectiveDoHHTTPAddr(id)
	wantSize := f.effectiveCacheConfig(id)
	wantQPS := f.effectiveRateLimitQPS(id)
	wantRecs := f.effectiveRecords(id)
	wantServers, wantRoutes, wantBootstrap := f.effectiveUpstream(id)
	f.mu.RUnlock()
	res := map[string]string{id: "ok"}
	if !i.hasToken() {
		res[id] = "not adopted"
		return res
	}
	// Collect per-step errors instead of last-wins overwriting, so a partial
	// failure is surfaced honestly (e.g. "doh: …; upstream: …"). Scopes push
	// concurrently (was 6 serial RTTs).
	var mu sync.Mutex
	var wg sync.WaitGroup
	var errs []string
	addErr := func(msg string) {
		mu.Lock()
		errs = append(errs, msg)
		mu.Unlock()
	}
	wg.Add(6)
	go func() {
		defer wg.Done()
		if err := i.ctl().SetDoHHTTPAddr(ctx, wantDoH); err != nil {
			addErr("doh: " + err.Error())
		}
	}()
	go func() {
		defer wg.Done()
		if err := i.ctl().SetCacheConfig(ctx, wantSize); err != nil {
			addErr("cache: " + err.Error())
		}
	}()
	go func() {
		defer wg.Done()
		if err := i.ctl().SetRateLimit(ctx, wantQPS, 0); err != nil {
			addErr("rate_limit: " + err.Error())
		}
	}()
	go func() {
		defer wg.Done()
		if err := i.ctl().SetRecords(ctx, wantRecs); err != nil {
			addErr("records: " + err.Error())
		}
	}()
	go func() {
		defer wg.Done()
		if eff != nil {
			if err := i.ctl().SetPolicy(ctx, eff); err != nil {
				addErr("policy: " + err.Error())
				return
			}
			i.markConfigAppliedWith(f.appliedHashFor(id), eff.Upstream)
		}
	}()
	go func() {
		defer wg.Done()
		if len(wantServers) > 0 || len(wantRoutes) > 0 {
			if err := i.ctl().SetUpstream(ctx, wantServers, wantRoutes, wantBootstrap); err != nil {
				addErr("upstream: " + err.Error())
			}
		}
	}()
	wg.Wait()
	// No blocklist push here: it is a multi-MB upload that belongs in the
	// poll-loop reconciler, which short-circuits on the reported hash and
	// backs off while a push is in flight.
	if len(errs) > 0 {
		res[id] = strings.Join(errs, "; ")
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
	eff, hash := f.effectivePolicy(i.id())
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
	if err := inst.ctl().SetPolicy(ctx, p); err != nil {
		return err
	}
	f.bus.Publish(Event{InstanceID: id, Instance: inst.label(), Type: "policy", At: f.now(), Msg: "set " + p.ID, Domain: p.ID})
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
	resp, err := inst.ctl().Adopt(ctx, code)
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
		old := inst.client
		inst.client = control.NewClient(inst.Config.URL, resp.Token)
		inst.mu.Unlock()
		if old != nil {
			old.CloseIdleConnections()
		}
		if f.configPath != "" {
			if err := f.saveConfig(); err != nil {
				log.Printf("blipc: warning: failed to persist adopted token: %v", err)
			}
		}
		// Newly adopted instance: hand it the fleet config and blocklist.
		f.maybePushConfig(context.Background(), inst, nil)
		f.maybePushBlocklist(context.Background(), inst, nil)
	}
	f.bus.Publish(Event{InstanceID: id, Instance: inst.label(), Type: "status", At: f.now(), Msg: "adopted"})
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
	return inst.ctl().AdoptStatus(context.Background())
}

// ResetAdoption resets a managed instance's adoption state.
func (f *Fleet) ResetAdoption(ctx context.Context, id string) error {
	inst := f.get(id)
	if inst == nil {
		return fmt.Errorf("controller: unknown instance %s", id)
	}
	if err := inst.ctl().ResetAdoption(ctx); err != nil {
		return err
	}
	f.bus.Publish(Event{InstanceID: id, Instance: inst.label(), Type: "status", At: f.now(), Msg: "adoption reset"})
	return nil
}

// SetLabel updates the label of a managed instance. Labels are capped at
// maxInstanceLabelLen chars to bound config/UI/event payloads.
func (f *Fleet) SetLabel(ctx context.Context, id, label string) error {
	inst := f.get(id)
	if inst == nil {
		return fmt.Errorf("controller: unknown instance %s", id)
	}
	label = strings.TrimSpace(label)
	if len(label) > maxInstanceLabelLen {
		label = label[:maxInstanceLabelLen]
	}
	inst.mu.Lock()
	inst.setLabelLocked(label)
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
	return inst.ctl().DeletePolicy(ctx, policyID)
}

// ListPolicies returns policies from a managed instance.
func (f *Fleet) ListPolicies(ctx context.Context, id string) (*control.ListResponse, error) {
	inst := f.get(id)
	if inst == nil {
		return nil, fmt.Errorf("controller: unknown instance %s", id)
	}
	return inst.ctl().ListPolicies(ctx)
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
	st.Disabled = make([]string, 0, len(f.blocklistDisabled))
	for u, d := range f.blocklistDisabled {
		if d {
			st.Disabled = append(st.Disabled, u)
		}
	}
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

// SetBlocklistSourcesDefault loads the source URLs at startup without
// persisting or importing. Restarts serve the persisted cache (pushed to
// instances by the reconcile loop); refreshes come from the auto-updater when
// due, or from an explicit operator action.
func (f *Fleet) SetBlocklistSourcesDefault(urls []string) {
	f.blMu.Lock()
	f.blocklistSources = cleanURLs(urls)
	f.blMu.Unlock()
}

// SetBlocklistSources replaces the source URLs, persists them to the config,
// and starts a background import job. The HTTP caller returns immediately;
// progress is visible via BlocklistStatus.
func (f *Fleet) SetBlocklistSources(ctx context.Context, urls []string) {
	f.blMu.Lock()
	clean := cleanURLs(urls)
	f.blocklistSources = clean
	if len(f.blocklistDisabled) > 0 {
		kept := make(map[string]bool)
		for _, u := range clean {
			if f.blocklistDisabled[u] {
				kept[u] = true
			}
		}
		f.blocklistDisabled = kept
	}
	f.blMu.Unlock()
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist blocklist sources: %v", err)
		}
	}
	f.startBlocklistImport("sources-updated")
}

// EnabledBlocklistSources returns the configured source URLs that are not in
// the disabled set.
func (f *Fleet) EnabledBlocklistSources() []string {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	out := make([]string, 0, len(f.blocklistSources))
	for _, u := range f.blocklistSources {
		if !f.blocklistDisabled[u] {
			out = append(out, u)
		}
	}
	return out
}

// SetBlocklistSourceEnabled toggles a single source on/off, persists the
// change, and starts a background import so the merged list (and every
// instance) reflects the new state. Disabling a source removes its domains
// from the active blocklist; re-enabling restores them on the next import.
func (f *Fleet) SetBlocklistSourceEnabled(ctx context.Context, url string, enabled bool) {
	f.blMu.Lock()
	if enabled {
		delete(f.blocklistDisabled, url)
	} else {
		f.blocklistDisabled[url] = true
	}
	f.blMu.Unlock()
	if f.configPath != "" {
		if err := f.saveConfig(); err != nil {
			log.Printf("blipc: warning: failed to persist blocklist source state: %v", err)
		}
	}
	f.startBlocklistImport("source-toggle")
}

// SetBlocklistDisabled records which source URLs are disabled. Used at startup
// to restore the disabled set before the first import runs; does not itself
// trigger an import.
func (f *Fleet) SetBlocklistDisabled(urls []string) {
	f.blMu.Lock()
	f.blocklistDisabled = make(map[string]bool, len(urls))
	for _, u := range cleanURLs(urls) {
		f.blocklistDisabled[u] = true
	}
	f.blMu.Unlock()
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
// Uses a timer until the next due time instead of a 1-minute poll wake.
func (f *Fleet) StartAutoUpdater() {
	go func() {
		for {
			next := f.nextAutoUpdateIn()
			if next <= 0 {
				// Not configured: recheck hourly for config changes.
				next = time.Hour
			}
			t := time.NewTimer(next)
			select {
			case <-t.C:
			}
			t.Stop()
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
				f.startBlocklistImport("auto-update")
			}
		}
	}()
}

func (f *Fleet) nextAutoUpdateIn() time.Duration {
	f.blMu.Lock()
	defer f.blMu.Unlock()
	if f.autoUpdateHours <= 0 || len(f.blocklistSources) == 0 {
		return 0
	}
	if f.blStatus.LastUpdate.IsZero() {
		return time.Minute
	}
	due := f.blStatus.LastUpdate.Add(time.Duration(f.autoUpdateHours) * time.Hour)
	d := time.Until(due)
	if d < time.Minute {
		d = time.Minute
	}
	return d
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
	var last time.Time
	for _, u := range f.blocklistSources {
		if meta, ok := m[u]; ok {
			ordered = append(ordered, SourceStat{URL: meta.URL, Domains: meta.Domains, LastUpdate: meta.LastUpdate, Error: meta.Error})
			if meta.LastUpdate.After(last) {
				last = meta.LastUpdate
			}
			delete(m, u)
		}
	}
	for url, meta := range m {
		ordered = append(ordered, SourceStat{URL: url, Domains: meta.Domains, LastUpdate: meta.LastUpdate, Error: meta.Error})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].URL < ordered[j].URL })
	f.sourceStats = ordered
	// Seed the last-import time from the persisted snapshots so a restart
	// with fresh snapshots doesn't look like a due auto-update.
	if !last.IsZero() {
		f.blStatus.LastUpdate = last
	}
	f.blMu.Unlock()
}

// LoadManualDomains restores the hand-added domains at startup so they survive
// both restarts and the fresh source import that follows one.
func (f *Fleet) LoadManualDomains(ctx context.Context) {
	if f.blocklistDB == nil {
		return
	}
	m, err := f.blocklistDB.loadDomainSet(ctx, "blocklist_manual")
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
		if err := f.blocklistDB.replaceDomainSet(context.Background(), "blocklist_manual", f.ManualDomains()); err != nil {
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
	m, err := f.blocklistDB.loadDomainSet(ctx, "blocklist_manual_allow")
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
	f.allowGen.Add(1)
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
	f.allowGen.Add(1)
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
// blocked and allowed domains. Gated on allowGen: the old code rebuilt + sorted
// the allow set on every poll per instance (N rebuilds per 5s).
func (f *Fleet) syncAllowed() {
	gen := f.allowGen.Load()
	if f.allowSyncedGen.Load() == gen {
		return
	}
	f.blocklist.SetAllowed(f.AllowedDomains())
	f.allowSyncedGen.Store(gen)
}

// ClearAllowedDomains removes every hand-added whitelist entry.
func (f *Fleet) ClearAllowedDomains() {
	f.blMu.Lock()
	f.manualAllowed = make(map[string]struct{})
	f.blMu.Unlock()
	f.allowGen.Add(1)
	f.blocklist.SetAllowed(nil)
	f.allowSyncedGen.Store(f.allowGen.Load())
	f.persistAllowed()
}

// persistAllowed snapshots the hand-added whitelist to the local DB in the
// background.
func (f *Fleet) persistAllowed() {
	if f.blocklistDB == nil {
		return
	}
	go func() {
		if err := f.blocklistDB.replaceDomainSet(context.Background(), "blocklist_manual_allow", f.AllowedDomains()); err != nil {
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

// maxBlocklistFetchers bounds how many blocklist sources blipc fetches
// concurrently during an import (matching the blocklist package's limit).
const maxBlocklistFetchers = 8

func (f *Fleet) startBlocklistImport(reason string) {
	f.blMu.Lock()
	f.blGen++
	gen := f.blGen
	superseded := f.blCancel != nil
	if superseded {
		f.blCancel() // cancel any in-flight import; the new one supersedes it
	}
	lastStart := f.blLastStart
	f.blLastStart = f.now()
	ctx, cancel := context.WithCancel(context.Background())
	f.blCancel = cancel
	f.blRunning = true
	enabled := 0
	for _, u := range f.blocklistSources {
		if !f.blocklistDisabled[u] {
			enabled++
		}
	}
	sourceCount := len(f.blocklistSources)
	f.blStatus = BlocklistStatus{Running: true, SourceTotal: enabled}
	f.importLog = nil
	f.blMu.Unlock()
	log.Printf("blipc: blocklist import trigger reason=%s gen=%d sources=%d enabled=%d superseded=%v since_last=%s",
		reason, gen, sourceCount, enabled, superseded, f.now().Sub(lastStart).Round(time.Second))
	if enabled < len(f.blocklistSources) {
		f.logImport("starting import of %d enabled source(s) (%d disabled)", enabled, len(f.blocklistSources)-enabled)
	} else {
		f.logImport("starting import of %d source(s)", len(f.blocklistSources))
	}
	go func() {
		defer recoverLog("blocklist import")
		f.runBlocklistImport(ctx, gen)
	}()
}

// logImport appends a timestamped line to the in-memory import log surfaced in
// the web UI. The buffer is capped so a long-running sync can't grow forever.
// The line is also mirrored to the process journal so a re-download loop is
// visible in journald even when nobody is watching the dashboard.
func (f *Fleet) logImport(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	f.blMu.Lock()
	f.importLog = append(f.importLog, fmt.Sprintf("%s %s", f.now().Format("15:04:05"), line))
	if len(f.importLog) > 300 {
		f.importLog = append([]string(nil), f.importLog[len(f.importLog)-300:]...)
	}
	f.blMu.Unlock()
	log.Printf("blipc: import: %s", line)
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

	allURLs := f.BlocklistSources()
	if len(allURLs) == 0 {
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

	// Sources may be individually disabled; only enabled sources contribute to
	// the merged list. If every source is disabled, keep only the manually
	// added domains (snapshots are preserved so a later re-enable can restore
	// the source from its last good state).
	urls := f.EnabledBlocklistSources()
	if len(urls) == 0 {
		f.logImport("all %d configured source(s) are disabled — keeping only manual domains", len(allURLs))
		merged := f.manualDomainSet()
		f.blocklist.FromDomainsMap(merged)
		f.persistBlocklist()
		f.pushBlocklist(context.Background())
		return
	}

	prevMeta := map[string]SourceMeta{}
	if f.blocklistDB != nil {
		if m, err := f.blocklistDB.LoadSourceMeta(ctx); err == nil {
			prevMeta = m
		}
	}

	manual := f.manualDomainSet()
	// Pre-size for the last known snapshot counts so a million-domain merge
	// doesn't rehash/grow repeatedly (prevMeta misses just under-hint).
	hint := len(manual)
	for _, u := range urls {
		if pm, ok := prevMeta[u]; ok {
			hint += pm.Domains
		}
	}
	merged := make(map[string]struct{}, hint)
	for d := range manual {
		merged[d] = struct{}{}
	}
	if len(merged) > 0 {
		f.logImport("seeding %d manually added domain(s)", len(merged))
	}

	// Fetch all sources concurrently (bounded) so a long list of feeds doesn't
	// serialize into an 8-minute download; results are merged in configured
	// order so progress and per-source stats stay deterministic.
	type blSourceResult struct {
		set         map[string]struct{}
		err         error
		dur         time.Duration
		notModified bool
		validators  blocklist.Validators
	}
	sem := make(chan struct{}, maxBlocklistFetchers)
	results := make([]blSourceResult, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[idx] = blSourceResult{err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			t0 := f.now()
			f.logImport("[%d/%d] fetching %s", idx+1, len(urls), u)
			// Echo the stored validators so an unchanged list costs a 304
			// instead of a full download.
			var v blocklist.Validators
			if pm, ok := prevMeta[u]; ok {
				v = blocklist.Validators{ETag: pm.ETag, LastModified: pm.LastModified}
			}
			fr, ferr := blocklist.FetchSource(ctx, u, v)
			if ferr != nil {
				results[idx] = blSourceResult{err: ferr, dur: time.Since(t0), validators: v}
				return
			}
			nv := fr.Validators
			if nv.ETag == "" && nv.LastModified == "" {
				nv = v // server sent none: keep echoing what we have
			}
			if fr.NotModified {
				results[idx] = blSourceResult{notModified: true, dur: time.Since(t0), validators: nv}
				return
			}
			results[idx] = blSourceResult{set: fr.Domains, dur: time.Since(t0), validators: nv}
		}(i, u)
	}
	wg.Wait()
	if !current() {
		return
	}

	stats := make([]SourceStat, 0, len(urls))
	failed := 0
	for i, r := range results {
		u := urls[i]
		st := SourceStat{URL: u}
		if r.err != nil {
			failed++
			st.Error = r.err.Error()
			f.logImport("[%d/%d] failed: %s", i+1, len(urls), r.err)
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
		} else if r.notModified {
			// 304: the server confirms our snapshot is still current. Merge
			// it without re-downloading or re-parsing anything.
			f.logImport("[%d/%d] unchanged since last fetch, keeping snapshot", i+1, len(urls))
			if f.blocklistDB != nil {
				if dbSet, derr := f.blocklistDB.LoadSourceDomains(ctx, u); derr == nil && len(dbSet) > 0 {
					for d := range dbSet {
						merged[d] = struct{}{}
					}
					st.Domains = len(dbSet)
				}
			}
			if st.Domains == 0 {
				if prev, ok := prevMeta[u]; ok {
					st.Domains = prev.Domains
				}
			}
			st.LastUpdate = f.now()
		} else {
			f.logImport("[%d/%d] ok: %d domains in %s", i+1, len(urls), len(r.set), r.dur.Round(time.Millisecond))
			for d := range r.set {
				merged[d] = struct{}{}
			}
			st.Domains = len(r.set)
			st.LastUpdate = f.now()
			if f.blocklistDB != nil {
				domains := make([]string, 0, len(r.set))
				for d := range r.set {
					domains = append(domains, d)
				}
				if err := f.blocklistDB.ReplaceSourceDomains(ctx, u, domains); err != nil {
					log.Printf("blipc: warning: persist blocklist source snapshot: %v", err)
				}
			}
		}
		if f.blocklistDB != nil {
			if err := f.blocklistDB.ReplaceSourceMeta(ctx, SourceMeta{
				URL:          u,
				Domains:      st.Domains,
				LastUpdate:   st.LastUpdate,
				Error:        st.Error,
				ETag:         r.validators.ETag,
				LastModified: r.validators.LastModified,
			}); err != nil {
				log.Printf("blipc: warning: persist blocklist source meta: %v", err)
			}
		}
		stats = append(stats, st)
		if !current() {
			return
		}
		// F-16: enforce the merge budget incrementally, not only at the end:
		// abort before further per-source SQLite snapshot writes and before
		// the merged map (+ distribution payload) grows without bound.
		if len(merged) > maxMergedBlocklistDomains {
			msg := fmt.Sprintf("merged list too large: %d domains exceeds cap of %d after source %d/%d — keeping previous list", len(merged), maxMergedBlocklistDomains, i+1, len(urls))
			f.blMu.Lock()
			f.blStatus.Errors = append(f.blStatus.Errors, msg)
			f.sourceStats = append([]SourceStat(nil), stats...)
			f.blMu.Unlock()
			f.logImport("%s", msg)
			return // keep the last good merged list untouched
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

	// Memory/time budget: refuse absurd merges instead of OOMing the
	// controller or shipping a multi-hundred-MB payload to every instance.
	if len(merged) > maxMergedBlocklistDomains {
		msg := fmt.Sprintf("merged list too large: %d domains exceeds cap of %d — keeping previous list", len(merged), maxMergedBlocklistDomains)
		f.blMu.Lock()
		f.blStatus.Errors = append(f.blStatus.Errors, msg)
		f.blMu.Unlock()
		f.logImport("%s", msg)
		return // keep the last good merged list untouched
	}

	prevHash := f.blocklist.Checksum()
	f.blocklist.FromDomainsMap(merged)
	blocklistChanged := f.blocklist.Checksum() != prevHash
	applied = true
	// Drop snapshots/metadata for sources that are no longer configured.
	// Disabled sources stay in allURLs so their snapshots survive, letting a
	// later re-enable restore the source from its last good state.
	if f.blocklistDB != nil {
		if err := f.blocklistDB.PruneSources(ctx, allURLs); err != nil {
			log.Printf("blipc: warning: prune blocklist source data: %v", err)
		}
		// One WAL truncate per import, not per source.
		_ = f.blocklistDB.checkpoint(ctx)
	}
	if !blocklistChanged {
		// Steady state (all 304 / same content): the merged set is identical,
		// so skip the full SQLite re-write and the multi-MB push to every
		// instance — reconcilers already converge any drifted node.
		f.logImport("list unchanged (%d domains) — skipping persist + distribute", len(merged))
		return
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
// clears the instances. Uploads fan out with bounded parallelism so one slow
// node (10min budget) never stalls the fleet.
func (f *Fleet) pushBlocklist(ctx context.Context) map[string]string {
	f.syncAllowed()
	domains := f.blocklist.List()
	allowed := f.blocklist.Allowed()
	hash := f.blocklist.Checksum()

	insts := f.snapshotInstances()

	log.Printf("blipc: distributing blocklist to %d instance(s): domains=%d allowed=%d hash=%016x", len(insts), len(domains), len(allowed), hash)
	results := make(map[string]string, len(insts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, inst := range insts {
		if !inst.hasToken() {
			results[inst.id()] = "not adopted"
			continue
		}
		wg.Add(1)
		go func(in *Instance) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				results[in.id()] = ctx.Err().Error()
				mu.Unlock()
				return
			}
			t0 := f.now()
			// Per-instance budget: blocklist uploads are multi-MB.
			ictx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()
			if err := in.ctl().SetBlocklist(ictx, domains, allowed); err != nil {
				log.Printf("blipc: distribute blocklist instance=%s FAILED after %s: %v", in.id(), f.now().Sub(t0).Round(time.Millisecond), err)
				mu.Lock()
				results[in.id()] = err.Error()
				mu.Unlock()
				return
			}
			in.markBlocklistApplied(hash)
			log.Printf("blipc: distribute blocklist instance=%s ok in %s (domains=%d)", in.id(), f.now().Sub(t0).Round(time.Millisecond), len(domains))
			mu.Lock()
			results[in.id()] = "ok"
			mu.Unlock()
		}(inst)
	}
	wg.Wait()
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
	// If the reported list matches neither the fleet's nor the list we last
	// pushed successfully, another controller (or process) has overwritten the
	// instance — warn loudly once so an external writer can't hide.
	if rep != i.pushedBlocklistHash() && i.foreignBlocklistDetected() {
		log.Printf("blipc: WARNING instance=%s url=%s blocklist changed by an external writer: reported=%016x fleet=%016x last-pushed=%016x",
			i.id(), i.snapshotConfig().URL, rep, hash, i.pushedBlocklistHash())
	}
	// Don't re-upload the whole list while a previous push is still in flight,
	// and back off after a failure so a stuck instance (or one that rejects the
	// payload) doesn't get hammered with full-list uploads every poll.
	if !i.tryBeginBlocklistPush(f.now()) {
		log.Printf("blipc: reconcile blocklist instance=%s url=%s SKIP (push in flight or backing off) fleet=%016x reported=%016x", i.id(), i.snapshotConfig().URL, hash, rep)
		return
	}
	log.Printf("blipc: reconcile blocklist instance=%s url=%s PUSH fleet=%016x reported=%016x domains=%d allowed=%d", i.id(), i.snapshotConfig().URL, hash, rep, f.blocklist.Count(), len(f.blocklist.Allowed()))
	err := i.ctl().SetBlocklist(ctx, f.blocklist.List(), f.blocklist.Allowed())
	i.finishBlocklistPush(err, hash)
	if err != nil {
		log.Printf("blipc: reconcile blocklist for %s: %v", i.id(), err)
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

// saveConfig writes the current fleet config (including updated tokens) to the config file.
// Serialized via saveMu and written atomically (tmp+rename 0600) so bursty UI
// saves can't interleave read-modify-writes (lost update) or leave a truncated
// controller.yaml on crash. The file is re-read to preserve unknown fields.
func (f *Fleet) saveConfig() error {
	if f.configPath == "" {
		return nil
	}
	f.saveMu.Lock()
	defer f.saveMu.Unlock()

	b, err := os.ReadFile(f.configPath)
	if err != nil {
		b = []byte{}
	}

	type fullConfig struct {
		Listen            string                       `yaml:"listen"`
		Username          string                       `yaml:"username"`
		Password          string                       `yaml:"password"`
		PasswordHash      string                       `yaml:"password_hash"`
		DashboardTLS      bool                         `yaml:"dashboard_tls"`
		TLSDir            string                       `yaml:"tls_dir"`
		TLSCertFile       string                       `yaml:"tls_cert_file"`
		TLSKeyFile        string                       `yaml:"tls_key_file"`
		TLSSANs           []string                     `yaml:"tls_san"`
		DefaultPolicy     *control.Policy              `yaml:"default_policy"`
		InstancePolicies  map[string]*InstanceOverride `yaml:"instance_overrides"`
		DoHHTTPAddr       string                       `yaml:"doh_http_addr"`
		RateLimitQPS      int                          `yaml:"rate_limit_qps"`
		UpstreamServers   []upstream.UpstreamServer    `yaml:"upstream_servers"`
		UpstreamRoutes    []upstream.UpstreamRoute     `yaml:"upstream_routes"`
		UpstreamBootstrap []upstream.UpstreamServer    `yaml:"upstream_bootstrap"`
		// F-18: pointer + omitempty so an explicit `cache_size: 0`
		// (unlimited) round-trips, while an unconfigured fleet omits the
		// field instead of persisting a misleading zero.
		CacheSize              *int                  `yaml:"cache_size,omitempty"`
		QueryLogRetentionHours int                   `yaml:"query_log_retention_hours"`
		TrustedProxies         []string              `yaml:"trusted_proxies"`
		BlocklistSources       []string              `yaml:"blocklist_sources"`
		BlocklistDisabled      []string              `yaml:"blocklist_disabled"`
		BlocklistUpdateHours   int                   `yaml:"blocklist_update_hours"`
		Instances              []InstanceConfig      `yaml:"instances"`
		Records                []control.RecordEntry `yaml:"records"`
		HACluster              control.HACluster     `yaml:"high_availability"`
		ReleaseChannel         string                `yaml:"release_channel"`
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
	// F-11: deep-copy everything marshaled after the lock is released.
	// The old code retained the live `overrides` map (and the shared
	// defaultPolicy pointer); a concurrent SetInstanceOverride mutated the
	// same map while yaml.Marshal read it -> concurrent map read/write
	// (panic / lost updates). Copies below own their memory, so saveMu
	// alone serializes writers without holding f.mu across YAML + disk I/O.
	def := clonePolicy(f.defaultPolicy)
	overs := make(map[string]*InstanceOverride, len(f.overrides))
	for id, o := range f.overrides {
		overs[id] = cloneInstanceOverride(o)
	}
	dohAddr := f.dohHTTPAddr
	rateQPS := f.rateLimitQPS
	upServers := append([]upstream.UpstreamServer(nil), f.upstreamServers...)
	upRoutes := append([]upstream.UpstreamRoute(nil), f.upstreamRoutes...)
	upBootstrap := append([]upstream.UpstreamServer(nil), f.upstreamBootstrap...)
	cacheSize := f.cacheSize
	cacheConfigured := f.cacheConfigured
	qlRetention := f.qlRetentionHours
	trusted := append([]string(nil), f.trustedProxies...)
	recs := append([]control.RecordEntry(nil), f.records...)
	ha := f.haCluster
	relChannel := f.releaseChannel
	if !control.ValidUpdateChannel(relChannel) {
		relChannel = string(control.ChannelStable)
	}
	f.mu.RUnlock()
	blSources := f.BlocklistSources()
	autoHours := f.AutoUpdateHours()
	cfg.Instances = instances
	cfg.DefaultPolicy = def
	cfg.InstancePolicies = overs
	cfg.DoHHTTPAddr = dohAddr
	cfg.RateLimitQPS = rateQPS
	upstreamServers, upstreamRoutes := upServers, upRoutes
	cfg.UpstreamServers = upstreamServers
	cfg.UpstreamRoutes = upstreamRoutes
	cfg.UpstreamBootstrap = upBootstrap
	// F-18: only persist cache_size when the operator explicitly configured
	// it (fleet-wide or per-instance); otherwise omit so a fresh load keeps
	// blipd's own default instead of inheriting a misleading zero.
	if cacheConfigured {
		cfg.CacheSize = &cacheSize
	} else {
		cfg.CacheSize = nil
	}
	cfg.QueryLogRetentionHours = qlRetention
	cfg.TrustedProxies = trusted
	cfg.BlocklistSources = blSources
	// ponytail: reset, not append — cfg was unmarshaled from the file on
	// disk, so appending re-added the stored entries on every save and the
	// disabled list grew with duplicates forever.
	cfg.BlocklistDisabled = nil
	f.blMu.Lock()
	for u := range f.blocklistDisabled {
		cfg.BlocklistDisabled = append(cfg.BlocklistDisabled, u)
	}
	f.blMu.Unlock()
	cfg.BlocklistUpdateHours = autoHours
	cfg.Records = recs
	cfg.HACluster = ha
	cfg.ReleaseChannel = relChannel

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	// 0600: config holds admin tokens for every instance, so no group/world
	// access. Atomic write: tmp file in the same directory + 0600 + rename, so
	// a crash mid-write never leaves a truncated config behind.
	dir := filepath.Dir(f.configPath)
	tmp, err := os.CreateTemp(dir, ".blipc-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup; a successful rename removes it anyway.
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return err
	}
	// Flush content to disk before the rename (fsync-ish best-effort).
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, f.configPath); err != nil {
		return err
	}
	// Rename preserves the tmp mode on most filesystems, but re-apply 0600 on
	// the destination best-effort in case the file pre-existed with wider
	// permissions or the umask interfered.
	if err := os.Chmod(f.configPath, 0600); err != nil {
		log.Printf("blipc: warning: chmod config: %v", err)
	}
	return nil
}

// ResolveTokenFile expands "@/path" token references (startup config-file
// loads only). Bare "/" values are treated literally and never read: only an
// explicit "@" prefix opts into file expansion, so a literal token that
// happens to look like a path can never trigger a filesystem read.
//
// Security note: the config file is trusted (it is loaded once at startup and
// controls which instances blipc talks to). If an attacker can tamper with the
// config they already have far greater leverage, so expansion is not treated as
// a privilege boundary. As defense-in-depth, path traversal (`..`) is rejected
// before any file is read. The management API never expands tokens (see
// ResolveTokenFileAllow with allowFile=false); use startup config for secrets.
func ResolveTokenFile(cfg InstanceConfig) InstanceConfig {
	return ResolveTokenFileAllow(cfg, true)
}

// ResolveTokenFileAllow is ResolveTokenFile with an explicit gate: when
// allowFile is false no filesystem read happens and the token is returned
// as-is. The API layer passes false so "@..." / "/..." values submitted over
// HTTP are stored literally (and rejected upfront by the handler).
func ResolveTokenFileAllow(cfg InstanceConfig, allowFile bool) InstanceConfig {
	if !allowFile {
		return cfg
	}
	if len(cfg.Token) < 2 || cfg.Token[0] != '@' {
		return cfg
	}
	p := cfg.Token[1:]
	// Reject path-traversal attempts (e.g. "@/../../etc/shadow").
	if hasTraversal(p) {
		log.Printf("blipc: refusing token path with traversal: %q", cfg.Token)
		return cfg
	}
	if b, err := os.ReadFile(p); err == nil {
		trimmed := strings.TrimSpace(string(b))
		if trimmed == "" {
			// Empty file: keep the original reference so the failure is
			// visible instead of silently adopting with an empty token.
			log.Printf("blipc: token file %q is empty", p)
			return cfg
		}
		cfg.Token = trimmed
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

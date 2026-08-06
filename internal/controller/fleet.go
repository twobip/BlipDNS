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
	"time"

	_ "modernc.org/sqlite"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/control"
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
}

// IsEmpty reports whether the override changes nothing.
func (o *InstanceOverride) IsEmpty() bool {
	return o == nil || (o.Upstream == nil && o.BlockAction == nil && o.Log == nil)
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
	sourceStats      []SourceStat                 // per-source download stats, refreshed on import
	importLog        []string                     // recent import output lines (capped ring buffer)
	autoUpdateHours  int                          // hours between automatic refreshes; 0 = manual only
	configPath       string                       // path to controller config YAML (for persisting tokens)
	defaultPolicy    *control.Policy              // fleet-wide default policy (source of truth)
	overrides        map[string]*InstanceOverride // per-instance partial configs (diff vs default)
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
	queryLog, _ := NewQueryLogStore("/var/lib/blipc/querylog.db")
	blocklistDB, _ := NewBlocklistStore("/var/lib/blipc/blocklist.db")
	return &Fleet{
		instances:   make(map[string]*Instance),
		bus:         NewBus(500),
		http:        &http.Client{Timeout: 10 * time.Second},
		now:         time.Now,
		queryLog:    queryLog,
		blocklistDB: blocklistDB,
		blocklist:   blocklist.New(),
		configPath:  configPath,
		overrides:   make(map[string]*InstanceOverride),
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

// pushConfigs sends each instance's effective config to it and marks its
// applied config hash on success.
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
// per-instance override is saved. Returns a single-entry result map.
func (f *Fleet) pushInstance(ctx context.Context, id string) map[string]string {
	i := f.get(id)
	if i == nil {
		return map[string]string{id: "unknown instance"}
	}
	f.mu.RLock()
	eff, _ := f.effectivePolicy(id)
	f.mu.RUnlock()
	if eff == nil {
		return map[string]string{id: "no config"}
	}
	if !i.hasToken() {
		return map[string]string{id: "not adopted"}
	}
	if err := i.ctl().SetPolicy(ctx, eff); err != nil {
		return map[string]string{id: err.Error()}
	}
	i.markConfigAppliedWith(f.appliedHashFor(id), eff.Upstream)
	return map[string]string{id: "ok"}
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

// LoadBlocklistCache restores the last persisted merged list into RAM at
// startup, so a restart blocks immediately without re-fetching sources, and
// pushes it to instances so they are covered even before a fresh import.
func (f *Fleet) LoadBlocklistCache(ctx context.Context) error {
	if f.blocklistDB == nil {
		return nil
	}
	set, err := f.blocklistDB.LoadSet(ctx)
	if err != nil {
		return err
	}
	if len(set) == 0 {
		return nil
	}
	f.blocklist.FromDomainsMap(set)
	f.blMu.Lock()
	f.blStatus.Domains = f.blocklist.Count()
	f.blMu.Unlock()
	log.Printf("blipc: restored %d blocklist domains from local cache", len(set))
	f.pushBlocklist(ctx)
	return nil
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

	merged := make(map[string]struct{})
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

// pushBlocklist sends the controller's merged blocklist to every instance and
// records the applied checksum on success. An empty list clears the instances.
func (f *Fleet) pushBlocklist(ctx context.Context) map[string]string {
	domains := f.blocklist.List()
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
		if err := i.ctl().SetBlocklist(ctx, domains); err != nil {
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
	hash := f.blocklist.Checksum()
	rep := uint64(0)
	if reported != nil {
		rep = reported.BlocklistHash
	}
	if rep == hash {
		i.markBlocklistApplied(hash)
		return
	}
	if err := i.ctl().SetBlocklist(ctx, f.blocklist.List()); err == nil {
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
		Listen               string                       `yaml:"listen"`
		Username             string                       `yaml:"username"`
		Password             string                       `yaml:"password"`
		DefaultPolicy        *control.Policy              `yaml:"default_policy"`
		InstancePolicies     map[string]*InstanceOverride `yaml:"instance_overrides"`
		BlocklistSources     []string                     `yaml:"blocklist_sources"`
		BlocklistUpdateHours int                          `yaml:"blocklist_update_hours"`
		Instances            []InstanceConfig             `yaml:"instances"`
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
	cfg.BlocklistSources = blSources
	cfg.BlocklistUpdateHours = autoHours

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(f.configPath, out, 0640)
}

// ResolveTokenFile expands token paths like "@/path" or absolute/relative files
// referenced in instance tokens (no-op if token isn't a path).
func ResolveTokenFile(cfg InstanceConfig) InstanceConfig {
	if len(cfg.Token) > 1 && (cfg.Token[0] == '@' || cfg.Token[0] == '/') {
		p := cfg.Token
		if p[0] == '@' {
			p = p[1:]
		}
		if b, err := os.ReadFile(p); err == nil {
			cfg.Token = string(b)
		}
	}
	return cfg
}

// ConfigDir returns the controller config directory hint.
func ConfigDir() string { return filepath.Dir(os.Args[0]) }

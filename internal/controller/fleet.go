// Package controller implements the blipc Unifi-style management controller.
// It connects to one or more blipd instances over their management API,
// aggregates stats/health/block events into a single feed, and exposes a
// token-gated HTTP API plus an embedded web dashboard.
package controller

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

// Event is a fleet-wide event (federated from instances).
type Event struct {
	InstanceID string                 `json:"instance_id"`
	Instance   string                 `json:"instance"` // human label
	Type       string                 `json:"type"`     // stats|block|health|policy|status
	At         time.Time              `json:"at"`
	Health     *control.HealthResponse `json:"health,omitempty"`
	Stats      *control.StatsResponse `json:"stats,omitempty"`
	Client     string                 `json:"client,omitempty"`
	Domain     string                 `json:"domain,omitempty"`
	Msg        string                 `json:"msg,omitempty"`
}

// InstanceConfig is one managed blipd entry (from controller config).
type InstanceConfig struct {
	ID     string `yaml:"id" json:"id"`
	URL    string `yaml:"url" json:"url"`       // http://host:8444
	Token  string `yaml:"token" json:"token"`
	Label  string `yaml:"label" json:"label"`
}

// Fleet holds all instances and the event bus.
type Fleet struct {
	mu        sync.RWMutex
	instances map[string]*Instance
	bus       *Bus
	http      *http.Client
	now       func() time.Time
	logfn     func(Event)
}

// NewFleet creates an empty fleet with a default event buffer.
func NewFleet() *Fleet {
	return &Fleet{
		instances: make(map[string]*Instance),
		bus:       NewBus(500),
		http:      &http.Client{Timeout: 10 * time.Second},
		now:       time.Now,
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
	inst.start(ctx)
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

// ConfigDir returns the controller config directory hint (used for token files).
func ConfigDir() string { return filepath.Dir(os.Args[0]) }

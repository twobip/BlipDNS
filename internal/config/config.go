// Package config loads blipd configuration from YAML with sane defaults.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/twobip/BlipDNS/internal/filter"
	"gopkg.in/yaml.v3"
)

// Config is the blipd YAML configuration.
type Config struct {
	DNSAddr      string        `yaml:"dns_addr"`
	DoHAddr      string        `yaml:"doh_addr"`
	CertFile     string        `yaml:"cert_file"`
	KeyFile      string        `yaml:"key_file"`
	AdminAddr    string        `yaml:"admin_addr"`
	AdminToken   string        `yaml:"admin_token"`
	StateFile    string        `yaml:"state_file"`  // persists "adopted" so the claim code isn't regenerated
	InstanceID   string        `yaml:"instance_id"` // stable id shown to the controller
	Upstream     string        `yaml:"upstream"`
	CacheCap     time.Duration `yaml:"cache_cap"`
	BlocklistURL  string        `yaml:"blocklist_url"` // AdBlock Plus feed URL (optional)
	BlocklistUpdateHours int    `yaml:"blocklist_update_hours"` // refresh interval (0 = no auto-refresh)
	Default       *filter.Policy `yaml:"default_policy"`
	Policies     []*filter.Policy `yaml:"policies"`
}

// Default returns a configuration that works out of the box (listens on
// localhost, forwards to Cloudflare over UDP with DoH failover).
func Default() *Config {
	return &Config{
		DNSAddr:  "127.0.0.1:5353",
		DoHAddr:  "127.0.0.1:8443",
		AdminAddr: "127.0.0.1:8443",
		Upstream: "udp://1.1.1.1:53 https://1.1.1.1/dns-query",
		CacheCap: 1 * time.Hour,
	}
}

// Load reads YAML from path, then applies defaults for any unset field.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}
	if c.CacheCap <= 0 {
		c.CacheCap = time.Hour
	}
	return c, nil
}

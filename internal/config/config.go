// Package config loads blipd configuration from YAML with sane defaults.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/twobip/BlipDNS/internal/upstream"
	"gopkg.in/yaml.v3"
)

// Config is the blipd YAML configuration.
type Config struct {
	DNSAddr              string                    `yaml:"dns_addr"`
	DoHAddr              string                    `yaml:"doh_addr"`
	CertFile             string                    `yaml:"cert_file"`
	KeyFile              string                    `yaml:"key_file"`
	DoHTLS               bool                      `yaml:"doh_tls"`       // serve DoH over HTTPS on DoHAddr (self-signed cert auto-generated when CertFile/KeyFile unset)
	DoHHTTPAddr          string                    `yaml:"doh_http_addr"` // additional plain-HTTP DoH listener ("" = off)
	TLSDir               string                    `yaml:"tls_dir"`       // where a generated self-signed DoH cert/key are persisted
	AdminAddr            string                    `yaml:"admin_addr"`
	AdminToken           string                    `yaml:"admin_token"`
	StateFile            string                    `yaml:"state_file"`  // persists "adopted" so the claim code isn't regenerated
	InstanceID           string                    `yaml:"instance_id"` // stable id shown to the controller
	Upstream             string                    `yaml:"upstream"`
	UpstreamServers      []upstream.UpstreamServer `yaml:"upstream_servers"`       // named upstream pool (priority 0 = route-only)
	UpstreamRoutes       []upstream.UpstreamRoute  `yaml:"upstream_routes"`        // conditional forwarding (qname/client -> server)
	CacheCap             time.Duration             `yaml:"cache_cap"`              // max TTL for cached responses
	CacheSize            int                       `yaml:"cache_size"`             // max cached responses in RAM (0 = unlimited)
	CacheWarmCount       int                       `yaml:"cache_warm_count"`       // most-popular entries kept fresh (0 = off)
	CacheWarmAhead       time.Duration             `yaml:"cache_warm_ahead"`       // refresh popular entries when TTL drops below this
	CacheWarmInterval    time.Duration             `yaml:"cache_warm_interval"`    // how often to check for stale popular entries
	CacheRegular         time.Duration             `yaml:"cache_regular"`          // how long non-most-popular entries stay cached (0 = use record TTL)
	BlocklistURL         string                    `yaml:"blocklist_url"`          // AdBlock Plus feed URL (optional, legacy single)
	BlocklistURLs        []string                  `yaml:"blocklist_urls"`         // one or more ABP/hosts feeds (Pi-hole style)
	BlocklistUpdateHours int                       `yaml:"blocklist_update_hours"` // refresh interval (0 = no auto-refresh)
	BlocklistCacheFile   string                    `yaml:"blocklist_cache_file"`   // persisted snapshot restored into RAM at startup
	Default              *filter.Policy            `yaml:"default_policy"`
	Policies             []*filter.Policy          `yaml:"policies"`
}

// Default returns a configuration that works out of the box (listens on
// localhost, forwards to Cloudflare over UDP with DoH failover).
func Default() *Config {
	return &Config{
		DNSAddr:            "127.0.0.1:5353",
		DoHAddr:            "127.0.0.1:8443",
		DoHTLS:             true,
		TLSDir:             "/var/lib/blipd",
		AdminAddr:          "127.0.0.1:8443",
		Upstream:           "udp://1.1.1.1:53 https://1.1.1.1/dns-query",
		CacheCap:           1 * time.Hour,
		CacheSize:          10000,
		CacheWarmCount:     100,
		CacheWarmAhead:     30 * time.Second,
		CacheWarmInterval:  10 * time.Second,
		BlocklistCacheFile: "/var/lib/blipd/blocklist.cache",
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
	if c.CacheWarmCount != 0 {
		// fill sensible intervals for a warm loop that's actually enabled
		if c.CacheWarmAhead <= 0 {
			c.CacheWarmAhead = 30 * time.Second
		}
		if c.CacheWarmInterval <= 0 {
			c.CacheWarmInterval = 10 * time.Second
		}
	}
	return c, nil
}

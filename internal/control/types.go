// Package control defines the management protocol shared by the blipd
// server (which exposes a management API) and the blipctl controller
// (which connects to managed instances). The controller initiates the
// connection, so blipd just needs to expose a small authenticated API.
package control

import (
	"time"

	"github.com/twobip/BlipDNS/internal/upstream"
)

// Policy mirrors filter.Policy over the wire.
type Policy struct {
	ID          string   `json:"id" yaml:"id"`
	Networks    []string `json:"networks" yaml:"networks"`
	Clients     []string `json:"clients" yaml:"clients"`
	Allow       []string `json:"allow" yaml:"allow"`
	Block       []string `json:"block" yaml:"block"`
	BlockAction string   `json:"block_action" yaml:"block_action"`
	Log         bool     `json:"log" yaml:"log"`
	Upstream    string   `json:"upstream" yaml:"upstream"`
}

// ---- request / response envelopes ----

type HealthResponse struct {
	OK      bool      `json:"ok"`
	Uptime  string    `json:"uptime"`
	Started time.Time `json:"started"`
	Version string    `json:"version"`
	// DroppedEvents counts WatchEvents dropped because a consumer could not
	// keep up. Non-zero is a signal that event delivery is falling behind.
	DroppedEvents int64 `json:"dropped_events"`
}

type StatsResponse struct {
	Cached         int               `json:"cached"`
	QueriesTotal   uint64            `json:"queries_total"`
	BlockedTotal   uint64            `json:"blocked_total"`
	UpstreamErr    uint64            `json:"upstream_errors"`
	PerClient      map[string]uint64 `json:"per_client,omitempty"`
	Upstream       string            `json:"upstream,omitempty"`
	BlocklistCount int               `json:"blocklist_count,omitempty"`
	BlocklistHash  uint64            `json:"blocklist_hash,omitempty"`
	// DohHTTPAddr is the additional plain-HTTP DoH listener address an
	// instance accepts ("" = off). Lets the controller reconcile it.
	DohHTTPAddr string `json:"doh_http_addr,omitempty"`
	// RateLimitQPS is the per-client DNS query rate limit in queries/second
	// applied by this instance (0 = unlimited). Reported so the controller can
	// reconcile it.
	RateLimitQPS int `json:"rate_limit_qps,omitempty"`
	// RateLimited counts queries dropped because they exceeded the per-client
	// rate limit.
	RateLimited uint64 `json:"rate_limited,omitempty"`
	// CacheSize / CacheWarm / CacheRegular expose the instance's runtime cache
	// config so the controller can reconcile it (0 = unlimited / auto-refresh
	// off / use record TTL).
	CacheSize    int `json:"cache_size,omitempty"`
	CacheWarm    int `json:"cache_warm,omitempty"`
	CacheRegular int `json:"cache_regular,omitempty"`
	// UpstreamServers / UpstreamRoutes expose the instance's conditional
	// forwarding configuration so the controller can detect drift.
	UpstreamServers []upstream.UpstreamServer `json:"upstream_servers,omitempty"`
	UpstreamRoutes  []upstream.UpstreamRoute  `json:"upstream_routes,omitempty"`
	// RecordsHash is a checksum of the instance's local DNS records so the
	// controller can detect drift (e.g. after a restart) and re-push them.
	RecordsHash uint64 `json:"records_hash,omitempty"`
}

// ListResponse returns the default (nil ID indicates default) plus all policies.
type ListResponse struct {
	Default  *Policy   `json:"default,omitempty"`
	Policies []*Policy `json:"policies"`
}

type SetPolicyRequest struct {
	Policy Policy `json:"policy"`
}

// SetDoHRequest toggles the optional plain-HTTP DoH listener. An empty
// http_addr disables it.
type SetDoHRequest struct {
	HTTPAddr string `json:"http_addr"`
}

// SetRateLimitRequest sets the per-client DNS query rate limit (QPS). A QPS of
// 0 disables rate limiting. Burst is the maximum burst above QPS; if <= 0 it
// defaults to QPS (min 1).
type SetRateLimitRequest struct {
	QPS   int `json:"qps"`
	Burst int `json:"burst,omitempty"`
}

// SetCacheRequest tunes the instance's response cache. Size is the max cached
// responses in RAM (0 = unlimited); Warm is the number of most-popular entries
// kept at their record TTL and auto-refreshed before expiry (0 = off); Regular
// is how long every other entry stays cached, in seconds (0 = use record TTL).
type SetCacheRequest struct {
	Size    int `json:"size"`
	Warm    int `json:"warm"`
	Regular int `json:"regular"`
}

// PurgeCacheResponse reports how many cached responses were dropped.
type PurgeCacheResponse struct {
	Purged int `json:"purged"`
}

// SetUpstreamRequest replaces the instance's upstream pool and conditional
// forwarding routes. Servers with priority 0 are route-only; an empty request
// reverts the instance to its local (config-file) upstream.
type SetUpstreamRequest struct {
	Servers []upstream.UpstreamServer `json:"servers"`
	Routes  []upstream.UpstreamRoute  `json:"routes"`
}

// domains (already normalized, plain "domain" or "*.root" wildcard entries).
// Allowed lists a whitelist that takes precedence over the blocked domains.
type SetBlocklistRequest struct {
	Domains []string `json:"domains"`
	Allowed []string `json:"allowed,omitempty"`
}

type DeletePolicyRequest struct {
	ID string `json:"id"`
}

type AckResponse struct {
	OK  bool   `json:"ok"`
	Msg string `json:"msg,omitempty"`
}

// Answer is a single resource record returned in a DNS response. Type is the
// textual RR type (e.g. "A", "AAAA", "TXT", "CNAME", "MX"); Data is the rdata
// rendered as it would appear on the wire (minus the owner name), e.g. an IP,
// a quoted TXT string, or "10.0.0.1, preference=10" for MX. TTL is the
// remaining TTL in seconds (0 if unknown).
type Answer struct {
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  int    `json:"ttl,omitempty"`
}

// WatchEvent is streamed by GET /api/v1/watch as SSE.
type WatchEvent struct {
	Type   string         `json:"type"` // "stats" | "block" | "pass" | "error"
	At     time.Time      `json:"at"`
	Stats  *StatsResponse `json:"stats,omitempty"`
	Client string         `json:"client,omitempty"`
	Domain string         `json:"domain,omitempty"`
	// QType is the queried RR type as a textual mnemonic (e.g. "A", "AAAA",
	// "TXT", "MX", "CNAME", "SRV"); derived from the DNS question.
	QType string   `json:"q_type,omitempty"`
	IPs   []string `json:"ips,omitempty"`
	// Answers carries every resource record in the response in display form,
	// so non-address answers (TXT, CNAME, MX, SRV, ...) are preserved instead
	// of collapsing to A/AAAA addresses alone. Omitted when empty.
	Answers []Answer `json:"answers,omitempty"`
	// Msg carries the error detail for type "error".
	Msg string `json:"msg,omitempty"`
	// DurationUs is how long the query took to answer, in microseconds.
	// Cached reports whether the answer was served from the response cache.
	DurationUs int64 `json:"duration_us,omitempty"`
	Cached     bool  `json:"cached,omitempty"`
	// Upstream names the resolver that answered a "pass" event (e.g.
	// "auto (DoH)" or "Local (udp://...)"); "" when unknown or cache-served.
	Upstream string `json:"upstream,omitempty"`
	// BlockList identifies the source of a "block" decision: "global" for the
	// merged blocklist, "policy:<id>" for a per-client policy, or "".
	BlockList string `json:"blocklist,omitempty"`
}

// ---- adoption (claim-code bootstrap) ----

// AdoptStatus reports whether the instance is already adopted.
type AdoptStatus struct {
	Adopted    bool   `json:"adopted"`
	InstanceID string `json:"instance_id"`
	Version    string `json:"version"`
}

// AdoptRequest carries the one-time claim code from a controller.
type AdoptRequest struct {
	Code string `json:"code"`
}

// AdoptResponse returns the real admin token on success so the controller
// never needs the operator to copy/paste it.
type AdoptResponse struct {
	Adopted bool   `json:"adopted"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

// RecordEntry is one static DNS record answered locally by blipd instead of
// being forwarded upstream. Type is the textual RR mnemonic ("A", "AAAA",
// "CNAME"); Value is the rdata (an IP, or a target name for CNAME); TTL is the
// cache lifetime in seconds (0 = server default, 60s).
type RecordEntry struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl,omitempty"`
}

// RecordsResponse is the GET /api/v1/records payload.
type RecordsResponse struct {
	Records []RecordEntry `json:"records"`
}

// SetRecordsRequest replaces a blipd instance's local DNS records. An empty
// records slice clears all local records.
type SetRecordsRequest struct {
	Records []RecordEntry `json:"records"`
}

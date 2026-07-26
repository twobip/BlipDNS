// Package control defines the management protocol shared by the blipd
// server (which exposes a management API) and the blipctl controller
// (which connects to managed instances). The controller initiates the
// connection, so blipd just needs to expose a small authenticated API.
package control

import "time"

// Policy mirrors filter.Policy over the wire.
type Policy struct {
	ID          string   `json:"id" yaml:"id"`
	Networks    []string `json:"networks" yaml:"networks"`
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
}

type StatsResponse struct {
	Cached       int            `json:"cached"`
	QueriesTotal uint64         `json:"queries_total"`
	BlockedTotal uint64         `json:"blocked_total"`
	UpstreamErr  uint64         `json:"upstream_errors"`
	PerClient    map[string]uint64 `json:"per_client,omitempty"`
	Upstream     string         `json:"upstream,omitempty"`
}

// ListResponse returns the default (nil ID indicates default) plus all policies.
type ListResponse struct {
	Default *Policy  `json:"default,omitempty"`
	Policies []*Policy `json:"policies"`
}

type SetPolicyRequest struct {
	Policy Policy `json:"policy"`
}

type DeletePolicyRequest struct {
	ID string `json:"id"`
}

type AckResponse struct {
	OK  bool   `json:"ok"`
	Msg string `json:"msg,omitempty"`
}

// WatchEvent is streamed by GET /api/v1/watch as SSE.
type WatchEvent struct {
	Type   string         `json:"type"` // "stats" | "block" | "health"
	At     time.Time      `json:"at"`
	Stats  *StatsResponse `json:"stats,omitempty"`
	Client string         `json:"client,omitempty"`
	Domain string         `json:"domain,omitempty"`
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

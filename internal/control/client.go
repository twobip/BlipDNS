package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is the controller-side client that connects to a managed blipd
// instance's management API.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// newTransport returns the tuned *http.Transport used by all control clients.
// blipd's management API is cleartext HTTP (the controller connects over
// http://host:8443/8444), so HTTP/2 is not negotiated here — ForceAttemptHTTP2
// would be a no-op on http:// URLs without an h2c upgrade handler on the server.
func newTransport(disableCompression bool) *http.Transport {
	return &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  disableCompression,
	}
}

// NewClient creates a controller client for baseURL (e.g.
// http://host:8444) guarded by token.
func NewClient(baseURL, token string) *Client {
	return &Client{
		base:  baseURL,
		token: token,
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: newTransport(false),
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("control: %s %s -> %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var h HealthResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/health", nil, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (c *Client) Stats(ctx context.Context) (*StatsResponse, error) {
	var s StatsResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/stats?per_client=0", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) ListPolicies(ctx context.Context) (*ListResponse, error) {
	var l ListResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/policies", nil, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

func (c *Client) SetPolicy(ctx context.Context, p *Policy) error {
	req := SetPolicyRequest{Policy: *p}
	return c.do(ctx, http.MethodPut, "/api/v1/policy", &req, nil)
}

// SetBlocklist replaces the instance's global blocklist and its whitelist.
// Large lists (e.g. oisd.big, ~2M domains) produce payloads of tens of MB, so
// this uses a much longer timeout than the default client.
func (c *Client) SetBlocklist(ctx context.Context, domains, allowed []string) error {
	req := SetBlocklistRequest{Domains: domains, Allowed: allowed}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+"/api/v1/blocklist", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	httpReq.Header.Set("Content-Type", "application/json")

	slow := &http.Client{
		Timeout:   10 * time.Minute,
		Transport: newTransport(true), // blocklist payloads are already large; no point negotiating gzip
	}
	resp, err := slow.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("control: set blocklist -> %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/policy?id="+id, nil, nil)
}

// SetDoHHTTPAddr toggles the instance's optional plain-HTTP DoH listener. An
// empty addr disables the listener; a non-empty host:port starts it.
func (c *Client) SetDoHHTTPAddr(ctx context.Context, addr string) error {
	return c.do(ctx, http.MethodPut, "/api/v1/doh", &SetDoHRequest{HTTPAddr: addr}, nil)
}

// SetRateLimit configures the instance's per-client DNS rate limit (QPS). A qps
// of 0 disables rate limiting.
func (c *Client) SetRateLimit(ctx context.Context, qps, burst int) error {
	return c.do(ctx, http.MethodPut, "/api/v1/ratelimit", &SetRateLimitRequest{QPS: qps, Burst: burst}, nil)
}

// SetCacheConfig tunes the instance's response cache: size is the max cached
// responses (0 = unlimited), warm the auto-refresh count (0 = off), and regular
// how long non-most-popular entries stay cached in seconds (0 = use record TTL).
func (c *Client) SetCacheConfig(ctx context.Context, size, warm, regular int) error {
	return c.do(ctx, http.MethodPut, "/api/v1/cache", &SetCacheRequest{Size: size, Warm: warm, Regular: regular}, nil)
}

// PurgeCache drops every cached response on the instance and returns how many
// entries were removed.
func (c *Client) PurgeCache(ctx context.Context) (int, error) {
	var out PurgeCacheResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/cache/purge", nil, &out); err != nil {
		return 0, err
	}
	return out.Purged, nil
}

// AdoptStatus fetches the instance's adoption state (unauthenticated).
func (c *Client) AdoptStatus(ctx context.Context) (*AdoptStatus, error) {
	var st AdoptStatus
	if err := c.do(ctx, http.MethodGet, "/api/v1/adopt/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Adopt presents a one-time claim code; on success it returns the real admin
// token so the controller can store it and never need manual copy/paste.
func (c *Client) Adopt(ctx context.Context, code string) (*AdoptResponse, error) {
	var resp AdoptResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/adopt", &AdoptRequest{Code: code}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ResetAdoption resets the instance's adoption handshake (requires the
// instance's current admin token).
func (c *Client) ResetAdoption(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/adopt/reset", nil, nil)
}

// GetRecords returns the instance's current local DNS records.
func (c *Client) GetRecords(ctx context.Context) ([]RecordEntry, error) {
	var out RecordsResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/records", nil, &out); err != nil {
		return nil, err
	}
	return out.Records, nil
}

// SetRecords replaces the instance's local DNS records. An empty slice clears
// all local records.
func (c *Client) SetRecords(ctx context.Context, records []RecordEntry) error {
	return c.do(ctx, http.MethodPut, "/api/v1/records", &SetRecordsRequest{Records: records}, nil)
}

// ClearRecords removes all local DNS records from the instance.
func (c *Client) ClearRecords(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/records", nil, nil)
}

// HAStatus returns the local keepalived/VRRP status.
func (c *Client) HAStatus(ctx context.Context) (*HAStatus, error) {
	var out HAStatus
	if err := c.do(ctx, http.MethodGet, "/api/v1/ha/status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetHAConfig writes the structured keepalived configuration without enabling
// the service.
func (c *Client) SetHAConfig(ctx context.Context, cfg HAConfig) error {
	return c.do(ctx, http.MethodPut, "/api/v1/ha", &cfg, nil)
}

func (c *Client) InstallHA(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/ha/install", nil, nil)
}

func (c *Client) ValidateHA(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/ha/validate", nil, nil)
}

func (c *Client) ApplyHA(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/ha/apply", nil, nil)
}

func (c *Client) DisableHA(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/ha/disable", nil, nil)
}

// Restart asks the node to restart its blipd service (root helper via sudo).
func (c *Client) Restart(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/restart", nil, nil)
}

// StartUpdate starts the managed node's asynchronous self-update.
func (c *Client) StartUpdate(ctx context.Context, channel string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/update?channel="+url.QueryEscape(channel), nil, nil)
}

// UpdateStatus returns the managed node's current update state.
func (c *Client) UpdateStatus(ctx context.Context) (*UpdateStatus, error) {
	var out UpdateStatus
	if err := c.do(ctx, http.MethodGet, "/api/v1/update", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Watch opens the SSE stream and invokes fn for each event until ctx is
// cancelled. It deliberately uses a client without an overall timeout: the
// stream is long-lived and an absolute deadline would kill it (and silently
// lose events) every few seconds. Cancellation is handled via ctx; blipd
// sends periodic stats keepalives to keep the connection healthy.
func (c *Client) Watch(ctx context.Context, fn func(WatchEvent)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/v1/watch", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := (&http.Client{
		Transport: newTransport(false),
	}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("control: watch -> %d: %s", resp.StatusCode, string(b))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 6 || line[:5] != "data:" {
			continue
		}
		var e WatchEvent
		if err := json.Unmarshal([]byte(line[5:]), &e); err != nil {
			continue
		}
		fn(e)
	}
	return sc.Err()
}

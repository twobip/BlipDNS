package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the controller-side client that connects to a managed blipd
// instance's management API.
type Client struct {
	base   string
	token  string
	http   *http.Client
}

// NewClient creates a controller client for baseURL (e.g.
// http://host:8443) guarded by token.
func NewClient(baseURL, token string) *Client {
	return &Client{
		base:  baseURL,
		token: token,
		http:  &http.Client{Timeout: 10 * time.Second},
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
	if err := c.do(ctx, http.MethodGet, "/api/v1/stats", nil, &s); err != nil {
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

	slow := &http.Client{Timeout: 10 * time.Minute}
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

// Watch opens the SSE stream and invokes fn for each event until ctx is
// cancelled.
func (c *Client) Watch(ctx context.Context, fn func(WatchEvent)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/v1/watch", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
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

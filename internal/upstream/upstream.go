// Package upstream resolves DNS queries against upstream resolvers.
// It supports DNS-over-HTTPS (RFC 8484) and classic UDP/TCP, with a
// failover wrapper that tries several resolvers in order.
package upstream

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// Resolver resolves a DNS query message and returns the response.
type Resolver interface {
	Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// UDPResolver forwards over UDP (falling back to TCP on truncation).
type UDPResolver struct {
	addr    string
	timeout time.Duration
}

// NewUDP creates a UDP/TCP upstream resolver for addr (host:port).
func NewUDP(addr string) *UDPResolver {
	return &UDPResolver{addr: addr, timeout: 5 * time.Second}
}

func (r *UDPResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: r.timeout}
	resp, _, err := c.Exchange(q, r.addr)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.Exchange(q, r.addr)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// DoHResolver forwards over DNS-over-HTTPS (RFC 8484).
type DoHResolver struct {
	endpoint string
	client   *http.Client
}

// NewDoH creates a DoH upstream resolver for endpoint (e.g.
// https://1.1.1.1/dns-query). The client reuses HTTP/2 connections.
func NewDoH(endpoint string) *DoHResolver {
	return &DoHResolver{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (r *DoHResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	buf, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: upstream returned %d", resp.StatusCode)
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh: unpack response: %w", err)
	}
	return out, nil
}

// MultiResolver tries each resolver in order until one succeeds.
type MultiResolver struct {
	resolvers []Resolver
}

// NewMulti wraps resolvers with failover semantics.
func NewMulti(resolvers ...Resolver) *MultiResolver {
	return &MultiResolver{resolvers: resolvers}
}

func (m *MultiResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, r := range m.resolvers {
		resp, err := r.Resolve(ctx, q)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("upstream: no resolvers configured")
	}
	return nil, lastErr
}

// FromSpec builds a Resolver from a URL-style spec:
//   - "udp://host:port"  -> UDPResolver
//   - "https://host/dns-query" or "doh://host/dns-query" -> DoHResolver
// Multiple specs joined by space or comma form a MultiResolver with failover.
func FromSpec(spec string) (Resolver, error) {
	var rs []Resolver
	for _, s := range splitSpec(spec) {
		switch {
		case len(s) >= 6 && s[:6] == "udp://":
			rs = append(rs, NewUDP(s[6:]))
		case len(s) >= 6 && s[:6] == "doh://":
			rs = append(rs, NewDoH("https://"+s[6:]))
		case len(s) >= 8 && s[:8] == "https://":
			rs = append(rs, NewDoH(s))
		default:
			return nil, fmt.Errorf("upstream: unrecognized spec %q", s)
		}
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("upstream: empty spec")
	}
	if len(rs) == 1 {
		return rs[0], nil
	}
	return NewMulti(rs...), nil
}

func splitSpec(spec string) []string {
	var out []string
	cur := ""
	flush := func() {
		if cur != "" {
			out = append(out, cur)
			cur = ""
		}
	}
	for _, r := range spec {
		if r == ' ' || r == ',' || r == '\n' || r == '\t' {
			flush()
			continue
		}
		cur += string(r)
	}
	flush()
	return out
}

// LookupIP is a convenience helper that resolves A/AAAA for host using r.
func LookupIP(ctx context.Context, r Resolver, host string) ([]net.IP, error) {
	var ips []net.IP
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(host), t)
		resp, err := r.Resolve(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A)
			case *dns.AAAA:
				ips = append(ips, v.AAAA)
			}
		}
	}
	return ips, nil
}

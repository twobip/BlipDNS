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
	"sort"
	"strconv"
	"strings"
	"sync"
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
		return nil, errUpstream(r.addr, err)
	}
	if resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.Exchange(q, r.addr)
		if err != nil {
			return nil, errUpstream(r.addr, err)
		}
	}
	return resp, nil
}

// errUpstream labels a network failure with the upstream address and strips
// the ephemeral local socket that Go embeds in the message ("read udp
// 127.0.0.1:50791->127.0.0.1:1: ..."), so the same failure always produces
// the same string and can be grouped on the errors page.
func errUpstream(addr string, err error) error {
	msg := err.Error()
	for _, p := range []string{"read udp ", "write udp ", "read tcp ", "write tcp ", "dial udp ", "dial tcp "} {
		if i := strings.Index(msg, "->"); strings.HasPrefix(msg, p) && i >= 0 {
			// The remainder already carries the remote (upstream) address.
			return fmt.Errorf("%s", msg[i+2:])
		}
	}
	return fmt.Errorf("%s: %s", addr, msg)
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

// MultiResolver tries each resolver in priority order until one succeeds and
// remembers which resolvers are currently failing so a down upstream is
// skipped for a short cooldown instead of stalling every request.
type MultiResolver struct {
	resolvers []Resolver
	mu        sync.Mutex
	downUntil []time.Time
	cooldown  time.Duration
}

// NewMulti wraps resolvers with failover semantics. Resolvers are tried in
// the order given; the caller is expected to order them by priority.
func NewMulti(resolvers ...Resolver) *MultiResolver {
	return &MultiResolver{
		resolvers: resolvers,
		downUntil: make([]time.Time, len(resolvers)),
		cooldown:  15 * time.Second,
	}
}

func (m *MultiResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m.mu.Lock()
	now := time.Now()
	var order []int
	allDown := true
	for i := range m.resolvers {
		if !m.downUntil[i].After(now) {
			order = append(order, i)
			allDown = false
		}
	}
	if allDown { // everything tripped: retry all in order this pass
		order = make([]int, len(m.resolvers))
		for i := range order {
			order[i] = i
		}
		m.downUntil = make([]time.Time, len(m.resolvers))
	}
	m.mu.Unlock()

	var lastErr error
	for _, i := range order {
		resp, err := m.resolvers[i].Resolve(ctx, q)
		if err == nil {
			m.mu.Lock()
			m.downUntil[i] = time.Time{}
			m.mu.Unlock()
			return resp, nil
		}
		lastErr = err
		m.mu.Lock()
		m.downUntil[i] = now.Add(m.cooldown)
		m.mu.Unlock()
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("upstream: no resolvers configured")
	}
	return nil, lastErr
}

// Spec describes a single upstream entry parsed from a spec string.
type Spec struct {
	Type     string // "udp" or "doh"
	Address  string // host:port (udp) or host/path (doh), scheme stripped
	Priority int    // lower = higher priority (tried first)
}

// ParseSpec splits a spec string into individual entries, sorted by priority.
// Each token is a URL-style spec ("udp://host:port", "https://host/path" or
// "doh://host/path") with an optional "|priority" suffix, e.g.
// "udp://1.1.1.1:53|1". Tokens without a priority keep their position
// (1-based) as priority, so plain space-separated lists still fail over
// left to right.
func ParseSpec(spec string) ([]Spec, error) {
	tokens := splitSpec(spec)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("upstream: empty spec")
	}
	out := make([]Spec, len(tokens))
	for i, tok := range tokens {
		raw, prio := splitPriority(tok)
		if prio <= 0 {
			prio = i + 1
		}
		var s Spec
		switch {
		case strings.HasPrefix(raw, "udp://"):
			s = Spec{Type: "udp", Address: ensurePort(raw[len("udp://"):]), Priority: prio}
		case strings.HasPrefix(raw, "doh://"):
			s = Spec{Type: "doh", Address: raw[len("doh://"):], Priority: prio}
		case strings.HasPrefix(raw, "https://"):
			s = Spec{Type: "doh", Address: raw[len("https://"):], Priority: prio}
		default:
			return nil, fmt.Errorf("upstream: unrecognized spec %q", tok)
		}
		out[i] = s
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}

// ensurePort appends ":53" to a UDP host when no port is present, so
// "udp://192.168.30.221" resolves to 192.168.30.221:53 instead of failing to
// dial. IPv6 hosts are bracketed correctly.
func ensurePort(addr string) string {
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	host := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	return net.JoinHostPort(host, "53")
}

// splitPriority separates an optional "|N" priority suffix from a spec token.
func splitPriority(tok string) (string, int) {
	if i := strings.LastIndex(tok, "|"); i > 0 {
		if p, err := strconv.Atoi(tok[i+1:]); err == nil {
			return tok[:i], p
		}
	}
	return tok, 0
}

// FromSpec builds a Resolver from a URL-style spec string:
//   - "udp://host:port"  -> UDPResolver
//   - "https://host/dns-query" or "doh://host/dns-query" -> DoHResolver
//   - an optional "|priority" suffix sets failover order
//
// Multiple specs joined by space or comma form a MultiResolver that is tried
// in priority order (lowest number first) with failover.
func FromSpec(spec string) (Resolver, error) {
	specs, err := ParseSpec(spec)
	if err != nil {
		return nil, err
	}
	rs := make([]Resolver, len(specs))
	for i, s := range specs {
		switch s.Type {
		case "udp":
			rs[i] = NewUDP(s.Address)
		case "doh":
			rs[i] = NewDoH("https://" + s.Address)
		}
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

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
	"sync/atomic"
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
	udp     dns.Client // pre-built; reused across queries (no per-query alloc)
	tcp     dns.Client
}

// NewUDP creates a UDP/TCP upstream resolver for addr (host:port) with the
// given timeout (0 = 5 second default).
func NewUDP(addr string, timeout time.Duration) *UDPResolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &UDPResolver{
		addr:    addr,
		timeout: timeout,
		udp:     dns.Client{Net: "udp", Timeout: timeout},
		tcp:     dns.Client{Net: "tcp", Timeout: timeout},
	}
}

func (r *UDPResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	resp, _, err := r.udp.Exchange(q, r.addr)
	if err != nil {
		return nil, errUpstream(r.addr, err)
	}
	if resp.Truncated {
		resp, _, err = r.tcp.Exchange(q, r.addr)
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
	endpoint  string
	client    *http.Client
	bootstrap Resolver
}

// NewDoH creates a DoH upstream resolver for endpoint (e.g.
// https://1.1.1.1/dns-query) with the given timeout (0 = 5 second default).
// The client reuses HTTP/2 connections.
func NewDoH(endpoint string, timeout time.Duration) *DoHResolver {
	return NewDoHWithBootstrap(endpoint, timeout, nil)
}

// NewDoHWithBootstrap creates a DoH upstream resolver like NewDoH, but resolves
// the endpoint's hostname through the bootstrap resolver before dialing instead
// of the system resolver. This lets a DoH server configured by hostname (e.g.
// https://dns.google/dns-query) be reached even when /etc/resolv.conf is
// unusable. Bootstrap resolvers themselves are dialed via the system resolver —
// there is no chicken-and-egg — so a bootstrap endpoint should normally be a
// literal IP such as https://1.1.1.1/dns-query. A nil bootstrap uses the
// system resolver (historical behavior).
func NewDoHWithBootstrap(endpoint string, timeout time.Duration, bootstrap Resolver) *DoHResolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tr := &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	if bootstrap != nil {
		tr.DialContext = bootstrapDialContext(bootstrap, timeout)
	}
	return &DoHResolver{
		endpoint:  endpoint,
		client:    &http.Client{Timeout: timeout, Transport: tr},
		bootstrap: bootstrap,
	}
}

// bootstrapDialContext returns a DialContext that resolves the address
// hostname through the bootstrap resolver and dials the first reachable
// address, keeping the port. TLS is handled by the transport after this dial,
// so the DoH certificate is still verified against the endpoint hostname.
func bootstrapDialContext(bootstrap Resolver, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return d.DialContext(ctx, network, addr)
		}
		ips := bootstrapLookupIP(ctx, bootstrap, host)
		if len(ips) == 0 {
			return nil, fmt.Errorf("bootstrap resolve %q: no addresses", host)
		}
		var lastErr error
		for _, ip := range ips {
			c, derr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if derr == nil {
				return c, nil
			}
			lastErr = derr
		}
		return nil, lastErr
	}
}

// bootstrapLookupIP resolves A and AAAA for host through r, tolerating a
// resolver that only answers one family (a failed AAAA query is not fatal when
// the A query succeeded, and vice-versa).
func bootstrapLookupIP(ctx context.Context, r Resolver, host string) []net.IP {
	var ips []net.IP
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(host), t)
		resp, err := r.Resolve(ctx, q)
		if err != nil {
			continue
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
	return ips
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
		return nil, err // url.Error already embeds the endpoint URL
	}
	defer resp.Body.Close()
	const maxDNSResponseBytes = 65535
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSResponseBytes+1))
	if err != nil {
		return nil, errUpstream(r.endpoint, err)
	}
	if len(body) > maxDNSResponseBytes {
		return nil, errUpstream(r.endpoint, fmt.Errorf("doh: upstream response too large"))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errUpstream(r.endpoint, fmt.Errorf("doh: upstream returned %d", resp.StatusCode))
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, errUpstream(r.endpoint, fmt.Errorf("doh: unpack response: %w", err))
	}
	return out, nil
}

// MultiResolver tries each resolver in priority order until one succeeds and
// remembers which resolvers are currently failing so a down upstream is
// skipped for a short cooldown instead of stalling every request.
//
// downUntil holds unix-nanos per resolver, accessed atomically: the hot path
// (all resolvers healthy) never takes a lock, it only loads the cooldown
// stamps. The mutex guards only the rare all-down reset.
type MultiResolver struct {
	resolvers []Resolver
	mu        sync.Mutex
	downUntil []int64 // unix nanos; 0 = up
	cooldown  time.Duration
}

// NewMulti wraps resolvers with failover semantics. Resolvers are tried in
// the order given; the caller is expected to order them by priority.
func NewMulti(resolvers ...Resolver) *MultiResolver {
	return &MultiResolver{
		resolvers: resolvers,
		downUntil: make([]int64, len(resolvers)),
		cooldown:  15 * time.Second,
	}
}

func (m *MultiResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	now := time.Now().UnixNano()
	var order []int
	allDown := true
	for i := range m.resolvers {
		if atomic.LoadInt64(&m.downUntil[i]) <= now {
			order = append(order, i)
			allDown = false
		}
	}
	if allDown { // everything tripped: retry all in order this pass
		m.mu.Lock()
		m.downUntil = make([]int64, len(m.resolvers))
		m.mu.Unlock()
		order = make([]int, len(m.resolvers))
		for i := range order {
			order[i] = i
		}
	}

	var lastErr error
	for _, i := range order {
		resp, err := m.resolvers[i].Resolve(ctx, q)
		if err == nil {
			atomic.StoreInt64(&m.downUntil[i], 0)
			return resp, nil
		}
		lastErr = err
		atomic.StoreInt64(&m.downUntil[i], now+m.cooldown.Nanoseconds())
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
// left to right. A token with no scheme is assumed to be UDP when it is a
// plain IP ("192.168.30.221") or a host:port pair ("9.9.9.9:53"), with a
// missing port defaulting to 53.
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
			if isBareUDP(raw) {
				s = Spec{Type: "udp", Address: ensurePort(raw), Priority: prio}
				break
			}
			return nil, fmt.Errorf("upstream: unrecognized spec %q", tok)
		}
		out[i] = s
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}

// isBareUDP reports whether an un-schemed spec token is unambiguous as a UDP
// endpoint: a plain IP (IPv4 or bracketed IPv6) or a host:port pair with a
// numeric port. Bare hostnames are deliberately left unrecognized because they
// could equally mean UDP or DoH, and a non-numeric port (e.g. "wibble://x") is
// not a valid endpoint.
func isBareUDP(tok string) bool {
	host, port, err := net.SplitHostPort(tok)
	if err == nil {
		if _, perr := strconv.Atoi(port); perr != nil {
			return false
		}
		return host != ""
	}
	ip := strings.TrimSuffix(strings.TrimPrefix(tok, "["), "]")
	return net.ParseIP(ip) != nil
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
			rs[i] = NewUDP(s.Address, 0)
		case "doh":
			rs[i] = NewDoH("https://"+s.Address, 0)
		}
	}
	if len(rs) == 1 {
		return rs[0], nil
	}
	return NewMulti(rs...), nil
}

func splitSpec(spec string) []string {
	return strings.FieldsFunc(spec, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\n' || r == '	'
	})
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

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

// UDPResolver forwards over UDP (falling back to TCP on truncation) with a
// small pool of connected sockets reused across queries. miekg/dns Exchange
// dials + closes per call; reusing connected conns via ExchangeWithConnContext
// removes a socket+connect+close per DNS query and honors ctx cancellation.
type UDPResolver struct {
	addr    string
	timeout time.Duration
	udp     dns.Client // pre-built; reused across queries (no per-query alloc)
	tcp     dns.Client
	mu      sync.Mutex
	conns   []*dns.Conn // idle connected UDP conns, LIFO
}

// udpPoolSize bounds reused sockets per upstream (LIFO stack, no channel).
const udpPoolSize = 4

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

func (r *UDPResolver) getConn(ctx context.Context) (*dns.Conn, error) {
	r.mu.Lock()
	n := len(r.conns)
	if n > 0 {
		c := r.conns[n-1]
		r.conns = r.conns[:n-1]
		r.mu.Unlock()
		return c, nil
	}
	r.mu.Unlock()
	// Dial outside the lock so concurrent queries dial in parallel.
	d := &net.Dialer{Timeout: r.timeout}
	// Prefer ctx deadline when tighter than the per-server timeout.
	conn, err := d.DialContext(ctx, "udp", r.addr)
	if err != nil {
		return nil, err
	}
	return &dns.Conn{Conn: conn}, nil
}

func (r *UDPResolver) putConn(c *dns.Conn) {
	if c == nil || c.Conn == nil {
		return
	}
	r.mu.Lock()
	if len(r.conns) < udpPoolSize {
		r.conns = append(r.conns, c)
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	_ = c.Close()
}

// CloseIdleConnections drains pooled UDP sockets.
func (r *UDPResolver) CloseIdleConnections() {
	r.mu.Lock()
	conns := r.conns
	r.conns = nil
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (r *UDPResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	// Bound by ctx when the caller set one (pool budget), else the per-server
	// timeout. ExchangeWithConnContext honors the deadline; the old Exchange
	// used Background and ignored ctx entirely.
	c, err := r.getConn(ctx)
	if err != nil {
		return nil, errUpstream(r.addr, err)
	}
	resp, _, err := r.udp.ExchangeWithConnContext(ctx, q, c)
	if err != nil {
		_ = c.Close()
		return nil, errUpstream(r.addr, err)
	}
	if !resp.Truncated {
		r.putConn(c)
		return resp, nil
	}
	// Truncated: return the UDP conn and fall back to TCP (rare path keeps a
	// per-query dial to avoid a second pool).
	r.putConn(c)
	resp2, _, err := r.tcp.ExchangeContext(ctx, q, r.addr)
	if err != nil {
		return nil, errUpstream(r.addr, err)
	}
	return resp2, nil
}

// TLSResolver forwards over DNS-over-TLS (RFC 7858, port 853) on a small pool
// of shared connections, redialed when the server closes them. The old single
// conn + single mutex capped throughput at 1/RTT; pooling K conns lets K
// queries proceed concurrently.
type TLSResolver struct {
	addr  string
	tls   dns.Client // pre-built; reused across queries (no per-query alloc)
	mu    sync.Mutex
	conns []*dns.Conn // idle TLS conns, LIFO
}

// tlsPoolSize bounds concurrent DoT connections per upstream.
const tlsPoolSize = 4

// NewTLS creates a DoT upstream resolver for addr (host:port) with the given
// timeout (0 = 5 second default). TLS is verified against the system roots.
func NewTLS(addr string, timeout time.Duration) *TLSResolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &TLSResolver{
		addr: addr,
		tls:  dns.Client{Net: "tcp-tls", Timeout: timeout},
	}
}

func (r *TLSResolver) getConn(ctx context.Context) (*dns.Conn, error) {
	r.mu.Lock()
	n := len(r.conns)
	if n > 0 {
		c := r.conns[n-1]
		r.conns = r.conns[:n-1]
		r.mu.Unlock()
		return c, nil
	}
	r.mu.Unlock()
	// DialContext honors ctx (pool budget) and falls back to Client.Timeout
	// when ctx has no deadline; old Dial ignored ctx entirely.
	c, err := r.tls.DialContext(ctx, r.addr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (r *TLSResolver) putConn(c *dns.Conn) {
	if c == nil {
		return
	}
	r.mu.Lock()
	if len(r.conns) < tlsPoolSize {
		r.conns = append(r.conns, c)
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	_ = c.Close()
}

// dropIdle closes all pooled idle connections (test hook for simulating a
// server-closed idle conn, plus pool teardown).
func (r *TLSResolver) dropIdle() {
	r.CloseIdleConnections()
}

// CloseIdleConnections drains pooled DoT connections.
func (r *TLSResolver) CloseIdleConnections() {
	r.mu.Lock()
	conns := r.conns
	r.conns = nil
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (r *TLSResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	// A server-closed idle connection only fails the exchange, never the
	// dial — so drop a dead connection and redial once before giving up.
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		var c *dns.Conn
		if c, err = r.getConn(ctx); err != nil {
			return nil, errUpstream(r.addr, err)
		}
		var resp *dns.Msg
		if resp, _, err = r.tls.ExchangeWithConnContext(ctx, q, c); err == nil {
			r.putConn(c)
			return resp, nil
		}
		_ = c.Close()
	}
	return nil, errUpstream(r.addr, err)
}

// upErr labels an upstream failure with its endpoint and gives it a stable
// message: the ephemeral local socket Go embeds in transport errors ("read
// udp 127.0.0.1:50791->127.0.0.1:1: ...") is stripped so identical failures
// group on the errors page, while the original error stays reachable through
// Unwrap so callers can still classify it (timeouts, resets) with errors.Is
// and errors.As.
type upErr struct {
	addr string
	err  error
}

func (e *upErr) Error() string {
	msg := e.err.Error()
	if cleaned, ok := stripLocalSocket(msg); ok {
		return cleaned
	}
	// No local socket to strip: keep the message as-is (it may already name
	// the endpoint, e.g. a dial error or a *url.Error), only prepend the
	// endpoint label when it is missing.
	if e.addr == "" || strings.Contains(msg, e.addr) {
		return msg
	}
	return e.addr + ": " + msg
}

func (e *upErr) Unwrap() error { return e.err }

// stripLocalSocket removes Go's "op net LOCAL->REMOTE: " address prefix from a
// transport error message, wherever it appears — bare, or wrapped in a
// *url.Error whose text reads `Post "https://…": read tcp …`. Text before the
// socket phrase (the request line) and the remote address after the arrow are
// kept; only the ephemeral local port is dropped.
func stripLocalSocket(msg string) (string, bool) {
	arrow := strings.Index(msg, "->")
	if arrow < 0 {
		return msg, false
	}
	for _, p := range []string{"read udp ", "write udp ", "read tcp ", "write tcp ", "dial udp ", "dial tcp "} {
		if i := strings.LastIndex(msg[:arrow], p); i >= 0 {
			return msg[:i] + msg[arrow+2:], true
		}
	}
	return msg, false
}

func errUpstream(addr string, err error) error {
	return &upErr{addr: addr, err: err}
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
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   minDuration(timeout, 10*time.Second),
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if bootstrap != nil {
		tr.DialContext = bootstrapDialContext(bootstrap, timeout)
	}
	return &DoHResolver{
		endpoint: endpoint,
		client: &http.Client{
			Timeout:   timeout,
			Transport: tr,
			// Never follow a redirect: it would move the query to a host the
			// operator never configured, and Go follows https->http. The
			// configured endpoint must be the one that answers.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		bootstrap: bootstrap,
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// CloseIdleConnections closes idle DoH keepalives so a replaced pool doesn't
// leak Transports until the 90s idle timeout.
func (r *DoHResolver) CloseIdleConnections() {
	if tr, ok := r.client.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// bootstrapDialContext returns a DialContext that resolves the address
// hostname through the bootstrap resolver and dials the first reachable
// address, keeping the port. TLS is handled by the transport after this dial,
// so the DoH certificate is still verified against the endpoint hostname.
func bootstrapDialContext(bootstrap Resolver, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			if blockedUpstreamIP(net.ParseIP(host)) {
				return nil, fmt.Errorf("refusing link-local/metadata upstream address %s", host)
			}
			return d.DialContext(ctx, network, addr)
		}
		ips := bootstrapLookupIP(ctx, bootstrap, host)
		if len(ips) == 0 {
			return nil, fmt.Errorf("bootstrap resolve %q: no addresses", host)
		}
		// Race dials across returned IPs with a shared deadline (Happy
		// Eyeballs-lite) instead of trying them serially with full timeouts.
		type dialRes struct {
			c   net.Conn
			err error
		}
		ch := make(chan dialRes, len(ips))
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		for _, ip := range ips {
			if blockedUpstreamIP(ip) {
				ch <- dialRes{err: fmt.Errorf("refusing link-local/metadata upstream address %s", ip)}
				continue
			}
			go func(ip net.IP) {
				c, derr := d.DialContext(dialCtx, network, net.JoinHostPort(ip.String(), port))
				ch <- dialRes{c: c, err: derr}
			}(ip)
		}
		var lastErr error
		for range ips {
			r := <-ch
			if r.err == nil {
				return r.c, nil
			}
			lastErr = r.err
		}
		return nil, lastErr
	}
}

// blockedUpstreamIP reports whether ip must never be dialled as an upstream:
// link-local (169.254.0.0/16 and fe80::/10, where cloud metadata services
// live) and the unspecified address. Loopback and RFC1918 stay allowed — a
// resolver legitimately forwards to a LAN or local upstream; the guard exists
// to stop the control plane, a policy override or a DNS answer from aiming
// blipd at the metadata service.
// ponytail: spec-time check rejects literal IPs, dial-time check covers
// resolved hostnames; an RFC1918 target stays allowed on purpose.
func blockedUpstreamIP(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// bootstrapCache caches bootstrap host->IPs with TTL to avoid paying 2
// bootstrap RTTs on every fresh DoH connection (and again after each 90s idle
// expiry). Bounded, single-mutex, TTL floor 60s / cap 10m.
var bootstrapCache = struct {
	sync.Mutex
	m map[string]bootstrapEntry
}{m: make(map[string]bootstrapEntry)}

type bootstrapEntry struct {
	ips    []net.IP
	expire time.Time
}

func bootstrapCacheGet(host string) ([]net.IP, bool) {
	bootstrapCache.Lock()
	defer bootstrapCache.Unlock()
	e, ok := bootstrapCache.m[host]
	if !ok || time.Now().After(e.expire) {
		if ok {
			delete(bootstrapCache.m, host)
		}
		return nil, false
	}
	out := make([]net.IP, len(e.ips))
	copy(out, e.ips)
	return out, true
}

func bootstrapCachePut(host string, ips []net.IP, ttl time.Duration) {
	if len(ips) == 0 {
		return
	}
	if ttl < 60*time.Second {
		ttl = 60 * time.Second
	}
	if ttl > 10*time.Minute {
		ttl = 10 * time.Minute
	}
	bootstrapCache.Lock()
	defer bootstrapCache.Unlock()
	if len(bootstrapCache.m) > 1024 {
		// Probabilistic eviction to bound memory.
		for k := range bootstrapCache.m {
			delete(bootstrapCache.m, k)
			break
		}
	}
	cp := make([]net.IP, len(ips))
	copy(cp, ips)
	bootstrapCache.m[host] = bootstrapEntry{ips: cp, expire: time.Now().Add(ttl)}
}

// clearBootstrapCache drops cached bootstrap resolutions (test isolation:
// TestDoHBootstrapResolve asserts the stub is consulted).
func clearBootstrapCache() {
	bootstrapCache.Lock()
	defer bootstrapCache.Unlock()
	bootstrapCache.m = make(map[string]bootstrapEntry)
}

// bootstrapLookupIP resolves A and AAAA for host through r, tolerating a
// resolver that only answers one family (a failed AAAA query is not fatal when
// the A query succeeded, and vice-versa). A+AAAA issue concurrently; results
// share the caller's ctx budget.
func bootstrapLookupIP(ctx context.Context, r Resolver, host string) []net.IP {
	if ips, ok := bootstrapCacheGet(host); ok {
		return ips
	}
	type famRes struct {
		ips []net.IP
		ttl time.Duration
	}
	ch := make(chan famRes, 2)
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		go func(t uint16) {
			q := new(dns.Msg)
			q.SetQuestion(dns.Fqdn(host), t)
			resp, err := r.Resolve(ctx, q)
			if err != nil {
				ch <- famRes{}
				return
			}
			var ips []net.IP
			minTTL := 10 * time.Minute
			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.A:
					ips = append(ips, v.A)
					if d := time.Duration(v.Hdr.Ttl) * time.Second; d < minTTL {
						minTTL = d
					}
				case *dns.AAAA:
					ips = append(ips, v.AAAA)
					if d := time.Duration(v.Hdr.Ttl) * time.Second; d < minTTL {
						minTTL = d
					}
				}
			}
			ch <- famRes{ips: ips, ttl: minTTL}
		}(t)
	}
	var all []net.IP
	ttl := 10 * time.Minute
	for i := 0; i < 2; i++ {
		fr := <-ch
		all = append(all, fr.ips...)
		if fr.ttl < ttl {
			ttl = fr.ttl
		}
	}
	bootstrapCachePut(host, all, ttl)
	return all
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
		// A *url.Error embeds the endpoint URL but also the local ephemeral
		// socket; errUpstream strips the socket and keeps the URL.
		return nil, errUpstream(r.endpoint, err)
	}
	defer resp.Body.Close()
	const maxDNSResponseBytes = 65535
	// Fixed buffer + Unpack avoids io.ReadAll doubling appends.
	var fixed [maxDNSResponseBytes + 1]byte
	n, err := io.ReadFull(resp.Body, fixed[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, errUpstream(r.endpoint, err)
	}
	if n > maxDNSResponseBytes {
		return nil, errUpstream(r.endpoint, fmt.Errorf("doh: upstream response too large"))
	}
	body := fixed[:n]
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
// stamps, and the rare all-down reset clears them in place with atomic stores
// — the slice is never replaced, so lock-free readers always see a valid one.
type MultiResolver struct {
	resolvers []Resolver
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
	// Pool-level budget so serial failover can't park a handler for
	// Σ(timeouts) (3 down upstreams ≈ 15s before). 8s covers typical RTTs
	// while bounding outage latency; an existing tighter deadline is kept.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
	}
	now := time.Now().UnixNano()
	// Stack-backed order avoids the per-query order []int heap alloc in the
	// common ≤8 upstream case.
	var orderBuf [8]int
	var order []int
	nOrder := 0
	allDown := true
	for i := range m.resolvers {
		if atomic.LoadInt64(&m.downUntil[i]) <= now {
			allDown = false
			if nOrder < len(orderBuf) {
				orderBuf[nOrder] = i
				nOrder++
			} else {
				if order == nil {
					order = append([]int(nil), orderBuf[:nOrder]...)
				}
				order = append(order, i)
			}
		}
	}
	if allDown && len(m.resolvers) > 0 { // everything tripped: retry all in order
		for i := range m.downUntil {
			atomic.StoreInt64(&m.downUntil[i], 0)
		}
		nOrder = 0
		order = nil
		for i := range m.resolvers {
			if nOrder < len(orderBuf) {
				orderBuf[nOrder] = i
				nOrder++
			} else {
				if order == nil {
					order = append([]int(nil), orderBuf[:nOrder]...)
				}
				order = append(order, i)
			}
		}
	}

	var firstErr error
	// Single ordered failover loop (no double queries).
	if order != nil {
		for _, i := range order {
			resp, err := m.resolvers[i].Resolve(ctx, q)
			if err == nil {
				atomic.StoreInt64(&m.downUntil[i], 0)
				return resp, nil
			}
			if firstErr == nil {
				firstErr = err
			}
			fail := time.Now().UnixNano()
			jitter := int64(float64(m.cooldown.Nanoseconds()) * 0.2 * (float64(int(fail>>8)&255)/255.0 - 0.5))
			atomic.StoreInt64(&m.downUntil[i], fail+m.cooldown.Nanoseconds()+jitter)
			if ctx.Err() != nil {
				break
			}
		}
	} else {
		for k := 0; k < nOrder; k++ {
			i := orderBuf[k]
			resp, err := m.resolvers[i].Resolve(ctx, q)
			if err == nil {
				atomic.StoreInt64(&m.downUntil[i], 0)
				return resp, nil
			}
			if firstErr == nil {
				firstErr = err
			}
			fail := time.Now().UnixNano()
			jitter := int64(float64(m.cooldown.Nanoseconds()) * 0.2 * (float64(int(fail>>8)&255)/255.0 - 0.5))
			atomic.StoreInt64(&m.downUntil[i], fail+m.cooldown.Nanoseconds()+jitter)
			if ctx.Err() != nil {
				break
			}
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("upstream: no resolvers configured")
	}
	return nil, firstErr
}

// Spec describes a single upstream entry parsed from a spec string.
type Spec struct {
	Type     string // "udp", "tls" (DoT) or "doh"
	Address  string // host:port (udp/tls) or host/path (doh), scheme stripped
	Priority int    // lower = higher priority (tried first)
}

// ParseSpec splits a spec string into individual entries, sorted by priority.
// Each token is a URL-style spec ("udp://host:port", "tls://host[:port]" or
// "https://host/path" / "doh://host/path") with an optional "|priority" suffix, e.g.
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
			s = Spec{Type: "udp", Address: ensurePort(raw[len("udp://"):], "53"), Priority: prio}
		case strings.HasPrefix(raw, "tls://"):
			s = Spec{Type: "tls", Address: ensurePort(raw[len("tls://"):], "853"), Priority: prio}
		case strings.HasPrefix(raw, "doh://"):
			s = Spec{Type: "doh", Address: raw[len("doh://"):], Priority: prio}
		case strings.HasPrefix(raw, "https://"):
			s = Spec{Type: "doh", Address: raw[len("https://"):], Priority: prio}
		default:
			if isBareUDP(raw) {
				s = Spec{Type: "udp", Address: ensurePort(raw, "53"), Priority: prio}
				break
			}
			return nil, fmt.Errorf("upstream: unrecognized spec %q", tok)
		}
		// Reject literal link-local/metadata targets at config time so the
		// failure names the spec instead of surfacing as a dial error later.
		if ip := net.ParseIP(specHost(s.Address)); ip != nil && blockedUpstreamIP(ip) {
			return nil, fmt.Errorf("upstream: %s: refusing link-local/metadata address %s", tok, ip)
		}
		out[i] = s
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}

// specHost returns the host part of a Spec address: "host:port" for udp/tls,
// "host/path" for doh.
func specHost(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
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

// ensurePort appends defaultPort to a host when no port is present, so
// "udp://192.168.30.221" resolves to 192.168.30.221:53 and "tls://9.9.9.9"
// to 9.9.9.9:853 instead of failing to dial. IPv6 hosts are bracketed
// correctly.
func ensurePort(addr, defaultPort string) string {
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	host := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	return net.JoinHostPort(host, defaultPort)
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
//   - "tls://host[:port]" -> TLSResolver (DoT, default port 853)
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
		case "tls":
			rs[i] = NewTLS(s.Address, 0)
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

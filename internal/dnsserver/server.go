// Package dnsserver implements a fast DNS resolver serving classic DNS
// (UDP + TCP) and DNS-over-HTTPS (RFC 8484) on the same query path.
// Requests are filtered per-client, cached with TTL-aware singleflight,
// and forwarded upstream.
package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/twobip/BlipDNS/internal/upstream"
)

// maxDNSQueryParam is the maximum base64url length of the DoH GET `dns`
// parameter. A 4096-byte DNS message encodes to ~5462 base64url chars; 8192
// leaves comfortable headroom while bounding the per-request allocation.
const maxDNSQueryParam = 8192

// maxDoHMessage is the maximum size (octets) of a POSTed DNS message body,
// per RFC 8484 §4.1 (a DNS message is at most 2^16 - 1 octets).
const maxDoHMessage = 65535

// Config configures a Server.
type Config struct {
	DNSAddr           string           // "127.0.0.1:53"
	DoHAddr           string           // "127.0.0.1:8443"
	CertFile          string           // optional explicit TLS cert/key for DoH
	KeyFile           string           // optional explicit TLS cert/key for DoH
	DoHTLS            bool             // serve DoH over HTTPS on DoHAddr (self-signed cert generated when no CertFile/KeyFile)
	DoHHTTPAddr       string           // also accept plain-HTTP DoH on this addr ("" = off; toggleable at runtime by the controller)
	RateLimitQPS      int              // per-client DNS QPS limit (0 = unlimited; toggleable at runtime by the controller)
	RateLimitBurst    int              // per-client burst above QPS (0 = auto = QPS, min 1)
	TLSCert           *tls.Certificate // in-memory cert+key (e.g. generated self-signed) used when DoHTLS
	Upstream          string           // upstream spec(s)
	UpstreamServers   []upstream.UpstreamServer
	UpstreamRoutes    []upstream.UpstreamRoute
	UpstreamBootstrap []upstream.UpstreamServer // DNS servers used to resolve DoH upstream hostnames
	CacheCap          time.Duration
	CacheSize         int // max cached responses in RAM (0 = unlimited)
	Store             *filter.Store
	Version           string
	Blocklist         *blocklist.Blocklist // global blocklist applied before per-client policy
	BlockAction       filter.BlockAction   // response for global-blocklist hits ("" = nxdomain)
	TrustedProxies    []string             // CIDRs/IPs trusted for X-Forwarded-For
}

// Server is the DNS + DoH resolver.
type Server struct {
	cfg   Config
	cache *cache.Cache
	ctrl  *control.Server
	cnt   *control.Counters
	upMu  sync.RWMutex
	// pool is the runtime upstream configuration: named servers, the automatic
	// failover rotation (priority>0 servers, or the configured upstream), and
	// conditional-forwarding routes. nil only when no upstream is configured.
	pool  *upstream.ResolverPool
	logfn func(client, domain string)
	udp   *dns.Server
	tcp   *dns.Server
	doch  *http.Server
	// Optional plain-HTTP DoH listener, toggled at runtime by the controller.
	dohPlainMu   sync.Mutex
	dohPlain     *http.Server
	dohPlainAddr string
	once         sync.Once
	// rl enforces the per-client DNS query rate limit (configurable live).
	rl *rateLimiter
	// cert is the certificate the DoH listener serves. Held atomically so a
	// re-derived pair (an HA VIP configured after startup) is picked up by the
	// next handshake without a restart.
	cert atomic.Pointer[tls.Certificate]
	// rec holds static local DNS records (A/AAAA/CNAME) answered before cache/upstream.
	rec *RecordStore
	// overrides memoizes per-policy upstream resolvers by spec string.
	// Specs come from operator policy (bounded set); building a fresh
	// resolver per query would mint a new http.Transport each time and
	// destroy keepalive reuse (a TCP+TLS handshake per DoH query).
	overrides sync.Map // string -> upstream.Resolver
	// cacheMu guards the runtime cache configuration, seeded from cfg and
	// overridable live by the controller (settings page).
	cacheMu        sync.RWMutex
	cacheSize      int // max cached responses (0 = unlimited)
	trustedProxies []*net.IPNet
}

// New builds a Server. If cfg.Store is nil a permissive default is used.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		cfg.Store = filter.NewStore(nil)
	}
	up, err := upstream.NewPoolWithBootstrap(cfg.UpstreamServers, cfg.UpstreamRoutes, cfg.Upstream, cfg.UpstreamBootstrap)
	if err != nil {
		return nil, err
	}
	trusted, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	c := cache.New(cfg.CacheCap, cfg.CacheSize)
	cnt := &control.Counters{}
	ctrl := control.NewServerWithBlocklist("", cfg.Store, c, cnt, cfg.Version, cfg.Blocklist)
	s := &Server{
		cfg:            cfg,
		cache:          c,
		pool:           up,
		ctrl:           ctrl,
		cnt:            cnt,
		rl:             newRateLimiter(),
		rec:            NewRecordStore(),
		cacheSize:      cfg.CacheSize,
		trustedProxies: trusted,
	}
	if cfg.TLSCert != nil {
		s.cert.Store(cfg.TLSCert)
	}
	// Let the management API toggle the optional plain-HTTP DoH listener, the
	// per-client rate limit, the conditional-forwarding upstream config, and
	// the response cache (size / purge) at runtime.
	ctrl.SetDoHController(s)
	ctrl.SetRateLimitController(s)
	ctrl.SetLocalResolverController(s)
	ctrl.SetCacheController(s)
	ctrl.SetRecordController(s)
	// Keepalived/VRRP is wired by cmd/blipd after the server is constructed,
	// because the manager belongs to the host rather than the DNS query path.
	// Seed the rate limit from config (controller can override later).
	if cfg.RateLimitQPS > 0 {
		_ = s.SetRateLimit(cfg.RateLimitQPS, cfg.RateLimitBurst)
	}
	return s, nil
}

// ControlServer exposes the management API server (e.g. to mount on an
// existing mux or to wrap with token auth). Caller sets the token.
func (s *Server) ControlServer() *control.Server { return s.ctrl }

// SetMgmtToken enables the management API with the given bearer token.
func (s *Server) SetMgmtToken(tok string) { s.ctrl.SetToken(tok) }

// SetTLSCert swaps the certificate served on the DoH listener. The next TLS
// handshake uses it; no restart and no listener bounce. Nil is ignored.
func (s *Server) SetTLSCert(c *tls.Certificate) {
	if c != nil {
		s.cert.Store(c)
	}
}

// SetBlockLogger registers a callback invoked for blocked queries when the
// matching policy has Log enabled.
func (s *Server) SetBlockLogger(fn func(client, domain string)) { s.logfn = fn }

// Handler returns the DoH handler (RFC 8484). Requests to
// /dns-query/{client-id} carry a client identity used for per-client policy
// matching and query-log attribution (e.g. /dns-query/phone).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleDoH)
	mux.HandleFunc("/dns-query/", s.handleDoH)
	return control.SecurityHeaders(mux)
}

// dohBodyPool reuses POST body buffers so attacker-sized (up to 64KiB) DoH
// bodies don't grow via doubling appends per request.
var dohBodyPool = sync.Pool{New: func() any { return make([]byte, 0, 4096) }}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req *dns.Msg
	switch r.Method {
	case http.MethodGet:
		// Only the `dns` param is read: extract it from RawQuery directly
		// instead of r.URL.Query() which parses + unescapes every param into
		// a map per request.
		v := dnsParamFromQuery(r.URL.RawQuery)
		if v == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		if len(v) > maxDNSQueryParam {
			http.Error(w, "dns parameter too large", http.StatusRequestURITooLong)
			return
		}
		// RFC 4648 URL-safe base64; RawURLEncoding tolerates missing padding.
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			http.Error(w, "bad dns parameter", http.StatusBadRequest)
			return
		}
		req = new(dns.Msg)
		if err := req.Unpack(b); err != nil {
			http.Error(w, "bad dns message", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		// Bound the body to the RFC 8484 max DNS message size and reject (413)
		// anything larger rather than silently truncate it. Buffer is pooled.
		buf := dohBodyPool.Get().([]byte)
		buf = buf[:0]
		// Grow at most to maxDoHMessage+1 to detect overflow.
		lr := io.LimitReader(r.Body, maxDoHMessage+1)
		// Manual read loop into pooled slice to avoid io.ReadAll doubling.
		tmp := make([]byte, 4096)
		tooLarge := false
		for {
			n, err := lr.Read(tmp)
			if n > 0 {
				if len(buf)+n > maxDoHMessage+1 {
					tooLarge = true
					break
				}
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		b := buf
		if tooLarge || len(b) > maxDoHMessage {
			dohBodyPool.Put(b[:0])
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		req = new(dns.Msg)
		err := req.Unpack(b)
		dohBodyPool.Put(b[:0])
		if err != nil {
			http.Error(w, "bad dns message", http.StatusBadRequest)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := clientIPFromReq(r, s.trustedProxies)
	clientID := clientIDFromPath(r.URL.Path)
	if clientID == "" {
		// Cloudflare Worker edge cache normalizes /dns-query/<id> to the
		// bare path (one cache entry per query) and forwards the identity
		// in X-Device-ID instead. Same validation as the path form.
		// Avoid string concat when the header is empty (common case).
		if h := r.Header.Get("X-Device-ID"); h != "" {
			clientID = clientIDFromPath("/dns-query/" + h)
		}
	}
	resp := s.serve(ctx, clientIP, clientID, control.ProtoDoH, req)
	buf, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	// RFC 8484 §5.1: HTTP freshness must not exceed the smallest answer TTL.
	// Answers here are per-client (policy/blocklist views), so they are also
	// marked private — a shared intermediary cache must not hand one client's
	// view to another.
	if age := dohMaxAge(resp); age > 0 {
		var cc [64]byte
		b := append(cc[:0], "max-age="...)
		b = strconv.AppendUint(b, uint64(age), 10)
		b = append(b, ", private"...)
		w.Header().Set("Cache-Control", string(b))
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf)
}

// dnsParamFromQuery extracts the first `dns` value from a raw query string
// without allocating the full url.Values map. Percent-encoding is left intact
// for the base64 decoder path (QueryUnescape is applied by the caller via the
// standard path only when needed); base64url has no reserved chars that
// require unescaping beyond what RawURLEncoding tolerates, but '+'/'%' forms
// from some clients need a single unescape — fall back to Query().Get there.
func dnsParamFromQuery(raw string) string {
	for len(raw) > 0 {
		var kv string
		if i := strings.IndexByte(raw, '&'); i >= 0 {
			kv, raw = raw[:i], raw[i+1:]
		} else {
			kv, raw = raw, ""
		}
		if kv == "" {
			continue
		}
		k, v, hasEq := strings.Cut(kv, "=")
		if k != "dns" || !hasEq {
			continue
		}
		// Fast path: base64url alphabet needs no unescaping.
		if strings.IndexAny(v, "%+") < 0 {
			return v
		}
		// Slow path: percent-encoded or '+'-as-space form.
		if un, err := unescapeQueryValue(v); err == nil {
			return un
		}
		return v
	}
	return ""
}

func unescapeQueryValue(v string) (string, error) {
	return url.QueryUnescape(v)
}

// dohMaxAge is the HTTP freshness (seconds) to advertise for a DoH response:
// the smallest TTL in the answer section, or in the authority section for a
// negative reply (the SOA of an NXDOMAIN). Zero means there is no TTL to
// promise, so the caller answers "no-store" (RFC 8484 §5.1).
func dohMaxAge(resp *dns.Msg) uint32 {
	min, seen := uint32(0), false
	for _, sec := range [][]dns.RR{resp.Answer, resp.Ns} {
		for _, rr := range sec {
			if t := rr.Header().Ttl; !seen || t < min {
				min, seen = t, true
			}
		}
	}
	if !seen {
		return 0
	}
	return min
}

// ServeDNS implements dns.Handler for classic DNS.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	// Zero-alloc client IP: type-assert the packet address instead of
	// String()+SplitHostPort+ParseIP (3 allocs per query on the old path).
	var clientIP net.IP
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		clientIP = a.IP
	case *net.TCPAddr:
		clientIP = a.IP
	default:
		if host, _, err := net.SplitHostPort(w.RemoteAddr().String()); err == nil {
			clientIP = net.ParseIP(host)
		} else {
			clientIP = net.ParseIP(w.RemoteAddr().String())
		}
	}
	isUDP := false
	// The mux serves both UDP and TCP on the same handler; only UDP needs
	// truncation to 1232 (DNS flag day) to avoid IP fragmentation. TCP can
	// carry the full response.
	if la := w.LocalAddr(); la != nil && la.Network() == "udp" {
		isUDP = true
	} else if ra := w.RemoteAddr(); ra != nil && ra.Network() == "udp" {
		isUDP = true
	}
	ctx, cancel := queryCtx()
	defer cancel()
	resp := s.serveInner(ctx, clientIP, "", control.ProtoDNS, isUDP, req)
	// Safety net for every early-return path (blocked/local/refused): a large
	// local answer over UDP must still fit the path MTU.
	if isUDP && resp != nil && resp.Len() > 1232 {
		resp.Truncate(1232)
	}
	_ = w.WriteMsg(resp)
}

// serve is the unified query path: filter -> cache -> upstream. clientID is
// the optional DoH client identity from /dns-query/{client-id}; it is only
// attributed in logs and query-log events when it actually selected its
// policy (see ClientIDSelected), otherwise the query is logged as
// "unverified-id". proto is the receiving listener (control.ProtoDoH or
// control.ProtoDNS) for query-log events. Classic-DNS callers that go through
// ServeDNS use serveInner directly with a precise UDP flag; direct serve()
// calls assume classic DNS is UDP so large responses are still truncated.
// queryCtx bounds one classic-DNS query (filter+cache+upstream) so a stalled
// upstream with a large TimeoutSec cannot park goroutines/FDs indefinitely.
// DoH callers already inherit the HTTP request context; classic DNS has none.
func queryCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func (s *Server) serve(ctx context.Context, clientIP net.IP, clientID, proto string, req *dns.Msg) *dns.Msg {
	isUDP := proto == control.ProtoDNS
	return s.serveInner(ctx, clientIP, clientID, proto, isUDP, req)
}

// chainBlockedError carries a CNAME/DNAME chain block out of the cache
// singleflight fetch so every coalesced waiter returns the blocked response
// instead of the poisoned upstream answer (which is never cached).
type chainBlockedError struct {
	target    string
	action    filter.BlockAction
	source    string
	shouldLog bool
}

func (e *chainBlockedError) Error() string { return "blipd: cname target blocked: " + e.target }

// chainBlocked inspects up to 8 CNAME/DNAME targets in m's answer section and
// reports whether any of them is blocked per classify (the same
// policy/blocklist function used for the qname).
func chainBlocked(m *dns.Msg, classify func(string) bool) bool {
	if m == nil {
		return false
	}
	checked := 0
	for _, rr := range m.Answer {
		if checked >= 8 {
			break
		}
		var target string
		switch v := rr.(type) {
		case *dns.CNAME:
			target = v.Target
		case *dns.DNAME:
			target = v.Target
		default:
			continue
		}
		if target == "" {
			continue
		}
		if classify(target) {
			return true
		}
		checked++
	}
	return false
}

// stripSubnet removes the EDNS0 client-subnet option (RFC 7871) from req so a
// client subnet is never forwarded upstream. Other OPT options (e.g. DO) are
// preserved.
func stripSubnet(req *dns.Msg) {
	if req == nil {
		return
	}
	opt := req.IsEdns0()
	if opt == nil {
		return
	}
	kept := make([]dns.EDNS0, 0, len(opt.Option))
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			continue
		}
		kept = append(kept, o)
	}
	opt.Option = kept
}

func (s *Server) serveInner(ctx context.Context, clientIP net.IP, clientID, proto string, isUDP bool, req *dns.Msg) *dns.Msg {
	start := time.Now()
	// A nil source IP must never be routed, cached or rate-bucketed: refuse
	// immediately. (DoH with an unparseable RemoteAddr, or a spoofed classic
	// query, would otherwise mint a "<nil>" bucket or bypass policy CIDRs.)
	if clientIP == nil {
		resp := new(dns.Msg)
		if req != nil {
			resp.SetReply(req)
		}
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeRefused
		return resp
	}
	// Only attribute the self-asserted DoH client-ID when it actually
	// selected its policy (IP inside that policy's networks). Otherwise the
	// query is logged as "unverified-id" so one client cannot impersonate
	// another's identity to escape its own policy. The log identity renders
	// lazily: the unlimited default path with no logging must not pay for
	// IP.String(), and the no-id case reuses one rendering.
	verifiedID := ""
	if clientID != "" && s.cfg.Store != nil && s.cfg.Store.ClientIDSelected(clientIP, clientID) {
		verifiedID = clientID
	}
	var client string
	clientRendered := false
	renderClient := func() string {
		if !clientRendered {
			if verifiedID != "" {
				client = verifiedID
			} else if clientID != "" {
				log.Printf("blipd: unverified client-id %q from %s", clientID, clientIP.String())
				client = "unverified-id"
			} else {
				client = clientIP.String()
			}
			clientRendered = true
		}
		return client
	}
	// Per-client rate limit is keyed by the SOURCE IP (post trusted-proxy
	// resolution, masked to /64 for IPv6), never the DoH client-id path
	// segment, so an attacker can't rotate /dns-query/{client-id} to get a
	// fresh bucket. The full IP is kept for policy lookup; only the bucket
	// key is masked. The atomic off check keeps the (default) unlimited case
	// lock- and alloc-free. Excess queries are dropped with REFUSED so abusive
	// clients can't exhaust upstream. REFUSED queries are tracked separately
	// (AddRateLimited) and excluded from the query totals / query log: only
	// queries that actually get resolved count toward throughput, cache and
	// top-domain stats.
	if s.rl != nil && !s.rl.off.Load() {
		if !s.rl.allow(rateLimitKey(clientIP)) {
			s.cnt.AddRateLimited()
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.RecursionAvailable = true
			resp.Rcode = dns.RcodeRefused
			return resp
		}
	}
	s.cnt.AddQuery()
	// Answer time of every served query feeds the dashboard's average
	// response-time stat; the deferred closure (a bare deferred call would
	// evaluate time.Since at registration) covers every return path below.
	defer func() { s.cnt.AddDuration(time.Since(start)) }()
	if len(req.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeFormatError
		return resp
	}
	q := req.Question[0]
	// Never forward CHAOS-class queries (version.bind, hostname.bind, …)
	// upstream: they disclose the upstream's identity (PoP names) and a
	// resolver has no CHAOS data of its own to give.
	if q.Qclass == dns.ClassCHAOS {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeRefused
		return resp
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true // locally-built replies must carry RA like relayed ones
	// ANY (255) and AXFR (252) are refused: ANY amplifies reflection attacks
	// and AXFR is a zone transfer, never a resolver query.
	if q.Qtype == dns.TypeANY || q.Qtype == dns.TypeAXFR {
		resp.Rcode = dns.RcodeRefused
		return resp
	}
	// Normalize once (ASCII fast path, no alloc when already lowercase) and
	// reuse for blocklist, filter Check and cache key — the old path lowercased
	// 3-4x per query.
	domain := filter.NormalizeName(q.Name)

	// Single filter evaluation: one lookup + one allow walk + one block walk.
	// Replaces the old Allowed+Classify+BlockSource triple (2-3x CIDR scans).
	allowed, blocked, action, upstreamOverride, doLog, source := s.cfg.Store.Check(clientIP, clientID, domain)

	// Check global blocklist first (applied to all clients). A per-client
	// allowlist always wins: a domain the client's policy whitelists is never
	// blocked by the global blocklist (or any policy block list).
	if s.cfg.Blocklist != nil && s.cfg.Blocklist.IsBlocked(domain) && !allowed {
		s.cnt.AddBlocked()
		c := renderClient()
		s.notifyBlock(req, resp, c, domain, "global", proto, start)
		if s.logfn != nil {
			s.logfn(c, domain)
		}
		applyBlockAction(resp, q, s.cfg.BlockAction)
		return resp
	}

	if blocked {
		s.cnt.AddBlocked()
		c := renderClient()
		s.notifyBlock(req, resp, c, domain, source, proto, start)
		if doLog && s.logfn != nil {
			s.logfn(c, domain)
		}
		applyBlockAction(resp, q, action)
		return resp
	}

	if doLog && s.logfn != nil {
		s.logfn(renderClient(), domain)
	}

	// Resolve the upstream. Order: a conditional-forwarding route (query name
	// + client CIDR) wins; otherwise a per-policy upstream override that only
	// applies when no route matched; otherwise the automatic rotation.
	// Check local static records first — these short-circuit before cache/upstream.
	// Snapshot the pool once so Match+Auto+LabelFor cost one RLock, not three.
	pool := s.safePool()
	if s.rec != nil {
		if recResp, ok := s.rec.Lookup(req); ok {
			if s.ctrl.HasWatchers() {
				s.ctrl.Notify(control.WatchEvent{
					Type:       "pass",
					Proto:      proto,
					At:         time.Now(),
					Client:     renderClient(),
					Domain:     domain,
					QType:      qType(req),
					Answers:    answersFor(req, recResp),
					Cached:     false,
					Upstream:   "local",
					DurationUs: time.Since(start).Microseconds(),
				})
			}
			out := recResp
			return out
		}
	}
	resolver, matchedRoute := s.upstreamForWithPool(pool, q.Name, clientIP)
	// Private reverse lookups never leave the box: a non-public IP has no
	// public PTR, so forwarding it only burns upstream quota (and leaks LAN
	// structure). An explicit conditional-forwarding route or per-policy
	// upstream override still wins — the operator asked for it.
	if q.Qtype == dns.TypePTR && !matchedRoute && upstreamOverride == "" {
		if ip, ok := ptrIPFromArpa(q.Name); ok && !ip.IsGlobalUnicast() {
			resp.Rcode = dns.RcodeNameError
			return resp
		}
	}
	if upstreamOverride != "" && !matchedRoute {
		var err error
		resolver, err = s.overrideResolver(upstreamOverride)
		if err != nil {
			s.cnt.AddUpErr()
			s.notifyUpstreamError(renderClient(), domain, "invalid upstream override "+strconv.Quote(upstreamOverride)+": "+err.Error())
			resp.Rcode = dns.RcodeServerFailure
			return resp
		}
	}
	if resolver == nil {
		s.cnt.AddUpErr()
		s.notifyUpstreamError(renderClient(), domain, "no upstream configured")
		resp.Rcode = dns.RcodeServerFailure
		return resp
	}
	upstreamLabel := upstreamLabelWithPool(pool, resolver, matchedRoute, upstreamOverride)

	// Never forward the client subnet upstream (RFC 7871 privacy): strip the
	// EDNS0_SUBNET option from the query OPT before it is cached or resolved.
	// The key partitions on the DO bit, and the subnet option is not part of
	// the key, so distinct subnets share one cache entry. The qname is already
	// normalized above; only the DO bit is read here (no second ToLower).
	// stripSubnet preserves all other OPT options (including DO), so the bit
	// can be read either side of the strip.
	do := false
	if opt := req.IsEdns0(); opt != nil && opt.Do() {
		do = true
	}
	stripSubnet(req)
	key := cache.KeyOfNormalized(q.Name, q.Qtype, q.Qclass, do)
	if upstreamLabel != "" {
		// Partition the cache by the resolver that will answer: routes and
		// per-policy overrides can give different clients different answers
		// for the same qname, and a shared entry would serve one client's
		// view to another. The label is compared, never parsed, so it needs
		// no sanitizing.
		key.Label = upstreamLabel
	}
	// classifyTarget applies the same policy/blocklist decision used for the
	// qname to a CNAME/DNAME target. Single Check evaluation on the normalized
	// target (one lookup + one allow/block walk) instead of the
	// Allowed+Classify+BlockSource triple.
	classifyTarget := func(target string) (bool, filter.BlockAction, string, bool) {
		bare := filter.NormalizeName(target)
		allowed, blocked, action, _, doLog, source := s.cfg.Store.Check(clientIP, clientID, bare)
		if s.cfg.Blocklist != nil && s.cfg.Blocklist.IsBlocked(bare) && !allowed {
			return true, s.cfg.BlockAction, "global", true
		}
		if blocked {
			return true, action, source, doLog
		}
		return false, "", "", false
	}
	fetch := func() (*dns.Msg, error) {
		m, err := resolver.Resolve(ctx, req)
		if err != nil {
			return nil, err
		}
		if m == nil {
			return nil, fmt.Errorf("upstream returned nil response")
		}
		// CNAME/DNAME chain inspection before the response is cached: a
		// qname that is allowed but aliases to a blocked domain must be
		// blocked the same way, without poisoning the cache with the
		// upstream's alias.
		if chainBlocked(m, func(target string) bool {
			ok, _, _, _ := classifyTarget(target)
			return ok
		}) {
			// Find the first blocked target to attribute the block.
			for _, rr := range m.Answer {
				var target string
				switch v := rr.(type) {
				case *dns.CNAME:
					target = v.Target
				case *dns.DNAME:
					target = v.Target
				default:
					continue
				}
				if target == "" {
					continue
				}
				if ok, act, src, lg := classifyTarget(target); ok {
					return nil, &chainBlockedError{target: strings.TrimSuffix(target, "."), action: act, source: src, shouldLog: lg}
				}
			}
			return nil, &chainBlockedError{target: domain, action: "", source: "", shouldLog: false}
		}
		return m, nil
	}
	out, cached, err := s.cache.DoHit(ctx, key, fetch)
	if err != nil {
		var cbe *chainBlockedError
		if errors.As(err, &cbe) {
			s.cnt.AddBlocked()
			blockedResp := new(dns.Msg)
			blockedResp.SetReply(req)
			blockedResp.RecursionAvailable = true
			notifyDomain := cbe.target
			if notifyDomain == "" {
				notifyDomain = domain
			}
			c := renderClient()
			s.notifyBlock(req, blockedResp, c, notifyDomain, cbe.source, proto, start)
			if s.logfn != nil && (cbe.shouldLog || cbe.source == "global") {
				s.logfn(c, notifyDomain)
			}
			applyBlockAction(blockedResp, q, cbe.action)
			return blockedResp
		}
		s.cnt.AddUpErr()
		s.notifyUpstreamError(renderClient(), domain, upstreamErrText(upstreamLabel, err))
		resp.Rcode = dns.RcodeServerFailure
		return resp
	}
	// A cached entry may predate a policy/blocklist change: re-inspect its
	// chain so a newly-blocked alias is not served from cache. Evict the
	// poisoned entry so later queries miss and refetch.
	if cached && chainBlocked(out, func(target string) bool {
		ok, _, _, _ := classifyTarget(target)
		return ok
	}) {
		var cbe *chainBlockedError
		for _, rr := range out.Answer {
			var target string
			switch v := rr.(type) {
			case *dns.CNAME:
				target = v.Target
			case *dns.DNAME:
				target = v.Target
			default:
				continue
			}
			if target == "" {
				continue
			}
			if ok, act, src, lg := classifyTarget(target); ok {
				cbe = &chainBlockedError{target: strings.TrimSuffix(target, "."), action: act, source: src, shouldLog: lg}
				break
			}
		}
		s.cache.Delete(key)
		s.cnt.AddBlocked()
		blockedResp := new(dns.Msg)
		blockedResp.SetReply(req)
		blockedResp.RecursionAvailable = true
		notifyDomain := domain
		var act filter.BlockAction
		var src string
		var lg bool
		if cbe != nil {
			notifyDomain = cbe.target
			act = cbe.action
			src = cbe.source
			lg = cbe.shouldLog
		}
		s.notifyBlock(req, blockedResp, renderClient(), notifyDomain, src, proto, start)
		if s.logfn != nil && (lg || src == "global") {
			s.logfn(renderClient(), notifyDomain)
		}
		applyBlockAction(blockedResp, q, act)
		return blockedResp
	}
	out.Id = req.Id
	out.Question = req.Question
	// UDP path-MTU safety (DNS flag day 1232): truncate large responses so
	// they fit without IP fragmentation; the client retries over TCP (TC bit).
	if isUDP && out.Len() > 1232 {
		out.Truncate(1232)
	}

	// Notify pass event for query log (with full answer records + qtype so
	// non-address answers like TXT/CNAME/MX are preserved, not just A/AAAA).
	// Building the event renders every answer record; skip it entirely when
	// nobody is streaming events.
	if s.ctrl.HasWatchers() {
		answers := answersFor(req, out)
		// answersFor already populated IPs for the legacy IPs field below.
		var ips []string
		for _, a := range answers {
			if isAddressType(a.Type) {
				ips = append(ips, a.Data)
			}
		}
		s.ctrl.Notify(control.WatchEvent{
			Type:       "pass",
			Proto:      proto,
			At:         time.Now(),
			Client:     renderClient(),
			Domain:     domain,
			QType:      qType(req),
			IPs:        ips,
			Answers:    answers,
			Cached:     cached,
			Upstream:   upstreamLabel,
			DurationUs: time.Since(start).Microseconds(),
		})
	}
	return out
}

// notifyBlock streams a block event for the query log. Building the event
// renders every answer record, so it is skipped entirely when nobody is
// streaming events.
func (s *Server) notifyBlock(req, resp *dns.Msg, client, domain, list, proto string, start time.Time) {
	if !s.ctrl.HasWatchers() {
		return
	}
	s.ctrl.Notify(control.WatchEvent{
		Type: "block", At: time.Now(),
		Client: client, Domain: domain, Proto: proto,
		QType: qType(req), Answers: answersFor(req, resp),
		BlockList:  list,
		DurationUs: time.Since(start).Microseconds(),
	})
}

// qType returns the textual RR-type mnemonic of the query question (e.g.
// "A", "AAAA", "TXT"); falls back to the numeric code if unknown.
func qType(req *dns.Msg) string {
	if len(req.Question) == 0 {
		return ""
	}
	return dns.TypeToString[req.Question[0].Qtype]
}

// isAddressType reports whether a rendered RR type is an IP address answer.
func isAddressType(t string) bool {
	return t == "A" || t == "AAAA"
}

// answersFor renders every resource record in a DNS response into a slice of
// control.Answer, preserving A/AAAA addresses, TXT strings (unescaped/quote
// trimmed), CNAME targets, and MX/SRV priorities. The owner name is omitted
// (it is the query name itself) to keep rows compact.
func answersFor(req *dns.Msg, resp *dns.Msg) []control.Answer {
	if resp == nil || len(resp.Answer) == 0 {
		return nil
	}
	out := make([]control.Answer, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		ttl := int(rr.Header().Ttl)
		switch a := rr.(type) {
		case *dns.A:
			out = append(out, control.Answer{Type: "A", Data: a.A.String(), TTL: ttl})
		case *dns.AAAA:
			out = append(out, control.Answer{Type: "AAAA", Data: a.AAAA.String(), TTL: ttl})
		case *dns.CNAME:
			out = append(out, control.Answer{Type: "CNAME", Data: a.Target, TTL: ttl})
		case *dns.TXT:
			out = append(out, control.Answer{Type: "TXT", Data: strings.Join(a.Txt, ""), TTL: ttl})
		case *dns.MX:
			out = append(out, control.Answer{Type: "MX", Data: fmt.Sprintf("%s %d", a.Mx, a.Preference), TTL: ttl})
		case *dns.SRV:
			out = append(out, control.Answer{Type: "SRV", Data: fmt.Sprintf("%d %d %d %s", a.Priority, a.Weight, a.Port, a.Target), TTL: ttl})
		default:
			out = append(out, control.Answer{Type: dns.TypeToString[rr.Header().Rrtype], Data: rr.String(), TTL: ttl})
		}
	}
	return out
}

// upstreamErrText renders a resolver failure for the Upstream Errors page.
// Timeouts say so plainly (keeping which upstream) instead of leaking Go
// http internals like "context deadline exceeded".
func upstreamErrText(upstream string, err error) string {
	var nerr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &nerr) && nerr.Timeout()) {
		if upstream != "" {
			return "timeout talking to " + upstream
		}
		return "upstream timeout"
	}
	return err.Error()
}

// notifyUpstreamError streams an upstream failure to the controller so it can
// be shown on the Upstream Errors page. Skipped entirely when nobody is
// streaming (which is exactly when upstream is down and this would hurt most).
func (s *Server) notifyUpstreamError(client, domain, msg string) {
	if !s.ctrl.HasWatchers() {
		return
	}
	s.ctrl.Notify(control.WatchEvent{
		Type:   "error",
		At:     time.Now(),
		Client: client,
		Domain: domain,
		Msg:    msg,
	})
}

// applyBlockAction sets the response status (and, for the zero action, a
// blackhole answer) for a blocked query. An unset action ("") falls back to
// the default nxdomain response.
func applyBlockAction(resp *dns.Msg, q dns.Question, action filter.BlockAction) {
	switch action {
	case filter.ActionRefused:
		resp.Rcode = dns.RcodeRefused
	case filter.ActionZero:
		resp.Rcode = dns.RcodeSuccess
		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4zero.To4(),
			}}
		case dns.TypeAAAA:
			resp.Answer = []dns.RR{&dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.IPv6zero,
			}}
		}
	default:
		resp.Rcode = dns.RcodeNameError
	}
}

// newHTTPServer builds an HTTP server with the timeouts used for every DoH
// listener (TLS and plain).
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
}

// Start launches UDP, TCP and DoH listeners (DoH blocks).
func (s *Server) Start() error {
	dh := s.Handler()
	s.doch = newHTTPServer(s.cfg.DoHAddr, dh)

	udpH := dns.NewServeMux()
	udpH.Handle(".", s)
	s.udp = &dns.Server{Addr: s.cfg.DNSAddr, Net: "udp", Handler: udpH, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 30 * time.Second }}
	s.tcp = &dns.Server{Addr: s.cfg.DNSAddr, Net: "tcp", Handler: udpH, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 30 * time.Second }}

	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()

	// give UDP/TCP a moment; any immediate error is fatal.
	select {
	case err := <-errCh:
		return err
	case <-time.After(50 * time.Millisecond):
	}

	// Optional plain-HTTP DoH listener (also toggled at runtime by the
	// controller via the management API). Start with whatever config says.
	if err := s.SetDoHHTTPAddr(s.cfg.DoHHTTPAddr); err != nil {
		return err
	}

	if s.cfg.DoHTLS {
		if s.cert.Load() != nil {
			// Serve TLS through http.Server (not a hand-decorated tls.Listen)
			// so HTTP/2 is set up and advertised via ALPN: a bare tls.Listen
			// passes the raw conns to Serve() with no h2 support at all.
			// GetCertificate reads the current pair, so a certificate re-derived
			// at runtime (VIP configured after startup) is served immediately.
			s.doch.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				// GCM/ChaCha only: exclude TLS1.2 CBC-SHA suites (Lucky13/ROBOT
				// class) while keeping broad client compatibility. TLS1.3
				// suites are always GCM/ChaCha and unaffected by this list.
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				PreferServerCipherSuites: true,
				CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					if c := s.cert.Load(); c != nil {
						return c, nil
					}
					return nil, fmt.Errorf("blipd: no DoH certificate loaded")
				},
			}
			ln, err := net.Listen("tcp", s.cfg.DoHAddr)
			if err != nil {
				return fmt.Errorf("blipd: doh listen: %w", err)
			}
			return s.doch.ServeTLS(ln, "", "")
		}
		if s.cfg.CertFile != "" && s.cfg.KeyFile != "" {
			return s.doch.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
		}
		return fmt.Errorf("blipd: doh_tls enabled but no certificate configured (set cert_file/key_file or tls_dir)")
	}
	return s.doch.ListenAndServe()
}

// SetDoHHTTPAddr toggles the optional plain-HTTP DoH listener. An empty addr
// stops a running listener; a non-empty addr starts one on that address. It is
// safe to call concurrently with Start/Shutdown and from the management API.
func (s *Server) SetDoHHTTPAddr(addr string) error {
	s.dohPlainMu.Lock()
	defer s.dohPlainMu.Unlock()
	if addr == s.dohPlainAddr {
		return nil
	}
	s.stopDoHPlainLocked()
	if addr == "" {
		return nil
	}
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		if err == nil {
			err = fmt.Errorf("missing port")
		}
		return fmt.Errorf("doh http addr %q: %w", addr, err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("doh http listen %s: %w", addr, err)
	}
	srv := newHTTPServer(addr, s.Handler())
	s.dohPlain = srv
	s.dohPlainAddr = addr
	// Cleartext DoH exposes queries, answers and client IDs to passive
	// observers: warn loudly unless it is loopback-only.
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" && host != "127.0.0.1" && host != "::1" && host != "localhost" {
		log.Printf("blipd: WARNING plain-HTTP DoH on non-loopback %s exposes DNS queries in cleartext; use only on a trusted LAN or with explicit insecure ack", addr)
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("blipd: doh http listener %s: %v", addr, err)
		}
	}()
	return nil
}

// DoHHTTPAddr reports the address of the optional plain-HTTP DoH listener
// ("" if it is not running).
func (s *Server) DoHHTTPAddr() string {
	s.dohPlainMu.Lock()
	defer s.dohPlainMu.Unlock()
	return s.dohPlainAddr
}

// SetRateLimit configures the per-client DNS query rate limit (QPS). A qps of 0
// disables rate limiting. burst is the per-client burst above qps; <= 0 means
// auto (qps, min 1).
func (s *Server) SetRateLimit(qps, burst int) error {
	if s.rl == nil {
		return nil
	}
	s.rl.set(qps, burst)
	return nil
}

// RateLimitQPS returns the current per-client QPS limit (0 = unlimited).
func (s *Server) RateLimitQPS() int {
	if s.rl == nil {
		return 0
	}
	return s.rl.qps()
}

// SetCacheConfig tunes the response cache size at runtime: the max cached
// responses (0 = unlimited). Must be >= 0.
func (s *Server) SetCacheConfig(size int) error {
	if size < 0 {
		return fmt.Errorf("cache size must be >= 0")
	}
	s.cacheMu.Lock()
	s.cacheSize = size
	s.cacheMu.Unlock()
	s.cache.SetMaxEntries(size)
	return nil
}

// CacheSize returns the current max cached responses (0 = unlimited).
func (s *Server) CacheSize() int {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.cacheSize
}

// PurgeCache drops every cached response (e.g. from the settings page).
func (s *Server) PurgeCache() {
	s.cache.Purge()
}

// stopDoHPlainLocked stops the plain-HTTP DoH listener; caller holds dohPlainMu.
func (s *Server) stopDoHPlainLocked() {
	if s.dohPlain == nil {
		s.dohPlainAddr = ""
		return
	}
	srv := s.dohPlain
	s.dohPlain = nil
	s.dohPlainAddr = ""
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// Shutdown stops all listeners.
func (s *Server) Shutdown() {
	s.once.Do(func() {
		s.dohPlainMu.Lock()
		s.stopDoHPlainLocked()
		s.dohPlainMu.Unlock()
		if s.udp != nil {
			_ = s.udp.Shutdown()
		}
		if s.tcp != nil {
			_ = s.tcp.Shutdown()
		}
		if s.doch != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.doch.Shutdown(ctx)
		}
	})
}

// SetRecords replaces the instance's local DNS records (implements
// control.RecordController). Called by the management API when the controller
// pushes the fleet-wide record set.
func (s *Server) SetRecords(records []control.RecordEntry) error {
	if s.rec == nil {
		return nil
	}
	return s.rec.SetRecords(records)
}

// GetRecords returns the instance's current local DNS records.
func (s *Server) GetRecords() ([]control.RecordEntry, error) {
	if s.rec == nil {
		return nil, nil
	}
	return s.rec.GetRecords()
}

// RecordsHash returns a checksum of the current local records for the management
// API stats readback (so the controller can detect drift after a restart).
func (s *Server) RecordsHash() uint64 {
	if s.rec == nil {
		return 0
	}
	return s.rec.Hash()
}

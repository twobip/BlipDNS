// Package dnsserver implements a fast DNS resolver serving classic DNS
// (UDP + TCP) and DNS-over-HTTPS (RFC 8484) on the same query path.
// Requests are filtered per-client, cached with TTL-aware singleflight,
// and forwarded upstream.
package dnsserver

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
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
	RateLimitQPS      int              // per-client DNS QPS limit (0 = unlimited, stock default 20; toggleable at runtime by the controller)
	RateLimitBurst    int              // per-client burst above QPS (0 = auto = QPS, min 1)
	DNSSEC            bool             // delegate validation to authenticated (DoT/DoH) upstreams: force DO upstream and serve their AD bit
	TLSCert           *tls.Certificate // in-memory cert+key (e.g. generated self-signed) used when DoHTLS
	Upstream          string           // upstream spec(s)
	UpstreamServers   []upstream.UpstreamServer
	UpstreamRoutes    []upstream.UpstreamRoute
	UpstreamBootstrap []upstream.UpstreamServer // DNS servers used to resolve DoH upstream hostnames
	CacheCap          time.Duration
	CacheSize         int // max cached responses in RAM (0 = bounded default)
	Store             *filter.Store
	Version           string
	Blocklist         *blocklist.Blocklist // global blocklist applied before per-client policy
	BlockAction       filter.BlockAction   // response for global-blocklist hits ("" = nxdomain)
	TrustedProxies    []string             // CIDRs/IPs trusted for X-Forwarded-For
	AllowedNetworks   []string             // recursion ACL: CIDRs/IPs allowed to recurse; empty on a non-loopback bind falls back to DefaultAllowedNetworks() with a warning (open only with OpenRecursion)
	OpenRecursion     bool                 // explicit ack for empty allowed_networks on a non-loopback bind (fail closed without it)
	RecordsCacheFile  string               // persisted local-record snapshot: loaded at startup, rewritten on every applied push ("" = off)
}

// maxInflightQueries bounds concurrent classic-DNS query handlers (UDP+TCP
// share ServeDNS; miekg/dns spawns a goroutine per datagram with no cap).
// Saturation sheds load with SERVFAIL instead of queueing: UDP has no
// backpressure, so blocking would park a goroutine per spoofed packet anyway.
// ponytail: fixed generous cap; add a Config knob if operators ever need it.
const maxInflightQueries = 1024

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
	// slowQueryMin is the answer-time threshold above which one diagnostic
	// line per query is logged (0 = off; see SetSlowQueryThreshold).
	slowQueryMin time.Duration
	// slowLogMu guards the slow-query log rate cap, so an upstream outage
	// (every query slow) cannot turn diagnostics into a journal flood.
	slowLogMu       sync.Mutex
	slowLogWindow   int64
	slowLogCount    int
	slowLogSuppress int
	// lifeMu guards udp/tcp/doch so Start (which publishes the listeners
	// from a goroutine in tests) never races Shutdown (which reads them).
	// The blocking Serve calls use the local copies taken under the lock.
	lifeMu sync.RWMutex
	udp    *dns.Server
	tcp    *dns.Server
	doch   *http.Server
	// Optional plain-HTTP DoH listener, toggled at runtime by the controller.
	dohPlainMu   sync.Mutex
	dohPlain     *http.Server
	dohPlainAddr string
	once         sync.Once
	// dnssec delegates DNSSEC validation to trusted upstreams: upstream
	// queries get DO=1 and the AD bit from a trusted server (per-server
	// trust_ad, defaulting to DoT/DoH yes and plain UDP/TCP no) is served to
	// clients that asked for it. Toggleable at runtime by the controller;
	// SetDNSSEC purges the cache because AD and DNSSEC-RR filtering differ
	// between modes.
	dnssec atomic.Bool
	// cacheGen bumps when the upstream pool or DNSSEC mode changes. Cache keys
	// carry it so a fetch started under the old policy cannot be read back
	// under the new one (SetUpstream/SetDNSSEC also purge, but a fetch already
	// in flight can land after the purge).
	cacheGen atomic.Uint64
	// rl enforces the per-client DNS query rate limit (configurable live).
	rl *rateLimiter
	// inflight bounds concurrent ServeDNS handlers (see maxInflightQueries).
	inflight chan struct{}
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
	cacheSize      int // max cached responses (0 = bounded default)
	trustedProxies []*net.IPNet
	// aclMu guards the recursion ACL (allowedNetworks). Empty/nil means
	// allow all (open recursion, backward-compat with warning).
	aclMu           sync.RWMutex
	allowedNetworks []*net.IPNet
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
	if cfg.DNSSEC && !up.AnyTrusted() {
		log.Printf("blipd: WARNING dnssec: true but no upstream is trusted; AD will be discarded, so clients will never receive validated answers")
	}
	trusted, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	allowed, err := control.ParseAllowedNetworks(cfg.AllowedNetworks)
	if err != nil {
		return nil, err
	}
	// No crash on a missing ACL: an empty list on a non-loopback bind falls
	// back to the safe closed default in memory (the daemon cannot persist
	// it — its own config file is read-only by design) and warns loudly on
	// every boot. Serving the world needs the explicit open_recursion ack.
	// Loopback-only binds keep the old warning (tests, single-host setups).
	if len(allowed) == 0 && !cfg.OpenRecursion && !isLoopbackBind(cfg.DNSAddr) {
		def := control.DefaultAllowedNetworks()
		log.Printf("blipd: WARNING no allowed_networks configured for non-loopback dns_addr %q: answering local networks only (%v); set allowed_networks explicitly, or open_recursion: true to serve the world", cfg.DNSAddr, def)
		allowed, err = control.ParseAllowedNetworks(def)
		if err != nil {
			return nil, err
		}
		cfg.AllowedNetworks = append([]string(nil), def...)
	}
	if len(allowed) == 0 {
		log.Printf("blipd: WARNING open recursion: no allowed_networks configured, answering all clients (restrict with allowed_networks to loopback/private LANs)")
	}
	// cache_size 0 selects cache.New's bounded default, never unlimited: an
	// unbounded resolver cache is one rotating flood away from OOM. True
	// unlimited is no longer reachable; set an explicit large size instead.
	c := cache.New(cfg.CacheCap, cfg.CacheSize)
	cnt := &control.Counters{}
	ctrl := control.NewServerWithBlocklist("", cfg.Store, c, cnt, cfg.Version, cfg.Blocklist)
	s := &Server{
		cfg:             cfg,
		cache:           c,
		pool:            up,
		ctrl:            ctrl,
		cnt:             cnt,
		rl:              newRateLimiter(),
		inflight:        make(chan struct{}, maxInflightQueries),
		rec:             NewRecordStore(),
		cacheSize:       cfg.CacheSize,
		trustedProxies:  trusted,
		allowedNetworks: allowed,
	}
	s.dnssec.Store(cfg.DNSSEC)
	if cfg.TLSCert != nil {
		s.cert.Store(cfg.TLSCert)
	}
	// Restore the last pushed local records before serving: a restart while
	// the controller is unreachable would otherwise answer no local names at
	// all until a push lands. The reconcile in blipc re-pushes on hash
	// mismatch, so a stale cache self-corrects on the next successful poll.
	if cfg.RecordsCacheFile != "" {
		n, err := s.rec.SetCachePath(cfg.RecordsCacheFile)
		switch {
		case err != nil:
			log.Printf("blipd: records cache: %v (serving no local records until the controller pushes)", err)
		case n > 0:
			log.Printf("blipd: restored %d local records from cache", n)
		default:
			log.Printf("blipd: no cached local records: local names resolve only after the controller pushes them")
		}
	}
	// Let the management API toggle the optional plain-HTTP DoH listener, the
	// per-client rate limit, the conditional-forwarding upstream config, and
	// the response cache (size / purge) at runtime.
	ctrl.SetDoHController(s)
	ctrl.SetRateLimitController(s)
	ctrl.SetDNSSECController(s)
	ctrl.SetACLController(s)
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

// certTLSConfig returns the hardened TLS config serving the live certificate
// pair (shared by DoH and, when auto-enabled, the management API).
func (s *Server) certTLSConfig() *tls.Config {
	return &tls.Config{
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
			return nil, fmt.Errorf("blipd: no certificate loaded")
		},
	}
}

// ManagementTLSConfig returns a TLS config serving the live DoH certificate
// for the management API (used when blipd auto-enables admin TLS).
func (s *Server) ManagementTLSConfig() *tls.Config {
	return s.certTLSConfig()
}

// SetBlockLogger registers a callback invoked for blocked queries when the
// matching policy has Log enabled.
func (s *Server) SetBlockLogger(fn func(client, domain string)) { s.logfn = fn }

// isLoopbackBind reports whether addr binds loopback only. An empty host
// (":53") binds all interfaces — never loopback (finding 8 precedent).
func isLoopbackBind(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if h == "" || strings.EqualFold(h, "localhost") {
		return h != ""
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// SetAllowedNetworks replaces the recursion ACL at runtime. Empty/nil clears
// to open recursion, which needs the boot-time OpenRecursion ack — without
// it an authed push (or a controller reconcile) silently re-opens a closed
// resolver. Returns an error for invalid CIDRs (including /0 catch-alls)
// without changing the current ACL.
func (s *Server) SetAllowedNetworks(values []string) error {
	nets, err := control.ParseAllowedNetworks(values)
	if err != nil {
		return err
	}
	if len(nets) == 0 && !s.cfg.OpenRecursion {
		return fmt.Errorf("refusing to clear allowed_networks without the open_recursion ack")
	}
	s.aclMu.Lock()
	s.allowedNetworks = nets
	// Keep cfg in sync for readback.
	s.cfg.AllowedNetworks = append([]string(nil), values...)
	s.aclMu.Unlock()
	if len(nets) == 0 {
		log.Printf("blipd: WARNING open recursion: allowed_networks cleared, answering all clients")
	}
	return nil
}

// AllowedNetworks returns the current recursion ACL (a copy; empty/nil means
// open recursion). Reported via /api/v1/stats so the controller can
// reconcile it.
func (s *Server) AllowedNetworks() []string {
	s.aclMu.RLock()
	defer s.aclMu.RUnlock()
	return append([]string(nil), s.cfg.AllowedNetworks...)
}

// OpenRecursion reports the boot-time open-resolver ack (refuse-to-start
// is bypassed when true). Reported via /api/v1/stats so the controller UI
// can show which instances run open.
func (s *Server) OpenRecursion() bool {
	return s.cfg.OpenRecursion
}

// isRecursionAllowed reports whether clientIP may recurse. Empty ACL allows
// all (backward-compat). A nil Server (tests constructing Server literals
// without New) also allows all.
func (s *Server) isRecursionAllowed(clientIP net.IP) bool {
	if s == nil {
		return true
	}
	s.aclMu.RLock()
	nets := s.allowedNetworks
	s.aclMu.RUnlock()
	if len(nets) == 0 {
		return true
	}
	if clientIP == nil {
		return false
	}
	// Normalize like filter.lookupLocked (4-in-6 mapped to 4B) so CIDR
	// containment matches the policy path exactly; Contains handles it, but
	// an explicit To4 keeps the two paths byte-identical.
	if ip4 := clientIP.To4(); ip4 != nil {
		clientIP = ip4
	}
	for _, n := range nets {
		if n.Contains(clientIP) {
			return true
		}
	}
	return false
}

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
	// Shed load before any body read or Unpack: concurrent garbage POSTs
	// must not burn parse CPU pre-gate. Mirrors the classic-DNS path
	// (ServeDNS acquires the same semaphore before serveInner). The nil
	// check keeps zero-value Servers (tests) working.
	if s.inflight != nil {
		select {
		case s.inflight <- struct{}{}:
			defer func() { <-s.inflight }()
		default:
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}
	}
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
		// Stack scratch: the old heap tmp cost 4 KiB per POST.
		var tmp [4096]byte
		tooLarge := false
		for {
			n, err := lr.Read(tmp[:])
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
			// Only pool back small buffers: one attacker-sized POST must not
			// permanently inflate every reused entry to 64 KiB.
			if cap(b) <= 16<<10 {
				dohBodyPool.Put(b[:0])
			}
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		req = new(dns.Msg)
		err := req.Unpack(b)
		// Only pool back small buffers: one attacker-sized POST must not
		// permanently inflate every reused entry to 64 KiB.
		if cap(b) <= 16<<10 {
			dohBodyPool.Put(b[:0])
		}
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
	if resp == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
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
	if resp == nil {
		return 0
	}
	min, seen := uint32(0), false
	update := func(rr dns.RR) {
		if rr == nil || rr.Header() == nil {
			return
		}
		t := rr.Header().Ttl
		// RFC 2308 §3: negative answers cache for min(SOA TTL, SOA
		// minimum) — mirror cache.minTTL so the advertised HTTP
		// freshness never exceeds the actual negative-cache TTL.
		if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < t {
			t = soa.Minttl
		}
		if !seen || t < min {
			min, seen = t, true
		}
	}
	// Two plain loops: the old [][]dns.RR{...} literal built a 2-elem
	// slice header per DoH response.
	for _, rr := range resp.Answer {
		update(rr)
	}
	for _, rr := range resp.Ns {
		update(rr)
	}
	if !seen {
		return 0
	}
	return min
}

// ServeDNS implements dns.Handler for classic DNS.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	// A classic-DNS panic must not kill blipd (DNS+DoH+API+HA share the
	// process); net/http recovers per-request but miekg/dns does not.
	defer func() {
		if r := recover(); r != nil {
			resp := new(dns.Msg)
			if req != nil {
				resp.SetReply(req)
			}
			resp.RecursionAvailable = true
			resp.Rcode = dns.RcodeServerFailure
			if w != nil {
				_ = w.WriteMsg(resp)
			}
		}
	}()
	isUDP := false
	// The mux serves both UDP and TCP on the same handler; the flag only
	// selects the response cap (see responseCap). Computed before the shed
	// below so overload can drop UDP silently.
	if w != nil {
		if la := w.LocalAddr(); la != nil && la.Network() == "udp" {
			isUDP = true
		} else if ra := w.RemoteAddr(); ra != nil && ra.Network() == "udp" {
			isUDP = true
		}
	}
	// Shed load past maxInflightQueries instead of growing a goroutine per
	// spoofed datagram. The nil channel check keeps zero-value Servers
	// (tests) working. UDP shed is dropped silently (spoofable source);
	// TCP gets SERVFAIL (real peer, needs an answer).
	if s.inflight != nil {
		select {
		case s.inflight <- struct{}{}:
			defer func() { <-s.inflight }()
		default:
			if isUDP {
				return
			}
			resp := new(dns.Msg)
			if req != nil {
				resp.SetReply(req)
			}
			resp.RecursionAvailable = true
			resp.Rcode = dns.RcodeServerFailure
			if w != nil {
				_ = w.WriteMsg(resp)
			}
			return
		}
	}
	// Zero-alloc client IP: type-assert the packet address instead of
	// String()+SplitHostPort+ParseIP (3 allocs per query on the old path).
	var clientIP net.IP
	if w != nil && w.RemoteAddr() != nil {
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
	}
	// Classic DNS has no request context: serveInner derives a fetch-scoped
	// timeout around the upstream lookup below, so blocked, local and
	// refused answers pay no timer alloc.
	trace := s.newSlowTrace()
	start := time.Now()
	resp, drop := s.serveInner(context.Background(), clientIP, "", control.ProtoDNS, isUDP, req, trace)
	s.logSlowQuery(start, trace, clientIP, "", control.ProtoDNS, req, resp)
	// Shed, not reflect: a spoofed UDP source gets silence, never REFUSED.
	if drop && isUDP {
		return
	}
	// Safety net for every early-return path (blocked/local/refused): a large
	// answer must still fit the path (UDP: DNS flag-day 1232; TCP: the
	// client's advertised EDNS0 bufsize capped at 1232, 512 + TC when the
	// client sent no OPT). serveInner never returns nil, but guard anyway —
	// WriteMsg(nil) would panic.
	if resp == nil {
		resp = new(dns.Msg)
		if req != nil {
			resp.SetReply(req)
		}
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeServerFailure
	} else if cap := responseCap(req, isUDP); resp.Len() > cap {
		resp.Truncate(cap)
	}
	if w == nil {
		return
	}
	_ = w.WriteMsg(resp)
}

// unverifiedIDLogLast bounds the "unverified client-id" warning below: a
// misconfigured chatty device would otherwise log on every query.
var unverifiedIDLogLast atomic.Int64

// serve is the unified query path: filter -> cache -> upstream. clientID is
// the optional DoH client identity from /dns-query/{client-id}; it is
// attributed in logs and query-log events when it actually selected its
// policy (see ClientIDSelected). An ID claimed by a policy but arriving from
// outside its networks is logged as "unverified-id" so one client cannot
// impersonate another's identity; an ID no policy claims is shown as-is.
// proto is the receiving listener (control.ProtoDoH or
// control.ProtoDNS) for query-log events. Classic-DNS callers that go through
// ServeDNS use serveInner directly with a precise UDP flag; direct serve()
// calls assume classic DNS is UDP so large responses are still truncated.
func (s *Server) serve(ctx context.Context, clientIP net.IP, clientID, proto string, req *dns.Msg) *dns.Msg {
	isUDP := proto == control.ProtoDNS
	// UDP shed is only honored by ServeDNS (the live socket); direct callers
	// (DoH, tests) always need the reply body.
	trace := s.newSlowTrace()
	start := time.Now()
	resp, _ := s.serveInner(ctx, clientIP, clientID, proto, isUDP, req, trace)
	s.logSlowQuery(start, trace, clientIP, clientID, proto, req, resp)
	return resp
}

// queryTrace carries the per-query detail a slow-query log line needs. It is
// allocated only while slow logging is enabled (newSlowTrace), so the hot
// path pays one nil check and nothing else when the knob is off.
type queryTrace struct {
	resolveUs int64  // cache lookup + upstream fetch (a coalesced waiter's wait counts here)
	cached    bool   // served from the response cache
	upstream  string // upstream label the answer came from ("" when unresolved)
}

func (s *Server) newSlowTrace() *queryTrace {
	if s == nil || s.slowQueryMin <= 0 {
		return nil
	}
	return &queryTrace{}
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

// responseCap is the largest response that may be sent back on this transport
// (RFC 8659 §6.1): honor the client's advertised EDNS0 buffer size capped at
// the DNS flag-day 1232 (floored at 512 per RFC 6891), defaulting to 1232 on
// UDP when the client sent no OPT. TCP has no datagram ceiling, so large
// answers are honored whole (Truncate sets TC so the client retries with OPT
// or over TCP — truncating TCP itself only re-truncates the retry).
func responseCap(req *dns.Msg, isUDP bool) int {
	if !isUDP {
		return 65535
	}
	if req != nil {
		if opt := req.IsEdns0(); opt != nil {
			if sz := int(opt.UDPSize()); sz > 0 {
				return min(max(sz, 512), 1232)
			}
		}
	}
	return 1232
}

// rrTarget returns the domain name carried by rr for blocklist inspection:
// the rdata target for name-bearing types, the owner name for address
// records. The second result is false for types that carry no domain name
// (or an empty one — NAPTR "." included, which normalizes away).
func rrTarget(rr dns.RR) (string, bool) {
	switch v := rr.(type) {
	case *dns.CNAME:
		return v.Target, v.Target != ""
	case *dns.DNAME:
		return v.Target, v.Target != ""
	case *dns.A, *dns.AAAA:
		name := rr.Header().Name
		return name, name != ""
	case *dns.MX:
		return v.Mx, v.Mx != ""
	case *dns.SRV:
		return v.Target, v.Target != ""
	case *dns.NS:
		return v.Ns, v.Ns != ""
	case *dns.SOA:
		return v.Ns, v.Ns != ""
	case *dns.SVCB:
		return v.Target, v.Target != ""
	case *dns.HTTPS:
		return v.Target, v.Target != ""
	case *dns.NAPTR:
		// "." is the NAPTR "no replacement" marker, not a name.
		return v.Replacement, v.Replacement != "" && v.Replacement != "."
	case *dns.CAA:
		// Value is "issuer-domain [params]" (e.g. "letsencrypt.org; validationmethods=dns-01").
		if f, _, _ := strings.Cut(v.Value, ";"); strings.TrimSpace(f) != "" {
			return strings.TrimSpace(f), true
		}
		return "", false
	case *dns.RP:
		return v.Mbox, v.Mbox != ""
	default:
		return "", false
	}
}

// maxChainInspect bounds CNAME/DNAME chain inspection. Chains longer than
// this are treated as blocked (fail-closed) rather than silently allowed:
// an unbounded upstream-constructed chain must never evade filtering, and an
// unbounded walk is itself a CPU concern on attacker-controlled responses.
const maxChainInspect = 64

// chainBlocked inspects every name carried in all sections (Answer, Ns,
// Extra) — rdata targets of name-bearing types plus A/AAAA owner names —
// reporting whether any of them is blocked per classify (the same
// policy/blocklist function used for the qname).
// F-08: the old code stopped after 8 targets, so a blocked domain placed 9th
// (or later) evaded filtering and poisoned the cache. Over-long chains
// (>maxChainInspect) fail closed.
func chainBlocked(m *dns.Msg, classify func(string) bool) bool {
	blocked, _, _, _, _ := inspectChain(m, func(target string) (bool, filter.BlockAction, string, bool) {
		return classify(target), "", "", false
	})
	return blocked
}

// inspectChain fuses the old chainBlocked boolean pass and the
// findBlockedTarget attribution pass into one walk: each carried name is
// classified once, and the first blocked target is returned with its action
// for the query log. Over-long chains fail closed with an empty target (the
// caller attributes those to the qname, as before).
func inspectChain(m *dns.Msg, classify func(string) (bool, filter.BlockAction, string, bool)) (blocked bool, target string, act filter.BlockAction, src string, lg bool) {
	if m == nil {
		return false, "", "", "", false
	}
	checked := 0
	// visit classifies one RR's carried name; true stops the walk.
	visit := func(rr dns.RR) bool {
		if rr == nil || rr.Header() == nil {
			return false
		}
		t, ok := rrTarget(rr)
		if !ok {
			return false
		}
		checked++
		if checked > maxChainInspect {
			blocked = true
			return true
		}
		if ok, a, s, l := classify(t); ok {
			blocked, target, act, src, lg = true, strings.TrimSuffix(t, "."), a, s, l
			return true
		}
		return false
	}
	// Three plain loops: ranging a composite literal built a slice per call.
	for _, rr := range m.Answer {
		if visit(rr) {
			return blocked, target, act, src, lg
		}
	}
	for _, rr := range m.Ns {
		if visit(rr) {
			return blocked, target, act, src, lg
		}
	}
	for _, rr := range m.Extra {
		if visit(rr) {
			return blocked, target, act, src, lg
		}
	}
	return false, "", "", "", false
}

// sanitizeBailiwick strips out-of-bailiwick records before cache+serve. Only
// the qname's own Answer records plus in-chain CNAME/DNAME targets (and
// in-bailiwick Ns records) are kept; Extra is dropped except OPT (which
// carries no addresses). At minimum this drops Answer A/AAAA whose owner is
// out-of-bailiwick of the query name and Ns records whose owner is
// out-of-zone.

// bailiwickName normalizes a DNS name for bailiwick comparison: lowercase,
// no root dot, no leading dots.
func bailiwickName(name string) string {
	return strings.TrimLeft(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")), ".")
}

func sanitizeBailiwick(qname string, m *dns.Msg) {
	if m == nil {
		return
	}
	qn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	qn = strings.TrimLeft(qn, ".")
	// Fast path: nothing to sanitize.
	if len(m.Answer) == 0 && len(m.Ns) == 0 && len(m.Extra) == 0 {
		return
	}
	if qn == "" {
		// Without a query name we cannot judge bailiwick: drop Answer and
		// Ns/Extra except OPT rather than serve attacker glue.
		var keptNs []dns.RR
		_ = keptNs
		m.Answer = nil
		m.Ns = nil
		keptExtra := m.Extra[:0]
		for _, rr := range m.Extra {
			if _, ok := rr.(*dns.OPT); ok {
				keptExtra = append(keptExtra, rr)
			}
		}
		m.Extra = keptExtra
		return
	}
	// Keep Answer records whose owner is the qname or an in-chain
	// CNAME/DNAME target: a rogue upstream alias (attacker.com CNAME
	// victim.com + victim.com A) must not be cached or served. Anything
	// else is out-of-bailiwick.
	allowed := map[string]struct{}{qn: {}}
	keptAnswer := m.Answer[:0]
	for _, rr := range m.Answer {
		if rr == nil || rr.Header() == nil {
			continue
		}
		owner := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
		owner = strings.TrimLeft(owner, ".")
		if _, ok := allowed[owner]; !ok {
			continue
		}
		keptAnswer = append(keptAnswer, rr)
		switch v := rr.(type) {
		case *dns.CNAME:
			allowed[bailiwickName(v.Target)] = struct{}{}
		case *dns.DNAME:
			allowed[bailiwickName(v.Target)] = struct{}{}
		}
	}
	// Clear the tail so dropped records are not retained via the backing array.
	for i := len(keptAnswer); i < len(m.Answer); i++ {
		m.Answer[i] = nil
	}
	m.Answer = keptAnswer
	// Keep Ns records whose owner is in-bailiwick: owner == qname, owner is an
	// ancestor of qname (qname is subdomain of owner), or owner is a subdomain
	// of qname (delegation child). Anything else is out-of-zone glue.
	keptNs := m.Ns[:0]
	for _, rr := range m.Ns {
		owner := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
		owner = strings.TrimLeft(owner, ".")
		if owner == "" {
			continue
		}
		if owner == qn || strings.HasSuffix(qn, "."+owner) || strings.HasSuffix(owner, "."+qn) {
			keptNs = append(keptNs, rr)
			continue
		}
		// Out-of-bailiwick Ns: drop. For NS-type records this also drops the
		// delegation; for SOA (negative answers) the owner is the qname's
		// ancestor and already kept above. Unknown out-of-zone owners are
		// never cached or served.
	}
	// Clear the tail so dropped records are not retained via the backing array.
	for i := len(keptNs); i < len(m.Ns); i++ {
		m.Ns[i] = nil
	}
	m.Ns = keptNs
	// Drop all Extra except OPT. Glue A/AAAA (even in-bailiwick) is not needed
	// by a stub-facing resolver and is the classic cache-poison vector.
	keptExtra := m.Extra[:0]
	for _, rr := range m.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			keptExtra = append(keptExtra, rr)
		}
	}
	for i := len(keptExtra); i < len(m.Extra); i++ {
		m.Extra[i] = nil
	}
	m.Extra = keptExtra
}

// freshUpstreamID returns a random DNS ID (crypto/rand). It never returns the
// caller's ID so a retry does not reuse a known value. On crypto/rand failure
// it returns an error instead of a predictable fallback (caller+time) which an
// off-path spoofer could predict.
func freshUpstreamID(caller uint16) (uint16, error) {
	var b [2]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("blipd: crypto/rand failed: %w", err)
	}
	id := binary.BigEndian.Uint16(b[:])
	if id == caller {
		// Extremely unlikely collision: flip a bit instead of falling back to
		// a predictable value.
		id ^= 0x8000
		if id == caller {
			id ^= 0x0001
		}
	}
	return id, nil
}

// classifyName applies the same policy/blocklist decision used for the qname
// to an arbitrary name (CNAME/DNAME target or A/AAAA owner).
func (s *Server) classifyName(clientIP net.IP, clientID, target string) (bool, filter.BlockAction, string, bool) {
	if s == nil {
		return false, "", "", false
	}
	bare := filter.NormalizeName(target)
	var allowed, blocked bool
	var action filter.BlockAction
	var doLog bool
	var source string
	if s.cfg.Store != nil {
		allowed, blocked, action, _, doLog, source = s.cfg.Store.Check(clientIP, clientID, bare)
	} else {
		action = filter.DefaultAction
	}
	if s.cfg.Blocklist != nil && s.cfg.Blocklist.IsBlockedNormalized(bare) && !allowed {
		return true, s.cfg.BlockAction, "global", doLog
	}
	if blocked {
		return true, action, source, doLog
	}
	return false, "", "", false
}

// isLocalBlocked reports whether a local-record response contains a blocked
// CNAME/DNAME target or a blocked A/AAAA owner.
func (s *Server) isLocalBlocked(m *dns.Msg, clientIP net.IP, clientID string) bool {
	if m == nil {
		return false
	}
	classify := func(target string) bool {
		ok, _, _, _ := s.classifyName(clientIP, clientID, target)
		return ok
	}
	return chainBlocked(m, classify)
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
	// Fast path: most queries carry OPT without a subnet option — scan
	// first so the common case pays no slice alloc.
	hasSubnet := false
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			hasSubnet = true
			break
		}
	}
	if !hasSubnet {
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

// upstreamEDNSUDPSize is the EDNS0 payload size blipd advertises when it must
// add an OPT RR to an upstream query itself. 1232 follows DNS Flag Day 2020:
// large enough for most signed answers, small enough to avoid IP
// fragmentation (UDPResolver retries over TCP if the upstream truncates).
const upstreamEDNSUDPSize = 1232

// setUpstreamDO forces the EDNS0 DNSSEC OK bit on an upstream query, adding an
// OPT RR when the client sent none. Used only with dnssec: true so a
// validating upstream returns RRSIGs and can assert AD.
func setUpstreamDO(m *dns.Msg) {
	if m == nil {
		return
	}
	if opt := m.IsEdns0(); opt != nil {
		opt.SetDo()
		return
	}
	m.SetEdns0(upstreamEDNSUDPSize, true)
}

// stripDNSSEC removes DNSSEC RRs the client did not explicitly ask for. RFC
// 4035 §3.2.1 says a security-aware server must not include them unless the
// request had DO=1; keep is the question type, so DNSKEY/DS/RRSIG queries
// still work with DO=0.
func stripDNSSEC(m *dns.Msg, keep uint16) {
	if m == nil {
		return
	}
	m.Answer = dropDNSSECRRs(m.Answer, keep)
	m.Ns = dropDNSSECRRs(m.Ns, keep)
	m.Extra = dropDNSSECRRs(m.Extra, keep)
}

func dropDNSSECRRs(rrs []dns.RR, keep uint16) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	out := rrs[:0]
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		t := rr.Header().Rrtype
		if t != keep && isDNSSECRR(t) {
			continue
		}
		out = append(out, rr)
	}
	// Drop references to filtered RRs so they can be GC'd with the slice.
	for i := len(out); i < len(rrs); i++ {
		rrs[i] = nil
	}
	return out
}

// isDNSSECRR reports whether t is a DNSSEC record type that is only included
// when the client set DO=1 or explicitly queried that type.
func isDNSSECRR(t uint16) bool {
	switch t {
	case dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY,
		dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeCDS, dns.TypeCDNSKEY,
		dns.TypeSIG, dns.TypeKEY, dns.TypeDLV:
		return true
	default:
		return false
	}
}

// normalizeResponseOPT aligns the response's OPT RR with the client's EDNS
// state. Forcing DO upstream can make the upstream echo an OPT (with DO=1) to
// a client that never sent EDNS, and DO must mirror the client's request, not
// our internal upstream query (RFC 3225 §3). A non-EDNS client gets no OPT;
// an EDNS client's response OPT keeps the remaining options but takes the
// client's DO bit.
func normalizeResponseOPT(out, req *dns.Msg, do bool) {
	if out == nil {
		return
	}
	opt := out.IsEdns0()
	if opt == nil {
		return
	}
	if req == nil || req.IsEdns0() == nil {
		kept := out.Extra[:0]
		for _, rr := range out.Extra {
			if rr != nil && rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			kept = append(kept, rr)
		}
		for i := len(kept); i < len(out.Extra); i++ {
			out.Extra[i] = nil
		}
		out.Extra = kept
		return
	}
	opt.SetDo(do)
}

// serveInner resolves one query. The bool reports UDP shed: when true the
// transport is spoofable and the reply must be dropped, not sent —
// answering REFUSED/SERVFAIL to a forged source makes blipd a reflector.
// Only the pre-routing sheds (nil source, ACL, rate limit) set it; policy
// blocks and upstream errors still reply (TCP/DoH always reply).
func (s *Server) serveInner(ctx context.Context, clientIP net.IP, clientID, proto string, isUDP bool, req *dns.Msg, trace ...*queryTrace) (*dns.Msg, bool) {
	start := time.Now()
	// Slow-query tracing is opt-in: trace is nil (and stays nil) unless
	// slow_query_ms is set, so the common path pays one nil compare.
	var tr *queryTrace
	if len(trace) > 0 {
		tr = trace[0]
	}
	// Nil guards: never dereference a nil request or server. A nil request
	// cannot be replied to meaningfully; refuse with an empty message.
	if req == nil {
		resp := new(dns.Msg)
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeFormatError
		return resp, false
	}
	if s == nil {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeServerFailure
		return resp, false
	}
	// A nil source IP must never be routed, cached or rate-bucketed: refuse
	// immediately. (DoH with an unparseable RemoteAddr, or a spoofed classic
	// query, would otherwise mint a "<nil>" bucket or bypass policy CIDRs.)
	// The source may be spoofed: drop (no reply) rather than reflect.
	if clientIP == nil {
		resp := new(dns.Msg)
		if req != nil {
			resp.SetReply(req)
		}
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeRefused
		return resp, true
	}
	// H4 open recursion: refuse non-allowlisted sources before any recursion
	// (filter/cache/upstream). Empty ACL means allow all (backward-compat).
	// UDP refusals are dropped, not sent: the source may be spoofed.
	if !s.isRecursionAllowed(clientIP) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeRefused
		return resp, true
	}
	// Only attribute the self-asserted DoH client-ID when it actually
	// selected its policy (IP inside that policy's networks). A claimed-but-
	// unscoped ID renders as "unverified-id" so one client cannot impersonate
	// another's identity to escape its own policy; an ID no policy claims
	// renders as-is. The log identity renders
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
				if s.cfg.Store != nil && s.cfg.Store.KnowsClientID(clientID) {
					// Sampled: a misconfigured device asserting a known-but-
					// unscoped ID on every query must not spam stderr.
					if now, last := time.Now().Unix(), unverifiedIDLogLast.Load(); now-last >= 10 &&
						unverifiedIDLogLast.CompareAndSwap(last, now) {
						log.Printf("blipd: unverified client-id %q from %s", clientID, clientIP.String())
					}
					client = "unverified-id"
				} else {
					// No policy claims this ID, so there is no identity to
					// impersonate: display the assertion as-is and keep
					// per-device attribution working with zero configuration.
					client = clientID
				}
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
	// top-domain stats. On UDP the refusal is dropped, not sent: replying to
	// a spoofable source is reflection.
	if s.rl != nil && !s.rl.off.Load() {
		if !s.rl.allow(rateLimitKey(clientIP)) {
			s.cnt.AddRateLimited()
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.RecursionAvailable = true
			resp.Rcode = dns.RcodeRefused
			return resp, true
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
		return resp, false
	}
	// A forwarder only implements QUERY: UPDATE/NOTIFY/etc. must never be
	// proxied to an upstream that might trust blipd's IP (zone-write
	// primitive). NOTIMP, before any routing or caching.
	if req.Opcode != dns.OpcodeQuery {
		opResp := new(dns.Msg)
		opResp.SetReply(req)
		opResp.RecursionAvailable = true
		opResp.Rcode = dns.RcodeNotImplemented
		return opResp, false
	}
	if len(req.Question) != 1 {
		multiResp := new(dns.Msg)
		multiResp.SetReply(req)
		multiResp.RecursionAvailable = true
		multiResp.Rcode = dns.RcodeFormatError
		return multiResp, false
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
		return resp, false
	}
	// ANY (255), AXFR (252) and IXFR (251) are refused: ANY amplifies reflection attacks
	// and AXFR/IXFR are zone transfers, never resolver queries. Built lazily:
	// the old prebuilt reply was orphaned on the pass path below.
	if q.Qtype == dns.TypeANY || q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		anyResp := new(dns.Msg)
		anyResp.SetReply(req)
		anyResp.RecursionAvailable = true
		anyResp.Rcode = dns.RcodeRefused
		return anyResp, false
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true // locally-built replies must carry RA like relayed ones
	// Normalize once (ASCII fast path, no alloc when already lowercase) and
	// reuse for blocklist, filter Check and cache key — the old path lowercased
	// 3-4x per query.
	domain := filter.NormalizeName(q.Name)

	// Single filter evaluation: one lookup + one allow walk + one block walk.
	// Replaces the old Allowed+Classify+BlockSource triple (2-3x CIDR scans).
	var allowed, blocked bool
	var action filter.BlockAction
	var upstreamOverride, source string
	var doLog bool
	if s.cfg.Store != nil {
		allowed, blocked, action, upstreamOverride, doLog, source = s.cfg.Store.Check(clientIP, clientID, domain)
	} else {
		action = filter.DefaultAction
	}

	// Check global blocklist first (applied to all clients). A per-client
	// allowlist always wins: a domain the client's policy whitelists is never
	// blocked by the global blocklist (or any policy block list).
	if s.cfg.Blocklist != nil && s.cfg.Blocklist.IsBlockedNormalized(domain) && !allowed {
		s.cnt.AddBlocked()
		c := renderClient()
		s.notifyBlock(req, resp, c, domain, "global", proto, start)
		if doLog && s.logfn != nil {
			s.logfn(c, domain)
		}
		applyBlockAction(resp, q, s.cfg.BlockAction)
		return resp, false
	}

	if blocked {
		s.cnt.AddBlocked()
		c := renderClient()
		s.notifyBlock(req, resp, c, domain, source, proto, start)
		if doLog && s.logfn != nil {
			s.logfn(c, domain)
		}
		applyBlockAction(resp, q, action)
		return resp, false
	}

	if doLog && s.logfn != nil {
		s.logfn(renderClient(), domain)
	}

	// Resolve the upstream. Order: a conditional-forwarding route (query name
	// + client CIDR) wins; otherwise a per-policy upstream override that only
	// applies when no route matched; otherwise the automatic rotation.
	// Check local static records first — these short-circuit before cache/upstream.
	// Snapshot the pool once so Match+Auto+LabelFor cost one RLock, not three,
	// and pair it with the cache generation under the same lock.
	pool, cacheGen := s.safePoolGen()
	if s.rec != nil {
		if recResp, ok := s.rec.Lookup(req); ok {
			// M2 AD: local records are not DNSSEC-validated; clear AD.
			if recResp != nil {
				recResp.AuthenticatedData = false
			}
			// M5: enforce the same CNAME/DNAME + A/AAAA-owner block checks
			// on local records as on upstream answers. A local CNAME
			// pointing at a blocked domain (or a local A for a blocked
			// owner) must be blocked, not served.
			if recResp != nil && s.isLocalBlocked(recResp, clientIP, clientID) {
				s.cnt.AddBlocked()
				blockedResp := new(dns.Msg)
				blockedResp.SetReply(req)
				blockedResp.RecursionAvailable = true
				blockedResp.AuthenticatedData = false
				c := renderClient()
				s.notifyBlock(req, blockedResp, c, domain, "local", proto, start)
				// Attribute to the first blocked chain target when possible
				// so the query log shows what was actually blocked.
				var act filter.BlockAction
				if blocked, _, a, _, _ := inspectChain(recResp, func(t string) (bool, filter.BlockAction, string, bool) {
					return s.classifyName(clientIP, clientID, t)
				}); blocked {
					act = a
				}
				applyBlockAction(blockedResp, q, act)
				return blockedResp, false
			}
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
			if out != nil {
				out.Id = req.Id
				out.Question = req.Question
				out.AuthenticatedData = false
			} else {
				// Lookup claimed a hit but handed back nil: SERVFAIL rather
				// than a nil Msg (ServeDNS would panic on WriteMsg(nil)).
				resp.Rcode = dns.RcodeServerFailure
				resp.AuthenticatedData = false
				return resp, false
			}
			return out, false
		}
	}
	resolver, matchedRoute := s.upstreamForWithPool(pool, q.Name, clientIP)
	// Private reverse lookups never leave the box: a non-public IP has no
	// public PTR, so forwarding it only burns upstream quota (and leaks LAN
	// structure). An explicit conditional-forwarding route or per-policy
	// upstream override still wins — the operator asked for it.
	if q.Qtype == dns.TypePTR && !matchedRoute && upstreamOverride == "" {
		// IsPrivate is load-bearing: Go's IsGlobalUnicast is true for
		// RFC1918/ULA, so the test used to be a no-op for 192.168/16 and
		// every LAN reverse lookup was forwarded (quota burn + LAN-structure
		// leak). Verified in Go: 192.168.30.1 => IsGlobalUnicast=true.
		// ponytail: shared 100.64/10 (CGNAT) and reserved blocks still
		// forward; add a range here if one ever shows up on the LAN.
		if ip, ok := ptrIPFromArpa(q.Name); ok && (!ip.IsGlobalUnicast() || ip.IsPrivate()) {
			resp.Rcode = dns.RcodeNameError
			return resp, false
		}
	}
	if upstreamOverride != "" && !matchedRoute {
		var err error
		resolver, err = s.overrideResolver(upstreamOverride)
		if err != nil {
			s.cnt.AddUpErr()
			s.notifyUpstreamError(renderClient(), domain, "invalid upstream override "+strconv.Quote(upstreamOverride)+": "+err.Error())
			resp.Rcode = dns.RcodeServerFailure
			return resp, false
		}
	}
	if resolver == nil {
		s.cnt.AddUpErr()
		s.notifyUpstreamError(renderClient(), domain, "no upstream configured")
		resp.Rcode = dns.RcodeServerFailure
		return resp, false
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
	key := cache.KeyOfNormalized(q.Name, q.Qtype, q.Qclass, do, req.CheckingDisabled, req.AuthenticatedData)
	key.Gen = cacheGen
	if upstreamLabel != "" {
		// Partition the cache by the resolver that will answer: routes and
		// per-policy overrides can give different clients different answers
		// for the same qname, and a shared entry would serve one client's
		// view to another. The label is compared, never parsed, so it needs
		// no sanitizing.
		key.Label = upstreamLabel
	}
	// classifyTarget applies the same policy/blocklist decision used for the
	// qname to an rdata target or A/AAAA owner: one shared evaluation
	// (see classifyName) instead of a second near-duplicate closure.
	classifyTarget := func(target string) (bool, filter.BlockAction, string, bool) {
		return s.classifyName(clientIP, clientID, target)
	}
	// Fetch-scoped timeout: a stalled upstream with a large TimeoutSec must
	// not park goroutines/FDs indefinitely. Scoped here (not per query) so
	// early refusals (blocks, local answers) skip it; the lookup path arms
	// it once for both cache hits and coalesced-miss waiters. 10s sits
	// above the pool's 8s failover budget, so classic-DNS timing is
	// unchanged; DoH previously had no outer bound and now has 10s.
	if ctx == nil {
		ctx = context.Background()
	}
	fctx, fcancel := context.WithTimeout(ctx, 10*time.Second)
	defer fcancel()
	fetch := func() (*dns.Msg, error) {
		// Per-upstream TXID: the client chose req.Id (attacker-known for
		// their own queries). Plaintext UDP copies and re-randomizes so
		// off-path spoofers cannot use the known ID; encrypted transports
		// (DoT/DoH) share req — the TLS channel, not the TXID, stops
		// spoofers. Fail closed if crypto/rand fails instead of using a
		// predictable ID.
		//
		// Delegated DNSSEC needs a copy even on an encrypted transport:
		// forcing DO must not mutate the client's request (responseCap
		// reads its OPT size later).
		upReq := req
		encrypted := upstream.Encrypted(resolver)
		forceDO := s.dnssec.Load() && !do
		if !encrypted || forceDO {
			c := req.Copy()
			if !encrypted {
				newID, idErr := freshUpstreamID(req.Id)
				if idErr != nil {
					return nil, idErr
				}
				c.Id = newID
			}
			if forceDO {
				setUpstreamDO(c)
			}
			upReq = c
		}
		m, err := resolver.Resolve(fctx, upReq)
		if err != nil {
			return nil, err
		}
		if m == nil {
			return nil, fmt.Errorf("upstream returned nil response")
		}
		// Delegated DNSSEC (dnssec: true): the AD bit is only meaningful
		// from an authenticated transport, and upstream.UDPResolver clears
		// it for plain UDP/TCP, so a mixed failover pool cannot launder an
		// unauthenticated AD=1. With the feature off, keep the historical
		// M2 behavior of never propagating upstream AD.
		if !s.dnssec.Load() {
			m.AuthenticatedData = false
		}
		// H5 bailiwick: strip out-of-bailiwick Ns/Extra glue before
		// cache+serve. Only Answer + in-bailiwick Ns are kept; Extra is
		// dropped except OPT.
		sanitizeBailiwick(q.Name, m)
		// CNAME/DNAME chain inspection before the response is cached: a
		// qname that is allowed but aliases to a blocked domain must be
		// blocked the same way, without poisoning the cache with the
		// upstream's alias. Also inspects Ns/Extra targets and A/AAAA
		// owners (glue for blocked names). One walk classifies and
		// attributes; over-long chains fail closed on the qname.
		if blocked, target, act, src, lg := inspectChain(m, classifyTarget); blocked {
			if target == "" {
				return nil, &chainBlockedError{target: domain, action: "", source: "", shouldLog: false}
			}
			return nil, &chainBlockedError{target: target, action: act, source: src, shouldLog: lg}
		}
		// RFC 4035 §3.2.1: a DO=0 client only gets the DNSSEC RR type it
		// explicitly asked for. Strip here (before DoHit caches the answer):
		// the DO=0 cache entry stays small and no later path can leak
		// RRSIGs to a client that did not request them. DO=1 keys are
		// already partitioned from DO=0 keys.
		if !do {
			stripDNSSEC(m, q.Qtype)
		}
		return m, nil
	}
	resolveStart := time.Now()
	out, cached, err := func() (*dns.Msg, bool, error) {
		if s.cache == nil {
			m, ferr := fetch()
			return m, false, ferr
		}
		return s.cache.DoHit(fctx, key, fetch)
	}()
	if tr != nil {
		tr.cached, tr.upstream, tr.resolveUs = cached, upstreamLabel, time.Since(resolveStart).Microseconds()
	}
	if err != nil {
		var cbe *chainBlockedError
		if errors.As(err, &cbe) {
			s.cnt.AddBlocked()
			blockedResp := new(dns.Msg)
			blockedResp.SetReply(req)
			blockedResp.RecursionAvailable = true
			blockedResp.AuthenticatedData = false
			notifyDomain := cbe.target
			if notifyDomain == "" {
				notifyDomain = domain
			}
			c := renderClient()
			s.notifyBlock(req, blockedResp, c, notifyDomain, cbe.source, proto, start)
			if s.logfn != nil && cbe.shouldLog {
				s.logfn(c, notifyDomain)
			}
			applyBlockAction(blockedResp, q, cbe.action)
			return blockedResp, false
		}
		// Caller went away (DoH disconnect, coalesced waiter gave up): not
		// an upstream failure — SERVFAIL the (gone) caller without counting
		// or reporting it. Mirrors upstream.isCallerCancel at the pool.
		if errors.Is(err, context.Canceled) || errors.Is(fctx.Err(), context.Canceled) {
			resp.Rcode = dns.RcodeServerFailure
			resp.AuthenticatedData = false
			return resp, false
		}
		s.cnt.AddUpErr()
		s.notifyUpstreamError(renderClient(), domain, upstreamErrText(upstreamLabel, err))
		resp.Rcode = dns.RcodeServerFailure
		resp.AuthenticatedData = false
		return resp, false
	}
	// A cached entry may predate a policy/blocklist change: re-inspect its
	// chain so a newly-blocked alias is not served from cache. Evict the
	// poisoned entry so later queries miss and refetch.
	var chainTarget, chainSrc string
	var chainAct filter.BlockAction
	var chainLg, chainHit bool
	if cached {
		chainHit, chainTarget, chainAct, chainSrc, chainLg = inspectChain(out, classifyTarget)
	}
	if chainHit {
		var cbe *chainBlockedError
		if chainTarget != "" {
			cbe = &chainBlockedError{target: chainTarget, action: chainAct, source: chainSrc, shouldLog: chainLg}
		}
		if s.cache != nil {
			s.cache.Delete(key)
		}
		s.cnt.AddBlocked()
		blockedResp := new(dns.Msg)
		blockedResp.SetReply(req)
		blockedResp.RecursionAvailable = true
		blockedResp.AuthenticatedData = false
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
		if s.logfn != nil && lg {
			s.logfn(renderClient(), notifyDomain)
		}
		applyBlockAction(blockedResp, q, act)
		return blockedResp, false
	}
	if out == nil {
		resp.Rcode = dns.RcodeServerFailure
		resp.AuthenticatedData = false
		return resp, false
	}
	out.Id = req.Id
	out.Question = req.Question
	// Delegated DNSSEC (dnssec: true) serves the upstream's AD bit only when
	// the answer came from a trusted upstream (upstream.UDPResolver clears AD
	// for plain UDP/TCP unless trust_ad), the client asked for validation
	// status with DO or AD (RFC 6840 §5.8), and checking was not disabled
	// (RFC 4035 §3.2.3). Capture the pre-gate upstream status first so the
	// query log can mark validated domains even when the client did not ask
	// for AD. Every other case keeps the historical M2 behavior: never assert
	// AD=1 without validation.
	dnssecVerified := s.dnssec.Load() && out.AuthenticatedData && !req.CheckingDisabled
	out.AuthenticatedData = dnssecVerified && (do || req.AuthenticatedData)
	// The upstream may echo an OPT/DO added solely to force validation; align
	// the response with what this client actually sent.
	normalizeResponseOPT(out, req, do)
	// Path-MTU safety: truncate large responses so they fit without IP
	// fragmentation (see responseCap); the client retries over TCP (TC bit)
	// or with a larger OPT buffer. DoH rides HTTPS framing, so its answers
	// are never truncated (a spurious TC bit would only force a useless
	// retry).
	if proto != control.ProtoDoH {
		if cap := responseCap(req, isUDP); out.Len() > cap {
			out.Truncate(cap)
		}
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
			DNSSEC:     dnssecVerified,
			Upstream:   upstreamLabel,
			DurationUs: time.Since(start).Microseconds(),
		})
	}
	return out, false
}

// notifyBlock streams a block event for the query log. Building the event
// renders every answer record, so it is skipped entirely when nobody is
// streaming events.
func (s *Server) notifyBlock(req, resp *dns.Msg, client, domain, list, proto string, start time.Time) {
	if s == nil || !s.ctrl.HasWatchers() {
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
	if req == nil || len(req.Question) == 0 {
		return ""
	}
	return dns.TypeToString[req.Question[0].Qtype]
}

// slowQueryLogPerSec caps emitted slow-query lines so a dead upstream (every
// query slow) cannot flood the journal. Suppressed lines are counted and
// reported on the next line that is emitted.
const slowQueryLogPerSec = 10

// SetSlowQueryThreshold makes blipd log one diagnostic line per query whose
// answer time exceeds d (0 disables). Wired from blipd.yaml slow_query_ms and
// set at startup, before serving, so the read on the hot path needs no lock.
func (s *Server) SetSlowQueryThreshold(d time.Duration) {
	if s == nil {
		return
	}
	if d < 0 {
		d = 0
	}
	s.slowQueryMin = d
}

// logSlowQuery emits the slow-query diagnostic: what was asked, who asked,
// whether the answer came from cache, how long resolution took versus the
// whole query, the rcode and which upstream served it. Clients are identified
// by source IP only (the DoH client-ID is appended verbatim when present but
// is self-asserted, so it is context, not identity).
func (s *Server) logSlowQuery(start time.Time, tr *queryTrace, clientIP net.IP, clientID, proto string, req, resp *dns.Msg) {
	if tr == nil || s == nil {
		return
	}
	total := time.Since(start)
	if total < s.slowQueryMin {
		return
	}
	s.slowLogMu.Lock()
	now := time.Now().Unix()
	if now != s.slowLogWindow {
		s.slowLogWindow, s.slowLogCount = now, 0
	}
	if s.slowLogCount >= slowQueryLogPerSec {
		s.slowLogSuppress++
		s.slowLogMu.Unlock()
		return
	}
	s.slowLogCount++
	suppressed := s.slowLogSuppress
	s.slowLogSuppress = 0
	s.slowLogMu.Unlock()

	cache := "miss"
	if tr.cached {
		cache = "hit"
	}
	up := tr.upstream
	if up == "" {
		up = "-"
	}
	rcode := "none"
	if resp != nil {
		rcode = dns.RcodeToString[resp.Rcode]
	}
	name := ""
	if req != nil && len(req.Question) > 0 {
		name = req.Question[0].Name
	}
	who := clientIP.String()
	if clientID != "" {
		who += " id=" + clientID
	}
	extra := ""
	if suppressed > 0 {
		extra = fmt.Sprintf(" suppressed=%d", suppressed)
	}
	log.Printf("blipd: slow query %s %s client=%s proto=%s cache=%s resolve_ms=%.3f total_ms=%.3f rcode=%s upstream=%s%s",
		name, qType(req), who, proto, cache, float64(tr.resolveUs)/1000, float64(total.Microseconds())/1000, rcode, up, extra)
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
		if rr == nil || rr.Header() == nil {
			continue
		}
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
	if err == nil {
		return "upstream error"
	}
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
	if s == nil || !s.ctrl.HasWatchers() {
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

// newClassicServers builds the UDP and TCP listeners for one address. The
// UDP read buffer is the DNS flag-day 1232: the vendored default (512) would
// FORMERR every query larger than 512 bytes (EDNS padding, large option
// sets, long QNAMEs).
func newClassicServers(addr string, h dns.Handler) (udp, tcp *dns.Server) {
	udp = &dns.Server{Addr: addr, Net: "udp", Handler: h, UDPSize: 1232, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 8 * time.Second }}
	tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: h, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 8 * time.Second }}
	return udp, tcp
}

// Start launches UDP, TCP and DoH listeners (DoH blocks).
func (s *Server) Start() error {
	dh := s.Handler()
	doch := newHTTPServer(s.cfg.DoHAddr, dh)

	udpH := dns.NewServeMux()
	udpH.Handle(".", s)
	udp, tcp := newClassicServers(s.cfg.DNSAddr, udpH)

	s.lifeMu.Lock()
	s.doch = doch
	s.udp = udp
	s.tcp = tcp
	s.lifeMu.Unlock()

	errCh := make(chan error, 2)
	go func() { errCh <- udp.ListenAndServe() }()
	go func() { errCh <- tcp.ListenAndServe() }()

	// give UDP/TCP a moment; any immediate error is fatal. Close the sibling
	// listener: otherwise a half-dead Start orphans a bound socket and the
	// next Start fails with EADDRINUSE on a port nobody serves.
	select {
	case err := <-errCh:
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
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
			// certTLSConfig reads the current pair, so a certificate re-derived
			// at runtime (VIP configured after startup) is served immediately.
			doch.TLSConfig = s.certTLSConfig()
			ln, err := net.Listen("tcp", s.cfg.DoHAddr)
			if err != nil {
				return fmt.Errorf("blipd: doh listen: %w", err)
			}
			return doch.ServeTLS(ln, "", "")
		}
		if s.cfg.CertFile != "" && s.cfg.KeyFile != "" {
			return doch.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
		}
		return fmt.Errorf("blipd: doh_tls enabled but no certificate configured (set cert_file/key_file or tls_dir)")
	}
	return doch.ListenAndServe()
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

// maxRateLimitQPS bounds the per-client QPS to prevent a misconfigured push
// from effectively disabling the limiter via absurd values or exhausting
// memory via burst. Complements the control-layer >=0 check.
const maxRateLimitQPS = 100000

// maxRateLimitBurst bounds the per-client burst.
const maxRateLimitBurst = 100000

// maxCacheSize bounds the runtime cache size to prevent a misconfigured push
// from exhausting memory. Complements the control-layer >=0 check.
const maxCacheSize = 1000000

// SetDNSSEC enables or disables delegated DNSSEC at runtime. Validation is
// still performed by trusted upstreams (trust_ad); the response cache is
// purged because cached answers from one mode must not be served under the
// other (AD and DNSSEC-RR filtering differ).
func (s *Server) SetDNSSEC(enabled bool) {
	if s.dnssec.Swap(enabled) == enabled {
		return
	}
	s.cacheGen.Add(1)
	if s.cache != nil {
		s.cache.Purge()
	}
	if enabled {
		if p := s.safePool(); p != nil && !p.AnyTrusted() {
			log.Printf("blipd: WARNING dnssec enabled but no upstream is trusted; AD will be discarded")
		}
	}
}

// DNSSECEnabled reports whether delegated DNSSEC is enabled.
func (s *Server) DNSSECEnabled() bool { return s.dnssec.Load() }

// SetRateLimit configures the per-client DNS query rate limit (QPS). A qps of 0
// disables rate limiting. burst is the per-client burst above qps; <= 0 means
// auto (qps, min 1).
func (s *Server) SetRateLimit(qps, burst int) error {
	if qps < 0 {
		return fmt.Errorf("qps must be >= 0")
	}
	if burst < 0 {
		burst = 0
	}
	if qps > maxRateLimitQPS {
		return fmt.Errorf("qps %d exceeds max %d", qps, maxRateLimitQPS)
	}
	if burst > maxRateLimitBurst {
		return fmt.Errorf("burst %d exceeds max %d", burst, maxRateLimitBurst)
	}
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

// Refusals reports the top clients by rate-limited queries for the management
// API's stats payload (the dashboard's refused-queries breakdown).
func (s *Server) Refusals() []control.ClientRefusals {
	if s.rl == nil {
		return nil
	}
	return s.rl.refusals(refusalsTopN)
}

// SetCacheConfig tunes the response cache size at runtime: 0 selects the
// bounded default (never unlimited). Must be >= 0 and <= maxCacheSize.
func (s *Server) SetCacheConfig(size int) error {
	if size < 0 {
		return fmt.Errorf("cache size must be >= 0")
	}
	if size == 0 {
		size = cache.DefaultMaxEntries()
	}
	if size > maxCacheSize {
		return fmt.Errorf("cache size %d exceeds max %d", size, maxCacheSize)
	}
	s.cacheMu.Lock()
	s.cacheSize = size
	s.cacheMu.Unlock()
	if s.cache != nil {
		s.cache.SetMaxEntries(size)
	}
	return nil
}

// CacheSize returns the current max cached responses (0 = bounded default).
func (s *Server) CacheSize() int {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.cacheSize
}

// PurgeCache drops every cached response (e.g. from the settings page).
func (s *Server) PurgeCache() {
	if s == nil || s.cache == nil {
		return
	}
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
		s.lifeMu.RLock()
		udp, tcp, doch := s.udp, s.tcp, s.doch
		s.lifeMu.RUnlock()
		if udp != nil {
			_ = udp.Shutdown()
		}
		if tcp != nil {
			_ = tcp.Shutdown()
		}
		if doch != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = doch.Shutdown(ctx)
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

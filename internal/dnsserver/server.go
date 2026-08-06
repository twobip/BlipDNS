// Package dnsserver implements a fast DNS resolver serving classic DNS
// (UDP + TCP) and DNS-over-HTTPS (RFC 8484) on the same query path.
// Requests are filtered per-client, cached with TTL-aware singleflight,
// and forwarded upstream.
package dnsserver

import (
	"crypto/tls"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/twobip/BlipDNS/internal/upstream"
	"github.com/miekg/dns"
)

// maxDNSQueryParam is the maximum base64url length of the DoH GET `dns`
// parameter. A 4096-byte DNS message encodes to ~5462 base64url chars; 8192
// leaves comfortable headroom while bounding the per-request allocation.
const maxDNSQueryParam = 8192

// Config configures a Server.
type Config struct {
	DNSAddr           string // "127.0.0.1:53"
	DoHAddr           string // "127.0.0.1:8443"
	CertFile          string // optional explicit TLS cert/key for DoH
	KeyFile           string // optional explicit TLS cert/key for DoH
	DoHTLS            bool   // serve DoH over HTTPS on DoHAddr (self-signed cert generated when no CertFile/KeyFile)
	DoHHTTPAddr       string // also accept plain-HTTP DoH on this addr ("" = off; toggleable at runtime by the controller)
	TLSCert           *tls.Certificate // in-memory cert+key (e.g. generated self-signed) used when DoHTLS
	Upstream          string // upstream spec(s)
	CacheCap          time.Duration
	CacheSize         int           // max cached responses in RAM (0 = unlimited)
	CacheWarmCount    int           // most-popular entries to auto-refresh (0 = off)
	CacheWarmAhead    time.Duration // refresh a popular entry when its TTL drops below this
	CacheWarmInterval time.Duration // how often to run the warm-refresh loop
	Store             *filter.Store
	Version           string
	Blocklist         *blocklist.Blocklist // global blocklist applied before per-client policy
	BlockAction       filter.BlockAction   // response for global-blocklist hits ("" = nxdomain)
}

// Server is the DNS + DoH resolver.
type Server struct {
	cfg   Config
	cache *cache.Cache
	up    upstream.Resolver
	ctrl  *control.Server
	cnt   *control.Counters
	logfn func(client, domain string)
	udp   *dns.Server
	tcp   *dns.Server
	doch  *http.Server
	// Optional plain-HTTP DoH listener, toggled at runtime by the controller.
	dohPlainMu  sync.Mutex
	dohPlain    *http.Server
	dohPlainAddr string
	close chan struct{}
	once  sync.Once
}

// New builds a Server. If cfg.Store is nil a permissive default is used.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		cfg.Store = filter.NewStore(nil)
	}
	up, err := upstream.FromSpec(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	c := cache.New(cfg.CacheCap, cfg.CacheSize)
	cnt := &control.Counters{}
	ctrl := control.NewServerWithBlocklist("", cfg.Store, c, cnt, cfg.Version, cfg.Blocklist)
	s := &Server{
		cfg:   cfg,
		cache: c,
		up:    up,
		ctrl:  ctrl,
		cnt:   cnt,
		close: make(chan struct{}),
	}
	// Let the management API toggle the optional plain-HTTP DoH listener.
	ctrl.SetDoHController(s)
	return s, nil
}

// ControlServer exposes the management API server (e.g. to mount on an
// existing mux or to wrap with token auth). Caller sets the token.
func (s *Server) ControlServer() *control.Server { return s.ctrl }

// SetMgmtToken enables the management API with the given bearer token.
func (s *Server) SetMgmtToken(tok string) { s.ctrl.SetToken(tok) }

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
	return s.withSecurityHeaders(mux)
}

// withSecurityHeaders attaches defense-in-depth headers to every DoH response,
// including error paths. DoH is an API (binary, never HTML), so these are
// safe defaults.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Defense-in-depth: DoH is binary (application/dns-message), never
		// HTML, so a restrictive CSP makes any future error-page mistake inert.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req *dns.Msg
	switch r.Method {
	case http.MethodGet:
		v := r.URL.Query().Get("dns")
		if v == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		if len(v) > maxDNSQueryParam {
			http.Error(w, "dns parameter too large", http.StatusRequestEntityTooLarge)
			return
		}
		b, err := base64urlDecode(v)
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
		b, err := io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		req = new(dns.Msg)
		if err := req.Unpack(b); err != nil {
			http.Error(w, "bad dns message", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := clientIPFromReq(r)
	clientID := clientIDFromPath(r.URL.Path)
	resp := s.serve(ctx, clientIP, clientID, req)
	buf, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf)
}

// ServeDNS implements dns.Handler for classic DNS.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	resp := s.serve(context.Background(), net.ParseIP(clientIP), "", req)
	_ = w.WriteMsg(resp)
}

// serve is the unified query path: filter -> cache -> upstream. clientID is
// the optional DoH client identity from /dns-query/{client-id}; it overrides
// the IP as the log identity and can select a per-client policy.
func (s *Server) serve(ctx context.Context, clientIP net.IP, clientID string, req *dns.Msg) *dns.Msg {
	start := time.Now()
	client := clientID
	if client == "" {
		client = clientIP.String()
	}
	s.cnt.AddQuery(client)
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		return resp
	}
	q := req.Question[0]
	// The DNS wire format always carries the root dot ("google.com."); strip it
	// so logs and the query log show the bare domain name.
	domain := strings.TrimSuffix(q.Name, ".")

	// Check global blocklist first (applied to all clients)
	if s.cfg.Blocklist != nil && s.cfg.Blocklist.IsBlocked(domain) {
		s.cnt.AddBlocked()
		s.ctrl.Notify(control.WatchEvent{
			Type: "block", At: time.Now(),
			Client: client, Domain: domain,
			DurationUs: time.Since(start).Microseconds(),
		})
		if s.logfn != nil {
			s.logfn(client, domain)
		}
		applyBlockAction(resp, q, s.cfg.BlockAction)
		return resp
	}

	blocked, action, upstreamOverride, log := s.cfg.Store.Classify(clientIP, clientID, domain)
	if blocked {
		s.cnt.AddBlocked()
		s.ctrl.Notify(control.WatchEvent{
			Type: "block", At: time.Now(),
			Client: client, Domain: domain,
			DurationUs: time.Since(start).Microseconds(),
		})
		if log && s.logfn != nil {
			s.logfn(client, domain)
		}
		applyBlockAction(resp, q, action)
		return resp
	}

	if log && s.logfn != nil {
		s.logfn(client, domain)
	}

	// Use policy-specific upstream if provided, else fall back to global
	resolver := s.up
	if upstreamOverride != "" {
		var err error
		resolver, err = upstream.FromSpec(upstreamOverride)
		if err != nil {
			s.cnt.AddUpErr()
			s.notifyUpstreamError(client, domain, fmt.Sprintf("invalid upstream override %q: %v", upstreamOverride, err))
			resp.Rcode = dns.RcodeServerFailure
			return resp
		}
	}

	key := cache.Key(req)
	out, cached, err := s.cache.DoHit(ctx, key, func() (*dns.Msg, error) {
		return resolver.Resolve(ctx, req)
	})
	if err != nil {
		s.cnt.AddUpErr()
		s.notifyUpstreamError(client, domain, err.Error())
		resp.Rcode = dns.RcodeServerFailure
		return resp
	}
	out.Id = req.Id
	out.Question = req.Question

	// Notify pass event for query log (with resolved IPs)
	var ips []string
	for _, rr := range out.Answer {
		switch a := rr.(type) {
		case *dns.A:
			ips = append(ips, a.A.String())
		case *dns.AAAA:
			ips = append(ips, a.AAAA.String())
		}
	}
	s.ctrl.Notify(control.WatchEvent{
		Type:   "pass",
		At:     time.Now(),
		Client: client,
		Domain: domain,
		IPs:    ips,
		// Cached=true when the answer came from the response cache.
		Cached:     cached,
		DurationUs: time.Since(start).Microseconds(),
	})
	return out
}

// notifyUpstreamError streams an upstream failure to the controller so it can
// be shown on the Upstream Errors page.
func (s *Server) notifyUpstreamError(client, domain, msg string) {
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

// startWarmLoop periodically re-resolves the most popular cached responses
// shortly before they expire, so heavy hitters never go stale for clients.
func (s *Server) startWarmLoop() {
	if s.cfg.CacheWarmCount <= 0 {
		return
	}
	interval := s.cfg.CacheWarmInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.close:
				return
			case <-ticker.C:
				s.refreshPopular()
			}
		}
	}()
}

// refreshPopular resolves the top CacheWarmCount cached keys that are stale
// (expired, or expiring within CacheWarmAhead) using the default upstream and
// re-caches the fresh responses. Best-effort: failures are skipped and the
// next pass retries.
func (s *Server) refreshPopular() {
	keys := s.cache.Popular(s.cfg.CacheWarmCount)
	if len(keys) == 0 {
		return
	}
	ahead := s.cfg.CacheWarmAhead
	if ahead <= 0 {
		ahead = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, k := range keys {
		if !s.cache.Stale(k, ahead) {
			continue
		}
		name, qtype, qclass, ok := cache.ParseKey(k)
		if !ok {
			continue
		}
		req := new(dns.Msg)
		req.RecursionDesired = true
		req.Question = []dns.Question{{Name: name, Qtype: qtype, Qclass: qclass}}
		m, err := s.up.Resolve(ctx, req)
		if err != nil {
			continue
		}
		s.cache.Set(k, m)
	}
}

// Start launches UDP, TCP and DoH listeners (DoH blocks).
func (s *Server) Start() error {
	s.startWarmLoop()
	dh := s.Handler()
	s.doch = &http.Server{Addr: s.cfg.DoHAddr, Handler: dh, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}

	udpH := dns.NewServeMux()
	udpH.Handle(".", s)
	s.udp = &dns.Server{Addr: s.cfg.DNSAddr, Net: "udp", Handler: udpH}
	s.tcp = &dns.Server{Addr: s.cfg.DNSAddr, Net: "tcp", Handler: udpH}

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
		if s.cfg.TLSCert != nil {
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{*s.cfg.TLSCert},
				MinVersion:   tls.VersionTLS12,
			}
			ln, err := tls.Listen("tcp", s.cfg.DoHAddr, tlsCfg)
			if err != nil {
				return fmt.Errorf("blipd: doh tls listen: %w", err)
			}
			return s.doch.Serve(ln)
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
	if err := validateAddr("tcp", addr); err != nil {
		return fmt.Errorf("doh http addr %q: %w", addr, err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("doh http listen %s: %w", addr, err)
	}
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	s.dohPlain = srv
	s.dohPlainAddr = addr
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("blipd: doh http listener %s: %v", addr, err)
		}
	}()
	return nil
}

// validateAddr checks that addr parses and (for TCP) carries a port.
func validateAddr(network, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if port == "" {
		return fmt.Errorf("missing port")
	}
	if network == "tcp" && host == "" {
		return nil
	}
	return nil
}

// DoHHTTPAddr reports the address of the optional plain-HTTP DoH listener
// ("" if it is not running).
func (s *Server) DoHHTTPAddr() string {
	s.dohPlainMu.Lock()
	defer s.dohPlainMu.Unlock()
	return s.dohPlainAddr
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
	_ = srv.Close()
	_ = srv.Shutdown(ctx)
}

// Shutdown stops all listeners.
func (s *Server) Shutdown() {
	s.once.Do(func() {
		close(s.close)
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

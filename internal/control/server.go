package control

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
)

// Server exposes the authenticated management API for a blipd instance.
// It also exposes an unauthenticated claim-code adoption handshake so a
// controller can bootstrap trust once without the operator copying tokens.
type Server struct {
	token     string
	tokenMu   sync.RWMutex
	store     *filter.Store
	cache     *cache.Cache
	stats     *Counters
	blocklist *blocklist.Blocklist
	started   time.Time
	version   string
	// logRing retains the process-log tail served by /api/v1/logs
	// (nil = unavailable, e.g. in tests that never set one).
	logRing  *LogRing
	mu       sync.RWMutex
	watchMu  sync.Mutex
	watchers map[chan WatchEvent]struct{}
	// watchCount mirrors len(watchers) as an atomic so the DNS hot path can
	// skip building WatchEvents entirely when no consumer is streaming.
	watchCount atomic.Int64

	// droppedEvents counts WatchEvents dropped because a consumer's buffer was
	// full. The send is non-blocking so the DNS hot path is never stalled.
	droppedEvents atomic.Int64

	// blocklistCachePath persists a received blocklist to disk so a restart
	// keeps blocking without waiting for the controller to re-push.
	blocklistCachePath string

	// adoption (claim-code bootstrap)
	adoptMu    sync.Mutex
	adopted    bool
	claimCode  string
	stateFile  string
	instanceID string
	// adoptFails tracks bad claim-code guesses per source IP, so one
	// attacker burning guesses can't lock out the real operator (and a
	// distributed guesser is still capped by the same small budget each).
	adoptFails map[string]*adoptFail
	// adoptedBy pins the management API to the controller that claimed the
	// instance (peer IP at adoption time, persisted in the state file).
	// Empty = unpinned (pre-pin state files, static-token setups).
	// Loopback peers always bypass the pin so box-local reset keeps working.
	adoptedBy string

	// authFails tracks bad bearer-token guesses per source IP (brute-force
	// guard on the management API): 5 fails => 5min 429. Reset on success.
	// Guarded by authMu (hot path: every authenticated request).
	authMu    sync.Mutex
	authFails map[string]*adoptFail

	// lastRestart tracks the last successful /api/v1/restart so rapid
	// double-clicks (or a retry loop) cannot reboot-loop the node: 30s
	// cooldown, 429 when too soon.
	lastRestart atomic.Int64 // unix nanos; 0 = never

	// ctrls are the runtime pieces of blipd the management API drives,
	// wired incrementally (DNS pieces at construction, host pieces later).
	ctrls Controllers
}

// Controllers bundles the runtime pieces of blipd the management API
// reconfigures live. Each is nil until wired (e.g. API-only mode).
type Controllers struct {
	DoH       DoHController
	RateLimit RateLimitController
	Cache     CacheController
	Records   RecordController
	Upstream  LocalResolverController
	HA        HAController
	Update    UpdateController
}

// controllers snapshots the wired controllers.
func (s *Server) controllers() Controllers {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ctrls
}

// DoHController is the piece of the DNS server the management API can reconfigure
// at runtime: the optional plain-HTTP DoH listener address ("" = off). The
// controller reports it back via stats so its poll loop can converge it.
type DoHController interface {
	SetDoHHTTPAddr(addr string) error
	DoHHTTPAddr() string
}

// SetDoHController wires the DNS server (which owns its DoH listeners) into
// the management API so Settings changes can toggle plain-HTTP DoH live.
func (s *Server) SetDoHController(c DoHController) {
	s.mu.Lock()
	s.ctrls.DoH = c
	s.mu.Unlock()
}

// RateLimitController is the piece of the DNS server the management API can
// reconfigure at runtime: the per-client query rate limit (QPS). The controller
// reports it back via stats so its poll loop can converge it.
type RateLimitController interface {
	SetRateLimit(qps, burst int) error
	RateLimitQPS() int
}

// SetRateLimitController wires the DNS server (which owns its rate limiter)
// into the management API so Settings changes can tune the per-client rate
// limit live.
func (s *Server) SetRateLimitController(c RateLimitController) {
	s.mu.Lock()
	s.ctrls.RateLimit = c
	s.mu.Unlock()
}

// CacheController is the piece of the DNS server the management API can tune
// at runtime: the response cache size limit and an explicit purge. The
// controller reports the config back via stats so its poll loop can converge it.
type CacheController interface {
	SetCacheConfig(size int) error
	CacheSize() int
	PurgeCache()
}

// SetCacheController wires the DNS server (which owns the response cache) into
// the management API so Settings changes can tune it live.
func (s *Server) SetCacheController(c CacheController) {
	s.mu.Lock()
	s.ctrls.Cache = c
	s.mu.Unlock()
}

// SetRecordController wires the DNS server's local-record store into the
// management API so records can be managed at runtime by the controller.
func (s *Server) SetRecordController(c RecordController) {
	s.mu.Lock()
	s.ctrls.Records = c
	s.mu.Unlock()
}

func (s *Server) SetLocalResolverController(c LocalResolverController) {
	s.mu.Lock()
	s.ctrls.Upstream = c
	s.mu.Unlock()
}

// SetHAController wires the local keepalived/VRRP manager into the API.
func (s *Server) SetHAController(c HAController) {
	s.mu.Lock()
	s.ctrls.HA = c
	s.mu.Unlock()
}

// SetUpdateController wires the local updater into the management API.
func (s *Server) SetUpdateController(c UpdateController) {
	s.mu.Lock()
	s.ctrls.Update = c
	s.mu.Unlock()
}

// NewServerWithBlocklist builds a management API server that can also receive
// a controller-managed global blocklist (nil disables the endpoint).
func NewServerWithBlocklist(token string, store *filter.Store, c *cache.Cache, stats *Counters, version string, bl *blocklist.Blocklist) *Server {
	return &Server{
		token:     token,
		store:     store,
		cache:     c,
		stats:     stats,
		blocklist: bl,
		started:   time.Now(),
		version:   version,
		watchers:  make(map[chan WatchEvent]struct{}),
	}
}

// SetLogRing attaches the process-log tail served by /api/v1/logs.
func (s *Server) SetLogRing(r *LogRing) { s.logRing = r }

// ConfigureAdoption initialises the claim-code handshake. If a prior adopted
// state file exists the instance is treated as already adopted (the claim code
// is not regenerated). Otherwise a fresh one-time code is generated and logged
// to the local journal only.
func (s *Server) ConfigureAdoption(stateFile, instanceID string) {
	s.adoptMu.Lock()
	defer s.adoptMu.Unlock()
	s.stateFile = stateFile
	if instanceID == "" {
		if h, err := os.Hostname(); err == nil {
			instanceID = h
		}
	}
	s.instanceID = instanceID

	if stateFile != "" {
		if b, err := os.ReadFile(stateFile); err == nil {
			var st struct {
				Adopted      bool   `json:"adopted"`
				InstanceID   string `json:"instance_id"`
				Token        string `json:"token,omitempty"`
				ControllerIP string `json:"controller_ip,omitempty"`
			}
			if json.Unmarshal(b, &st) == nil && st.Adopted {
				s.adopted = true
				s.claimCode = ""
				s.adoptedBy = st.ControllerIP
				if st.Token != "" {
					s.token = st.Token
				}
				log.Printf("blipd: management already adopted (state %s); claim code not required", stateFile)
				return
			}
		}
	}

	// A token explicitly configured by the operator is already an established
	// trust relationship. Do not require the claim-code bootstrap in that case;
	// otherwise instances added with their admin_token remain misleadingly
	// "pending" forever in the controller.
	s.tokenMu.RLock()
	hasToken := s.token != ""
	s.tokenMu.RUnlock()
	if hasToken {
		s.adopted = true
		s.claimCode = ""
		s.persistAdopted(true)
		log.Printf("blipd: management token configured statically; claim-code adoption not required")
		return
	}

	s.tokenMu.Lock()
	s.token = genToken()
	s.tokenMu.Unlock()
	log.Printf("blipd: WARNING no admin_token configured; generated ephemeral token (set admin_token in config to persist)")
	s.genClaim()
}

func (s *Server) genClaim() {
	s.claimCode = genClaimCode()
	s.adopted = false
	// M9: do NOT log the code value — it is a secret. Box-local retrieval is
	// via the 0600 adopt-code file + one-time stdout in cmd/blipd.
	log.Printf("blipd: adoption code generated (see %s 0600, printed once to stdout)", DefaultAdoptCodeFile)
}

func (s *Server) persistAdopted(adopted bool) {
	if s.stateFile == "" {
		return
	}
	if !adopted {
		_ = os.Remove(s.stateFile)
		return
	}
	b, _ := json.Marshal(struct {
		Adopted      bool      `json:"adopted"`
		InstanceID   string    `json:"instance_id"`
		Token        string    `json:"token,omitempty"`
		ControllerIP string    `json:"controller_ip,omitempty"`
		AdoptedAt    time.Time `json:"adopted_at"`
	}{Adopted: true, InstanceID: s.instanceID, Token: s.currentToken(), ControllerIP: s.adoptedBy, AdoptedAt: time.Now()})
	// 0600: state holds the management token, so no group/world access.
	if err := os.WriteFile(s.stateFile, b, 0600); err != nil {
		log.Printf("blipd: warning: cannot persist adoption state to %s: %v", s.stateFile, err)
	}
	// WriteFile never chmods an existing file; enforce 0600 in case the file
	// predates this mode (e.g. created before hardening). Best-effort, like the
	// querylog chmod — do not fail adoption over a defensive chmod.
	if err := os.Chmod(s.stateFile, 0600); err != nil {
		log.Printf("blipd: warning: cannot chmod adoption state %s: %v", s.stateFile, err)
	}
}

// HasWatchers reports whether any consumer is currently streaming events.
// Event producers check this (one atomic load) to skip building WatchEvent
// payloads — answer rendering, timestamps, slices — that no one would read.
func (s *Server) HasWatchers() bool {
	if s == nil {
		return false
	}
	return s.watchCount.Load() > 0
}

// Notify pushes a WatchEvent to all connected watchers. Sends are
// non-blocking and hold watchMu so handleWatch cannot close a channel
// mid-send (send-on-closed panic). A consumer that cannot keep up has events
// dropped and counted (see droppedEvents) rather than stalling the caller.
func (s *Server) Notify(e WatchEvent) {
	if s == nil || !s.HasWatchers() {
		return
	}
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	for ch := range s.watchers {
		select {
		case ch <- e:
		default:
			s.droppedEvents.Add(1)
		}
	}
}

// Handler returns the http.Handler for the management API. Every route except
// the adoption handshake requires the bearer token.
func (s *Server) Handler() http.Handler {
	return s.handler(false)
}

// LocalHandler returns the management API handler for the local Unix socket.
// The peer is already authorized by the socket's filesystem permissions (0600,
// owned by the blipd user — i.e. root or the service account), so the bearer
// token and controller pin are not required. It serves the exact same routes;
// only the auth gate differs. Never serve this handler on TCP.
func (s *Server) LocalHandler() http.Handler {
	return s.handler(true)
}

// ServeTLS serves the management API over TLS (e.g. when the operator
// provides a management certificate via certFile/keyFile). Plain-HTTP serving
// via Handler()/LocalHandler() is unchanged — this only adds the opt-in TLS
// listener, so existing http:// loopback and LAN use keeps working.
func (s *Server) ServeTLS(addr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// ServeTLSConfig is ServeTLS with an explicit tls.Config instead of cert/key
// files (in-memory certificates, custom roots, mTLS). The config must carry a
// certificate (Certificates or GetCertificate); pass "" cert/key files.
func (s *Server) ServeTLSConfig(addr string, tlsConf *tls.Config) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConf,
	}
	return srv.ListenAndServeTLS("", "")
}

// handler builds the management API mux. local must only be true for the Unix
// socket listener, where the OS filesystem permissions are the auth boundary
// (Pi-hole model: privileged local access needs no password).
func (s *Server) handler(local bool) http.Handler {
	auth := s.auth
	if local {
		// The Unix socket's filesystem permissions are the auth boundary,
		// so the bearer token (and controller pin) are not required. This
		// also works when no token is configured at all.
		auth = func(h http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { h(w, r) }
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", auth(s.handleHealth))
	mux.HandleFunc("/api/v1/stats", auth(s.handleStats))
	mux.HandleFunc("/api/v1/policies", auth(s.handleListPolicies))
	mux.HandleFunc("/api/v1/policy", auth(s.handlePolicy))
	mux.HandleFunc("/api/v1/blocklist", auth(s.handleBlocklist))
	mux.HandleFunc("/api/v1/doh", auth(s.handleDoH))             // toggle plain-HTTP DoH
	mux.HandleFunc("/api/v1/ratelimit", auth(s.handleRateLimit)) // per-client QPS
	mux.HandleFunc("/api/v1/upstream", auth(s.handleUpstream))   // conditional forwarding
	mux.HandleFunc("/api/v1/cache", auth(s.handleCache))         // cache size + auto-refresh
	mux.HandleFunc("/api/v1/cache/purge", auth(s.handleCachePurge))
	mux.HandleFunc("/api/v1/records", auth(s.handleRecords)) // local DNS records
	mux.HandleFunc("/api/v1/ha/status", auth(s.handleHAStatus))
	mux.HandleFunc("/api/v1/ha", auth(s.handleHAConfig))
	mux.HandleFunc("/api/v1/ha/validate", auth(s.handleHAValidate))
	mux.HandleFunc("/api/v1/ha/apply", auth(s.handleHAApply))
	mux.HandleFunc("/api/v1/ha/disable", auth(s.handleHADisable))
	mux.HandleFunc("/api/v1/update", auth(s.handleUpdate))
	mux.HandleFunc("/api/v1/restart", auth(s.handleRestart))
	mux.HandleFunc("/api/v1/logs", auth(s.handleLogs))
	mux.HandleFunc("/api/v1/watch", auth(s.handleWatch))
	// unauthenticated adoption handshake
	mux.HandleFunc("/api/v1/adopt/status", s.handleAdoptStatus)
	mux.HandleFunc("/api/v1/adopt", s.handleAdopt)
	mux.HandleFunc("/api/v1/adopt/reset", auth(s.handleAdoptReset))
	if !local {
		// No route enumeration oracle: unauthenticated hits on unknown
		// paths get the same 401 as known routes instead of 404.
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if s.currentToken() == "" {
				http.Error(w, "management API disabled", http.StatusServiceUnavailable)
				return
			}
			if !s.authenticated(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.NotFound(w, r)
		})
	}
	return s.withSecurityHeaders(mux)
}

// SecurityHeaders attaches defense-in-depth headers to every response,
// including error paths. Shared by the management API and the DoH handler:
// both serve machine-readable bodies (JSON / binary DNS), never HTML, so
// these are safe defaults.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Defense-in-depth: a restrictive CSP makes any future HTML-rendering
		// mistake inert.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// HSTS is only meaningful (and RFC 6797 permits it) over TLS, so skip
		// it on plain-HTTP listeners.
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// withSecurityHeaders adds the shared headers plus a body-size cap for the
// management API (the blocklist endpoint carries its own larger cap).
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL.Path != "/api/v1/blocklist" {
			r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		}
		next.ServeHTTP(w, r)
	}))
}

// checkToken compares the Authorization header against the bearer token in
// constant time ("Bearer " prefix optional).
func checkToken(hdr, want string) bool {
	tok := hdr
	if len(tok) > 7 && tok[:7] == "Bearer " {
		tok = tok[7:]
	}
	if tok == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(want)) == 1
}

func checkClaimCode(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.tokenMu.RLock()
		tok := s.token
		s.tokenMu.RUnlock()
		if tok == "" {
			http.Error(w, "management API disabled", http.StatusServiceUnavailable)
			return
		}
		src := adoptIP(r)
		// Brute-force guard: 5 bad tokens from one IP => 5min 429.
		s.authMu.Lock()
		sweepAuthFailsLocked(s.authFails)
		if f := s.authFails[src]; f != nil && time.Now().Before(f.until) {
			s.authMu.Unlock()
			http.Error(w, "too many attempts; try again later", http.StatusTooManyRequests)
			return
		}
		s.authMu.Unlock()
		if !checkToken(r.Header.Get("Authorization"), tok) {
			s.authMu.Lock()
			if s.authFails == nil {
				s.authFails = make(map[string]*adoptFail)
			}
			// Bound the table so rotating source IPs cannot grow it forever.
			if len(s.authFails) >= maxAuthFailEntries {
				sweepAuthFailsLocked(s.authFails)
				if len(s.authFails) >= maxAuthFailEntries {
					evictOldestAuthFailLocked(s.authFails)
				}
			}
			f := s.authFails[src]
			if f == nil {
				f = &adoptFail{}
				s.authFails[src] = f
			}
			f.count++
			f.seen = time.Now()
			if f.count >= 5 {
				f.until = time.Now().Add(5 * time.Minute)
				f.count = 0
			}
			s.authMu.Unlock()
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Success: clear this IP's failure state.
		s.authMu.Lock()
		if s.authFails != nil {
			delete(s.authFails, src)
		}
		s.authMu.Unlock()
		// Controller pin (set at claim-code adoption): only the adopting
		// controller — or box-local access — may drive the management API.
		if peer := adoptIP(r); s.adoptedBy != "" && peer != s.adoptedBy && !net.ParseIP(peer).IsLoopback() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, HealthResponse{
		OK:            true,
		Uptime:        time.Since(s.started).Round(time.Second).String(),
		Started:       s.started,
		Version:       s.version,
		DroppedEvents: s.droppedEvents.Load(),
	})
}

// handleLogs serves the retained process-log tail, oldest first.
// ?limit caps the lines (default/max = ring capacity).
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.logRing == nil {
		http.Error(w, "process logs unavailable", http.StatusServiceUnavailable)
		return
	}
	n := defaultLogRingCap
	if q := r.URL.Query().Get("limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 {
			n = min(v, defaultLogRingCap)
		}
	}
	writeJSON(w, LogsResponse{Lines: s.logRing.Snapshot(n)})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.stats == nil {
		writeJSON(w, &StatsResponse{})
		return
	}
	st := s.stats.Stats()
	if st != nil {
		st.Cached = s.cache.Len()
		// Add upstream from default policy
		if def, _ := s.store.All(); def != nil {
			st.Upstream = def.Upstream
		}
		// Report the active global blocklist so the controller can detect drift.
		if s.blocklist != nil {
			st.BlocklistCount = s.blocklist.Count()
			st.BlocklistHash = s.blocklist.Checksum()
		}
		// Single controllers snapshot (was 5x RLock per /stats poll).
		ctrls := s.controllers()
		// Report the optional plain-HTTP DoH listener address so the
		// controller can converge it (and surface it in the UI / health).
		if dc := ctrls.DoH; dc != nil {
			st.DohHTTPAddr = dc.DoHHTTPAddr()
		}
		// Report the per-client rate limit so the controller can converge it
		// and surface it in the UI.
		if ifc := ctrls.RateLimit; ifc != nil {
			st.RateLimitQPS = ifc.RateLimitQPS()
		}
		// Report the runtime cache size limit so the controller can converge
		// it after a restart.
		if cc := ctrls.Cache; cc != nil {
			st.CacheSize = cc.CacheSize()
		}
		// Report the local DNS record hash so the controller can converge them
		// (e.g. after a restart) by re-pushing on drift.
		if rc := ctrls.Records; rc != nil {
			if recs, err := rc.GetRecords(); err == nil {
				st.RecordsHash = RecordsHash(recs)
			}
		}
	}
	s.addUpstreamStats(st)
	writeJSON(w, st)
}

// handleDoH toggles the optional plain-HTTP DoH listener at runtime. The
// controller pushes this from the Settings page; an empty http_addr disables it.
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	dc := s.controllers().DoH
	if dc == nil {
		http.Error(w, "doh settings not available on this instance", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"http_addr": dc.DoHHTTPAddr()})
	case http.MethodPut, http.MethodPost:
		var req SetDoHRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("blipd: management: bad request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.HTTPAddr != "" {
			if _, _, err := net.SplitHostPort(req.HTTPAddr); err != nil {
				http.Error(w, "invalid http_addr: must be host:port", http.StatusBadRequest)
				return
			}
		}
		if err := dc.SetDoHHTTPAddr(req.HTTPAddr); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "doh http addr set"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRateLimit gets/sets the per-client DNS query rate limit (QPS). The
// controller pushes this from the Settings page; an empty/qps=0 disables it.
func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	rc := s.controllers().RateLimit
	if rc == nil {
		http.Error(w, "rate limit control not available on this instance", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"qps": rc.RateLimitQPS()})
	case http.MethodPut, http.MethodPost:
		var req SetRateLimitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("blipd: management: bad request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.QPS < 0 {
			http.Error(w, "qps must be >= 0", http.StatusBadRequest)
			return
		}
		// Upper bound: an absurd QPS is either a typo or abuse — it would
		// effectively disable the limiter and can overflow downstream burst
		// math. The controller enforces the same bound, so accepted fleet
		// values are always pushable.
		if req.QPS > maxMgmtRateLimit {
			http.Error(w, "qps too large (max 100000)", http.StatusBadRequest)
			return
		}
		if req.Burst < 0 {
			req.Burst = 0
		}
		if req.Burst > maxMgmtRateLimit {
			http.Error(w, "burst too large (max 100000)", http.StatusBadRequest)
			return
		}
		if err := rc.SetRateLimit(req.QPS, req.Burst); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "rate limit set"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	def, list := s.store.All()
	out := &ListResponse{Policies: make([]*Policy, 0, len(list))}
	for _, p := range list {
		out.Policies = append(out.Policies, fromFilter(p))
	}
	if def != nil {
		out.Default = fromFilter(def)
	}
	writeJSON(w, out)
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var req SetPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("blipd: management: bad request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		fp := toFilter(&req.Policy)
		if req.Policy.ID == "default" {
			// The "default" policy replaces the store's fallback, so it applies
			// to clients that match no scoped policy (the settings panel edits
			// this via id "default").
			s.store.SetDefault(fp)
		} else if err := s.store.SetPolicy(fp); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Policy edits can flip blocked/allowed state: purge responses cached
		// under the previous policy (mirrors the blocklist handler).
		if s.cache != nil {
			s.cache.Purge()
		}
		s.Notify(WatchEvent{Type: "policy", At: time.Now(), Domain: req.Policy.ID})
		writeJSON(w, AckResponse{OK: true, Msg: "policy set"})
	case http.MethodDelete:
		var req DeletePolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			req.ID = r.URL.Query().Get("id")
		} else if req.ID == "" {
			req.ID = r.URL.Query().Get("id")
		}
		if req.ID == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		s.store.RemovePolicy(req.ID)
		// A policy change can flip domains between blocked and allowed, so
		// drop cached responses resolved under the old policy (mirrors the
		// blocklist handler below).
		if s.cache != nil {
			s.cache.Purge()
		}
		writeJSON(w, AckResponse{OK: true, Msg: "policy deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// SetBlocklistCache enables persisting each received blocklist to path, so a
// blipd restart can restore it into RAM instantly. Pass "" to disable.
func (s *Server) SetBlocklistCache(path string) {
	s.blocklistCachePath = path
}

// handleBlocklist replaces the instance's global blocklist with the given
// domains. It accepts a large payload (multi-million entry lists).
func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.blocklist == nil {
		http.Error(w, "blocklist not configured", http.StatusServiceUnavailable)
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 256<<20)) // 256 MiB cap: the largest real lists are tens of MB
	dec.UseNumber()
	var req SetBlocklistRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// F-16: bound the decoded domain count as well as the byte count: a
	// crafted payload under 256 MiB can still decode into tens of millions of
	// strings and OOM the resolver. The controller caps merged lists at 5M;
	// refuse anything clearly beyond that here instead of building it.
	const maxPushDomains = 6_000_000
	if len(req.Domains) > maxPushDomains || len(req.Allowed) > maxPushDomains {
		http.Error(w, "blocklist too large", http.StatusRequestEntityTooLarge)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	log.Printf("blipd: set blocklist from %s domains=%d allowed=%d", host, len(req.Domains), len(req.Allowed))
	s.blocklist.FromDomains(req.Domains)
	s.blocklist.SetAllowed(req.Allowed)
	// A new blocklist can flip domains between blocked and allowed, so drop
	// any cached responses that were resolved under the old list.
	if s.cache != nil {
		s.cache.Purge()
	}
	if s.blocklistCachePath != "" {
		path := s.blocklistCachePath
		go func() {
			if err := s.blocklist.SaveCache(path); err != nil {
				log.Printf("blipd: blocklist cache: %v", err)
			}
		}()
	}
	writeJSON(w, AckResponse{OK: true, Msg: "blocklist updated"})
}

// RecordsHash returns a stable checksum of a record set so the controller can
// detect drift after a restart (mirroring the blocklist checksum). Records are
// sorted before hashing so the checksum is independent of slice order.
func RecordsHash(records []RecordEntry) uint64 {
	sorted := make([]RecordEntry, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Domain != sorted[j].Domain {
			return sorted[i].Domain < sorted[j].Domain
		}
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		if sorted[i].Value != sorted[j].Value {
			return sorted[i].Value < sorted[j].Value
		}
		return sorted[i].TTL < sorted[j].TTL
	})
	h := fnv.New64()
	for _, r := range sorted {
		h.Write([]byte(r.Domain))
		h.Write([]byte{0})
		h.Write([]byte(r.Type))
		h.Write([]byte{0})
		h.Write([]byte(r.Value))
		h.Write([]byte{0})
		h.Write(fmt.Appendf(nil, "%d", r.TTL))
		h.Write([]byte{0})
	}
	return h.Sum64()
}

// handleRecords manages the instance's local DNS records (A/AAAA/CNAME) that are
// answered directly instead of being forwarded upstream.
func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	rc := s.controllers().Records
	if rc == nil {
		http.Error(w, "records not available on this instance", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		recs, err := rc.GetRecords()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, RecordsResponse{Records: recs})
	case http.MethodPut, http.MethodPost:
		var req SetRecordsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("blipd: management: bad request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := rc.SetRecords(req.Records); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "records set"})
	case http.MethodDelete:
		if err := rc.SetRecords(nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "records cleared"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHAStatus(w http.ResponseWriter, r *http.Request) {
	ctrl := s.controllers().HA
	if ctrl == nil {
		http.Error(w, "high availability is not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, ctrl.HAStatus())
}

func (s *Server) handleHAConfig(w http.ResponseWriter, r *http.Request) {
	ctrl := s.controllers().HA
	if ctrl == nil {
		http.Error(w, "high availability is not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var cfg HAConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&cfg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := ctrl.SetHAConfig(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, AckResponse{OK: true, Msg: "high availability configuration saved"})
}

func (s *Server) handleHAValidate(w http.ResponseWriter, r *http.Request) {
	ctrl := s.controllers().HA
	if ctrl == nil {
		http.Error(w, "high availability is not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := ctrl.ValidateHA(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, AckResponse{OK: true, Msg: "high availability configuration is valid"})
}

func (s *Server) handleHAApply(w http.ResponseWriter, r *http.Request) {
	ctrl := s.controllers().HA
	if ctrl == nil {
		http.Error(w, "high availability is not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := ctrl.ApplyHA(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, AckResponse{OK: true, Msg: "high availability applied"})
}

func (s *Server) handleHADisable(w http.ResponseWriter, r *http.Request) {
	ctrl := s.controllers().HA
	if ctrl == nil {
		http.Error(w, "high availability is not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := ctrl.DisableHA(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, AckResponse{OK: true, Msg: "high availability disabled"})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	ctrl := s.controllers().Update
	if ctrl == nil {
		http.Error(w, "remote update is not available", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, ctrl.UpdateStatus())
	case http.MethodPost:
		channel := r.URL.Query().Get("channel")
		if !ValidUpdateChannel(channel) {
			http.Error(w, "channel must be stable or dev", http.StatusBadRequest)
			return
		}
		log.Printf("blipd: audit: update started channel=%q from %s", channel, adoptIP(r))
		if err := ctrl.StartUpdate(channel); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "update started"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRestart restarts this node's blipd service. The response is written
// first: systemd continues the restart job even when this process is killed
// mid-flight by its own cgroup teardown (same pattern as the updater's final
// restart).
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 30s cooldown: a stolen token or retry loop must not reboot-loop the
	// node into a DNS outage.
	if last := s.lastRestart.Load(); last != 0 && time.Since(time.Unix(0, last)) < 30*time.Second {
		http.Error(w, "restart too soon; try again later", http.StatusTooManyRequests)
		return
	}
	s.lastRestart.Store(time.Now().UnixNano())
	log.Printf("blipd: audit: restart requested from %s", adoptIP(r))
	writeJSON(w, AckResponse{OK: true, Msg: "restarting blipd"})
	go func() {
		_ = exec.Command("sudo", "-n", "/usr/bin/systemctl", "restart", "blipd.service").Run()
	}()
}

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// SSE must outlive the API server's absolute Read/WriteTimeout (10 minutes
	// each): the write deadline cuts the stream at 10:00, and the read
	// deadline fires the connection's background read, whose timeout cancels
	// this request's context. Either one made every watch stream die at
	// exactly 10:00 and the controller reconnect on a timer, losing whatever
	// events fell in the gap. Clearing both lets the stream live until the
	// client leaves (the 15s keepalives below keep it healthy).
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Time{})
	ch := make(chan WatchEvent, 4096)
	s.watchMu.Lock()
	// Cap concurrent watchers so one client cannot exhaust fds/memory with
	// thousands of SSE streams.
	if len(s.watchers) >= 100 {
		s.watchMu.Unlock()
		http.Error(w, "too many watchers", http.StatusTooManyRequests)
		return
	}
	s.watchers[ch] = struct{}{}
	s.watchCount.Store(int64(len(s.watchers)))
	s.watchMu.Unlock()
	log.Printf("blipd: watch open")
	defer func() {
		s.watchMu.Lock()
		delete(s.watchers, ch)
		s.watchCount.Store(int64(len(s.watchers)))
		s.watchMu.Unlock()
		close(ch)
		log.Printf("blipd: watch close")
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			writeSSEEvent(w, e)
			flusher.Flush()
		case <-ticker.C:
			// Keepalive: a lightweight stats ping so the controller can
			// detect liveness on the live event stream.
			st := &StatsResponse{}
			if s.stats != nil {
				st = s.stats.Stats()
				st.UpstreamServers = nil
				st.UpstreamRoutes = nil
			}
			writeSSEEvent(w, WatchEvent{Type: "stats", At: time.Now(), Stats: st})
			flusher.Flush()
		}
	}
}

// ---- adoption handshake ----

func (s *Server) handleAdoptStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.adoptMu.Lock()
	adopted := s.adopted
	inst := s.instanceID
	ver := s.version
	s.adoptMu.Unlock()
	// The adopt/status endpoint is unauthenticated. instance_id and version are
	// useful reconnaissance for an attacker (instance fingerprinting, CVE
	// matching), and the controller only needs the `adopted` boolean here — so
	// they are masked unless the caller proves it is the operator (valid bearer
	// token). Operators can read the real values through any authenticated
	// management endpoint.
	if !s.authenticated(r) {
		inst = ""
		ver = ""
	}
	writeJSON(w, AdoptStatus{Adopted: adopted, InstanceID: inst, Version: ver})
}

// authenticated reports whether the request carries the instance's management
// bearer token (i.e. the operator, not a casual visitor).
func (s *Server) authenticated(r *http.Request) bool {
	tok := s.currentToken()
	if tok == "" {
		return false
	}
	return checkToken(r.Header.Get("Authorization"), tok)
}

func (s *Server) currentToken() string {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	return s.token
}

func (s *Server) handleAdopt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req AdoptRequest
	// Bound the body like every other management endpoint so a giant payload
	// cannot be slurped (the claim code itself is a few dozen bytes).
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.adoptMu.Lock()
	defer s.adoptMu.Unlock()
	if s.adopted {
		writeJSON(w, AdoptResponse{Adopted: true, Message: "already adopted"})
		return
	}
	if s.adoptFails == nil {
		s.adoptFails = make(map[string]*adoptFail)
	}
	sweepAuthFailsLocked(s.adoptFails)
	src := adoptIP(r)
	if f := s.adoptFails[src]; f != nil && time.Now().Before(f.until) {
		http.Error(w, "too many attempts; try again later", http.StatusTooManyRequests)
		return
	}
	if req.Code == "" || !checkClaimCode(req.Code, s.claimCode) {
		if len(s.adoptFails) >= maxAuthFailEntries {
			sweepAuthFailsLocked(s.adoptFails)
			if len(s.adoptFails) >= maxAuthFailEntries {
				evictOldestAuthFailLocked(s.adoptFails)
			}
		}
		f := s.adoptFails[src]
		if f == nil {
			f = &adoptFail{}
			s.adoptFails[src] = f
		}
		f.count++
		f.seen = time.Now()
		if f.count >= 5 {
			f.until = time.Now().Add(5 * time.Minute)
			f.count = 0
		}
		writeJSON(w, AdoptResponse{Adopted: false, Message: "invalid code"})
		return
	}
	s.adopted = true
	s.claimCode = ""  // one-time: invalidate immediately
	s.adoptedBy = src // pin the management API to the adopting controller
	s.persistAdopted(true)
	ClearAdoptCodeFile("")
	log.Printf("blipd: instance adopted via claim code")
	writeJSON(w, AdoptResponse{Adopted: true, Token: s.currentToken()})
}

func (s *Server) handleAdoptReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.adoptMu.Lock()
	s.adopted = false
	s.adoptedBy = "" // unpin: the next adoption pins the new controller
	s.adoptFails = make(map[string]*adoptFail)
	s.persistAdopted(false)
	s.genClaim()
	s.adoptMu.Unlock()
	// Rewrite the 0600 code file here (not in the TCP-only adoptAudit
	// wrapper) so resets over the local Unix socket also leave a readable
	// code behind. adoptAudit's rewrite stays as an idempotent best-effort.
	if err := s.WriteAdoptCodeFile(""); err != nil {
		log.Printf("blipd: adopt reset: cannot write code file: %v", err)
	}
	writeJSON(w, AckResponse{OK: true, Msg: "reset; new adoption code generated"})
}

// adoptFail is one source IP's bad-guess state for the claim-code handshake
// (and, via the same shape, for bearer-token guesses on the management API).
type adoptFail struct {
	count int
	until time.Time
	// seen is the last failure time. Unlocked counters expire authFailWindow
	// after it (sliding window, mirroring the controller login limiter) so
	// stale guesses age out instead of accumulating forever.
	seen time.Time
}

// maxAuthFailEntries bounds the brute-force tables so rotating source IPs
// cannot grow them without bound. Expired entries are swept first, then the
// least-recently-used entry is evicted.
const maxAuthFailEntries = 10000

// authFailWindow is the sliding window after which an unlocked (never locked)
// failure counter expires. It mirrors the controller login limiter's
// loginLockWindow so a slow trickle of guesses cannot build up indefinitely.
const authFailWindow = 5 * time.Minute

// maxMgmtRateLimit caps QPS/burst accepted by /api/v1/ratelimit. Anything
// above is a typo or abuse (it would effectively disable the limiter).
const maxMgmtRateLimit = 100_000

// sweepAuthFailsLocked drops expired locks and stale unlocked counters.
// Caller holds authMu or adoptMu.
func sweepAuthFailsLocked(m map[string]*adoptFail) {
	if len(m) == 0 {
		return
	}
	now := time.Now()
	for k, f := range m {
		if f == nil {
			delete(m, k)
			continue
		}
		if !f.until.IsZero() {
			// Locked: drop only once the lock itself expired.
			if now.After(f.until) {
				delete(m, k)
			}
			continue
		}
		// Unlocked counter: expire after a sliding window with no new
		// failures (mirrors the login limiter's window).
		if f.seen.IsZero() || now.Sub(f.seen) > authFailWindow {
			delete(m, k)
		}
	}
}

// evictOldestAuthFailLocked removes the least-recently-used entry so the
// brute-force tables stay bounded under rotating-IP attacks. Entries without
// an active lock are preferred victims; an active lock is evicted only when
// the whole table is locked. Caller holds authMu or adoptMu.
func evictOldestAuthFailLocked(m map[string]*adoptFail) {
	now := time.Now()
	victim := ""
	var oldest time.Time
	for pass := 0; pass < 2 && victim == ""; pass++ {
		first := true
		for k, f := range m {
			if f == nil {
				victim = k
				break
			}
			if pass == 0 && !f.until.IsZero() && now.Before(f.until) {
				continue // active lock: only a second-pass victim
			}
			if first || f.seen.Before(oldest) {
				victim, oldest, first = k, f.seen, false
			}
		}
	}
	if victim != "" {
		delete(m, victim)
	}
}

// adoptIP keys guess tracking on the immediate peer, not X-Forwarded-For
// (spoofable) — same reason the controller's login limiter ignores it.
func adoptIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// MustJSON renders v for SSE streams; encoding/json never fails on the
// protocol structs passed here. Pooled buffer avoids a bytes->string->wire
// double copy per event.
var mustJSONPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func MustJSON(v interface{}) string {
	buf := mustJSONPool.Get().(*bytes.Buffer)
	buf.Reset()
	_ = json.NewEncoder(buf).Encode(v)
	// Encoder appends a trailing newline; strip it for SSE data: framing.
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	s := string(b)
	buf.Reset()
	mustJSONPool.Put(buf)
	return s
}

// writeSSEEvent writes one SSE data frame without the MustJSON string copy.
func writeSSEEvent(w io.Writer, v interface{}) {
	buf := mustJSONPool.Get().(*bytes.Buffer)
	buf.Reset()
	_ = json.NewEncoder(buf).Encode(v)
	b := buf.Bytes()
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
	buf.Reset()
	mustJSONPool.Put(buf)
}

func fromFilter(p *filter.Policy) *Policy {
	return &Policy{
		ID:          p.ID,
		Networks:    p.Networks,
		Clients:     p.Clients,
		Allow:       p.Allow,
		Block:       p.Block,
		BlockAction: string(p.BlockAction),
		Log:         p.Log,
		Upstream:    p.Upstream,
	}
}

func toFilter(p *Policy) *filter.Policy {
	return &filter.Policy{
		ID:          p.ID,
		Networks:    p.Networks,
		Clients:     p.Clients,
		Allow:       p.Allow,
		Block:       p.Block,
		BlockAction: filter.BlockAction(p.BlockAction),
		Log:         p.Log,
		Upstream:    p.Upstream,
	}
}

// genClaimCode returns a 16-char grouped (8-8) claim code from an
// unambiguous 32-symbol alphabet (~80 bits of entropy). It is one-time use
// and rate-limited, so 40 bits was already adequate in practice; the wider
// alphabet space is defense-in-depth against offline brute force if a code
// leaks (e.g. via logs).
func genClaimCode() string {
	const alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("secure claim-code generation failed: %v", err))
	}
	for i := range b {
		b[i] = alpha[int(b[i])%len(alpha)]
	}
	return string(b[:8]) + "-" + string(b[8:])
}

// genToken returns a 32-byte hex token.
func genToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("secure token generation failed: %v", err))
	}
	return fmt.Sprintf("%x", b)
}

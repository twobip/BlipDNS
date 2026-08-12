package control

import (
	"crypto/rand"
	"crypto/subtle"
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
)

// StatsCollector is the read-side the management API needs from the server.
type StatsCollector interface {
	Stats() *StatsResponse
}

// Server exposes the authenticated management API for a blipd instance.
// It also exposes an unauthenticated claim-code adoption handshake so a
// controller can bootstrap trust once without the operator copying tokens.
type Server struct {
	token     string
	store     *filter.Store
	cache     *cache.Cache
	stats     StatsCollector
	blocklist *blocklist.Blocklist
	started   time.Time
	version   string
	mu        sync.RWMutex
	watchMu   sync.Mutex
	watchers  map[chan WatchEvent]struct{}

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
	adoptFails int
	adoptUntil time.Time

	// dohCtrl drives the optional plain-HTTP DoH listener at runtime.
	dohCtrl DoHController
	// rlCtrl drives the per-client DNS query rate limit at runtime.
	rlCtrl RateLimitController
	// cacheCtrl tunes the response cache at runtime.
	cacheCtrl CacheController
	// recCtrl drives the local DNS records at runtime.
	recCtrl    RecordController
	upCtrl     LocalResolverController
	haCtrl     HAController
	updateCtrl UpdateController
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
	s.dohCtrl = c
	s.mu.Unlock()
}

// dohController returns the wired DoH controller (may be nil, e.g. when blipd
// runs API-only without a DNS server).
func (s *Server) dohController() DoHController {
	s.mu.RLock()
	c := s.dohCtrl
	s.mu.RUnlock()
	return c
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
	s.rlCtrl = c
	s.mu.Unlock()
}

// rateLimitController returns the wired rate-limit controller (may be nil).
func (s *Server) rateLimitController() RateLimitController {
	s.mu.RLock()
	c := s.rlCtrl
	s.mu.RUnlock()
	return c
}

// CacheController is the piece of the DNS server the management API can tune
// at runtime: the response cache size limit, the auto-refresh (warm) count,
// and an explicit purge. The controller reports the config back via stats so
// its poll loop can converge it.
type CacheController interface {
	SetCacheConfig(size, warm int, regular time.Duration) error
	CacheSize() int
	CacheWarm() int
	CacheRegular() time.Duration
	PurgeCache()
}

// SetCacheController wires the DNS server (which owns the response cache) into
// the management API so Settings changes can tune it live.
func (s *Server) SetCacheController(c CacheController) {
	s.mu.Lock()
	s.cacheCtrl = c
	s.mu.Unlock()
}

// cacheController returns the wired cache controller (may be nil).
func (s *Server) cacheController() CacheController {
	s.mu.RLock()
	c := s.cacheCtrl
	s.mu.RUnlock()
	return c
}

// SetRecordController wires the DNS server's local-record store into the
// management API so records can be managed at runtime by the controller.
func (s *Server) SetRecordController(c RecordController) {
	s.mu.Lock()
	s.recCtrl = c
	s.mu.Unlock()
}

// recordController returns the wired record controller (may be nil).
func (s *Server) recordController() RecordController {
	s.mu.RLock()
	c := s.recCtrl
	s.mu.RUnlock()
	return c
}

func (s *Server) SetLocalResolverController(c LocalResolverController) {
	s.mu.Lock()
	s.upCtrl = c
	s.mu.Unlock()
}

func (s *Server) localResolverController() LocalResolverController {
	s.mu.RLock()
	c := s.upCtrl
	s.mu.RUnlock()
	return c
}

// SetHAController wires the local keepalived/VRRP manager into the API.
func (s *Server) SetHAController(c HAController) {
	s.mu.Lock()
	s.haCtrl = c
	s.mu.Unlock()
}

func (s *Server) haController() HAController {
	s.mu.RLock()
	c := s.haCtrl
	s.mu.RUnlock()
	return c
}

// SetUpdateController wires the local updater into the management API.
func (s *Server) SetUpdateController(c UpdateController) {
	s.mu.Lock()
	s.updateCtrl = c
	s.mu.Unlock()
}

func (s *Server) updateController() UpdateController {
	s.mu.RLock()
	c := s.updateCtrl
	s.mu.RUnlock()
	return c
}

// NewServer builds a management API server guarded by token.
func NewServer(token string, store *filter.Store, c *cache.Cache, stats StatsCollector, version string) *Server {
	return NewServerWithBlocklist(token, store, c, stats, version, nil)
}

// NewServerWithBlocklist builds a management API server that can also receive
// a controller-managed global blocklist (nil disables the endpoint).
func NewServerWithBlocklist(token string, store *filter.Store, c *cache.Cache, stats StatsCollector, version string, bl *blocklist.Blocklist) *Server {
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
				Adopted    bool   `json:"adopted"`
				InstanceID string `json:"instance_id"`
				Token      string `json:"token,omitempty"`
			}
			if json.Unmarshal(b, &st) == nil && st.Adopted {
				s.adopted = true
				s.claimCode = ""
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
	if s.token != "" {
		s.adopted = true
		s.claimCode = ""
		s.persistAdopted(true)
		log.Printf("blipd: management token configured statically; claim-code adoption not required")
		return
	}

	s.token = genToken()
	log.Printf("blipd: WARNING no admin_token configured; generated ephemeral token (set admin_token in config to persist)")
	s.genClaim()
}

func (s *Server) genClaim() {
	s.claimCode = genClaimCode()
	s.adopted = false
	log.Printf("blipd: ADOPTION CODE = %s  (use it ONCE in the controller to claim this instance; printed to the local journal only)", s.claimCode)
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
		Adopted    bool      `json:"adopted"`
		InstanceID string    `json:"instance_id"`
		Token      string    `json:"token,omitempty"`
		AdoptedAt  time.Time `json:"adopted_at"`
	}{true, s.instanceID, s.token, time.Now()})
	// 0600: state holds the management token, so no group/world access.
	if err := os.WriteFile(s.stateFile, b, 0600); err != nil {
		log.Printf("blipd: warning: cannot persist adoption state to %s: %v", s.stateFile, err)
	}
}

// Notify pushes a WatchEvent to all connected watchers. Sends are
// non-blocking: a consumer that cannot keep up has events dropped and counted
// (see droppedEvents) rather than stalling the caller.
func (s *Server) Notify(e WatchEvent) {
	if s == nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.watchers {
		select {
		case ch <- e:
		default:
			s.droppedEvents.Add(1)
		}
	}
}

// Handler returns the http.Handler for the management API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.auth(s.handleHealth))
	mux.HandleFunc("/api/v1/stats", s.auth(s.handleStats))
	mux.HandleFunc("/api/v1/policies", s.auth(s.handleListPolicies))
	mux.HandleFunc("/api/v1/policy", s.auth(s.handlePolicy))
	mux.HandleFunc("/api/v1/blocklist", s.auth(s.handleBlocklist))
	mux.HandleFunc("/api/v1/doh", s.auth(s.handleDoH))             // toggle plain-HTTP DoH
	mux.HandleFunc("/api/v1/ratelimit", s.auth(s.handleRateLimit)) // per-client QPS
	mux.HandleFunc("/api/v1/upstream", s.auth(s.handleUpstream))   // conditional forwarding
	mux.HandleFunc("/api/v1/cache", s.auth(s.handleCache))         // cache size + auto-refresh
	mux.HandleFunc("/api/v1/cache/purge", s.auth(s.handleCachePurge))
	mux.HandleFunc("/api/v1/records", s.auth(s.handleRecords)) // local DNS records
	mux.HandleFunc("/api/v1/ha/status", s.auth(s.handleHAStatus))
	mux.HandleFunc("/api/v1/ha", s.auth(s.handleHAConfig))
	mux.HandleFunc("/api/v1/ha/install", s.auth(s.handleHAInstall))
	mux.HandleFunc("/api/v1/ha/validate", s.auth(s.handleHAValidate))
	mux.HandleFunc("/api/v1/ha/apply", s.auth(s.handleHAApply))
	mux.HandleFunc("/api/v1/ha/disable", s.auth(s.handleHADisable))
	mux.HandleFunc("/api/v1/update", s.auth(s.handleUpdate))
	mux.HandleFunc("/api/v1/restart", s.auth(s.handleRestart))
	mux.HandleFunc("/api/v1/watch", s.auth(s.handleWatch))
	// unauthenticated adoption handshake
	mux.HandleFunc("/api/v1/adopt/status", s.handleAdoptStatus)
	mux.HandleFunc("/api/v1/adopt", s.handleAdopt)
	mux.HandleFunc("/api/v1/adopt/reset", s.auth(s.handleAdoptReset))
	return s.withSecurityHeaders(mux)
}

// withSecurityHeaders attaches defense-in-depth headers to every blipd
// management API response (including the DoH toggle endpoint). These are JSON
// API responses (never HTML), so the headers are safe defaults.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Defense-in-depth: these are JSON/text API responses (never HTML), so a
		// restrictive CSP makes any future HTML-rendering mistake inert.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL.Path != "/api/v1/blocklist" {
			r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" {
			http.Error(w, "management API disabled", http.StatusServiceUnavailable)
			return
		}
		tok := r.Header.Get("Authorization")
		if len(tok) > 7 && tok[:7] == "Bearer " {
			tok = tok[7:]
		}
		if len(tok) != len(s.token) || subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
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
		// Report the optional plain-HTTP DoH listener address so the
		// controller can converge it (and surface it in the UI / health).
		if dc := s.dohController(); dc != nil {
			st.DohHTTPAddr = dc.DoHHTTPAddr()
		}
		// Report the per-client rate limit so the controller can converge it
		// and surface it in the UI.
		if ifc := s.rateLimitController(); ifc != nil {
			st.RateLimitQPS = ifc.RateLimitQPS()
		}
		// Report the runtime cache config so the controller can converge it
		// (size limit + auto-refresh count) after a restart.
		if cc := s.cacheController(); cc != nil {
			st.CacheSize = cc.CacheSize()
			st.CacheWarm = cc.CacheWarm()
			st.CacheRegular = int(cc.CacheRegular().Seconds())
		}
		// Report the local DNS record hash so the controller can converge them
		// (e.g. after a restart) by re-pushing on drift.
		if rc := s.recordController(); rc != nil {
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
	dc := s.dohController()
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
			http.Error(w, err.Error(), http.StatusBadRequest)
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
	rc := s.rateLimitController()
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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.QPS < 0 {
			http.Error(w, "qps must be >= 0", http.StatusBadRequest)
			return
		}
		if req.Burst < 0 {
			req.Burst = 0
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
			http.Error(w, err.Error(), http.StatusBadRequest)
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
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<31)) // 2 GiB cap
	dec.UseNumber()
	var req SetBlocklistRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
		h.Write([]byte(fmt.Sprintf("%d", r.TTL)))
		h.Write([]byte{0})
	}
	return h.Sum64()
}

// handleRecords manages the instance's local DNS records (A/AAAA/CNAME) that are
// answered directly instead of being forwarded upstream.
func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	rc := s.recordController()
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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := rc.SetRecords(req.Records); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "records set"})
	case http.MethodDelete:
		if err := rc.ClearRecords(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "records cleared"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHAStatus(w http.ResponseWriter, r *http.Request) {
	ctrl := s.haController()
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
	ctrl := s.haController()
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

func (s *Server) handleHAInstall(w http.ResponseWriter, r *http.Request) {
	ctrl := s.haController()
	if ctrl == nil {
		http.Error(w, "high availability is not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := ctrl.InstallHA(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, AckResponse{OK: true, Msg: "keepalived installed"})
}

func (s *Server) handleHAValidate(w http.ResponseWriter, r *http.Request) {
	ctrl := s.haController()
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
	ctrl := s.haController()
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
	ctrl := s.haController()
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
	ctrl := s.updateController()
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
	ch := make(chan WatchEvent, 4096)
	s.watchMu.Lock()
	s.watchers[ch] = struct{}{}
	s.watchMu.Unlock()
	defer func() {
		s.watchMu.Lock()
		delete(s.watchers, ch)
		s.watchMu.Unlock()
		close(ch)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(e))
			flusher.Flush()
		case <-ticker.C:
			st := &StatsResponse{}
			if s.stats != nil {
				st = s.stats.Stats()
			}
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(WatchEvent{Type: "stats", At: time.Now(), Stats: st}))
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
	if s.token == "" {
		return false
	}
	tok := r.Header.Get("Authorization")
	if len(tok) > 7 && tok[:7] == "Bearer " {
		tok = tok[7:]
	}
	return tok != "" && len(tok) == len(s.token) && subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) == 1
}

func (s *Server) handleAdopt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req AdoptRequest
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
	if time.Now().Before(s.adoptUntil) {
		http.Error(w, "too many attempts; try again later", http.StatusTooManyRequests)
		return
	}
	if req.Code == "" || req.Code != s.claimCode {
		s.adoptFails++
		if s.adoptFails >= 5 {
			s.adoptUntil = time.Now().Add(5 * time.Minute)
			s.adoptFails = 0
		}
		writeJSON(w, AdoptResponse{Adopted: false, Message: "invalid code"})
		return
	}
	s.adopted = true
	s.claimCode = "" // one-time: invalidate immediately
	s.persistAdopted(true)
	log.Printf("blipd: instance adopted via claim code")
	writeJSON(w, AdoptResponse{Adopted: true, Token: s.token})
}

func (s *Server) handleAdoptReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.adoptMu.Lock()
	s.adopted = false
	s.adoptFails = 0
	s.adoptUntil = time.Time{}
	s.persistAdopted(false)
	s.genClaim()
	s.adoptMu.Unlock()
	writeJSON(w, AckResponse{OK: true, Msg: "reset; new adoption code generated (see journal)"})
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
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

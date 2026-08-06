package control

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
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

	if s.token == "" {
		s.token = genToken()
		log.Printf("blipd: WARNING no admin_token configured; generated ephemeral token (set admin_token in config to persist)")
	}
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
	if err := os.WriteFile(s.stateFile, b, 0640); err != nil {
		log.Printf("blipd: warning: cannot persist adoption state to %s: %v", s.stateFile, err)
	}
}

// Notify pushes a WatchEvent to all connected watchers.
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
	mux.HandleFunc("/api/v1/watch", s.auth(s.handleWatch))
	// unauthenticated adoption handshake
	mux.HandleFunc("/api/v1/adopt/status", s.handleAdoptStatus)
	mux.HandleFunc("/api/v1/adopt", s.handleAdopt)
	mux.HandleFunc("/api/v1/adopt/reset", s.auth(s.handleAdoptReset))
	return mux
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
		if tok != s.token {
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
		OK:      true,
		Uptime:  time.Since(s.started).Round(time.Second).String(),
		Started: s.started,
		Version: s.version,
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
	}
	writeJSON(w, st)
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

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch := make(chan WatchEvent, 16)
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
	s.adoptMu.Unlock()
	writeJSON(w, AdoptStatus{Adopted: adopted, InstanceID: inst, Version: s.version})
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
		Allow:       p.Allow,
		Block:       p.Block,
		BlockAction: filter.BlockAction(p.BlockAction),
		Log:         p.Log,
		Upstream:    p.Upstream,
	}
}

// genClaimCode returns an 8-char grouped code from an unambiguous alphabet
// (no I/O/0/1), ~40 bits of entropy.
func genClaimCode() string {
	const alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = alpha[(int(time.Now().UnixNano())+i)%len(alpha)]
		}
	}
	for i := range b {
		b[i] = alpha[int(b[i])%len(alpha)]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

// genToken returns a 32-byte hex token.
func genToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

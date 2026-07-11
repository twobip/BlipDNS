package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/twobip/BlipDNS/internal/cache"
	"github.com/twobip/BlipDNS/internal/filter"
)

// StatsCollector is the read-side the management API needs from the server.
type StatsCollector interface {
	Stats() *StatsResponse
}

// Server exposes the authenticated management API for a blipd instance.
type Server struct {
	token    string
	store    *filter.Store
	cache    *cache.Cache
	stats    StatsCollector
	started  time.Time
	version  string
	mu       sync.RWMutex
	watchers map[chan WatchEvent]struct{}
}

// NewServer builds a management API server guarded by token.
func NewServer(token string, store *filter.Store, c *cache.Cache, stats StatsCollector, version string) *Server {
	return &Server{
		token:    token,
		store:    store,
		cache:    c,
		stats:    stats,
		started:  time.Now(),
		version:  version,
		watchers: make(map[chan WatchEvent]struct{}),
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
	mux.HandleFunc("/api/v1/watch", s.auth(s.handleWatch))
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
		if err := s.store.SetPolicy(fp); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.Notify(WatchEvent{Type: "policy", At: time.Now(), Domain: req.Policy.ID})
		writeJSON(w, AckResponse{OK: true, Msg: "policy set"})
	case http.MethodDelete:
		var req DeletePolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// allow ?id= query form
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

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch := make(chan WatchEvent, 16)
	s.mu.Lock()
	s.watchers[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.watchers, ch)
		s.mu.Unlock()
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

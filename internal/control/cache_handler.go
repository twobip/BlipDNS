package control

import (
	"encoding/json"
	"net/http"
)

// handleCache gets/sets the runtime response cache size limit. The controller
// pushes this from the Settings page; an absent value means "0" (unlimited).
func (s *Server) handleCache(w http.ResponseWriter, r *http.Request) {
	cc := s.cacheController()
	if cc == nil {
		http.Error(w, "cache settings not available on this instance", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"size": cc.CacheSize()})
	case http.MethodPut, http.MethodPost:
		var req SetCacheRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Size < 0 {
			http.Error(w, "size must be >= 0", http.StatusBadRequest)
			return
		}
		if err := cc.SetCacheConfig(req.Size); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "cache config set"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCachePurge drops every cached response on this instance and reports how
// many entries were removed.
func (s *Server) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	cc := s.cacheController()
	if cc == nil {
		http.Error(w, "cache settings not available on this instance", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var purged int
	if s.cache != nil {
		purged = s.cache.Len()
	}
	cc.PurgeCache()
	writeJSON(w, PurgeCacheResponse{Purged: purged})
}

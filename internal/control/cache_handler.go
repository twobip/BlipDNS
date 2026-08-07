package control

import (
	"encoding/json"
	"net/http"
)

// handleCache gets/sets the runtime response cache configuration (max size and
// auto-refresh count). The controller pushes this from the Settings page; an
// absent value means "0" (unlimited / auto-refresh off).
func (s *Server) handleCache(w http.ResponseWriter, r *http.Request) {
	cc := s.cacheController()
	if cc == nil {
		http.Error(w, "cache settings not available on this instance", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"size": cc.CacheSize(), "warm": cc.CacheWarm()})
	case http.MethodPut, http.MethodPost:
		var req SetCacheRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Size < 0 || req.Warm < 0 {
			http.Error(w, "size and warm must be >= 0", http.StatusBadRequest)
			return
		}
		if err := cc.SetCacheConfig(req.Size, req.Warm); err != nil {
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

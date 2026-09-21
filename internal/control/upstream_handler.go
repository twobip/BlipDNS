package control

import (
	"encoding/json"
	"log"
	"net/http"
)

// handleUpstream gets/sets the named upstream pool, conditional-forwarding
// routes, and bootstrap DNS servers. The controller pushes this from the
// Settings page (Servers + Conditional forwarding + Bootstrap DNS); an empty
// request reverts to the instance's local (config-file) upstream.
func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
	uc := s.controllers().Upstream
	if uc == nil {
		http.Error(w, "upstream control not available on this instance", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		servers, routes, bootstrap := uc.Upstream()
		writeJSON(w, map[string]interface{}{"servers": servers, "routes": routes, "bootstrap": bootstrap})
	case http.MethodPut, http.MethodPost:
		var req SetUpstreamRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("blipd: management: bad request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		for _, sv := range req.Servers {
			if sv.TimeoutSec < 0 || sv.TimeoutSec > 30 {
				http.Error(w, "timeout_sec must be 0-30 (0 = 5s default)", http.StatusBadRequest)
				return
			}
		}
		for _, sv := range req.Bootstrap {
			if sv.TimeoutSec < 0 || sv.TimeoutSec > 30 {
				http.Error(w, "timeout_sec must be 0-30 (0 = 5s default)", http.StatusBadRequest)
				return
			}
		}
		if err := uc.SetUpstream(req.Servers, req.Routes, req.Bootstrap); err != nil {
			log.Printf("blipd: management: set upstream: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "upstream set"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// addUpstreamStats surfaces the active upstream pool + routes + bootstrap from
// the DNS server (via the management API) so the controller can detect drift
// after a restart.
func (s *Server) addUpstreamStats(st *StatsResponse) {
	if st == nil {
		return
	}
	uc := s.controllers().Upstream
	if uc == nil {
		return
	}
	st.UpstreamServers, st.UpstreamRoutes, st.BootstrapServers = uc.Upstream()
}

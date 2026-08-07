package control

import (
	"encoding/json"
	"net/http"
)

// handleUpstream gets/sets the named upstream pool and conditional-forwarding
// routes. The controller pushes this from the Settings page (Servers +
// Conditional forwarding); an empty request reverts to the instance's local
// (config-file) upstream.
func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
	uc := s.localResolverController()
	if uc == nil {
		http.Error(w, "upstream control not available on this instance", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		servers, routes := uc.Upstream()
		writeJSON(w, map[string]interface{}{"servers": servers, "routes": routes})
	case http.MethodPut, http.MethodPost:
		var req SetUpstreamRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := uc.SetUpstream(req.Servers, req.Routes); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, AckResponse{OK: true, Msg: "upstream set"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// addUpstreamStats surfaces the active upstream pool + routes from the DNS server
// (via the management API) so the controller can detect drift after a restart.
func (s *Server) addUpstreamStats(st *StatsResponse) {
	if st == nil {
		return
	}
	uc := s.localResolverController()
	if uc == nil {
		return
	}
	st.UpstreamServers, st.UpstreamRoutes = uc.Upstream()
}

package controller

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/upstream"
)

// Server is the blipc controller HTTP + UI server.
type Server struct {
	auth  *Auth
	fleet *Fleet
	ui    fs.FS // embedded web assets (index.html etc.)
}

// NewServer builds the controller HTTP server. ui may be nil (API-only).
// username/password configure the login gate; empty password => closed auth.
func NewServer(username, password string, fleet *Fleet, ui fs.FS) *Server {
	return &Server{auth: NewAuth(username, password), fleet: fleet, ui: ui}
}

// Handler returns the controller's HTTP handler (API + UI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Login / logout are unauthenticated (login obviously; logout is idempotent).
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)

	// API (session-gated)
	api := func(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return s.requireAuth(h)
	}
	mux.HandleFunc("/api/instances", api(s.handleInstances))
	mux.HandleFunc("/api/instances/", api(s.handleInstance))            // /add /delete /policies /policy /adopt /adopt/status /adopt/reset /label /query-log
	mux.HandleFunc("/api/queries", api(s.handleQueries))                // query log
	mux.HandleFunc("/api/upstream-errors", api(s.handleUpstreamErrors)) // upstream failure details
	mux.HandleFunc("/api/clients", api(s.handleClients))                // per-client activity
	mux.HandleFunc("/api/client-names", api(s.handleClientNames))       // friendly client renames
	mux.HandleFunc("/api/stats", api(s.handleStats))                    // aggregated query stats for graphs
	mux.HandleFunc("/api/top-domains", api(s.handleTopDomains))         // dashboard most-queried list
	mux.HandleFunc("/api/cache-stats", api(s.handleCacheStats))         // cache hit rate + live cache sizes
	mux.HandleFunc("/api/maintenance", api(s.handleMaintenance))        // POST reset_stats / clear_query_log
	mux.HandleFunc("/api/events", api(s.handleEvents))
	mux.HandleFunc("/api/health", api(s.handleHealth))
	mux.HandleFunc("/api/settings", api(s.handleSettings)) // fleet-wide default config
	mux.HandleFunc("/api/cache/purge", api(s.handleCachePurge))

	// Blocklist (session-gated)
	mux.HandleFunc("/api/blocklist", api(s.handleBlocklist))                     // GET list / POST add / DELETE remove
	mux.HandleFunc("/api/blocklist/export", api(s.handleBlocklistExport))        // GET text
	mux.HandleFunc("/api/blocklist/sources", api(s.handleBlocklistSources))      // PUT sources + import / GET status
	mux.HandleFunc("/api/blocklist/status", api(s.handleBlocklistStatus))        // GET import progress
	mux.HandleFunc("/api/blocklist/clear-log", api(s.handleBlocklistClearLog))   // POST clear import output
	mux.HandleFunc("/api/blocklist/import-url", api(s.handleBlocklistImportURL)) // POST fetch from URL (legacy)

	// UI: login page is public; static assets (js/css) are public; everything
	// else requires a session. Assets hold no secrets and must load as relative
	// sub-resources; the control plane (/api/*) stays session-gated.
	if s.ui != nil {
		mux.Handle("/", s.securityHeaders(http.HandlerFunc(s.serveUI)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "blipc: no UI embedded (API only)", http.StatusNotFound)
		})
	}
	return s.securityHeaders(mux)
}

// securityHeaders applies defense-in-depth headers to every response.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' https://unpkg.com; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.Authed(r) {
			w.Header().Set("WWW-Authenticate", "Bearer realm=\"blipc\"")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// handleLogin authenticates a username/password and mints a session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	// bound the body so a giant payload can't be slurped
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.auth.Configured() {
		http.Error(w, "authentication not configured", http.StatusForbidden)
		return
	}
	id, err := s.auth.Login(req.Username, req.Password, ClientIP(r))
	if err != nil {
		if err == errLocked {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.auth.MintCookie(w, r, id)
	writeJSON(w, map[string]bool{"ok": true})
}

// handleLogout invalidates the session and clears the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.auth.Destroy(r)
	s.auth.ClearCookie(w, r)
	writeJSON(w, map[string]bool{"ok": true})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.fleet.List())
	case http.MethodPost:
		var cfg InstanceConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfg = ResolveTokenFile(cfg)
		if err := s.fleet.Add(r.Context(), cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"ok": "added", "id": cfg.ID})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInstance serves /api/instances/<id>[/policies|/policy].
func (s *Server) handleInstance(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/instances/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	ctx := r.Context()

	switch sub {
	case "policies":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		l, err := s.fleet.ListPolicies(ctx, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, l)
	case "policy":
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			var p control.Policy
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := s.fleet.SetPolicy(ctx, id, &p); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			writeJSON(w, map[string]string{"ok": "set", "id": p.ID})
			return
		}
		if r.Method == http.MethodDelete {
			pid := r.URL.Query().Get("id")
			if err := s.fleet.DeletePolicy(ctx, id, pid); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			writeJSON(w, map[string]string{"ok": "deleted", "id": pid})
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	case "adopt/status":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		st, err := s.fleet.GetAdoptStatus(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, st)
	case "adopt":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := s.fleet.Adopt(ctx, id, req.Code); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"ok": "adopted", "id": id})
	case "adopt/reset":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.fleet.ResetAdoption(ctx, id); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]string{"ok": "reset", "id": id})
	case "label":
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Label string `json:"label"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Label == "" {
			http.Error(w, "label required", http.StatusBadRequest)
			return
		}
		if err := s.fleet.SetLabel(ctx, id, req.Label); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]string{"ok": "label updated", "id": id})
	case "query-log":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.fleet.queryLog == nil {
			http.Error(w, "query log not available", http.StatusServiceUnavailable)
			return
		}
		instance := r.URL.Query().Get("instance")
		filter := r.URL.Query().Get("filter")
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			fmt.Sscanf(l, "%d", &limit)
		}
		since := time.Now().Add(-24 * time.Hour)
		if s := r.URL.Query().Get("since"); s != "" {
			if d, err := time.ParseDuration(s); err == nil {
				since = time.Now().Add(-d)
			}
		}
		entries, err := s.fleet.queryLog.Query(ctx, instance, filter, since, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, entries)
	case "": // delete instance
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.fleet.Remove(id)
		writeJSON(w, map[string]string{"ok": "removed", "id": id})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// handleSettings reads/updates the fleet default policy and per-instance
// overrides. blipc is the source of truth; PUT persists the change and
// distributes the effective config (default for the fleet scope, merged
// default+override for an instance scope).
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		upServers, upRoutes := s.fleet.Upstream()
		cacheSize, cacheWarm := s.fleet.CacheConfig()
		writeJSON(w, map[string]interface{}{
			"default_policy":            s.fleet.DefaultPolicy(),
			"instance_overrides":        s.fleet.InstanceOverrides(),
			"doh_http_addr":             s.fleet.DoHHTTPAddr(),
			"rate_limit_qps":            s.fleet.RateLimitQPS(),
			"upstream_servers":          upServers,
			"upstream_routes":           upRoutes,
			"cache_size":                cacheSize,
			"cache_warm":                cacheWarm,
			"query_log_retention_hours": s.fleet.QueryLogRetentionHours(),
		})
	case http.MethodPut:
		var req struct {
			Scope                  string                     `json:"scope"`
			Policy                 *control.Policy            `json:"default_policy"`
			Instance               string                     `json:"instance"`
			Override               *InstanceOverride          `json:"override"`
			DoHHTTPAddr            *string                    `json:"doh_http_addr"`
			RateLimitQPS           *int                       `json:"rate_limit_qps"`
			CacheSize              *int                       `json:"cache_size"`
			CacheWarm              *int                       `json:"cache_warm"`
			QueryLogRetentionHours *int                       `json:"query_log_retention_hours"`
			UpstreamServers        *[]upstream.UpstreamServer `json:"upstream_servers"`
			UpstreamRoutes         *[]upstream.UpstreamRoute  `json:"upstream_routes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Plain-HTTP DoH toggle (fleet-wide or per-instance), applied on its
		// own so it can be saved independently of the upstream editor.
		if req.DoHHTTPAddr != nil {
			addr := *req.DoHHTTPAddr
			if addr != "" {
				if _, _, err := net.SplitHostPort(addr); err != nil {
					http.Error(w, "invalid doh_http_addr: must be host:port", http.StatusBadRequest)
					return
				}
			}
			if req.Scope == "instance" && req.Instance != "" {
				existing := s.fleet.InstanceOverrideOf(req.Instance)
				merged := mergeOverride(existing, &InstanceOverride{DoHHTTPAddr: req.DoHHTTPAddr})
				// empty address on an instance means "inherit the fleet-wide
				// default": clear any previously set per-instance value.
				if *req.DoHHTTPAddr == "" {
					merged.DoHHTTPAddr = nil
				}
				applied := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
				return
			}
			applied := s.fleet.SetDoHHTTPAddr(r.Context(), addr)
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		// Query log retention (controller-local: the log is stored on blipc,
		// so there is no per-instance scope and nothing to push).
		if req.QueryLogRetentionHours != nil {
			hours := *req.QueryLogRetentionHours
			if !ValidQueryLogRetentionHours(hours) {
				http.Error(w, "invalid query_log_retention_hours: must be 24, 168, 720, 4320 or 8760", http.StatusBadRequest)
				return
			}
			applied := s.fleet.SetQueryLogRetention(r.Context(), hours)
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		// Per-client DNS rate limit (fleet-wide or per-instance).
		if req.RateLimitQPS != nil {
			qps := *req.RateLimitQPS
			if qps < 0 {
				qps = 0
			}
			if req.Scope == "instance" && req.Instance != "" {
				existing := s.fleet.InstanceOverrideOf(req.Instance)
				merged := mergeOverride(existing, &InstanceOverride{RateLimitQPS: req.RateLimitQPS})
				if qps == 0 {
					merged.RateLimitQPS = nil
				}
				applied := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
				return
			}
			applied := s.fleet.SetRateLimitQPS(r.Context(), qps)
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		// Response cache settings (fleet-wide or per-instance): max size and
		// auto-refresh count. Zero values mean "unlimited"/"off"; on an
		// instance scope they fall through to the fleet-wide default.
		if req.CacheSize != nil || req.CacheWarm != nil {
			cacheSize, cacheWarm := 0, 0
			if req.CacheSize != nil {
				cacheSize = *req.CacheSize
			}
			if req.CacheWarm != nil {
				cacheWarm = *req.CacheWarm
			}
			if cacheSize < 0 || cacheWarm < 0 {
				http.Error(w, "cache size and warm count must be >= 0", http.StatusBadRequest)
				return
			}
			if req.Scope == "instance" && req.Instance != "" {
				existing := s.fleet.InstanceOverrideOf(req.Instance)
				merged := mergeOverride(existing, &InstanceOverride{CacheSize: req.CacheSize, CacheWarm: req.CacheWarm})
				// Zero values mean "inherit the fleet-wide default": clear any
				// previously set per-instance value.
				if req.CacheSize != nil && cacheSize == 0 {
					merged.CacheSize = nil
				}
				if req.CacheWarm != nil && cacheWarm == 0 {
					merged.CacheWarm = nil
				}
				applied := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
				return
			}
			applied := s.fleet.SetCache(r.Context(), cacheSize, cacheWarm)
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		// Upstream server pool + conditional-forwarding routes (fleet-wide or
		// per-instance). The arrays are sent whole from the upstream editor;
		// an empty array clears the value (per-instance: falls through to the
		// fleet-wide default) while an absent field is left untouched so a
		// servers-only save does not wipe the fleet routes (and vice-versa).
		if req.UpstreamServers != nil || req.UpstreamRoutes != nil {
			// An absent field keeps the current value (fleet default or an
			// existing per-instance override); an explicitly-empty array clears
			// it (per-instance: falls through to the fleet-wide default). The
			// resulting pool is validated before persisting, so a bad server
			// spec or a route to an unknown server is rejected up front instead
			// of being saved and failing every push to the instances.
			fleetServers, fleetRoutes := s.fleet.Upstream()
			if req.Scope == "instance" && req.Instance != "" {
				existing := s.fleet.InstanceOverrideOf(req.Instance)
				merged := mergeOverride(existing, &InstanceOverride{
					UpstreamServers: req.UpstreamServers,
					UpstreamRoutes:  req.UpstreamRoutes,
				})
				if req.UpstreamServers != nil && len(*req.UpstreamServers) == 0 {
					merged.UpstreamServers = nil
				}
				if req.UpstreamRoutes != nil && len(*req.UpstreamRoutes) == 0 {
					merged.UpstreamRoutes = nil
				}
				effServers, effRoutes := fleetServers, fleetRoutes
				if merged.UpstreamServers != nil {
					effServers = *merged.UpstreamServers
				}
				if merged.UpstreamRoutes != nil {
					effRoutes = *merged.UpstreamRoutes
				}
				if _, err := upstream.NewPool(effServers, effRoutes, ""); err != nil {
					http.Error(w, "invalid upstream: "+err.Error(), http.StatusBadRequest)
					return
				}
				applied := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
				return
			}
			if req.UpstreamServers != nil {
				fleetServers = *req.UpstreamServers
			}
			if req.UpstreamRoutes != nil {
				fleetRoutes = *req.UpstreamRoutes
			}
			if _, err := upstream.NewPool(fleetServers, fleetRoutes, ""); err != nil {
				http.Error(w, "invalid upstream: "+err.Error(), http.StatusBadRequest)
				return
			}
			applied := s.fleet.SetUpstream(r.Context(), fleetServers, fleetRoutes)
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		// Default policy / per-instance policy fields. Per-instance edits are
		// merged onto any existing override so saving upstream doesn't wipe a
		// previously saved DoH override (and vice-versa).
		if req.Scope == "instance" && req.Instance != "" {
			existing := s.fleet.InstanceOverrideOf(req.Instance)
			merged := mergeOverride(existing, req.Override)
			applied := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		if req.Policy == nil {
			http.Error(w, "default_policy required", http.StatusBadRequest)
			return
		}
		applied := s.fleet.SetDefaultPolicy(r.Context(), req.Policy)
		writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	out := map[string]interface{}{
		"instances": s.fleet.Health(),
	}
	if s.fleet.queryLog != nil {
		out["query_log_dropped"] = s.fleet.queryLog.DroppedEvents()
	}
	writeJSON(w, out)
}

func (s *Server) handleQueries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.fleet.queryLog == nil {
		http.Error(w, "query log not available", http.StatusServiceUnavailable)
		return
	}
	instance := r.URL.Query().Get("instance")
	filter := r.URL.Query().Get("filter")
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			since = time.Now().Add(-d)
		}
	}
	entries, err := s.fleet.queryLog.Query(r.Context(), instance, filter, since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, entries)
}

// handleClients returns per-client activity (DoH client IDs and source IPs).
func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.fleet.queryLog == nil {
		http.Error(w, "query log not available", http.StatusServiceUnavailable)
		return
	}
	instance := r.URL.Query().Get("instance")
	limit := 250
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			since = time.Now().Add(-d)
		}
	}
	stats, err := s.fleet.queryLog.ClientStats(r.Context(), instance, since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, stats)
}

// handleClientNames manages the client → friendly-name mapping used for
// display only; the raw client ID/IP is never rewritten.
func (s *Server) handleClientNames(w http.ResponseWriter, r *http.Request) {
	if s.fleet.queryLog == nil {
		http.Error(w, "query log not available", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		names, err := s.fleet.queryLog.ClientNames(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, names)
	case http.MethodPut:
		var req struct {
			Client string `json:"client"`
			Name   string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Client == "" {
			http.Error(w, "client required", http.StatusBadRequest)
			return
		}
		if err := s.fleet.queryLog.SetClientName(r.Context(), req.Client, req.Name); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.fleet.queryLog == nil {
		http.Error(w, "query log not available", http.StatusServiceUnavailable)
		return
	}
	instance := r.URL.Query().Get("instance")
	bucketSize := 5 * time.Minute
	if b := r.URL.Query().Get("bucket"); b != "" {
		if d, err := time.ParseDuration(b); err == nil {
			bucketSize = d
		}
	}
	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			since = time.Now().Add(-d)
		}
	}
	agg, err := s.fleet.queryLog.AggregateStats(r.Context(), instance, bucketSize, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// The dashboard errors stat must match the Upstream Errors page, which
	// reads the upstream_errors table (and is cleared by "Clear errors").
	// Override the counter-derived value so clearing the page zeroes the stat.
	n, err := s.fleet.queryLog.UpstreamErrorCount(r.Context(), instance, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	agg.UpstreamErrors = n
	writeJSON(w, agg)
}

// handleTopDomains returns the most-queried domains within the requested
// range, most frequent first, for the dashboard's Top Queried Domains panel.
func (s *Server) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.fleet.queryLog == nil {
		http.Error(w, "query log not available", http.StatusServiceUnavailable)
		return
	}
	instance := r.URL.Query().Get("instance")
	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			since = time.Now().Add(-d)
		}
	}
	domains, err := s.fleet.queryLog.TopDomains(r.Context(), instance, since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]interface{}{"domains": domains})
}

// handleCacheStats reports per-instance cache hit rates over the query-log
// window plus the current in-memory cache size (domains held) and configured
// limit for each instance, from the last stats poll.
func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.fleet.queryLog == nil {
		http.Error(w, "query log not available", http.StatusServiceUnavailable)
		return
	}
	instance := r.URL.Query().Get("instance")
	since := time.Now().Add(-24 * time.Hour)
	if d, err := time.ParseDuration(r.URL.Query().Get("since")); err == nil {
		since = time.Now().Add(-d)
	}
	perInstance, err := s.fleet.queryLog.CacheStats(r.Context(), instance, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	total := InstanceCacheStat{}
	for _, c := range perInstance {
		total.Queries += c.Queries
		total.CachedQueries += c.CachedQueries
	}
	if total.Queries > 0 {
		total.PercentCached = float64(total.CachedQueries) / float64(total.Queries) * 100
	}
	live := make(map[string]int)
	limit := make(map[string]int)
	for _, is := range s.fleet.List() {
		if is.Stats != nil {
			live[is.ID] = is.Stats.Cached
			limit[is.ID] = is.Stats.CacheSize
		}
	}
	writeJSON(w, map[string]interface{}{
		"total":        total,
		"per_instance": perInstance,
		"live":         live,
		"limit":        limit,
	})
}

// handleUpstreamErrors returns upstream failures grouped by message/domain/
// instance, most frequent first, within the requested range.
func (s *Server) handleUpstreamErrors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.fleet.queryLog == nil {
		http.Error(w, "query log not available", http.StatusServiceUnavailable)
		return
	}
	instance := r.URL.Query().Get("instance")
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			since = time.Now().Add(-d)
		}
	}
	stats, err := s.fleet.queryLog.UpstreamErrorStats(r.Context(), instance, since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	total := 0
	for _, st := range stats {
		total += st.Count
	}
	writeJSON(w, map[string]interface{}{"total": total, "errors": stats})
}

// handleMaintenance handles destructive maintenance actions: reset_stats
// (clear + re-baseline aggregated statistics), clear_query_log and
// clear_upstream_errors (optionally filtered to one instance).
func (s *Server) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Action   string `json:"action"`
		Instance string `json:"instance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch req.Action {
	case "reset_stats":
		if s.fleet.queryLog == nil {
			http.Error(w, "query log not available", http.StatusServiceUnavailable)
			return
		}
		if err := s.fleet.queryLog.ClearStatsSamples(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "clear_query_log":
		if s.fleet.queryLog == nil {
			http.Error(w, "query log not available", http.StatusServiceUnavailable)
			return
		}
		if err := s.fleet.queryLog.ClearQueryLog(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "clear_upstream_errors":
		if s.fleet.queryLog == nil {
			http.Error(w, "query log not available", http.StatusServiceUnavailable)
			return
		}
		if err := s.fleet.queryLog.ClearUpstreamErrors(r.Context(), req.Instance); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch, backlog := s.fleet.Bus().Subscribe()
	defer s.fleet.Bus().Unsubscribe(ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	for _, e := range backlog {
		fmt.Fprintf(w, "data: %s\n\n", mustJSON(e))
	}
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(e))
			flusher.Flush()
		}
	}
}

// handleCachePurge drops every cached response on every adopted instance and
// reports how many entries were removed fleet-wide.
func (s *Server) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	applied, total := s.fleet.PurgeCache(r.Context())
	writeJSON(w, map[string]interface{}{"ok": true, "applied": applied, "purged": total})
}

func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		domains := s.fleet.ManualDomains()
		if lim := r.URL.Query().Get("limit"); lim != "" {
			if n, err := strconv.Atoi(lim); err == nil && n > 0 && len(domains) > n {
				domains = domains[:n]
			}
		}
		writeJSON(w, map[string]interface{}{
			"domains": domains,
			"allowed": s.fleet.AllowedDomains(),
			"total":   s.fleet.Blocklist().Count(),
			"sources": s.fleet.BlocklistSources(),
			"status":  s.fleet.BlocklistStatus(),
		})
	case http.MethodPost, http.MethodDelete:
		var req struct {
			Domain string `json:"domain"`
			Allow  bool   `json:"allow"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Domain == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost {
			if req.Allow {
				s.fleet.AddAllowedDomain(req.Domain)
			} else {
				s.fleet.AddManualDomain(req.Domain)
			}
			writeJSON(w, map[string]string{"ok": "added"})
		} else {
			if req.Allow {
				s.fleet.RemoveAllowedDomain(req.Domain)
			} else {
				s.fleet.RemoveManualDomain(req.Domain)
			}
			writeJSON(w, map[string]string{"ok": "removed"})
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBlocklistExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	for _, d := range s.fleet.Blocklist().List() {
		fmt.Fprintln(w, d)
	}
}

func (s *Server) handleBlocklistImportURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	// Treat the URL as the (sole) source, Pi-hole style, and import async so a
	// huge list never blocks the request.
	s.fleet.SetBlocklistSources(r.Context(), []string{req.URL})
	writeJSON(w, map[string]interface{}{"ok": true, "running": true})
}

// handleBlocklistSources manages the Pi-hole style source URLs.
func (s *Server) handleBlocklistSources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"sources": s.fleet.BlocklistSources(),
			"status":  s.fleet.BlocklistStatus(),
		})
	case http.MethodPut, http.MethodPost:
		var req struct {
			URLs            []string `json:"urls"`
			AutoUpdateHours *int     `json:"auto_update_hours"`
			ClearManual     bool     `json:"clear_manual"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.AutoUpdateHours != nil {
			s.fleet.SetAutoUpdateHours(*req.AutoUpdateHours)
		}
		urls := cleanURLs(req.URLs)
		if len(urls) == 0 {
			// Saving an empty source list clears the blocklist.
			s.fleet.SetBlocklistSources(r.Context(), nil)
			s.fleet.Blocklist().FromDomains(nil)
			if req.ClearManual {
				s.fleet.ClearManualDomains()
				s.fleet.ClearAllowedDomains()
			}
			s.fleet.persistBlocklist()
			writeJSON(w, map[string]interface{}{"ok": true, "count": 0})
			return
		}
		s.fleet.SetBlocklistSources(r.Context(), urls)
		writeJSON(w, map[string]interface{}{"ok": true, "running": true, "sources": urls})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBlocklistStatus reports import progress / last result.
func (s *Server) handleBlocklistStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.fleet.BlocklistStatus())
}

// handleBlocklistClearLog drops the buffered import output shown in the UI.
func (s *Server) handleBlocklistClearLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.fleet.ClearImportLog()
	writeJSON(w, map[string]interface{}{"ok": true})
}

// serveUI dispatches inbound HTTP to embedded assets (public) or the SPA
// (session-gated) or the login page (public).
func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	// Public static assets: js/css/svg/ico/png embed token-free, served without
	// a session so browsers can load them as relative sub-resources.
	if isUIAsset(r.URL.Path) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		b, err := fs.ReadFile(s.ui, name)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType(name))
		_, _ = w.Write(b)
		return
	}

	// Public login page (must be reachable without a session).
	if r.URL.Path == "/login" || r.URL.Path == "/login.html" {
		b, err := fs.ReadFile(s.ui, "login.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
		return
	}

	// Everything else is a session-gated SPA route.
	if !s.auth.Authed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	b, err := fs.ReadFile(s.ui, "index.html")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func isUIAsset(p string) bool {
	switch {
	case strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".css"),
		strings.HasSuffix(p, ".svg"), strings.HasSuffix(p, ".ico"),
		strings.HasSuffix(p, ".png"):
		return true
	}
	return false
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".js"):
		return "application/javascript"
	case strings.HasSuffix(name, ".css"):
		return "text/css"
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".ico"):
		return "image/x-icon"
	}
	return "application/octet-stream"
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

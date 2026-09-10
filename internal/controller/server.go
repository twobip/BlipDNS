package controller

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/upstream"
)

// Server is the blipc controller HTTP + UI server.
type Server struct {
	auth       *Auth
	fleet      *Fleet
	ui         fs.FS // embedded web assets (index.html etc.)
	configPath string
	setupToken string
	setupMu    sync.Mutex
	sweepOnce  sync.Once
	selfUpdate *SelfUpdater
}

// NewServer builds the controller HTTP server. ui may be nil (API-only).
// username/password configure the login gate; empty password => closed auth.
// It is intended for tests and API-only callers; first-run setup is disabled.
func NewServer(username, password string, fleet *Fleet, ui fs.FS) *Server {
	return NewServerWithConfig(username, password, fleet, ui, "", "")
}

// NewServerWithConfig is NewServer plus the config path and one-time setup
// token used by first-run setup.
func NewServerWithConfig(username, password string, fleet *Fleet, ui fs.FS, configPath, setupToken string) *Server {
	return &Server{auth: NewAuth(username, password), fleet: fleet, ui: ui, configPath: configPath, setupToken: setupToken, selfUpdate: NewSelfUpdater()}
}

// NewSetupToken returns a cryptographically random token for first-run setup.
func NewSetupToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Handler returns the controller's HTTP handler (API + UI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.sweepOnce.Do(func() {
		go func() {
			t := time.NewTicker(10 * time.Minute)
			defer t.Stop()
			for range t.C {
				s.auth.Sweep()
			}
		}()
	})

	// Login / setup / logout are unauthenticated. Setup is only accepted while
	// the server remains unconfigured; Auth.Configure makes it one-time.
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/setup", s.handleSetup)
	mux.HandleFunc("/api/logout", s.handleLogout)
	// Key management is session-only (never bearer): a key must not mint keys.
	mux.HandleFunc("/api/keys", s.handleAPIKeys)

	// API (session-gated)
	api := func(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return s.requireAuth(h)
	}
	mux.HandleFunc("/api/instances", api(s.handleInstances))
	mux.HandleFunc("/api/instances/update", api(s.handleInstanceUpdate))
	mux.HandleFunc("/api/instances/restart", api(s.handleInstanceRestart))
	mux.HandleFunc("/api/instances/", api(s.handleInstance))            // /add /delete /policies /policy /adopt /adopt/status /adopt/reset /label /query-log
	mux.HandleFunc("/api/queries", api(s.handleQueries))                // query log
	mux.HandleFunc("/api/upstream-errors", api(s.handleUpstreamErrors)) // upstream failure details
	mux.HandleFunc("/api/upstream/test", api(s.handleUpstreamTest))     // POST test query against given upstreams
	mux.HandleFunc("/api/clients", api(s.handleClients))                // per-client activity
	mux.HandleFunc("/api/client-names", api(s.handleClientNames))       // friendly client renames
	mux.HandleFunc("/api/stats", api(s.handleStats))                    // aggregated query stats for graphs
	mux.HandleFunc("/api/top-domains", api(s.handleTopDomains))         // dashboard most-queried list
	mux.HandleFunc("/api/cache-stats", api(s.handleCacheStats))         // cache hit rate + live cache sizes
	mux.HandleFunc("/api/maintenance", api(s.handleMaintenance))        // POST reset_stats / clear_query_log
	mux.HandleFunc("/api/events", api(s.handleEvents))
	mux.HandleFunc("/api/health", api(s.handleHealth))
	mux.HandleFunc("/api/records", api(s.handleRecords))
	mux.HandleFunc("/api/settings", api(s.handleSettings)) // fleet-wide default config
	mux.HandleFunc("/api/update", api(s.handleSelfUpdate)) // controller self-update
	mux.HandleFunc("/api/high-availability", api(s.handleHighAvailability))
	mux.HandleFunc("/api/cache/purge", api(s.handleCachePurge))

	// Blocklist (session-gated)
	mux.HandleFunc("/api/blocklist", api(s.handleBlocklist))                   // GET list / POST add / DELETE remove
	mux.HandleFunc("/api/blocklist/export", api(s.handleBlocklistExport))      // GET text
	mux.HandleFunc("/api/blocklist/sources", api(s.handleBlocklistSources))    // PUT sources + import / GET status
	mux.HandleFunc("/api/blocklist/source", api(s.handleBlocklistSource))      // POST enable/disable one source
	mux.HandleFunc("/api/blocklist/status", api(s.handleBlocklistStatus))      // GET import progress
	mux.HandleFunc("/api/blocklist/clear-log", api(s.handleBlocklistClearLog)) // POST clear import output

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
		// The SPA shell and embedded assets (app.js/style.css) are versioned by
		// the binary, not the URL, so a rebuild must reach the browser without
		// a manual cache clear. These responses are also session-gated/owned, so
		// disable caching entirely: stale JS is the #1 "my edit didn't take" bug.
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.Authed(r) && !s.auth.validAPIKey(bearerToken(r)) {
			w.Header().Set("WWW-Authenticate", "Bearer realm=\"blipc\"")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// bearerToken extracts a "Bearer <token>" API key from the request.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return h[7:]
	}
	return ""
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

// handleSetup creates the first controller credentials and immediately signs
// the operator in. It is deliberately unavailable after the first success.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.auth.Configured() {
		http.Error(w, "setup already completed", http.StatusForbidden)
		return
	}
	var req struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.setupToken == "" || len(req.Token) != len(s.setupToken) || subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.setupToken)) != 1 {
		http.Error(w, "invalid setup token", http.StatusForbidden)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 1 || len(req.Username) > 64 {
		http.Error(w, "username must be between 1 and 64 characters", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 || len(req.Password) > 72 {
		http.Error(w, "password must be between 8 and 72 characters", http.StatusBadRequest)
		return
	}
	if req.Password != req.Confirm {
		http.Error(w, "passwords do not match", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "could not secure password", http.StatusInternalServerError)
		return
	}
	if s.configPath == "" {
		http.Error(w, "setup persistence is unavailable", http.StatusInternalServerError)
		return
	}
	if err := persistCredentials(s.configPath, req.Username, string(hash)); err != nil {
		http.Error(w, "could not save credentials", http.StatusInternalServerError)
		return
	}
	if !s.auth.Configure(req.Username, string(hash)) {
		http.Error(w, "setup already completed", http.StatusForbidden)
		return
	}
	id, err := s.auth.Login(req.Username, req.Password, ClientIP(r))
	if err != nil {
		http.Error(w, "could not start session", http.StatusInternalServerError)
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

// handleAPIKeys manages expiring bearer keys for /api/* (debug sharing
// without sharing the password). Session-only: bearer keys are accepted on
// every other /api/* route but never here, so a key cannot mint more keys.
// Keys live in memory — a controller restart revokes them all.
func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Authed(r) {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"blipc\"")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		keys := s.auth.ListAPIKeys()
		if keys == nil {
			keys = []APIKeyInfo{}
		}
		writeJSON(w, map[string]interface{}{"keys": keys})
	case http.MethodPost:
		var req struct {
			Label    string `json:"label"`
			TTLHours int    `json:"ttl_hours"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		id, secret, expires, err := s.auth.CreateAPIKey(req.Label, time.Duration(req.TTLHours)*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]interface{}{"id": id, "key": secret, "expires_at": expires})
	case http.MethodDelete:
		if !s.auth.RevokeAPIKey(r.URL.Query().Get("id")) {
			http.Error(w, "unknown key", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// handleSelfUpdate starts (POST) or reports (GET) the controller's own update.
func (s *Server) handleSelfUpdate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"version": ControllerVersion(),
			"status":  s.selfUpdate.UpdateStatus(),
		})
	case http.MethodPost:
		channel := r.URL.Query().Get("channel")
		if !control.ValidUpdateChannel(channel) {
			http.Error(w, "channel must be stable or dev", http.StatusBadRequest)
			return
		}
		if err := s.selfUpdate.StartUpdate(channel); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "status": s.selfUpdate.UpdateStatus()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleInstanceUpdate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.fleet.UpdateJob())
	case http.MethodPost:
		channel := s.fleet.ReleaseChannel()
		if requested := r.URL.Query().Get("channel"); requested != "" {
			channel = requested
		}
		job, err := s.fleet.StartUpdates(r.Context(), channel)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, job)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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

// handleInstanceRestart asks one adopted node to restart its blipd service.
func (s *Server) handleInstanceRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	if err := s.fleet.RestartInstance(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "msg": "restarting " + req.ID})
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
		action := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("action")))
		if action != "" && action != "PASS" && action != "BLOCK" {
			action = ""
		}
		cached := strings.TrimSpace(r.URL.Query().Get("cached"))
		if cached != "" && cached != "0" && cached != "1" {
			cached = ""
		}
		limit := boundedLimit(r, 100, 500)
		offset := boundedOffset(r)
		since := time.Now().Add(-boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour))
		entries, err := s.fleet.queryLog.Query(ctx, instance, filter, action, cached, since, offset, limit)
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

// handleRecords manages the fleet-wide local DNS records (A/AAAA/CNAME). blipd
// is the runtime store; blipc persists the fleet-wide set and pushes it to every
// adopted instance, reconciling on poll.
func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"records": s.fleet.Records()})
	case http.MethodPut, http.MethodPost:
		var req struct {
			Records []control.RecordEntry `json:"records"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		applied := s.fleet.SetRecords(r.Context(), req.Records)
		writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
	case http.MethodDelete:
		applied := s.fleet.SetRecords(r.Context(), nil)
		writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
		cacheSize := s.fleet.CacheConfig()
		writeJSON(w, map[string]interface{}{
			"default_policy":            s.fleet.DefaultPolicy(),
			"instance_overrides":        s.fleet.InstanceOverrides(),
			"doh_http_addr":             s.fleet.DoHHTTPAddr(),
			"rate_limit_qps":            s.fleet.RateLimitQPS(),
			"upstream_servers":          upServers,
			"upstream_routes":           upRoutes,
			"upstream_bootstrap":        s.fleet.UpstreamBootstrap(),
			"cache_size":                cacheSize,
			"query_log_retention_hours": s.fleet.QueryLogRetentionHours(),
			"records":                   s.fleet.Records(),
			"release_channel":           s.fleet.ReleaseChannel(),
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
			QueryLogRetentionHours *int                       `json:"query_log_retention_hours"`
			UpstreamServers        *[]upstream.UpstreamServer `json:"upstream_servers"`
			UpstreamRoutes         *[]upstream.UpstreamRoute  `json:"upstream_routes"`
			UpstreamBootstrap      *[]upstream.UpstreamServer `json:"upstream_bootstrap"`
			ReleaseChannel         *string                    `json:"release_channel"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.ReleaseChannel != nil {
			if err := s.fleet.SetReleaseChannel(*req.ReleaseChannel); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]interface{}{"ok": true, "release_channel": s.fleet.ReleaseChannel()})
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
		// Response cache size (fleet-wide or per-instance). Zero means
		// "unlimited"; on an instance scope it falls through to the
		// fleet-wide default.
		if req.CacheSize != nil {
			cacheSize := *req.CacheSize
			if cacheSize < 0 {
				http.Error(w, "cache size must be >= 0", http.StatusBadRequest)
				return
			}
			if req.Scope == "instance" && req.Instance != "" {
				existing := s.fleet.InstanceOverrideOf(req.Instance)
				merged := mergeOverride(existing, &InstanceOverride{CacheSize: req.CacheSize})
				// Zero values mean "inherit the fleet-wide default": clear any
				// previously set per-instance value.
				if cacheSize == 0 {
					merged.CacheSize = nil
				}
				applied := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
				return
			}
			applied := s.fleet.SetCache(r.Context(), cacheSize)
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		// Upstream server pool + conditional-forwarding routes + bootstrap DNS
		// (fleet-wide or per-instance). The arrays are sent whole from the
		// upstream editor; an empty array clears the value (per-instance: falls
		// through to the fleet-wide default) while an absent field is left
		// untouched so a servers-only save does not wipe the fleet routes (and
		// vice-versa).
		if req.UpstreamServers != nil || req.UpstreamRoutes != nil || req.UpstreamBootstrap != nil {
			// An absent field keeps the current value (fleet default or an
			// existing per-instance override); an explicitly-empty array clears
			// it (per-instance: falls through to the fleet-wide default). The
			// resulting pool is validated before persisting, so a bad server
			// spec or a route to an unknown server is rejected up front instead
			// of being saved and failing every push to the instances.
			fleetServers, fleetRoutes := s.fleet.Upstream()
			fleetBootstrap := s.fleet.UpstreamBootstrap()
			if req.Scope == "instance" && req.Instance != "" {
				existing := s.fleet.InstanceOverrideOf(req.Instance)
				merged := mergeOverride(existing, &InstanceOverride{
					UpstreamServers:   req.UpstreamServers,
					UpstreamRoutes:    req.UpstreamRoutes,
					UpstreamBootstrap: req.UpstreamBootstrap,
				})
				if req.UpstreamServers != nil && len(*req.UpstreamServers) == 0 {
					merged.UpstreamServers = nil
				}
				if req.UpstreamRoutes != nil && len(*req.UpstreamRoutes) == 0 {
					merged.UpstreamRoutes = nil
				}
				if req.UpstreamBootstrap != nil && len(*req.UpstreamBootstrap) == 0 {
					merged.UpstreamBootstrap = nil
				}
				effServers, effRoutes, effBootstrap := fleetServers, fleetRoutes, fleetBootstrap
				if merged.UpstreamServers != nil {
					effServers = *merged.UpstreamServers
				}
				if merged.UpstreamRoutes != nil {
					effRoutes = *merged.UpstreamRoutes
				}
				if merged.UpstreamBootstrap != nil {
					effBootstrap = *merged.UpstreamBootstrap
				}
				if _, err := upstream.NewPoolWithBootstrap(effServers, effRoutes, "", effBootstrap); err != nil {
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
			if req.UpstreamBootstrap != nil {
				fleetBootstrap = *req.UpstreamBootstrap
			}
			if _, err := upstream.NewPoolWithBootstrap(fleetServers, fleetRoutes, "", fleetBootstrap); err != nil {
				http.Error(w, "invalid upstream: "+err.Error(), http.StatusBadRequest)
				return
			}
			applied := s.fleet.SetUpstream(r.Context(), fleetServers, fleetRoutes, fleetBootstrap)
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

func (s *Server) handleHighAvailability(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cluster := s.fleet.HACluster()
		// VRRP passwords are write-only: the UI keeps any value already typed
		// locally, while API reads never disclose credentials.
		cluster.Primary.AuthPass = ""
		cluster.Secondary.AuthPass = ""
		writeJSON(w, map[string]interface{}{"cluster": cluster, "statuses": s.fleet.HAStatuses(r.Context())})
	case http.MethodPut:
		var req struct {
			Cluster control.HACluster `json:"cluster"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// VRRP authentication is write-only. An empty password on an update
		// means "keep the existing password"; clearing it is intentionally not
		// exposed through the general save path.
		current := s.fleet.HACluster()
		if req.Cluster.Primary.AuthPass == "" && req.Cluster.Secondary.AuthPass == "" {
			req.Cluster.Primary.AuthPass = current.Primary.AuthPass
			req.Cluster.Secondary.AuthPass = current.Secondary.AuthPass
		}
		if err := s.fleet.SetHACluster(r.Context(), req.Cluster); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	case http.MethodPost:
		action := r.URL.Query().Get("action")
		cluster := s.fleet.HACluster()
		var err error
		switch action {
		case "validate":
			err = s.fleet.ValidateHA(r.Context(), cluster)
		case "apply":
			err = s.fleet.ApplyHA(r.Context(), cluster)
		case "disable":
			err = s.fleet.DisableHA(r.Context(), cluster)
		default:
			http.Error(w, "unknown high availability action", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
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
	// action: "" (any), "PASS" or "BLOCK"
	action := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("action")))
	if action != "" && action != "PASS" && action != "BLOCK" {
		action = ""
	}
	// cached: "" (any), "1" (cached only), "0" (uncached only)
	cached := strings.TrimSpace(r.URL.Query().Get("cached"))
	if cached != "" && cached != "0" && cached != "1" {
		cached = ""
	}
	limit := boundedLimit(r, 100, 500)
	offset := boundedOffset(r)
	since := time.Now().Add(-boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour))
	entries, err := s.fleet.queryLog.Query(r.Context(), instance, filter, action, cached, since, offset, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	total, err := s.fleet.queryLog.QueryCount(r.Context(), instance, filter, action, cached, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]interface{}{
		"entries":  entries,
		"total":    total,
		"has_more": len(entries) == limit && offset+limit < total,
	})
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
	limit := boundedLimit(r, 250, 500)
	since := time.Now().Add(-boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour))
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
		if len(req.Client) > 256 || len(req.Name) > 128 {
			http.Error(w, "client/name too long", http.StatusBadRequest)
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
	bucketSize := boundedDuration(r, "bucket", 5*time.Minute, time.Second, 24*time.Hour)
	since := time.Now().Add(-boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour))
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
// range, most frequent first, for the dashboard panels. action filters by
// query outcome: "" (any), "PASS" (Top Queried) or "BLOCK" (Top Blocked).
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
	limit := boundedLimit(r, 10, 100)
	since := time.Now().Add(-boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour))
	// action: "" (any), "PASS" or "BLOCK"
	action := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("action")))
	if action != "" && action != "PASS" && action != "BLOCK" {
		action = ""
	}
	domains, err := s.fleet.queryLog.TopDomains(r.Context(), instance, since, limit, action)
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
	since := time.Now().Add(-boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour))
	topLimit := boundedLimit(r, 50, 200)
	topOffset := boundedOffset(r)
	perInstance, err := s.fleet.queryLog.CacheStats(r.Context(), instance, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	topCached, err := s.fleet.queryLog.TopCachedDomains(r.Context(), instance, since, topOffset, topLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	topTotal, err := s.fleet.queryLog.TopCachedDomainsCount(r.Context(), instance, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	total := InstanceCacheStat{}
	var cachedSum, fetchedSum float64
	var cachedN, fetchedN int
	for _, c := range perInstance {
		total.Queries += c.Queries
		total.CachedQueries += c.CachedQueries
		cachedN += c.CachedQueries
		fetchedN += c.Queries - c.CachedQueries
		cachedSum += c.AvgCachedUs * float64(c.CachedQueries)
		fetchedSum += c.AvgFetchedUs * float64(c.Queries-c.CachedQueries)
	}
	if total.Queries > 0 {
		total.PercentCached = float64(total.CachedQueries) / float64(total.Queries) * 100
	}
	if cachedN > 0 {
		total.AvgCachedUs = cachedSum / float64(cachedN)
	}
	if fetchedN > 0 {
		total.AvgFetchedUs = fetchedSum / float64(fetchedN)
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
		"total":            total,
		"per_instance":     perInstance,
		"live":             live,
		"limit":            limit,
		"top_cached":       topCached,
		"top_cached_total": topTotal,
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
	limit := boundedLimit(r, 100, 500)
	since := time.Now().Add(-boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour))
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

// handleUpstreamTest probes each given upstream with one A query (default
// example.com) and reports per-server reachability + latency. The probes run
// from blipc itself, concurrently, each bounded by its server timeout —
// useful to validate the editor contents before saving. This deliberately
// stays blipc-local: it does not touch instances or the control.Client.
func (s *Server) handleUpstreamTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Servers []upstream.UpstreamServer `json:"servers"`
		Domain  string                    `json:"domain"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Servers) == 0 {
		http.Error(w, "no servers to test", http.StatusBadRequest)
		return
	}
	if len(req.Servers) > 32 {
		http.Error(w, "too many servers (max 32)", http.StatusBadRequest)
		return
	}
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		domain = "example.com"
	}
	if len(domain) > 253 {
		http.Error(w, "domain too long", http.StatusBadRequest)
		return
	}
	// Cap the whole fan-out; individual probes time out sooner via their own
	// per-server timeout.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	// DoH endpoints given as hostnames (e.g. dns.quad9.net) resolve through
	// the fleet's bootstrap servers when configured, instead of blipc's
	// system resolver — the same path blipd itself uses. The bootstrap
	// resolver is cached on the fleet so DoH keep-alives survive across Test
	// clicks instead of paying a fresh TLS handshake (and RST risk) per click.
	bootstrap, err := s.fleet.ProbeBootstrap()
	if err != nil {
		http.Error(w, "bad bootstrap servers: "+err.Error(), http.StatusBadRequest)
		return
	}
	results := make([]upstream.ProbeResult, len(req.Servers))
	var wg sync.WaitGroup
	for i, sv := range req.Servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = upstream.ProbeServerWithBootstrap(ctx, sv, domain, bootstrap)
		}()
	}
	wg.Wait()
	writeJSON(w, map[string]interface{}{"domain": domain, "results": results})
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
	case "reset_stats", "clear_query_log", "clear_upstream_errors":
		if s.fleet.queryLog == nil {
			http.Error(w, "query log not available", http.StatusServiceUnavailable)
			return
		}
		var err error
		switch req.Action {
		case "reset_stats":
			err = s.fleet.queryLog.ClearStatsSamples(r.Context())
		case "clear_query_log":
			err = s.fleet.queryLog.ClearQueryLog(r.Context())
		case "clear_upstream_errors":
			err = s.fleet.queryLog.ClearUpstreamErrors(r.Context(), req.Instance)
		}
		if err != nil {
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
		fmt.Fprintf(w, "data: %s\n\n", control.MustJSON(e))
	}
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", control.MustJSON(e))
			flusher.Flush()
		case <-time.After(15 * time.Second):
			fmt.Fprint(w, ": keepalive\n\n")
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

// handleBlocklistSource toggles a single source URL on/off. Disabling a source
// removes its domains from the active blocklist (and every instance); enabling
// restores them on the next import.
func (s *Server) handleBlocklistSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	url := strings.TrimSpace(req.URL)
	if url == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	s.fleet.SetBlocklistSourceEnabled(r.Context(), url, req.Enabled)
	writeJSON(w, map[string]interface{}{"ok": true, "enabled": req.Enabled})
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
	if !s.auth.Configured() && (r.URL.Path == "/" || r.URL.Path == "/setup" || r.URL.Path == "/setup.html" || r.URL.Path == "/login" || r.URL.Path == "/login.html") {
		s.serveUIFile(w, "setup.html")
		return
	}
	// Public static assets: js/css/svg/ico/png embed token-free, served without
	// a session so browsers can load them as relative sub-resources.
	if isUIAsset(r.URL.Path) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		name = filepath.Clean(name)
		if name == "." || strings.HasPrefix(name, ".."+string(filepath.Separator)) || name == ".." {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.serveUIFile(w, name)
		return
	}

	// Public login page (must be reachable without a session).
	if r.URL.Path == "/login" || r.URL.Path == "/login.html" {
		s.serveUIFile(w, "login.html")
		return
	}

	// Everything else is a session-gated SPA route.
	if !s.auth.Authed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.serveUIFile(w, "index.html")
}

// serveUIFile writes one embedded UI file with its content type.
func (s *Server) serveUIFile(w http.ResponseWriter, name string) {
	b, err := fs.ReadFile(s.ui, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType(name))
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
	if strings.HasSuffix(name, ".js") {
		return "application/javascript" // historical; the mime DB says text/javascript
	}
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}

// persistCredentials updates only the auth keys in the existing YAML document,
// preserving fleet settings and comments written by the operator.
func persistCredentials(path, username, passwordHash string) error {
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var doc yaml.Node
	if len(b) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	} else if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("config root must be a YAML mapping")
	}
	root := doc.Content[0]
	set := func(key, value string) {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == key {
				root.Content[i+1].Kind = yaml.ScalarNode
				root.Content[i+1].Tag = "!!str"
				root.Content[i+1].Value = value
				return
			}
		}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
		)
	}
	set("username", username)
	set("password_hash", passwordHash)
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "password" {
			root.Content = append(root.Content[:i], root.Content[i+2:]...)
			break
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".blipc-setup-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"github.com/twobip/BlipDNS/internal/blocklist"
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
	// trustedProxies gates X-Forwarded-For/Proto/Host for reverse-proxy
	// deployments. Nil/empty = forwarded headers are never trusted.
	trustedProxies *ProxyTrust
	// probeMu guards probeHits: per-IP sliding-window counts for
	// /api/upstream/test (10/min each), so the endpoint cannot be used as
	// an unthrottled LAN port-scan oracle.
	probeMu   sync.Mutex
	probeHits map[string][]time.Time
	// StrictCSRF, when true, fails closed on state-changing session-authed
	// requests that carry no Origin/Referer/Sec-Fetch-Site (indistinguishable
	// from forged legacy-browser posts) and rejects bodies without
	// Content-Type: application/json. Default false for backward
	// compatibility: existing API clients and tests omit Origin, while the
	// dashboard always sends Origin or Sec-Fetch-Site. Enable in production
	// where all legitimate callers are browsers or JSON API clients.
	StrictCSRF bool
}

// maxProbeEntries bounds the probe-limiter table: rotating IPs must not
// grow it forever.
const maxProbeEntries = 10000

// probeAllowed reports whether ip may probe upstreams now (10 requests per
// rolling minute) and records the attempt.
func (s *Server) probeAllowed(ip string) bool {
	if ip == "" {
		ip = "unknown"
	}
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if s.probeHits == nil {
		s.probeHits = make(map[string][]time.Time)
	}
	hits := s.probeHits[ip][:0]
	for _, t := range s.probeHits[ip] {
		if t.After(cutoff) {
			hits = append(hits, t)
		}
	}
	if len(hits) >= 10 {
		s.probeHits[ip] = hits
		return false
	}
	if _, ok := s.probeHits[ip]; !ok && len(s.probeHits) >= maxProbeEntries {
		sweepProbeHitsLocked(s.probeHits, now)
		if len(s.probeHits) >= maxProbeEntries {
			evictOldestProbeLocked(s.probeHits)
		}
	}
	s.probeHits[ip] = append(hits, now)
	return true
}

// sweepProbeHitsLocked drops keys with no in-window hits. Caller holds probeMu.
func sweepProbeHitsLocked(m map[string][]time.Time, now time.Time) {
	cutoff := now.Add(-time.Minute)
	for k, hits := range m {
		keep := false
		for _, t := range hits {
			if t.After(cutoff) {
				keep = true
				break
			}
		}
		if !keep {
			delete(m, k)
		}
	}
}

// evictOldestProbeLocked removes the key with the stalest latest hit.
// Caller holds probeMu.
func evictOldestProbeLocked(m map[string][]time.Time) {
	victim := ""
	var oldest time.Time
	first := true
	for k, hits := range m {
		var latest time.Time
		for _, t := range hits {
			if t.After(latest) {
				latest = t
			}
		}
		if first || latest.Before(oldest) {
			victim, oldest, first = k, latest, false
		}
	}
	if victim != "" {
		delete(m, victim)
	}
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

// SetTrustedProxies configures which immediate peers may supply
// X-Forwarded-For/Proto/Host (reverse proxy / Cloudflare Tunnel).
// Empty clears the trust (forwarded headers ignored). Behind a
// TLS-terminating proxy this list is required for more than client-IP
// accuracy: without it session cookies mint without Secure and CSRF Origin
// checks compare against the internal scheme/host.
func (s *Server) SetTrustedProxies(values []string) error {
	pt, err := ParseTrustedProxies(values)
	if err != nil {
		return err
	}
	s.trustedProxies = pt
	return nil
}

// getTrust returns the effective proxy trust: Fleet's persisted value when a
// fleet is attached (UI-managed), else the startup-set Server value (tests /
// API-only). Parsed per call — dashboard QPS is low, correctness over caching.
func (s *Server) getTrust() *ProxyTrust {
	if s.fleet != nil {
		if pt, err := ParseTrustedProxies(s.fleet.TrustedProxies()); err == nil {
			return pt
		}
	}
	return s.trustedProxies
}

func (s *Server) clientIP(r *http.Request) string {
	return s.getTrust().ClientIP(r)
}

func (s *Server) isSecure(r *http.Request) bool {
	return s.getTrust().IsSecure(r)
}

func (s *Server) requestHost(r *http.Request) string {
	return s.getTrust().RequestHost(r)
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
	mux.HandleFunc("/api/settings", api(s.handleSettings))        // fleet-wide default config
	mux.HandleFunc("/api/setup/listen", api(s.handleSetupListen)) // dashboard bind address (setup wizard)
	mux.HandleFunc("/api/update", api(s.handleSelfUpdate))        // controller self-update
	mux.HandleFunc("/api/high-availability", api(s.handleHighAvailability))
	mux.HandleFunc("/api/cache/purge", api(s.handleCachePurge))

	// Blocklist (session-gated)
	mux.HandleFunc("/api/blocklist", api(s.handleBlocklist))                   // GET list / POST add / DELETE remove
	mux.HandleFunc("/api/blocklist/export", api(s.handleBlocklistExport))      // GET text
	mux.HandleFunc("/api/doh-mobileconfig", api(s.handleDoHMobileConfig))      // GET Apple .mobileconfig for DoH (host/port/client_id)
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
		if s.isSecure(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
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

const (
	maxControllerRateLimitQPS = 100000
	maxControllerCacheSize    = 1000000
)

func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := bearerToken(r)
		// Session-only routes (key management) never accept bearer keys, so a
		// key cannot mint more keys — enforced in handleAPIKeys itself.
		if bearer != "" {
			ip := s.clientIP(r)
			// Brute-force guard on bearer keys: 5 bad keys from one IP
			// => 5min 429 (mirrors blipd's management-API guard).
			if !s.auth.allowAPIKey(ip) {
				http.Error(w, "too many attempts", http.StatusTooManyRequests)
				return
			}
			scope, ok := s.auth.apiKeyScope(bearer)
			if !ok {
				s.auth.recordAPIKeyFail(ip)
				w.Header().Set("WWW-Authenticate", "Bearer realm=\"blipc\"")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			s.auth.clearAPIKeyFails(ip)
			// Read-scoped keys are limited to safe GET/HEAD reads.
			if scope == APIKeyScopeRead && r.Method != http.MethodGet && r.Method != http.MethodHead {
				http.Error(w, "read-only API key", http.StatusForbidden)
				return
			}
			// F-12: a general read key must not become a query-history export
			// credential. Query logs, client metadata, live event streams,
			// upstream-error details, and the query-derived aggregates
			// (top-domains, cache-stats, stats) stay admin-only even for GET.
			if scope == APIKeyScopeRead && readScopeDenied(r.URL.Path) {
				http.Error(w, "read-only API key cannot access query history", http.StatusForbidden)
				return
			}
			// Per-instance query-log and process-log tails live under
			// /api/instances/<id>/query-log|/logs (same prefix as other
			// instance reads), so they are filtered here by suffix rather
			// than by the top-level path switch above.
			if scope == APIKeyScopeRead && strings.HasPrefix(r.URL.Path, "/api/instances/") &&
				(strings.HasSuffix(r.URL.Path, "/query-log") || strings.HasSuffix(r.URL.Path, "/logs")) {
				http.Error(w, "read-only API key cannot access query history", http.StatusForbidden)
				return
			}
			h(w, r)
			return
		}
		if !s.auth.Authed(r) {
			w.Header().Set("WWW-Authenticate", "Bearer realm=\"blipc\"")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// CSRF defense-in-depth for cookie-authed mutating requests (no Bearer
		// / API key present): a cross-site form/fetch cannot set a JSON
		// Content-Type or a matching Origin, so require both.
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			if !s.csrfOriginAllowed(r) {
				http.Error(w, "cross-site request rejected", http.StatusForbidden)
				return
			}
			if fetchSite := r.Header.Get("Sec-Fetch-Site"); fetchSite == "cross-site" {
				http.Error(w, "cross-site request rejected", http.StatusForbidden)
				return
			}
			if r.ContentLength != 0 {
				ct := r.Header.Get("Content-Type")
				if ct != "" {
					mt, _, err := mime.ParseMediaType(ct)
					if err != nil || mt != "application/json" {
						http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
						return
					}
				} else if s.StrictCSRF {
					// Fail closed: a body without a content type is the
					// shape of a header-stripped cross-site fetch (simple
					// requests need no preflight). The dashboard always
					// sends application/json.
					http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
					return
				}
				// Missing Content-Type with a body is allowed through (unless
				// StrictCSRF) so the handler returns its normal 400; strict
				// 415 broke existing clients/tests. Simple cross-site form
				// posts still send urlencoded/multipart and are rejected below.
			} else if ct := r.Header.Get("Content-Type"); ct != "" {
				mt, _, err := mime.ParseMediaType(ct)
				if err != nil || mt != "application/json" {
					http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
					return
				}
			}
		}
		h(w, r)
	}
}

// csrfOriginAllowed checks Origin (falling back to Referer when Origin is
// absent): when present its scheme and host must match the client-facing
// origin, otherwise the request may be a cross-site form/fetch riding the
// session cookie. Behind a reverse proxy the client-facing host/scheme come
// from X-Forwarded-Host/Proto (trusted peers only); direct access compares
// against r.Host and r.TLS. Ports are compared (with default-port
// normalization) and the scheme is compared: the old host-only comparison let
// an http origin pass for an https dashboard and let a different port on the
// same host pass.
func (s *Server) csrfOriginAllowed(r *http.Request) bool {
	expectedHost := s.requestHost(r)
	expectedScheme := "http"
	if s.isSecure(r) {
		expectedScheme = "https"
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		if !equalOrigin(u.Scheme, u.Host, expectedScheme, expectedHost) {
			return false
		}
		return true
	}
	if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" {
		u, err := url.Parse(ref)
		if err != nil {
			return false
		}
		if !equalOrigin(u.Scheme, u.Host, expectedScheme, expectedHost) {
			return false
		}
		return true
	}
	// Both Origin and Referer are absent. By default this passes (curl-style
	// API clients and existing tests send neither), but under StrictCSRF a
	// state-changing request with no Sec-Fetch-Site hint either is
	// indistinguishable from a forged legacy-browser post, so fail closed.
	if s.StrictCSRF && stateChangingMethod(r.Method) && strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")) == "" {
		return false
	}
	return true
}

// stateChangingMethod reports whether method mutates state (CSRF-relevant).
func stateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

// csrfOriginAllowed is the package-level helper for tests without a Server.
func csrfOriginAllowed(r *http.Request) bool {
	return (&Server{}).csrfOriginAllowed(r)
}

// equalOrigin reports whether an Origin/Referer (scheme + host[:port]) matches
// the expected client-facing origin. Scheme must match exactly (http vs https);
// hosts compare case-insensitively with default-port normalization, so
// "https://host" matches "host" (443) but "http://host" does not match an
// https dashboard, and "http://host" (port 80) does not match "host:8500".
func equalOrigin(gotScheme, gotHost, wantScheme, wantHost string) bool {
	if !strings.EqualFold(strings.TrimSpace(gotScheme), strings.TrimSpace(wantScheme)) {
		return false
	}
	scheme := strings.ToLower(strings.TrimSpace(wantScheme))
	return normalizeOriginHost(gotHost, scheme) == normalizeOriginHost(wantHost, scheme)
}

// normalizeOriginHost lowercases the hostname and makes the port explicit,
// filling the scheme default when absent, so "host" and "host:443" compare
// equal for https (and "host" vs "host:80" for http) while distinct
// non-default ports stay distinct.
func normalizeOriginHost(h, scheme string) string {
	h = strings.TrimSpace(h)
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		host = h
		port = ""
	}
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	host = strings.TrimSuffix(host, ".")
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host + ":" + strings.ToLower(port)
}

// readScopeDenied reports whether a path is off-limits to read-scoped API
// keys. F-12: /api/queries returns queried domains, client IPs/IDs, instance
// labels, answers and timing — privacy-sensitive query history that must not
// ride on a general health/dashboard read credential. The same applies to the
// client-activity, client-name, live-event and upstream-error feeds, and to
// the query-derived aggregates: /api/top-domains (most-queried domains),
// /api/cache-stats (top cached domains plus hit rates) and /api/stats
// (bucketed query/block counts) all reveal query history in summary form.
func readScopeDenied(path string) bool {
	switch path {
	case "/api/queries",
		"/api/clients",
		"/api/client-names",
		"/api/events",
		"/api/upstream-errors",
		"/api/top-domains",
		"/api/cache-stats",
		"/api/stats",
		// HA topology (VIP, interfaces, peer IPs) is infrastructure detail,
		// not query history, but it has no business on a least-privilege
		// read credential either.
		"/api/high-availability",
		// Fleet configuration and topology: instance management URLs,
		// upstream servers/routes/bootstrap, trusted proxies, client CIDR
		// policy, local records, the manual block/allow lists and full
		// blocklist export, and the DoH mobileconfig all disclose
		// infrastructure a dashboard-read key has no need for.
		"/api/settings",
		"/api/instances",
		"/api/records",
		"/api/blocklist",
		"/api/blocklist/export",
		"/api/doh-mobileconfig":
		return true
	}
	// Per-instance policies carry per-client allow/block domain lists plus
	// client IDs and networks — the same policy class as /api/blocklist.
	if strings.HasPrefix(path, "/api/instances/") && strings.HasSuffix(path, "/policies") {
		return true
	}
	return false
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
	// Login mints a session cookie, so require the same Origin check as
	// logout and other mutating routes; otherwise a cross-site auto-POST
	// can mint an attacker-known session (login CSRF). Headerless
	// clients only pass when StrictCSRF is off; under StrictCSRF a
	// headerless POST is rejected like a forged legacy-browser post.
	if !s.csrfOriginAllowed(r) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	id, err := s.auth.Login(req.Username, req.Password, s.clientIP(r))
	if err != nil {
		if err == errLocked {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.auth.MintCookieSecure(w, r, id, s.isSecure(r))
	writeJSON(w, map[string]bool{"ok": true})
}

// handleSetup creates the first controller credentials and immediately signs
// the operator in. It is deliberately unavailable after the first success.
// AdGuard-style: no setup token — whoever reaches this first-boot page first
// claims the controller, so only boot unconfigured on a trusted network. The
// per-IP brute-force limiter still applies.
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
		Username string `json:"username"`
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Setup mints a session cookie, so require the same Origin check as
	// login; otherwise a cross-site auto-POST mints a session (setup CSRF).
	// (Tokenless first-run setup has no secret to guess, so there is no
	// failure bucket here: the endpoint goes inert after first success.)
	if !s.csrfOriginAllowed(r) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
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
	id, err := s.auth.Login(req.Username, req.Password, s.clientIP(r))
	if err != nil {
		http.Error(w, "could not start session", http.StatusInternalServerError)
		return
	}
	s.auth.MintCookieSecure(w, r, id, s.isSecure(r))
	writeJSON(w, map[string]bool{"ok": true})
}

// handleLogout invalidates the session and clears the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Logout rides the session cookie, so require the same Origin check as
	// other mutating routes; otherwise any cross-site auto-POST logs the
	// operator out (annoyance + forced re-auth phishing window).
	if s.auth.Authed(r) && !s.csrfOriginAllowed(r) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	if fetchSite := r.Header.Get("Sec-Fetch-Site"); fetchSite == "cross-site" {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	s.auth.Destroy(r)
	s.auth.ClearCookieSecure(w, r, s.isSecure(r))
	writeJSON(w, map[string]bool{"ok": true})
}

// handleAPIKeys manages expiring bearer keys for /api/* (debug sharing
// without sharing the password). Session-only: bearer keys are accepted on
// every other /api/* route but never here, so a key cannot mint more keys.
// Keys live in memory — a controller restart revokes them all. Scopes: "admin"
// (default, full API access) or "read" (GET/HEAD only, enforced in
// requireAuth).
func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Authed(r) {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"blipc\"")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// F-13: /api/keys is registered outside the requireAuth wrapper, so it
	// missed the normal session CSRF checks (Origin/Referer + Sec-Fetch-Site
	// + JSON content-type). A session cookie rides automatically, so mutating
	// calls (POST/DELETE) get the same checks here. SameSite=Strict + no CORS
	// headers already blunt cross-origin reads; this closes the state-changing
	// gap (key creation/revocation) in same-site-subdomain and legacy-browser
	// scenarios.
	if r.Method == http.MethodPost || r.Method == http.MethodDelete || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		if !s.csrfOriginAllowed(r) {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		if fetchSite := r.Header.Get("Sec-Fetch-Site"); fetchSite == "cross-site" {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			mt, _, err := mime.ParseMediaType(ct)
			if err != nil || mt != "application/json" {
				http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		} else if s.StrictCSRF && r.ContentLength != 0 {
			http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		// Missing Content-Type with a body is allowed through (unless
		// StrictCSRF) so the handler returns its normal 400 (mirrors
		// requireAuth: strict 415 broke existing clients/tests).
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
			Scope    string `json:"scope"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Scope == "" {
			req.Scope = APIKeyScopeAdmin
		}
		if req.Scope != APIKeyScopeAdmin && req.Scope != APIKeyScopeRead {
			http.Error(w, "scope must be read or admin", http.StatusBadRequest)
			return
		}
		id, secret, expires, err := s.auth.CreateAPIKey(req.Label, time.Duration(req.TTLHours)*time.Hour, req.Scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]interface{}{"id": id, "key": secret, "scope": req.Scope, "expires_at": expires})
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

// fleetErrStatus maps fleet errors to HTTP status: persist failures are
// server-side (500); validation and unknown-instance errors stay 400.
func fleetErrStatus(err error) int {
	if errors.Is(err, errPersist) {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
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
		log.Printf("blipc: audit: self-update started channel=%q from %s", channel, s.clientIP(r))
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
		var req struct {
			ID      string `json:"id"`
			Channel string `json:"channel"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		channel := s.fleet.ReleaseChannel()
		if req.Channel != "" {
			channel = req.Channel
		} else if requested := r.URL.Query().Get("channel"); requested != "" {
			channel = requested
		}
		var (
			job UpdateJobStatus
			err error
		)
		if req.ID != "" {
			job, err = s.fleet.StartUpdateOne(r.Context(), req.ID, channel)
		} else {
			job, err = s.fleet.StartUpdates(r.Context(), channel)
		}
		if err != nil {
			if errors.Is(err, errUpdateBusy) {
				http.Error(w, err.Error(), http.StatusConflict)
			} else {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		}
		log.Printf("blipc: audit: instance update started id=%q channel=%q from %s", req.ID, channel, s.clientIP(r))
		writeJSON(w, job)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// bundleURLScheme returns the http/https scheme of an adopt-bundle URL (""
// when unparseable; the bundle codec already validated it, this is just
// extraction).
func bundleURLScheme(bundleURL string) string {
	u, err := url.Parse(bundleURL)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return u.Scheme
}

// addInstanceRequest is the POST /api/instances body. It mirrors
// InstanceConfig field-for-field but keeps a JSON-visible token: Token is
// write-only on InstanceConfig (never serialized back), while manual setup
// still needs to supply one.
type addInstanceRequest struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	Token      string `json:"token"`
	Label      string `json:"label"`
	Claim      string `json:"claim"`
	MgmtCertFP string `json:"mgmt_cert_fp"`
}

func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.fleet.List())
	case http.MethodPost:
		// Token is write-only on InstanceConfig (json:"-": accepted but
		// never serialized back), so the add body decodes into an intake
		// struct that still carries a token for manual (non-adopt) setup.
		var req addInstanceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfg := InstanceConfig{ID: req.ID, URL: req.URL, Token: req.Token, Label: req.Label, Claim: req.Claim, MgmtCertFP: req.MgmtCertFP}
		// Token file expansion is never allowed via the API: "@..." or
		// absolute-path-looking tokens are rejected so an API caller cannot
		// make the controller read arbitrary local files. Use startup config
		// for secret-file expansion.
		if tok := strings.TrimSpace(cfg.Token); strings.HasPrefix(tok, "@") || strings.HasPrefix(tok, "/") {
			http.Error(w, "token file expansion not allowed via API; use startup config", http.StatusBadRequest)
			return
		}
		cfg = ResolveTokenFileAllow(cfg, false)
		// Adopt bundle: one opaque paste carrying id + management URL +
		// one-time code. Fills whatever the caller left empty (the setup
		// wizard sends only name + bundle + optional Advanced host:port);
		// a legacy bare code passes through untouched.
		if b, ok := control.ParseAdoptBundle(cfg.Claim); ok {
			if cfg.URL == "" {
				cfg.URL = b.URL
			} else if bundleScheme := bundleURLScheme(b.URL); bundleScheme != "" && !strings.Contains(cfg.URL, "://") {
				// Scheme-less Advanced override (host:port) inherits the
				// bundle scheme so http/https stays correct.
				cfg.URL = bundleScheme + "://" + cfg.URL
			}
			if cfg.ID == "" {
				cfg.ID = b.ID
			}
			cfg.Claim = b.Code
		}
		if err := validateInstanceURL(cfg.URL); err != nil {
			http.Error(w, err.Error()+": paste an adopt bundle or provide host and port", http.StatusBadRequest)
			return
		}
		if err := s.fleet.Add(r.Context(), cfg); err != nil {
			http.Error(w, err.Error(), fleetErrStatus(err))
			return
		}
		writeJSON(w, map[string]interface{}{"ok": "added", "id": cfg.ID, "adopted": s.fleet.Adopted(cfg.ID)})
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
	log.Printf("blipc: audit: instance restart id=%q from %s", req.ID, s.clientIP(r))
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
		log.Printf("blipc: audit: adopt/status for instance %q from %s", id, s.clientIP(r))
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
			log.Printf("blipc: audit: adopt instance %q from %s failed: %v", id, s.clientIP(r), err)
			http.Error(w, err.Error(), fleetErrStatus(err))
			return
		}
		log.Printf("blipc: audit: adopt instance %q from %s", id, s.clientIP(r))
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
		log.Printf("blipc: audit: adopt/reset instance %q from %s", id, s.clientIP(r))
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
		if strings.TrimSpace(req.Label) == "" {
			http.Error(w, "label required", http.StatusBadRequest)
			return
		}
		if len(req.Label) > maxInstanceLabelLen {
			http.Error(w, "label too long (max 128 characters)", http.StatusBadRequest)
			return
		}
		if err := s.fleet.SetLabel(ctx, id, req.Label); err != nil {
			http.Error(w, err.Error(), fleetErrStatus(err))
			return
		}
		writeJSON(w, map[string]string{"ok": "label updated", "id": id})
	case "logs":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		logs, err := s.fleet.InstanceLogs(ctx, id, boundedLimit(r, 200, 500))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, logs)
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
		proto := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("proto")))
		if proto != "dns" && proto != "doh" {
			proto = ""
		}
		limit := boundedLimit(r, 100, 500)
		offset := boundedOffset(r)
		since := time.Now().Add(-boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour))
		entries, err := s.fleet.queryLog.Query(ctx, instance, filter, action, cached, proto, since, offset, limit)
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
		if err := s.fleet.Remove(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
		// Reject bad records here, not on the instances: blipd refuses the
		// whole push on one bad entry, so one typo would brick the
		// fleet-wide records until fixed.
		for i, rec := range req.Records {
			if err := control.ValidateRecordEntry(rec); err != nil {
				http.Error(w, fmt.Sprintf("record %d: %v", i, err), http.StatusBadRequest)
				return
			}
		}
		applied, err := s.fleet.SetRecords(r.Context(), req.Records)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
	case http.MethodDelete:
		applied, err := s.fleet.SetRecords(r.Context(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
			"allowed_networks":          s.fleet.AllowedNetworks(),
			"open_recursion_ack":        s.fleet.OpenRecursionAck(),
			"upstream_servers":          upServers,
			"upstream_routes":           upRoutes,
			"upstream_bootstrap":        s.fleet.UpstreamBootstrap(),
			"cache_size":                cacheSize,
			"query_log_retention_hours": s.fleet.QueryLogRetentionHours(),
			"trusted_proxies":           s.fleet.TrustedProxies(),
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
			AllowedNetworks        *[]string                  `json:"allowed_networks"`
			OpenRecursionAck       *bool                      `json:"open_recursion_ack"`
			CacheSize              *int                       `json:"cache_size"`
			QueryLogRetentionHours *int                       `json:"query_log_retention_hours"`
			TrustedProxies         *[]string                  `json:"trusted_proxies"`
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
				applied, err := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
				return
			}
			applied, err := s.fleet.SetDoHHTTPAddr(r.Context(), addr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
			applied, err := s.fleet.SetQueryLogRetention(r.Context(), hours)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		// Reverse-proxy trust (controller-local): which peers may supply
		// X-Forwarded-For/Proto/Host. Validated as CIDRs/bare IPs; empty
		// clears back to "trust none". Applies immediately (next request
		// parses Fleet) and persists to controller.yaml.
		if req.TrustedProxies != nil {
			if err := s.fleet.SetTrustedProxies(*req.TrustedProxies); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Keep the startup-set Server trust in sync for paths without
			// a fleet (tests) — getTrust prefers Fleet, so this is best-effort.
			_ = s.SetTrustedProxies(*req.TrustedProxies)
			writeJSON(w, map[string]interface{}{"ok": true, "trusted_proxies": s.fleet.TrustedProxies()})
			return
		}
		// Per-client DNS rate limit (fleet-wide or per-instance).
		if req.RateLimitQPS != nil {
			qps := *req.RateLimitQPS
			if qps < 0 {
				http.Error(w, "rate_limit_qps must be >= 0", http.StatusBadRequest)
				return
			}
			// Upper bound: an absurd QPS silently neuters the limiter
			// (effectively off). Mirrors blipd's maxMgmtRateLimit (100k) so
			// every value the controller accepts is pushable.
			if qps > maxControllerRateLimitQPS {
				http.Error(w, "rate_limit_qps too large (max 100000)", http.StatusBadRequest)
				return
			}
			if req.Scope == "instance" && req.Instance != "" {
				existing := s.fleet.InstanceOverrideOf(req.Instance)
				merged := mergeOverride(existing, &InstanceOverride{RateLimitQPS: req.RateLimitQPS})
				if qps == 0 {
					merged.RateLimitQPS = nil
				}
				applied, err := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
				return
			}
			applied, err := s.fleet.SetRateLimitQPS(r.Context(), qps)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		// Fleet-wide open-resolver ack: explicit opt-in to pushing an empty
		// ACL. Applied before the ACL below so one request can ack+clear.
		if req.OpenRecursionAck != nil {
			if err := s.fleet.SetOpenRecursionAck(*req.OpenRecursionAck); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// A lone ack flip (no ACL in the same request) is done here.
			if req.AllowedNetworks == nil {
				writeJSON(w, map[string]interface{}{"ok": true, "open_recursion_ack": s.fleet.OpenRecursionAck()})
				return
			}
		}
		// Recursion ACL (fleet-wide or per-instance). Entries are validated
		// (including the /0 catch-all guard) before persisting. An empty
		// fleet-wide list means "no fleet opinion" and is never pushed; an
		// explicitly-empty per-instance list clears back to the fleet
		// default.
		if req.AllowedNetworks != nil {
			nets := *req.AllowedNetworks
			if _, err := control.ParseAllowedNetworks(nets); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if len(nets) == 0 && req.Scope != "instance" && !s.fleet.OpenRecursionAck() {
				http.Error(w, "clearing the fleet ACL opens recursion to the world; set open_recursion_ack first", http.StatusBadRequest)
				return
			}
			if req.Scope == "instance" && req.Instance != "" {
				existing := s.fleet.InstanceOverrideOf(req.Instance)
				merged := mergeOverride(existing, &InstanceOverride{AllowedNetworks: req.AllowedNetworks})
				if len(nets) == 0 {
					merged.AllowedNetworks = nil
				}
				applied, err := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
				return
			}
			if _, err := control.ParseAllowedNetworks(nets); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			applied, err := s.fleet.SetAllowedNetworks(r.Context(), nets)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
			// Upper bound: 0 already means unlimited, so a huge value can
			// only balloon RAM (or neuter the cache via overflow).
			if cacheSize > maxControllerCacheSize {
				http.Error(w, "cache size too large (max 1000000)", http.StatusBadRequest)
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
				applied, err := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
				return
			}
			applied, err := s.fleet.SetCache(r.Context(), cacheSize)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
				applied, err := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
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
			applied, err := s.fleet.SetUpstream(r.Context(), fleetServers, fleetRoutes, fleetBootstrap)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		// Default policy / per-instance policy fields. Per-instance edits are
		// merged onto any existing override so saving upstream doesn't wipe a
		// previously saved DoH override (and vice-versa).
		if req.Scope == "instance" && req.Instance != "" {
			existing := s.fleet.InstanceOverrideOf(req.Instance)
			merged := mergeOverride(existing, req.Override)
			if merged.Records != nil {
				for i, rec := range *merged.Records {
					if err := control.ValidateRecordEntry(rec); err != nil {
						http.Error(w, fmt.Sprintf("record %d: %v", i, err), http.StatusBadRequest)
						return
					}
				}
			}
			applied, err := s.fleet.SetInstanceOverride(r.Context(), req.Instance, merged)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
			return
		}
		if req.Policy == nil {
			http.Error(w, "default_policy required", http.StatusBadRequest)
			return
		}
		applied, err := s.fleet.SetDefaultPolicy(r.Context(), req.Policy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "applied": applied})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHighAvailability(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Audit: HA topology is infrastructure-sensitive; log who reads it.
		authKind := "session"
		if bearerToken(r) != "" {
			authKind = "api-key"
		}
		log.Printf("blipc: audit: /api/high-availability read from %s via %s", s.clientIP(r), authKind)
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
		if action == "validate" {
			// Validate the unsaved draft when the UI sends one: the point
			// of Validate is checking what you typed before saving it.
			// Absent body (older callers) falls back to stored state.
			var req struct {
				Cluster *control.HACluster `json:"cluster"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil && err != io.EOF {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if req.Cluster != nil {
				cluster = *req.Cluster
			}
		}
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
	// Audit: query history is privacy-sensitive; log who reads it.
	authKind := "session"
	if bearerToken(r) != "" {
		authKind = "api-key"
	}
	log.Printf("blipc: audit: /api/queries access from %s via %s instance=%q filter=%q", s.clientIP(r), authKind, r.URL.Query().Get("instance"), r.URL.Query().Get("filter"))
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
	// proto: "" (any), "dns" (classic only), "doh" (DoH only)
	proto := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("proto")))
	if proto != "dns" && proto != "doh" {
		proto = ""
	}
	limit := boundedLimit(r, 100, 500)
	offset := boundedOffset(r)
	since := time.Now().Add(-boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour))
	entries, total, err := s.fleet.queryLog.QueryPage(r.Context(), instance, filter, action, cached, proto, since, offset, limit)
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
	// Audit: per-client activity is privacy-sensitive; log who reads it.
	authKind := "session"
	if bearerToken(r) != "" {
		authKind = "api-key"
	}
	log.Printf("blipc: audit: /api/clients access from %s via %s instance=%q", s.clientIP(r), authKind, r.URL.Query().Get("instance"))
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
	sinceDur := boundedDuration(r, "since", 24*time.Hour, time.Minute, 30*24*time.Hour)
	// Bound analytics cost: cap time-series buckets so ?since=720h&bucket=1s
	// cannot build a multi-million-entry map (OOM/CPU DoS by an authenticated
	// caller). 2000 buckets max; grow the bucket to fit the range.
	if sinceDur/bucketSize > 2000 {
		bucketSize = (sinceDur + 1999) / 2000
		if bucketSize < time.Second {
			bucketSize = time.Second
		}
	}
	since := time.Now().Add(-sinceDur)
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
	// Audit: most-queried domains are query history; log who reads it.
	authKind := "session"
	if bearerToken(r) != "" {
		authKind = "api-key"
	}
	log.Printf("blipc: audit: /api/top-domains access from %s via %s instance=%q action=%q", s.clientIP(r), authKind, r.URL.Query().Get("instance"), r.URL.Query().Get("action"))
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
	// Session-only: bearer API keys are for scripts, and probing arbitrary
	// host:ports from blipc's network vantage is a LAN port-scan oracle.
	// The interactive Test button rides the session cookie; scripts can save
	// the pool and watch stats/upstream-errors instead.
	if bearerToken(r) != "" {
		http.Error(w, "session required", http.StatusForbidden)
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
	if len(req.Servers) > 8 {
		http.Error(w, "too many servers (max 8)", http.StatusBadRequest)
		return
	}
	// Rate-limit probes per client IP (10/min): each request fans out to up to
	// 8 upstreams from blipc's network vantage, so an unthrottled endpoint
	// is a LAN port-scan oracle for anyone holding a session.
	if !s.probeAllowed(s.clientIP(r)) {
		http.Error(w, "probe rate limit exceeded; try again later", http.StatusTooManyRequests)
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
	log.Printf("blipc: audit: /api/upstream/test from %s servers=%d domain=%q", s.clientIP(r), len(req.Servers), domain)
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
	// The dashboard's SSE stream must outlive the server's 30s absolute
	// Read/WriteTimeout, otherwise every browser's event stream is cut and
	// re-connected on a 30s cycle instead of streaming.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Time{})
	ch, backlog, ok := s.fleet.Bus().TrySubscribe()
	if !ok {
		http.Error(w, "too many event subscribers", http.StatusTooManyRequests)
		return
	}
	defer s.fleet.Bus().Unsubscribe(ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")

	for _, e := range backlog {
		fmt.Fprintf(w, "data: %s\n\n", control.MustJSON(e))
	}
	flusher.Flush()
	// Bound the stream lifetime like blipd's watch endpoint: stalled readers
	// must not pin goroutines and subscriptions forever. Browsers reconnect.
	streamMax := time.NewTimer(30 * time.Minute)
	defer streamMax.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-streamMax.C:
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
		// Only hand-added allows are listed: source-declared $denyallow=
		// exceptions still apply fleet-wide, they are just not operator state.
		allowed := s.fleet.ManualAllowedDomains()
		if lim := r.URL.Query().Get("limit"); lim != "" {
			if n, err := strconv.Atoi(lim); err == nil && n > 0 {
				if len(domains) > n {
					domains = domains[:n]
				}
				if len(allowed) > n {
					allowed = allowed[:n]
				}
			}
		}
		writeJSON(w, map[string]interface{}{
			"domains": domains,
			"allowed": allowed,
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
			// ponytail: strings.Fields so pasting "a.com b.com" (or
			// multi-line) adds each; invalid entries normalize to "" and
			// are skipped inside Add*.
			for _, d := range strings.Fields(req.Domain) {
				if req.Allow {
					s.fleet.AddAllowedDomain(d)
				} else {
					s.fleet.AddManualDomain(d)
				}
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
	// Cap the export so a multi-million-domain list cannot OOM the controller
	// or the browser: ?limit= pages through it (default 100k, max 1M).
	// Stream directly without materializing the full list first.
	limit := boundedLimit(r, 100_000, 1_000_000)
	w.Header().Set("Content-Type", "text/plain")
	s.fleet.Blocklist().WriteLimited(w, limit)
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
			Clear           bool     `json:"clear"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		urls := cleanURLs(req.URLs)
		// Fail closed: an empty source list is only destructive when the
		// caller asks for it. A UI whose source list was lost (e.g. an old
		// startup bug clobbered blocklist_sources in the config) PUTs its
		// empty view on an unrelated save — auto-update hours — and used to
		// wipe the merged blocklist on every instance.
		if len(urls) == 0 && !req.Clear {
			http.Error(w, "refusing to save an empty source list; send clear:true to remove all sources and domains", http.StatusBadRequest)
			return
		}
		if req.AutoUpdateHours != nil {
			if err := s.fleet.SetAutoUpdateHours(*req.AutoUpdateHours); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if len(urls) > maxBlocklistSources {
			http.Error(w, fmt.Sprintf("too many blocklist sources (max %d)", maxBlocklistSources), http.StatusBadRequest)
			return
		}
		// Reject bad URLs here, not at import: an invalid/internal URL would
		// otherwise persist and fail on every refresh. The fetch layer still
		// re-validates (redirect/rebind-safe), so this is UX, not the guard.
		for i, u := range urls {
			if err := blocklist.ValidateSourceURL(u); err != nil {
				http.Error(w, fmt.Sprintf("source %d: %v", i, err), http.StatusBadRequest)
				return
			}
		}
		if len(urls) == 0 {
			// clear:true with no URLs: drop the sources and the merged list.
			if err := s.fleet.SetBlocklistSources(r.Context(), nil); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.fleet.Blocklist().FromDomains(nil)
			if req.ClearManual {
				s.fleet.ClearManualDomains()
				s.fleet.ClearAllowedDomains()
			}
			s.fleet.persistBlocklist()
			writeJSON(w, map[string]interface{}{"ok": true, "count": 0})
			return
		}
		if err := s.fleet.SetBlocklistSources(r.Context(), urls); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
	if err := s.fleet.SetBlocklistSourceEnabled(r.Context(), url, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

// loadYAMLDoc reads a YAML mapping document, returning an empty document when
// the file is missing or empty so first-boot callers can create config keys.
func loadYAMLDoc(path string) (*yaml.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var doc yaml.Node
	if len(b) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	} else if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config root must be a YAML mapping")
	}
	return &doc, nil
}

// setYAMLKey sets one top-level scalar key in place, preserving the rest of
// the document (fleet settings, comments).
func setYAMLKey(root *yaml.Node, key, value string) {
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

// writeYAMLAtomic marshals the document and swaps it into place (tmp+rename,
// 0600) so a concurrent reader never sees a truncation.
func writeYAMLAtomic(path string, doc *yaml.Node) error {
	out, err := yaml.Marshal(doc)
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

// persistCredentials updates only the auth keys in the existing YAML document,
// preserving fleet settings and comments written by the operator.
func persistCredentials(path, username, passwordHash string) error {
	doc, err := loadYAMLDoc(path)
	if err != nil {
		return err
	}
	root := doc.Content[0]
	setYAMLKey(root, "username", username)
	setYAMLKey(root, "password_hash", passwordHash)
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "password" {
			root.Content = append(root.Content[:i], root.Content[i+2:]...)
			break
		}
	}
	return writeYAMLAtomic(path, doc)
}

// persistListenKey updates only the `listen` key in the existing YAML
// document, preserving everything else.
func persistListenKey(path, listen string) error {
	doc, err := loadYAMLDoc(path)
	if err != nil {
		return err
	}
	setYAMLKey(doc.Content[0], "listen", listen)
	return writeYAMLAtomic(path, doc)
}

// handleSetupListen persists the dashboard listen address chosen in the setup
// wizard. Session-gated (the wizard holds a session from /api/setup by now).
// Shape is validated here; startup policy (plain-remote refusal) still applies
// on the next boot, and the new address takes effect after a controller
// restart — there is no in-process rebind.
func (s *Server) handleSetupListen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Listen string `json:"listen"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(req.Listen))
	if err != nil {
		http.Error(w, "listen must be host:port", http.StatusBadRequest)
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		http.Error(w, "port must be 1-65535", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(host) == "" {
		http.Error(w, "interface/host is required", http.StatusBadRequest)
		return
	}
	listen := net.JoinHostPort(host, strconv.Itoa(port))
	if s.configPath == "" {
		http.Error(w, "setup persistence is unavailable", http.StatusInternalServerError)
		return
	}
	if err := persistListenKey(s.configPath, listen); err != nil {
		http.Error(w, "could not save listen address", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "listen": listen, "restart_required": true})
}

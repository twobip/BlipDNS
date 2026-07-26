package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

// Server is the blipc controller HTTP + UI server.
type Server struct {
	token string
	fleet *Fleet
	ui    fs.FS // embedded web assets (index.html etc.)
}

// NewServer builds the controller HTTP server. ui may be nil (API-only).
func NewServer(token string, fleet *Fleet, ui fs.FS) *Server {
	return &Server{token: token, fleet: fleet, ui: ui}
}

// Handler returns the controller's HTTP handler (API + UI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API (token-gated)
	api := func(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return s.auth(h)
	}
	mux.HandleFunc("/api/instances", api(s.handleInstances))
	mux.HandleFunc("/api/instances/", api(s.handleInstance)) // /add /delete /policies /policy /adopt /adopt/status /adopt/reset /label /query-log
	mux.HandleFunc("/api/queries", api(s.handleQueries)) // query log
	mux.HandleFunc("/api/stats", api(s.handleStats)) // aggregated query stats for graphs
	mux.HandleFunc("/api/events", api(s.handleEvents))
	mux.HandleFunc("/api/health", api(s.handleHealth))

	// UI: the page itself requires the token, but static assets (js/css) are
	// served unauthenticated. Browsers fetch sub-resources like /app.js as
	// relative URLs, which drop the ?token= query — gating them would 401 and
	// leave the console stuck on "connecting". The assets hold no secrets; the
	// control plane (/api/*) stays fully token-gated.
	if s.ui != nil {
		mux.Handle("/", http.HandlerFunc(s.serveUI))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "blipc: no UI embedded (API only)", http.StatusNotFound)
		})
	}
	return mux
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validToken(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// validToken reports whether the request carries the server's token, either as
// a Bearer header or a ?token= query parameter.
func (s *Server) validToken(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	tok := r.Header.Get("Authorization")
	if len(tok) > 7 && strings.EqualFold(tok[:7], "Bearer ") {
		tok = tok[7:]
	} else if q := r.URL.Query().Get("token"); q != "" {
		tok = q
	}
	return tok == s.token
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.fleet.Health())
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
	stats, err := s.fleet.queryLog.GetQueryStats(r.Context(), instance, bucketSize, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, stats)
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

func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" && r.URL.Path != "/instances" && r.URL.Path != "/instances.html" && r.URL.Path != "/queries" && r.URL.Path != "/queries.html" && r.URL.Path != "/settings" && r.URL.Path != "/settings.html" && !isUIAsset(r.URL.Path) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// The page requires the token; static assets (js/css) are served
	// unauthenticated so browsers can load them as relative sub-resources.
	if r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/instances" || r.URL.Path == "/instances.html" || r.URL.Path == "/queries" || r.URL.Path == "/queries.html" || r.URL.Path == "/settings" || r.URL.Path == "/settings.html" {
		if !s.validToken(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	b, err := fs.ReadFile(s.ui, name)
	if err != nil {
		// SPA fallback to index.html
		if b, err = fs.ReadFile(s.ui, "index.html"); err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		name = "index.html"
	}
		// Inject token into {{TOKEN}} placeholders for nav links
		tok := r.URL.Query().Get("token")
		if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
			tok = h[7:]
		}
		if tok != "" && len(b) > 0 {
			b = bytes.ReplaceAll(b, []byte("{{TOKEN}}"), []byte(tok))
		}
		ct := contentType(name)
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(b)
	}

func isUIAsset(p string) bool {
	switch {
	case strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".css"),
		strings.HasSuffix(p, ".html"), strings.HasSuffix(p, ".svg"),
		strings.HasSuffix(p, ".ico"), strings.HasSuffix(p, ".png"):
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

var _ = time.Now

// Package controller — auth sub-system for the blipc control plane.
//
// Replaces the old single-shared-token auth with a real login: an operator
// authenticates with username + password once, and receives an HttpOnly,
// SameSite=Strict, cryptographically-random session cookie. No open auth: if
// no credentials are configured the server starts but denies ALL logins.
package controller

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie = "blip_session"
	sessionTTL    = 24 * time.Hour

	// brute-force guard
	maxLoginFails   = 5
	loginLockWindow = 5 * time.Minute

	// brute-force guard for bearer API keys (mirrors blipd's management-API
	// guard: 5 bad keys from one IP => 5min 429).
	maxAPIKeyFails       = 5
	apiKeyLockWindow     = 5 * time.Minute
	maxAPIKeyFailEntries = 10000
)

var (
	errBadCreds  = errors.New("invalid username or password")
	errLocked    = errors.New("too many failed attempts, try again later")
	errNoAuthCfg = errors.New("auth not configured")
)

type loginFails struct {
	count       int
	windowStart time.Time
}

// Auth verifies credentials and mints/validates session cookies.
type Auth struct {
	username   string
	passHash   []byte
	configured bool

	mu       sync.Mutex
	sessions map[string]time.Time // sessionID -> expiry
	keys     map[string]apiKey    // key ID -> expiring bearer key (debug sharing)

	flMu sync.Mutex
	fl   map[string]*loginFails // client IP -> failure state
	// setupFl tracks setup-token guesses separately so burning setup
	// attempts can never lock out login (and vice versa).
	setupFl map[string]*loginFails // client IP -> setup failure state

	apiFlMu sync.Mutex
	apiFl   map[string]*apiKeyFail // client IP -> bearer-key failure state
}

// Sweep removes expired sessions, expired API keys, and stale login-failure records.
func (a *Auth) Sweep() {
	now := time.Now()
	a.mu.Lock()
	for id, expiry := range a.sessions {
		if now.After(expiry) {
			delete(a.sessions, id)
		}
	}
	for id, k := range a.keys {
		if now.After(k.expires) {
			delete(a.keys, id)
		}
	}
	a.mu.Unlock()
	a.flMu.Lock()
	for ip, f := range a.fl {
		if now.After(f.windowStart.Add(loginLockWindow)) {
			delete(a.fl, ip)
		}
	}
	for ip, f := range a.setupFl {
		if f == nil || now.After(f.windowStart.Add(loginLockWindow)) {
			delete(a.setupFl, ip)
		}
	}
	a.flMu.Unlock()
	a.apiFlMu.Lock()
	for ip, f := range a.apiFl {
		if f == nil || (!f.until.IsZero() && now.After(f.until)) || (f.until.IsZero() && now.Sub(f.last) > apiKeyLockWindow) {
			delete(a.apiFl, ip)
		}
	}
	a.apiFlMu.Unlock()
}

// NewAuth builds an Auth from a username + password. The password may be either
// plaintext (it is bcrypt-hashed at startup) or a pre-computed bcrypt hash
// (string starting with "$2"), which lets operators keep a plaintext password
// out of the config file. An empty password yields a *closed* Auth that
// rejects every login — never an open one.
func NewAuth(username, password string) *Auth {
	a := &Auth{
		sessions: make(map[string]time.Time),
		keys:     make(map[string]apiKey),
		fl:       make(map[string]*loginFails),
		setupFl:  make(map[string]*loginFails),
	}
	if username == "" || password == "" {
		return a // configured=false -> all logins rejected
	}
	hash, err := bcryptHashFor(password)
	if err != nil {
		return a
	}
	a.username = username
	a.passHash = hash
	a.configured = true
	return a
}

// bcryptHashFor returns a bcrypt hash for the password, or returns the password
// verbatim when it already looks like a bcrypt hash (so pre-hashed passwords
// from config are stored as-is rather than re-hashed, which would fail later
// comparison). A string that merely starts with "$2" but is not a valid bcrypt
// hash is rejected (fail-closed) so a broken config doesn't silently accept
// logins.
func bcryptHashFor(password string) ([]byte, error) {
	if looksLikeBcryptHash(password) {
		err := bcrypt.CompareHashAndPassword([]byte(password), []byte(""))
		// ErrMismatchedHashAndPassword means the hash is well-formed (just didn't
		// match the empty probe) — valid format. Any other error means malformed.
		if err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, fmt.Errorf("password_hash is not a valid bcrypt hash")
		}
		return []byte(password), nil
	}
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// looksLikeBcryptHash reports whether s is a bcrypt $2a/$2b/$2y hash.
func looksLikeBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}

// Configured reports whether valid credentials are configured.
func (a *Auth) Configured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.configured
}

// Configure installs credentials exactly once. It is used by the first-run
// setup flow after the new bcrypt hash has been persisted successfully.
func (a *Auth) Configure(username, passwordHash string) bool {
	if username == "" || passwordHash == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.configured {
		return false
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("")); err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false
	}
	a.username = username
	a.passHash = []byte(passwordHash)
	a.configured = true
	return true
}

// Login validates credentials for an authenticated-less request and, on
// success, creates a session. It enforces a per-IP brute-force lockout.
func (a *Auth) Login(username, password, clientIP string) (string, error) {
	if !a.Configured() {
		return "", errNoAuthCfg
	}
	// Credential first: a correct password always succeeds, so bad guesses
	// from anywhere can never lock out the legitimate operator. The limiter
	// below only ever sees failures.
	if a.verify(username, password) {
		a.clearFails(clientIP)
		id, err := newSessionID()
		if err != nil {
			return "", err
		}
		a.mu.Lock()
		a.sessions[id] = time.Now().Add(sessionTTL)
		a.mu.Unlock()
		return id, nil
	}
	// Failed credential: loopback callers are never locked out (same-box
	// access must survive a guessing flood).
	if !isLoopbackIP(clientIP) {
		if !a.allowLogin(clientIP) {
			return "", errLocked
		}
		a.recordFail(clientIP)
	}
	return "", errBadCreds
}

func (a *Auth) verify(user, pass string) bool {
	a.mu.Lock()
	username := a.username
	hash := append([]byte(nil), a.passHash...)
	a.mu.Unlock()
	if !constantTimeEq(user, username) {
		// Burn the same bcrypt cost as a wrong password so unknown-user
		// and wrong-password are indistinguishable by response timing.
		_ = bcrypt.CompareHashAndPassword(hash, []byte(pass))
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(pass)) == nil
}

func constantTimeEq(a, b string) bool {
	// length-leaking is acceptable here (usernames aren't secret); contents are
	// compared in constant time to resist timing attacks on the password.
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Authed reports whether the request carries a valid, unexpired session.
func (a *Auth) Authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(a.sessions, c.Value)
		return false
	}
	return true
}

// Destroy invalidates a session (logout).
func (a *Auth) Destroy(r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
}

// ClearCookie writes an expired cookie so the browser forgets the session.
func (a *Auth) ClearCookie(w http.ResponseWriter, r *http.Request) {
	a.ClearCookieSecure(w, r, r.TLS != nil)
}

// ClearCookieSecure is ClearCookie with an explicit Secure flag so callers
// behind a TLS-terminating reverse proxy can mark the cookie Secure when
// X-Forwarded-Proto=https came from a trusted proxy.
func (a *Auth) ClearCookieSecure(w http.ResponseWriter, _ *http.Request, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

// MintCookie writes a fresh session cookie for the given session id.
func (a *Auth) MintCookie(w http.ResponseWriter, r *http.Request, id string) {
	a.MintCookieSecure(w, r, id, r.TLS != nil)
}

// MintCookieSecure is MintCookie with an explicit Secure flag for
// reverse-proxy deployments (Secure when the client-facing proto is https).
func (a *Auth) MintCookieSecure(w http.ResponseWriter, _ *http.Request, id string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   int(sessionTTL.Seconds()),
		Expires:  time.Now().Add(sessionTTL),
	})
}

const (
	maxAPIKeyLabelLen = 64
	maxAPIKeyTTL      = 30 * 24 * time.Hour
)

// APIKeyInfo is the list-safe view of a key — it never includes the secret,
// which is shown once at creation time.
type APIKeyInfo struct {
	ID      string    `json:"id"`
	Label   string    `json:"label"`
	Scope   string    `json:"scope"`
	Created time.Time `json:"created_at"`
	Expires time.Time `json:"expires_at"`
}

type apiKey struct {
	secret  string
	label   string
	scope   string // "read" or "admin" ("" = legacy admin, treated as admin)
	created time.Time
	expires time.Time
}

// API key scopes: "admin" can call any /api/* route; "read" is limited to
// safe GET/HEAD reads (enforced in requireAuth) and additionally cannot read
// query history, client metadata, live events or upstream-error details
// (F-12: those stay admin-only even for GET).
const (
	APIKeyScopeAdmin = "admin"
	APIKeyScopeRead  = "read"
)

// normalizeAPIKeyScope maps "" (unset/legacy) and unknown values to admin,
// so keys minted before scopes existed keep full access.
func normalizeAPIKeyScope(scope string) string {
	if scope == APIKeyScopeRead {
		return APIKeyScopeRead
	}
	return APIKeyScopeAdmin
}

// CreateAPIKey mints a bearer key for /api/* valid for ttl. ttl must be
// positive and at most 30 days. scope is "read" (GET/HEAD only) or "admin"
// (full access); "" defaults to admin for backward compatibility.
func (a *Auth) CreateAPIKey(label string, ttl time.Duration, scope string) (id, secret string, expires time.Time, err error) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > maxAPIKeyLabelLen {
		return "", "", time.Time{}, errors.New("label must be 1-64 characters")
	}
	if ttl <= 0 || ttl > maxAPIKeyTTL {
		return "", "", time.Time{}, errors.New("ttl must be positive and at most 30 days")
	}
	scope = normalizeAPIKeyScope(scope)
	raw, err := newSessionID() // 32 random bytes, hex — reuse the session secret shape
	if err != nil {
		return "", "", time.Time{}, err
	}
	idRaw := make([]byte, 6)
	if _, err := rand.Read(idRaw); err != nil {
		return "", "", time.Time{}, err
	}
	now := time.Now()
	k := apiKey{secret: "blip_" + raw, label: label, scope: scope, created: now, expires: now.Add(ttl)}
	id = hex.EncodeToString(idRaw)
	a.mu.Lock()
	a.keys[id] = k
	a.mu.Unlock()
	return id, k.secret, k.expires, nil
}

// ListAPIKeys returns live and expired-but-unswept keys without secrets.
func (a *Auth) ListAPIKeys() []APIKeyInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]APIKeyInfo, 0, len(a.keys))
	for id, k := range a.keys {
		out = append(out, APIKeyInfo{ID: id, Label: k.label, Scope: normalizeAPIKeyScope(k.scope), Created: k.created, Expires: k.expires})
	}
	return out
}

// RevokeAPIKey deletes a key immediately. It reports whether one existed.
func (a *Auth) RevokeAPIKey(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.keys[id]; !ok {
		return false
	}
	delete(a.keys, id)
	return true
}

// validAPIKey reports whether secret is a live key.
// ponytail: O(n) scan, per-key map when keys number in the hundreds.
func (a *Auth) validAPIKey(secret string) bool {
	_, ok := a.apiKeyScope(secret)
	return ok
}

// apiKeyScope reports the scope of a live key ("read" or "admin"). Expired or
// unknown secrets return ok=false.
func (a *Auth) apiKeyScope(secret string) (scope string, ok bool) {
	if secret == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for _, k := range a.keys {
		if len(secret) == len(k.secret) && subtle.ConstantTimeCompare([]byte(secret), []byte(k.secret)) == 1 {
			if now.Before(k.expires) {
				return normalizeAPIKeyScope(k.scope), true
			}
			return "", false
		}
	}
	return "", false
}

// ---- brute-force guard (sliding window) ----

// maxLoginFailEntries bounds the login/setup failure tables (mirroring the
// bearer-key table): expired entries sweep first, then the stalest window.
const maxLoginFailEntries = 10000

func (a *Auth) allowLogin(ip string) bool {
	a.flMu.Lock()
	defer a.flMu.Unlock()
	return allowLoginFor(a.fl, ip)
}

// allowSetup reports whether ip may attempt first-run setup now. Setup
// guesses draw from their own bucket so they never lock out login.
func (a *Auth) allowSetup(ip string) bool {
	a.flMu.Lock()
	defer a.flMu.Unlock()
	return allowLoginFor(a.setupFl, ip)
}

func allowLoginFor(m map[string]*loginFails, ip string) bool {
	f, ok := m[ip]
	if !ok || f == nil || time.Now().After(f.windowStart.Add(loginLockWindow)) {
		return true
	}
	return f.count < maxLoginFails
}

func (a *Auth) recordFail(ip string) {
	a.flMu.Lock()
	defer a.flMu.Unlock()
	recordFailFor(a.fl, ip)
}

// recordSetupFail records one bad setup token from ip.
func (a *Auth) recordSetupFail(ip string) {
	a.flMu.Lock()
	defer a.flMu.Unlock()
	if a.setupFl == nil {
		a.setupFl = make(map[string]*loginFails)
	}
	recordFailFor(a.setupFl, ip)
}

func recordFailFor(m map[string]*loginFails, ip string) {
	now := time.Now()
	if len(m) >= maxLoginFailEntries {
		for k, f := range m {
			if f == nil || now.After(f.windowStart.Add(loginLockWindow)) {
				delete(m, k)
			}
		}
	}
	for len(m) >= maxLoginFailEntries {
		// LRU: evict the stalest window so rotating IPs stay bounded.
		victim := ""
		var oldest time.Time
		first := true
		for k, f := range m {
			var t time.Time
			if f != nil {
				t = f.windowStart
			}
			if first || t.Before(oldest) {
				victim, oldest, first = k, t, false
			}
		}
		if victim == "" {
			break
		}
		delete(m, victim)
	}
	f, ok := m[ip]
	if !ok || f == nil || now.After(f.windowStart.Add(loginLockWindow)) {
		m[ip] = &loginFails{count: 1, windowStart: now}
		return
	}
	f.count++
}

func (a *Auth) clearFails(ip string) {
	a.flMu.Lock()
	delete(a.fl, ip)
	a.flMu.Unlock()
}

// ---- bearer API-key brute-force guard (5 fails => 5min 429 per IP) ----

// apiKeyFail is one client IP's bad-bearer-key state.
type apiKeyFail struct {
	count int
	until time.Time
	last  time.Time // last failure; unlocked counters expire apiKeyLockWindow after it
}

// allowAPIKey reports whether ip may attempt bearer auth now.
func (a *Auth) allowAPIKey(ip string) bool {
	a.apiFlMu.Lock()
	defer a.apiFlMu.Unlock()
	f, ok := a.apiFl[ip]
	if !ok {
		return true
	}
	now := time.Now()
	if !f.until.IsZero() {
		if now.Before(f.until) {
			return false
		}
		delete(a.apiFl, ip)
		return true
	}
	if now.Sub(f.last) > apiKeyLockWindow {
		delete(a.apiFl, ip)
	}
	return true
}

// recordAPIKeyFail records one bad bearer key from ip, locking the IP for
// apiKeyLockWindow once the failure budget is spent.
func (a *Auth) recordAPIKeyFail(ip string) {
	a.apiFlMu.Lock()
	defer a.apiFlMu.Unlock()
	if a.apiFl == nil {
		a.apiFl = make(map[string]*apiKeyFail)
	}
	now := time.Now()
	if len(a.apiFl) >= maxAPIKeyFailEntries {
		for k, f := range a.apiFl {
			if f == nil || (!f.until.IsZero() && now.After(f.until)) || (f.until.IsZero() && now.Sub(f.last) > apiKeyLockWindow) {
				delete(a.apiFl, k)
			}
		}
	}
	for len(a.apiFl) >= maxAPIKeyFailEntries {
		// LRU: evict the stalest entry so rotating IPs stay bounded.
		victim := ""
		var oldest time.Time
		first := true
		for k, f := range a.apiFl {
			var t time.Time
			if f != nil {
				t = f.last
			}
			if first || t.Before(oldest) {
				victim, oldest, first = k, t, false
			}
		}
		if victim == "" {
			break
		}
		delete(a.apiFl, victim)
	}
	f := a.apiFl[ip]
	if f == nil {
		f = &apiKeyFail{}
		a.apiFl[ip] = f
	} else if now.Sub(f.last) > apiKeyLockWindow {
		f.count = 0
		f.until = time.Time{}
	}
	f.count++
	f.last = now
	if f.count >= maxAPIKeyFails {
		f.until = now.Add(apiKeyLockWindow)
		f.count = 0
	}
}

// clearAPIKeyFails resets ip's bearer failure state after a successful auth.
func (a *Auth) clearAPIKeyFails(ip string) {
	a.apiFlMu.Lock()
	delete(a.apiFl, ip)
	a.apiFlMu.Unlock()
}

// isLoopbackIP reports whether ip is a loopback address. Unparseable input
// is not loopback (fail-closed: strangers get the limiter).
func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil && parsed.IsLoopback()
}

// ClientIP returns the immediate peer address. Forwarded headers are NOT
// trusted (they are trivially spoofable), so the brute-force limiter cannot be
// bypassed by rotating X-Forwarded-For.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

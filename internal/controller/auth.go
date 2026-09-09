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
	a.flMu.Unlock()
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
	if !a.allowLogin(clientIP) {
		return "", errLocked
	}
	// constant-time username + password comparison
	if !a.verify(username, password) {
		a.recordFail(clientIP)
		return "", errBadCreds
	}
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

func (a *Auth) verify(user, pass string) bool {
	a.mu.Lock()
	username := a.username
	hash := append([]byte(nil), a.passHash...)
	a.mu.Unlock()
	if !constantTimeEq(user, username) {
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
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

// MintCookie writes a fresh session cookie for the given session id.
func (a *Auth) MintCookie(w http.ResponseWriter, r *http.Request, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
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
	Created time.Time `json:"created_at"`
	Expires time.Time `json:"expires_at"`
}

type apiKey struct {
	secret  string
	label   string
	created time.Time
	expires time.Time
}

// CreateAPIKey mints a bearer key for /api/* valid for ttl. ttl must be
// positive and at most 30 days.
func (a *Auth) CreateAPIKey(label string, ttl time.Duration) (id, secret string, expires time.Time, err error) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > maxAPIKeyLabelLen {
		return "", "", time.Time{}, errors.New("label must be 1-64 characters")
	}
	if ttl <= 0 || ttl > maxAPIKeyTTL {
		return "", "", time.Time{}, errors.New("ttl must be positive and at most 30 days")
	}
	raw, err := newSessionID() // 32 random bytes, hex — reuse the session secret shape
	if err != nil {
		return "", "", time.Time{}, err
	}
	idRaw := make([]byte, 6)
	if _, err := rand.Read(idRaw); err != nil {
		return "", "", time.Time{}, err
	}
	now := time.Now()
	k := apiKey{secret: "blip_" + raw, label: label, created: now, expires: now.Add(ttl)}
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
		out = append(out, APIKeyInfo{ID: id, Label: k.label, Created: k.created, Expires: k.expires})
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
	if secret == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for _, k := range a.keys {
		if len(secret) == len(k.secret) && subtle.ConstantTimeCompare([]byte(secret), []byte(k.secret)) == 1 {
			return now.Before(k.expires)
		}
	}
	return false
}

// ---- brute-force guard (sliding window) ----

func (a *Auth) allowLogin(ip string) bool {
	a.flMu.Lock()
	defer a.flMu.Unlock()
	f, ok := a.fl[ip]
	if !ok || time.Now().After(f.windowStart.Add(loginLockWindow)) {
		return true
	}
	return f.count < maxLoginFails
}

func (a *Auth) recordFail(ip string) {
	a.flMu.Lock()
	defer a.flMu.Unlock()
	f, ok := a.fl[ip]
	now := time.Now()
	if !ok || now.After(f.windowStart.Add(loginLockWindow)) {
		a.fl[ip] = &loginFails{count: 1, windowStart: now}
		return
	}
	f.count++
}

func (a *Auth) clearFails(ip string) {
	a.flMu.Lock()
	delete(a.fl, ip)
	a.flMu.Unlock()
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

// Package filter implements per-client DNS filtering policy.
//
// A Store maps a client's source IP to a Policy via longest-prefix CIDR
// matching. Each Policy carries allow/block domain sets with suffix and
// wildcard matching, a block action, and optional upstream override.
package filter

import (
	"errors"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
)

// BlockAction is what the server returns for a blocked query.
type BlockAction string

const (
	ActionNXDOMAIN BlockAction = "nxdomain"
	ActionRefused  BlockAction = "refused"
	ActionZero     BlockAction = "zero"
)

// DefaultAction is used when a policy omits BlockAction.
const DefaultAction = ActionNXDOMAIN

// Policy describes filtering for a set of client networks or DoH client IDs.
type Policy struct {
	ID          string      `json:"id" yaml:"id"`
	Networks    []string    `json:"networks" yaml:"networks"` // CIDR strings
	Clients     []string    `json:"clients" yaml:"clients"`   // DoH client IDs: exact match on the /dns-query/<id> segment (prefix optional); only applies to clients also inside Networks
	Allow       []string    `json:"allow" yaml:"allow"`       // whitelist (exact/suffix/*.wild)
	Block       []string    `json:"block" yaml:"block"`       // blacklist (exact/suffix/*.wild)
	BlockAction BlockAction `json:"block_action" yaml:"block_action"`
	Log         bool        `json:"log" yaml:"log"`
	Upstream    string      `json:"upstream" yaml:"upstream"` // optional upstream group id
}

func (p *Policy) action() BlockAction {
	if p.BlockAction == "" {
		return DefaultAction
	}
	return p.BlockAction
}

// matcher matches a domain name against an exact/suffix/wildcard set.
type matcher struct {
	exact   map[string]struct{}
	suffix  map[string]struct{} // root domain; matches name == root or subdomain of root
	subOnly map[string]struct{} // from *.root; matches only subdomains of root
}

func buildMatcher(domains []string) *matcher {
	m := &matcher{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			root := strings.TrimSuffix(d[2:], ".")
			// A leading-dot remainder (e.g. "*..example.com") is a typo, not
			// a subdomain: reject it rather than liberalising a malformed
			// allow entry into a broad match.
			if root == "" || strings.HasPrefix(root, ".") || strings.Contains(root, "..") {
				continue
			}
			if m.subOnly == nil {
				m.subOnly = make(map[string]struct{}, len(domains))
			}
			m.subOnly[root] = struct{}{}
			continue
		}
		// Leading-dot form (".example.com") is equivalent to "example.com"
		// (exact + subdomains), not "never match". Strip leading dots.
		if strings.HasPrefix(d, ".") {
			d = strings.TrimLeft(d, ".")
			if d == "" {
				continue
			}
		}
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		// Strip any residual leading dot after trailing-dot removal.
		d = strings.TrimPrefix(d, ".")
		if d == "" {
			continue
		}
		if m.exact == nil {
			m.exact = make(map[string]struct{}, len(domains))
			m.suffix = make(map[string]struct{}, len(domains))
		}
		m.exact[d] = struct{}{}
		m.suffix[d] = struct{}{}
	}
	return m
}

// broadPublicSuffixes is a minimal set of public suffixes used only to warn
// when an allowlist entry is dangerously broad. Matching semantics are
// unchanged; this only drives a loud log warning.
var broadPublicSuffixes = map[string]struct{}{
	"com": {}, "org": {}, "net": {}, "io": {}, "dev": {}, "app": {},
	"co": {}, "ne": {}, "or": {},
	"co.uk": {}, "org.uk": {}, "me.uk": {}, "co.jp": {}, "com.au": {},
	"com.br": {}, "co.in": {}, "co.nz": {}, "com.cn": {},
}

// isBroadAllowEntry reports whether an allowlist entry is dangerously broad:
// a single-label TLD (e.g. "com"), a public suffix (e.g. "co.uk"), a bare
// "*" wildcard, or a "*.TLD" / "*.public-suffix" entry that would allow
// millions of domains. Callers must not change matching semantics based on
// this; it only drives a warning log.
func isBroadAllowEntry(d string) bool {
	s := strings.ToLower(strings.TrimSpace(d))
	if s == "" {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	if s == "*" {
		return true
	}
	if strings.HasPrefix(s, "*.") {
		root := strings.TrimSuffix(s[2:], ".")
		root = strings.TrimPrefix(root, ".")
		if root == "" {
			return true
		}
		if !strings.Contains(root, ".") {
			// "*.com" covers a whole TLD.
			return true
		}
		if _, ok := broadPublicSuffixes[root]; ok {
			return true
		}
		// Very short roots (e.g. "*.a.bc") are almost certainly public.
		if len(root) <= 5 {
			return true
		}
		return false
	}
	if strings.HasPrefix(s, ".") {
		s = strings.TrimLeft(s, ".")
		s = strings.TrimSuffix(s, ".")
		if s == "" {
			return true
		}
	}
	if !strings.Contains(s, ".") {
		// Single-label allow (e.g. "com") matches the TLD and all subdomains.
		return true
	}
	if _, ok := broadPublicSuffixes[s]; ok {
		return true
	}
	return false
}

// IsBroadAllowEntry reports whether an allowlist entry is dangerously broad.
// Exported for tests and management tooling; matching semantics are unchanged.
func IsBroadAllowEntry(d string) bool { return isBroadAllowEntry(d) }

func warnBroadAllow(policyID string, allow []string) {
	for _, a := range allow {
		if isBroadAllowEntry(a) {
			log.Printf("filter: WARNING policy %q allow entry %q is very broad (matches a TLD/public-suffix or millions of domains); refine it to avoid bypassing the blocklist", policyID, a)
		}
	}
}

// NormalizeName lowercases a DNS name and strips the root dot (wire format
// always carries it). Matchers store normalized keys, so every lookup
// normalizes once up front instead of per match walk. ASCII fast path avoids
// allocating when the name is already lowercase (the common case) — DNS names
// are ASCII, so strings.ToLower's Unicode handling is unnecessary here.
func NormalizeName(name string) string {
	name = strings.TrimSuffix(name, ".")
	// Audit 2026-10-01 #11: qnames reach log lines (blipd [block] log, query
	// log, /api/v1/logs), so strip control bytes here at the shared choke
	// point — every caller normalizes through this function.
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x20 || c == 0x7f {
			name = strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return -1
				}
				return r
			}, name)
			break
		}
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c >= 'A' && c <= 'Z' {
			return strings.ToLower(name)
		}
	}
	return name
}

// normalizeName lowercases a DNS name and strips the root dot (wire format
// always carries it). Matchers store normalized keys, so every lookup
// normalizes once up front instead of per match walk.
func normalizeName(name string) string {
	return NormalizeName(name)
}

// match reports whether name is covered by this matcher.
// name must already be normalized (see normalizeName).
func (m *matcher) match(name string) bool {
	if m == nil || name == "" {
		return false
	}
	if _, ok := m.exact[name]; ok {
		return true
	}
	// Single dot-walk probing both tables per label boundary: the old code
	// walked the name twice (suffix, then subOnly).
	if len(m.suffix) == 0 && len(m.subOnly) == 0 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] != '.' {
			continue
		}
		rest := name[i+1:]
		if _, ok := m.suffix[rest]; ok {
			return true
		}
		if _, ok := m.subOnly[rest]; ok {
			return true
		}
	}
	return false
}

type compiledPolicy struct {
	Policy
	allowM *matcher
	blockM *matcher
	nets   []*net.IPNet // parsed from Networks once at Set time
}

func compile(p *Policy) *compiledPolicy {
	return &compiledPolicy{
		Policy: *p,
		allowM: buildMatcher(p.Allow),
		blockM: buildMatcher(p.Block),
	}
}

type netEntry struct {
	net    *net.IPNet
	ones   int // prefix length, precomputed at rebuild for longest-match sort
	policy *compiledPolicy
}

// Store maps client IPs and DoH client IDs to policies and classifies queries.
type Store struct {
	mu       sync.RWMutex
	defaults *compiledPolicy
	policies map[string]*compiledPolicy // by ID
	nets     []netEntry
	byClient map[string]*compiledPolicy // by DoH client ID
}

// NewStore creates a Store with the given default policy (nil allowed).
func NewStore(def *Policy) *Store {
	s := &Store{
		policies: make(map[string]*compiledPolicy),
		byClient: make(map[string]*compiledPolicy),
	}
	if def != nil {
		s.defaults = compileDefault(def)
	}
	s.rebuildLocked()
	return s
}

// SetDefault replaces the default (fallback) policy.
func (s *Store) SetDefault(p *Policy) {
	if p != nil {
		warnBroadAllow("default", p.Allow)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil {
		s.defaults = nil
		s.rebuildLocked()
		return
	}
	s.defaults = compileDefault(p)
	s.rebuildLocked()
}

// compileDefault compiles the fallback policy including its networks (best
// effort) so IDs listed on it verify. Named policies stay strict via
// SetPolicy; a bad default CIDR fails closed to no networks.
func compileDefault(p *Policy) *compiledPolicy {
	cp := compile(p)
	if nets, err := parseNetworks(p); err == nil {
		cp.nets = nets
	}
	return cp
}

// SetPolicy adds or replaces a policy by ID and (re)builds its network table.
func (s *Store) SetPolicy(p *Policy) error {
	if p == nil || p.ID == "" {
		return ErrPolicyID
	}
	warnBroadAllow(p.ID, p.Allow)
	cp := compile(p)
	nets, err := parseNetworks(p)
	if err != nil {
		return err
	}
	cp.nets = nets
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = cp
	s.rebuildLocked()
	return nil
}

// parseNetworks parses p.Networks once. SetPolicy is strict (bad CIDR is an
// error); the default path is best-effort — a bad default CIDR fails closed
// to no networks, exactly as before, when defaults never parsed Networks.
func parseNetworks(p *Policy) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, n := range p.Networks {
		_, ipnet, err := net.ParseCIDR(n)
		if err != nil {
			return nil, &NetError{Net: n, Err: err}
		}
		nets = append(nets, ipnet)
	}
	return nets, nil
}

// RemovePolicy deletes a policy by ID.
func (s *Store) RemovePolicy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, id)
	s.rebuildLocked()
}

func (s *Store) rebuildLocked() {
	totalNets := 0
	totalClients := 0
	for _, cp := range s.policies {
		totalNets += len(cp.nets)
		totalClients += len(cp.Clients)
	}
	if s.defaults != nil {
		totalClients += len(s.defaults.Clients)
	}
	nets := make([]netEntry, 0, totalNets)
	byClient := make(map[string]*compiledPolicy, totalClients)
	// Iterate in a stable order so a client ID claimed by several policies
	// resolves deterministically (the last policy in sorted ID order wins).
	ids := make([]string, 0, len(s.policies))
	for id := range s.policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		cp := s.policies[id]
		for _, ipnet := range cp.nets {
			ones, _ := ipnet.Mask.Size()
			nets = append(nets, netEntry{net: ipnet, ones: ones, policy: cp})
		}
	}
	// Index the default's client IDs first (named policies overwrite on
	// collision): IDs on the fleet-wide default verify like any other
	// policy. Its networks stay out of the table above: the default remains
	// a fallback and only ever matches its explicit IDs — still requiring
	// the source IP inside its networks, enforced at lookup.
	ordered := make([]*compiledPolicy, 0, len(ids)+1)
	if s.defaults != nil {
		ordered = append(ordered, s.defaults)
	}
	for _, id := range ids {
		ordered = append(ordered, s.policies[id])
	}
	for _, cp := range ordered {
		for _, c := range cp.Clients {
			// Accept the documented "/dns-query/<id>" form as well as the bare
			// id: clientIDFromPath yields the bare path segment, so a policy
			// written with the prefix would otherwise never match.
			// Client IDs match case-insensitively (see foldClientID): a case
			// difference must not silently drop a device into the default,
			// more permissive policy.
			c = strings.TrimPrefix(strings.TrimSpace(c), "/dns-query/")
			if c != "" {
				byClient[foldClientID(c)] = cp
			}
		}
	}
	// Longest-prefix first so lookup can early-exit on first match instead of
	// scanning every CIDR and recomputing Mask.Size per hit.
	sort.Slice(nets, func(i, j int) bool { return nets[i].ones > nets[j].ones })
	s.nets = nets
	s.byClient = byClient
}

func netsContain(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ErrPolicyID is returned when a policy has no ID.
var ErrPolicyID = errors.New("filter: policy requires a non-empty id")

// NetError wraps a CIDR parse failure.
type NetError struct {
	Net string
	Err error
}

func (e *NetError) Error() string {
	return "filter: invalid network " + e.Net + ": " + e.Err.Error()
}

func (e *NetError) Unwrap() error { return e.Err }

// All returns a snapshot of every policy plus the default.
func (s *Store) All() (def *Policy, list []*Policy) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.defaults != nil {
		d := s.defaults.Policy
		def = &d
	}
	list = make([]*Policy, 0, len(s.policies))
	for _, cp := range s.policies {
		p := cp.Policy
		list = append(list, &p)
	}
	return
}

// foldClientID normalizes a DoH client ID for policy matching. IDs are
// matched case-insensitively: the ID travels in a URL path segment and in
// operator-written config, so "Phone" and "phone" must select the same
// policy rather than dropping the device into the default policy.
func foldClientID(id string) string {
	return strings.ToLower(id)
}

// lookup returns the most specific (longest-prefix) policy for ip, else the
// default. A DoH client ID only breaks ties between equally specific CIDR
// matches: it never outranks a longer prefix, and an ID-only policy (no
// networks) never matches. Nets are sorted longest-prefix first so the first
// match wins (early exit, no Mask.Size recompute).
func (s *Store) lookup(ip net.IP, clientID string) *compiledPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lookupLocked(ip, clientID)
}

func (s *Store) lookupLocked(ip net.IP, clientID string) *compiledPolicy {
	// Normalize once: net.ParseIP returns 16B; To4 returns a 4B slice.
	nip := ip
	if ip4 := ip.To4(); ip4 != nil {
		nip = ip4
	}
	// Longest-prefix CIDR match first: nets are sorted most-specific first,
	// so the first hit is the most specific policy covering ip. A
	// self-asserted DoH client-ID must not outrank a more specific CIDR: on
	// 10.9.0.5 with a strict /32, claiming an ID scoped to a broader /16
	// must still land in the /32.
	var best *compiledPolicy
	bestOnes := -1
	for i := range s.nets {
		if s.nets[i].net.Contains(nip) {
			best = s.nets[i].policy
			bestOnes = s.nets[i].ones
			break
		}
	}
	if clientID != "" {
		if p, ok := s.byClient[foldClientID(clientID)]; ok {
			// The ID only breaks ties: it selects its policy when the
			// source IP falls inside that policy's networks at the same
			// specificity as the longest match. A policy with no
			// networks never matches by ID alone: otherwise anyone could
			// claim an ID whose policy carries an allowlist (escaping
			// the global blocklist) or another client's identity. Scope
			// an ID policy with Networks to use it.
			if idOnes := maxContainOnes(p.nets, nip); idOnes >= 0 && idOnes == bestOnes {
				return p
			}
		}
	}
	if best != nil {
		return best
	}
	return s.defaults
}

// maxContainOnes returns the longest prefix length among nets containing ip,
// or -1 when none contains it.
func maxContainOnes(nets []*net.IPNet, ip net.IP) int {
	best := -1
	for _, n := range nets {
		if n.Contains(ip) {
			if ones, _ := n.Mask.Size(); ones > best {
				best = ones
			}
		}
	}
	return best
}

// KnowsClientID reports whether any policy (including the default) lists
// clientID, ignoring networks. It answers "is this name claimed anywhere",
// letting callers tell an unknown asserted ID (safe to display as-is —
// there is no identity to impersonate) from a known-but-unscoped one, which
// must stay "unverified-id".
func (s *Store) KnowsClientID(clientID string) bool {
	if clientID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byClient[foldClientID(clientID)]
	return ok
}

// ClientIDSelected reports whether clientID actually selected its policy for
// ip: the ID is known and the source IP falls inside that policy's networks.
// A self-asserted DoH client-ID must only be attributed in logs and query-log
// events when it really selected the policy; a claimed-but-unscoped ID is
// logged as "unverified-id" so one client cannot impersonate another's
// identity.
func (s *Store) ClientIDSelected(ip net.IP, clientID string) bool {
	if clientID == "" || ip == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.byClient[foldClientID(clientID)]
	if !ok || len(p.nets) == 0 {
		return false
	}
	nip := ip
	if ip4 := ip.To4(); ip4 != nil {
		nip = ip4
	}
	if !netsContain(p.nets, nip) {
		return false
	}
	// The ID counts as selected only when lookup actually picks its policy:
	// a more specific CIDR may have won instead.
	return s.lookupLocked(ip, clientID) == p
}

// Check evaluates allow/block for an already-normalized name in a single
// lookup + single allow walk + single block walk. It replaces the
// Allowed+Classify+BlockSource triple on the query hot path (which paid 2-3x
// CIDR scans, normalizes and walks). Callers that already normalized with
// NormalizeName must use this (or the *Normalized helpers) to avoid
// re-lowercasing per stage.
func (s *Store) Check(clientIP net.IP, clientID, normalizedName string) (allowed, blocked bool, action BlockAction, upstream string, doLog bool, source string) {
	s.mu.RLock()
	p := s.lookupLocked(clientIP, clientID)
	s.mu.RUnlock()
	if p == nil {
		return false, false, DefaultAction, "", false, ""
	}
	if p.allowM.match(normalizedName) {
		return true, false, p.action(), p.Upstream, p.Log, ""
	}
	if p.blockM.match(normalizedName) {
		id := p.ID
		if id == "" {
			id = "default"
		}
		return false, true, p.action(), p.Upstream, p.Log, "policy:" + id
	}
	return false, false, p.action(), p.Upstream, p.Log, ""
}

// ClassifyNormalized is Classify for an already-normalized name (see
// NormalizeName): it skips the per-call ToLower allocation.
func (s *Store) ClassifyNormalized(clientIP net.IP, clientID, normalizedName string) (blocked bool, action BlockAction, upstream string, log bool) {
	_, blocked, action, upstream, log, _ = s.Check(clientIP, clientID, normalizedName)
	return blocked, action, upstream, log
}

// AllowedNormalized is Allowed for an already-normalized name.
func (s *Store) AllowedNormalized(clientIP net.IP, clientID, normalizedName string) bool {
	allowed, _, _, _, _, _ := s.Check(clientIP, clientID, normalizedName)
	return allowed
}

// Classify reports whether name from clientIP (or DoH clientID) should be
// blocked. The longest-prefix CIDR match wins; a client ID only breaks ties
// between equally specific matches.
// Allowlist takes precedence over blocklist. Returns the matched policy's
// block action, upstream override (if any), and whether logging is enabled.
func (s *Store) Classify(clientIP net.IP, clientID, name string) (blocked bool, action BlockAction, upstream string, log bool) {
	p := s.lookup(clientIP, clientID)
	if p == nil {
		return false, DefaultAction, "", false
	}
	name = normalizeName(name)
	if p.allowM.match(name) {
		return false, p.action(), p.Upstream, p.Log
	}
	if p.blockM.match(name) {
		return true, p.action(), p.Upstream, p.Log
	}
	return false, p.action(), p.Upstream, p.Log
}

// Allowed reports whether name is allowlisted by the policy for this client (or
// the default policy), regardless of any block rules. A whitelisted domain
// ignores every blocklist — the global one included. Returns false when no
// policy applies or the name is not allowlisted.
func (s *Store) Allowed(clientIP net.IP, clientID, name string) bool {
	p := s.lookup(clientIP, clientID)
	if p == nil {
		return false
	}
	return p.allowM.match(normalizeName(name))
}

// BlockSource returns a short label identifying the rule that would block
// name from clientIP (or DoH clientID), or "" when the name is not blocked —
// e.g. it is allowed by an allowlist or no policy applies. Labels look like
// "policy:default". Used to attribute block events to a specific policy.
func (s *Store) BlockSource(clientIP net.IP, clientID, name string) string {
	p := s.lookup(clientIP, clientID)
	if p == nil {
		return ""
	}
	name = normalizeName(name)
	if p.allowM.match(name) || !p.blockM.match(name) {
		return ""
	}
	id := p.ID
	if id == "" {
		id = "default"
	}
	return "policy:" + id
}

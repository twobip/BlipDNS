// Package filter implements per-client DNS filtering policy.
//
// A Store maps a client's source IP to a Policy via longest-prefix CIDR
// matching. Each Policy carries allow/block domain sets with suffix and
// wildcard matching, a block action, and optional upstream override.
package filter

import (
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
	Clients     []string    `json:"clients" yaml:"clients"`   // DoH client IDs (exact match, e.g. "/dns-query/phone")
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
	m := &matcher{
		exact:   make(map[string]struct{}),
		suffix:  make(map[string]struct{}),
		subOnly: make(map[string]struct{}),
	}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			root := d[2:]
			if root != "" {
				m.subOnly[root] = struct{}{}
			}
			continue
		}
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		m.exact[d] = struct{}{}
		m.suffix[d] = struct{}{}
	}
	return m
}

// match reports whether name is covered by this matcher.
func (m *matcher) match(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return false
	}
	if _, ok := m.exact[name]; ok {
		return true
	}
	labels := strings.Split(name, ".")
	// suffix roots: name == root or name is a subdomain of root.
	for i := 0; i < len(labels); i++ {
		root := strings.Join(labels[i:], ".")
		if _, ok := m.suffix[root]; ok {
			return true
		}
	}
	// subOnly roots: only subdomains (i >= 1) match.
	for i := 1; i < len(labels); i++ {
		root := strings.Join(labels[i:], ".")
		if _, ok := m.subOnly[root]; ok {
			return true
		}
	}
	return false
}

type compiledPolicy struct {
	Policy
	allowM *matcher
	blockM *matcher
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
		s.defaults = compile(def)
	}
	return s
}

// SetDefault replaces the default (fallback) policy.
func (s *Store) SetDefault(p *Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil {
		s.defaults = nil
		return
	}
	s.defaults = compile(p)
}

// SetPolicy adds or replaces a policy by ID and (re)builds its network table.
func (s *Store) SetPolicy(p *Policy) error {
	if p == nil || p.ID == "" {
		return ErrPolicyID
	}
	cp := compile(p)
	entries := make([]netEntry, 0, len(p.Networks))
	for _, n := range p.Networks {
		_, ipnet, err := net.ParseCIDR(n)
		if err != nil {
			return &NetError{Net: n, Err: err}
		}
		entries = append(entries, netEntry{net: ipnet, policy: cp})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = cp
	s.rebuildLocked()
	return nil
}

// RemovePolicy deletes a policy by ID.
func (s *Store) RemovePolicy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, id)
	s.rebuildLocked()
}

func (s *Store) rebuildLocked() {
	nets := make([]netEntry, 0)
	byClient := make(map[string]*compiledPolicy)
	// Iterate in a stable order so a client ID claimed by several policies
	// resolves deterministically (the last policy in sorted ID order wins).
	ids := make([]string, 0, len(s.policies))
	for id := range s.policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		cp := s.policies[id]
		for _, n := range cp.Networks {
			_, ipnet, err := net.ParseCIDR(n)
			if err != nil {
				continue
			}
			nets = append(nets, netEntry{net: ipnet, policy: cp})
		}
		for _, c := range cp.Clients {
			if c != "" {
				byClient[c] = cp
			}
		}
	}
	s.nets = nets
	s.byClient = byClient
}

// All returns a snapshot of every policy plus the default.
func (s *Store) All() (def *Policy, list []*Policy) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.defaults != nil {
		d := s.defaults.Policy
		def = &d
	}
	for _, cp := range s.policies {
		p := cp.Policy
		list = append(list, &p)
	}
	return
}

// lookup returns the policy for a DoH client ID if one matches, otherwise the
// most specific policy for ip, else the default.
func (s *Store) lookup(ip net.IP, clientID string) *compiledPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if clientID != "" {
		if p, ok := s.byClient[clientID]; ok {
			return p
		}
	}
	best := -1
	var bp *compiledPolicy
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, e := range s.nets {
		if e.net.Contains(ip) {
			ones, _ := e.net.Mask.Size()
			if ones > best {
				best = ones
				bp = e.policy
			}
		}
	}
	if bp != nil {
		return bp
	}
	return s.defaults
}

// Classify reports whether name from clientIP (or DoH clientID) should be
// blocked. A matching client ID takes precedence over the IP network.
// Allowlist takes precedence over blocklist. Returns the matched policy's
// block action, upstream override (if any), and whether logging is enabled.
func (s *Store) Classify(clientIP net.IP, clientID, name string) (blocked bool, action BlockAction, upstream string, log bool) {
	p := s.lookup(clientIP, clientID)
	if p == nil {
		return false, DefaultAction, "", false
	}
	if p.allowM.match(name) {
		return false, p.action(), p.Upstream, p.Log
	}
	if p.blockM.match(name) {
		return true, p.action(), p.Upstream, p.Log
	}
	return false, p.action(), p.Upstream, p.Log
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
	if p.allowM.match(name) || !p.blockM.match(name) {
		return ""
	}
	id := p.ID
	if id == "" {
		id = "default"
	}
	return "policy:" + id
}

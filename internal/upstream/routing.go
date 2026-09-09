package upstream

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// UpstreamServer is a named upstream endpoint. A server is part of the
// automatic failover rotation only when Priority > 0; Priority == 0 means the
// server is used *only* when an UpstreamRoute points at it — it is never tried
// automatically, even when every Priority>0 server is down.
type UpstreamServer struct {
	Name       string `json:"name" yaml:"name"`
	Address    string `json:"address" yaml:"address"` // single endpoint spec: "udp://host:port", "tls://host[:port]" (DoT, default 853) or "https://host/dns-query"
	Priority   int    `json:"priority" yaml:"priority"`
	TimeoutSec int    `json:"timeout_sec,omitempty" yaml:"timeout_sec,omitempty"` // seconds to wait before failing over to next server (0 = 5s default)
}

// UpstreamRoute conditionally forwards a query to a named server when its qname
// ends with QnameSuffix and (optionally) the client source IP is inside
// ClientCIDR. A ClientCIDR of "" or "0.0.0.0/0" matches every client. A route
// with Disabled set is carried through config/stats readback but never matches
// queries — the operator can turn it on without losing the rule.
type UpstreamRoute struct {
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	QnameSuffix string `json:"qname_suffix" yaml:"qname_suffix"` // e.g. ".in-addr.arpa." (trailing dot optional)
	Server      string `json:"server" yaml:"server"`             // references an UpstreamServer.Name
	ClientCIDR  string `json:"client_cidr,omitempty" yaml:"client_cidr,omitempty"`
	Disabled    bool   `json:"disabled,omitempty" yaml:"disabled,omitempty"` // absent/false = active
}

// ResolverPool is the runtime upstream configuration: named resolvers, the
// automatic failover rotation (Priority>0 servers, or the legacy upstream
// string), conditional-forwarding routes, and the bootstrap DNS servers used
// to resolve DoH server hostnames. It is built once and replaced wholesale via
// SetUpstream, so its fields are read-only after construction.
type ResolverPool struct {
	named     map[string]Resolver // server name -> resolver (all servers, incl. priority 0)
	auto      Resolver            // Priority>0 servers as an ordered failover group, or the legacy upstream
	rules     []routeRule         // conditional-forwarding routes
	servers   []UpstreamServer
	routes    []UpstreamRoute
	bootstrap []UpstreamServer // bootstrap DNS servers for resolving DoH server hostnames
}

type routeRule struct {
	suffix  string     // lowercased, root-dotted
	network *net.IPNet // nil = match all
	server  string
}

// NewPool builds a resolver pool. If servers is empty and legacyUp is non-empty,
// legacyUp is parsed into the automatic rotation (so existing single
// `upstream:` configs keep working). Passing nil/empty for both servers and
// legacyUp yields a pool with no automatic resolver (only routes).
func NewPool(servers []UpstreamServer, routes []UpstreamRoute, legacyUp string) (*ResolverPool, error) {
	return NewPoolWithBootstrap(servers, routes, legacyUp, nil)
}

// NewPoolWithBootstrap builds a resolver pool exactly like NewPool, plus a set
// of bootstrap DNS servers used to resolve the hostnames of DoH upstream
// servers before dialing them. Each entry is a single endpoint spec like
// "1.1.1.1" or "https://1.1.1.1/dns-query" (bootstrap servers support both UDP
// and DoH; see fromServerSpec). An empty bootstrap leaves DoH hostnames to the
// system resolver.
func NewPoolWithBootstrap(servers []UpstreamServer, routes []UpstreamRoute, legacyUp string, bootstrap []UpstreamServer) (*ResolverPool, error) {
	p := &ResolverPool{named: make(map[string]Resolver), bootstrap: bootstrap}
	p.servers = servers
	p.routes = routes
	bootstrapResolver, err := BuildBootstrapResolver(bootstrap)
	if err != nil {
		return nil, err
	}
	for _, sv := range servers {
		if sv.Name == "" {
			sv.Name = "server#" + sv.Address
		}
		if _, dup := p.named[sv.Name]; dup {
			return nil, fmt.Errorf("upstream: duplicate server name %q", sv.Name)
		}
		r, err := fromServerSpecWithBootstrap(sv.Address, timeoutForServer(sv), bootstrapResolver)
		if err != nil {
			return nil, fmt.Errorf("upstream: server %q: %w", sv.Name, err)
		}
		p.named[sv.Name] = r
	}
	// Automatic rotation: Priority>0 servers, lowest number first.
	var order []string
	for _, sv := range p.servers {
		if sv.Priority > 0 {
			order = append(order, sv.Name)
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		pi := serverPriority(p.servers, order[i])
		pj := serverPriority(p.servers, order[j])
		if pi == pj {
			return order[i] < order[j]
		}
		return pi < pj
	})
	var autos []Resolver
	for _, name := range order {
		autos = append(autos, p.named[name])
	}
	switch len(autos) {
	case 0:
		if legacyUp != "" {
			r, err := FromSpec(legacyUp)
			if err != nil {
				return nil, fmt.Errorf("upstream: default upstream %q: %w", legacyUp, err)
			}
			p.auto = r
		}
	case 1:
		p.auto = autos[0]
	default:
		p.auto = NewMulti(autos...)
	}
	for _, rt := range routes {
		if rt.Disabled {
			continue
		}
		rule, err := makeRouteRule(rt, p.named)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, rule)
	}
	return p, nil
}

// NewPoolWithAuto builds a resolver pool whose automatic resolver is exactly r,
// with no named servers or routes. It exists so tests can inject a stub
// resolver; production code builds pools from server specs via NewPool.
func NewPoolWithAuto(r Resolver) *ResolverPool {
	return &ResolverPool{auto: r}
}

func serverPriority(servers []UpstreamServer, name string) int {
	for _, sv := range servers {
		if sv.Name == name || (sv.Name == "" && "server#"+sv.Address == name) {
			return sv.Priority
		}
	}
	return 0
}

// fromServerSpec builds a single resolver from one endpoint spec and timeout.
// A server address must name exactly one endpoint (the multi-token form belongs
// to the legacy `upstream:` string, handled by FromSpec).
func fromServerSpec(spec string, timeout time.Duration) (Resolver, error) {
	return fromServerSpecWithBootstrap(spec, timeout, nil)
}

// fromServerSpecWithBootstrap is fromServerSpec with the DoH resolver threaded
// a bootstrap resolver for resolving the endpoint's own hostname.
func fromServerSpecWithBootstrap(spec string, timeout time.Duration, bootstrap Resolver) (Resolver, error) {
	specs, err := ParseSpec(spec)
	if err != nil {
		return nil, err
	}
	if len(specs) != 1 {
		return nil, fmt.Errorf("address %q resolves to %d endpoints; a server address must name exactly one (e.g. \"udp://1.1.1.1:53\" or \"https://1.1.1.1/dns-query\")", spec, len(specs))
	}
	switch specs[0].Type {
	case "udp":
		return NewUDP(specs[0].Address, timeout), nil
	case "tls":
		return NewTLS(specs[0].Address, timeout), nil
	case "doh":
		return NewDoHWithBootstrap("https://"+specs[0].Address, timeout, bootstrap), nil
	}
	return nil, fmt.Errorf("unknown upstream type %q", specs[0].Type)
}

// BuildBootstrapResolver converts the bootstrap server list into a failover
// resolver (MultiResolver) used to resolve DoH server hostnames, or nil for an
// empty list. Bootstrap servers are built without a bootstrap of their own:
// their hostnames resolve via the system resolver, since bootstrapping the
// bootstrap would be circular — so a bootstrap endpoint should be a literal IP
// (e.g. "1.1.1.1" or "https://1.1.1.1/dns-query").
func BuildBootstrapResolver(bootstrap []UpstreamServer) (Resolver, error) {
	var rs []Resolver
	for _, sv := range bootstrap {
		r, err := fromServerSpec(sv.Address, timeoutForServer(sv))
		if err != nil {
			return nil, fmt.Errorf("upstream: bootstrap server %q: %w", sv.Address, err)
		}
		rs = append(rs, r)
	}
	switch len(rs) {
	case 0:
		return nil, nil
	case 1:
		return rs[0], nil
	default:
		return NewMulti(rs...), nil
	}
}

// timeoutForServer returns the resolver timeout for an UpstreamServer, defaulting
// to 5 seconds when TimeoutSec is unset (0).
func timeoutForServer(s UpstreamServer) time.Duration {
	if s.TimeoutSec > 0 {
		return time.Duration(s.TimeoutSec) * time.Second
	}
	return 5 * time.Second
}

func makeRouteRule(rt UpstreamRoute, named map[string]Resolver) (routeRule, error) {
	if rt.Server == "" {
		return routeRule{}, fmt.Errorf("upstream: route %q has empty server", rt.Name)
	}
	if _, ok := named[rt.Server]; !ok {
		return routeRule{}, fmt.Errorf("upstream: route %q references unknown server %q", rt.Name, rt.Server)
	}
	rule := routeRule{server: rt.Server}
	if rt.QnameSuffix == "" {
		return routeRule{}, fmt.Errorf("upstream: route %q has empty qname_suffix", rt.Name)
	}
	rule.suffix = fqdn(rt.QnameSuffix)
	if rt.ClientCIDR != "" && rt.ClientCIDR != "0.0.0.0/0" {
		_, n, err := net.ParseCIDR(rt.ClientCIDR)
		if err != nil {
			return routeRule{}, fmt.Errorf("upstream: route %q has invalid client_cidr %q", rt.Name, rt.ClientCIDR)
		}
		rule.network = n
	}
	return rule, nil
}

// fqdn lowercases and root-dots a domain for suffix comparison.
func fqdn(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "."
	}
	if s[len(s)-1] != '.' {
		s += "."
	}
	return s
}

// Auto returns the automatic failover resolver (Priority>0 servers or the
// legacy upstream), or nil if there is none.
func (p *ResolverPool) Auto() Resolver {
	if p == nil {
		return nil
	}
	return p.auto
}

// Servers and Routes expose the configured set (for stats readback).
func (p *ResolverPool) Servers() []UpstreamServer {
	if p == nil {
		return nil
	}
	return p.servers
}

func (p *ResolverPool) Routes() []UpstreamRoute {
	if p == nil {
		return nil
	}
	return p.routes
}

// Bootstrap returns the configured bootstrap DNS servers (for stats readback).
func (p *ResolverPool) Bootstrap() []UpstreamServer {
	if p == nil {
		return nil
	}
	return p.bootstrap
}

// Match returns the resolver for the best-matching route (longest qname suffix,
// restricted to a matching client CIDR), or nil if no route matches.
func (p *ResolverPool) Match(qname string, client net.IP) Resolver {
	if p == nil {
		return nil
	}
	q := fqdn(qname)
	var best *routeRule
	for i := range p.rules {
		rt := &p.rules[i]
		if !strings.HasSuffix(q, rt.suffix) {
			continue
		}
		if rt.network != nil && client != nil {
			if !rt.network.Contains(client) {
				continue
			}
		}
		if best == nil || len(rt.suffix) > len(best.suffix) {
			best = rt
		}
	}
	if best == nil {
		return nil
	}
	return p.named[best.server]
}

// LabelFor returns a short human-readable label describing r when it is one
// of the pool's named servers or the automatic rotation, and "" otherwise
// (e.g. a per-policy override built outside the pool). The label is used to
// attribute a query to the upstream that answered it.
func (p *ResolverPool) LabelFor(r Resolver) string {
	if p == nil || r == nil {
		return ""
	}
	if r == p.auto {
		var names []string
		for _, sv := range p.servers {
			if sv.Priority > 0 {
				names = append(names, sv.Name)
			}
		}
		if len(names) == 0 {
			return "auto"
		}
		return "auto (" + strings.Join(names, ", ") + ")"
	}
	for _, sv := range p.servers {
		if sv.Name != "" && p.named[sv.Name] == r {
			if sv.Address != "" {
				return sv.Name + " (" + sv.Address + ")"
			}
			return sv.Name
		}
	}
	return ""
}

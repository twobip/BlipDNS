package upstream

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// UpstreamServer is a named upstream endpoint. A server is part of the
// automatic failover rotation only when Priority > 0; Priority == 0 means the
// server is used *only* when an UpstreamRoute points at it — it is never tried
// automatically, even when every Priority>0 server is down.
type UpstreamServer struct {
	Name     string `json:"name" yaml:"name"`
	Address  string `json:"address" yaml:"address"` // single endpoint spec: "udp://host:port" or "https://host/dns-query"
	Priority int    `json:"priority" yaml:"priority"`
}

// UpstreamRoute conditionally forwards a query to a named server when its qname
// ends with QnameSuffix and (optionally) the client source IP is inside
// ClientCIDR. A ClientCIDR of "" or "0.0.0.0/0" matches every client.
type UpstreamRoute struct {
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	QnameSuffix string `json:"qname_suffix" yaml:"qname_suffix"` // e.g. ".in-addr.arpa." (trailing dot optional)
	Server      string `json:"server" yaml:"server"`             // references an UpstreamServer.Name
	ClientCIDR  string `json:"client_cidr,omitempty" yaml:"client_cidr,omitempty"`
}

// ResolverPool is the runtime upstream configuration: named resolvers, the
// automatic failover rotation (Priority>0 servers, or the legacy upstream
// string), and conditional-forwarding routes. It is built once and replaced
// wholesale via SetUpstream, so its fields are read-only after construction.
type ResolverPool struct {
	named   map[string]Resolver // server name -> resolver (all servers, incl. priority 0)
	auto    Resolver            // Priority>0 servers as an ordered failover group, or the legacy upstream
	rules   []routeRule         // conditional-forwarding routes
	servers []UpstreamServer
	routes  []UpstreamRoute
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
	p := &ResolverPool{named: make(map[string]Resolver)}
	p.servers = servers
	p.routes = routes
	for _, sv := range servers {
		if sv.Name == "" {
			sv.Name = "server#" + sv.Address
		}
		if _, dup := p.named[sv.Name]; dup {
			return nil, fmt.Errorf("upstream: duplicate server name %q", sv.Name)
		}
		r, err := fromServerSpec(sv.Address)
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

// fromServerSpec builds a single resolver from one endpoint spec. A server
// address must name exactly one endpoint (the multi-token form belongs to the
// legacy `upstream:` string, handled by FromSpec).
func fromServerSpec(spec string) (Resolver, error) {
	specs, err := ParseSpec(spec)
	if err != nil {
		return nil, err
	}
	if len(specs) != 1 {
		return nil, fmt.Errorf("address %q resolves to %d endpoints; a server address must name exactly one (e.g. \"udp://1.1.1.1:53\" or \"https://1.1.1.1/dns-query\")", spec, len(specs))
	}
	switch specs[0].Type {
	case "udp":
		return NewUDP(specs[0].Address), nil
	case "doh":
		return NewDoH("https://" + specs[0].Address), nil
	}
	return nil, fmt.Errorf("unknown upstream type %q", specs[0].Type)
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

package dnsserver

import (
	"log"
	"net"

	"github.com/twobip/BlipDNS/internal/upstream"
)

// safePool returns the current resolver pool under the read lock (may be nil).
// The pool pointer is swapped by SetUpstream under upMu, so callers must snapshot
// it rather than holding the field across upstream lookups.
func (s *Server) safePool() *upstream.ResolverPool {
	s.upMu.RLock()
	defer s.upMu.RUnlock()
	return s.pool
}

// upstreamAuto returns the automatic failover resolver: the priority>0 servers
// (or, if none, the configured upstream string). It is the default destination
// for queries that match no conditional-forwarding route and no per-policy
// upstream override.
func (s *Server) upstreamAuto() upstream.Resolver {
	p := s.safePool()
	if p == nil {
		return nil
	}
	return p.Auto()
}

// SetUpstream atomically replaces the upstream pool, conditional-forwarding
// routes, and bootstrap DNS servers. Passing nil/empty for all reverts to the
// blipd config-file upstream. This implements control.LocalResolverController
// so the management API can reconfigure forwarding at runtime (the controller
// pushes from Settings).
func (s *Server) SetUpstream(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute, bootstrap []upstream.UpstreamServer) error {
	pool, err := upstream.NewPoolWithBootstrap(servers, routes, s.cfg.Upstream, bootstrap)
	if err != nil {
		return err
	}
	s.upMu.Lock()
	prev := s.pool
	s.pool = pool
	s.upMu.Unlock()
	if prev != nil && pool != nil {
		log.Printf("blipd: upstream pool replaced (was %d servers, now %d)", len(prev.Servers()), len(pool.Servers()))
	}
	return nil
}

// Upstream returns the active upstream pool (servers + routes + bootstrap) for
// stats readback, so the controller can detect drift after a restart.
func (s *Server) Upstream() ([]upstream.UpstreamServer, []upstream.UpstreamRoute, []upstream.UpstreamServer) {
	p := s.safePool()
	if p == nil {
		return nil, nil, nil
	}
	return p.Servers(), p.Routes(), p.Bootstrap()
}

// upstreamFor selects the resolver for a query. Order (per the settings model):
// a matching conditional-forwarding route (name + optional client CIDR) first;
// then the automatic rotation. The per-policy upstream override is applied by
// the caller when routeResolved is false.
func (s *Server) upstreamFor(name string, clientIP net.IP) (r upstream.Resolver, routeResolved bool) {
	p := s.safePool()
	if p != nil {
		if m := p.Match(name, clientIP); m != nil {
			return m, true
		}
	}
	return s.upstreamAuto(), false
}

// overrideResolver returns the memoized resolver for a per-policy upstream
// spec string, building it once on first use.
func (s *Server) overrideResolver(spec string) (upstream.Resolver, error) {
	if r, ok := s.overrides.Load(spec); ok {
		return r.(upstream.Resolver), nil
	}
	r, err := upstream.FromSpec(spec)
	if err != nil {
		return nil, err
	}
	actual, _ := s.overrides.LoadOrStore(spec, r)
	return actual.(upstream.Resolver), nil
}

// upstreamLabel returns a short display label for the resolver used to answer
// a query, for query-log attribution. A per-policy override that actually
// took effect is labeled with its spec; otherwise the pool names the resolver
// (named server or automatic rotation).
func (s *Server) upstreamLabel(resolver upstream.Resolver, matchedRoute bool, override string) string {
	if !matchedRoute && override != "" {
		return "override: " + override
	}
	if p := s.safePool(); p != nil {
		if l := p.LabelFor(resolver); l != "" {
			return l
		}
	}
	return "upstream"
}

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

// SetUpstream atomically replaces the upstream pool and conditional-forwarding
// routes. Passing nil/empty for both reverts to the blipd config-file upstream.
// This implements control.LocalResolverController so the management API can
// reconfigure forwarding at runtime (the controller pushes from Settings).
func (s *Server) SetUpstream(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute) error {
	pool, err := upstream.NewPool(servers, routes, s.cfg.Upstream)
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

// Upstream returns the active upstream pool (servers + routes) for stats
// readback, so the controller can detect drift after a restart.
func (s *Server) Upstream() ([]upstream.UpstreamServer, []upstream.UpstreamRoute) {
	p := s.safePool()
	if p == nil {
		return nil, nil
	}
	return p.Servers(), p.Routes()
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

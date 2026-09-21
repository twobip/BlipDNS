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
// pushes from Settings). The replaced pool's idle DoH keepalives are closed so
// fleet pushes don't leak Transports and thunder-reconnect.
func (s *Server) SetUpstream(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute, bootstrap []upstream.UpstreamServer) error {
	pool, err := upstream.NewPoolWithBootstrap(servers, routes, s.cfg.Upstream, bootstrap)
	if err != nil {
		return err
	}
	s.upMu.Lock()
	prev := s.pool
	s.pool = pool
	s.upMu.Unlock()
	if prev != nil {
		prev.CloseIdleConnections()
		if pool != nil {
			log.Printf("blipd: upstream pool replaced (was %d servers, now %d)", len(prev.Servers()), len(pool.Servers()))
		}
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
	return s.upstreamForWithPool(s.safePool(), name, clientIP)
}

// upstreamForWithPool is upstreamFor against an already-snapshotted pool so
// the hot path takes one RLock per query instead of three (Match + Auto +
// LabelFor each locked separately).
func (s *Server) upstreamForWithPool(p *upstream.ResolverPool, name string, clientIP net.IP) (r upstream.Resolver, routeResolved bool) {
	if p != nil {
		if m := p.Match(name, clientIP); m != nil {
			return m, true
		}
		return p.Auto(), false
	}
	return nil, false
}

// overrideResolver returns the memoized resolver for a per-policy upstream
// spec string, building it once on first use. The memo is capped (LRU-ish
// random eviction with idle-close) so distinct override strings can't grow
// Transports forever.
func (s *Server) overrideResolver(spec string) (upstream.Resolver, error) {
	if r, ok := s.overrides.Load(spec); ok {
		return r.(upstream.Resolver), nil
	}
	r, err := upstream.FromSpec(spec)
	if err != nil {
		return nil, err
	}
	actual, loaded := s.overrides.LoadOrStore(spec, r)
	if !loaded {
		// Cap distinct specs: evict one arbitrary entry when over budget.
		count := 0
		s.overrides.Range(func(k, v any) bool { count++; return count <= 64 })
		if count > 64 {
			s.overrides.Range(func(k, v any) bool {
				if ks, ok := k.(string); ok && ks != spec {
					if old, loaded := s.overrides.LoadAndDelete(ks); loaded {
						if d, ok := old.(interface{ CloseIdleConnections() }); ok {
							d.CloseIdleConnections()
						}
					}
					return false
				}
				return true
			})
		}
		return r, nil
	}
	// Lost the race: close the throwaway's idle conns if DoH-backed.
	if d, ok := r.(interface{ CloseIdleConnections() }); ok {
		d.CloseIdleConnections()
	}
	return actual.(upstream.Resolver), nil
}

// upstreamLabel returns a short display label for the resolver used to answer
// a query, for query-log attribution. A per-policy override that actually
// took effect is labeled with its spec; otherwise the pool names the resolver
// (named server or automatic rotation).
func (s *Server) upstreamLabel(resolver upstream.Resolver, matchedRoute bool, override string) string {
	return upstreamLabelWithPool(s.safePool(), resolver, matchedRoute, override)
}

// upstreamLabelWithPool is upstreamLabel against an already-snapshotted pool.
func upstreamLabelWithPool(p *upstream.ResolverPool, resolver upstream.Resolver, matchedRoute bool, override string) string {
	if !matchedRoute && override != "" {
		return "override: " + override
	}
	if p != nil {
		if l := p.LabelFor(resolver); l != "" {
			return l
		}
	}
	return "upstream"
}

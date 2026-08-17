package control

import "github.com/twobip/BlipDNS/internal/upstream"

// LocalResolverController is the piece of the DNS server the management API can
// reconfigure at runtime: the named upstream pool, conditional-forwarding
// routes, and the bootstrap DNS servers used to resolve DoH server hostnames.
// The controller pushes it from the Settings page and reads it back via
// stats so its poll loop can converge a restarted instance (mirroring the DoH
// and rate-limit controllers).
type LocalResolverController interface {
	// SetUpstream atomically replaces the upstream pool, routes and bootstrap
	// servers. Passing nil for all reverts to the instance's local
	// (config-file) upstream.
	SetUpstream(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute, bootstrap []upstream.UpstreamServer) error
	Upstream() (servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute, bootstrap []upstream.UpstreamServer)
}

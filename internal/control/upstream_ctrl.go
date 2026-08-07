package control

import "github.com/twobip/BlipDNS/internal/upstream"

// LocalResolverController is the piece of the DNS server the management API can
// reconfigure at runtime: the named upstream pool and conditional-forwarding
// routes. The controller pushes it from the Settings page and reads it back via
// stats so its poll loop can converge a restarted instance (mirroring the DoH
// and rate-limit controllers).
type LocalResolverController interface {
	// SetUpstream atomically replaces the upstream pool and routes. Passing nil
	// for both reverts to the instance's local (config-file) upstream.
	SetUpstream(servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute) error
	Upstream() ([]upstream.UpstreamServer, []upstream.UpstreamRoute)
}

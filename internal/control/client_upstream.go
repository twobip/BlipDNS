package control

import (
	"context"
	"net/http"

	"github.com/twobip/BlipDNS/internal/upstream"
)

// SetUpstream replaces the instance's upstream pool and conditional-forwarding
// routes. Passing nil/empty for both reverts the instance to its local
// (config-file) upstream.
func (c *Client) SetUpstream(ctx context.Context, servers []upstream.UpstreamServer, routes []upstream.UpstreamRoute) error {
	return c.do(ctx, http.MethodPut, "/api/v1/upstream", &SetUpstreamRequest{Servers: servers, Routes: routes}, nil)
}

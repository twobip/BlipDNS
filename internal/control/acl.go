// Shared recursion-ACL parsing: blipd validates pushes here at the trust
// boundary, and the DNS server builds its runtime ACL from the same parser
// so the two can never disagree about what a CIDR means.
package control

import (
	"fmt"
	"net"
	"strings"
)

// DefaultAllowedNetworks is the safe closed default: loopback + RFC1918 +
// ULA. Used when blipd boots with no allowed_networks on a non-loopback
// bind (warn-and-default, never crash, never open) and shipped by the
// installer and deploy/blipd.yaml. Single source: keep them in sync.
func DefaultAllowedNetworks() []string {
	return []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}
}

// ParseAllowedNetworks parses recursion-ACL CIDRs/IPs. Empty input means
// allow all (open recursion). Single IPs are treated as /32 (/128 for IPv6).
// Catch-all /0 CIDRs are rejected, mirroring the trusted-proxy parser: they
// silently restore open recursion, so they must be explicit (open_recursion).
func ParseAllowedNetworks(values []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("invalid allowed network %q", value)
			}
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			} else {
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
			continue
		}
		_, n, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed network %q: %w", value, err)
		}
		if ones, _ := n.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("invalid allowed network %q: catch-all CIDR would allow the whole internet; leave allowed_networks empty (with open_recursion: true) for open recursion instead", value)
		}
		out = append(out, n)
	}
	return out, nil
}

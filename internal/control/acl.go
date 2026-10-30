// Shared recursion-ACL parsing: blipd validates pushes here at the trust
// boundary, and the DNS server builds its runtime ACL from the same parser
// so the two can never disagree about what a CIDR means.
package control

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
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
	// Reject split full-space coverage too (0.0.0.0/1 + 128.0.0.0/1, or the
	// IPv6 equivalent): a single /0 is not the only way to allow the whole
	// internet, and this check is the last line of defense against an
	// accidental open resolver. The trusted-proxy parser uses the same guard.
	if FullSpaceCovered(out) {
		return nil, fmt.Errorf("allowed_networks entries collectively cover the whole internet; leave the list empty (with open_recursion: true) for open recursion instead")
	}
	return out, nil
}

// FullSpaceCovered reports whether nets collectively cover the entire IPv4
// or the entire IPv6 address space (e.g. 0.0.0.0/1 + 128.0.0.0/1). Split
// CIDRs like that bypass per-entry /0 rejection and re-trust the whole
// internet (F-17: forwarded-header spoofing via trusted proxies). Shared by
// the trusted-proxy and recursion-ACL parsers so both stay consistent.
func FullSpaceCovered(nets []*net.IPNet) bool {
	var v4 [][2]uint32
	var v6 [][2][16]byte
	for _, n := range nets {
		if n == nil {
			continue
		}
		ones, bits := n.Mask.Size()
		if ones < 0 {
			continue
		}
		switch bits {
		case 32:
			ip := n.IP.To4()
			if ip == nil {
				continue
			}
			m := net.CIDRMask(ones, 32)
			mask := binary.BigEndian.Uint32(m)
			base := binary.BigEndian.Uint32(ip.Mask(m))
			v4 = append(v4, [2]uint32{base, base | ^mask})
		case 128:
			ip := n.IP.To16()
			if ip == nil {
				continue
			}
			m := net.CIDRMask(ones, 128)
			var lo, hi [16]byte
			copy(lo[:], ip.Mask(m))
			for i := range hi {
				hi[i] = lo[i] | ^m[i]
			}
			v6 = append(v6, [2][16]byte{lo, hi})
		}
	}
	return coversV4(v4) || coversV6(v6)
}

// coversV4 reports whether sorted-and-merged ranges cover [0, 2^32).
func coversV4(rs [][2]uint32) bool {
	if len(rs) == 0 {
		return false
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i][0] != rs[j][0] {
			return rs[i][0] < rs[j][0]
		}
		return rs[i][1] > rs[j][1]
	})
	if rs[0][0] != 0 {
		return false
	}
	end := rs[0][1]
	for _, r := range rs[1:] {
		if r[0] > end {
			if end == ^uint32(0) {
				continue
			}
			if r[0] != end+1 {
				return false
			}
		}
		if r[1] > end {
			end = r[1]
		}
	}
	return end == ^uint32(0)
}

// coversV6 reports whether ranges cover the whole 128-bit space.
func coversV6(rs [][2][16]byte) bool {
	if len(rs) == 0 {
		return false
	}
	sort.Slice(rs, func(i, j int) bool {
		if c := bytes.Compare(rs[i][0][:], rs[j][0][:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(rs[i][1][:], rs[j][1][:]) > 0
	})
	var zero [16]byte
	if rs[0][0] != zero {
		return false
	}
	end := rs[0][1]
	for _, r := range rs[1:] {
		if bytes.Compare(r[0][:], end[:]) > 0 {
			next := end
			incr16(&next)
			if r[0] != next {
				return false
			}
		}
		if bytes.Compare(r[1][:], end[:]) > 0 {
			end = r[1]
		}
	}
	var full [16]byte
	for i := range full {
		full[i] = 0xff
	}
	return end == full
}

// incr16 increments a 128-bit address (for adjacency checks in coversV6).
func incr16(a *[16]byte) {
	for i := len(a) - 1; i >= 0; i-- {
		a[i]++
		if a[i] != 0 {
			return
		}
	}
}

package control

import (
	"fmt"
	"net"
	"strings"
)

// MaxRecordTTL caps how long a local record may live (one week, in seconds).
const MaxRecordTTL = 7 * 24 * 3600

// ValidateRecordEntry reports whether r is a servable local DNS record:
// domain labels are ≤63 octets, total ≤253, charset [a-z0-9-]; Type is one of
// A/AAAA/CNAME (case-insensitive); A values must be IPv4, AAAA values IPv6
// (no v4-mapped), CNAME targets must be valid hostnames; TTL is 0 (server
// default) or 1..MaxRecordTTL, compared as int before any uint32 cast.
// Both blipd (push backstop) and blipc (input boundary, so one bad record
// fails the API call instead of bricking every instance push) use this.
func ValidateRecordEntry(r RecordEntry) error {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), "."))
	domain = strings.TrimLeft(domain, ".")
	if domain == "" {
		return fmt.Errorf("empty domain")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain %q too long", r.Domain)
	}
	if strings.HasPrefix(domain, "*.") {
		parent := domain[2:]
		if parent == "" {
			return fmt.Errorf("wildcard %q missing parent", r.Domain)
		}
		if !validRecordHostname(parent) {
			return fmt.Errorf("invalid wildcard parent %q", r.Domain)
		}
	} else {
		if strings.Contains(domain, "*") {
			return fmt.Errorf("wildcard only allowed as \"*.\" prefix: %q", r.Domain)
		}
		if !validRecordHostname(domain) {
			return fmt.Errorf("invalid domain %q", r.Domain)
		}
	}
	t := strings.ToUpper(strings.TrimSpace(r.Type))
	if t != "A" && t != "AAAA" && t != "CNAME" {
		return fmt.Errorf("invalid type %q (want A/AAAA/CNAME)", r.Type)
	}
	if len(r.Value) == 0 || len(strings.TrimSuffix(r.Value, ".")) > 253 {
		return fmt.Errorf("value too long or empty")
	}
	switch t {
	case "A":
		ip := net.ParseIP(strings.TrimSpace(r.Value))
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid A value %q (want IPv4)", r.Value)
		}
	case "AAAA":
		ip := net.ParseIP(strings.TrimSpace(r.Value))
		if ip == nil || ip.To16() == nil || ip.To4() != nil {
			return fmt.Errorf("invalid AAAA value %q (want IPv6, not IPv4)", r.Value)
		}
	case "CNAME":
		target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Value), "."))
		target = strings.TrimLeft(target, ".")
		if target == "" || strings.Contains(target, "*") || !validRecordHostname(target) {
			return fmt.Errorf("invalid CNAME target %q", r.Value)
		}
	}
	// Compare as int before any uint32 cast: a large int64 TTL truncated to
	// uint32 would otherwise wrap to a small value and dodge the cap.
	if r.TTL != 0 && (r.TTL < 1 || r.TTL > MaxRecordTTL) {
		return fmt.Errorf("invalid TTL %d (want 0 or 1..%d)", r.TTL, MaxRecordTTL)
	}
	return nil
}

func validRecordLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '-' {
			continue
		}
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	return true
}

func validRecordHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, l := range strings.Split(host, ".") {
		if !validRecordLabel(l) {
			return false
		}
	}
	return true
}

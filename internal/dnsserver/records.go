package dnsserver

import (
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/twobip/BlipDNS/internal/control"
)

// defaultRecordTTL is the TTL used when a record entry omits one (0) or sets
// an invalid negative one (which would otherwise wrap to ~136 years as uint32).
const defaultRecordTTL = 60

// maxRecordTTL caps how long a local record may live (one week, in seconds).
const maxRecordTTL = 7 * 24 * 3600

// RecordStore holds static DNS records (A, AAAA, CNAME) answered locally by
// blipd instead of being forwarded upstream. It implements control.RecordController.
//
// Records whose domain begins with "*." are treated as wildcards: e.g.
// "*.lan.twobip.com" answers any subdomain of lan.twobip.com (host.lan.twobip.com,
// deep.host.lan.twobip.com, …) but NOT lan.twobip.com itself. This mirrors the
// suffix/wildcard matching used by the filter policy store. An exact (non-wildcard)
// record always takes precedence over a wildcard.
type RecordStore struct {
	mu        sync.RWMutex
	records   map[string][]control.RecordEntry // exact: keyed by lowercased domain (no trailing .)
	wildcards map[string][]control.RecordEntry // wildcard: keyed by the parent suffix (e.g. "lan.twobip.com" for "*.lan.twobip.com")
}

func NewRecordStore() *RecordStore {
	return &RecordStore{
		records:   make(map[string][]control.RecordEntry),
		wildcards: make(map[string][]control.RecordEntry),
	}
}

// SetRecords replaces all local records atomically. Records whose Domain
// begins with "*." (e.g. "*.lan.twobip.com") are stored as wildcards and answered
// for any matching subdomain; the apex itself is not matched by a wildcard.
func (rs *RecordStore) SetRecords(records []control.RecordEntry) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.records = make(map[string][]control.RecordEntry, len(records))
	rs.wildcards = make(map[string][]control.RecordEntry, len(records))
	for _, r := range records {
		key := strings.ToLower(strings.TrimSuffix(r.Domain, "."))
		if key == "" {
			continue
		}
		if strings.HasPrefix(key, "*.") {
			parent := key[2:]
			if parent == "" {
				continue
			}
			rs.wildcards[parent] = append(rs.wildcards[parent], r)
			continue
		}
		rs.records[key] = append(rs.records[key], r)
	}
	return nil
}

// GetRecords returns all records as a flat slice (exact and wildcard).
func (rs *RecordStore) GetRecords() ([]control.RecordEntry, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]control.RecordEntry, 0, len(rs.records)+len(rs.wildcards))
	for _, recs := range rs.records {
		out = append(out, recs...)
	}
	for _, recs := range rs.wildcards {
		out = append(out, recs...)
	}
	return out, nil
}

// ClearRecords removes all local records.
func (rs *RecordStore) ClearRecords() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.records = make(map[string][]control.RecordEntry)
	rs.wildcards = make(map[string][]control.RecordEntry)
	return nil
}

// Lookup answers a query from the local record store. Returns the response
// message (with the question set) and true if a local record matched, or
// false otherwise. Only A, AAAA and CNAME queries are answered locally.
func (rs *RecordStore) Lookup(req *dns.Msg) (*dns.Msg, bool) {
	if len(req.Question) == 0 {
		return nil, false
	}
	q := req.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if domain == "" {
		return nil, false
	}

	// An exact record always wins; otherwise fall back to the most specific
	// (deepest) wildcard covering the queried subdomain. A wildcard "*.root"
	// matches host.root and deep.host.root but not "root" itself (no apex match),
	// matching the suffix/wildcard semantics used by the filter policy store.
	rs.mu.RLock()
	recs := rs.records[domain]
	if len(recs) == 0 {
		labels := strings.Split(domain, ".")
		for i := 1; i < len(labels); i++ {
			parent := strings.Join(labels[i:], ".")
			if w, ok := rs.wildcards[parent]; ok {
				recs = w
				break
			}
		}
	}
	rs.mu.RUnlock()
	if len(recs) == 0 {
		return nil, false
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	var matched bool
	for _, r := range recs {
		rrType, ok := dns.StringToType[strings.ToUpper(r.Type)]
		if !ok {
			continue
		}
		if rrType != dns.TypeA && rrType != dns.TypeAAAA && rrType != dns.TypeCNAME {
			continue
		}
		if rrType != q.Qtype {
			continue
		}
		ttl := uint32(r.TTL)
		if r.TTL <= 0 {
			ttl = defaultRecordTTL
		} else if ttl > maxRecordTTL {
			ttl = maxRecordTTL
		}
		switch rrType {
		case dns.TypeA:
			ip := net.ParseIP(r.Value)
			if ip == nil {
				continue
			}
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip.To4(),
			})
		case dns.TypeAAAA:
			ip := net.ParseIP(r.Value)
			if ip == nil {
				continue
			}
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip.To16(),
			})
		case dns.TypeCNAME:
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: dns.Fqdn(r.Value),
			})
		}
		matched = true
	}

	if matched {
		return resp, true
	}
	return nil, false
}

// Hash returns a stable checksum of the current records for reconciliation.
func (rs *RecordStore) Hash() uint64 {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	// Collect a flat snapshot so the hash is order-independent of the map
	// iteration, matching how the controller computes its expected hash.
	all := make([]control.RecordEntry, 0, len(rs.records)+len(rs.wildcards))
	for _, recs := range rs.records {
		all = append(all, recs...)
	}
	for _, recs := range rs.wildcards {
		all = append(all, recs...)
	}
	return control.RecordsHash(all)
}

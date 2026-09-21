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
// blipd instead of being forwarded upstream. PTR queries for an IP present in
// the records are synthesized locally from the matching A/AAAA entry, so LAN
// reverse lookups never need to leave the box. It implements control.RecordController.
//
// Records whose domain begins with "*." are treated as wildcards: e.g.
// "*.lan.twobip.com" answers any subdomain of lan.twobip.com (host.lan.twobip.com,
// deep.host.lan.twobip.com, …) but NOT lan.twobip.com itself. This mirrors the
// suffix/wildcard matching used by the filter policy store. An exact (non-wildcard)
// record always takes precedence over a wildcard.
type RecordStore struct {
	mu        sync.RWMutex
	records   map[string][]compiledRecord // exact: keyed by lowercased domain (no trailing .)
	wildcards map[string][]compiledRecord // wildcard: keyed by the parent suffix (e.g. "lan.twobip.com" for "*.lan.twobip.com")
	// raw preserves the original entries for GetRecords/Hash round-trips.
	raw []control.RecordEntry
	// ptrIndex maps string(ip) -> indexes into raw for O(1) PTR synthesis.
	ptrIndex map[string][]int
}

// compiledRecord is a RecordEntry with its hot-path parsing done once at
// SetRecords: resolved RR type, pre-parsed IP and pre-computed TTL/target.
type compiledRecord struct {
	entry  control.RecordEntry
	rrType uint16
	ip     net.IP
	target string // FQDN for CNAME / PTR owner
	ttl    uint32
}

func compileRecord(r control.RecordEntry) (compiledRecord, bool) {
	rrType, ok := dns.StringToType[strings.ToUpper(r.Type)]
	if !ok {
		return compiledRecord{}, false
	}
	if rrType != dns.TypeA && rrType != dns.TypeAAAA && rrType != dns.TypeCNAME {
		return compiledRecord{}, false
	}
	ttl := uint32(r.TTL)
	if r.TTL <= 0 {
		ttl = defaultRecordTTL
	} else if ttl > maxRecordTTL {
		ttl = maxRecordTTL
	}
	cr := compiledRecord{entry: r, rrType: rrType, ttl: ttl}
	switch rrType {
	case dns.TypeA, dns.TypeAAAA:
		ip := net.ParseIP(r.Value)
		if ip == nil {
			return compiledRecord{}, false
		}
		cr.ip = ip
	case dns.TypeCNAME:
		cr.target = dns.Fqdn(r.Value)
	}
	return cr, true
}

func NewRecordStore() *RecordStore {
	return &RecordStore{
		records:   make(map[string][]compiledRecord),
		wildcards: make(map[string][]compiledRecord),
		ptrIndex:  make(map[string][]int),
	}
}

// SetRecords replaces all local records atomically. Records whose Domain
// begins with "*." (e.g. "*.lan.twobip.com") are stored as wildcards and answered
// for any matching subdomain; the apex itself is not matched by a wildcard.
func (rs *RecordStore) SetRecords(records []control.RecordEntry) error {
	recs := make(map[string][]compiledRecord, len(records))
	wilds := make(map[string][]compiledRecord, len(records))
	raw := make([]control.RecordEntry, 0, len(records))
	ptrIndex := make(map[string][]int)
	for _, r := range records {
		key := strings.ToLower(strings.TrimSuffix(r.Domain, "."))
		if key == "" {
			continue
		}
		cr, ok := compileRecord(r)
		if !ok {
			// Keep unparsable entries for GetRecords round-trip fidelity but
			// skip them on the lookup path (Lookup re-validates anyway).
			raw = append(raw, r)
			continue
		}
		// Precompute PTR owner target once.
		cr.target = dns.Fqdn(strings.ToLower(strings.TrimSuffix(r.Domain, ".")))
		// CNAME target is the rdata, not the owner.
		if cr.rrType == dns.TypeCNAME {
			cr.target = dns.Fqdn(r.Value)
		}
		raw = append(raw, r)
		idx := len(raw) - 1
		if strings.HasPrefix(key, "*.") {
			parent := key[2:]
			if parent == "" {
				continue
			}
			wilds[parent] = append(wilds[parent], cr)
			continue
		}
		recs[key] = append(recs[key], cr)
		if cr.rrType == dns.TypeA || cr.rrType == dns.TypeAAAA {
			ptrIndex[string(cr.ip.To16())] = append(ptrIndex[string(cr.ip.To16())], idx)
		}
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.records = recs
	rs.wildcards = wilds
	rs.raw = raw
	rs.ptrIndex = ptrIndex
	return nil
}

// GetRecords returns all records as a flat slice (exact and wildcard).
func (rs *RecordStore) GetRecords() ([]control.RecordEntry, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]control.RecordEntry, len(rs.raw))
	copy(out, rs.raw)
	return out, nil
}

// Lookup answers a query from the local record store. Returns the response
// message (with the question set) and true if a local record matched, or
// false otherwise. A, AAAA and CNAME queries are answered locally; PTR
// queries are synthesized from the A/AAAA entries (see lookupPTR).
func (rs *RecordStore) Lookup(req *dns.Msg) (*dns.Msg, bool) {
	if len(req.Question) == 0 {
		return nil, false
	}
	q := req.Question[0]
	// ASCII fast-path normalize (DNS is ASCII): avoid ToLower alloc when
	// already lowercase.
	domain := strings.TrimSuffix(q.Name, ".")
	needLower := false
	for i := 0; i < len(domain); i++ {
		if c := domain[i]; c >= 'A' && c <= 'Z' {
			needLower = true
			break
		}
	}
	if needLower {
		domain = strings.ToLower(domain)
	}
	if domain == "" {
		return nil, false
	}
	if q.Qtype == dns.TypePTR {
		return rs.lookupPTR(req, q.Name)
	}

	// An exact record always wins; otherwise fall back to the most specific
	// (deepest) wildcard covering the queried subdomain. A wildcard "*.root"
	// matches host.root and deep.host.root but not "root" itself (no apex match),
	// matching the suffix/wildcard semantics used by the filter policy store.
	// Dot-walk without Split/Join allocations.
	rs.mu.RLock()
	recs := rs.records[domain]
	if len(recs) == 0 {
		for i := 0; i < len(domain); i++ {
			if domain[i] != '.' {
				continue
			}
			if w, ok := rs.wildcards[domain[i+1:]]; ok {
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
	resp.RecursionAvailable = true // blipd recurses via upstream; nslookup warns without this

	var matched, nameKnown bool
	for _, r := range recs {
		rrType := r.rrType
		nameKnown = true
		if rrType != q.Qtype {
			continue
		}
		switch rrType {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: r.ttl},
				A:   r.ip.To4(),
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: r.ttl},
				AAAA: r.ip.To16(),
			})
		case dns.TypeCNAME:
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: r.ttl},
				Target: dns.Fqdn(r.entry.Value),
			})
		default:
			continue
		}
		matched = true
	}

	if matched {
		return resp, true
	}
	if nameKnown {
		// The name exists locally but has no record of the queried type:
		// NODATA (NOERROR, no answers), not a fallthrough to upstream
		// NXDOMAIN. resp is already an authoritative empty reply.
		return resp, true
	}
	return nil, false
}

// lookupPTR synthesizes a PTR answer from the A/AAAA records already held: a
// reverse query for an IP present in the local records returns the record
// name(s). Unknown IPs and non-arpa names fall through (nil, false) so the
// caller decides — serve() NXDOMAINs non-public reverse locally and forwards
// the rest. Only exact records participate; a wildcard (*.lan) has no single
// name to return, so it is skipped.
func (rs *RecordStore) lookupPTR(req *dns.Msg, qname string) (*dns.Msg, bool) {
	ip, ok := ptrIPFromArpa(qname)
	if !ok {
		return nil, false
	}
	// Snapshot index + raw under a short RLock, then build outside the lock so
	// a large record set doesn't stall SetRecords.
	rs.mu.RLock()
	indexes := rs.ptrIndex[string(ip.To16())]
	raw := rs.raw
	rs.mu.RUnlock()
	if len(indexes) == 0 {
		return nil, false
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	for _, idx := range indexes {
		if idx < 0 || idx >= len(raw) {
			continue
		}
		r := raw[idx]
		ttl := uint32(defaultRecordTTL)
		if r.TTL > 0 {
			ttl = uint32(r.TTL)
			if ttl > maxRecordTTL {
				ttl = maxRecordTTL
			}
		}
		resp.Answer = append(resp.Answer, &dns.PTR{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl},
			Ptr: dns.Fqdn(strings.ToLower(strings.TrimSuffix(r.Domain, "."))),
		})
	}
	if len(resp.Answer) == 0 {
		return nil, false
	}
	return resp, true
}

// ptrIPFromArpa parses a reverse-DNS name ("4.30.168.192.in-addr.arpa.") into
// the IP it denotes. Both v4 (in-addr.arpa) and v6 (ip6.arpa, 32 nibbles) are
// handled; anything else returns false.
func ptrIPFromArpa(name string) (net.IP, bool) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if rest, ok := strings.CutSuffix(n, ".in-addr.arpa"); ok {
		parts := strings.Split(rest, ".")
		if len(parts) != 4 {
			return nil, false
		}
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		if ip := net.ParseIP(strings.Join(parts, ".")); ip != nil && ip.To4() != nil {
			return ip, true
		}
		return nil, false
	}
	if rest, ok := strings.CutSuffix(n, ".ip6.arpa"); ok {
		nibbles := strings.Split(rest, ".")
		if len(nibbles) != 32 {
			return nil, false
		}
		for i, j := 0, len(nibbles)-1; i < j; i, j = i+1, j-1 {
			nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
		}
		var groups [8]string
		for i := range groups {
			groups[i] = strings.Join(nibbles[i*4:(i+1)*4], "")
		}
		if ip := net.ParseIP(strings.Join(groups[:], ":")); ip != nil {
			return ip, true
		}
	}
	return nil, false
}

// Hash returns a stable checksum of the current records for reconciliation.
func (rs *RecordStore) Hash() uint64 {
	rs.mu.RLock()
	raw := rs.raw
	rs.mu.RUnlock()
	return control.RecordsHash(raw)
}

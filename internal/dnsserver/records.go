package dnsserver

import (
	"net"
	"strings"
	"sync"

	"github.com/twobip/BlipDNS/internal/control"
	"github.com/miekg/dns"
)

// defaultRecordTTL is the TTL used when a record entry omits one (0).
const defaultRecordTTL = 60

// RecordStore holds static DNS records (A, AAAA, CNAME) answered locally by
// blipd instead of being forwarded upstream. It implements control.RecordController.
type RecordStore struct {
	mu      sync.RWMutex
	records map[string][]control.RecordEntry // keyed by lowercased domain
}

func NewRecordStore() *RecordStore {
	return &RecordStore{records: make(map[string][]control.RecordEntry)}
}

// SetRecords replaces all local records atomically.
func (rs *RecordStore) SetRecords(records []control.RecordEntry) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.records = make(map[string][]control.RecordEntry, len(records))
	for _, r := range records {
		key := strings.ToLower(strings.TrimSuffix(r.Domain, "."))
		if key == "" {
			continue
		}
		rs.records[key] = append(rs.records[key], r)
	}
	return nil
}

// GetRecords returns all records as a flat slice.
func (rs *RecordStore) GetRecords() ([]control.RecordEntry, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]control.RecordEntry, 0, len(rs.records))
	for _, recs := range rs.records {
		out = append(out, recs...)
	}
	return out, nil
}

// ClearRecords removes all local records.
func (rs *RecordStore) ClearRecords() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.records = make(map[string][]control.RecordEntry)
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

	rs.mu.RLock()
	recs := rs.records[domain]
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
		if ttl == 0 {
			ttl = defaultRecordTTL
		}
		switch rrType {
		case dns.TypeA:
			ip := net.ParseIP(r.Value)
			if ip == nil {
				continue
			}
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A: ip.To4(),
			})
		case dns.TypeAAAA:
			ip := net.ParseIP(r.Value)
			if ip == nil {
				continue
			}
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip.To16(),
			})
		case dns.TypeCNAME:
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
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
	all := make([]control.RecordEntry, 0, len(rs.records))
	for _, recs := range rs.records {
		all = append(all, recs...)
	}
	return control.RecordsHash(all)
}

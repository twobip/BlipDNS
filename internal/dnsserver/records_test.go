package dnsserver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/twobip/BlipDNS/internal/control"
)

func q(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	return m
}

func aIP(t *testing.T, resp *dns.Msg) string {
	t.Helper()
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", resp.Answer[0])
	}
	return a.A.String()
}

func TestRecordStoreExactMatch(t *testing.T) {
	rs := NewRecordStore()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "recorded.test.", Type: "A", Value: "10.10.10.10", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	resp, ok := rs.Lookup(q(t, "recorded.test.", dns.TypeA))
	if !ok {
		t.Fatal("expected match, got none")
	}
	if got := aIP(t, resp); got != "10.10.10.10" {
		t.Errorf("ip = %v, want 10.10.10.10", got)
	}
}

func TestRecordStoreWildcardMatchSubdomain(t *testing.T) {
	rs := NewRecordStore()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.5", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	resp, ok := rs.Lookup(q(t, "host.lan.twobip.com.", dns.TypeA))
	if !ok {
		t.Fatal("expected wildcard match for subdomain, got none")
	}
	if got := aIP(t, resp); got != "10.0.0.5" {
		t.Errorf("ip = %v, want 10.0.0.5", got)
	}
}

func TestRecordStoreWildcardMatchesDeepSubdomain(t *testing.T) {
	rs := NewRecordStore()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.5", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	resp, ok := rs.Lookup(q(t, "deep.host.lan.twobip.com.", dns.TypeA))
	if !ok {
		t.Fatal("expected wildcard match for deep subdomain, got none")
	}
	if got := aIP(t, resp); got != "10.0.0.5" {
		t.Errorf("ip = %v, want 10.0.0.5", got)
	}
}

func TestRecordStoreWildcardDoesNotMatchApex(t *testing.T) {
	rs := NewRecordStore()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.5", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := rs.Lookup(q(t, "lan.twobip.com.", dns.TypeA)); ok {
		t.Fatal("wildcard must not match the apex domain itself")
	}
}

func TestRecordStoreExactBeatsWildcard(t *testing.T) {
	rs := NewRecordStore()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.5", TTL: 60},
		{Domain: "host.lan.twobip.com.", Type: "A", Value: "10.0.0.9", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	resp, ok := rs.Lookup(q(t, "host.lan.twobip.com.", dns.TypeA))
	if !ok {
		t.Fatal("expected exact match, got none")
	}
	if got := aIP(t, resp); got != "10.0.0.9" {
		t.Errorf("ip = %v, want exact 10.0.0.9 (not wildcard 10.0.0.5)", got)
	}
}

func TestRecordStoreMostSpecificWildcardWins(t *testing.T) {
	rs := NewRecordStore()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.5", TTL: 60},
		{Domain: "*.twobip.com.", Type: "A", Value: "10.0.0.7", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	resp, ok := rs.Lookup(q(t, "host.lan.twobip.com.", dns.TypeA))
	if !ok {
		t.Fatal("expected wildcard match, got none")
	}
	if got := aIP(t, resp); got != "10.0.0.5" {
		t.Errorf("ip = %v, want most-specific wildcard 10.0.0.5", got)
	}
}

func TestRecordStoreWildcardNoMatchFallsThrough(t *testing.T) {
	rs := NewRecordStore()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.5", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := rs.Lookup(q(t, "host.other.com.", dns.TypeA)); ok {
		t.Fatal("expected no match for unrelated domain")
	}
}

func TestRecordStoreGetRecordsRoundTrip(t *testing.T) {
	rs := NewRecordStore()
	want := []control.RecordEntry{
		{Domain: "exact.test.", Type: "A", Value: "10.0.0.1", TTL: 60},
		{Domain: "*.wild.test.", Type: "A", Value: "10.0.0.2", TTL: 60},
		{Domain: "v6.test.", Type: "AAAA", Value: "2001:db8::1", TTL: 0},
	}
	if err := rs.SetRecords(want); err != nil {
		t.Fatal(err)
	}
	got, err := rs.GetRecords()
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]control.RecordEntry{}
	for _, r := range got {
		byKey[r.Domain] = r
	}
	for _, w := range want {
		g, ok := byKey[w.Domain]
		if !ok {
			t.Errorf("missing record domain %q in GetRecords()", w.Domain)
			continue
		}
		if g.Type != w.Type || g.Value != w.Value || g.TTL != w.TTL {
			t.Errorf("record %q = %+v, want %+v", w.Domain, g, w)
		}
	}
}

func TestRecordStoreWildcardHashStable(t *testing.T) {
	rs := NewRecordStore()
	empty := NewRecordStore()

	// Two empty stores hash identically (FNV-1a of no input == offset basis,
	// not zero — both blipd and blipc compute the same thing via RecordsHash).
	if rs.Hash() != empty.Hash() {
		t.Errorf("empty store hashes differ: %d vs %d", rs.Hash(), empty.Hash())
	}

	// Adding a wildcard record must move the hash once the empty baseline.
	before := empty.Hash()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.5", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	if rs.Hash() == before {
		t.Error("hash should change once a wildcard record is present")
	}

	// Re-applying the records read back via GetRecords must reproduce the hash.
	got, err := rs.GetRecords()
	if err != nil {
		t.Fatal(err)
	}
	rs2 := NewRecordStore()
	if err := rs2.SetRecords(got); err != nil {
		t.Fatal(err)
	}
	if rs.Hash() != rs2.Hash() {
		t.Errorf("hash not stable across GetRecords->SetRecords: %d vs %d", rs.Hash(), rs2.Hash())
	}

	// A different value must move the hash.
	rs3 := NewRecordStore()
	if err := rs3.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.6", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	if rs.Hash() == rs3.Hash() {
		t.Error("different record value should produce a different hash")
	}
}

// Lookup is case-insensitive on the name even when the stored domain's casing
// differs: SetRecords lowercases the lookup key, so a query matches regardless.
func TestRecordStoreWildcardCaseInsensitive(t *testing.T) {
	rs := NewRecordStore()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "*.LAN.TWOBIP.COM.", Type: "A", Value: "10.0.0.5", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	resp, ok := rs.Lookup(q(t, "host.lan.twobip.com.", dns.TypeA))
	if !ok {
		t.Fatal("expected case-insensitive wildcard match")
	}
	if got := aIP(t, resp); got != "10.0.0.5" {
		t.Errorf("ip = %v, want 10.0.0.5", got)
	}
}

func TestRecordStoreClearRemovesWildcards(t *testing.T) {
	rs := NewRecordStore()
	_ = rs.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.5", TTL: 60},
	})
	if _, ok := rs.Lookup(q(t, "host.lan.twobip.com.", dns.TypeA)); !ok {
		t.Fatal("expected match before clear")
	}
	if err := rs.ClearRecords(); err != nil {
		t.Fatal(err)
	}
	if _, ok := rs.Lookup(q(t, "host.lan.twobip.com.", dns.TypeA)); ok {
		t.Fatal("expected no match after clear")
	}
}

// sanity: the wildcard owner name is NOT echoed in the answer — the answer is
// for the queried name (correct wildcard expansion), not the literal "*.domain".
func TestRecordStoreWildcardAnswerOwnerIsQueriedName(t *testing.T) {
	rs := NewRecordStore()
	if err := rs.SetRecords([]control.RecordEntry{
		{Domain: "*.lan.twobip.com.", Type: "A", Value: "10.0.0.5", TTL: 60},
	}); err != nil {
		t.Fatal(err)
	}
	resp, ok := rs.Lookup(q(t, "host.lan.twobip.com.", dns.TypeA))
	if !ok {
		t.Fatal("expected match")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", resp.Answer[0])
	}
	if a.Hdr.Name != "host.lan.twobip.com." {
		t.Errorf("answer owner = %q, want queried name host.lan.twobip.com.", a.Hdr.Name)
	}
	if !a.A.Equal(net.ParseIP("10.0.0.5")) {
		t.Errorf("A = %v, want 10.0.0.5", a.A)
	}
}

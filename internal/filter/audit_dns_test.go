package filter

import (
	"net"
	"testing"
)

// Client IDs match case-insensitively: "Phone" in config must select the
// policy for a device asserting "phone" (or vice versa), instead of dropping
// it into the default, more permissive policy (audit #36).
func TestClientIDCaseFold(t *testing.T) {
	s := NewStore(nil)
	if err := s.SetPolicy(&Policy{
		ID: "kids", Networks: []string{"10.0.0.0/8"}, Clients: []string{"Phone"},
	}); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("10.0.0.5")
	for _, id := range []string{"Phone", "phone", "PHONE", "pHoNe"} {
		if got := s.lookup(ip, id); got == nil || got.ID != "kids" {
			gotID := "<nil>"
			if got != nil {
				gotID = got.ID
			}
			t.Errorf("lookup(%q) = %q, want policy %q", id, gotID, "kids")
		}
		if !s.KnowsClientID(id) {
			t.Errorf("KnowsClientID(%q) = false, want true", id)
		}
		if !s.ClientIDSelected(ip, id) {
			t.Errorf("ClientIDSelected(%q) = false, want true", id)
		}
	}
	// Unknown IDs still miss the ID path (an in-network IP matches by network,
	// which is correct), and the scoping rule (ID + in-network IP) is
	// unchanged: out-of-network IPs never match by ID alone.
	if s.KnowsClientID("tablet") {
		t.Errorf("KnowsClientID(tablet) = true, want false")
	}
	if s.ClientIDSelected(ip, "tablet") {
		t.Errorf("ClientIDSelected(tablet) = true, want false")
	}
	if got := s.lookup(net.ParseIP("192.168.1.5"), "phone"); got != nil && got.ID == "kids" {
		t.Errorf("out-of-network ID selected the policy")
	}
}

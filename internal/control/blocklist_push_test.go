package control

import (
	"encoding/json"
	"strings"
	"testing"
)

// decodeBlocklistPush must accept exactly what Client.SetBlocklist sends
// (including null for nil slices) and abort oversized pushes mid-stream.
func TestDecodeBlocklistPush(t *testing.T) {
	// Wire shape, as marshalled by Client.SetBlocklist.
	body, _ := json.Marshal(SetBlocklistRequest{Domains: []string{"a.test", "b.test"}})
	req, err := decodeBlocklistPush(strings.NewReader(string(body)))
	if err != nil || len(req.Domains) != 2 || req.Domains[0] != "a.test" {
		t.Fatalf("wire body -> %+v, err=%v", req, err)
	}
	// Nil slices marshal as null: clearing a list must still decode.
	body, _ = json.Marshal(SetBlocklistRequest{})
	if req, err = decodeBlocklistPush(strings.NewReader(string(body))); err != nil || len(req.Domains) != 0 {
		t.Fatalf("null lists -> %+v, err=%v", req, err)
	}
	// Over-cap aborts with the sentinel, not a generic error.
	big := `{"domains":[` + strings.Repeat(`"a.test",`, maxPushDomains+1) + `"z.test"]}`
	if _, err = decodeBlocklistPush(strings.NewReader(big)); err != errBlocklistTooLarge {
		t.Fatalf("over-cap err = %v, want sentinel", err)
	}
	// Oversize element and non-object are plain bad requests.
	if _, err = decodeBlocklistPush(strings.NewReader(`{"domains":["` + strings.Repeat("x", maxPushEntryLen+1) + `"]}`)); err == nil || err == errBlocklistTooLarge {
		t.Fatalf("oversize element err = %v", err)
	}
	if _, err = decodeBlocklistPush(strings.NewReader(`[1,2]`)); err == nil {
		t.Fatal("non-object accepted")
	}
	// Unknown fields are ignored, matching encoding/json into the struct.
	if req, err = decodeBlocklistPush(strings.NewReader(`{"domains":[],"zzz":123}`)); err != nil {
		t.Fatalf("unknown field err = %v", err)
	}
}

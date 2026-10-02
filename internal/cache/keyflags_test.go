package cache

import (
	"fmt"
	"strings"
	"testing"
)

// TestKeySeparatesCDAD proves CD and AD participate in the cache key: a
// response fetched with checking disabled (or requested as authenticated
// data) must never be served to a client that asked for different validation
// semantics.
func TestKeySeparatesCDAD(t *testing.T) {
	base := mkMsg("a.test", 60)
	cd := mkMsg("a.test", 60)
	cd.CheckingDisabled = true
	ad := mkMsg("a.test", 60)
	ad.AuthenticatedData = true

	kBase, kCD, kAD := KeyOf(base), KeyOf(cd), KeyOf(ad)
	if kBase == kCD {
		t.Error("CD=0 and CD=1 produce the same cache key")
	}
	if kBase == kAD {
		t.Error("AD=0 and AD=1 produce the same cache key")
	}
	if kCD == kAD {
		t.Error("CD=1 and AD=1 produce the same cache key")
	}
	// DO still partitions as before.
	do := mkMsg("a.test", 60)
	do.SetEdns0(4096, true)
	if KeyOf(base) == KeyOf(do) {
		t.Error("DO=0 and DO=1 produce the same cache key")
	}
}

func TestKeyStringCompact(t *testing.T) {
	k := Key{Name: "sub.ads.example.com.", QType: 1, QClass: 1, Label: "auto", DO: true}
	if got, want := k.String(), "sub.ads.example.com.|1|1|auto|100"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if n := testing.AllocsPerRun(100, func() { _ = k.String() }); n != 1 {
		t.Fatalf("String() allocs = %v, want 1", n)
	}
	for _, tc := range []struct {
		key  Key
		want string
	}{
		{Key{Name: "a.test.", QType: 1, QClass: 1, CD: true}, "a.test.|1|1||010"},
		{Key{Name: "a.test.", QType: 1, QClass: 1, AD: true}, "a.test.|1|1||001"},
	} {
		if got := tc.key.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
	// Oversized keys stay correct on the heap path.
	long := strings.Repeat("a", 300) + ".test."
	kl := Key{Name: long, QType: 28, QClass: 1, Label: "x", CD: true, AD: true}
	if got, want := kl.String(), fmt.Sprintf("%s|%d|%d|%s|011", long, 28, 1, "x"); got != want {
		t.Errorf("oversized String() = %q, want %q", got, want)
	}
}

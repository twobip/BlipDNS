package cache

import (
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

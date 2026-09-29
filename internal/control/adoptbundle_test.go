package control

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAdoptBundleRoundTrip(t *testing.T) {
	s, err := MakeAdoptBundle("office-dns", "http://10.0.0.5:8444", "ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(s, "{") || strings.Contains(s, "ABCD") {
		t.Fatalf("bundle is not opaque: %s", s)
	}
	b, ok := ParseAdoptBundle(s)
	if !ok {
		t.Fatalf("bundle did not parse: %s", s)
	}
	if b.ID != "office-dns" || b.URL != "http://10.0.0.5:8444" || b.Code != "ABCD-1234" {
		t.Fatalf("bad decode: %+v", b)
	}
	// Whitespace tolerance: pasted with a trailing newline from `cat`.
	if _, ok := ParseAdoptBundle("  " + s + "\n"); !ok {
		t.Fatal("padded bundle did not parse")
	}
}

func TestAdoptBundleLegacyAndGarbage(t *testing.T) {
	if _, ok := ParseAdoptBundle("ABCD-1234"); ok {
		t.Fatal("bare code parsed as bundle")
	}
	if _, ok := ParseAdoptBundle(""); ok {
		t.Fatal("empty parsed as bundle")
	}
	for _, bad := range []string{
		"blip1_",
		"blip1_!!!not-base64!!!",
		"blip1_aGVsbG8", // valid base64, not a bundle envelope
	} {
		if _, ok := ParseAdoptBundle(bad); ok {
			t.Fatalf("garbage parsed as bundle: %q", bad)
		}
	}
	if _, err := MakeAdoptBundle("x", "http://h:1", ""); err == nil {
		t.Fatal("empty code accepted")
	}
	if _, err := MakeAdoptBundle("x", "gopher://h:1", "C"); err == nil {
		t.Fatal("bad scheme accepted")
	}
	if _, err := MakeAdoptBundle("x", "http://", "C"); err == nil {
		t.Fatal("hostless url accepted")
	}
}

func TestAdoptCodePathFollowsStateDir(t *testing.T) {
	dir := t.TempDir()
	s := &Server{}
	s.ConfigureAdoption(filepath.Join(dir, "adopted.json"), "n1")
	if got := s.AdoptCodePath(); got != filepath.Join(dir, "adopt-code") {
		t.Fatalf("state-dir path = %q", got)
	}
	plain := &Server{}
	if got := plain.AdoptCodePath(); got != DefaultAdoptCodeFile {
		t.Fatalf("default path = %q", got)
	}
}

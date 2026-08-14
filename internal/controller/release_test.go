package controller

import "testing"

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"blipd/0.2.0", "0.2.0"},
		{"blipc/0.2.0", "0.2.0"},
		{"0.2.0", "0.2.0"},
		{"blipd/0.2.0-rc1", ""},
		{"", ""},
		{"not-a-version", ""},
		{"1.2", ""},
		{"1.2.3.4", ""},
	}
	for _, c := range cases {
		if got := extractVersion(c.in); got != c.want {
			t.Errorf("extractVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSemverLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.1.0", "0.2.0", true},
		{"0.2.0", "0.1.0", false},
		{"0.2.0", "0.2.0", false},
		{"0.1.9", "0.1.10", true},
		{"0.10.0", "0.9.0", false},
		{"1.0.0", "0.9.9", false},
	}
	for _, c := range cases {
		if got := semverLess(c.a, c.b); got != c.want {
			t.Errorf("semverLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestReleaseCheckAvailable(t *testing.T) {
	rc := newReleaseCheck()
	rc.mu.Lock()
	rc.versions["stable"] = "0.2.0"
	rc.versions["dev"] = "0.3.0"
	rc.mu.Unlock()

	if rc.available("stable", "blipd/0.2.0") {
		t.Error("same version reported as update available")
	}
	if !rc.available("stable", "blipd/0.1.0") {
		t.Error("older version not reported as update available")
	}
	if rc.available("stable", "blipd/0.3.0") {
		t.Error("newer version reported as update available")
	}
	if !rc.available("dev", "blipd/0.2.0") {
		t.Error("dev latest is 0.3.0; 0.2.0 should be behind")
	}
	if !rc.available("stable", "blipd/0.0.0") {
		t.Error("unstamped dev build (0.0.0) should be behind the latest release")
	}
	if rc.available("stable", "blipd/not-a-version") {
		t.Error("unparseable version reported as update available")
	}
}

func TestBranchForChannel(t *testing.T) {
	if got := branchForChannel("stable"); got != "master" {
		t.Errorf("stable -> %q, want master", got)
	}
	if got := branchForChannel("dev"); got != "dev" {
		t.Errorf("dev -> %q, want dev", got)
	}
}

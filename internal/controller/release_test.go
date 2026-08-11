package controller

import "testing"

func TestExtractSHA(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"blipd/0.1.0+abcdef1234567890", "abcdef123456"},
		{"blipd/0.1.0", ""},
		{"", ""},
		{"not-a-sha", ""},
		{"ABCDEF1234567890ABCDEF1234567890ABCDEF12", "abcdef123456"},
	}
	for _, c := range cases {
		if got := extractSHA(c.in); got != c.want {
			t.Errorf("extractSHA(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReleaseCheckAvailable(t *testing.T) {
	rc := newReleaseCheck()
	rc.mu.Lock()
	rc.heads["stable"] = "aaaa111111"
	rc.heads["dev"] = "bbbb222222"
	rc.mu.Unlock()

	if rc.available("stable", "blipd/0.1.0+aaaa111111") {
		t.Error("same head reported as update available")
	}
	if !rc.available("stable", "blipd/0.1.0+cccc333333") {
		t.Error("different head not reported as update available")
	}
	if rc.available("stable", "blipd/0.1.0") {
		t.Error("unknown build version reported as update available")
	}
	if !rc.available("dev", "blipd/0.1.0+aaaa111111") {
		t.Error("dev head bbbb222222 differs from running aaaa111111; update should be available")
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

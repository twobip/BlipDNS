package control

import "testing"

func TestAddCommit(t *testing.T) {
	rev := "47cf192abc1234567890abcdef1234567890abcd"
	for _, tc := range []struct{ v, rev, want string }{
		{"0.7.0", rev, "0.7.0+47cf192"},
		{"0.7.0", "", "0.7.0"},
		{"0.7.0", "abc", "0.7.0"},
		{"0.7.0+a29f043", rev, "0.7.0+a29f043"},
		{"blipd/0.7.0", rev, "blipd/0.7.0+47cf192"},
	} {
		if got := addCommit(tc.v, tc.rev); got != tc.want {
			t.Errorf("addCommit(%q) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

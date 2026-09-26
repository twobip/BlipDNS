package control

import (
	"runtime/debug"
	"strings"
)

// commitLen is the short-hash length appended as +hex build metadata,
// matching git's default --short and the form extractVersion/commitOf
// recognise (e.g. "blipd/0.7.0+47cf192").
const commitLen = 7

// WithCommit appends the binary's own git commit as +hex build metadata
// ("0.7.0" -> "0.7.0+47cf192"). The commit comes from the VCS stamp Go
// embeds when building from a git checkout, so every build path (local go
// build, blip-restart, install scripts) reports it with no flag changes. A
// version that already carries metadata, or a binary without a VCS stamp
// (tarball, -buildvcs=false), is returned unchanged.
func WithCommit(v string) string {
	return addCommit(v, buildCommit())
}

func addCommit(v, rev string) string {
	if i := strings.IndexByte(v, '+'); i >= 0 || len(rev) < commitLen {
		return v
	}
	return v + "+" + rev[:commitLen]
}

// buildCommit returns the full commit hash of the running binary ("" when
// the build carries no VCS stamp).
func buildCommit() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}

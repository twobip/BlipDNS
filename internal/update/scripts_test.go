package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRootHelpersPinPath guards the sudo privilege boundary. The helpers run
// as root via sudo, and sudo only resets PATH to a safe value when the host
// configures secure_path. Without the pin a compromised service account could
// shadow ssh-keygen/sha256sum/systemctl/keepalived with attacker binaries and
// turn the signature gate into arbitrary root execution.
//
// The shebang must also be absolute: /usr/bin/env bash resolves bash through
// the caller's PATH before the script body can pin anything.
func TestRootHelpersPinPath(t *testing.T) {
	const wantPath = `export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`
	for _, name := range []string{"blipd-install.sh", "blipd-keepalived.sh", "blipc-install.sh"} {
		path := filepath.Join("..", "..", "scripts", name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		s := string(b)
		if !strings.HasPrefix(s, "#!/bin/bash\n") {
			t.Errorf("%s: shebang must be #!/bin/bash, got %q", name, firstLine(s))
		}
		if !strings.Contains(s, wantPath) {
			t.Errorf("%s: missing pinned PATH %q", name, wantPath)
		}
	}
}

// TestInstallersSetSecurePath checks the other half of the fix for fresh
// installs: even commands added to the helpers later inherit a root-owned
// search path from sudoers.
func TestInstallersSetSecurePath(t *testing.T) {
	for name, want := range map[string]string{
		"install-blipd.sh": `Defaults:blip secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
		"install-blipc.sh": `Defaults:blipc secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
	} {
		path := filepath.Join("..", "..", "scripts", name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s: missing %q", name, want)
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// listenUnix binds a throwaway Unix listener so socketAlive finds it live.
func listenUnix(t *testing.T, sock string) (net.Listener, error) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

func writeControllerConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "blipc.yaml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

const testControllerYAML = `listen: "127.0.0.1:8500"
instances:
  - id: office-dns
    label: Office
    url: "http://10.0.0.5:8444"
    token: "secret-office"
  - id: home-dns
    url: "http://10.0.0.6:8444/"
    token: "secret-home"
`

func TestResolveTargetByID(t *testing.T) {
	cfg := writeControllerConfig(t, testControllerYAML)
	base, tok, err := resolveTarget("office-dns", "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if base != "http://10.0.0.5:8444" || tok != "secret-office" {
		t.Errorf("got %q %q, want url+secret-office", base, tok)
	}
}

func TestResolveTargetExplicitTokenWins(t *testing.T) {
	cfg := writeControllerConfig(t, testControllerYAML)
	base, tok, err := resolveTarget("office-dns", "explicit", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if base != "http://10.0.0.5:8444" || tok != "explicit" {
		t.Errorf("got %q %q, want url+explicit", base, tok)
	}
	// Direct URLs also prefer the explicit token.
	base, tok, err = resolveTarget("http://10.0.0.5:8444", "explicit", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if base != "http://10.0.0.5:8444" || tok != "explicit" {
		t.Errorf("got %q %q, want url+explicit", base, tok)
	}
}

func TestResolveTargetURLFallsBackToController(t *testing.T) {
	cfg := writeControllerConfig(t, testControllerYAML)
	// Trailing-slash form still matches the stored URL.
	base, tok, err := resolveTarget("http://10.0.0.6:8444", "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if base != "http://10.0.0.6:8444/" || tok != "secret-home" {
		t.Errorf("got %q %q, want stored url+secret-home", base, tok)
	}
}

func TestResolveTargetURLWithoutController(t *testing.T) {
	base, tok, err := resolveTarget("http://10.0.0.9:8444", "", filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if base != "http://10.0.0.9:8444" || tok != "" {
		t.Errorf("got %q %q, want passthrough with empty token", base, tok)
	}
}

func TestResolveTargetUnknownID(t *testing.T) {
	cfg := writeControllerConfig(t, testControllerYAML)
	if _, _, err := resolveTarget("nope", "", cfg); err == nil {
		t.Error("unknown id should error")
	}
}

func TestResolveTargetMissingConfigForID(t *testing.T) {
	_, _, err := resolveTarget("office-dns", "", filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil || !strings.Contains(err.Error(), "--token") {
		t.Errorf("missing config should hint at --token, got %v", err)
	}
}

func TestResolveTargetTokenFileExpansion(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "token")
	if err := os.WriteFile(secret, []byte("file-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := writeControllerConfig(t, "instances:\n  - id: f\n    url: \"http://10.0.0.7:8444\"\n    token: \"@"+secret+"\"\n")
	_, tok, err := resolveTarget("f", "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "file-secret" {
		t.Errorf("token = %q, want file-secret", tok)
	}
}

func TestExpandTokenRef(t *testing.T) {
	if got, err := expandTokenRef("literal"); err != nil || got != "literal" {
		t.Errorf("literal = %q, %v", got, err)
	}
	if _, err := expandTokenRef("@/../etc/passwd"); err == nil {
		t.Error("traversal should error")
	}
	if _, err := expandTokenRef("@/nonexistent-" + filepath.Base(t.TempDir())); err == nil {
		t.Error("missing token file should error")
	}
	// Bare absolute paths are literals (same as the controller).
	if got, err := expandTokenRef("/abs/path"); err != nil || got != "/abs/path" {
		t.Errorf("abs = %q, %v", got, err)
	}
}

func TestLoadControllerInstancesMissing(t *testing.T) {
	insts, err := loadControllerInstances(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil || insts != nil {
		t.Errorf("missing file = %v, %v; want nil, nil", insts, err)
	}
}

func TestTokenRequired(t *testing.T) {
	if tokenRequired("adopt") || tokenRequired("adopt-status") {
		t.Error("adopt commands must not require a token")
	}
	if !tokenRequired("stats") || !tokenRequired("health") || !tokenRequired("watch") {
		t.Error("management commands must require a token")
	}
}

func TestIsCommand(t *testing.T) {
	for _, c := range []string{"health", "stats", "policies", "set-policy", "block", "del-policy", "adopt-status", "adopt", "watch"} {
		if !isCommand(c) {
			t.Errorf("isCommand(%q) = false", c)
		}
	}
	if isCommand("office-dns") || isCommand("http://10.0.0.5:8444") || isCommand("") {
		t.Error("ids/urls must not count as commands")
	}
}

func TestInstanceIDExists(t *testing.T) {
	cfg := writeControllerConfig(t, testControllerYAML)
	if !instanceIDExists("office-dns", cfg) {
		t.Error("known id should exist")
	}
	if instanceIDExists("nope", cfg) {
		t.Error("unknown id should not exist")
	}
	if instanceIDExists("office-dns", filepath.Join(t.TempDir(), "missing.yaml")) {
		t.Error("missing config should not report ids")
	}
	if instanceIDExists("office-dns", "") {
		t.Error("disabled lookup should not report ids")
	}
}

func TestResolveBarePrefersLiveSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "blipd.sock")
	ln, err := listenUnix(t, sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := writeControllerConfig(t, testControllerYAML)
	rt, err := resolveBare("", cfg, sock)
	if err != nil {
		t.Fatal(err)
	}
	if !rt.useSocket || rt.socketPath != sock {
		t.Errorf("got %+v, want live socket", rt)
	}
}

func TestResolveBareStaleSocketFallsBackToSingleInstance(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "stale.sock") // nothing listening
	cfg := writeControllerConfig(t, "instances:\n  - id: only\n    url: \"http://10.0.0.9:8444\"\n    token: \"tok-only\"\n")
	rt, err := resolveBare("", cfg, sock)
	if err != nil {
		t.Fatal(err)
	}
	if rt.useSocket || rt.base != "http://10.0.0.9:8444" || rt.token != "tok-only" || rt.instanceID != "only" {
		t.Errorf("got %+v, want single-instance fallback", rt)
	}
}

func TestResolveBareExplicitTokenWinsFallback(t *testing.T) {
	cfg := writeControllerConfig(t, "instances:\n  - id: only\n    url: \"http://10.0.0.9:8444\"\n    token: \"tok-only\"\n")
	rt, err := resolveBare("explicit", cfg, filepath.Join(t.TempDir(), "missing.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if rt.token != "explicit" {
		t.Errorf("token = %q, want explicit", rt.token)
	}
}

func TestResolveBareMultipleInstancesErrors(t *testing.T) {
	cfg := writeControllerConfig(t, testControllerYAML)
	_, err := resolveBare("", cfg, filepath.Join(t.TempDir(), "missing.sock"))
	if err == nil || !strings.Contains(err.Error(), "office-dns") || !strings.Contains(err.Error(), "home-dns") {
		t.Errorf("multi-instance should list ids, got %v", err)
	}
}

func TestResolveBareNothingConfiguredErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := resolveBare("", missing, filepath.Join(t.TempDir(), "missing.sock"))
	if err == nil {
		t.Error("no socket + no config should error")
	}
	empty := writeControllerConfig(t, "listen: 127.0.0.1:8500\n")
	_, err = resolveBare("", empty, filepath.Join(t.TempDir(), "missing.sock"))
	if err == nil {
		t.Error("no socket + no instances should error")
	}
}

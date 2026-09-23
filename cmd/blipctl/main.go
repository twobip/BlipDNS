// Command blipctl is the controller CLI that connects to managed blipd
// instances over their management API.
//
// Usage:
//
//	blipctl <command> [args]                        (local socket first, then single-instance controller token)
//	blipctl [--token TOKEN] <instance-url> <command> [args]
//	blipctl <instance-id> <command> [args]          (token read from the local blipc config; try sudo)
//	blipctl --socket /var/lib/blipd/blipd.sock <command> [args]  (local blipd, no token; try sudo)
//
// Commands:
//
//	health                 show instance health
//	stats                  show live stats
//	policies               list filter policies
//	set-policy <file.yml>  push a policy (YAML)
//	block <cidr> <domain>  convenience: add a block policy for a client CIDR
//	del-policy <id>        remove a policy
//	watch                  stream events (SSE)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/twobip/BlipDNS/internal/config"
	"github.com/twobip/BlipDNS/internal/control"
	"gopkg.in/yaml.v3"
)

// defaultControllerPath is where blipc keeps the fleet (instance urls+tokens)
// when blipctl runs on the controller host.
const defaultControllerPath = "/etc/blipc/blipc.yaml"

func main() {
	token := flag.String("token", os.Getenv("BLIP_TOKEN"), "management API bearer token (visible via ps; prefer --token-file)")
	tokenFile := flag.String("token-file", "", "read management API bearer token from file (0600 recommended; used only when --token/BLIP_TOKEN is empty)")
	outTokenFile := flag.String("out-token-file", "", "write the adopted admin token to this file (0600) instead of printing it to stdout")
	socketPath := flag.String("socket", "", "talk to a local blipd over its Unix admin socket (no token required; try sudo)")
	controllerPath := flag.String("controller", controllerPathDefault(), "local blipc config used to resolve instance ids/urls to tokens (\"\" disables)")
	flag.Usage = func() { usage() }
	flag.Parse()

	// Warn when the secret travels via argv/env: it is visible in `ps`,
	// /proc/<pid>/cmdline (or environ), shell history, and audit logs.
	if t := strings.TrimSpace(*token); t != "" {
		if isFlagSet("token") {
			fmt.Fprintln(os.Stderr, "warning: --token is visible via ps and shell history; prefer --token-file with mode 0600")
		} else {
			fmt.Fprintln(os.Stderr, "warning: BLIP_TOKEN is visible via /proc/<pid>/environ; prefer --token-file with mode 0600")
		}
	}

	if *token == "" && *tokenFile != "" {
		if fi, err := os.Stat(*tokenFile); err == nil && fi.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr, "warning: token file %s is group/world-accessible (mode %04o); use chmod 600\n", *tokenFile, fi.Mode().Perm())
		}
		b, err := os.ReadFile(*tokenFile)
		die(err)
		*token = strings.TrimSpace(string(b))
	}

	ctx := context.Background()

	// Local socket mode: the socket's filesystem permissions are the auth
	// boundary, so no instance address or token is needed.
	if strings.TrimSpace(*socketPath) != "" {
		args := flag.Args()
		if len(args) < 1 {
			usage()
			os.Exit(2)
		}
		client := control.NewClientUnix(strings.TrimSpace(*socketPath), *token)
		run(ctx, client, args[0], args[1:], strings.TrimSpace(*outTokenFile))
		return
	}

	args := flag.Args()
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}

	// Bare command: `blipctl stats` with no instance. The first arg is a
	// command (and not an instance id in the local controller config), so
	// there is nothing to resolve: try the local admin socket first, then
	// the controller's token for a single-instance fleet.
	if isCommand(args[0]) && !instanceIDExists(args[0], strings.TrimSpace(*controllerPath)) {
		runBare(ctx, args[0], args[1:], strings.TrimSpace(*token), strings.TrimSpace(*controllerPath), strings.TrimSpace(*outTokenFile))
		return
	}

	if len(args) < 2 {
		usage()
		os.Exit(2)
	}
	target, cmd, rest := args[0], args[1], args[2:]

	base, tok, err := resolveTarget(target, strings.TrimSpace(*token), strings.TrimSpace(*controllerPath))
	die(err)
	if tok == "" && tokenRequired(cmd) {
		die(fmt.Errorf("no token for %q: pass --token/--token-file, or run on the controller host with access to %s (try sudo)", target, displayControllerPath(strings.TrimSpace(*controllerPath))))
	}

	client := control.NewClient(base, tok)
	run(ctx, client, cmd, rest, strings.TrimSpace(*outTokenFile))
}

// runBare implements the no-target form (`blipctl stats`): the local admin
// socket wins when a blipd is listening on it, otherwise a single-instance
// fleet from the local controller config supplies the URL and token.
func runBare(ctx context.Context, cmd string, rest []string, flagToken, controllerPath, outTokenFile string) {
	rt, err := resolveBare(flagToken, controllerPath, config.Default().AdminSocket)
	die(err)
	if rt.useSocket {
		run(ctx, control.NewClientUnix(rt.socketPath, flagToken), cmd, rest, outTokenFile)
		return
	}
	if rt.token == "" && tokenRequired(cmd) {
		die(fmt.Errorf("no token for %q: pass --token/--token-file, or run on the controller host with access to %s (try sudo)", rt.instanceID, displayControllerPath(controllerPath)))
	}
	run(ctx, control.NewClient(rt.base, rt.token), cmd, rest, outTokenFile)
}

// bareTarget is the outcome of resolveBare: either a local socket or one
// controller-known instance.
type bareTarget struct {
	useSocket  bool
	socketPath string
	instanceID string
	base       string
	token      string
}

// resolveBare picks the admin path for a bare `blipctl <command>`: a live
// local socket first, else the only instance in the local controller config.
// An explicit flagToken overrides the stored one. It errors when neither
// exists, or when the fleet has several instances (the operator must name
// one: `blipctl <id> <command>`).
func resolveBare(flagToken, controllerPath, socketPath string) (bareTarget, error) {
	if socketPath != "" && socketAlive(socketPath) {
		return bareTarget{useSocket: true, socketPath: socketPath}, nil
	}
	if controllerPath == "" {
		return bareTarget{}, fmt.Errorf("no local admin socket at %s and controller lookup disabled; pass <instance-url|instance-id> with --token, or --socket <path>", socketPath)
	}
	insts, err := loadControllerInstances(controllerPath)
	if err != nil {
		return bareTarget{}, fmt.Errorf("no local admin socket at %s: %w", socketPath, err)
	}
	if insts == nil {
		return bareTarget{}, fmt.Errorf("no local admin socket at %s and no controller config at %s; pass <instance-url|instance-id> with --token, or --socket <path>", socketPath, controllerPath)
	}
	if len(insts) == 0 {
		return bareTarget{}, fmt.Errorf("no local admin socket at %s and no instances in %s", socketPath, controllerPath)
	}
	if len(insts) > 1 {
		ids := make([]string, 0, len(insts))
		for _, in := range insts {
			ids = append(ids, in.ID)
		}
		return bareTarget{}, fmt.Errorf("multiple instances (%s); specify one: blipctl <instance-id> %s", strings.Join(ids, ", "), "<command>")
	}
	in := insts[0]
	tok := flagToken
	if tok == "" {
		var err error
		tok, err = expandTokenRef(in.Token)
		if err != nil {
			return bareTarget{}, fmt.Errorf("instance %q: %w", in.ID, err)
		}
	}
	return bareTarget{instanceID: in.ID, base: in.URL, token: tok}, nil
}

// socketAlive reports whether something is listening on the Unix socket path.
// A stale file from an unclean shutdown refuses the dial and falls through to
// the token path.
func socketAlive(path string) bool {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// isCommand reports whether s names a blipctl command (i.e. the first bare
// arg is a command, not an instance id or URL).
func isCommand(s string) bool {
	switch s {
	case "health", "stats", "policies", "set-policy", "block", "del-policy",
		"adopt-status", "adopt", "watch":
		return true
	default:
		return false
	}
}

// instanceIDExists reports whether id names an instance in the local
// controller config. Any load failure (missing file, permission denied)
// counts as false so bare-command mode still gets to probe the socket.
func instanceIDExists(id, controllerPath string) bool {
	if id == "" || controllerPath == "" {
		return false
	}
	insts, err := loadControllerInstances(controllerPath)
	if err != nil {
		return false
	}
	for _, in := range insts {
		if in.ID == id {
			return true
		}
	}
	return false
}

// tokenRequired reports whether cmd needs a bearer token. The adoption
// handshake (and its status probe) intentionally work without one.
func tokenRequired(cmd string) bool {
	switch cmd {
	case "adopt-status", "adopt":
		return false
	default:
		return true
	}
}

func run(ctx context.Context, client *control.Client, cmd string, rest []string, outTokenFile string) {
	switch cmd {
	case "health":
		h, err := client.Health(ctx)
		die(err)
		printJSON(h)
	case "stats":
		s, err := client.Stats(ctx)
		die(err)
		printJSON(s)
	case "policies":
		l, err := client.ListPolicies(ctx)
		die(err)
		printJSON(l)
	case "set-policy":
		if len(rest) < 1 {
			die(fmt.Errorf("set-policy requires a YAML file path"))
		}
		p := loadPolicyFile(rest[0])
		die(client.SetPolicy(ctx, p))
		fmt.Println("policy set:", p.ID)
	case "block":
		if len(rest) < 2 {
			die(fmt.Errorf("block requires <cidr> <domain>"))
		}
		p := &control.Policy{
			ID:       "ctl-" + sanitize(rest[0]),
			Networks: []string{rest[0]},
			Block:    []string{rest[1]},
			Log:      true,
		}
		die(client.SetPolicy(ctx, p))
		fmt.Println("blocked", rest[1], "for", rest[0])
	case "del-policy":
		if len(rest) < 1 {
			die(fmt.Errorf("del-policy requires <id>"))
		}
		die(client.DeletePolicy(ctx, rest[0]))
		fmt.Println("deleted policy:", rest[0])
	case "adopt-status":
		st, err := client.AdoptStatus(ctx)
		die(err)
		printJSON(st)
	case "adopt":
		if len(rest) < 1 {
			die(fmt.Errorf("adopt requires <code>"))
		}
		resp, err := client.Adopt(ctx, rest[0])
		die(err)
		if !resp.Adopted {
			die(fmt.Errorf("adoption rejected: %s", resp.Message))
		}
		if resp.Token != "" {
			if outTokenFile != "" {
				if err := os.WriteFile(outTokenFile, []byte(resp.Token+"\n"), 0600); err != nil {
					die(err)
				}
				// WriteFile does not chmod existing files; enforce 0600.
				_ = os.Chmod(outTokenFile, 0600)
				fmt.Println("adopted. admin token written to", outTokenFile, "(mode 0600; keep it private)")
			} else {
				fmt.Fprintln(os.Stderr, "WARNING: this admin token is printed once — store it in a 0600 file (see --out-token-file) and clear your terminal history")
				fmt.Println("adopted. admin token:", resp.Token)
			}
		} else {
			fmt.Println("already adopted (token was issued earlier; use the stored token)")
		}
	case "watch":
		fmt.Println("watching (ctrl-c to stop)")
		die(client.Watch(ctx, func(e control.WatchEvent) {
			b, _ := json.Marshal(e)
			fmt.Println(time.Now().Format("15:04:05"), string(b))
		}))
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		usage()
		os.Exit(2)
	}
}

// controllerInstance is the subset of the blipc fleet config blipctl needs to
// resolve an instance id (or url) to its address and token.
type controllerInstance struct {
	ID    string `yaml:"id"`
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
	Label string `yaml:"label"`
}

// resolveTarget maps the first positional arg to an instance URL and token.
// A target containing "://" is a direct URL (an explicit token still wins; a
// matching local controller entry supplies the token otherwise). Anything else
// is an instance id looked up in the local blipc config, so operators on the
// controller host never handle tokens directly.
func resolveTarget(target, flagToken, controllerPath string) (base, token string, err error) {
	if strings.Contains(target, "://") {
		if flagToken != "" {
			return target, flagToken, nil
		}
		if controllerPath != "" {
			if insts, lerr := loadControllerInstances(controllerPath); lerr == nil {
				for _, in := range insts {
					if normalizeURL(in.URL) == normalizeURL(target) {
						tok, terr := expandTokenRef(in.Token)
						if terr != nil {
							return "", "", fmt.Errorf("instance %q: %w", in.ID, terr)
						}
						return in.URL, tok, nil
					}
				}
			}
		}
		return target, "", nil
	}
	if controllerPath == "" {
		return "", "", fmt.Errorf("unknown instance %q: controller lookup disabled; pass a URL with --token", target)
	}
	insts, err := loadControllerInstances(controllerPath)
	if err != nil {
		return "", "", fmt.Errorf("unknown instance %q: %w", target, err)
	}
	if insts == nil {
		return "", "", fmt.Errorf("unknown instance %q: no controller config at %s; pass a URL with --token", target, controllerPath)
	}
	for _, in := range insts {
		if in.ID == target {
			if flagToken != "" {
				return in.URL, flagToken, nil
			}
			tok, err := expandTokenRef(in.Token)
			if err != nil {
				return "", "", fmt.Errorf("instance %q: %w", in.ID, err)
			}
			return in.URL, tok, nil
		}
	}
	return "", "", fmt.Errorf("unknown instance %q: not in %s; pass a URL with --token", target, controllerPath)
}

// loadControllerInstances reads the instance list from the local blipc config.
// A missing file returns (nil, nil) so remote-only use keeps working; an
// existing-but-unreadable file is an error (usually: re-run with sudo, since
// the config holds instance tokens at mode 0600).
func loadControllerInstances(path string) ([]controllerInstance, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("cannot read %s (permission denied; try sudo)", path)
		}
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	var cfg struct {
		Instances []controllerInstance `yaml:"instances"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("cannot parse %s: %w", path, err)
	}
	return cfg.Instances, nil
}

// expandTokenRef resolves an "@/path" token file reference from the controller
// config, mirroring the controller's own expansion: only "@" opts into a file
// read, ".." components are rejected, and an empty file is an error (instead
// of silently authenticating with an empty token). Bare "/abs/path" values are
// literals, exactly as the controller treats them.
func expandTokenRef(tok string) (string, error) {
	if len(tok) < 2 || tok[0] != '@' {
		return tok, nil
	}
	p := tok[1:]
	for _, el := range strings.Split(p, string(filepath.Separator)) {
		if el == ".." {
			return "", fmt.Errorf("refusing token path with traversal: %q", tok)
		}
	}
	if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: token file %s is group/world-accessible (mode %04o); use chmod 600\n", p, fi.Mode().Perm())
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return "", fmt.Errorf("cannot read token file %s (permission denied; try sudo)", p)
		}
		return "", fmt.Errorf("cannot read token file %s: %w", p, err)
	}
	if trimmed := strings.TrimSpace(string(b)); trimmed != "" {
		return trimmed, nil
	}
	return "", fmt.Errorf("token file %s is empty", p)
}

func normalizeURL(u string) string {
	return strings.TrimSuffix(strings.TrimSpace(u), "/")
}

func controllerPathDefault() string {
	if p := strings.TrimSpace(os.Getenv("BLIPC_CONFIG")); p != "" {
		return p
	}
	return defaultControllerPath
}

func displayControllerPath(p string) string {
	if p == "" {
		return "(controller lookup disabled)"
	}
	return p
}

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func loadPolicyFile(path string) *control.Policy {
	b, err := os.ReadFile(path)
	die(err)
	var p control.Policy
	die(yaml.Unmarshal(b, &p))
	if p.ID == "" {
		die(fmt.Errorf("policy file missing id"))
	}
	return &p
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
}

func printJSON(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `blipctl <command> [args]
blipctl [--token TOKEN] <instance-url|instance-id> <command> [args]
blipctl --socket <path> <command> [args]

With no instance, blipctl tries the local blipd admin socket first (no token;
needs socket access, so use sudo), then the token of a single-instance fleet
from the local blipc config. With several instances, name one explicitly.
On the controller host (blipc + blipctl installed together) an instance id is
enough: the token is read from the local blipc config (needs read access, so
use sudo). Direct URLs still work from anywhere with --token/--token-file.
On the blipd host itself, --socket uses the local admin socket with no token
at all (sudo blipctl --socket /var/lib/blipd/blipd.sock stats).

flags:
  --token TOKEN        management API bearer token (visible via ps; prefer --token-file)
  --token-file PATH    read the token from file (0600 recommended)
  --socket PATH        local blipd Unix admin socket (no token required)
  --controller PATH    local blipc config for id/token lookup (default /etc/blipc/blipc.yaml, env BLIPC_CONFIG; "" disables)
  --out-token-file P   write an adopted admin token to P (0600) instead of stdout

commands:
  health                 show instance health
  stats                  show live stats
  policies               list filter policies
  set-policy <file.yml>  push a policy
  block <cidr> <domain>  add a block policy for a client CIDR
  del-policy <id>        remove a policy
  adopt-status           show adoption state (no token needed)
  adopt <code>           claim this instance once; prints its admin token
  watch                  stream events (SSE)
`)
}

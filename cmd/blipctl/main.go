// Command blipctl is the controller CLI that connects to managed blipd
// instances over their management API.
//
// Usage:
//
//	blipctl [--token TOKEN] <instance-url> <command> [args]
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
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
	"gopkg.in/yaml.v3"
)

func main() {
	token := flag.String("token", os.Getenv("BLIP_TOKEN"), "management API bearer token (visible via ps; prefer --token-file)")
	tokenFile := flag.String("token-file", "", "read management API bearer token from file (0600 recommended; used only when --token/BLIP_TOKEN is empty)")
	outTokenFile := flag.String("out-token-file", "", "write the adopted admin token to this file (0600) instead of printing it to stdout")
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

	args := flag.Args()
	if len(args) < 2 {
		usage()
		os.Exit(2)
	}
	base := args[0]
	cmd := args[1]
	rest := args[2:]

	client := control.NewClient(base, *token)
	ctx := context.Background()

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
			if strings.TrimSpace(*outTokenFile) != "" {
				if err := os.WriteFile(*outTokenFile, []byte(resp.Token+"\n"), 0600); err != nil {
					die(err)
				}
				// WriteFile does not chmod existing files; enforce 0600.
				_ = os.Chmod(*outTokenFile, 0600)
				fmt.Println("adopted. admin token written to", *outTokenFile, "(mode 0600; keep it private)")
			} else {
				fmt.Fprintln(os.Stderr, "WARNING: this admin token is printed once — store it in a 0600 file (see --out-token-file) and clear your terminal history")
				fmt.Println("adopted. admin token:", resp.Token)
			}
		} else {
			fmt.Println("already adopted (token was issued earlier; use the stored token)")
		}
	case "watch":
		fmt.Println("watching", base, "(ctrl-c to stop)")
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
	fmt.Fprint(os.Stderr, `blipctl [--token TOKEN] <instance-url> <command> [args]

commands:
  health                 show instance health
  stats                  show live stats
  policies               list filter policies
  set-policy <file.yml>  push a policy
  block <cidr> <domain>  add a block policy for a client CIDR
  del-policy <id>        remove a policy
  adopt-status           show adoption state (unauth)
  adopt <code>           claim this instance once; prints its admin token
  watch                  stream events (SSE)
`)
}

// Command blipc is the BlipDNS controller: a Unifi-style management console
// that connects to one or more blipd instances, aggregates their stats and
// block logs, pushes filter policy to them, and serves a web dashboard.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/controller"
	"gopkg.in/yaml.v3"
)

const version = "blipc/0.1.0"

type config struct {
	Listen               string                                  `yaml:"listen"`
	Username             string                                  `yaml:"username"`
	Password             string                                  `yaml:"password"`
	PasswordHash         string                                  `yaml:"password_hash"`
	DefaultPolicy        *control.Policy                         `yaml:"default_policy"`
	InstanceOverrides    map[string]*controller.InstanceOverride `yaml:"instance_overrides"`
	DoHHTTPAddr          string                                  `yaml:"doh_http_addr"`
	RateLimitQPS         int                                     `yaml:"rate_limit_qps"`
	BlocklistSources     []string                                `yaml:"blocklist_sources"`
	BlocklistUpdateHours int                                     `yaml:"blocklist_update_hours"`
	Instances            []controller.InstanceConfig             `yaml:"instances"`
}

func main() {
	cfgPath := flag.String("config", "/etc/blipc/blipc.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := load(*cfgPath)
	if err != nil {
		log.Fatalf("blipc: %v", err)
	}
	warnConfigPerms(*cfgPath)
	if cfg.Username == "" {
		cfg.Username = os.Getenv("BLIPC_USER")
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv("BLIPC_PASS")
	}
	if cfg.PasswordHash == "" {
		cfg.PasswordHash = os.Getenv("BLIPC_PASS_HASH")
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:8500"
	}

	fleet := controller.NewFleet(*cfgPath)
	if cfg.DefaultPolicy != nil {
		fleet.SetDefault(cfg.DefaultPolicy)
	}
	for id, o := range cfg.InstanceOverrides {
		fleet.SetOverride(id, o)
	}
	if cfg.DoHHTTPAddr != "" {
		fleet.SetDoHDefault(cfg.DoHHTTPAddr)
	}
	if cfg.RateLimitQPS > 0 {
		fleet.SetRateLimitQPSDefault(cfg.RateLimitQPS)
	}
	ctx := context.Background()
	for _, ic := range cfg.Instances {
		ic = controller.ResolveTokenFile(ic)
		if err := fleet.Add(ctx, ic); err != nil {
			log.Printf("blipc: instance %s: %v", ic.ID, err)
		}
	}
	// Restore the last merged blocklist into RAM from the local DB so a restart
	// blocks immediately, then seed the sources and fetch fresh data in the
	// background; instances pick the list up via the poll reconcile / push.
	if err := fleet.LoadBlocklistCache(ctx); err != nil {
		log.Printf("blipc: blocklist cache: %v", err)
	}
	fleet.LoadManualDomains(ctx)
	fleet.LoadAllowedDomains(ctx)
	fleet.LoadSourceStats(ctx)
	if cfg.BlocklistUpdateHours > 0 {
		fleet.SetAutoUpdateHours(cfg.BlocklistUpdateHours)
	}
	if len(cfg.BlocklistSources) > 0 {
		fleet.SetBlocklistSources(ctx, cfg.BlocklistSources)
	}
	fleet.StartAutoUpdater()

	// Prefer a pre-hashed bcrypt password (kept out of the config plaintext);
	// fall back to the plaintext password, which NewAuth hashes at startup.
	authPass := cfg.PasswordHash
	if authPass == "" {
		authPass = cfg.Password
	}
	srv := controller.NewServer(cfg.Username, authPass, fleet, controller.UI())
	httpSrv := &http.Server{
		Addr:    cfg.Listen,
		Handler: srv.Handler(),
	}
	log.Printf("blipc %s listening on %s (%d instances)", version, cfg.Listen, len(cfg.Instances))
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("blipc: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("blipc: shutting down")
	_ = httpSrv.Close()
	fleet.Bus().Publish(controller.Event{Type: "status", At: time.Now(), Msg: "shutdown"})
}

func load(path string) (*config, error) {
	c := &config{Listen: "0.0.0.0:8500"}
	b, err := os.ReadFile(path)
	if err != nil {
		// not fatal: allow running with zero instances (add via UI)
		log.Printf("blipc: no config at %s (continuing with none): %v", path, err)
		return c, nil
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

// warnConfigPerms logs a warning if the config file is group- or world-readable,
// since it holds the admin password and per-instance tokens.
func warnConfigPerms(path string) {
	if path == "" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("blipc: cannot stat config %s: %v", path, err)
		}
		return
	}
	m := fi.Mode().Perm()
	if m&0o077 != 0 {
		log.Printf("blipc: WARNING: config file %s is group/world-accessible (mode %04o); it may contain credentials. Use `chmod 600 %s`.", path, m, path)
	}
}

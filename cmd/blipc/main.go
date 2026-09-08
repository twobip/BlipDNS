// Command blipc is the BlipDNS controller: a Unifi-style management console
// that connects to one or more blipd instances, aggregates their stats and
// block logs, pushes filter policy to them, and serves a web dashboard.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	blipconfig "github.com/twobip/BlipDNS/internal/config"
	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/controller"
	"github.com/twobip/BlipDNS/internal/upstream"
	"gopkg.in/yaml.v3"
)

type config struct {
	Listen                 string                                  `yaml:"listen"`
	Username               string                                  `yaml:"username"`
	Password               string                                  `yaml:"password"`
	PasswordHash           string                                  `yaml:"password_hash"`
	DefaultPolicy          *control.Policy                         `yaml:"default_policy"`
	InstanceOverrides      map[string]*controller.InstanceOverride `yaml:"instance_overrides"`
	DoHHTTPAddr            string                                  `yaml:"doh_http_addr"`
	RateLimitQPS           int                                     `yaml:"rate_limit_qps"`
	CacheSize              int                                     `yaml:"cache_size"`
	CacheWarm              int                                     `yaml:"cache_warm"`
	CacheRegular           int                                     `yaml:"cache_regular"`
	QueryLogRetentionHours int                                     `yaml:"query_log_retention_hours"`
	UpstreamServers        []upstream.UpstreamServer               `yaml:"upstream_servers"`
	UpstreamRoutes         []upstream.UpstreamRoute                `yaml:"upstream_routes"`
	UpstreamBootstrap      []upstream.UpstreamServer               `yaml:"upstream_bootstrap"`
	BlocklistSources       []string                                `yaml:"blocklist_sources"`
	BlocklistDisabled      []string                                `yaml:"blocklist_disabled"`
	BlocklistUpdateHours   int                                     `yaml:"blocklist_update_hours"`
	Instances              []controller.InstanceConfig             `yaml:"instances"`
	Records                []control.RecordEntry                   `yaml:"records"`
	HACluster              control.HACluster                       `yaml:"high_availability"`
	ReleaseChannel         string                                  `yaml:"release_channel"`
}

func main() {
	cfgPath := flag.String("config", "/etc/blipc/blipc.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := load(*cfgPath)
	if err != nil {
		log.Fatalf("blipc: %v", err)
	}
	blipconfig.WarnConfigPerms("blipc", *cfgPath)
	warnPlainHTTP("blipc", "dashboard", cfg.Listen)
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
	if cfg.CacheSize > 0 || cfg.CacheWarm > 0 || cfg.CacheRegular > 0 {
		fleet.SetCacheDefault(cfg.CacheSize, cfg.CacheWarm, cfg.CacheRegular)
	}
	fleet.SetQueryLogRetentionDefault(cfg.QueryLogRetentionHours)
	fleet.SetRecords(context.Background(), cfg.Records)
	if cfg.HACluster.Enabled {
		if err := fleet.SetHAClusterDefault(cfg.HACluster); err != nil {
			log.Printf("blipc: high availability config: %v", err)
		}
	}
	if cfg.ReleaseChannel != "" {
		if err := fleet.SetReleaseChannelDefault(cfg.ReleaseChannel); err != nil {
			log.Printf("blipc: release channel: %v", err)
		}
	} else {
		fleet.StartReleaseCheck()
	}
	if len(cfg.UpstreamServers) > 0 || len(cfg.UpstreamRoutes) > 0 {
		fleet.SetUpstreamDefault(cfg.UpstreamServers, cfg.UpstreamRoutes, cfg.UpstreamBootstrap)
		if len(cfg.UpstreamServers) > 0 {
			fleet.WarnOrphanPolicyUpstreams(cfg.UpstreamServers)
		}
	}
	ctx := context.Background()
	// Kick off the blocklist restore in the background (multi-million domains;
	// the SQLite read + set rebuild are slow). The per-instance reconcile holds
	// off via f.blLoading until it finishes, so a node with its own cached list
	// is never cleared by a transient empty in-memory list.
	fleet.LoadBlocklistCache(ctx)
	fleet.LoadManualDomains(ctx)
	fleet.LoadAllowedDomains(ctx)
	fleet.LoadSourceStats(ctx)
	for _, ic := range cfg.Instances {
		ic = controller.ResolveTokenFile(ic)
		if err := fleet.Add(ctx, ic); err != nil {
			log.Printf("blipc: instance %s: %v", ic.ID, err)
		}
	}
	if cfg.BlocklistUpdateHours > 0 {
		fleet.SetAutoUpdateHours(cfg.BlocklistUpdateHours)
	}
	if len(cfg.BlocklistSources) > 0 {
		// Restore the disabled set first so the initial import (triggered by
		// SetBlocklistSources) skips sources the operator turned off.
		fleet.SetBlocklistDisabled(cfg.BlocklistDisabled)
		fleet.SetBlocklistSources(ctx, cfg.BlocklistSources)
	}
	fleet.StartAutoUpdater()

	// Prefer a pre-hashed bcrypt password (kept out of the config plaintext);
	// fall back to the plaintext password, which NewAuth hashes at startup.
	authPass := cfg.PasswordHash
	if authPass == "" {
		authPass = cfg.Password
	}
	setupToken := ""
	if cfg.Username == "" || authPass == "" || !controller.NewAuth(cfg.Username, authPass).Configured() {
		var tokenErr error
		setupToken, tokenErr = controller.NewSetupToken()
		if tokenErr != nil {
			log.Fatalf("blipc: generate setup token: %v", tokenErr)
		}
		log.Printf("blipc: first-run setup token: %s", setupToken)
		log.Printf("blipc: open http://%s/setup#token=%s to create the administrator account", cfg.Listen, setupToken)
	}
	srv := controller.NewServerWithConfig(cfg.Username, authPass, fleet, controller.UI(), *cfgPath, setupToken)
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("blipc %s (pid %d) listening on %s (%d instances)", controller.ControllerVersion(), os.Getpid(), cfg.Listen, len(cfg.Instances))
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

// warnPlainHTTP logs when the credential-bearing dashboard binds beyond
// loopback without TLS (session cookies cross the wire in cleartext there).
func warnPlainHTTP(prog, what, addr string) {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	if h == "" || h == "127.0.0.1" || h == "::1" || h == "localhost" {
		return
	}
	log.Printf("%s: WARNING: %s on %s is plain HTTP on a non-loopback address; session cookies are sniffable. Terminate TLS in front of it.", prog, what, addr)
}

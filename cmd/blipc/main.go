// Command blipc is the BlipDNS controller: a Unifi-style management console
// that connects to one or more blipd instances, aggregates their stats and
// block logs, pushes filter policy to them, and serves a web dashboard.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/twobip/BlipDNS/internal/certgen"
	blipconfig "github.com/twobip/BlipDNS/internal/config"
	"github.com/twobip/BlipDNS/internal/control"
	"github.com/twobip/BlipDNS/internal/controller"
	"github.com/twobip/BlipDNS/internal/upstream"
	"gopkg.in/yaml.v3"
)

type config struct {
	Listen                 string                                  `yaml:"listen"`
	TrustedProxies         []string                                `yaml:"trusted_proxies"`
	DashboardTLS           bool                                    `yaml:"dashboard_tls"`
	TLSDir                 string                                  `yaml:"tls_dir"`
	TLSCertFile            string                                  `yaml:"tls_cert_file"`
	TLSKeyFile             string                                  `yaml:"tls_key_file"`
	TLSSANs                []string                                `yaml:"tls_san"`
	Username               string                                  `yaml:"username"`
	Password               string                                  `yaml:"password"`
	PasswordHash           string                                  `yaml:"password_hash"`
	DefaultPolicy          *control.Policy                         `yaml:"default_policy"`
	InstanceOverrides      map[string]*controller.InstanceOverride `yaml:"instance_overrides"`
	DoHHTTPAddr            string                                  `yaml:"doh_http_addr"`
	RateLimitQPS           int                                     `yaml:"rate_limit_qps"`
	CacheSize              int                                     `yaml:"cache_size"`
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
	if cfg.CacheSize > 0 {
		fleet.SetCacheDefault(cfg.CacheSize)
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
		// Restore the lists without importing: restarts serve the persisted
		// cache, and refreshes come from the auto-updater (when due) or an
		// explicit operator action.
		fleet.SetBlocklistDisabled(cfg.BlocklistDisabled)
		fleet.SetBlocklistSourcesDefault(cfg.BlocklistSources)
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
		log.Printf("blipc: open http%s://%s/setup#token=%s to create the administrator account", map[bool]string{true: "s", false: ""}[cfg.DashboardTLS || (cfg.TLSCertFile != "" && cfg.TLSKeyFile != "")], cfg.Listen, setupToken)
	}
	if len(cfg.TrustedProxies) > 0 {
		fleet.SetTrustedProxiesDefault(cfg.TrustedProxies)
	}
	srv := controller.NewServerWithConfig(cfg.Username, authPass, fleet, controller.UI(), *cfgPath, setupToken)
	if len(cfg.TrustedProxies) > 0 {
		if err := srv.SetTrustedProxies(cfg.TrustedProxies); err != nil {
			log.Fatalf("blipc: trusted_proxies: %v", err)
		}
		log.Printf("blipc: trusting proxy headers from %v", cfg.TrustedProxies)
	}
	// Dashboard TLS: same self-signed mechanism as blipd DoH (certgen). When
	// dashboard_tls is set (or explicit cert/key files are given), serve
	// HTTPS; otherwise plain HTTP (loopback or behind a TLS proxy).
	dashboardTLS := cfg.DashboardTLS || (cfg.TLSCertFile != "" && cfg.TLSKeyFile != "")
	if !dashboardTLS {
		blipconfig.WarnPlainHTTP("blipc", "dashboard", cfg.Listen, "session cookies")
	}
	var tlsCert *tls.Certificate
	if dashboardTLS {
		tlsDir := cfg.TLSDir
		if tlsDir == "" {
			tlsDir = "/var/lib/blipc"
		}
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			pair, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				log.Fatalf("blipc: load tls cert/key: %v", err)
			}
			tlsCert = &pair
		} else {
			certPath := filepath.Join(tlsDir, "dashboard-cert.pem")
			keyPath := filepath.Join(tlsDir, "dashboard-key.pem")
			certPEM, keyPEM, persisted, err := certgen.EnsureFiles(certPath, keyPath, cfg.TLSSANs...)
			if err != nil {
				log.Printf("blipc: self-signed dashboard cert: %v (serving with in-memory cert this session)", err)
			}
			pair, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				log.Fatalf("blipc: build self-signed cert: %v", err)
			}
			tlsCert = &pair
			if persisted {
				log.Printf("blipc: dashboard serving HTTPS with certificate %s", certPath)
			}
		}
	}
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if tlsCert != nil {
		httpSrv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			PreferServerCipherSuites: true,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			Certificates:             []tls.Certificate{*tlsCert},
		}
	}
	scheme := "http"
	if tlsCert != nil {
		scheme = "https"
	}
	log.Printf("blipc %s (pid %d) listening on %s://%s (%d instances)", controller.ControllerVersion(), os.Getpid(), scheme, cfg.Listen, len(cfg.Instances))
	go func() {
		var err error
		if tlsCert != nil {
			err = httpSrv.ListenAndServeTLS("", "")
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
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
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, err
	}
	return c, nil
}

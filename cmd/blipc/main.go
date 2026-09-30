// Command blipc is the BlipDNS controller: a Unifi-style management console
// that connects to one or more blipd instances, aggregates their stats and
// block logs, pushes filter policy to them, and serves a web dashboard.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
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
	Listen         string   `yaml:"listen"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	// DashboardTLS nil (omitted) means true: the dashboard serves HTTPS by
	// default. Explicit `dashboard_tls: false` restores plaintext (loopback
	// or behind a TLS-terminating proxy only; non-loopback plaintext is
	// refused unless allow_plain_remote is set).
	DashboardTLS      *bool                                   `yaml:"dashboard_tls"`
	AllowPlainRemote  bool                                    `yaml:"allow_plain_remote"`
	StrictCSRF        *bool                                   `yaml:"strict_csrf"`
	TLSDir            string                                  `yaml:"tls_dir"`
	TLSCertFile       string                                  `yaml:"tls_cert_file"`
	TLSKeyFile        string                                  `yaml:"tls_key_file"`
	TLSSANs           []string                                `yaml:"tls_san"`
	Username          string                                  `yaml:"username"`
	Password          string                                  `yaml:"password"`
	PasswordHash      string                                  `yaml:"password_hash"`
	DefaultPolicy     *control.Policy                         `yaml:"default_policy"`
	InstanceOverrides map[string]*controller.InstanceOverride `yaml:"instance_overrides"`
	DoHHTTPAddr       string                                  `yaml:"doh_http_addr"`
	RateLimitQPS      int                                     `yaml:"rate_limit_qps"`
	// CacheSize is a pointer so "omitted" (nil = blipd keeps its own default)
	// stays distinct from an explicit "cache_size: 0" (unlimited, F-18).
	CacheSize              *int                        `yaml:"cache_size"`
	QueryLogRetentionHours int                         `yaml:"query_log_retention_hours"`
	UpstreamServers        []upstream.UpstreamServer   `yaml:"upstream_servers"`
	UpstreamRoutes         []upstream.UpstreamRoute    `yaml:"upstream_routes"`
	UpstreamBootstrap      []upstream.UpstreamServer   `yaml:"upstream_bootstrap"`
	BlocklistSources       []string                    `yaml:"blocklist_sources"`
	BlocklistDisabled      []string                    `yaml:"blocklist_disabled"`
	BlocklistUpdateHours   int                         `yaml:"blocklist_update_hours"`
	Instances              []controller.InstanceConfig `yaml:"instances"`
	Records                []control.RecordEntry       `yaml:"records"`
	HACluster              control.HACluster           `yaml:"high_availability"`
	ReleaseChannel         string                      `yaml:"release_channel"`
}

func main() {
	cfgPath := flag.String("config", "/etc/blipc/blipc.yaml", "path to YAML config")
	showVersion := flag.Bool("version", false, "print the release version and exit")
	flag.Parse()

	// Finding 9: downgrade guards need a trustworthy local version, so
	// --version prints the bare stamped release (e.g. "0.7.0+47cf192").
	if *showVersion {
		fmt.Println(controller.ControllerVersion())
		return
	}

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
		// F-04: secure-by-default. The deploy template already uses
		// 127.0.0.1:8500; the code default matches it so a missing `listen`
		// never silently exposes cleartext HTTP + session cookies on all
		// interfaces. Operators needing LAN access must opt in explicitly
		// (prefer dashboard_tls + reverse proxy, see deploy/reverse-proxy.md).
		cfg.Listen = "127.0.0.1:8500"
	}

	fleet := controller.NewFleet(*cfgPath)
	// Seed trusted proxies BEFORE anything that persists: the instance Add
	// loop below saves the config, and saveConfig writes trusted_proxies
	// from memory — seeding afterwards wiped a configured list on every
	// restart (the later live-server call only needed srv to exist).
	if len(cfg.TrustedProxies) > 0 {
		fleet.SetTrustedProxiesDefault(cfg.TrustedProxies)
	}
	// Restore persisted blocklist settings FIRST: several startup calls below
	// (SetRecords, Add) persist the config, and saveConfig writes the source
	// list from memory — restoring afterwards lets every restart clobber
	// blocklist_sources on disk, and a second restart before any save then
	// loses the sources permanently while the SQLite snapshot keeps
	// blocking, masking the loss.
	restoreBlocklistSettings(fleet, cfg.BlocklistSources, cfg.BlocklistDisabled, cfg.BlocklistUpdateHours)
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
	// F-18: CacheSize is presence-aware (*int). An explicit `cache_size: 0`
	// means unlimited and must reach the fleet; an omitted field leaves
	// blipd on its own default. The old `> 0` check silently dropped
	// explicit zeros, drifting from the documented behavior.
	if cfg.CacheSize != nil {
		fleet.SetCacheDefault(*cfg.CacheSize)
	}
	fleet.SetQueryLogRetentionDefault(cfg.QueryLogRetentionHours)
	// Startup seeding uses the non-persisting Default variant: the persisting
	// SetRecords would saveConfig with a still-empty fleet (the instance Add
	// loop runs below) and permanently wipe the configured instances.
	fleet.SetRecordsDefault(cfg.Records)
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
	fleet.StartAutoUpdater()

	// Prefer a pre-hashed bcrypt password (kept out of the config plaintext);
	// fall back to the plaintext password, which NewAuth hashes at startup.
	// F-06: plaintext `password` stays supported for first-boot/testing, but
	// it is warned about loudly — production must use `password_hash`.
	if cfg.Password != "" {
		log.Printf("blipc: WARNING plaintext `password` is set in %s; switch to `password_hash` (bcrypt) and remove it", *cfgPath)
	}
	authPass := cfg.PasswordHash
	if authPass == "" {
		authPass = cfg.Password
	}
	// Effective dashboard scheme is needed for the first-run setup URL.
	dashboardTLS := effectiveDashboardTLS(cfg)
	setupToken := ""
	if cfg.Username == "" || authPass == "" || !controller.NewAuth(cfg.Username, authPass).Configured() {
		var tokenErr error
		setupToken, tokenErr = controller.NewSetupToken()
		if tokenErr != nil {
			log.Fatalf("blipc: generate setup token: %v", tokenErr)
		}
		// First-run bootstrap: no admin exists yet, so the one-time token is
		// printed once to the local log only (journal, blipc/root-readable).
		// It is single-use and the /api/setup endpoint rate-limits guesses.
		// Logged as a single setup URL (not a bare token plus a URL) so the
		// secret appears once, not twice. Keep it private.
		log.Printf("blipc: first-run setup (one-time, keep private): open http%s://%s/setup#token=%s to create the administrator account", map[bool]string{true: "s", false: ""}[dashboardTLS], cfg.Listen, setupToken)
	}
	srv := controller.NewServerWithConfig(cfg.Username, authPass, fleet, controller.UI(), *cfgPath, setupToken)
	// StrictCSRF defaults true for new deploys (fail closed on header-stripped
	// cross-site posts). Explicit `strict_csrf: false` restores the legacy
	// compat mode for API clients that omit Origin/Sec-Fetch-Site.
	strictCSRF := true
	if cfg.StrictCSRF != nil {
		strictCSRF = *cfg.StrictCSRF
	}
	srv.StrictCSRF = strictCSRF
	if len(cfg.TrustedProxies) > 0 {
		if err := srv.SetTrustedProxies(cfg.TrustedProxies); err != nil {
			log.Fatalf("blipc: trusted_proxies: %v", err)
		}
		log.Printf("blipc: trusting proxy headers from %v", cfg.TrustedProxies)
	}
	// Dashboard TLS: HTTPS by default (same self-signed mechanism as blipd
	// DoH via certgen). Explicit cert/key files always win; otherwise a
	// co-located blipd DoH pair is reused when readable so a single cert
	// covers DNS + dashboard; else a dedicated dashboard pair is generated
	// under tls_dir. Explicit `dashboard_tls: false` opts back into plain
	// HTTP: loopback or behind a TLS-terminating proxy (trusted_proxies set)
	// warn; directly-exposed plaintext without a proxy is refused below.
	if refusePlainRemote(cfg.Listen, dashboardTLS, cfg.AllowPlainRemote, cfg.TrustedProxies) {
		log.Fatalf("blipc: refusing plain HTTP on non-loopback %s with no trusted proxy (session cookies would be sniffable); serve dashboard_tls: true, bind listen to 127.0.0.1:8500 behind a TLS proxy and set trusted_proxies (see deploy/reverse-proxy.md), or set allow_plain_remote: true to acknowledge the risk", cfg.Listen)
	}
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
		} else if sharedCertPEM, sharedKeyPEM, ok := coLocatedDoHPair(); ok {
			// Single-cert default: the co-located blipd DoH pair covers the
			// dashboard too, so LAN clients pin one fingerprint. Falls
			// through to a dedicated pair when blipd is absent, remote,
			// or unreadable (e.g. blip:blip 0600 key).
			pair, err := tls.X509KeyPair(sharedCertPEM, sharedKeyPEM)
			if err != nil {
				log.Fatalf("blipc: build shared DoH cert: %v", err)
			}
			tlsCert = &pair
			log.Printf("blipc: dashboard reusing co-located blipd DoH pair %s", sharedDoHCertFile)
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

// restoreBlocklistSettings loads the persisted blocklist source list,
// disabled set and refresh interval into the fleet without importing.
// Restarts serve the persisted cache; refreshes come from the auto-updater
// (when due) or an explicit operator action. The no-save setters run first
// and SetAutoUpdateHours (which persists) last, so a save can never observe
// a half-restored fleet.

// sharedDoH paths are blipd's default self-signed pair (see cmd/blipd
// TLSDir/doh-cert.pem). When blipc is co-located and can read both files,
// the dashboard reuses them so one fingerprint covers DoH + dashboard.
const (
	sharedDoHCertFile = "/var/lib/blipd/doh-cert.pem"
	sharedDoHKeyFile  = "/var/lib/blipd/doh-key.pem"
)

// effectiveDashboardTLS reports whether the dashboard serves HTTPS.
// Explicit cert/key files always enable TLS; otherwise an omitted
// dashboard_tls defaults to true (secure by default). Explicit
// `dashboard_tls: false` opts back into plaintext.
func effectiveDashboardTLS(cfg *config) bool {
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		return true
	}
	if cfg.DashboardTLS == nil {
		return true
	}
	return *cfg.DashboardTLS
}

// coLocatedDoHPair returns the blipd DoH pair when both files are readable
// by this process (co-located install, permissive key). Callers fall back
// to a dedicated dashboard pair otherwise.
func coLocatedDoHPair() (certPEM, keyPEM []byte, ok bool) {
	certPEM, err := os.ReadFile(sharedDoHCertFile)
	if err != nil {
		return nil, nil, false
	}
	keyPEM, err = os.ReadFile(sharedDoHKeyFile)
	if err != nil {
		return nil, nil, false
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, false
	}
	return certPEM, keyPEM, true
}

// refusePlainRemote reports whether plaintext must be fatal: non-loopback,
// no TLS, no explicit ack, and no trusted proxy. A configured proxy means
// client-facing TLS terminates there (Secure cookies + HSTS follow
// X-Forwarded-Proto); backend plaintext over the mgmt LAN only warns.
func refusePlainRemote(listen string, dashboardTLS, allowPlainRemote bool, trustedProxies []string) bool {
	return !dashboardTLS && !allowPlainRemote && !isLoopbackListen(listen) && len(trustedProxies) == 0
}

func isLoopbackListen(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	// Empty host (":8500", "8500") binds ALL interfaces via net.Listen —
	// it must never count as loopback.
	if h == "" {
		return false
	}
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func restoreBlocklistSettings(fleet *controller.Fleet, sources, disabled []string, updateHours int) {
	if len(sources) > 0 {
		fleet.SetBlocklistDisabled(disabled)
		fleet.SetBlocklistSourcesDefault(sources)
	}
	if updateHours > 0 {
		// Default variant: persisting here would saveConfig with a
		// still-empty fleet (Adds run later) and wipe the instances.
		fleet.SetAutoUpdateHoursDefault(updateHours)
	}
}

func load(path string) (*config, error) {
	c := &config{Listen: "127.0.0.1:8500"}
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

// Command blipd is the fast DNS + DoH resolver with per-client filtering.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/certgen"
	"github.com/twobip/BlipDNS/internal/config"
	"github.com/twobip/BlipDNS/internal/dnsserver"
	"github.com/twobip/BlipDNS/internal/filter"
	"github.com/twobip/BlipDNS/internal/ha"
	"github.com/twobip/BlipDNS/internal/update"
)

// version is the blipd release version, stamped at build time from the repo's
// VERSION file: -ldflags "-X main.version=$(cat VERSION)". It defaults to
// "0.0.0" for local, unstamped builds.
var version = "0.0.0"

// reportedVersion exposes the release version to the management API.
func reportedVersion() string {
	return "blipd/" + version
}

// blocklistSources merges the legacy single URL with the new plural list.
func blocklistSources(cfg *config.Config) []string {
	if len(cfg.BlocklistURLs) > 0 {
		return cfg.BlocklistURLs
	}
	if cfg.BlocklistURL != "" {
		return []string{cfg.BlocklistURL}
	}
	return nil
}

func main() {
	cfgPath := flag.String("config", "", "path to YAML config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("blipd: %v", err)
	}
	config.WarnConfigPerms("blipd", *cfgPath)
	warnPlainHTTP("blipd", "management API", cfg.AdminAddr)

	store := filter.NewStore(cfg.Default)
	for _, p := range cfg.Policies {
		if err := store.SetPolicy(p); err != nil {
			log.Fatalf("blipd: policy %q: %v", p.ID, err)
		}
	}

	bl := blocklist.New()
	// Restore the last persisted list into RAM first, so a restart blocks
	// immediately; the sources (if any) overwrite it with fresh data.
	if cfg.BlocklistCacheFile != "" {
		if cached, err := blocklist.LoadCache(cfg.BlocklistCacheFile); err != nil {
			log.Printf("blipd: blocklist cache: %v", err)
		} else if cached != nil && cached.Count() > 0 {
			bl = cached
			log.Printf("blipd: restored %d blocklist domains from cache", cached.Count())
		}
	}
	if urls := blocklistSources(cfg); len(urls) > 0 {
		load := func(ctx context.Context) error {
			res, err := bl.LoadFromURLs(ctx, urls, nil)
			if err != nil {
				return err
			}
			log.Printf("blipd: blocklist loaded (%d domains)", res.Domains)
			if cfg.BlocklistCacheFile != "" {
				_ = bl.SaveCache(cfg.BlocklistCacheFile)
			}
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := load(ctx); err != nil {
			log.Printf("blipd: blocklist load: %v (continuing without blocklist)", err)
		} else if cfg.BlocklistUpdateHours > 0 {
			go func() {
				ticker := time.NewTicker(time.Duration(cfg.BlocklistUpdateHours) * time.Hour)
				defer ticker.Stop()
				for range ticker.C {
					log.Printf("blipd: refreshing blocklist from %d sources", len(urls))
					if err := load(context.Background()); err != nil {
						log.Printf("blipd: blocklist refresh: %v", err)
					}
				}
			}()
		}
	}

	// The global blocklist uses the default policy's block action so operators
	// can choose 0.0.0.0 (zero) instead of NXDOMAIN for blocked domains.
	blockAction := filter.DefaultAction
	if cfg.Default != nil && cfg.Default.BlockAction != "" {
		blockAction = cfg.Default.BlockAction
	}

	// Materialise the TLS material for DoH. When doh_tls is enabled and no
	// explicit cert/key files are given, blipd generates a self-signed cert
	// (persisted under tls_dir so the fingerprint is stable across restarts).
	var tlsCert *tls.Certificate
	if cfg.DoHTLS {
		if cfg.CertFile != "" && cfg.KeyFile != "" {
			pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				log.Fatalf("blipd: load tls cert/key: %v", err)
			}
			tlsCert = &pair
		} else {
			certPath := filepath.Join(cfg.TLSDir, "doh-cert.pem")
			keyPath := filepath.Join(cfg.TLSDir, "doh-key.pem")
			certPEM, keyPEM, persisted, err := certgen.EnsureFiles(certPath, keyPath)
			if err != nil {
				log.Printf("blipd: self-signed DoH cert: %v (serving with in-memory cert this session)", err)
			} else if !persisted {
				log.Printf("blipd: TLS cert dir %s not writable; DoH cert is in-memory only", cfg.TLSDir)
			}
			pair, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				log.Fatalf("blipd: build self-signed cert: %v", err)
			}
			tlsCert = &pair
			if persisted {
				log.Printf("blipd: DoH serving HTTPS with certificate %s", certPath)
			}
		}
	}

	srv, err := dnsserver.New(dnsserver.Config{
		DNSAddr:           cfg.DNSAddr,
		DoHAddr:           cfg.DoHAddr,
		CertFile:          cfg.CertFile,
		KeyFile:           cfg.KeyFile,
		DoHTLS:            cfg.DoHTLS,
		DoHHTTPAddr:       cfg.DoHHTTPAddr,
		RateLimitQPS:      cfg.RateLimitQPS,
		RateLimitBurst:    cfg.RateLimitBurst,
		TLSCert:           tlsCert,
		Upstream:          cfg.Upstream,
		UpstreamServers:   cfg.UpstreamServers,
		UpstreamRoutes:    cfg.UpstreamRoutes,
		UpstreamBootstrap: cfg.UpstreamBootstrap,
		CacheCap:          cfg.CacheCap,
		CacheSize:         cfg.CacheSize,
		CacheWarmCount:    cfg.CacheWarmCount,
		CacheWarmAhead:    cfg.CacheWarmAhead,
		CacheWarmInterval: cfg.CacheWarmInterval,
		CacheRegular:      cfg.CacheRegular,
		Store:             store,
		Version:           reportedVersion(),
		Blocklist:         bl,
		BlockAction:       blockAction,
		TrustedProxies:    cfg.TrustedProxies,
	})
	if err != nil {
		log.Fatalf("blipd: %v", err)
	}

	srv.SetBlockLogger(func(client, domain string) {
		log.Printf("[block] %s -> %s", client, domain)
	})
	// The HA manager owns only the local keepalived configuration and is
	// reachable through the authenticated management API.
	haMgr := ha.NewManagerWithState("", cfg.StateFile)
	srv.ControlServer().SetHAController(haMgr)
	upMgr := update.NewManager()
	srv.ControlServer().SetUpdateController(upMgr)
	haMgr.SetUpdateController(upMgr)

	// Admin / management API.
	if cfg.AdminToken != "" || cfg.StateFile != "" {
		srv.SetMgmtToken(cfg.AdminToken)
		srv.ControlServer().ConfigureAdoption(cfg.StateFile, cfg.InstanceID)
		if cfg.BlocklistCacheFile != "" {
			srv.ControlServer().SetBlocklistCache(cfg.BlocklistCacheFile)
		}
		go func() {
			admin := &http.Server{
				Addr:    cfg.AdminAddr,
				Handler: srv.ControlServer().Handler(),
				// The controller ships the blocklist over this API as a single
				// multi-tens-of-MB JSON body (it caps at 2 GiB server-side).
				// A 30s Read/WriteTimeout cuts such an upload off on any link
				// slower than ~3 MB/s, which makes the controller retry the
				// whole list every poll and burn bandwidth/CPU forever. Use a
				// generous deadline (matching the controller's 10-minute
				// SetBlocklist client) and keep a short header timeout for
				// slowloris protection.
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       10 * time.Minute,
				WriteTimeout:      10 * time.Minute,
				IdleTimeout:       60 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}
			log.Printf("blipd: management API on %s", cfg.AdminAddr)
			if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("blipd: admin server: %v", err)
			}
		}()
	}

	if len(cfg.UpstreamServers) > 0 {
		log.Printf("blipd: upstream pool = %d servers, %d routes", len(cfg.UpstreamServers), len(cfg.UpstreamRoutes))
	} else {
		log.Printf("blipd: DNS on %s, DoH on %s (%s), upstream=%s", cfg.DNSAddr, cfg.DoHAddr, dohScheme(cfg), cfg.Upstream)
	}
	if cfg.DoHHTTPAddr != "" {
		log.Printf("blipd: also accepting plain-HTTP DoH on %s", cfg.DoHHTTPAddr)
	}

	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("blipd: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("blipd: shutting down")
	srv.Shutdown()
}

func dohScheme(cfg *config.Config) string {
	if cfg.DoHTLS {
		return "https"
	}
	return "http"
}

// warnPlainHTTP logs when a credential-bearing HTTP listener binds beyond
// loopback without TLS (bearer tokens cross the wire in cleartext there).
func warnPlainHTTP(prog, what, addr string) {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	if h == "" || h == "127.0.0.1" || h == "::1" || h == "localhost" {
		return
	}
	log.Printf("%s: WARNING: %s on %s is plain HTTP on a non-loopback address; bearer tokens are sniffable. Terminate TLS in front of it.", prog, what, addr)
}

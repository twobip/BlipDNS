// Command blipd is the fast DNS + DoH resolver with per-client filtering.
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

	"github.com/twobip/BlipDNS/internal/blocklist"
	"github.com/twobip/BlipDNS/internal/config"
	"github.com/twobip/BlipDNS/internal/dnsserver"
	"github.com/twobip/BlipDNS/internal/filter"
)

const version = "blipd/0.1.0"

func main() {
	cfgPath := flag.String("config", "", "path to YAML config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("blipd: %v", err)
	}

	store := filter.NewStore(cfg.Default)
	for _, p := range cfg.Policies {
		if err := store.SetPolicy(p); err != nil {
			log.Fatalf("blipd: policy %q: %v", p.ID, err)
		}
	}

	bl := blocklist.New()
	if cfg.BlocklistURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := bl.LoadFromURL(ctx, cfg.BlocklistURL); err != nil {
			log.Printf("blipd: blocklist load %s: %v (continuing without blocklist)", cfg.BlocklistURL, err)
		} else {
			log.Printf("blipd: blocklist loaded from %s (%d domains)", cfg.BlocklistURL, len(bl.List()))
			if cfg.BlocklistUpdateHours > 0 {
				go func() {
					ticker := time.NewTicker(time.Duration(cfg.BlocklistUpdateHours) * time.Hour)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							log.Printf("blipd: refreshing blocklist from %s", cfg.BlocklistURL)
							if err := bl.LoadFromURL(context.Background(), cfg.BlocklistURL); err != nil {
								log.Printf("blipd: blocklist refresh: %v", err)
							} else {
								log.Printf("blipd: blocklist refreshed (%d domains)", len(bl.List()))
							}
						}
					}
				}()
			}
		}
	}

	srv, err := dnsserver.New(dnsserver.Config{
		DNSAddr:    cfg.DNSAddr,
		DoHAddr:    cfg.DoHAddr,
		CertFile:   cfg.CertFile,
		KeyFile:    cfg.KeyFile,
		Upstream:   cfg.Upstream,
		CacheCap:   cfg.CacheCap,
		Store:      store,
		Version:    version,
		Blocklist:  bl,
	})
	if err != nil {
		log.Fatalf("blipd: %v", err)
	}

	srv.SetBlockLogger(func(client, domain string) {
		log.Printf("[block] %s -> %s", client, domain)
	})

	// Admin / management API.
	if cfg.AdminToken != "" || cfg.StateFile != "" {
		if cfg.AdminToken == "" && cfg.StateFile == "" {
			cfg.AdminToken = "" // let ConfigureAdoption generate an ephemeral token
		}
		srv.SetMgmtToken(cfg.AdminToken)
		srv.ControlServer().ConfigureAdoption(cfg.StateFile, cfg.InstanceID)
		go func() {
			admin := &http.Server{Addr: cfg.AdminAddr, Handler: srv.ControlServer().Handler()}
			log.Printf("blipd: management API on %s", cfg.AdminAddr)
			if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("blipd: admin server: %v", err)
			}
		}()
	}

	log.Printf("blipd: DNS on %s, DoH on %s, upstream=%s", cfg.DNSAddr, cfg.DoHAddr, cfg.Upstream)

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
	_ = context.Background()
}

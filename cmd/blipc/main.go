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
	Listen        string                      `yaml:"listen"`
	Username      string                      `yaml:"username"`
	Password      string                      `yaml:"password"`
	DefaultPolicy *control.Policy             `yaml:"default_policy"`
	Instances     []controller.InstanceConfig `yaml:"instances"`
}

func main() {
	cfgPath := flag.String("config", "/etc/blipc/blipc.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := load(*cfgPath)
	if err != nil {
		log.Fatalf("blipc: %v", err)
	}
	if cfg.Username == "" {
		cfg.Username = os.Getenv("BLIPC_USER")
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv("BLIPC_PASS")
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:8500"
	}

	fleet := controller.NewFleet(*cfgPath)
	if cfg.DefaultPolicy != nil {
		fleet.SetDefault(cfg.DefaultPolicy)
	}
	ctx := context.Background()
	for _, ic := range cfg.Instances {
		ic = controller.ResolveTokenFile(ic)
		if err := fleet.Add(ctx, ic); err != nil {
			log.Printf("blipc: instance %s: %v", ic.ID, err)
		}
	}

	srv := controller.NewServer(cfg.Username, cfg.Password, fleet, controller.UI())
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

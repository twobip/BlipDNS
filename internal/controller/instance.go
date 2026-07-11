package controller

import (
	"context"
	"sync"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

// InstanceStatus is a point-in-time view of an instance.
type InstanceStatus struct {
	ID             string                  `json:"id"`
	Label          string                  `json:"label"`
	URL            string                  `json:"url"`
	Online         bool                    `json:"online"`
	Adopted        bool                    `json:"adopted"`
	Health         *control.HealthResponse `json:"health,omitempty"`
	Stats          *control.StatsResponse  `json:"stats,omitempty"`
	LastOK         time.Time               `json:"last_ok"`
	Err            string                  `json:"error,omitempty"`
}

// Instance is a managed blipd with background poll + watch loops.
type Instance struct {
	Config    InstanceConfig
	client    *control.Client
	fleet     *Fleet
	claimCode string // optional code the controller was pre-seeded with

	mu     sync.RWMutex
	online bool
	health *control.HealthResponse
	stats  *control.StatsResponse
	last   time.Time
	err    string

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// pollInterval is how often the controller polls an instance's health/stats.
// Overridable in tests.
var pollInterval = 5 * time.Second

func (i *Instance) start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	i.cancel = cancel

	// periodic health/stats poll (independent of SSE watch)
	i.wg.Add(1)
	go func() {
		defer i.wg.Done()
		t := time.NewTicker(pollInterval)
		defer t.Stop()
		i.poll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				i.poll(ctx)
			}
		}
	}()

	// SSE watch for live block/event stream
	i.wg.Add(1)
	go func() {
		defer i.wg.Done()
		i.watch(ctx)
	}()
}

func (i *Instance) stop() {
	if i.cancel != nil {
		i.cancel()
	}
	i.wg.Wait()
}

func (i *Instance) ctl() *control.Client {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.client
}

func (i *Instance) poll(ctx context.Context) {
	c := i.ctl()
	h, herr := c.Health(ctx)
	s, serr := c.Stats(ctx)
	i.mu.Lock()
	if herr == nil {
		i.online = true
		i.health = h
		i.last = i.fleet.now()
		i.err = ""
	} else {
		i.online = false
		i.err = herr.Error()
	}
	if serr == nil {
		i.stats = s
	}
	i.mu.Unlock()
	if herr == nil {
		i.fleet.bus.Publish(Event{
			InstanceID: i.Config.ID, Instance: i.Config.Label,
			Type: "health", At: i.fleet.now(), Health: h, Stats: s,
		})
	}
}

func (i *Instance) watch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		err := i.ctl().Watch(ctx, func(e control.WatchEvent) {
			i.fleet.bus.Publish(Event{
				InstanceID: i.Config.ID,
				Instance:   i.Config.Label,
				Type:       e.Type,
				At:         e.At,
				Stats:      e.Stats,
				Client:     e.Client,
				Domain:     e.Domain,
			})
		})
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func (i *Instance) status() *InstanceStatus {
	i.mu.RLock()
	defer i.mu.RUnlock()
	st := &InstanceStatus{
		ID:     i.Config.ID,
		Label:  i.Config.Label,
		URL:    i.Config.URL,
		Online: i.online,
		Health: i.health,
		Stats:  i.stats,
		LastOK: i.last,
		Err:    i.err,
	}
	if ad, err := i.ctl().AdoptStatus(context.Background()); err == nil {
		st.Adopted = ad.Adopted
	}
	return st
}

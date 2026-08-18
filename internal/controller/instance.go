package controller

import (
	"context"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

// InstanceStatus is a point-in-time view of an instance.
type InstanceStatus struct {
	ID              string                  `json:"id"`
	Label           string                  `json:"label"`
	URL             string                  `json:"url"`
	Online          bool                    `json:"online"`
	Adopted         bool                    `json:"adopted"`
	ConfigSynced    bool                    `json:"config_synced"`
	BlocklistSynced bool                    `json:"blocklist_synced"`
	Health          *control.HealthResponse `json:"health,omitempty"`
	Stats           *control.StatsResponse  `json:"stats,omitempty"`
	LastOK          time.Time               `json:"last_ok"`
	Err             string                  `json:"error,omitempty"`
	PingAvgMs       float64                 `json:"ping_avg_ms"`
	PingLastMs      float64                 `json:"ping_last_ms"`
	PingSamples     int                     `json:"ping_samples"`
	UpdateAvailable bool                    `json:"update_available"`
	LatestVersion   string                  `json:"latest_version,omitempty"`
}

// Instance is a managed blipd with background poll + watch loops.
type Instance struct {
	Config    InstanceConfig
	client    *control.Client
	fleet     *Fleet
	claimCode string // optional code the controller was pre-seeded with

	mu          sync.RWMutex
	online      bool
	health      *control.HealthResponse
	stats       *control.StatsResponse
	last        time.Time
	err         string
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	pingSamples int
	pingSumMs   float64
	pingAvgMs   float64
	pingLastMs  float64
	appliedHash string // hash of the effective config last successfully applied
	lastUpstr   string // default upstream the instance last reported (for drift detection)
	blHash      uint64 // checksum of the blocklist last successfully pushed
	haHash      string // hash of the HA config last successfully applied

	blPushing    bool      // a blocklist push is in flight
	blRetryAfter time.Time // earliest time a failed blocklist push may be retried
	blForeign    bool      // a non-fleet writer changed the instance's list since our last push
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
		defer recoverLog("instance poll")
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
		defer recoverLog("instance watch")
		i.watch(ctx)
	}()
}

func (i *Instance) stop() {
	if i.cancel != nil {
		i.cancel()
	}
	i.wg.Wait()
}

// recoverLog logs any panic from a background goroutine with a full stack trace
// instead of letting it kill the whole process. blipc restarting silently is a
// plausible cause of repeated blocklist re-imports, so a crash must never go
// unobserved.
func recoverLog(label string) {
	if r := recover(); r != nil {
		log.Printf("blipc: PANIC in %s: %v\n%s", label, r, string(debug.Stack()))
	}
}

func (i *Instance) ctl() *control.Client {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.client
}

// hasToken reports whether the instance has an admin token (i.e. adopted).
func (i *Instance) hasToken() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.Config.Token != ""
}

// configApplied reports whether the instance has applied the config with the
// given hash (empty hash means no config has ever been pushed).
func (i *Instance) configApplied(hash string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.appliedHash == hash
}

// markConfigAppliedWith records the applied config and the upstream it
// carries, so the synced indicator flips immediately after a push instead of
// waiting for the next poll to observe it.
func (i *Instance) markConfigAppliedWith(hash, upstr string) {
	i.mu.Lock()
	i.appliedHash = hash
	i.lastUpstr = upstr
	i.mu.Unlock()
}

func (i *Instance) haConfigApplied(hash string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.haHash == hash
}

func (i *Instance) markHAApplied(hash string) {
	i.mu.Lock()
	i.haHash = hash
	i.mu.Unlock()
}

// blocklistApplied reports whether the instance has the blocklist with the
// given checksum (empty checksum means none has ever been pushed).
func (i *Instance) blocklistApplied(hash uint64) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.blHash == hash
}

// pushedBlocklistHash returns the checksum of the list this controller last
// pushed successfully (0 when none).
func (i *Instance) pushedBlocklistHash() uint64 {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.blHash
}

// foreignBlocklistDetected claims (once) that the instance's list no longer
// matches what this controller pushed, i.e. some other writer changed it. It
// reports false until the controller pushes successfully again, so the
// resulting warning is logged once per foreign-write episode instead of on
// every poll.
func (i *Instance) foreignBlocklistDetected() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.blForeign {
		return false
	}
	i.blForeign = true
	return true
}

// reportedBlocklistHash returns the blocklist checksum the instance reported
// in its latest stats (0 when unknown).
func reportedBlocklistHash(s *control.StatsResponse) uint64 {
	if s == nil {
		return 0
	}
	return s.BlocklistHash
}

// markBlocklistApplied records the checksum of the blocklist just pushed.
func (i *Instance) markBlocklistApplied(hash uint64) {
	i.mu.Lock()
	i.blHash = hash
	i.mu.Unlock()
}

// blocklistPushBackoff is how long the poll loop waits before retrying a
// failed blocklist push. Without it, a push that keeps failing (e.g. the
// instance is unreachable, or the management API rejects the payload) would be
// re-uploaded wholesale every poll interval, burning bandwidth and CPU for
// nothing — the exact symptom of a large list getting cut off by the peer's
// request timeout.
const blocklistPushBackoff = 60 * time.Second

// tryBeginBlocklistPush claims the blocklist push slot, reporting false when a
// push is already in flight or the previous attempt failed within the backoff
// window. Concurrent reconcilers (the poll loop and the import path) can both
// reach SetBlocklist, so this keeps full-list uploads from piling up.
func (i *Instance) tryBeginBlocklistPush(now time.Time) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.blPushing || now.Before(i.blRetryAfter) {
		return false
	}
	i.blPushing = true
	return true
}

// finishBlocklistPush releases the push slot and records the outcome. A
// failure arms the retry cooldown so the next poll doesn't immediately re-send
// the whole list; a success clears it and records the applied checksum.
func (i *Instance) finishBlocklistPush(err error, hash uint64) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.blPushing = false
	if err != nil {
		i.blRetryAfter = i.fleet.now().Add(blocklistPushBackoff)
		return
	}
	i.blRetryAfter = time.Time{}
	i.blHash = hash
	i.blForeign = false
}

func (i *Instance) poll(ctx context.Context) {
	c := i.ctl()
	start := time.Now()
	h, herr := c.Health(ctx)
	s, serr := c.Stats(ctx)
	latencyMs := float64(time.Since(start).Milliseconds())

	if herr != nil && ctx.Err() == nil {
		log.Printf("blipc: poll instance=%s health error: %v", i.Config.ID, herr)
	}
	if serr != nil && ctx.Err() == nil {
		log.Printf("blipc: poll instance=%s stats error: %v", i.Config.ID, serr)
	}
	if d := time.Since(start); d > time.Second && ctx.Err() == nil {
		log.Printf("blipc: poll instance=%s slow: %s (health=%v stats=%v)", i.Config.ID, d.Round(time.Millisecond), herr, serr)
	}

	i.mu.Lock()
	if herr == nil {
		i.online = true
		i.health = h
		i.last = i.fleet.now()
		i.err = ""
		// Update ping stats
		i.pingSamples++
		i.pingSumMs += latencyMs
		i.pingAvgMs = i.pingSumMs / float64(i.pingSamples)
		i.pingLastMs = latencyMs
	} else {
		i.online = false
		i.err = herr.Error()
	}
	if serr == nil {
		i.stats = s
		i.lastUpstr = s.Upstream
		// Persist cumulative counters so the dashboard statistics survive
		// restarts of blipd or blipc (deltas are computed at query time).
		if i.fleet.queryLog != nil {
			_ = i.fleet.queryLog.AddStatsSample(ctx, StatsSample{
				Timestamp: time.Now(),
				Instance:  i.Config.ID,
				Queries:   s.QueriesTotal,
				Blocked:   s.BlockedTotal,
				Errors:    s.UpstreamErr,
			})
		}
	}
	i.mu.Unlock()
	if herr == nil {
		// The bus event carries stats to the browser via SSE. PerClient
		// (which grows with every unique client IP) is not needed in the
		// live event stream — it's only consumed by the /api/stats
		// endpoint — so nil it out to keep SSE payloads small. Use a
		// shallow copy so convergence checks below still see the full map.
		statsForEvent := s
		if statsForEvent != nil {
			statsForEvent = &control.StatsResponse{}
			*statsForEvent = *s
			statsForEvent.PerClient = nil
		}
		i.fleet.bus.Publish(Event{
			InstanceID: i.Config.ID, Instance: i.Config.Label,
			Type: "health", At: i.fleet.now(), Health: h, Stats: statsForEvent,
		})
		// Converge the instance to the fleet default config if it is behind
		// (newly added/adopted, restarted, or reverted to its own config).
		i.fleet.maybePushConfig(ctx, i, s)
		// Converge the optional plain-HTTP DoH listener the same way.
		i.fleet.maybePushDoH(ctx, i, s)
		// Converge the per-client DNS rate limit the same way.
		i.fleet.maybePushRateLimit(ctx, i, s)
		// Converge the response cache config (size / auto-refresh) the same way.
		i.fleet.maybePushCache(ctx, i, s)
		// Converge the upstream pool + routes the same way.
		i.fleet.maybePushUpstream(ctx, i, s)
		// Converge the instance's global blocklist the same way.
		i.fleet.maybePushBlocklist(ctx, i, s)
		// Converge the instance's local DNS records the same way.
		i.fleet.maybePushRecords(ctx, i, s)
		// Converge the HA/keepalived config the same way: retry a previously
		// failed keepalived reload so a transient sudoers issue or update-
		// time priority degradation is corrected automatically.
		i.fleet.maybePushHA(ctx, i)
		// Also log to query log
		if i.fleet.queryLog != nil && s != nil {
			_ = i.fleet.queryLog.Insert(ctx, QueryLogEntry{
				Timestamp: time.Now(),
				Instance:  i.Config.Label,
				Client:    "controller",
				Domain:    "health_check",
				Action:    "POLL",
				Upstream:  "",
			})
		}
	}
}

func (i *Instance) watch(ctx context.Context) {
	reconnects := 0
	lastLog := time.Time{}
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
				Msg:        e.Msg,
				QType:      e.QType,
				IPs:        e.IPs,
				Answers:    toAnswers(e.Answers),
				Cached:     e.Cached,
				Upstream:   e.Upstream,
				DurationUs: e.DurationUs,
			})
			// Also log block/pass events to query log (async, batched so the
			// watch stream can't be bottlenecked by per-row SQLite writes).
			if (e.Type == "block" || e.Type == "pass") && i.fleet.queryLog != nil {
				blockList := ""
				if e.Type == "block" {
					blockList = i.fleet.resolveBlockList(ctx, e.BlockList, e.Domain)
				}
				i.fleet.queryLog.Enqueue(QueryLogEntry{
					Timestamp:  e.At,
					Instance:   i.Config.Label,
					Client:     e.Client,
					Domain:     e.Domain,
					Action:     strings.ToUpper(e.Type), // "BLOCK" or "PASS"
					QType:      e.QType,
					Upstream:   e.Upstream,
					BlockList:  blockList,
					IPs:        e.IPs,
					Answers:    toAnswers(e.Answers),
					DurationUs: e.DurationUs,
					Cached:     e.Cached,
				})
			}
			// Upstream failures are persisted individually for the errors page.
			if e.Type == "error" && i.fleet.queryLog != nil {
				_ = i.fleet.queryLog.RecordUpstreamError(ctx, UpstreamError{
					Timestamp: e.At,
					Instance:  i.Config.Label,
					Domain:    e.Domain,
					Message:   e.Msg,
				})
			}
		})
		// Watch returns nil on a clean EOF (the instance closed the stream).
		// Reconnecting immediately on EOF with no delay would busy-loop at
		// 100% CPU when the stream drops quickly, so every reconnect — error
		// or not — waits at least a second.
		if time.Since(lastLog) > 15*time.Second || reconnects%50 == 0 {
			log.Printf("blipc: watch reconnect instance=%s count=%d err=%v", i.Config.ID, reconnects, err)
			lastLog = time.Now()
		}
		reconnects++
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// toAnswers converts the []control.Answer carried by a WatchEvent into the
// controller package's own Answer type for storage. The two types are
// structurally identical; this avoids importing control from querylog.go.
func toAnswers(in []control.Answer) []Answer {
	if len(in) == 0 {
		return nil
	}
	out := make([]Answer, len(in))
	for i, a := range in {
		out[i] = Answer{Type: a.Type, Data: a.Data, TTL: a.TTL}
	}
	return out
}

func (i *Instance) status() *InstanceStatus {
	i.mu.RLock()
	st := &InstanceStatus{
		ID:          i.Config.ID,
		Label:       i.Config.Label,
		URL:         i.Config.URL,
		Online:      i.online,
		Health:      i.health,
		Stats:       i.stats,
		LastOK:      i.last,
		Err:         i.err,
		PingAvgMs:   i.pingAvgMs,
		PingLastMs:  i.pingLastMs,
		PingSamples: i.pingSamples,
	}
	// Compare the node's reported build against the release-channel head so
	// the Instances page can badge it "update available" (and show the target).
	if i.health != nil {
		st.UpdateAvailable = i.fleet.UpdateAvailable(i.health.Version)
		st.LatestVersion = i.fleet.LatestVersion()
	}
	applied := i.appliedHash
	reportedUpstream := i.lastUpstr
	repBlHash := reportedBlocklistHash(i.stats)
	i.mu.RUnlock()
	// Snapshot the fleet's expected config hash and upstream outside the
	// instance lock (they read fleet state) and mark synced when both match.
	if want, ok := i.fleet.wantConfig(i.Config.ID); ok {
		synced := applied == want.hash
		if synced && want.upstream != "" && reportedUpstream != want.upstream {
			synced = false
		}
		st.ConfigSynced = synced
	} else {
		// No fleet policy means the controller has nothing to reconcile. This
		// is a healthy, unmanaged state—not a perpetually pending sync.
		st.ConfigSynced = true
	}
	// Blocklist is synced when the checksum the instance reports matches the
	// fleet's (trust what the instance actually has, not what we pushed).
	st.BlocklistSynced = i.fleet.Blocklist().Checksum() != 0 && i.fleet.Blocklist().Checksum() == repBlHash
	// Adoption state is local (hasToken): reading it here avoids a blocking
	// per-instance network call (10s timeout) that would stall the instances
	// list whenever a node is unreachable. The remote status is fetched
	// separately by the adopt flow (GetAdoptStatus).
	st.Adopted = i.hasToken()
	return st
}

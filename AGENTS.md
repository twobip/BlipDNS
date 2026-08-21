# AGENTS.md — BlipDNS

## What this repo is
- Go 1.25 monorepo (`module github.com/twobip/BlipDNS`), **vendored** (`vendor/`, `go.mod`). No Makefile, no CI workflows.
- Three commands, two daemons:
  - `blipd` (`cmd/blipd`) — resolver: classic DNS (UDP/TCP) + DoH (RFC 8484) + management API.
  - `blipc` (`cmd/blipc`) — controller: web dashboard + fleet manager that pushes policy/blocklist/upstream/rate-limit to `blipd` instances over their management API.
  - `blipctl` (`cmd/blipctl`) — CLI controller that drives fleets of `blipd` instances over their management API using a bearer token.

## Layout worth knowing
- `internal/dnsserver` — unified query path: **filter → cache → upstream**. Owns the rate limiter and both DoH listeners.
- `internal/control` — **shared** types + the `blipd` management API server `control.Server` and the `control.Client` the controller uses. API contract lives here (request/response structs, routes under `/api/v1/*`).
- `internal/controller` — the fleet manager (used by `blipc`): pushes policy/blocklist/DoH-addr/rate-limit/upstream to instances, persists `controller.yaml`.
- `internal/filter` — per-client CIDR policy store (longest-prefix match) + suffix/wildcard domain matching. Allowlist beats blocklist.
- `internal/upstream` — DoH + UDP resolvers with failover (`MultiResolver`). `UpstreamServer.TimeoutSec` controls per-server failover timeout.
- `internal/cache`, `internal/config`, `internal/certgen`, `internal/blocklist`.
- `internal/ha` — keepalived/VRRP config manager for 2-node LAN HA (writes `/var/lib/blipd/keepalived.conf`).
- `internal/controller/querylog.go` — SQLite query log via `modernc.org/sqlite` (CGO-free); per-client activity on the dashboard comes from here, not from in-memory counters.
- `deploy/` — example systemd units, configs, and install/uninstall scripts.
- `scripts/install-*.sh` — one-shot install scripts that clone from GitHub, build, and set up systemd.
- `testing/` — dnsperf input files, security audit reports, and `testing/benchmarks/` (hot-path Go benchmarks). **Gitignored** — local-only, never commit it.

## Commands (memorize these)
```
go build ./...                                   # everything compiles
go build -o bin/blipd ./cmd/blipd && go build -o bin/blipctl ./cmd/blipctl && go build -o bin/blipc ./cmd/blipc
go vet ./...
gofmt -w <file>                                  # only gofmt files you edit
go test ./...
go test ./internal/dnsserver/                   # a single package
go test -bench . -benchmem ./testing/benchmarks/  # hot-path benchmarks (cache Get, MultiResolver)
```
- Required order: **build → vet → test**. `go vet` and `go test` are fast and gate the whole repo.
- `go test` is hermetic for the controller (`internal/controller/*_test.go` spins up an in-process fake `blipd` HTTP API — no live daemon needed).
- `gofmt -l internal/ cmd/` is clean.

## Test quirks / gotchas
- The `TestDnsperf*` tests in `internal/dnsserver` require the external `dnsperf` binary and a **live `blipd` on `:53`**. They `t.Skip` only when `dnsperf` is absent — if the binary is installed but no resolver is listening, they **fail** rather than skip (all 4 fail identically on a clean tree; check the daemon first).
- `bin/`, `/testing/`, `.worktrees/` are gitignored. `*.log` files are gitignored — do not commit them.
- Management API requires a bearer token (`SetMgmtToken`); `blipd` runs `warnConfigPerms` and warns if the config file is group/world readable (it holds tokens).

## Query hot path (performance-sensitive)
`dnsserver.Server.serve` runs per query: filter → blocklist → local records → cache/upstream. Hard-won rules from past optimization passes:
- No mutex-guarded counters or map writes on this path — use `atomic.Uint64` etc. (`control.Counters`, `cache.entry.hits` are all atomics now).
- Don't build `control.WatchEvent` payloads without checking `s.ctrl.HasWatchers()` first: rendering answers allocates per RR and nobody consumes it when no SSE client is connected.
- Cache hits stay on `RLock`; LRU promotion is approximate (every 16th hit, `promoteEvery`). Don't reintroduce an exclusive-lock escalation per hit.
- `MultiResolver.downUntil` is atomic unix-nanos; the healthy fast path takes no lock.
- Verify hot-path changes with `testing/benchmarks/` before/after, not by eyeballing.

## Architecture flow (rate-limit feature, as a worked example)
Runtime config of the per-client DNS QPS limit flows **controller → blipd**:
1. Operator: `PUT /api/settings {"rate_limit_qps": N}` (or per-instance override) in the blipc web UI. blipc persists it to `controller.yaml` and pushes.
2. `control.Client.SetRateLimit` → `PUT /api/v1/ratelimit {qps,burst}`.
3. `blipd` management server (`control.Server`) routes to `control.RateLimitController.SetRateLimit` → `dnsserver.Server.SetRateLimit` → `rateLimiter.set`, resetting buckets.
4. Each query: `dnsserver.Server.serve` calls `rateLimiter.allow(client)` (key = DoH client-id else source IP); REFUSED on excess.
5. `blipd` reports current `rate_limit_qps` in `/api/v1/stats`; the controller reconciles a restarted instance back to its effective value via `maybePushRateLimit`.
When adding runtime-toggled state, always wire it the same way: a control API method on the server, mirrored by `control.Client`, plus controller push + reconcile.

## Architecture flow (upstream timeout, as a worked example)
Per-server failover timeout flows **blipc UI → controller.yaml → blipd**:
1. Operator edits `timeout_sec` (seconds) on an upstream server in the blipc Settings → Upstream Servers panel.
2. `ControlClient.SetUpstream` → `PUT /api/v1/upstream {servers,route}`. The `UpstreamServer.TimeoutSec` field is part of the shared types in `internal/control/types.go`.
3. `blipd` management server routes to `control.UpstreamController.SetUpstream` → `dnsserver.Server.SetUpstream` → rebuilds `upstream.NewPool`, which calls `fromServerSpec(sv.Address, timeoutForServer(sv))`.
4. `timeoutForServer` defaults to 5s when `TimeoutSec == 0`. `NewUDP`/`NewDoH` bake the timeout into their respective client config.
5. At query time, `MultiResolver.Resolve` tries resolvers in priority order; a `Resolve` call that times out (or errors) marks the server down for the 15s cooldown and moves to the next.

## Conventions
- `control.Server` handlers are registered on a mux in `internal/control/server.go`; add routes there, not ad hoc.
- Controller fleet config persists through `Fleet.*` setters (they save+push) — do not mutate `fleet` fields directly; use `SetDoHDefault`/`SetRateLimitQPSDefault` for startup seeding.
- Per-instance overrides (`InstanceOverride`) are sparse diffs over the fleet default; clearing an override is represented by setting the field to its zero/nil value so it falls through to the fleet default.
- `UpstreamServer.TimeoutSec` of 0 means "use the 5 second default" — never set it to 0 to mean "no timeout".

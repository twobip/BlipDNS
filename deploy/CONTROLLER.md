# BlipDNS Controller (`blipc`)

A Unifi-style management console for BlipDNS. It runs as its own service
(co-located or on a separate host) and:

- **discovers & manages** `blipd` instances over their management API
- **aggregates** health, stats and per-client block logs from the whole fleet
- **pushes** filter policy to any instance (via the web UI or API)
- **serves a web dashboard** at `http://<host>:8500/` (session-cookie login)
  showing live instance cards + a streaming block/event feed

## Build

```
go build -o bin/blipc ./cmd/blipc
```

## Run

```
./bin/blipc -config blipc.yaml
```

Config (`/etc/blipc/blipc.yaml`):

```yaml
listen: "127.0.0.1:8500"
# trusted_proxies: ["127.0.0.1/32", "::1/128"]  # required behind a
#   TLS-terminating proxy: without it client IPs show the proxy, session
#   cookies mint without Secure, and CSRF origin checks use the internal host.
# Auth is username/password session auth (HttpOnly + SameSite=Strict cookie,
# Secure when served over TLS directly or behind a trusted proxy sending
# X-Forwarded-Proto: https). First boot uses the one-time setup flow to create
# the administrator account; production uses `password_hash` (bcrypt).
username: "admin"
# password_hash: "$2b$10$..."   # bcrypt hash — use this in production
instances:
  - id: office-dns
    label: "Office"
    url:  "http://10.0.0.5:8444"
    token: "blipd-admin-token"  # the managed instance's admin_token
```

`token` (per instance) may be a literal, `@/path/to/file`, or `/abs/path`
(a file containing the token). Instances can also be added at runtime from
the web UI. If no config is found, blipc starts with zero instances and you
add them via the UI.

## Web UI

Open `http://<host>:8500/` and log in. You'll see:
- an **instances** grid (online/offline, queries, blocked, upstream errors, cache)
- a live **event stream** (block events, policy changes, health) — filterable
  by domain/client
- a **+** button to add a `blipd` instance

The UI is session-gated (HttpOnly + SameSite=Strict cookie, `Secure` over
TLS); without a valid session you are bounced to `/login` (API: `401`).
There is no `?token=` query model — do not put secrets in URLs (they leak via
history, logs and Referer). Programmatic access uses short-lived API keys
(`POST /api/keys` with a session, then `Authorization: Bearer <key>`).

## Adding an instance (one-time claim-code adoption)

A newly installed `blipd` writes a **one-time claim code** to a `0600` file
(e.g. `/var/lib/blipd/adopt-code`). When started interactively (stdout is a
TTY) it also prints the code once to stdout; under systemd stdout is the
journal (`StandardOutput=journal`), so the code is never printed there — the
journal only records that a code was generated, not the code itself. Read the
file box-locally:

```
sudo cat /var/lib/blipd/adopt-code
sudo journalctl -u blipd | grep -i adopt   # shows generation/adopt audit, not the code
```

In the controller web UI, click **+**, enter the instance URL + label, paste
the claim code, and the controller will:

1. call `blipd`'s unauthenticated `POST /api/v1/adopt` with the code,
2. receive the instance's real **admin token** back (never typed by a human),
3. store it and immediately start polling/stats — the instance shows `claimed`.

The code is **one-time**: after adoption it's invalidated and the `adopted`
state is persisted to `state_file` (e.g. `/var/lib/blipd/adopted.json`) so a
reboot doesn't regenerate a code. To re-adopt (e.g. after losing the
controller), call `POST /api/v1/adopt/reset` on `blipd` (requires its current
admin token) to mint a fresh code.

This is the "automatic verify between them, once" bootstrap: no pre-shared
secret is needed to bring a new instance under management, but a rogue host on
the LAN can't hijack it without the box-local code. The code is single-use
(invalidated immediately on success), per-IP rate-limited (5 bad guesses then
5min `429`), and every adopt success/failure is audit-logged server-side
(without logging the code).

CLI equivalent (on the controller host an instance id is enough — the token
is read from the local blipc config, so use sudo; on the blipd host itself
`--socket` needs no token at all):
```
blipctl <id> adopt-status                # is it claimed?
blipctl <id> adopt <CODE>                 # claim it; prints the admin token
sudo blipctl --socket /var/lib/blipd/blipd.sock health   # box-local admin
```

## Controller API (session + API-key gated)

```
# Session: POST /api/login {username,password} -> HttpOnly session cookie.
# Keys:    POST /api/keys (session only) -> {id, secret} expiring bearer key.
GET    /api/instances                 list managed instances
POST   /api/instances                 add instance  {id,label,url,token,claim}
DELETE /api/instances/<id>            remove instance
GET    /api/instances/<id>/policies   list policies on the instance
PUT    /api/instances/<id>/policy      set policy  {id,networks,block,allow,...}
DELETE /api/instances/<id>/policy?id= push delete
GET    /api/instances/<id>/adopt/status  adoption state (unauth)
POST   /api/instances/<id>/adopt         adopt with {code} (one-time bootstrap)
POST   /api/instances/<id>/adopt/reset   reset adoption (requires instance token)
GET    /api/events                    SSE fleet event stream
GET    /api/health                    {instances: {per-instance health}, query_log_dropped}
GET    /api/upstream-errors           grouped upstream failures {total, errors:[{message,domain,instance,count,first_seen,last_seen}]}
```

Browser calls carry the session cookie automatically (same-origin). Scripts use
`Authorization: Bearer <api-key>` (keys are short-lived, scoped `read`/`admin`,
and can never mint more keys). There is no `?token=` model.

Note: read-scoped keys cannot access query history or query-derived
aggregates (`/api/queries`, `/api/clients`, `/api/client-names`, `/api/events`,
`/api/upstream-errors`, `/api/top-domains`, `/api/cache-stats`, `/api/stats`,
per-instance `/query-log`): those stay admin-only and return `403` for read
keys. Health/liveness for read keys lives at `/api/health` and
`/api/instances`.

Note: instance IDs are restricted to `[A-Za-z0-9._-]` (1–64 chars). IDs
created before this restriction that use other characters must be renamed
(delete + re-add under a compliant ID); the API rejects non-conforming IDs
with `400`.

## Management API TLS (`blipd -admin-tls-cert/key`)

When both flags are set `blipd` serves its management API over HTTPS.
The controller dials `https://` instance URLs with the system roots, so a
self-signed management cert must be installed into the system trust first —
otherwise polling fails TLS verification and the instance shows offline.
For isolated/LAN use prefer plain HTTP on a trusted network (the controller
warns on remote cleartext) or co-locate via the local Unix socket.
`control.NewClientWithTLS` / `SetTLSConfig` remain available for custom roots
outside the fleet manager.

## Install as a service

```
# Prefer verifying the installer against the pinned ref before piping to root:
curl -fsSL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/twobip/BlipDNS/master/scripts/install-blipc.sh -o /tmp/install-blipc.sh
# compare sha256 against the published release/tag value (or git show from a clone), inspect, then:
sudo bash /tmp/install-blipc.sh --local   # builds from checkout, installs, enables blipc
sudo systemctl status blipc
```

The unit runs as an unprivileged `blipc` user, hardened
(`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `CAP_NET_BIND_SERVICE`).
`NoNewPrivileges` is deliberately left OFF so the self-updater can elevate to
the root install helper via sudo. Trade-off: leaving it OFF is what allows the
narrow `blipc-install .../blipc.new` / `blipctl.new` sudo rule to work; turning
it ON would break self-updates (the helper could no longer setuid to root) and
is therefore not recommended. The sudo rule stays pinned to the two fixed
staged paths plus `EXPECTED_SHA256` re-verify (fail-closed), so the service
cannot gain arbitrary root file writes.

## Architecture

```
                          ┌─────────────┐
   browser ──HTTP/SS──▶   │   blipc     │  (web UI + API, :8500)
                          │ controller  │
                          └──────┬──────┘
              management API    │   ▲  (poll /api/v1/{health,stats,policies}
              (SSE /watch)      │   │   + PUT /api/v1/policy)
                                 ▼   │
                          ┌─────────────┐
                          │   blipd     │  (DNS + DoH + filtering, :53/:8443)
                          └─────────────┘
```

The controller is the single pane of glass; each `blipd` stays independent
and keeps working if the controller is down.

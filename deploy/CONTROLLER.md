# BlipDNS Controller (`blipc`)

A Unifi-style management console for BlipDNS. It runs as its own service
(co-located or on a separate host) and:

- **discovers & manages** `blipd` instances over their management API
- **aggregates** health, stats and per-client block logs from the whole fleet
- **pushes** filter policy to any instance (via the web UI or API)
- **serves a web dashboard** at `http://<host>:8500/?token=<token>` showing
  live instance cards + a streaming block/event feed

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
listen: "0.0.0.0:8500"
token:  "web-ui-token"          # required to open the UI / call the API
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

Open `http://<host>:8500/?token=<token>`. You'll see:
- an **instances** grid (online/offline, queries, blocked, upstream errors, cache)
- a live **event stream** (block events, policy changes, health) — filterable
  by domain/client
- a **+** button to add a `blipd` instance

The UI is token-gated; without the token you get `401`.

## Adding an instance (one-time claim-code adoption)

A newly installed `blipd` prints a **one-time claim code** to its journal on
first start (and after `adopt/reset`):

```
journalctl -u blipd | grep ADOPTION CODE
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
the LAN can't hijack it without the local-journal code.

CLI equivalent:
```
blipctl http://host:8444 adopt-status        # is it claimed?
blipctl http://host:8444 adopt <CODE>         # claim it; prints the admin token
```

## Controller API (also token-gated)

```
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

Token may be passed as `Authorization: Bearer <token>` or `?token=<token>`.

## Install as a service

```
sudo ./scripts/install-blipc.sh --local   # builds from checkout, installs, enables blipc
sudo systemctl status blipc
```

The unit runs as an unprivileged `blipc` user, hardened
(`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `CAP_NET_BIND_SERVICE`).
`NoNewPrivileges` is deliberately left OFF so the self-updater can elevate to
the root install helper via sudo.

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

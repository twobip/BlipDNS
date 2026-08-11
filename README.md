# BlipDNS

A fast DNS server in Go with **per-client filtering**, **DNS-over-HTTPS (RFC 8484)**,
and a **controller** (`blipctl`) that connects to managed instances and pushes
filter policy to them.

## Layout

```
cmd/blipd     the resolver daemon (classic DNS + DoH + management API)
cmd/blipctl   the controller CLI (connects to managed instances)
internal/
  filter/     per-client CIDR policy store + suffix/wildcard domain matching
  cache/      TTL-aware DNS response cache with singleflight coalescing
  upstream/   DoH + UDP resolvers with failover
  control/    management API server + controller client (shared types)
  dnsserver/  unified UDP/TCP/DoH query path: filter -> cache -> upstream
  config/     YAML configuration loader
testdata/
  mockdns/    tiny DNS server used by the e2e smoke test
```

## Build

```
go build -o bin/blipd ./cmd/blipd
go build -o bin/blipctl ./cmd/blipctl
go build -o bin/blipc ./cmd/blipc
```

## Install (one-liner, requires Go 1.25+)

### Resolver daemon (blipd)

```bash
curl -sL https://raw.githubusercontent.com/twobip/BlipDNS/master/scripts/install-blipd.sh | sudo bash
# or: sudo bash -s stable   # pin to the latest tagged release
```

Installs:
- `blipd` binary → `/usr/local/bin/blipd`
- Default config → `/etc/blipd/blipd.yaml` (chmod 600, **edit `admin_token`!**)
- systemd unit → `/etc/systemd/system/blipd.service`

Then:
```bash
sudo systemctl enable --now blipd
```

### Controller (blipc + blipctl)

```bash
curl -sL https://raw.githubusercontent.com/twobip/BlipDNS/master/scripts/install-blipc.sh | sudo bash
# or: sudo bash -s stable
```

Installs:
- `blipc` (web dashboard) and `blipctl` (CLI) → `/usr/local/bin/`
- Default config → `/etc/blipc/blipc.yaml` (chmod 600, add username/password_hash and instances)
- systemd unit → `/etc/systemd/system/blipc.service`

Then:
```bash
sudo systemctl enable --now blipc
```

Both scripts accept an optional argument: `master` (default), `stable`, or a version tag (e.g. `v1.2.3`). They clone the repo, build from source, and install under `/usr/local/bin` with secure config directories.

## Run blipd

```
./bin/blipd -config config.example.yaml
```

It listens on:
- `dns_addr`    classic DNS over UDP + TCP
- `doh_addr`    DNS-over-HTTPS at `GET/POST /dns-query` (RFC 8484)
- `admin_addr`  management API (token-protected)

The `upstream` field accepts space/comma-separated specs with failover:
- `udp://host:port` (or a bare `ip`/`host:port`; missing port defaults to 53)
- `https://host/dns-query` or `doh://host/dns-query`

Example: `upstream: "https://1.1.1.1/dns-query https://8.8.8.8/dns-query"`

## Per-client filtering

Policies map a **client source IP** (longest-prefix CIDR match) to an allow/block
list. Matching supports exact names, **suffix** (`ads.example.com` matches
`sub.ads.example.com`), and **wildcard** (`*.tracker.net` matches any subdomain
but not `tracker.net`). The allowlist takes precedence over the blocklist.
A `default_policy` applies to clients with no matching network.

`block_action` is one of: `nxdomain` (default), `refused`, `zero`.

## Controller: blipctl

```
blipctl [--token TOKEN] <instance-url> <command> [args]

  health                 show instance health
  stats                  show live stats
  policies               list filter policies
  set-policy <file.yml>  push a policy
  block <cidr> <domain>  add a block policy for a client CIDR
  del-policy <id>        remove a policy
  watch                  stream events (SSE)
```

Example:

```
blipctl --token SECRET http://10.0.0.5:8444 set-policy kids.yaml
blipctl --token SECRET http://10.0.0.5:8444 block 192.168.10.0/24 ads.net
```

## Test

```
go test ./...
```

The `testdata/mockdns` helper plus `config.e2e.yaml` can drive a full
end-to-end smoke test (see the build notes) that exercises the classic DNS
path, the DoH path, and live per-client policy pushes from the controller.
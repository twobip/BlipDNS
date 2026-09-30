# Upgrade notes (post security-audit hardening)

Three one-time manual steps when upgrading from a release before these fixes.
Each failure mode prints an actionable error; nothing here is silent.

## 1. blipd refuses to start: empty `allowed_networks` + wildcard bind

`blipd` now refuses to boot as an open resolver. If your `blipd.yaml` has no
`allowed_networks` (or an empty list) and `dns_addr` is non-loopback, add:

```yaml
allowed_networks: ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
```

Trim to your LANs. Deliberately open resolver instead: set
`open_recursion: true` — see `deploy/blipd.yaml`.

## 2. First self-update fails closed: unknown installed version

The downgrade guard is now fatal on unknown versions, and the old binary has
no `--version` flag and no install stamp. One-time fix per node, either:

- re-run `scripts/install-blipd.sh` / `install-blipc.sh` once (writes the stamp), or
- run one update cycle with `ALLOW_DOWNGRADE=1` (documented escape, then it self-heals).

## 3. Controller refuses pinned-HTTPS-mgmt node after blipd cert regen

Certs no longer embed RFC1918/Docker IPs, so nodes regenerate once on boot.
If blipc TOFU-pinned the old cert (`mgmt_cert_fp`), clear the pin to re-pin;
plain-HTTP-mgmt and explicit-cert nodes are unaffected.

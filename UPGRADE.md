# Upgrade notes (post security-audit hardening)

Three one-time manual steps when upgrading from a release before these fixes.
Each failure mode prints an actionable error; nothing here is silent.

## 1. blipd no longer refuses to start on an empty `allowed_networks` — it warns and defaults closed

`blipd` boots with the safe closed default (loopback + RFC1918 + ULA,
`control.DefaultAllowedNetworks`) when `allowed_networks` is empty on a
non-loopback bind, warning loudly on every start. Serving the world still
needs the explicit `open_recursion: true`. An explicit list is still
recommended (the default covers all private ranges, not just your LANs).

## 2. First self-update fails closed: unknown installed version

The downgrade guard is now fatal on unknown versions, and the old binary has
no `--version` flag and no install stamp. One-time fix per node, either:

- re-run `scripts/install-blipd.sh` / `install-blipc.sh` once (writes the stamp), or
- run one update cycle with `ALLOW_DOWNGRADE=1` (documented escape, then it self-heals).

## 3. Controller refuses pinned-HTTPS-mgmt node after blipd cert regen

Certs no longer embed RFC1918/Docker IPs, so nodes regenerate once on boot.
If blipc TOFU-pinned the old cert (`mgmt_cert_fp`), clear the pin to re-pin;
plain-HTTP-mgmt and explicit-cert nodes are unaffected.

# Upgrade notes (post security-audit hardening)

Four one-time manual steps when upgrading from a release before these fixes.
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

## 3. Root helpers pin PATH (refresh the installed copies)

`blipd-install`, `blipd-keepalived` and `blipc-install` now pin a fixed,
root-owned `PATH` before running any command and use an absolute
`#!/bin/bash` shebang; the installers also set `secure_path` in
`/etc/sudoers.d/blipd-install` / `blipc-install`. Without that pin, a host
whose `/etc/sudoers` has no system-wide `secure_path` lets sudo preserve the
caller's PATH, so a compromised service account could shadow
`ssh-keygen`/`sha256sum`/`systemctl`/`keepalived` and turn the signed-update
gate into arbitrary root execution. Existing nodes keep the old helpers until
they re-run `scripts/install-blipd.sh` / `install-blipc.sh` once (or install
a release that ships the updated helpers). Verify with:

```
sudo grep -n 'secure_path' /etc/sudoers.d/blipd-install /etc/sudoers.d/blipc-install
head -1 /usr/local/sbin/blipd-install /usr/local/sbin/blipd-keepalived /usr/local/sbin/blipc-install
```

## 4. Controller refuses pinned-HTTPS-mgmt node after blipd cert regen

Certs no longer embed RFC1918/Docker IPs, so nodes regenerate once on boot.
If blipc TOFU-pinned the old cert (`mgmt_cert_fp`), clear the pin to re-pin;
plain-HTTP-mgmt and explicit-cert nodes are unaffected. The regenerated cert
no longer names the node's LAN IP, which older controllers additionally
required (SAN check): update blipc alongside blipd — current blipc pins by
fingerprint (exact-cert match) and no longer needs the dialled IP in SANs.

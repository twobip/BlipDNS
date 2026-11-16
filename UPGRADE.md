# Upgrade notes

One-time manual steps when moving a fleet to 0.8.0 from an earlier release.
Each failure mode prints an actionable error; nothing here is silent. Read §1
before refreshing any helper — it gates every other step.

## 1. 0.8.0 is the first signed release; earlier tags cannot be installed or updated onto

Every release before 0.8.0 ships a `SHA256SUMS` with no `SHA256SUMS.sig`. The
installers and both updaters fail closed on a missing signature:

- `install-blipd.sh` / `install-blipc.sh` → `unsigned release, refusing to install`
- `blipd-update` / `blipc-update` → `release vX.Y.Z has no SHA256SUMS.sig`

`stable` resolves through `master/VERSION`, so a refreshed installer pointed at
an older stable version dead-ends. The fix is a signed release, not a node
change. Once 0.8.0 (or later) exists:

1. Re-run `scripts/install-blipd.sh` / `scripts/install-blipc.sh` once per node.
   That is the **only** thing that replaces `/usr/local/sbin/blipd-update`,
   `/usr/local/sbin/blipd-install`, `/usr/local/sbin/blipc-update` and
   `/usr/local/sbin/blipc-install`; a self-update never touches them, so a node
   keeps whatever helpers it was installed with.
2. Then update normally (`blipd update stable`, the dashboard button, or a fleet
   push).

`--install-deps` now installs `openssh-client` (`openssh-clients` on
RHEL/Fedora): `ssh-keygen` is the signature verifier. It is checked where it is
used rather than at script start, so a slim image can bootstrap with
`--install-deps` instead of failing before dependencies are installed.

## 2. First self-update fails closed: unknown installed version

The downgrade guard is fatal on unknown versions, and a binary installed from
0.7.0 or earlier has neither `--version` nor an install stamp. One-time fix per
node, either:

- re-run `scripts/install-blipd.sh` / `install-blipc.sh` once (writes the
  stamp), or
- run one update cycle with `ALLOW_DOWNGRADE=1` (documented escape, then it
  self-heals).

`ALLOW_DOWNGRADE=1` also disables the downgrade check itself, so only use it
while you know the target is the release you expect.

## 3. blipd refuses a cleartext, non-loopback management listener with a static token

`blipd` no longer only warns when `admin_addr` is not loopback and a static
`admin_token` is configured. With no TLS on that listener, the management API
is not opened at all:

```
not starting the management API: admin_addr "0.0.0.0:8444" is not loopback
while a static admin_token is configured and the listener has no TLS ... DNS
and DoH keep serving.
```

DNS and DoH keep serving, so the node looks healthy while `blipc` has lost it —
and the fix cannot be pushed through the API that is down. Before upgrading a
node in that position, pick one:

- `admin_allow_unpinned_remote: true` in `blipd.yaml` (accepts the cleartext
  bearer token), or
- give the listener TLS: startup already reuses the DoH certificate whenever
  `doh_tls: true`, or pass `-admin-tls-cert` / `-admin-tls-key`, or
- bind `admin_addr` to `127.0.0.1` and adopt the node with a claim code.

Nodes on the default `doh_tls: true` already have a certificate, so they are
warned rather than refused.

## 4. A missing `rate_limit_qps` now means 20 QPS, not unlimited

The stock per-client limit is 20 QPS (`config.DefaultRateLimitQPS`). An existing
`blipd.yaml` that never mentions the key picks that default up on upgrade; only
an explicit `rate_limit_qps: 0` means unlimited. A node serving a whole LAN
through one forwarder (dnsmasq, AdGuard, NAT) sees every client as that single
source IP and starts answering `REFUSED` once it passes 20 QPS.

```yaml
rate_limit_qps: 0        # unlimited
# or a limit sized to the site
```

A managed node takes its value from the controller, not its file: `blipc`'s
fleet default is also 20 when `controller.yaml` has no `rate_limit_qps`, so set
it in the dashboard (Settings → rate limit) or as a per-instance override.

## 5. Root helpers pin PATH (refresh the installed copies)

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

## 6. blipd no longer refuses to start on an empty `allowed_networks` — it warns and defaults closed

`blipd` boots with the safe closed default (loopback + RFC1918 + ULA,
`control.DefaultAllowedNetworks`) when `allowed_networks` is empty on a
non-loopback bind, warning loudly on every start. Serving the world still
needs the explicit `open_recursion: true`. An explicit list is still
recommended (the default covers all private ranges, not just your LANs).

Note the default does not include CGNAT (100.64.0.0/10, used by Tailscale), so a
node serving a tailnet must list it explicitly.

## 7. Controller refuses pinned-HTTPS-mgmt node after blipd cert regen

Certs no longer embed RFC1918/Docker IPs, so nodes regenerate once on boot.
If blipc TOFU-pinned the old cert (`mgmt_cert_fp`), clear the pin to re-pin;
plain-HTTP-mgmt and explicit-cert nodes are unaffected. The regenerated cert
no longer names the node's LAN IP, which older controllers additionally
required (SAN check): update blipc alongside blipd — current blipc pins by
fingerprint (exact-cert match) and no longer needs the dialled IP in SANs.

Order matters for a fleet: update `blipc` **first**, then the `blipd` nodes. A
0.7.0-or-older controller talking to a freshly regenerated cert can drop the
node until the pin is cleared.

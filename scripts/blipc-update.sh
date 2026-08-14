#!/usr/bin/env bash
set -euo pipefail

# Unprivileged half of the blipc self-updater. Runs as the 'blipc' service user
# (never root): downloads the pre-built static binary for the chosen release
# channel, verifies its SHA256 checksum, then asks root — via the minimal
# /usr/local/sbin/blipc-install helper — to install and restart. The network
# never runs with root privileges, and no Go toolchain or git is required.

readonly BASE="https://github.com/twobip/BlipDNS/releases/download"
readonly RAW="https://raw.githubusercontent.com/twobip/BlipDNS"

CHANNEL="${1:-stable}"
case "$CHANNEL" in
  stable|master)
    VER="$(curl -fsSL "$RAW/master/VERSION")" \
      || { echo "error: could not read stable VERSION from GitHub" >&2; exit 1; }
    TAG="v$VER" ;;
  dev)
    TAG="dev" ;;
  v*)
    TAG="$CHANNEL" ;;
  *)
    echo "channel must be stable or dev" >&2; exit 1 ;;
esac

WORK="/var/lib/blipc/update"
mkdir -p "$WORK"

echo "phase: downloading ($TAG)"
DL="$(mktemp -d "$WORK/dl.XXXXXX")"
trap 'rm -rf "$DL"' EXIT
curl -fL "$BASE/$TAG/blipc-linux-amd64" -o "$DL/blipc-linux-amd64"
curl -fsSL "$BASE/$TAG/SHA256SUMS" -o "$DL/SHA256SUMS"

echo "phase: verifying"
expected="$(awk '$2=="blipc-linux-amd64" {print $1; exit}' "$DL/SHA256SUMS")"
[ -n "$expected" ] || { echo "error: no checksum entry for blipc-linux-amd64" >&2; exit 1; }
actual="$(sha256sum "$DL/blipc-linux-amd64" | awk '{print $1}')"
[ "$expected" = "$actual" ] || { echo "error: checksum verification failed — refusing to install" >&2; exit 1; }

install -m 0755 "$DL/blipc-linux-amd64" "$WORK/blipc.new"

# Hand the verified (unprivileged) binary to the root install helper.
sudo -n /usr/local/sbin/blipc-install "$WORK/blipc.new"
echo "phase: done"

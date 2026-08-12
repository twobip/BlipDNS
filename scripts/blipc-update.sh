#!/usr/bin/env bash
set -euo pipefail

# Root-owned controller (blipc) updater. Only stable/dev are accepted; the
# branch cannot be supplied as arbitrary shell input by the browser or API.
readonly REPO="https://github.com/twobip/BlipDNS.git"
BRANCH="${1:-stable}"
case "$BRANCH" in
  stable) BRANCH="master" ;;
  dev) BRANCH="dev" ;;
  *) echo "channel must be stable or dev" >&2; exit 1 ;;
esac
readonly BIN="/usr/local/bin/blipc"
readonly PREVIOUS="/usr/local/bin/blipc.previous"

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
# /root may be read-only (containers/LXC); keep Go caches somewhere writable.
CACHE_DIR="/var/cache/blipc-update"
mkdir -p "$CACHE_DIR/gomod" "$CACHE_DIR/gocache" "$CACHE_DIR/gopath"
export GOMODCACHE="$CACHE_DIR/gomod"
export GOCACHE="$CACHE_DIR/gocache"
export GOPATH="$CACHE_DIR/gopath"
tmp="$(mktemp -d /tmp/blipc-update.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

# Persistent clone: clone once, fetch+reset on later runs.
SRC_DIR="$CACHE_DIR/src"
if [ -d "$SRC_DIR/.git" ]; then
  git -C "$SRC_DIR" fetch --depth 1 --quiet origin "$BRANCH"
  git -C "$SRC_DIR" checkout --quiet --detach FETCH_HEAD
  git -C "$SRC_DIR" reset --hard --quiet FETCH_HEAD
else
  git clone --depth 1 --branch "$BRANCH" --quiet "$REPO" "$SRC_DIR"
fi
cd "$SRC_DIR"
echo "phase: cloning"
go build -trimpath -ldflags "-X main.buildSHA=$(git rev-parse HEAD)" -o "$tmp/blipc.new" ./cmd/blipc
echo "phase: built"
install -o root -g root -m 0755 "$tmp/blipc.new" "$tmp/blipc.installed"

if [[ -x "$BIN" ]]; then
  cp -p "$BIN" "$PREVIOUS"
fi
echo "phase: installing"
install -o root -g root -m 0755 "$tmp/blipc.installed" "$BIN"
echo "phase: restarting"
if ! systemctl restart blipc || ! systemctl is-active --quiet blipc; then
  if [[ -x "$PREVIOUS" ]]; then
    install -o root -g root -m 0755 "$PREVIOUS" "$BIN"
    systemctl restart blipc || true
  fi
  echo "blipc restart/health check failed; previous binary restored" >&2
  exit 1
fi
printf '%s\n' "blipc updated from $BRANCH ($(git rev-parse HEAD))"

#!/usr/bin/env bash
set -euo pipefail

# Stable-channel updater. Keep production changes on master; use another branch
# (for example dev) for development. Only stable/dev are accepted; the branch
# cannot be supplied as arbitrary shell input by the browser or API request.
readonly REPO="https://github.com/twobip/BlipDNS.git"
BRANCH="${1:-stable}"
case "$BRANCH" in
  stable) BRANCH="master" ;;
  dev) BRANCH="dev" ;;
  *) echo "channel must be stable or dev" >&2; exit 1 ;;
esac
readonly BIN="/usr/local/bin/blipd"
readonly PREVIOUS="/usr/local/bin/blipd.previous"

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
tmp="$(mktemp -d /tmp/blipd-update.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

git clone --depth 1 --branch "$BRANCH" "$REPO" "$tmp/src"
cd "$tmp/src"
go build -trimpath -o "$tmp/blipd.new" ./cmd/blipd
install -o root -g root -m 0755 "$tmp/blipd.new" "$tmp/blipd.installed"

if [[ -x "$BIN" ]]; then
  cp -p "$BIN" "$PREVIOUS"
fi
install -o root -g root -m 0755 "$tmp/blipd.installed" "$BIN"
if ! systemctl restart blipd || ! systemctl is-active --quiet blipd; then
  if [[ -x "$PREVIOUS" ]]; then
    install -o root -g root -m 0755 "$PREVIOUS" "$BIN"
    systemctl restart blipd || true
  fi
  echo "blipd restart/health check failed; previous binary restored" >&2
  exit 1
fi
printf '%s\n' "blipd updated from $BRANCH ($(git rev-parse HEAD))"

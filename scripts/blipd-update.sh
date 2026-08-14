#!/usr/bin/env bash
set -euo pipefail

# Unprivileged half of the blipd self-updater. Runs as the 'blip' service user
# (never root): clones the repo and builds blipd, then asks root — via the
# minimal /usr/local/sbin/blipd-install helper — to install and restart. The
# compiler and the network never run with root privileges.
readonly REPO="https://github.com/twobip/BlipDNS.git"
BRANCH="${1:-stable}"
case "$BRANCH" in
  stable) BRANCH="master" ;;
  dev) BRANCH="dev" ;;
  *) echo "channel must be stable or dev" >&2; exit 1 ;;
esac

# All build state lives under /var/lib/blipd — the only path the blip service
# may write. The root-owned /var/cache/blipd-update is deliberately avoided.
# GOTOOLCHAIN is left at its default (auto): the system Go may be older than
# the repo's required version, in which case the matching toolchain is fetched
# into GOMODCACHE (still as blip).
WORK="/var/lib/blipd/update"
mkdir -p "$WORK/gomod" "$WORK/gocache" "$WORK/gopath"
export HOME="$WORK"
export GOMODCACHE="$WORK/gomod"
export GOCACHE="$WORK/gocache"
export GOPATH="$WORK/gopath"

# Persistent clone: clone once, fetch+reset on later runs.
SRC_DIR="$WORK/src"
if [ -d "$SRC_DIR/.git" ]; then
  git -C "$SRC_DIR" fetch --depth 1 --quiet origin "$BRANCH"
  git -C "$SRC_DIR" checkout --quiet --detach FETCH_HEAD
  git -C "$SRC_DIR" reset --hard --quiet FETCH_HEAD
else
  git clone --depth 1 --branch "$BRANCH" --quiet "$REPO" "$SRC_DIR"
fi
cd "$SRC_DIR"
echo "phase: cloning"
go build -v -trimpath -ldflags "-X main.version=$(cat VERSION)" -o "$WORK/blipd.new" ./cmd/blipd
echo "phase: built"
# Hand the freshly built (unprivileged) binary to the root install helper.
sudo -n /usr/local/sbin/blipd-install "$WORK/blipd.new"
echo "phase: done"

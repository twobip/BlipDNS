#!/usr/bin/env bash
set -euo pipefail

# Unprivileged half of the blipc self-updater. Runs as the 'blipc' service user
# (never root): clones the repo and builds blipc, then asks root — via the
# minimal /usr/local/sbin/blipc-install helper — to install and restart. The
# compiler and the network never run with root privileges.
readonly REPO="https://github.com/twobip/BlipDNS.git"
BRANCH="${1:-stable}"
case "$BRANCH" in
  stable) BRANCH="master" ;;
  dev) BRANCH="dev" ;;
  *) echo "channel must be stable or dev" >&2; exit 1 ;;
esac

# All build state lives under /var/lib/blipc — the only path the blipc service
# may write. GOTOOLCHAIN is left at its default (auto): the system Go may be
# older than the repo's required version, in which case the matching toolchain
# is fetched into GOMODCACHE (still as blipc).
WORK="/var/lib/blipc/update"
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
go build -trimpath -ldflags "-X main.buildSHA=$(git rev-parse HEAD)" -o "$WORK/blipc.new" ./cmd/blipc
echo "phase: built"
# Hand the freshly built (unprivileged) binary to the root install helper.
sudo -n /usr/local/sbin/blipc-install "$WORK/blipc.new"
echo "phase: done"

#!/usr/bin/env bash
#
# install-blipc.sh — install the BlipDNS controller (blipc) and CLI (blipctl)
# and set up a systemd service for blipc.
#
# Usage:  curl -sL https://raw.githubusercontent.com/twobip/BlipDNS/master/scripts/install-blipc.sh | sudo bash
# Optional: append --install-deps to install prerequisites (curl, CA certs) first.
#           append --build-from-source to clone + build instead of downloading release binaries.
#           append --local to build from the current checkout instead of downloading or cloning.
#
set -euo pipefail

REPO="github.com/twobip/BlipDNS"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/blipc}"
STATE_DIR="${STATE_DIR:-/var/lib/blipc}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_NAME="blipc"
SYSTEMD_AVAILABLE=0
BASE_URL="https://github.com/twobip/BlipDNS/releases/download"
RAW_BASE="https://raw.githubusercontent.com/twobip/BlipDNS"

# --- helpers -----------------------------------------------------------------
log()  { echo "[install-blipc] $*"; }
err()  { echo "[install-blipc] ERROR: $*" >&2; exit 1; }

# Remove leftovers from the old clone+build install method (Go caches + the
# persistent clone + telemetry). The download-based updater still stages
# downloads under $STATE_DIR/update, so only that dir's build subdirs are
# removed — never the dir itself, and never the runtime databases or config.
cleanup_old_build() {
  log "cleaning up build leftovers from the old install method"
  # Don't rm -rf the directory itself — it may still be referenced by
  # an existing systemd unit's ReadWritePaths (ProtectSystem=strict
  # makes systemd fail to start the service if a ReadWritePaths path
  # doesn't exist). Clean its contents instead.
  mkdir -p /var/cache/blipc-update
  rm -rf /var/cache/blipc-update/*
  rm -rf "$STATE_DIR/update/src" \
         "$STATE_DIR/update/gomod" \
         "$STATE_DIR/update/gocache" \
         "$STATE_DIR/update/gopath" \
         "$STATE_DIR/update/.config" \
         "$STATE_DIR/update/blipc.new"
  rm -rf "$STATE_DIR/.config/go"
}

usage() {
  cat <<'EOF'
Usage: install-blipc.sh [stable|dev|vX.Y.Z] [--install-deps] [--build-from-source] [--local]

Installs blipc and blipctl from pre-built GitHub release binaries (default) or from source.
  stable|dev|vX.Y.Z  Release channel or explicit version (default: stable)
  --install-deps      Install prerequisites (curl, CA certs; plus Git/Go when building)
  --build-from-source Clone and build from source instead of downloading release binaries
  --local             Build from the current checkout instead of downloading or cloning
EOF
}

# --- arguments ---------------------------------------------------------------
INSTALL_DEPS=0
BUILD_FROM_SOURCE=0
LOCAL=0
INSTALL=""
for ARG in "$@"; do
  case "$ARG" in
    --install-deps)
      INSTALL_DEPS=1
      ;;
    --build-from-source)
      BUILD_FROM_SOURCE=1
      ;;
    --local)
      LOCAL=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -* )
      err "unknown option: $ARG (use --help for usage)"
      ;;
    *)
      [ -z "$INSTALL" ] || err "only one version or branch may be specified"
      INSTALL="$ARG"
      ;;
  esac
done

GO_REQUIRED_VERSION="1.25.0"
GO_INSTALL_DIR="/usr/local/go-blipdns-${GO_REQUIRED_VERSION}"
GO_TMPDIR=""

cleanup_go_tmp() {
  if [ -n "${GO_TMPDIR:-}" ]; then
    rm -rf "$GO_TMPDIR"
    GO_TMPDIR=""
  fi
}

install_dependencies() {
  local packages="ca-certificates curl"
  local go_needed=0
  if [ "$BUILD_FROM_SOURCE" -eq 1 ] || [ "$LOCAL" -eq 1 ]; then
    packages="git ca-certificates curl jq"
    go_needed=1
    if dedicated_go_is_supported || { command -v go >/dev/null 2>&1 && go_is_supported; }; then
      go_needed=0
      log "reusing an existing supported Go installation"
    fi
  fi
  log "installing dependencies: $packages$( [ "$go_needed" -eq 1 ] && echo ' and Go' )"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    if [ "$go_needed" -eq 1 ]; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y $packages golang-go
    else
      DEBIAN_FRONTEND=noninteractive apt-get install -y $packages
    fi
  elif command -v dnf >/dev/null 2>&1; then
    if [ "$go_needed" -eq 1 ]; then
      dnf install -y $packages golang
    else
      dnf install -y $packages
    fi
  elif command -v yum >/dev/null 2>&1; then
    if [ "$go_needed" -eq 1 ]; then
      yum install -y $packages golang
    else
      yum install -y $packages
    fi
  elif command -v apk >/dev/null 2>&1; then
    if [ "$go_needed" -eq 1 ]; then
      apk add --no-cache $packages go
    else
      apk add --no-cache $packages
    fi
  elif command -v pacman >/dev/null 2>&1; then
    if [ "$go_needed" -eq 1 ]; then
      pacman -S --noconfirm $packages go
    else
      pacman -S --noconfirm $packages
    fi
  elif command -v zypper >/dev/null 2>&1; then
    if [ "$go_needed" -eq 1 ]; then
      zypper --non-interactive install $packages go
    else
      zypper --non-interactive install $packages
    fi
  else
    err "--install-deps was requested, but no supported package manager was found"
  fi
}

install_git() {
  if command -v git >/dev/null 2>&1; then
    return
  fi
  log "git is not installed — attempting to install it"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y git
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y git
  elif command -v yum >/dev/null 2>&1; then
    yum install -y git
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache git
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm git
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install git
  else
    err "git is not installed and no supported package manager was found; install Git and run this script again"
  fi
  command -v git >/dev/null 2>&1 || err "Git installation failed; install Git and run this script again"
}

# Return success only when the installed Go version is at least 1.25.
go_version_is_supported() {
  local version major minor
  version="$1"
  [[ "$version" =~ go([0-9]+)\.([0-9]+) ]] || return 1
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 25 ]; }
}

go_is_supported() {
  go_version_is_supported "$(go version 2>/dev/null)"
}

dedicated_go_is_supported() {
  [ -x "$GO_INSTALL_DIR/bin/go" ] || return 1
  go_version_is_supported "$($GO_INSTALL_DIR/bin/go version 2>/dev/null)"
}

use_dedicated_go() {
  export PATH="$GO_INSTALL_DIR/bin:$PATH"
  hash -r
}

install_go_from_archive() {
  local arch archive archive_name metadata expected actual tmp

  # Reuse the dedicated Go installation from a previous run before doing any
  # network work. This is especially important when the distro Go is too old.
  if dedicated_go_is_supported; then
    use_dedicated_go
    if go_is_supported; then
      log "reusing Go installation at $GO_INSTALL_DIR"
      return
    fi
  fi

  case "$(uname -m)" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    armv6l|armv7l) arch="armv6l" ;;
    i386|i686) arch="386" ;;
    ppc64le) arch="ppc64le" ;;
    s390x) arch="s390x" ;;
    riscv64) arch="riscv64" ;;
    loongarch64) arch="loong64" ;;
    *) err "cannot install Go ${GO_REQUIRED_VERSION}: unsupported Linux architecture $(uname -m)" ;;
  esac
  command -v curl >/dev/null 2>&1 || err "curl is required to install Go ${GO_REQUIRED_VERSION}; install curl and run this script again"
  command -v sha256sum >/dev/null 2>&1 || err "sha256sum is required to verify Go; install coreutils and run this script again"

  tmp="$(mktemp -d)"
  GO_TMPDIR="$tmp"
  trap cleanup_go_tmp EXIT
  command -v jq >/dev/null 2>&1 || err "jq is required to verify Go metadata; rerun with --install-deps"
  archive_name="go${GO_REQUIRED_VERSION}.linux-${arch}.tar.gz"
  archive="$tmp/$archive_name"
  metadata="$tmp/go.json"
  log "installing Go ${GO_REQUIRED_VERSION} from the official Go archive"
  if ! curl -fL "https://go.dev/dl/$archive_name" -o "$archive"; then
    err "failed to download Go ${GO_REQUIRED_VERSION} for Linux/$arch"
  fi
  if ! curl -fsSL "https://go.dev/dl/?mode=json&include=all" -o "$metadata"; then
    err "failed to download Go checksum metadata"
  fi
  if ! expected="$(jq -er --arg file "$archive_name" 'first(.[] | .files[]? | select(.filename == $file) | .sha256)' "$metadata")"; then
    err "Go archive checksum metadata was not found"
  fi
  actual="$(sha256sum "$archive" | awk '{print $1}')"
  if [ "$expected" != "$actual" ]; then
    err "Go archive checksum verification failed"
  fi

  rm -rf "$GO_INSTALL_DIR"
  mkdir -p "$GO_INSTALL_DIR"
  if ! tar -xzf "$archive" -C "$GO_INSTALL_DIR" --strip-components=1; then
    rm -rf "$GO_INSTALL_DIR"
    err "failed to extract Go ${GO_REQUIRED_VERSION}"
  fi
  export PATH="$GO_INSTALL_DIR/bin:$PATH"
  hash -r
  cleanup_go_tmp
}

require_go() {
  if dedicated_go_is_supported; then
    use_dedicated_go
  elif ! command -v go >/dev/null 2>&1; then
    if [ "$INSTALL_DEPS" -eq 1 ]; then
      install_go_from_archive
    else
      err "Go is not installed. Install Go 1.25+ first: https://go.dev/dl/ (or rerun with --install-deps)"
    fi
  elif ! go_is_supported; then
    if [ "$INSTALL_DEPS" -eq 1 ]; then
      install_go_from_archive
    else
      err "Go 1.25+ is required; found $(go version 2>/dev/null). Install a newer Go version: https://go.dev/dl/ (or rerun with --install-deps)"
    fi
  fi
  go_is_supported || err "Go ${GO_REQUIRED_VERSION}+ installation failed"
  log "using $(go version)"
}

# --- sanity ------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || err "this script must be run as root (use sudo)"

if [ "$BUILD_FROM_SOURCE" -eq 1 ] || [ "$LOCAL" -eq 1 ]; then
  [ "$INSTALL_DEPS" -eq 1 ] && install_dependencies
  install_git
  require_go
else
  # Download path needs only curl and sha256sum (coreutils) — no Go, no git.
  command -v sha256sum >/dev/null 2>&1 || err "sha256sum (coreutils) is required; install coreutils and rerun"
  if ! command -v curl >/dev/null 2>&1; then
    if [ "$INSTALL_DEPS" -eq 1 ]; then
      install_dependencies
    else
      err "curl is required to download the release binaries; install curl or rerun with --install-deps"
    fi
  fi
fi

# --- resolve release channel / tag ------------------------------------------
if [ -z "$INSTALL" ]; then
  CHANNEL="stable"
else
  CHANNEL="$INSTALL"
fi

case "$CHANNEL" in
  stable|master)
    REF="master"
    TAG="v$(curl -fsSL "$RAW_BASE/master/VERSION" || err "could not read the current stable version from GitHub")" ;;
  dev)
    REF="dev"
    TAG="dev" ;;
  v*)
    REF="$CHANNEL"
    TAG="$CHANNEL" ;;
  *)
    err "unknown release: $CHANNEL (use stable, dev, or vX.Y.Z)" ;;
esac

# --- obtain the binaries (download, clone + build, or local build) -----------
# /root may be read-only (containers/LXC); keep Go caches somewhere writable.
CACHE_DIR="/var/cache/blipc-update"
mkdir -p "$CACHE_DIR/gomod" "$CACHE_DIR/gocache" "$CACHE_DIR/gopath"
export GOMODCACHE="$CACHE_DIR/gomod"
export GOCACHE="$CACHE_DIR/gocache"
export GOPATH="$CACHE_DIR/gopath"

# fetch_verified <tag> <asset> <destfile> — download and SHA256-verify one asset.
fetch_verified() {
  local tag="$1" asset="$2" dest="$3" expected actual
  curl -fL "$BASE_URL/$tag/$asset" -o "$TMPDIR/$asset" || err "download failed: $BASE_URL/$tag/$asset"
  curl -fsSL "$BASE_URL/$tag/SHA256SUMS" -o "$TMPDIR/SHA256SUMS" || err "download failed: SHA256SUMS"
  expected="$(awk -v a="$asset" '$2==a {print $1; exit}' "$TMPDIR/SHA256SUMS")"
  [ -n "$expected" ] || err "no checksum entry for $asset in SHA256SUMS"
  actual="$(sha256sum "$TMPDIR/$asset" | awk '{print $1}')"
  [ "$expected" = "$actual" ] || err "checksum verification FAILED for $asset — refusing to install"
  mv "$TMPDIR/$asset" "$dest"
  rm -f "$TMPDIR/SHA256SUMS"
}

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [ "$LOCAL" -eq 1 ]; then
  SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  [ -f "$SRC_DIR/go.mod" ] || err "--local requires running from inside the BlipDNS repository"
  log "building from local checkout: $SRC_DIR"
  cd "$SRC_DIR"
  log "building blipc and blipctl (first build can take a few minutes — package list below shows progress)"
  go build -v -ldflags "-X github.com/twobip/BlipDNS/internal/controller.version=$(cat VERSION)" -o "$TMPDIR/blipc" ./cmd/blipc
  go build -v -o "$TMPDIR/blipctl" ./cmd/blipctl
elif [ "$BUILD_FROM_SOURCE" -eq 1 ]; then
  SRC_DIR="$TMPDIR/src"
  log "cloning $REPO @ $REF"
  git clone --depth 1 --branch "$REF" \
    "https://${REPO}.git" "$SRC_DIR" || \
    git clone "https://${REPO}.git" "$SRC_DIR"
  cd "$SRC_DIR"
  log "building blipc and blipctl (first build can take a few minutes — package list below shows progress)"
  go build -v -ldflags "-X github.com/twobip/BlipDNS/internal/controller.version=$(cat VERSION)" -o "$TMPDIR/blipc" ./cmd/blipc
  go build -v -o "$TMPDIR/blipctl" ./cmd/blipctl
else
  cleanup_old_build
  log "downloading blipc and blipctl from release $TAG"
  fetch_verified "$TAG" blipc-linux-amd64 "$TMPDIR/blipc"
  fetch_verified "$TAG" blipctl-linux-amd64 "$TMPDIR/blipctl"
  log "checksums verified"
fi

# --- install binaries --------------------------------------------------------
log "installing binaries to $BIN_DIR"
install -m 0755 "$TMPDIR/blipc"   "$BIN_DIR/blipc"
install -m 0755 "$TMPDIR/blipctl" "$BIN_DIR/blipctl"

log "ensuring system user 'blipc'"
if ! id blipc >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin blipc
fi

log "installing controller updater"
if [ "$BUILD_FROM_SOURCE" -eq 1 ] || [ "$LOCAL" -eq 1 ]; then
  install -m 0755 "$SRC_DIR/scripts/blipc-update.sh" /usr/local/sbin/blipc-update
  install -m 0755 "$SRC_DIR/scripts/blipc-install.sh" /usr/local/sbin/blipc-install
else
  curl -fsSL "$RAW_BASE/$REF/scripts/blipc-update.sh" -o /usr/local/sbin/blipc-update \
    || err "failed to fetch blipc-update.sh"
  curl -fsSL "$RAW_BASE/$REF/scripts/blipc-install.sh" -o /usr/local/sbin/blipc-install \
    || err "failed to fetch blipc-install.sh"
  chmod 0755 /usr/local/sbin/blipc-update /usr/local/sbin/blipc-install
fi
# Only the install helper runs as root; the download (blipc-update) runs as blipc.
cat > /etc/sudoers.d/blipc-install <<'EOF'
blipc ALL=(root) NOPASSWD: /usr/local/sbin/blipc-install
EOF
chmod 0440 /etc/sudoers.d/blipc-install
visudo -cf /etc/sudoers.d/blipc-install

# --- config / state dirs -----------------------------------------------------
log "creating config and state directories"
mkdir -p "$CONFIG_DIR" "$STATE_DIR"
chown blipc:blipc "$CONFIG_DIR" "$STATE_DIR"
chmod 700 "$CONFIG_DIR" "$STATE_DIR"

# Create a default config if none exists.
if [ ! -f "$CONFIG_DIR/blipc.yaml" ]; then
  log "writing default config to $CONFIG_DIR/blipc.yaml"
  cat > "$CONFIG_DIR/blipc.yaml" <<'EOF'
# BlipDNS controller configuration
# See: https://github.com/twobip/BlipDNS
listen: "0.0.0.0:8500"
# username / password_hash can also be set via BLIPC_USER / BLIPC_PASS_HASH env vars.
# username: blip
# password_hash: $2b$12$...   # bcrypt hash from: blipctl hash <password>
# instances:
#   - id: "1.2.3.4:8444"
#     label: "living-room"
#     token: "secret-token"
EOF
  chown blipc:blipc "$CONFIG_DIR/blipc.yaml"
  chmod 600 "$CONFIG_DIR/blipc.yaml"
else
  # An existing config may still be root-owned from an older install; the
  # blipc service cannot read that, so it silently starts unconfigured and
  # the setup page appears. Restore ownership so upgrades keep working.
  chown blipc:blipc "$CONFIG_DIR/blipc.yaml"
  chmod 600 "$CONFIG_DIR/blipc.yaml"
fi

# --- systemd service (if systemd is available) --------------------------------
if [ -d "$SYSTEMD_DIR" ] && command -v systemctl >/dev/null 2>&1; then
  SYSTEMD_AVAILABLE=1
  log "installing systemd unit: $SYSTEMD_DIR/$SERVICE_NAME.service"
  cat > "$SYSTEMD_DIR/$SERVICE_NAME.service" <<EOF
[Unit]
Description=BlipDNS Controller - Unifi-style fleet management console
Documentation=https://github.com/twobip/BlipDNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=blipc
Group=blipc
ExecStart=$BIN_DIR/blipc -config $CONFIG_DIR/blipc.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3

AmbientCapabilities=CAP_NET_BIND_SERVICE
# No CapabilityBoundingSet restriction: blipc elevates to the pinned
# /usr/local/sbin/blipc-install helper via sudo (narrow sudoers rule), which
# needs CAP_SETGID/CAP_SETUID available.
# NoNewPrivileges must stay OFF for the same reason.
UMask=0077
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$STATE_DIR $CONFIG_DIR /usr/local/bin
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=blipc

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$SYSTEMD_DIR/$SERVICE_NAME.service"
  log "reloading systemd daemon"
  systemctl daemon-reload || true
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "restarting active $SERVICE_NAME service to use the newly installed binary"
    systemctl restart "$SERVICE_NAME" || err "failed to restart $SERVICE_NAME; run: sudo systemctl restart $SERVICE_NAME"
  else
    log "to start:  sudo systemctl enable --now $SERVICE_NAME"
  fi
  log "if the service does not start: sudo systemctl status $SERVICE_NAME --no-pager"
  log "                         sudo journalctl -u $SERVICE_NAME -n 100 --no-pager"
else
  log "systemd not found — skipping service installation (run 'blipc -config $CONFIG_DIR/blipc.yaml' manually)"
fi

log ""
log "blipc installed successfully."
log ""
"$BIN_DIR/blipctl" 2>/dev/null || true
log "binaries:  $BIN_DIR/blipc      $BIN_DIR/blipctl"
log "config:    $CONFIG_DIR/blipc.yaml"
log "state:     $STATE_DIR"
log ""
log "Next steps:"
if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
  log "  1. Start blipc: sudo systemctl enable --now blipc"
  log "  2. Get the one-time setup URL from the service log:"
  log "     sudo journalctl -u blipc -n 50 --no-pager | grep 'setup'"
else
  log "  1. Start blipc manually: $BIN_DIR/blipc -config $CONFIG_DIR/blipc.yaml"
  log "  2. Copy the one-time setup URL printed by blipc."
fi
log "  3. Open the setup URL in a browser, replacing 0.0.0.0 with this server's IP or hostname if needed."
log "  4. On the setup page, enter a username, an 8–72 character password, and confirm the password."
log "     Click 'Create account'; you will be signed in automatically."
log "  5. Setup is disabled after the account is created; add blipd instances from the web dashboard."
log ""
log "The setup URL contains a one-time token. Keep it private and use the page on a trusted network or over HTTPS."

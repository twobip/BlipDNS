#!/usr/bin/env bash
#
# install-blipc.sh — install the BlipDNS controller (blipc) and CLI (blipctl)
# and set up a systemd service for blipc.
#
# Usage:  curl -sL https://raw.githubusercontent.com/twobip/BlipDNS/master/scripts/install-blipc.sh | sudo bash
# Optional: append --install-deps to install Git, Go, CA certificates, curl, and jq first.
#
set -euo pipefail

REPO="github.com/twobip/BlipDNS"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/blipc}"
STATE_DIR="${STATE_DIR:-/var/lib/blipc}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_NAME="blipc"

# --- helpers -----------------------------------------------------------------
log()  { echo "[install-blipc] $*"; }
err()  { echo "[install-blipc] ERROR: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install-blipc.sh [VERSION|BRANCH] [--install-deps]

Installs blipc and blipctl from the BlipDNS repository.
  VERSION|BRANCH    Optional release or branch (default: master)
  --install-deps    Install Git, Go, CA certificates, curl, and jq using the system package manager
EOF
}

# --- arguments ---------------------------------------------------------------
INSTALL_DEPS=0
INSTALL=""
for ARG in "$@"; do
  case "$ARG" in
    --install-deps)
      INSTALL_DEPS=1
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
  log "installing dependencies: git, go, ca-certificates, curl, jq"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y git golang-go ca-certificates curl jq
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y git golang ca-certificates curl jq
  elif command -v yum >/dev/null 2>&1; then
    yum install -y git golang ca-certificates curl jq
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache git go ca-certificates curl jq
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm git go ca-certificates curl jq
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install git go ca-certificates curl jq
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
go_is_supported() {
  local version major minor
  version="$(go version 2>/dev/null)" || return 1
  [[ "$version" =~ go([0-9]+)\.([0-9]+) ]] || return 1
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 25 ]; }
}

install_go_from_archive() {
  local arch archive archive_name metadata expected actual tmp
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
  if ! curl -fsSL "https://go.dev/dl/$archive_name" -o "$archive"; then
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

  if [ -x "$GO_INSTALL_DIR/bin/go" ]; then
    export PATH="$GO_INSTALL_DIR/bin:$PATH"
    hash -r
    if go_is_supported; then
      cleanup_go_tmp
      return
    fi
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
  if ! command -v go >/dev/null 2>&1; then
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
[ "$INSTALL_DEPS" -eq 1 ] && install_dependencies
install_git
require_go

# --- resolve install prefix --------------------------------------------------
if [ -n "$INSTALL" ]; then
  case "$INSTALL" in
    stable|master)
      INSTALL="$INSTALL" ;;
    *) INSTALL="${INSTALL#v}" ;;
  esac
  RELEASE="refs/heads/${INSTALL}"
else
  RELEASE="refs/heads/master"
fi

# --- clone & build -----------------------------------------------------------
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

log "cloning $REPO @ $RELEASE"
git clone --depth 1 --branch "$(echo "$RELEASE" | sed 's#refs/heads/##')" \
  "https://${REPO}.git" "$TMPDIR/src" 2>/dev/null || \
  git clone "https://${REPO}.git" "$TMPDIR/src"

cd "$TMPDIR/src"
log "building blipc and blipctl"
go build -o "$TMPDIR/blipc" ./cmd/blipc
go build -o "$TMPDIR/blipctl" ./cmd/blipctl

# --- install binaries --------------------------------------------------------
log "installing binaries to $BIN_DIR"
install -m 0755 "$TMPDIR/blipc"   "$BIN_DIR/blipc"
install -m 0755 "$TMPDIR/blipctl" "$BIN_DIR/blipctl"

# --- config / state dirs -----------------------------------------------------
log "creating config and state directories"
mkdir -p "$CONFIG_DIR" "$STATE_DIR"
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
  chmod 600 "$CONFIG_DIR/blipc.yaml"
fi

# --- systemd service (if systemd is available) --------------------------------
if [ -d "$SYSTEMD_DIR" ] && command -v systemctl >/dev/null 2>&1; then
  log "installing systemd unit: $SYSTEMD_DIR/$SERVICE_NAME.service"
  cat > "$SYSTEMD_DIR/$SERVICE_NAME.service" <<EOF
[Unit]
Description=BlipDNS controller (blipc)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/blipc -config $CONFIG_DIR/blipc.yaml
Restart=on-failure
RestartSec=5
# Uncomment the next line to run as a non-root user (recommended).
# User=blip
# Group=blip
ReadWritePaths=$STATE_DIR $CONFIG_DIR
StateDirectory=blipc
ReadWritePaths=$STATE_DIR
ProtectSystem=strict
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$SYSTEMD_DIR/$SERVICE_NAME.service"
  log "reloading systemd daemon"
  systemctl daemon-reload || true
  log "to start:  sudo systemctl enable --now $SERVICE_NAME"
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
log "  1. Edit $CONFIG_DIR/blipc.yaml to set username/password_hash and add instances."
log "  2. sudo systemctl enable --now blipc"

#!/usr/bin/env bash
#
# install-blipd.sh — install the BlipDNS resolver daemon (blipd)
# and set up a systemd service for blipd.
#
# Usage:  curl -sL https://raw.githubusercontent.com/twobip/BlipDNS/master/scripts/install-blipd.sh | sudo bash
# Optional: append --install-deps to install Git, Go, and CA certificates first.
#
set -euo pipefail

REPO="github.com/twobip/BlipDNS"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/blipd}"
STATE_DIR="${STATE_DIR:-/var/lib/blipd}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_NAME="blipd"

# --- helpers -----------------------------------------------------------------
log()  { echo "[install-blipd] $*"; }
err()  { echo "[install-blipd] ERROR: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install-blipd.sh [VERSION|BRANCH] [--install-deps]

Installs blipd from the BlipDNS repository.
  VERSION|BRANCH    Optional release or branch (default: master)
  --install-deps    Install Git, Go, and CA certificates using the system package manager
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

install_dependencies() {
  log "installing dependencies: git, go, ca-certificates"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y git golang-go ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y git golang ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y git golang ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache git go ca-certificates
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm git go ca-certificates
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install git go ca-certificates
  else
    err "--install-deps was requested, but no supported package manager was found"
  fi
}

# --- sanity ------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || err "this script must be run as root (use sudo)"
[ "$INSTALL_DEPS" -eq 1 ] && install_dependencies

# Git is needed to fetch the source when this script is run remotely.
if ! command -v git >/dev/null 2>&1; then
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
fi
command -v git >/dev/null 2>&1 || err "Git installation failed; install Git and run this script again"
# Git is needed to fetch the source when this script is run remotely.
if ! command -v git >/dev/null 2>&1; then
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
fi
command -v git >/dev/null 2>&1 || err "Git installation failed; install Git and run this script again"

require_go() {
  command -v go >/dev/null 2>&1 || err "Go is not installed. Install Go 1.25+ first: https://go.dev/dl/"
  local version major minor
  version="$(go version 2>/dev/null)" || err "Could not determine the Go version"
  if [[ "$version" =~ go([0-9]+)\.([0-9]+) ]]; then
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    if [ "$major" -lt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -lt 25 ]; }; then
      err "Go 1.25+ is required; found $version. Install a newer Go version: https://go.dev/dl/"
    fi
  else
    err "Could not determine the Go version from: $version"
  fi
}
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
log "building blipd"
go build -o "$TMPDIR/blipd" ./cmd/blipd

# --- install binary ----------------------------------------------------------
log "installing binary to $BIN_DIR"
install -m 0755 "$TMPDIR/blipd" "$BIN_DIR/blipd"

# --- config / state dirs -----------------------------------------------------
log "creating config and state directories"
mkdir -p "$CONFIG_DIR" "$STATE_DIR"
chmod 700 "$CONFIG_DIR" "$STATE_DIR"

# Create a default config if none exists.
if [ ! -f "$CONFIG_DIR/blipd.yaml" ]; then
  log "writing default config to $CONFIG_DIR/blipd.yaml"
  cat > "$CONFIG_DIR/blipd.yaml" <<'EOF'
# BlipDNS resolver configuration
# See: https://github.com/twobip/BlipDNS
#
# dns_addr: address for classic DNS (UDP + TCP)
# doh_addr: address for DNS-over-HTTPS (HTTPS)
# admin_addr / admin_token: management API (used by the controller)
dns_addr: "0.0.0.0:53"
doh_addr: "0.0.0.0:443"
doh_tls: true
admin_addr: "0.0.0.0:8443"
admin_token: "replace-me-with-a-secret-token"
upstream: "udp://1.1.1.1:53 https://1.1.1.1/dns-query"
cache_size: 10000
# Per-server upstream timeout (seconds before failing over to next priority server):
# upstream_servers:
#   - name: "cloudflare"
#     address: "udp://1.1.1.1:53"
#     priority: 1
#     timeout_sec: 3
#   - name: "google"
#     address: "https://8.8.8.8/dns-query"
#     priority: 2
#     timeout_sec: 5
EOF
  chmod 600 "$CONFIG_DIR/blipd.yaml"
  log "IMPORTANT: edit $CONFIG_DIR/blipd.yaml to set a strong admin_token"
fi

# --- systemd service (if systemd is available) --------------------------------
if [ -d "$SYSTEMD_DIR" ] && command -v systemctl >/dev/null 2>&1; then
  log "installing systemd unit: $SYSTEMD_DIR/$SERVICE_NAME.service"
  cat > "$SYSTEMD_DIR/$SERVICE_NAME.service" <<EOF
[Unit]
Description=BlipDNS resolver (blipd)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/blipd -config $CONFIG_DIR/blipd.yaml
Restart=on-failure
RestartSec=5
# blipd binds to port 53 / 443 — root is required unless you use AmbientCapabilities:
#   AmbientCapabilities=CAP_NET_BIND_SERVICE
#   User=blip
#   Group=blip
ReadWritePaths=$STATE_DIR $CONFIG_DIR
StateDirectory=blipd
ProtectSystem=strict
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$SYSTEMD_DIR/$SERVICE_NAME.service"
  log "reloading systemd daemon"
  systemctl daemon-reload || true
  log "to start:  sudo systemctl enable --now $SERVICE_NAME"
else
  log "systemd not found — skipping service installation (run 'blipd -config $CONFIG_DIR/blipd.yaml' manually)"
fi

log ""
log "blipd installed successfully."
log ""
log "binary:    $BIN_DIR/blipd"
log "config:    $CONFIG_DIR/blipd.yaml"
log "state:     $STATE_DIR"
log ""
log "Next steps:"
log "  1. Edit $CONFIG_DIR/blipd.yaml — set a strong admin_token and your upstream servers."
log "  2. sudo systemctl enable --now blipd"
log "  3. Point your controller at the blipd admin_addr and token."

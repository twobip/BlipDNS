#!/usr/bin/env bash
#
# install-blipd.sh — install the BlipDNS resolver daemon (blipd)
# and set up a systemd service for blipd.
#
# Usage:  curl -sL https://raw.githubusercontent.com/twobip/BlipDNS/master/scripts/install-blipd.sh | sudo bash
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

# --- sanity ------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || err "this script must be run as root (use sudo)"
command -v go >/dev/null 2>&1 || err "Go is not installed. Install Go 1.25+ first: https://go.dev/dl/"

# --- resolve install prefix --------------------------------------------------
INSTALL="${1:-}"
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

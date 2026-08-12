#!/usr/bin/env bash
#
# install-blipd.sh — install the BlipDNS resolver daemon (blipd)
# and set up a systemd service for blipd.
#
# Usage:  curl -sL https://raw.githubusercontent.com/twobip/BlipDNS/master/scripts/install-blipd.sh | sudo bash
# Optional: append --install-deps to install Git, Go, CA certificates, curl, and jq first.
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
  local packages="git ca-certificates curl jq"
  local go_needed=1
  if dedicated_go_is_supported || { command -v go >/dev/null 2>&1 && go_is_supported; }; then
    go_needed=0
    log "reusing an existing supported Go installation"
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

generate_admin_token() {
  local token
  command -v od >/dev/null 2>&1 || err "od is required to generate a secure admin token"
  token="$(od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]')"
  [ "${#token}" -eq 64 ] || err "failed to generate a secure admin token"
  printf '%s' "$token"
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
  local arch archive archive_name metadata expected actual

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

  GO_TMPDIR="$(mktemp -d)"
  trap cleanup_go_tmp EXIT
  command -v jq >/dev/null 2>&1 || err "jq is required to verify Go metadata; rerun with --install-deps"
  archive_name="go${GO_REQUIRED_VERSION}.linux-${arch}.tar.gz"
  archive="$GO_TMPDIR/$archive_name"
  metadata="$GO_TMPDIR/go.json"
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

# /root may be read-only (containers/LXC); keep Go caches somewhere writable.
CACHE_DIR="/var/cache/blipd-update"
mkdir -p "$CACHE_DIR/gomod" "$CACHE_DIR/gocache" "$CACHE_DIR/gopath"
export GOMODCACHE="$CACHE_DIR/gomod"
export GOCACHE="$CACHE_DIR/gocache"
export GOPATH="$CACHE_DIR/gopath"

log "cloning $REPO @ $RELEASE"
git clone --depth 1 --branch "$(echo "$RELEASE" | sed 's#refs/heads/##')" \
  "https://${REPO}.git" "$TMPDIR/src" 2>/dev/null || \
  git clone "https://${REPO}.git" "$TMPDIR/src"

cd "$TMPDIR/src"
log "building blipd"
go build -ldflags "-X main.buildSHA=$(git -C "$TMPDIR/src" rev-parse HEAD)" -o "$TMPDIR/blipd" ./cmd/blipd

# --- install binary ----------------------------------------------------------
log "installing binary to $BIN_DIR"
install -m 0755 "$TMPDIR/blipd" "$BIN_DIR/blipd"
install -m 0755 "$TMPDIR/src/scripts/blipd-update.sh" /usr/local/sbin/blipd-update
cat > /etc/sudoers.d/blipd-update <<'EOF'
blip ALL=(root) NOPASSWD: /usr/local/sbin/blipd-update
EOF
chmod 0440 /etc/sudoers.d/blipd-update
visudo -cf /etc/sudoers.d/blipd-update

# --- config / state dirs -----------------------------------------------------
log "creating config and state directories"
mkdir -p "$CONFIG_DIR" "$STATE_DIR"
chmod 700 "$CONFIG_DIR" "$STATE_DIR"

# Create a default config if none exists.
if [ ! -f "$CONFIG_DIR/blipd.yaml" ]; then
  ADMIN_TOKEN="$(generate_admin_token)"
  log "writing default config to $CONFIG_DIR/blipd.yaml with a generated admin token"
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
admin_token: "__BLIP_ADMIN_TOKEN__"
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
  sed -i "s/__BLIP_ADMIN_TOKEN__/$ADMIN_TOKEN/" "$CONFIG_DIR/blipd.yaml"
  chmod 600 "$CONFIG_DIR/blipd.yaml"
  log "admin token saved in $CONFIG_DIR/blipd.yaml (do not share it)"
elif grep -Eq '^[[:space:]]*admin_token:[[:space:]]*("replace-me-with-a-secret-token"|replace-me-with-a-secret-token|"__BLIP_ADMIN_TOKEN__"|__BLIP_ADMIN_TOKEN__|""|null|)[[:space:]]*$' "$CONFIG_DIR/blipd.yaml"; then
  ADMIN_TOKEN="$(generate_admin_token)"
  sed -i -E "s|^([[:space:]]*admin_token:)[[:space:]].*$|\\1 \\\"$ADMIN_TOKEN\\\"|" "$CONFIG_DIR/blipd.yaml"
  chmod 600 "$CONFIG_DIR/blipd.yaml"
  log "replaced the placeholder admin token in $CONFIG_DIR/blipd.yaml (do not share it)"
fi
chmod 600 "$CONFIG_DIR/blipd.yaml"

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
log "  1. Edit $CONFIG_DIR/blipd.yaml to set your upstream servers if needed."
log "  2. Start blipd: sudo systemctl enable --now blipd"
log "  3. Copy the admin token from $CONFIG_DIR/blipd.yaml into your controller's instance settings."
log "     To view it: sudo grep '^admin_token:' $CONFIG_DIR/blipd.yaml"
log "  4. Keep the admin token private; it controls this blipd management API."

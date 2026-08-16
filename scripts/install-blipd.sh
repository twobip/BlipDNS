#!/usr/bin/env bash
#
# install-blipd.sh — install the BlipDNS resolver daemon (blipd)
# and set up a systemd service for blipd.
#
# Usage:  curl -sL https://raw.githubusercontent.com/twobip/BlipDNS/master/scripts/install-blipd.sh | sudo bash
# Optional: append --install-deps to install prerequisites (curl, CA certs) first.
#           append --build-from-source to clone + build instead of downloading a release binary.
#
set -euo pipefail

REPO="github.com/twobip/BlipDNS"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/blipd}"
STATE_DIR="${STATE_DIR:-/var/lib/blipd}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_NAME="blipd"
BASE_URL="https://github.com/twobip/BlipDNS/releases/download"
RAW_BASE="https://raw.githubusercontent.com/twobip/BlipDNS"

# --- helpers -----------------------------------------------------------------
log()  { echo "[install-blipd] $*"; }
err()  { echo "[install-blipd] ERROR: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install-blipd.sh [stable|dev|vX.Y.Z] [--install-deps] [--build-from-source]

Installs blipd from a pre-built GitHub release binary (default) or from source.
  stable|dev|vX.Y.Z  Release channel or explicit version (default: stable)
  --install-deps      Install prerequisites (curl, CA certs; plus Git/Go when building)
  --build-from-source Clone and build from source instead of downloading a release binary
EOF
}

# --- arguments ---------------------------------------------------------------
INSTALL_DEPS=0
BUILD_FROM_SOURCE=0
INSTALL=""
for ARG in "$@"; do
  case "$ARG" in
    --install-deps)
      INSTALL_DEPS=1
      ;;
    --build-from-source)
      BUILD_FROM_SOURCE=1
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
  if [ "$BUILD_FROM_SOURCE" -eq 1 ]; then
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

if [ "$BUILD_FROM_SOURCE" -eq 1 ]; then
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
      err "curl is required to download the release binary; install curl or rerun with --install-deps"
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

# --- obtain the binary (download, or clone + build) -------------------------
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [ "$BUILD_FROM_SOURCE" -eq 1 ]; then
  # /root may be read-only (containers/LXC); keep Go caches somewhere writable.
  CACHE_DIR="/var/cache/blipd-update"
  mkdir -p "$CACHE_DIR/gomod" "$CACHE_DIR/gocache" "$CACHE_DIR/gopath"
  export GOMODCACHE="$CACHE_DIR/gomod"
  export GOCACHE="$CACHE_DIR/gocache"
  export GOPATH="$CACHE_DIR/gopath"

  log "cloning $REPO @ $REF"
  git clone --depth 1 --branch "$REF" \
    "https://${REPO}.git" "$TMPDIR/src" || \
    git clone "https://${REPO}.git" "$TMPDIR/src"

  cd "$TMPDIR/src"
  log "building blipd (first build can take a few minutes — package list below shows progress)"
  go build -v -ldflags "-X main.version=$(cat VERSION)" -o "$TMPDIR/blipd" ./cmd/blipd
else
  log "downloading blipd-linux-amd64 from release $TAG"
  curl -fL "$BASE_URL/$TAG/blipd-linux-amd64" -o "$TMPDIR/blipd" \
    || err "download failed: $BASE_URL/$TAG/blipd-linux-amd64"
  curl -fsSL "$BASE_URL/$TAG/SHA256SUMS" -o "$TMPDIR/SHA256SUMS" \
    || err "download failed: SHA256SUMS"
  log "verifying checksum"
  expected="$(awk '$2=="blipd-linux-amd64" {print $1; exit}' "$TMPDIR/SHA256SUMS")"
  [ -n "$expected" ] || err "no checksum entry for blipd-linux-amd64 in SHA256SUMS"
  actual="$(sha256sum "$TMPDIR/blipd" | awk '{print $1}')"
  [ "$expected" = "$actual" ] || err "checksum verification FAILED for blipd-linux-amd64 — refusing to install"
  log "checksum verified"
fi

# --- install binary ----------------------------------------------------------
log "installing binary to $BIN_DIR"
install -m 0755 "$TMPDIR/blipd" "$BIN_DIR/blipd"

# Install the self-updater helpers. From a source build they come out of the
# clone; from a release they are fetched from the pinned ref over HTTPS.
if [ "$BUILD_FROM_SOURCE" -eq 1 ]; then
  install -m 0755 "$TMPDIR/src/scripts/blipd-update.sh" /usr/local/sbin/blipd-update
  install -m 0755 "$TMPDIR/src/scripts/blipd-install.sh" /usr/local/sbin/blipd-install
else
  curl -fsSL "$RAW_BASE/$REF/scripts/blipd-update.sh" -o /usr/local/sbin/blipd-update \
    || err "failed to fetch blipd-update.sh"
  curl -fsSL "$RAW_BASE/$REF/scripts/blipd-install.sh" -o /usr/local/sbin/blipd-install \
    || err "failed to fetch blipd-install.sh"
  chmod 0755 /usr/local/sbin/blipd-update /usr/local/sbin/blipd-install
fi
# Only the install helper is allowed to run as root; the download (blipd-update)
# runs unprivileged as the blip service user.

log "ensuring system user 'blip'"
if ! id blip >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin blip
fi

cat > /etc/sudoers.d/blipd-install <<'EOF'
blip ALL=(root) NOPASSWD: /usr/local/sbin/blipd-install
EOF
chmod 0440 /etc/sudoers.d/blipd-install
visudo -cf /etc/sudoers.d/blipd-install
cat > /etc/sudoers.d/blipd-restart <<'EOF'
blip ALL=(root) NOPASSWD: /usr/bin/systemctl restart blipd.service
EOF
chmod 0440 /etc/sudoers.d/blipd-restart
visudo -cf /etc/sudoers.d/blipd-restart

# Allow the 'blip' user to reload keepalived (needed for HA priority changes
# during fleet updates — blipd reloads keepalived to re-read the rendered
# config). Both `systemctl reload` and `pkill -HUP` are permitted: the
# former is preferred, the latter is the SIGHUP fallback when the systemd
# unit lacks an ExecReload handler.
cat > /etc/sudoers.d/blipd-keepalived <<'EOF'
blip ALL=(root) NOPASSWD: /usr/bin/systemctl reload keepalived
blip ALL=(root) NOPASSWD: /usr/bin/pkill -HUP keepalived
EOF
chmod 0440 /etc/sudoers.d/blipd-keepalived
visudo -cf /etc/sudoers.d/blipd-keepalived

# --- config / state dirs -----------------------------------------------------
log "creating config and state directories"
mkdir -p "$CONFIG_DIR" "$STATE_DIR" /etc/keepalived
chmod 700 "$CONFIG_DIR" "$STATE_DIR"

# Point keepalived at blipd's rendered config. Debian's keepalived.service ships
# with "ConditionFileNotEmpty=/etc/keepalived/keepalived.conf", so without this
# symlink keepalived refuses to start and the VRRP VIP never comes up. The target
# won't exist until HA is first applied in the controller; a dangling symlink is
# fine (keepalived simply won't start until then, which is correct).
ln -sfn "$STATE_DIR/keepalived.conf" /etc/keepalived/keepalived.conf

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

# The service runs as the unprivileged 'blip' user; give it write access to its
# state directory and read access to the config (which holds the admin token).
log "setting ownership for the blip service user"
chown -R blip:blip "$STATE_DIR"
chown -R root:blip "$CONFIG_DIR"
chown blip:blip "$CONFIG_DIR/blipd.yaml"
chmod 750 "$CONFIG_DIR"
# chmod 600 already set above (line 438); 640 would warn in blipd.

# --- systemd service (if systemd is available) --------------------------------
if [ -d "$SYSTEMD_DIR" ] && command -v systemctl >/dev/null 2>&1; then
  log "installing systemd unit: $SYSTEMD_DIR/$SERVICE_NAME.service"
  cat > "$SYSTEMD_DIR/$SERVICE_NAME.service" <<EOF
[Unit]
Description=BlipDNS - fast per-client filtering DNS server with DoH
Documentation=https://github.com/twobip/BlipDNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=blip
Group=blip
ExecStart=$BIN_DIR/blipd -config $CONFIG_DIR/blipd.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3

# Allow binding privileged ports (e.g. 53) as the unprivileged 'blip' user.
AmbientCapabilities=CAP_NET_BIND_SERVICE
# No CapabilityBoundingSet restriction: blipd elevates to the pinned
# /usr/local/sbin/blipd-install helper via sudo (narrow sudoers rule), which
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
SyslogIdentifier=blipd

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

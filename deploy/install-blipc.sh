#!/usr/bin/env bash
# Install BlipDNS controller (blipc) as a systemd service. Must run as root.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="$HERE/bin/blipc"
BIN_DST="/usr/local/bin/blipc"
CFG_DIR="/etc/blipc"
CFG_DST="$CFG_DIR/blipc.yaml"
TPL="$HERE/deploy/blipc.yaml"
UNIT_SRC="$HERE/deploy/blipc.service"
UNIT_DST="/etc/systemd/system/blipc.service"
SVC_USER="blipc"

echo ">> building blipc"
CACHE_DIR="/var/cache/blipc-update"
mkdir -p "$CACHE_DIR/gomod" "$CACHE_DIR/gocache" "$CACHE_DIR/gopath"
export GOMODCACHE="$CACHE_DIR/gomod" GOCACHE="$CACHE_DIR/gocache" GOPATH="$CACHE_DIR/gopath"
( cd "$HERE" && go build -ldflags "-X main.buildSHA=$(git -C "$HERE" rev-parse HEAD)" -o bin/blipc ./cmd/blipc )

echo ">> installing binary -> $BIN_DST"
install -Dm 0755 "$BIN_SRC" "$BIN_DST"

echo ">> installing controller updater"
install -Dm 0755 "$HERE/scripts/blipc-update.sh" /usr/local/sbin/blipc-update
install -Dm 0755 "$HERE/scripts/blipc-install.sh" /usr/local/sbin/blipc-install
# Only the install helper runs as root; the build (blipc-update) runs as blipc.
cat > /etc/sudoers.d/blipc-install <<'EOF'
blipc ALL=(root) NOPASSWD: /usr/local/sbin/blipc-install
EOF
chmod 0440 /etc/sudoers.d/blipc-install
visudo -cf /etc/sudoers.d/blipc-install

echo ">> ensuring system user '$SVC_USER'"
if ! id "$SVC_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

echo ">> installing config -> $CFG_DST"
mkdir -p "$CFG_DIR"
if [[ -f "$CFG_DST" ]]; then
  echo "   (existing config preserved — not overwriting; edit $CFG_DST to change)"
else
  # Fresh installs remain closed until the one-time web setup creates
  # credentials. BLIPC_SETUP_TOKEN=1 is retained for operators who want the
  # bootstrap URL/token printed explicitly.
  if [[ "${BLIPC_SETUP_TOKEN:-0}" == "1" ]]; then
    TOKEN="$(openssl rand -hex 16)"
    sed "s/__BLIPC_TOKEN__/$TOKEN/" "$TPL" > "$CFG_DST"
    chmod 0600 "$CFG_DST"
    chown root:"$SVC_USER" "$CFG_DST"
    echo "   setup token: $TOKEN   (open http://<host>:8500/setup#token=$TOKEN)"
  else
    sed 's/token: "__BLIPC_TOKEN__"/token: ""/' "$TPL" > "$CFG_DST"
    chmod 0600 "$CFG_DST"
    chown root:"$SVC_USER" "$CFG_DST"
    echo "   auth: CLOSED until first-run setup at http://<host>:8500/setup"
  fi
fi

echo ">> installing unit -> $UNIT_DST"
install -Dm 0644 "$UNIT_SRC" "$UNIT_DST"

systemctl daemon-reload
systemctl enable --now blipc

systemctl status --no-pager blipc
echo
echo "BlipDNS Controller is running. Open the web UI:"
if [[ "${BLIPC_SETUP_TOKEN:-0}" == "1" ]]; then
  echo "  http://localhost:8500/setup#token=$TOKEN"
else
  echo "  http://localhost:8500/setup   (create the administrator account)"
fi

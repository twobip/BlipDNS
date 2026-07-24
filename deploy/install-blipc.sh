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
( cd "$HERE" && go build -o bin/blipc ./cmd/blipc )

echo ">> installing binary -> $BIN_DST"
install -Dm 0755 "$BIN_SRC" "$BIN_DST"

echo ">> ensuring system user '$SVC_USER'"
if ! id "$SVC_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

echo ">> installing config -> $CFG_DST"
mkdir -p "$CFG_DIR"
if [[ -f "$CFG_DST" ]]; then
  echo "   (existing config preserved — not overwriting; edit $CFG_DST to change)"
else
  # Default config ships with token: "" (OPEN, no auth) for convenient
  # testing on a trusted management VLAN. To require a token on a fresh
  # install, run with BLIPC_SETUP_TOKEN=1 (a random token is generated).
  if [[ "${BLIPC_SETUP_TOKEN:-0}" == "1" ]]; then
    TOKEN="$(openssl rand -hex 16)"
    sed "s/__BLIPC_TOKEN__/$TOKEN/" "$TPL" > "$CFG_DST"
    chmod 0640 "$CFG_DST"
    chown root:"$SVC_USER" "$CFG_DST"
    echo "   web UI token: $TOKEN   (open http://<host>:8500/?token=$TOKEN)"
  else
    sed 's/token: "__BLIPC_TOKEN__"/token: ""/' "$TPL" > "$CFG_DST"
    chmod 0640 "$CFG_DST"
    chown root:"$SVC_USER" "$CFG_DST"
    echo "   auth: OPEN (no token). Set 'token:' in $CFG_DST to enable."
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
  echo "  http://localhost:8500/?token=$TOKEN"
else
  echo "  http://localhost:8500/   (auth: OPEN)"
fi

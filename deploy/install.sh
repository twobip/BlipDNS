#!/usr/bin/env bash
# Install BlipDNS as a systemd service. Must be run as root (sudo ./install.sh).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="$HERE/bin/blipd"
BIN_DST="/usr/local/bin/blipd"
CFG_DIR="/etc/blipd"
CFG_DST="$CFG_DIR/blipd.yaml"
TPL="$HERE/deploy/blipd.yaml"
UNIT_SRC="$HERE/deploy/blipd.service"
UNIT_DST="/etc/systemd/system/blipd.service"
SVC_USER="blip"

echo ">> building blipd"
( cd "$HERE" && go build -o bin/blipd ./cmd/blipd )

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
  TOKEN="$(openssl rand -hex 16)"
  sed "s/__BLIP_ADMIN_TOKEN__/$TOKEN/" "$TPL" > "$CFG_DST"
  chmod 0640 "$CFG_DST"
  chown root:"$SVC_USER" "$CFG_DST"
  echo "   admin token: $TOKEN   (use with: blipctl --token $TOKEN http://127.0.0.1:8444 ...)"
fi

echo ">> installing unit -> $UNIT_DST"
install -Dm 0644 "$UNIT_SRC" "$UNIT_DST"

echo ">> daemon-reload + enable/start"
systemctl daemon-reload
systemctl enable --now blipd

echo ">> status"
systemctl status --no-pager blipd
echo
echo "BlipDNS is running. Quick test:"
echo "  dig +short @127.0.0.1 example.com"
echo "  blipctl --token $TOKEN http://127.0.0.1:8444 health"

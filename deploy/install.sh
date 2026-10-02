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
mkdir -p /var/lib/blipd
# M16 + audit 2026-10-01 #8: the config holds the admin token. It must be
# root-owned and group-readable (not blip-owned 0600, which lets a
# compromised service user rewrite its own token/upstreams): blipd runs as
# user blip, so group read is enough. Matches scripts/install-blipd.sh.
chown -R root:"$SVC_USER" "$CFG_DIR"
chmod 750 "$CFG_DIR"
chown -R "$SVC_USER":"$SVC_USER" /var/lib/blipd
chmod 700 /var/lib/blipd
if [[ -f "$CFG_DST" ]]; then
  echo "   (existing config preserved — not overwriting; edit $CFG_DST to change)"
  # Normalize ownership on re-run so an old blip-owned config stops being
  # daemon-writable.
  chown root:"$SVC_USER" "$CFG_DST"
  chmod 640 "$CFG_DST"
else
  TOKEN="$(openssl rand -hex 16)"
  sed "s/__BLIP_ADMIN_TOKEN__/$TOKEN/" "$TPL" > "$CFG_DST"
  chmod 640 "$CFG_DST"
  chown root:"$SVC_USER" "$CFG_DST"
  echo "   admin token stored in $CFG_DST (never printed; 640 root-owned)"
  echo "   read it with: sudo cat $CFG_DST   (use: blipctl --token-file <(sudo cat $CFG_DST) http://127.0.0.1:8444 ...)"
  echo "   claim code is written to /var/lib/blipd/adopt-code (0600); read it box-locally with: sudo cat /var/lib/blipd/adopt-code"
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
echo "  blipctl --token-file <(sudo cat $CFG_DST) http://127.0.0.1:8444 health"
# The fresh token must not linger in this shell's environment for later
# commands (or screenshots of them) to leak.
unset TOKEN

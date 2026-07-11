#!/usr/bin/env bash
# Remove the BlipDNS systemd service (keeps /etc/blipd/blipd.yaml unless -c).
set -euo pipefail
UNIT="/etc/systemd/system/blipd.service"
CFG="/etc/blipd/blipd.yaml"

systemctl disable --now blipd 2>/dev/null || true
rm -f "$UNIT"
rm -f /usr/local/bin/blipd
systemctl daemon-reload

if [[ "${1:-}" == "-c" ]]; then
  rm -rf /etc/blipd
  echo "removed service, binary, unit and config dir"
else
  echo "removed service, binary and unit (config at $CFG kept)"
fi

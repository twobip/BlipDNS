#!/usr/bin/env bash
# Remove the BlipDNS controller service (keeps /etc/blipc unless -c).
set -euo pipefail
UNIT="/etc/systemd/system/blipc.service"
CFG="/etc/blipc"

systemctl disable --now blipc 2>/dev/null || true
rm -f "$UNIT"
rm -f /usr/local/bin/blipc
systemctl daemon-reload

if [[ "${1:-}" == "-c" ]]; then
  rm -rf "$CFG"
  echo "removed service, binary, unit and config dir"
else
  echo "removed service, binary and unit (config at $CFG kept)"
fi

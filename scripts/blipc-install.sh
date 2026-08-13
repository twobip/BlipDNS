#!/usr/bin/env bash
set -euo pipefail

# Root half of the blipc self-updater. Installs a binary that was already
# built (unprivileged) and restarts the service. No network, no compiler — the
# smallest possible privileged surface. The staged path is trusted only after
# confirming it is a regular ELF file at a fixed location.
STAGED="${1:-}"
readonly BIN="/usr/local/bin/blipc"
readonly PREVIOUS="/usr/local/bin/blipc.previous"

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ -n "$STAGED" && -f "$STAGED" && ! -L "$STAGED" ]] || { echo "staged binary missing or not a regular file" >&2; exit 1; }
[[ "$(head -c 4 "$STAGED" 2>/dev/null)" == $'\x7fELF' ]] || { echo "staged file is not an ELF binary" >&2; exit 1; }

echo "phase: installing"
tmp="$(mktemp /usr/local/bin/.blipc.XXXXXX)"
trap 'rm -f "$tmp"' EXIT
install -o root -g root -m 0755 "$STAGED" "$tmp"
if [[ -x "$BIN" ]]; then
  cp -p "$BIN" "$PREVIOUS"
fi
mv -f "$tmp" "$BIN"

echo "phase: restarting"
if ! systemctl restart blipc || ! systemctl is-active --quiet blipc; then
  if [[ -x "$PREVIOUS" ]]; then
    install -o root -g root -m 0755 "$PREVIOUS" "$BIN"
    systemctl restart blipc || true
  fi
  echo "blipc restart/health check failed; previous binary restored" >&2
  exit 1
fi
printf '%s\n' "blipc installed and healthy"

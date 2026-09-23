#!/usr/bin/env bash
set -euo pipefail

# Root half of the blipd self-updater. Installs a binary that was already
# built (unprivileged) and restarts the service. No network, no compiler — the
# smallest possible privileged surface. The staged path is trusted only after
# confirming it is a regular ELF file at a fixed location.
STAGED="${1:-}"
readonly BIN="/usr/local/bin/blipd"
readonly PREVIOUS="/usr/local/bin/blipd.previous"
readonly EXPECTED_STAGED="/var/lib/blipd/update/blipd.new"
readonly EXPECTED_DIR="/var/lib/blipd/update"
# F-03: the lock must NOT live in the service-writable update dir. That dir is
# owned by the unprivileged service account, so a lock file there can be
# swapped for a symlink and the root helper would follow it (truncating an
# attacker-chosen path). /run/lock is root-owned (tmpfs), so only root can
# create/rename entries there.
readonly LOCK_FILE="/run/lock/blipd-install.lock"

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
# H2: enforce the fixed staged path pinned in the sudoers rule. Reject
# anything else so the NOPASSWD entry cannot be abused for arbitrary files.
[[ "$STAGED" == "$EXPECTED_STAGED" ]] || { echo "staged path must be $EXPECTED_STAGED (got: ${STAGED:-<empty>})" >&2; exit 1; }
[[ -n "$STAGED" && -f "$STAGED" && ! -L "$STAGED" ]] || { echo "staged binary missing or not a regular file" >&2; exit 1; }
# O_NOFOLLOW-style check: staged file must live directly in the update dir
# (dirname equality + symlink rejection above defeats dir/file swap tricks).
[[ "$(dirname "$STAGED")" == "$EXPECTED_DIR" ]] || { echo "staged file must be inside $EXPECTED_DIR" >&2; exit 1; }
[[ "$(head -c 4 "$STAGED" 2>/dev/null)" == $'\x7fELF' ]] || { echo "staged file is not an ELF binary" >&2; exit 1; }
# Optional SHA256 re-verify: when the unprivileged updater exports the
# checksum it verified, re-check it here before installing as root.
if [[ -n "${EXPECTED_SHA256:-}" ]]; then
  actual_sum="$(sha256sum "$STAGED" | awk '{print $1}')"
  [[ "$actual_sum" == "$EXPECTED_SHA256" ]] || { echo "staged SHA256 mismatch — refusing to install" >&2; exit 1; }
else
  echo "warning: EXPECTED_SHA256 not set, skipping root-side re-verify" >&2
fi
# Serialize installs. Use flock when available; fall back to a mkdir lock.
# The lock dir is root-owned, and the lock file itself is symlink-rejected
# before opening so a pre-existing attacker symlink is never followed.
USE_MKDIR_LOCK=0
if [[ -L "$LOCK_FILE" ]]; then echo "lock $LOCK_FILE is a symlink — refusing" >&2; exit 1; fi
mkdir -p "$(dirname "$LOCK_FILE")"
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK_FILE" || { echo "cannot open lock $LOCK_FILE" >&2; exit 1; }
  flock -n 9 || { echo "another install is in progress ($LOCK_FILE held)" >&2; exit 1; }
else
  if ! mkdir "${LOCK_FILE}.d" 2>/dev/null; then
    echo "another install is in progress (fallback lock held)" >&2; exit 1
  fi
  USE_MKDIR_LOCK=1
fi

echo "phase: installing"
tmp="$(mktemp /usr/local/bin/.blipd.XXXXXX)"
cleanup() {
  rm -f "$tmp"
  if [[ "${USE_MKDIR_LOCK:-0}" -eq 1 ]]; then
    rmdir "${LOCK_FILE}.d" 2>/dev/null || true
  fi
}
trap cleanup EXIT
install -o root -g root -m 0755 "$STAGED" "$tmp"
if [[ -x "$BIN" ]]; then
  cp -p "$BIN" "$PREVIOUS"
fi
mv -f "$tmp" "$BIN"

echo "phase: restarting"
if ! systemctl restart blipd || ! systemctl is-active --quiet blipd; then
  if [[ -x "$PREVIOUS" ]]; then
    install -o root -g root -m 0755 "$PREVIOUS" "$BIN"
    systemctl restart blipd || true
  fi
  echo "blipd restart/health check failed; previous binary restored" >&2
  exit 1
fi
printf '%s\n' "blipd installed and healthy"

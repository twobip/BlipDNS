#!/usr/bin/env bash
set -euo pipefail
umask 077

# Root half of the blipd self-updater. Installs a binary that was already
# built (unprivileged) and restarts the service. No network, no compiler — the
# smallest possible privileged surface. The staged binary is trusted only
# after verifying the release signature over SHA256SUMS (embedded key) and
# matching the staged inode's hash against the signed entry.
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
# Release signing (F-U1): the release workflow signs SHA256SUMS with an
# ed25519 key (ssh-keygen -Y sign, namespace below). The public half is
# embedded here; this helper is root-owned, so it is the one copy of the
# trust anchor the service user cannot rewrite. Rotation: add the new pubkey
# line beside the old one (overlap window), re-run install-blipd.sh on the
# nodes, then replace the CI secret.
readonly SIGN_IDENTITY="release@blipdns"
readonly SIGN_NAMESPACE="blipdns-release"
readonly SIGNING_ALLOWED='release@blipdns ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAllzM9gHKiNT3JLmP4nj0VgS68IBkFVsP6OIirPEm2V BlipDNS release signing (GitHub Actions)'
readonly SUMS="$EXPECTED_DIR/SHA256SUMS"
readonly SUMS_SIG="$EXPECTED_DIR/SHA256SUMS.sig"
readonly ASSET="blipd-linux-amd64"

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
# H2: enforce the fixed staged path pinned in the sudoers rule. Reject
# anything else so the NOPASSWD entry cannot be abused for arbitrary files.
[[ "$STAGED" == "$EXPECTED_STAGED" ]] || { echo "staged path must be $EXPECTED_STAGED (got: ${STAGED:-<empty>})" >&2; exit 1; }
[[ -n "$STAGED" && -f "$STAGED" && ! -L "$STAGED" ]] || { echo "staged binary missing or not a regular file" >&2; exit 1; }
# O_NOFOLLOW-style check: staged file must live directly in the update dir
# (dirname equality + symlink rejection above defeats dir/file swap tricks).
[[ "$(dirname "$STAGED")" == "$EXPECTED_DIR" ]] || { echo "staged file must be inside $EXPECTED_DIR" >&2; exit 1; }
# H2/F-U1: authenticity — a checksum only proves transit integrity, and a
# compromised publisher ships matching sums. Verify the release signature
# over SHA256SUMS HERE, at the privilege boundary, against the embedded key;
# the staged binary is then bound to a hash taken FROM THE SIGNED SUMS, not
# from anything the unprivileged half asserts.
command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen (openssh-client) is required to verify release signatures" >&2; exit 1; }
[[ -f "$SUMS" && ! -L "$SUMS" ]] || { echo "signed SHA256SUMS missing at $SUMS — unsigned/old release or stale updater; re-run install-blipd.sh" >&2; exit 1; }
[[ -f "$SUMS_SIG" && ! -L "$SUMS_SIG" ]] || { echo "SHA256SUMS.sig missing at $SUMS_SIG — release is not signed — refusing to install" >&2; exit 1; }
# TOCTOU: the update dir is service-user-writable, so pin the sums inode and
# read every later use through the fd (same idiom as the binary below).
exec 4<"$SUMS" || { echo "cannot open $SUMS" >&2; exit 1; }
if [[ -e /proc/self/fd/4 ]]; then SUMS_FD="/proc/self/fd/4"; else SUMS_FD="/dev/fd/4"; fi
# allowed_signers must be root-private: /usr/local/bin stays root-owned even
# through the unit's RW bind, unlike the update dir where the service user
# could swap the file for one naming its own key.
SIGNERS_TMP="$(mktemp /usr/local/bin/.blipd-signers.XXXXXX)" || { echo "cannot create signers scratch file in /usr/local/bin" >&2; exit 1; }
trap 'rm -f "$SIGNERS_TMP"' EXIT
printf '%s\n' "$SIGNING_ALLOWED" > "$SIGNERS_TMP"
ssh-keygen -Y verify -f "$SIGNERS_TMP" -I "$SIGN_IDENTITY" -n "$SIGN_NAMESPACE" -s "$SUMS_SIG" < "$SUMS_FD" \
  || { echo "SHA256SUMS signature verification FAILED — refusing to install (tampered or unsigned release)" >&2; exit 1; }
expected="$(awk -v a="$ASSET" '$2==a {print $1; exit}' "$SUMS_FD")"
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "no checksum entry for $ASSET in the signed SHA256SUMS" >&2; exit 1; }
# Belt: when the updater forwarded its own checksum (env_keep), it must agree
# with the signed sums — catches staging skew between the two halves.
if [[ -n "${EXPECTED_SHA256:-}" && "$EXPECTED_SHA256" != "$expected" ]]; then
  echo "EXPECTED_SHA256 disagrees with the signed SHA256SUMS — refusing to install" >&2; exit 1
fi
# H2 TOCTOU: the stage dir is service-writable, so pin the staged inode once
# and verify+install the SAME inode via fd (no re-read of the path). Any
# swap of $STAGED after this open does not affect /proc/self/fd/3.
exec 3<"$STAGED" || { echo "cannot open staged file" >&2; exit 1; }
if [[ -e /proc/self/fd/3 ]]; then
  FD_SRC="/proc/self/fd/3"
else
  FD_SRC="/dev/fd/3"
fi
[[ "$(head -c 4 "$FD_SRC" 2>/dev/null)" == $'\x7fELF' ]] || { echo "staged file is not an ELF binary" >&2; exit 1; }
actual_sum="$(sha256sum "$FD_SRC" | awk '{print $1}')"
[[ "$actual_sum" == "$expected" ]] || { echo "staged SHA256 mismatch — refusing to install" >&2; exit 1; }
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
  rm -f "$tmp" "${SIGNERS_TMP:-}"
  exec 3<&- 2>/dev/null || true
  exec 4<&- 2>/dev/null || true
  if [[ "${USE_MKDIR_LOCK:-0}" -eq 1 ]]; then
    rmdir "${LOCK_FILE}.d" 2>/dev/null || true
  fi
}
trap cleanup EXIT
# Same-inode install: copy from the pinned fd, not the service-writable path.
cat "$FD_SRC" > "$tmp" || { echo "staged read failed" >&2; exit 1; }
chmod 0755 "$tmp"
chown root:root "$tmp"
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

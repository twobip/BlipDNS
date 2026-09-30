#!/usr/bin/env bash
set -euo pipefail

# Unprivileged half of the blipd self-updater. Runs as the 'blip' service user
# (never root): downloads the pre-built static binary for the chosen release
# channel, verifies its SHA256 checksum, then asks root — via the minimal
# /usr/local/sbin/blipd-install helper — to install and restart. The network
# never runs with root privileges, and no Go toolchain or git is required.

readonly BASE="https://github.com/twobip/BlipDNS/releases/download"
readonly RAW="https://raw.githubusercontent.com/twobip/BlipDNS"

CHANNEL="${1:-stable}"
case "$CHANNEL" in
  stable|master)
    VER="$(curl -fsSL --proto '=https' --tlsv1.2 "$RAW/master/VERSION")" \
      || { echo "error: could not read stable VERSION from GitHub" >&2; exit 1; }
    # H2: validate the VERSION payload before turning it into a download URL.
    [[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "error: invalid VERSION from GitHub: $VER" >&2; exit 1; }
    TAG="v$VER" ;;
  dev)
    TAG="dev" ;;
  v*)
    TAG="$CHANNEL" ;;
  *)
    echo "channel must be stable or dev" >&2; exit 1 ;;
esac

# H2: validate the resolved tag so a compromised/malformed VERSION cannot
# turn into an arbitrary release URL.
if [[ "$TAG" != "dev" ]]; then
  [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "error: invalid tag: $TAG" >&2; exit 1; }
fi

WORK="/var/lib/blipd/update"
mkdir -p "$WORK"

# Downgrade guard (finding 9): ask the installed binary for its version
# via `blipd --version`, falling back to the install-time stamp. Unknown
# current version => FAIL CLOSED (refuse the update). Set ALLOW_DOWNGRADE=1
# to bypass explicitly (documented escape hatch, e.g. for unstamped local
# builds). The "dev" rolling tag is exempt (no ordering).
semver_cmp() {
  local a="${1#v}" b="${2#v}"
  a="${a%%+*}"; b="${b%%+*}"
  local IFS=.
  local av bv i x y
  # shellcheck disable=SC2206
  av=($a); bv=($b)
  for i in 0 1 2; do
    x="${av[$i]:-0}"; y="${bv[$i]:-0}"
    x="${x%%[^0-9]*}"; y="${y%%[^0-9]*}"
    x="${x:-0}"; y="${y:-0}"
    if (( 10#$x > 10#$y )); then echo 1; return; fi
    if (( 10#$x < 10#$y )); then echo 2; return; fi
  done
  echo 0
}
current_version() {
  local v=""
  if [[ -x /usr/local/bin/blipd ]]; then
    v="$(/usr/local/bin/blipd --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
  fi
  if [[ -z "$v" && -f "$WORK/.installed-version" ]]; then
    v="$(tr -d '[:space:]' < "$WORK/.installed-version" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
  fi
  printf '%s' "$v"
}
if [[ "$TAG" != "dev" && "${ALLOW_DOWNGRADE:-0}" != "1" ]]; then
  CUR="$(current_version || true)"
  if [[ -z "$CUR" ]]; then
    echo "error: installed version unknown (blipd --version failed and no $WORK/.installed-version stamp) — refusing to update; re-run the installer once, or set ALLOW_DOWNGRADE=1 to bypass" >&2; exit 1
  fi
  TARGET="${TAG#v}"
  if [[ "$(semver_cmp "$TARGET" "$CUR")" == "2" ]]; then
    echo "error: refusing downgrade $CUR -> $TARGET (set ALLOW_DOWNGRADE=1 to bypass)" >&2; exit 1
  fi
fi

echo "phase: downloading ($TAG)"
DL="$(mktemp -d "$WORK/dl.XXXXXX")"
trap 'rm -rf "$DL"' EXIT
curl -fL --proto '=https' --tlsv1.2 "$BASE/$TAG/blipd-linux-amd64" -o "$DL/blipd-linux-amd64"
curl -fsSL --proto '=https' --tlsv1.2 "$BASE/$TAG/SHA256SUMS" -o "$DL/SHA256SUMS"
curl -fsSL --proto '=https' --tlsv1.2 "$BASE/$TAG/SHA256SUMS.sig" -o "$DL/SHA256SUMS.sig" \
  || { echo "error: release $TAG has no SHA256SUMS.sig (unsigned release) — refusing to update" >&2; exit 1; }

echo "phase: verifying"
expected="$(awk '$2=="blipd-linux-amd64" {print $1; exit}' "$DL/SHA256SUMS")"
[ -n "$expected" ] || { echo "error: no checksum entry for blipd-linux-amd64" >&2; exit 1; }
actual="$(sha256sum "$DL/blipd-linux-amd64" | awk '{print $1}')"
[ "$expected" = "$actual" ] || { echo "error: checksum verification failed — refusing to install" >&2; exit 1; }

install -m 0755 "$DL/blipd-linux-amd64" "$WORK/blipd.new"
# Stage the sums + signature for the root helper: it re-verifies the signature
# (embedded key) and then the staged inode against the SIGNED sums entry.
install -m 0644 "$DL/SHA256SUMS" "$WORK/SHA256SUMS"
install -m 0644 "$DL/SHA256SUMS.sig" "$WORK/SHA256SUMS.sig"

# Hand the verified (unprivileged) binary to the root install helper.
# Pass the verified checksum too: the root side cross-checks it against the
# SIGNED SHA256SUMS — never retry without the checksum.
install_out="$(sudo -n EXPECTED_SHA256="$expected" /usr/local/sbin/blipd-install "$WORK/blipd.new" 2>&1)" && install_rc=0 || install_rc=$?
printf '%s\n' "$install_out"
if [[ "$install_rc" -ne 0 ]]; then
  if [[ "$install_out" == *"environment"* || "$install_out" == *"EXPECTED_SHA256 not set"* ]]; then
    echo "error: sudo stripped EXPECTED_SHA256 (sudoers missing env_keep); re-run install-blipd.sh to refresh sudoers, then retry" >&2
  fi
  exit "$install_rc"
fi
# Refresh the installed-version stamp for future downgrade checks.
if [[ "$TAG" != "dev" ]]; then
  printf '%s\n' "${TAG#v}" > "$WORK/.installed-version" 2>/dev/null || true
fi
echo "phase: done"

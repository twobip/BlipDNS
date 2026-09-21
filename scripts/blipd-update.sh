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

# M14: best-effort downgrade guard. blipd has no --version flag, so probe the
# local management API, then binary strings, then the last recorded stamp.
# Unknown current version => warn and continue. Set ALLOW_DOWNGRADE=1 to
# bypass the check explicitly. The "dev" rolling tag is exempt (no ordering).
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
current_version_best_effort() {
  local v=""
  if command -v curl >/dev/null 2>&1; then
    v="$(curl -fsSL --max-time 3 http://127.0.0.1:8444/api/v1/stats 2>/dev/null | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | grep -o '[0-9][0-9.]*' | head -n1 || true)"
  fi
  if [[ -z "$v" && -x /usr/local/bin/blipd ]]; then
    v="$(strings /usr/local/bin/blipd 2>/dev/null | grep -o 'blipd/[0-9][0-9.]*' | head -n1 | cut -d/ -f2 || true)"
  fi
  if [[ -z "$v" && -f "$WORK/.installed-version" ]]; then
    v="$(tr -d '[:space:]' < "$WORK/.installed-version" 2>/dev/null || true)"
  fi
  printf '%s' "$v"
}
if [[ "$TAG" != "dev" && "${ALLOW_DOWNGRADE:-0}" != "1" ]]; then
  CUR="$(current_version_best_effort || true)"
  if [[ -n "$CUR" ]]; then
    TARGET="${TAG#v}"
    if [[ "$(semver_cmp "$TARGET" "$CUR")" == "2" ]]; then
      echo "error: refusing downgrade $CUR -> $TARGET (set ALLOW_DOWNGRADE=1 to bypass)" >&2; exit 1
    fi
  else
    echo "warning: installed version unknown — downgrade check skipped (no --version flag; probed API/strings/stamp)" >&2
  fi
fi

echo "phase: downloading ($TAG)"
DL="$(mktemp -d "$WORK/dl.XXXXXX")"
trap 'rm -rf "$DL"' EXIT
curl -fL --proto '=https' --tlsv1.2 "$BASE/$TAG/blipd-linux-amd64" -o "$DL/blipd-linux-amd64"
curl -fsSL --proto '=https' --tlsv1.2 "$BASE/$TAG/SHA256SUMS" -o "$DL/SHA256SUMS"

echo "phase: verifying"
expected="$(awk '$2=="blipd-linux-amd64" {print $1; exit}' "$DL/SHA256SUMS")"
[ -n "$expected" ] || { echo "error: no checksum entry for blipd-linux-amd64" >&2; exit 1; }
actual="$(sha256sum "$DL/blipd-linux-amd64" | awk '{print $1}')"
[ "$expected" = "$actual" ] || { echo "error: checksum verification failed — refusing to install" >&2; exit 1; }

install -m 0755 "$DL/blipd-linux-amd64" "$WORK/blipd.new"

# Hand the verified (unprivileged) binary to the root install helper.
# Pass the verified checksum so the root side can re-verify (H2). Sudo
# without SETENV rejects VAR=val assignments, so retry bare only when sudo
# itself complains about the environment (the helper warns and still
# enforces path/ELF checks). Genuine install failures propagate as-is.
install_out="$(sudo -n EXPECTED_SHA256="$expected" /usr/local/sbin/blipd-install "$WORK/blipd.new" 2>&1)" && install_rc=0 || install_rc=$?
printf '%s\n' "$install_out"
if [[ "$install_rc" -ne 0 && "$install_out" == *"environment"* ]]; then
  echo "warning: sudo rejected the checksum env, retrying without it" >&2
  sudo -n /usr/local/sbin/blipd-install "$WORK/blipd.new"
elif [[ "$install_rc" -ne 0 ]]; then
  exit "$install_rc"
fi
# Record the installed version stamp for future downgrade checks (M14).
if [[ "$TAG" != "dev" ]]; then
  printf '%s\n' "${TAG#v}" > "$WORK/.installed-version" 2>/dev/null || true
fi
echo "phase: done"

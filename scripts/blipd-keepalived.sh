#!/bin/bash
set -euo pipefail
# Pin PATH before any external command runs. This helper executes as root
# through sudo; when the host's sudoers has no secure_path, sudo preserves the
# caller's PATH, and a compromised blipd account could shadow keepalived,
# systemctl, pkill, flock or mktemp with binaries it controls. A fixed,
# root-owned search path is the primary defense (the sudoers snippet sets
# secure_path as well, but existing installs may predate it). Every command in
# this file resolves from here.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

# Root half of the HA apply path.
#
# blipd previously wrote /var/lib/blipd/keepalived.conf (service-owned) and
# reloaded keepalived via sudo. Because keepalived executes vrrp_script and
# notify_* commands as root, a compromised blipd account could write an
# arbitrary directive and escalate to root.
#
# This helper is the only permitted writer of the keepalived config. It takes
# structured fields (never a pre-rendered config), validates every value, and
# renders a fixed template itself. There is no field that can introduce a new
# keepalived directive, so the service user cannot smuggle in a root command.

readonly CONF_DIR="/etc/keepalived"
readonly CONF="$CONF_DIR/keepalived.conf"
readonly LOCK_FILE="/run/lock/blipd-keepalived.lock"

die() { echo "blipd-keepalived: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "must run as root"
[[ "$#" -eq 10 ]] || die "usage: blipd-keepalived MODE ROLE IFACE SOURCE_IP PEER_IP VIP VRID PRIORITY ADVERT AUTH_PASS"

mode="$1"
role="$2"
iface="$3"
source_ip="$4"
peer_ip="$5"
virtual_ip="$6"
vrid="$7"
priority="$8"
advert="$9"
auth_pass="${10}"

[[ "$mode" == "unicast" || "$mode" == "multicast" ]] || die "invalid mode"
[[ "$role" == "primary" || "$role" == "secondary" ]] || die "invalid role"
[[ "$iface" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] || die "invalid interface"
[[ "$source_ip" =~ ^[0-9A-Fa-f:.]{2,64}$ ]] || die "invalid source_ip"
[[ "$virtual_ip" =~ ^[0-9A-Fa-f:.]{2,64}/[0-9]{1,3}$ ]] || die "invalid virtual_ip"
[[ "$vrid" =~ ^[0-9]{1,3}$ ]] || die "invalid virtual_router_id"
[[ "$priority" =~ ^[0-9]{1,3}$ ]] || die "invalid priority"
[[ "$advert" =~ ^[0-9]{1,2}$ ]] || die "invalid advert_interval_sec"
[[ "$auth_pass" =~ ^[A-Za-z0-9]{0,8}$ ]] || die "invalid auth_pass"

vip_addr="${virtual_ip%/*}"
vip_prefix="${virtual_ip##*/}"
if [[ "$vip_addr" == *:* ]]; then
  (( vip_prefix >= 1 && vip_prefix <= 128 )) || die "invalid IPv6 prefix"
else
  (( vip_prefix >= 1 && vip_prefix <= 32 )) || die "invalid IPv4 prefix"
fi
(( vrid >= 1 && vrid <= 255 )) || die "virtual_router_id must be 1-255"
(( priority >= 1 && priority <= 254 )) || die "priority must be 1-254"
(( advert >= 1 && advert <= 60 )) || die "advert_interval_sec must be 1-60"

if [[ "$mode" == "unicast" ]]; then
  [[ "$peer_ip" =~ ^[0-9A-Fa-f:.]{2,64}$ ]] || die "invalid peer_ip"
  [[ "$peer_ip" != "$source_ip" ]] || die "peer_ip must differ from source_ip"
  if [[ "$source_ip" == *:* && "$vip_addr" != *:* ]] || [[ "$source_ip" != *:* && "$vip_addr" == *:* ]]; then
    die "source_ip and virtual_ip must use the same address family"
  fi
  if [[ "$peer_ip" == *:* && "$vip_addr" != *:* ]] || [[ "$peer_ip" != *:* && "$vip_addr" == *:* ]]; then
    die "peer_ip and virtual_ip must use the same address family"
  fi
else
  [[ -z "$peer_ip" ]] || die "peer_ip must be empty in multicast mode"
fi

command -v keepalived >/dev/null 2>&1 || die "keepalived is not installed"
[[ -d "$CONF_DIR" ]] || die "$CONF_DIR is missing; re-run install-blipd.sh"

# Serialize applies. /run/lock is root-owned, and a pre-existing symlink is
# never followed.
if [[ -L "$LOCK_FILE" ]]; then die "lock $LOCK_FILE is a symlink"; fi
mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -n 9 || die "another keepalived apply is in progress"

tmp="$(mktemp "$CONF_DIR/.keepalived.XXXXXX")"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

state="BACKUP"
if [[ "$role" == "primary" ]]; then state="MASTER"; fi

{
  printf 'global_defs {\n    router_id blipd-ha\n    enable_script_security\n}\n\n'
  printf 'vrrp_script chk_blipd {\n    script "/usr/bin/systemctl is-active --quiet blipd"\n    user blip\n    interval 2\n    fall 2\n    rise 2\n    weight -20\n}\n\n'
  printf 'vrrp_instance BLIPDNS {\n'
  printf '    state %s\n' "$state"
  printf '    interface %s\n' "$iface"
  printf '    virtual_router_id %s\n' "$vrid"
  printf '    priority %s\n' "$priority"
  printf '    advert_int %s\n' "$advert"
  if [[ "$mode" == "unicast" ]]; then
    printf '    unicast_src_ip %s\n    unicast_peer {\n        %s\n    }\n' "$source_ip" "$peer_ip"
  fi
  if [[ -n "$auth_pass" ]]; then
    printf '    authentication {\n        auth_type PASS\n        auth_pass %s\n    }\n' "$auth_pass"
  fi
  printf '    virtual_ipaddress {\n        %s dev %s\n    }\n    track_script {\n        chk_blipd\n    }\n}\n' "$virtual_ip" "$iface"
} > "$tmp"

# Validate the rendered file before replacing the live config. A failure here
# leaves the previous config untouched.
keepalived -t -f "$tmp" >/dev/null 2>&1 || die "keepalived rejected the rendered configuration"

chown root:root "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$CONF"

# Reload: systemd first, then SIGHUP for units without ExecReload.
if systemctl reload keepalived >/dev/null 2>&1; then
  exit 0
fi
if pkill -HUP keepalived >/dev/null 2>&1; then
  exit 0
fi
die "keepalived reload failed (systemctl reload and pkill -HUP both failed)"

#!/usr/bin/env bash
set -euo pipefail
usage(){ echo "Usage: $0 --public-key FILE --user USER --service UNIT [--service UNIT ...] [--allow-power]" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
key= user= allow_power=0; services=()
while (($#)); do case "$1" in --public-key) key=${2:-};shift 2;;--user) user=${2:-};shift 2;;--service) services+=("${2:-}");shift 2;;--allow-power) allow_power=1;shift;;*) usage;;esac;done
[[ -f $key && $user =~ ^[A-Za-z_][A-Za-z0-9_-]*$ && ${#services[@]} -gt 0 ]] || usage
home=$(getent passwd "$user"|cut -d: -f6); install -d -m 700 -o "$user" -g "$user" "$home/.ssh"
touch "$home/.ssh/authorized_keys"; grep -qxF "$(cat "$key")" "$home/.ssh/authorized_keys" || cat "$key" >>"$home/.ssh/authorized_keys"
chown "$user:$user" "$home/.ssh/authorized_keys";chmod 600 "$home/.ssh/authorized_keys"
systemctl_bin=$(command -v systemctl);rules=()
for unit in "${services[@]}";do [[ $unit =~ ^[A-Za-z0-9_.@:-]+\.service$ ]] || { echo "Invalid service: $unit" >&2;exit 1; };for verb in start stop restart;do rules+=("$systemctl_bin $verb $unit");done;done
((allow_power))&&rules+=("$systemctl_bin reboot" "$systemctl_bin poweroff")
printf '%s ALL=(root) NOPASSWD: %s\n' "$user" "$(IFS=', ';echo "${rules[*]}")" >/etc/sudoers.d/pinoc-management
chmod 440 /etc/sudoers.d/pinoc-management;visudo -cf /etc/sudoers.d/pinoc-management
echo "Installed key and narrowly scoped PiNOC rules. Host enrollment must still be performed from PiNOC with ssh-keyscan and out-of-band fingerprint verification."

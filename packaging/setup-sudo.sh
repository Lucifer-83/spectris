#!/usr/bin/env bash
# One-time setup: grant passwordless sudo for the WiFi Pentest Toolkit's wireless
# tools, so the backend's `sudo -n <tool>` calls run without a password prompt
# (that prompt is why attacks showed "sudo: a password is required").
#
#   sudo bash packaging/setup-sudo.sh
#
# Removes the grant again with:  sudo rm /etc/sudoers.d/wifi-pentest-toolkit
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run me with sudo:  sudo bash packaging/setup-sudo.sh" >&2
  exit 1
fi

USER_NAME="${SUDO_USER:-$USER}"
TOOLS=(iw ip nmcli airodump-ng aireplay-ng airmon-ng hcxdumptool reaver bully hostapd dnsmasq iptables)

paths=()
for t in "${TOOLS[@]}"; do
  p="$(command -v "$t" 2>/dev/null || true)"
  [ -n "$p" ] && paths+=("$p")
done

# `kill` is a shell builtin, so `command -v` won't yield a binary path — add the
# real binary explicitly. The backend needs it to stop root-owned tools
# (sudo -n kill -<sig> -<pgid>); without it, captures/AP "won't stop".
for k in /usr/bin/kill /bin/kill; do
  [ -x "$k" ] && paths+=("$k") && break
done

if [ "${#paths[@]}" -eq 0 ]; then
  echo "None of the wireless tools were found on PATH — install them first (see Setup > System tools)." >&2
  exit 1
fi

IFS=,; cmds="${paths[*]}"; unset IFS
target=/etc/sudoers.d/wifi-pentest-toolkit
echo "$USER_NAME ALL=(root) NOPASSWD: $cmds" > "$target"
chmod 440 "$target"
visudo -c -f "$target"

echo
echo "Done — '$USER_NAME' can now run these tools without a sudo password:"
printf '  %s\n' "${paths[@]}"

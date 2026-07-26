#!/bin/bash
# ============================================================
#  Spectris — package post-install hook (deb & rpm)
#
#  Grants PASSWORDLESS sudo for ONLY the wireless tools the backend drives,
#  so `sudo -n <tool>` works with zero manual setup. Without this, monitor
#  mode / scan / capture / deauth all fail with "sudo: a password is required"
#  unless the user first runs start.sh.
#
#  Scoped to specific binaries (not blanket root) and removed on uninstall
#  (see postremove.sh). This is a security-sensitive grant appropriate for a
#  wireless-assessment tool the operator installs deliberately.
# ============================================================
set -e

# Wireless tools live in sbin dirs; make sure they're searchable even if the
# maintainer-script PATH is minimal.
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# The user who will actually run the app: the invoker of the install, else the
# console login, else the first regular (uid>=1000) account.
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
  TARGET_USER="$(logname 2>/dev/null || true)"
fi
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
  TARGET_USER="$(getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1; exit}')"
fi
if [ -z "$TARGET_USER" ]; then
  echo "spectris: no target user found — skipping sudo setup (run packaging/setup-sudo.sh manually)." >&2
  exit 0
fi

TOOLS="iw ip nmcli airodump-ng aireplay-ng airmon-ng hcxdumptool reaver bully hostapd dnsmasq iptables"
paths=""
for t in $TOOLS; do
  p="$(command -v "$t" 2>/dev/null || true)"
  [ -n "$p" ] && paths="${paths:+$paths,}$p"
done
# `kill` is a shell builtin; the backend needs the real binary to stop
# root-owned tools (sudo -n kill -<sig> -<pgid>).
for k in /usr/bin/kill /bin/kill; do
  [ -x "$k" ] && paths="${paths:+$paths,}$k" && break
done

if [ -z "$paths" ]; then
  echo "spectris: wireless tools not found yet — sudo grant skipped." >&2
  exit 0
fi

target=/etc/sudoers.d/spectris
umask 077
echo "$TARGET_USER ALL=(root) NOPASSWD: $paths" > "$target"
chmod 440 "$target"

# Never leave a broken sudoers file — validate, and drop it if invalid.
if command -v visudo >/dev/null 2>&1 && ! visudo -cf "$target" >/dev/null 2>&1; then
  rm -f "$target"
  echo "spectris: sudoers validation failed — grant not applied." >&2
  exit 0
fi

echo "spectris: passwordless sudo granted to '$TARGET_USER' for wireless tools."
exit 0

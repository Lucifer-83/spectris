#!/usr/bin/env bash
# Start Spectris — backend + desktop app.
#
#   bash start.sh
#
# If anything misbehaves:  bash stop.sh   then   bash start.sh
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$ROOT/backend/dist/wifi-backend/wifi-backend"
APP="$ROOT/gui/release/linux-unpacked/spectris"

# clean any previous instance so restarts are reliable
pkill -f "linux-unpacked/spectris" 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true
sleep 2

if [ ! -x "$BACKEND" ]; then
  echo "[!] backend binary not found — build it first:  cd gui && npm run dist:linux" >&2
  exit 1
fi

# Take sudo up front — the wireless tools (airodump, aireplay, reaver, hostapd…)
# run as root via `sudo -n`, so we grant passwordless sudo for them now, once,
# with a single password prompt. If it's denied or fails, we do NOT start the
# tool at all — every attack tab would just fail with "sudo: a password is
# required", so there's no point launching without it.
echo "[*] granting sudo for the wireless tools (you'll be asked for your password once) ..."
if ! sudo bash "$ROOT/packaging/setup-sudo.sh"; then
  echo "[!] sudo was not granted — the toolkit needs root to drive the wireless hardware." >&2
  echo "    Nothing was started. Re-run 'bash start.sh' and enter your password when prompted." >&2
  exit 1
fi

# Clean up any stuck root-owned wireless tools left by a previous run — they hold
# the adapters and can't be killed from the (non-root) app. sudo is fresh from the
# grant above, so this won't re-prompt.
echo "[*] clearing any leftover wireless tool processes ..."
for t in hcxdumptool airodump-ng aireplay-ng reaver bully hostapd dnsmasq; do
  sudo pkill -x "$t" 2>/dev/null || true
done

echo "[*] starting backend (127.0.0.1:8000) ..."
setsid "$BACKEND" >/tmp/wifi-backend.log 2>&1 </dev/null &
disown

# wait until the backend answers
for _ in $(seq 1 30); do
  if curl -s -o /dev/null http://127.0.0.1:8000/tools/status; then break; fi
  sleep 0.5
done
echo "[+] backend up. log: /tmp/wifi-backend.log"

echo "[*] launching app ..."
setsid "$APP" --no-sandbox >/tmp/wifi-app.log 2>&1 </dev/null &
disown

echo "[+] done. The app window should open. Backend is already online —"
echo "    in Setup just press 'Refresh' (or 'Start backend & detect adapter')."
echo "    Logs: /tmp/wifi-backend.log  and  /tmp/wifi-app.log"

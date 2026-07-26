#!/usr/bin/env bash
# Stop Spectris and RETURN THE BOX TO NORMAL — stop attacks,
# revert monitor mode back to managed, undo the evil-twin network changes, free
# the ports, and close the app + backend. So the next `bash start.sh` is clean.
#
#   bash stop.sh
set -u

# 1) ask the backend to revert everything first (monitor->managed, stop attacks,
#    remove iptables redirect). It runs as the user with the sudo grant, so this
#    is the reliable path. Give it a few seconds (monitor toggles take a moment).
echo "[*] reverting adapters + stopping attacks (via backend) ..."
curl -s -m 15 -X POST http://127.0.0.1:8000/engagement/shutdown >/dev/null 2>&1 || true

echo "[*] closing app ..."
pkill -f "linux-unpacked/spectris" 2>/dev/null || true

echo "[*] stopping backend + freeing ports ..."
fuser -k 8000/tcp 2>/dev/null || true   # backend API
fuser -k 5333/tcp 2>/dev/null || true   # captive portal
pkill -f "wifi-backend/wifi-backend" 2>/dev/null || true

# 2) belt-and-suspenders: kill any leftover root-owned wireless tools (the grant
#    makes kill passwordless). They hold the adapters if the backend was killed
#    before it could stop them.
for t in hcxdumptool airodump-ng aireplay-ng reaver bully hostapd dnsmasq; do
  for pid in $(pgrep -x "$t" 2>/dev/null); do sudo -n kill "$pid" 2>/dev/null || true; done
done

sleep 1
echo "[+] stopped and reverted. Next 'bash start.sh' will start clean."

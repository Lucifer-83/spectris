#!/usr/bin/env bash
# ============================================================
#  Build a DISTRO-PORTABLE backend.
#
#  Freezes the backend inside Debian bullseye (glibc 2.31) via Docker, so the
#  binary runs on any Linux with glibc >= 2.31 (Ubuntu 20.04+, Debian 11+,
#  Fedora, RHEL, Kali). Replaces backend/dist/wifi-backend in place.
#
#  Usage (on the build machine, with Docker available):
#     bash packaging/build-portable-backend.sh
# ============================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE=spectris-backend-portable

if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker isn't reachable. Start it and grant access first:" >&2
  echo "      sudo systemctl start docker" >&2
  echo "      sudo chown \"\$USER\" /var/run/docker.sock" >&2
  exit 1
fi

echo "[*] Building portable backend image (Debian bullseye / glibc 2.31)…"
docker build -f packaging/Dockerfile.backend -t "$IMAGE" .

echo "[*] Extracting frozen backend -> backend/dist/wifi-backend …"
cid="$(docker create "$IMAGE")"
rm -rf backend/dist/wifi-backend
mkdir -p backend/dist
docker cp "$cid:/build/dist/wifi-backend" backend/dist/wifi-backend
docker rm "$cid" >/dev/null

echo "[+] Done: backend/dist/wifi-backend (portable)."
echo "    Now repackage:  cd gui && npx electron-builder --linux AppImage deb rpm"

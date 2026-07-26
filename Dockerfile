# syntax=docker/dockerfile:1
# =============================================================================
# WiFi Pentest Toolkit — single self-contained image.
# End users install nothing else: all wireless tooling + the backend + the
# built web UI ship inside. Open http://localhost:8000 in a browser.
#
# Requires host wireless hardware access at run time — see docker-compose.yml
# (Linux: privileged + host networking; Mac cannot pass a USB WiFi adapter into
# Docker, so real attacks are Linux/Windows-WSL2 only).
# =============================================================================

# ---- Stage 1: build the React/Vite web UI ----------------------------------
FROM node:22-slim AS webbuild
WORKDIR /gui
COPY gui/package.json gui/package-lock.json ./
RUN npm ci
COPY gui/ ./
RUN npm run build

# ---- Stage 2: runtime with the pentest toolchain ---------------------------
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive

# Wireless attack tooling + python. sudo is included because the app shells out
# via `sudo -n` (as root in the container that is a no-op that still succeeds).
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
      sudo iproute2 iw iptables wireless-tools \
      aircrack-ng reaver bully hcxdumptool hcxtools wifite \
      hostapd dnsmasq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r backend/requirements.txt

COPY backend/ ./backend/
# built UI is served by FastAPI from ./static (see app.main static mount)
COPY --from=webbuild /gui/dist ./backend/static

WORKDIR /app/backend
EXPOSE 8000
# uvicorn on 0.0.0.0 so the host browser can reach it (host networking at run time)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

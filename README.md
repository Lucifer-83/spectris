<div align="center">

<img src="docs/icon.png" width="120" alt="Spectris logo" />

# Spectris

**_Nothing on the air stays hidden._**

A premium, guided **Wi-Fi penetration-testing toolkit** for **authorized** security assessments —
scan, capture, crack, WPS, deauth, and evil-twin captive portals, all **scope-gated** and
**audit-logged** by design.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux-2563eb.svg)
![Backend](https://img.shields.io/badge/backend-Python%20·%20FastAPI-3776ab.svg)
![Frontend](https://img.shields.io/badge/frontend-React%20·%20TypeScript%20·%20Electron-4d9dff.svg)

</div>

---

> ⚠️ **Authorized engagements only.** Use Spectris **only** on networks you own or have explicit
> written permission to test. Every hardware action is checked against an engagement scope you define
> *before* it runs, and every action is written to an immutable audit log — do not remove those
> guardrails. Unauthorized use of these techniques is illegal in most jurisdictions.

## Why Spectris

The Wi-Fi security space is full of powerful tools (aircrack-ng, wifite, reaver…) — all of them
raw CLIs. Spectris wraps that same battle-tested tooling in a **clean, guided desktop app** with a
real safety model: you declare an authorized **scope**, and the backend simply refuses to touch any
BSSID/SSID that isn't in it — with a tamper-evident audit trail of everything it did.

## Features

| Step | What it does | Tools wrapped |
|------|--------------|---------------|
| **Setup** | Detect adapters, monitor mode, tool checks, hashcat benchmark | `iw`, `ip`, `hashcat` |
| **Scope** | Declare authorized BSSIDs / SSIDs — the core safety guardrail | — |
| **Scan & Target** | Discover nearby APs (signal, clients, encryption, WPS) and pick an in-scope target | `airodump-ng`, `wash` |
| **Auto (1-click)** | Capture → deauth → convert → crack, end-to-end | (chained) |
| **Handshake Capture** | Automatic WPA/WPA2 handshake / PMKID capture, auto-converts for hashcat | `hcxdumptool`, `hcxpcapngtool` |
| **WPS Attack** | **Pixie Dust** (offline) and online PIN attacks | `reaver`, `bully`, `pixiewps` |
| **Deauth** | Kick clients off a scope-authorized AP (bounded or continuous) | `aireplay-ng` |
| **Crack** | Offline PSK recovery — wordlist / rules / mask, GPU or CPU | `hashcat`, `aircrack-ng` |
| **Evil Twin** | Rogue AP + generic captive portal that verifies the real Wi-Fi password against a captured handshake; continuous deauth until captured | `hostapd`, `dnsmasq`, `iptables` |
| **Results & Log** | Immutable audit trail of every action, scope check, and rejection | SQLite |

## Screenshots

> _Add screenshots of the running app here (Setup, Scan & Target, Crack, Evil Twin)._

<p align="center"><img src="docs/hero.png" width="360" alt="Spectris" /></p>

## Install (Linux)

Download a release artifact and run it — no build needed.

**AppImage** (any distro — Ubuntu, Fedora, Debian, Arch, Kali):

```bash
chmod +x Spectris-1.0.0.AppImage
./Spectris-1.0.0.AppImage
```

**Debian / Ubuntu / Kali** (`.deb`) — also pulls in the wireless tools automatically:

```bash
sudo apt install ./spectris_1.0.0_amd64.deb
spectris
```

**Fedora / RHEL** (`.rpm`):

```bash
sudo dnf install ./spectris-1.0.0.x86_64.rpm
```

> The attack tools run as root via passwordless `sudo` (granted once for a fixed allowlist of
> wireless binaries — see `packaging/setup-sudo.sh`). On first run, use `./start.sh` which grants it,
> starts the backend, and launches the app.

### Platform support

Wi-Fi monitor mode + injection needs a **Linux kernel** and an adapter whose driver supports it — so
the universal path is **Linux (native or a Linux VM) with a compatible USB adapter**. Packaging makes
it install-free, but it can't change that hardware requirement.

| Platform | Status | How |
|----------|--------|-----|
| **Linux (native)** | ✅ Full | AppImage / `.deb` / `.rpm` + a compatible adapter |
| **Linux VM** (VirtualBox / VMware) | ✅ Full | Pass an external USB Wi-Fi adapter through to the VM |
| **Windows** | 🟡 Experimental | WSL2 + `usbipd-win` + external USB adapter (needs a wireless-capable WSL2 kernel) |
| **macOS** | ⚠️ Limited | Needs a full Linux VM + USB adapter passthrough; internal Wi-Fi can't do monitor mode |

**Recommended adapters:** Ralink `rt2800usb`, Atheros `ath9k_htc`. **Often problematic:** Realtek
RTL88xxAU on the in-kernel `rtw88` driver (sets monitor mode but usually captures nothing).

## Architecture

- **`backend/`** — Python **FastAPI** service on `127.0.0.1:8000`. One module per capability
  (`adapter`, `scan`, `capture`, `wps`, `deauth`, `eviltwin`, `portal`, `crack`), a **`scope`**
  guardrail singleton every hardware action must pass, and a SQLite **audit log**. Root tools are
  launched in their own process group so they can be reliably stopped (`procs.py`).
- **`gui/`** — **React 19 + TypeScript + Vite** premium UI, packaged with **Electron** into a
  frameless desktop app (Light/Dark theme, liquid-glass transparency), or served over HTTP.

## Run from source (development)

```bash
# backend
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --port 8000

# GUI (dev server)
cd gui && npm install && npm run dev            # http://localhost:5173
# or the full Electron desktop app:
cd gui && npm run electron:dev

# build the Linux packages (AppImage + .deb + .rpm)
cd gui && npm run dist:packages
```

## Tests

```bash
cd backend && .venv/bin/pytest      # scope-gating, command building, parsing, portal capture
```

## License

[MIT](LICENSE) © 2026 Tejas Patil

# Setup

Prep the environment before any assessment — verify prerequisites, confirm the wireless tools are
installed, and benchmark your crack speed so later time estimates are realistic.

## What this step does

- **Detects your Wi-Fi adapters** and whether each can enter monitor mode.
- **Checks the required tools** are present (`aircrack-ng`, `hcxdumptool`, `hcxpcapngtool`,
  `reaver`, `bully`, `pixiewps`, `hashcat`, `iw`, `ip`).
- **Runs a hashcat benchmark** (WPA/WPA2 mode 22000) so the Crack tab can estimate how long a
  wordlist or mask will take on *your* hardware.
- Grants the fixed, passwordless `sudo` allowlist the attack tools need (see `packaging/setup-sudo.sh`).

## Requirements

- A **Linux kernel** (native or a Linux VM). Wi-Fi monitor mode and injection are Linux features.
- An adapter whose driver supports **monitor mode + injection** — ideally an external USB adapter
  (see [Adapters](Adapters.md)).
- The wireless tools installed. The `.deb` / `.rpm` packages pull most of them in automatically.

## Tips

- If a tool shows as missing, install it from your distro's repos (`apt install aircrack-ng
  hcxtools reaver`, or the Fedora/RHEL equivalents).
- A GPU dramatically speeds up cracking. The benchmark will show hashes/sec — a higher number means
  shorter crack times later.

---

*Part of [Spectris](README.md). Authorized engagements only.*

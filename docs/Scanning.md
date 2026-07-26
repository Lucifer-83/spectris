# Scanning

Discover the Wi-Fi networks around you — their signal strength, connected clients, encryption type,
channel, and whether **WPS** is enabled — then pick an **in-scope** target to work on.

## What you see

| Column | Meaning |
|--------|---------|
| **SSID / BSSID** | Network name and the AP's MAC address |
| **Signal** | Strength (closer/stronger = more reliable attacks) |
| **Clients** | How many devices are connected (needed for deauth / handshake capture) |
| **Encryption** | Open / WEP / WPA / WPA2 / WPA3 |
| **WPS** | Whether WPS is on (a potential [Pixie Dust](WPS-Pixie-Dust.md) path) |

## How it works

Spectris puts the adapter into monitor mode and runs `airodump-ng` (and `wash` for WPS detection),
then parses the results into the live table. Signal and client counts update as it listens.

## Picking a target

- Only **in-scope** networks (see [Engagement Scope](Engagement-Scope.md)) can be selected — the
  rest are locked.
- Prefer a **strong signal** and, for handshake/deauth work, a target **with at least one client**.
- Note the **encryption** — it decides which attack path makes sense (WPS vs handshake capture vs
  evil-twin).

Selecting a target carries its BSSID, channel, and SSID into the other tabs automatically.

---

*Part of [Spectris](README.md). Authorized engagements only.*

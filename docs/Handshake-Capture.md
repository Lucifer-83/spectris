# Handshake Capture

Capture the material needed to crack a WPA/WPA2 network offline — either a **4-way handshake**
(produced when a client joins) or a **PMKID** (which some APs leak without any client). Spectris
auto-converts the capture to a hashcat-ready hash the moment it lands.

**Typical success: ~85%** at *capturing* — but remember, this is capture, **not** cracking.

## The two things you can capture

- **PMKID** — a value some routers include in the first handshake message. It can often be grabbed
  **without any connected client**, directly from the AP.
- **4-way handshake** — the exchange when a client authenticates. Needs a client to join (or
  rejoin) the network — use the [Deauth](Deauth.md) tab to force a reconnect.

## How it works

Spectris runs `hcxdumptool` on the in-scope target's channel to listen for the handshake / PMKID,
then converts the `.pcapng` to the hashcat `22000` format with `hcxpcapngtool`. The result feeds
straight into [Offline Cracking](Offline-Cracking.md).

## Requirements

- An adapter in **monitor mode** (injection needed only if you must deauth for a handshake).
- For a 4-way handshake: **a connected client** on the target.

## Note

> Capturing a handshake proves nothing about the password's strength — you still have to *crack* it
> offline, and that depends entirely on your wordlist.

---

*Part of [Spectris](README.md). Authorized engagements only.*

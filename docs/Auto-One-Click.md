# Auto (1-Click)

The end-to-end pipeline: **capture → deauth → convert → crack** a WPA/WPA2 handshake, in one click.
It chains the individual steps so you don't have to drive each tab by hand.

**Typical success: ~40%** — because the final step is only as good as your wordlist.

## What it chains

1. **Capture** — starts a handshake / PMKID capture on the in-scope target
   (see [Handshake Capture](Handshake-Capture.md)).
2. **Deauth** — briefly kicks a connected client so it reconnects and produces a 4-way handshake
   (see [Deauth](Deauth.md)).
3. **Convert** — turns the captured `.pcapng` into a hashcat `22000` hash (`hcxpcapngtool`).
4. **Crack** — runs the hash against your wordlist with hashcat
   (see [Offline Cracking](Offline-Cracking.md)).

## Requirements

- A **WPA/WPA2** target **with a connected client** (needed to force a handshake).
- An **injection-capable adapter** in monitor mode.
- A **wordlist** — the password must be in it to be recovered.

## What it really hinges on

> As good as your wordlist. A PSK that isn't in the list won't crack, no matter how clean the
> capture is. Use targeted wordlists (region, ISP default patterns, rules/masks) rather than one
> giant generic list.

---

*Part of [Spectris](README.md). Authorized engagements only.*

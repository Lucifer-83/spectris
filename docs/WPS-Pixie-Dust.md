# WPS — Pixie Dust & PIN

Recover the WPA key by attacking **WPS** (Wi-Fi Protected Setup) rather than the password itself.
Two paths: **Pixie Dust** (a fast *offline* attack against weak WPS implementations) and an
**online PIN** brute force.

**Typical success: ~35%** — only against routers that are actually WPS-vulnerable.

## Pixie Dust (offline)

Many routers generate the WPS exchange's nonces with too little entropy. Pixie Dust captures a
single exchange and computes the PIN **offline** in seconds to minutes — no online brute force
needed. Once the PIN is known, the router hands over the WPA passphrase.

## Online PIN

If Pixie Dust doesn't apply, an online attack tries PINs against the AP. This is slow and noisy, and
modern routers **lock out** after a few failures — often making it impractical.

## Engines

| Tool | Notes |
|------|-------|
| **reaver** | Recommended — best-maintained, native `pixiewps` integration |
| **bully** | Alternative engine; try it if reaver stalls |

(`pixiewps` does the offline PIN computation for both.)

## Requirements & limits

- Works only on routers with WPS **enabled, unlocked, and genuinely vulnerable**.
- Needs an **injection-capable adapter** in monitor mode.
- Many vendors have patched Pixie Dust or disabled external-registrar WPS — a "no WPS" or locked AP
  simply won't yield.

---

*Part of [Spectris](README.md). Authorized engagements only.*

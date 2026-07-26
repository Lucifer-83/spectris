# Spectris — Documentation

<img src="icon.png" width="96" alt="Spectris" />

**Spectris** is a premium, guided **Wi-Fi penetration-testing toolkit** for **authorized**
security assessments. These pages are the "Read more about this attack" targets linked from
inside the app — one page per step.

> ⚠️ **Authorized engagements only.** Use Spectris **only** on networks you own or have explicit
> written permission to test. Every hardware action is checked against an engagement scope you
> define *before* it runs, and everything is written to an immutable audit log. Unauthorized use of
> these techniques is illegal in most jurisdictions.

## Steps

| Page | What it covers |
|------|----------------|
| [Setup](Setup.md) | Prerequisites, tool checks, crack-speed benchmark |
| [Adapters](Adapters.md) | Wi-Fi cards, bands, and monitor mode |
| [Engagement Scope](Engagement-Scope.md) | The core safety guardrail — authorizing targets |
| [Scanning](Scanning.md) | Discovering nearby networks |
| [Auto (1-click)](Auto-One-Click.md) | Capture → deauth → convert → crack, end to end |
| [WPS Pixie Dust](WPS-Pixie-Dust.md) | Recovering a key through a WPS flaw |
| [Handshake Capture](Handshake-Capture.md) | Capturing WPA/WPA2 handshakes / PMKID |
| [Deauth](Deauth.md) | Forcing clients to reconnect |
| [Offline Cracking](Offline-Cracking.md) | Recovering the PSK from a captured handshake |
| [Evil Twin](Evil-Twin.md) | Rogue AP + captive portal |
| [Audit Log](Audit-Log.md) | The immutable record of every action |
| [About](About.md) | What Spectris is, platform support, responsible use |

---

The **success percentages** shown in the app are honest rough estimates ("typical", not a
guarantee). Real results depend on your adapter, the target, and your wordlist — each page
explains what it really hinges on.

# Deauth

Send **deauthentication** frames to knock a client off a target AP. When the client automatically
reconnects, it performs the 4-way handshake — which you can [capture](Handshake-Capture.md) and
later [crack](Offline-Cracking.md). Deauth is the usual way to *force* a handshake on demand.

**Typical success: ~80%** at forcing a reconnect.

## How it works

Spectris uses `aireplay-ng` to send deauth frames to the client (or broadcast) on the target's
channel. Output streams live in the app. You can run a **bounded** burst (a set number of frames)
or **continuous** mode (`0` = keep going until you stop it).

## Requirements

- An **injection-capable adapter** in monitor mode.
- A **connected client** on the target — deauth has nothing to disconnect otherwise.
- The correct **channel** (carried over automatically when you select a target in Scan).

## Responsible use

> Deauth is disruptive by nature — it drops real users' connections. Spectris only lets you deauth a
> target that is in your [engagement scope](Engagement-Scope.md), and every deauth is
> [audit-logged](Audit-Log.md). Never deauth a network you aren't authorized to test; broad or
> continuous deauth against others is illegal and harmful.

## Note on modern devices

Many current clients and APs support **802.11w (Protected Management Frames)**, which makes classic
deauth ineffective. If a client won't drop, PMF is a likely reason — consider a PMKID capture
instead.

---

*Part of [Spectris](README.md). Authorized engagements only.*

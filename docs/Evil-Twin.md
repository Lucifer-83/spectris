# Evil Twin

Clone the target AP and stand up a **captive portal** that asks the user for the Wi-Fi password.
Unlike cracking, this is a **social** attack — it succeeds when a real user connects to the clone
and types the password, which the portal then **verifies against a captured handshake** so you know
it's genuine.

**Typical success: ~60%** — but it depends entirely on user behaviour.

## How it works

1. Spectris raises a rogue AP with the **same SSID** using `hostapd`, hands out IPs with `dnsmasq`,
   and redirects all traffic to a local **captive portal** with `iptables`.
2. It runs **continuous [deauth](Deauth.md)** on the real AP so clients drop and are nudged toward
   the clone.
3. When a user submits a password on the portal, it's **checked against the real network's captured
   handshake** — a wrong guess is rejected, so you only accept the true password.

## Requirements

- **Two adapters** — one to host the rogue AP, one to deauth / stay on the real channel.
- A **captured handshake** for the target (so the portal can verify submissions) — see
  [Handshake Capture](Handshake-Capture.md).

## Responsible use

> This impersonates a network and prompts a person for a credential — only ever run it against your
> own [in-scope](Engagement-Scope.md) engagement, with the portal capture consented to in your rules
> of engagement. It is [audit-logged](Audit-Log.md) like everything else. Doing this to the public
> is illegal.

---

*Part of [Spectris](README.md). Authorized engagements only.*

# Adapters

Your Wi-Fi cards — internal vs external, model, supported bands, and whether they can enter
**monitor mode** (the mode that lets you capture raw 802.11 frames and inject packets).

## Why the adapter matters

Most attacks in Spectris need an adapter that supports **monitor mode** *and* **packet injection*.
Many built-in laptop cards can do neither reliably. An external USB adapter with a good chipset is
the single most important piece of hardware for Wi-Fi testing.

## Recommended chipsets

| Chipset / driver | Notes |
|------------------|-------|
| Ralink **rt2800usb** | Reliable monitor + injection, widely supported |
| Atheros **ath9k_htc** | Excellent, well-maintained in-kernel driver |

## Often problematic

- **Realtek RTL88xxAU** on the in-kernel `rtw88` driver — will *set* monitor mode but frequently
  captures nothing and can't inject. If you must use it, the out-of-tree `aircrack-ng/rtl8812au`
  DKMS driver works far better.

## Monitor mode

Spectris switches the chosen adapter into monitor mode for you when a step needs it, and restores
managed mode afterwards. If monitor mode fails, it's almost always a driver limitation — try a
different (external) adapter.

## VM users

Pass an **external USB adapter through to the VM** (VirtualBox/VMware USB passthrough). The VM's
"virtual" NIC can never do monitor mode; only a passed-through physical adapter can.

---

*Part of [Spectris](README.md). Authorized engagements only.*

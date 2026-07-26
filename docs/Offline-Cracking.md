# Offline Cracking

Recover the Wi-Fi password **offline** from a captured handshake / PMKID. Nothing is sent to the
target during this step — it's pure computation against your wordlist or mask.

**Typical success: ~42%** — meaning whether the password happens to be in your list.

## Engines

| Tool | Notes |
|------|-------|
| **hashcat** | Recommended — GPU or CPU, dramatically faster with a GPU |
| **aircrack-ng** | Pure-CPU fallback, no GPU needed |

Both test the **same** candidate passwords, so the *odds* are identical — hashcat is simply much
faster if you have a GPU.

## Attack modes

- **Wordlist** — try each password in a list (e.g. `rockyou.txt`, targeted lists).
- **Rules** — mutate wordlist entries (capitalisation, digits, leetspeak) to cover common human
  patterns without a bigger list.
- **Mask** — brute-force a known structure (e.g. 8–10 digits, or `Name####`). Great for default-PSK
  patterns; infeasible for long random passwords.

Spectris shows **live progress** and an ETA based on your [Setup](Setup.md) benchmark.

## What it really hinges on

> Success = whether the password is in your wordlist / mask space. A long, random WPA2 passphrase is
> effectively uncrackable this way — that's expected, and it's the correct real-world result to
> report. WPA3 (SAE) resists offline cracking by design.

---

*Part of [Spectris](README.md). Authorized engagements only.*

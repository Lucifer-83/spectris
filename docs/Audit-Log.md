# Audit Log

An **immutable record** of every action Spectris takes — each scan, capture, deauth, WPS attempt,
evil-twin session, crack, **and every scope rejection**. It's the accountability half of the safety
model that starts with the [Engagement Scope](Engagement-Scope.md).

## What's recorded

- **Timestamp** and the **action** performed.
- The **target** (BSSID / SSID) and whether it was **in scope**.
- **Scope rejections** — attempts to act on out-of-scope targets are logged as refusals, not silently
  dropped.
- The tool invoked and the outcome.

## Why it matters

- **Proof of good conduct** — you can show a client exactly what was and wasn't touched during the
  engagement.
- **Boundary evidence** — the rejections demonstrate the scope guardrail actually held.
- **Reporting** — the log feeds the assessment's timeline and the exportable report.

## Where it lives

The log is stored in a local SQLite database on the tester's machine. Because it can contain
**sensitive engagement data (including recovered passwords)**, it is **excluded from version
control** (`.gitignore`) and must never be committed or shared outside the engagement.

---

*Part of [Spectris](README.md). Authorized engagements only.*

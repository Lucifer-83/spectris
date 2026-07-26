# Engagement Scope

**The core safety guardrail.** Before Spectris will touch any network, you declare the specific
BSSIDs and/or SSIDs you are **authorized** to test. Every hardware action — scan targeting, deauth,
capture, WPS, evil-twin — is checked against this scope *before* it runs. Anything not in scope is
refused, and the refusal is written to the [Audit Log](Audit-Log.md).

## Why it exists

Wi-Fi attack tools are indiscriminate by default — a deauth or a rogue AP will happily disrupt any
network in range, including your neighbours' or bystanders'. That is both unethical and illegal
without authorization. The scope turns "point at everything" into "act only on what the client
signed off on".

## How to use it

1. Get **written authorization** from the network owner (a signed engagement / rules of engagement).
2. Add the in-scope **BSSIDs** (the AP's MAC) and/or **SSIDs** (the network name) to the scope.
3. Run your assessment. Out-of-scope targets are greyed out / rejected everywhere in the app.

## What it protects

- Prevents accidental disruption of networks you don't own.
- Creates a defensible, auditable boundary for the engagement.
- Pairs with the audit log so you can prove exactly what was and wasn't touched.

> Scope is enforced in the backend, not just the UI — the API rejects out-of-scope requests even if
> they're crafted directly.

---

*Part of [Spectris](README.md). Authorized engagements only.*

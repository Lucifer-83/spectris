# About Spectris

**_Nothing on the air stays hidden._**

Spectris is a premium, guided **Wi-Fi penetration-testing toolkit** for **authorized** security
assessments. It wraps battle-tested wireless tools (aircrack-ng, hcxdumptool, reaver, hashcat,
hostapd…) in a clean desktop app with a real safety model: you declare an authorized **scope**, and
the backend refuses to touch anything outside it — with a tamper-evident **audit log** of everything
it did.

## Platform support

Wi-Fi monitor mode + injection needs a **Linux kernel** and an adapter whose driver supports it.

| Platform | Status |
|----------|--------|
| **Linux (native)** | ✅ Full — AppImage / `.deb` / `.rpm` + a compatible adapter |
| **Linux VM** | ✅ Full — pass an external USB Wi-Fi adapter through to the VM |
| **Windows** | 🟡 Experimental — WSL2 + `usbipd-win` + external adapter |
| **macOS** | ⚠️ Limited — needs a Linux VM + USB passthrough |

See [Adapters](Adapters.md) for recommended hardware.

## Architecture

- **Backend** — Python **FastAPI** service; one module per capability, a **scope** guardrail every
  hardware action must pass, and a SQLite audit log.
- **Frontend** — **React + TypeScript + Vite**, packaged with **Electron** into a frameless desktop
  app (light/dark, liquid-glass UI).

## Responsible use

> Spectris exists for **authorized** testing, education, and defensive research. Every offensive
> feature is **scope-gated** and **audit-logged** by design — do not remove those guardrails.
> Unauthorized use of these techniques is illegal in most jurisdictions.

## License

MIT © 2026 Tejas Patil — see [LICENSE](../LICENSE).

---

*Part of [Spectris](README.md).*

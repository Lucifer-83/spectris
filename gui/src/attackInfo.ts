/* ============================================================
   Per-tab metadata: what each step is for (tagline), a "read more"
   docs link, and — for the actual attacks — which tool to prefer and
   a rough real-world success rate.

   The success numbers are HONEST rough estimates ("typical", not a
   guarantee) — every meter carries a caveat about what it really
   depends on. Do not present them as precise.

   👉 Set DOCS_BASE to your project's GitHub wiki/docs once it's up —
   it's the single place that controls every "Read more" link.
   ============================================================ */

export const DOCS_BASE = "https://github.com/kalyanistudio/wifi-pentest-toolkit/wiki";

export interface ToolRating {
  name: string;
  success: number; // rough typical success %, 0–100
  recommended?: boolean;
  note?: string;
}

export interface AttackInfo {
  /** one-liner shown under the sidebar label and in the view header */
  tagline: string;
  /** "Read more about this attack" target (GitHub) */
  doc: string;
  /** headline effectiveness for the header meter (omit for non-attack tabs) */
  success?: number;
  /** engine comparison, for tabs that offer a tool choice */
  tools?: ToolRating[];
  /** honest note about what the % really hinges on */
  caveat?: string;
}

const page = (slug: string) => `${DOCS_BASE}/${slug}`;

export const ATTACK_INFO: Record<string, AttackInfo> = {
  setup: {
    tagline: "Prep the environment — prerequisites, tools and crack-speed benchmark.",
    doc: page("Setup"),
  },
  adapters: {
    tagline: "Your Wi-Fi cards — internal vs external, model, bands, and monitor mode.",
    doc: page("Adapters"),
  },
  scope: {
    tagline: "Define the networks you're authorized to test — every attack is gated on this.",
    doc: page("Engagement-Scope"),
  },
  scan: {
    tagline: "Discover nearby networks with signal, clients, encryption and WPS status.",
    doc: page("Scanning"),
  },
  auto: {
    tagline: "One click: capture → deauth → convert → crack a WPA/WPA2 handshake.",
    doc: page("Auto-One-Click"),
    success: 40,
    tools: [{ name: "hashcat pipeline", success: 40, recommended: true }],
    caveat: "As good as your wordlist — a PSK that isn't in the list won't crack. Needs a WPA/WPA2 target with a connected client.",
  },
  wps: {
    tagline: "Recover the WPA key through a WPS flaw — Pixie Dust (offline) or online PIN.",
    doc: page("WPS-Pixie-Dust"),
    success: 35,
    tools: [
      { name: "reaver", success: 35, recommended: true, note: "best-maintained, native pixiewps" },
      { name: "bully", success: 30, note: "alternative engine, try if reaver stalls" },
    ],
    caveat: "Only works on routers with WPS enabled, unlocked, and actually vulnerable. Needs an injection-capable adapter in monitor mode.",
  },
  action: {
    tagline: "Automatic WPA/WPA2 handshake / PMKID capture — auto-converts when it lands.",
    doc: page("Handshake-Capture"),
    success: 85,
    tools: [{ name: "hcxdumptool", success: 85, recommended: true }],
    caveat: "This is capture, not cracking. PMKID often lands on its own; a 4-way handshake needs a client — use the Deauth tab to force one.",
  },
  deauth: {
    tagline: "Kick clients off a target AP so they reconnect (forces a handshake).",
    doc: page("Deauth"),
    success: 80,
    tools: [{ name: "aireplay-ng", success: 80, recommended: true }],
    caveat: "Needs an injection-capable adapter in monitor mode and a connected client. 0 = continuous until you stop it.",
  },
  crack: {
    tagline: "Recover the Wi-Fi password offline from a captured handshake.",
    doc: page("Offline-Cracking"),
    success: 42,
    tools: [
      { name: "hashcat", success: 42, recommended: true, note: "GPU/CPU, much faster" },
      { name: "aircrack-ng", success: 42, note: "pure CPU fallback, no GPU needed" },
    ],
    caveat: "Success = whether the password is in your wordlist. Same crack odds for both engines; hashcat is far faster if you have a GPU.",
  },
  eviltwin: {
    tagline: "Clone the AP with a captive portal to harvest the Wi-Fi password from a user.",
    doc: page("Evil-Twin"),
    success: 60,
    tools: [{ name: "hostapd + dnsmasq", success: 60, recommended: true }],
    caveat: "Social, not cryptographic — depends on a user connecting to the clone and typing the password. Needs two adapters.",
  },
  log: {
    tagline: "Immutable audit trail of every action, scope check and rejection.",
    doc: page("Audit-Log"),
  },
  about: {
    tagline: "What Spectris is, platform support, adapters, and responsible use.",
    doc: page("About"),
  },
};

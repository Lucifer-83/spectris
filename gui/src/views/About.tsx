import { Card, Pill } from "../components/ui";
import { IconChip, IconInfo, IconLock } from "../components/icons";
import heroImg from "../assets/spectris-icon.png";

const VERSION = "1.0.0";

type PlatformStatus = "full" | "ok" | "limited";
const PLATFORMS: { os: string; status: PlatformStatus; pill: string; detail: string }[] = [
  {
    os: "Linux (native)",
    status: "full",
    pill: "Full support",
    detail: "The home turf. Run the AppImage or via Docker with a compatible adapter.",
  },
  {
    os: "Linux VM (VirtualBox / VMware)",
    status: "full",
    pill: "Full support",
    detail: "Pass an external USB Wi-Fi adapter through to the VM — monitor mode works inside.",
  },
  {
    os: "Windows",
    status: "ok",
    pill: "Supported",
    detail: "Via WSL2 + usbipd-win + an external USB adapter (the app guides the passthrough).",
  },
  {
    os: "macOS",
    status: "limited",
    pill: "Limited",
    detail:
      "Needs a full Linux VM (Parallels / VMware) + USB adapter passthrough. The internal Wi-Fi can't do monitor mode, and Docker-on-Mac can't pass USB devices through.",
  },
];

const ADAPTERS_GOOD = ["Ralink rt2800usb", "Atheros ath9k_htc"];
const ADAPTERS_TRICKY = ["Realtek RTL88xxAU (in-kernel rtw88 — sets monitor but often captures nothing)"];
const STACK = [
  "Python · FastAPI",
  "React · TypeScript · Vite",
  "Electron",
  "aircrack-ng",
  "hcxtools",
  "reaver / bully",
  "hostapd · dnsmasq",
  "hashcat",
];

export function About() {
  return (
    <div className="view">
      <div className="about-hero">
        <img src={heroImg} alt="Spectris" className="about-hero__img" />
        <div>
          <div className="about-hero__title">
            Spectris <span className="about-hero__ver">v{VERSION}</span>
          </div>
          <div className="about-hero__tag">Nothing on the air stays hidden.</div>
        </div>
      </div>

      <p className="view__intro">
        Spectris is a premium, guided <strong>Wi-Fi penetration-testing toolkit</strong> for{" "}
        <strong>authorized security assessments only</strong>. It wraps the standard Linux wireless tooling
        into one clean workflow — scan &amp; target, handshake capture, WPS Pixie Dust, deauth, offline PSK
        cracking, and evil-twin captive portals — with every action gated to an engagement scope you define
        and written to an immutable audit log.
      </p>

      <Card title="Responsible use" icon={<IconLock size={18} />}>
        <p>
          Only test networks you <strong>own</strong> or have <strong>explicit written permission</strong> to
          assess. Every hardware action is checked against your engagement scope <em>before</em> it runs, and
          every start / stop / capture is recorded (see <strong>Results &amp; Log</strong>). Unauthorized use
          of these techniques is illegal in most jurisdictions — this tool is for professional, authorized
          engagements and learning on your own equipment.
        </p>
      </Card>

      <Card title="Platform support" icon={<IconChip size={18} />}>
        <p className="field__hint" style={{ marginBottom: 12 }}>
          Wi-Fi monitor mode + injection needs a <strong>Linux kernel</strong> and an adapter whose driver
          supports it — so the universal path is <strong>Linux (native or VM) with a compatible USB adapter</strong>.
          Packaging (Docker / AppImage) makes it install-free, but it can't change this hardware requirement.
        </p>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Platform</th>
                <th>Status</th>
                <th>How</th>
              </tr>
            </thead>
            <tbody>
              {PLATFORMS.map((p) => (
                <tr key={p.os}>
                  <td>
                    <strong>{p.os}</strong>
                  </td>
                  <td>
                    <Pill variant={p.status === "full" ? "ok" : p.status === "ok" ? "accent" : "warn"} dot={false}>
                      {p.pill}
                    </Pill>
                  </td>
                  <td>{p.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Wireless adapter" icon={<IconChip size={18} />}>
        <p>
          A monitor-mode + injection-capable adapter is the single most important requirement — most "scan
          finds nothing" problems are the adapter, not the software.
        </p>
        <div>
          <div className="about-label">Recommended</div>
          <div className="about-chips">
            {ADAPTERS_GOOD.map((a) => (
              <Pill key={a} variant="ok" dot={false}>
                {a}
              </Pill>
            ))}
          </div>
        </div>
        <div>
          <div className="about-label">Often problematic</div>
          <div className="about-chips">
            {ADAPTERS_TRICKY.map((a) => (
              <Pill key={a} variant="warn" dot={false}>
                {a}
              </Pill>
            ))}
          </div>
        </div>
      </Card>

      <Card title="Built with" icon={<IconInfo size={18} />}>
        <div className="about-chips">
          {STACK.map((t) => (
            <Pill key={t} dot={false}>
              {t}
            </Pill>
          ))}
        </div>
        <p className="field__hint" style={{ marginTop: 12 }}>
          A FastAPI backend drives the root-level wireless tools; a React + Electron desktop app is the guided
          UI. All attacks are scope-gated and audit-logged by design.
        </p>
      </Card>
    </div>
  );
}

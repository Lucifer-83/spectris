import { useEffect, useRef, useState } from "react";
import { api, type AccessPoint, type ScopeState, type WirelessInterface } from "../api";
import { useTarget } from "../TargetContext";
import { Banner, Button, Card, EmptyState, Field, Input, Pill } from "../components/ui";
import { IconPlay, IconScan, IconStop, IconWps } from "../components/icons";

// rtw88 (in-kernel RTL88xxAU) sets monitor mode but usually captures NOTHING —
// the classic "scan finds no networks" cause. Flag it so we can warn.
const isWeakDriver = (i?: WirelessInterface) => !!i && i.driver.startsWith("rtw88");

/** Numeric dBm for sorting: stronger (closer to 0, e.g. -45) sorts above weaker
 *  (e.g. -85). Unknown/invalid readings sink to the bottom. */
function dbmValue(dbmStr: string): number {
  const dbm = parseInt(dbmStr, 10);
  if (isNaN(dbm) || dbm >= 0 || dbm === -1) return -Infinity;
  return dbm;
}

/** Turn a raw dBm reading into a near/far label + signal bars. */
function signalInfo(dbmStr: string): { bars: number; label: string; variant: string } {
  const dbm = parseInt(dbmStr, 10);
  if (isNaN(dbm) || dbm >= 0 || dbm === -1) return { bars: 0, label: "unknown", variant: "neutral" };
  if (dbm >= -50) return { bars: 4, label: "very near", variant: "ok" };
  if (dbm >= -60) return { bars: 3, label: "near", variant: "ok" };
  if (dbm >= -70) return { bars: 2, label: "medium", variant: "warn" };
  if (dbm >= -80) return { bars: 1, label: "far", variant: "warn" };
  return { bars: 1, label: "very far", variant: "danger" };
}

function SignalCell({ dbm }: { dbm: string }) {
  const s = signalInfo(dbm);
  return (
    <span className={`signal signal--${s.variant}`}>
      <span className="bars">
        {[0, 1, 2, 3].map((i) => (
          <i key={i} className={i < s.bars ? "on" : ""} />
        ))}
      </span>
      <span className="signal__label">{s.label}</span>
      <span className="faint mono" style={{ fontSize: "0.75rem" }}>{dbm}dBm</span>
    </span>
  );
}

export function ScanTarget() {
  const { target, setTarget } = useTarget();
  const [running, setRunning] = useState(false);
  const [accessPoints, setAccessPoints] = useState<AccessPoint[]>([]);
  const [scope, setScope] = useState<ScopeState | null>(null);
  const [interfaces, setInterfaces] = useState<WirelessInterface[]>([]);
  const [scanStartMs, setScanStartMs] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  // WPS scan results: bssid (upper) -> locked. null = not scanned yet.
  const [wpsMap, setWpsMap] = useState<Record<string, boolean> | null>(null);
  const [wpsScanning, setWpsScanning] = useState(false);
  const pollRef = useRef<number | null>(null);

  const stopPolling = () => {
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const startPolling = () => {
    if (pollRef.current) return;
    pollRef.current = window.setInterval(async () => {
      try {
        const results = await api.getScanResults();
        setRunning(results.running);
        setAccessPoints(results.access_points);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }, 2000);
  };

  useEffect(() => {
    api.getScope().then(setScope).catch(() => {});
    // Detect adapters so the interface is a dropdown (not a hardcoded "wlan1"),
    // and default to a monitor-capable EXTERNAL card if the current pick is absent.
    api.getAdapterStatus().then((a) => {
      setInterfaces(a.interfaces);
      const present = a.interfaces.some((i) => i.name === target.interfaceName);
      if (!present) {
        const pick = a.interfaces.find((i) => i.supports_monitor && i.connection === "external")
          ?? a.interfaces.find((i) => i.supports_monitor);
        if (pick) setTarget({ interfaceName: pick.name });
      }
    }).catch(() => {});
    api
      .getScanResults()
      .then((results) => {
        setRunning(results.running);
        setAccessPoints(results.access_points);
        if (results.running) startPolling();
      })
      .catch(() => {});
    return stopPolling;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const start = async () => {
    setError(null);
    try {
      await api.startScan(target.interfaceName);
      setRunning(true);
      setScanStartMs(Date.now());
      startPolling();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const stop = async () => {
    await api.stopScan().catch(() => {});
    setRunning(false);
    stopPolling();
  };

  const scanWps = async () => {
    setError(null);
    setWpsScanning(true);
    try {
      await api.stopScan().catch(() => {});
      setRunning(false);
      stopPolling();
      const res = await api.scanWps(target.interfaceName);
      const map: Record<string, boolean> = {};
      for (const ap of res.access_points) map[ap.bssid.toUpperCase()] = ap.locked;
      setWpsMap(map);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setWpsScanning(false);
    }
  };

  const isInScope = (ap: AccessPoint) =>
    !!scope?.is_set && (scope.bssids.includes(ap.bssid.toLowerCase()) || scope.ssids.includes(ap.ssid));

  // WPS open (unlocked) after a wash scan = worth a Pixie Dust attempt. wash can't
  // *prove* Pixie vulnerability (only the attack does), so this flags a candidate.
  const isPixieCandidate = (ap: AccessPoint) => wpsMap !== null && wpsMap[ap.bssid.toUpperCase()] === false;

  // Strongest signal first (high → low), unknown readings last.
  const sortedAps = [...accessPoints].sort((a, b) => dbmValue(b.signal_dbm) - dbmValue(a.signal_dbm));

  // Selecting a target updates the SHARED target so Capture / WPS / Evil Twin auto-fill.
  const select = (ap: AccessPoint) => setTarget({ bssid: ap.bssid, ssid: ap.ssid, channel: ap.channel, encryption: ap.encryption });
  const clearTarget = () => setTarget({ bssid: "", ssid: "", channel: "", encryption: "" });

  const addToScopeAndSelect = async (ap: AccessPoint) => {
    setError(null);
    try {
      // add BOTH the BSSID and (if present) the SSID — Evil Twin is SSID-scoped,
      // so without the SSID it would still be rejected.
      const bssids = [...(scope?.bssids ?? []), ap.bssid];
      const ssids = ap.ssid && !(scope?.ssids ?? []).includes(ap.ssid)
        ? [...(scope?.ssids ?? []), ap.ssid]
        : scope?.ssids ?? [];
      const updated = await api.setScope(bssids, ssids);
      setScope(updated);
      select(ap);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const removeFromScope = async (ap: AccessPoint) => {
    setError(null);
    try {
      // symmetric with addToScopeAndSelect — drop both the BSSID and the SSID
      const bssids = (scope?.bssids ?? []).filter((b) => b.toLowerCase() !== ap.bssid.toLowerCase());
      const ssids = (scope?.ssids ?? []).filter((s) => s !== ap.ssid);
      const updated = await api.setScope(bssids, ssids);
      setScope(updated);
      // an out-of-scope AP can't stay the active target — deselect it
      if (target.bssid === ap.bssid) clearTarget();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const wpsCell = (ap: AccessPoint) => {
    if (wpsMap === null) return <span className="faint">—</span>;
    const locked = wpsMap[ap.bssid.toUpperCase()];
    if (locked === undefined) return <span className="faint">no WPS</span>;
    return locked ? (
      <Pill variant="warn" dot={false}>locked</Pill>
    ) : (
      <Pill variant="ok" dot={false}>WPS open</Pill>
    );
  };

  return (
    <div className="view">
      <p className="view__intro">
        Run a passive scan on a monitor-mode interface, then pick a target — selecting one auto-fills
        Capture, WPS and Evil Twin (BSSID + SSID + channel), and adds both the BSSID and SSID to the
        scope. Networks are listed <strong>strongest signal first</strong>; "Clients" is how many
        devices are connected. Click <strong>Selected ✓</strong> again to deselect and drop it from
        scope. Run "Scan for WPS" to flag <strong>⚡ Pixie</strong> candidates (WPS-open APs).
      </p>

      {error && <Banner variant="error">{error}</Banner>}
      {!scope?.is_set && (
        <Banner variant="warn">No engagement scope configured yet — set it in the Scope tab first.</Banner>
      )}
      {(() => {
        const sel = interfaces.find((i) => i.name === target.interfaceName);
        const weak = isWeakDriver(sel);
        // scanning 12s+ with nothing found is the classic non-capturing-driver symptom
        const dryScan = running && accessPoints.length === 0 && scanStartMs !== null && Date.now() - scanStartMs > 12000;
        if (weak) {
          return (
            <Banner variant="warn">
              ⚠️ <code>{sel!.name}</code> uses the <code>rtw88</code> driver (RTL88xxAU). It sets monitor mode
              but usually <strong>captures nothing</strong> — that's why scan finds no networks. Use a
              <strong> Ralink (rt2800usb) or Atheros</strong> USB adapter, or install the out-of-tree driver:
              <code>sudo apt install realtek-rtl88xxau-dkms</code> then blacklist <code>rtw88_8821au</code> and replug.
            </Banner>
          );
        }
        if (dryScan) {
          return (
            <Banner variant="warn">
              No networks after 12s on <code>{target.interfaceName}</code>. Check it's really in monitor mode
              (Adapters tab), interferers are freed ("Free from NM"), and the adapter's driver actually
              captures — many RTL8821AU (rtw88) builds don't.
            </Banner>
          );
        }
        return null;
      })()}

      <Card
        title="Scanner"
        icon={<IconScan size={18} />}
        right={running ? <Pill variant="ok" live>Scanning</Pill> : <Pill>Idle</Pill>}
      >
        <div className="toolbar" style={{ alignItems: "flex-end" }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <Field label="Monitor-mode interface" hint="Pick the adapter to scan on. Must be in monitor mode (Adapters tab).">
              {interfaces.length > 0 ? (
                <select className="input" value={target.interfaceName} onChange={(e) => setTarget({ interfaceName: e.target.value })} disabled={running}>
                  {interfaces.map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.name} — {i.mode}{i.connection === "internal" ? " · internal" : ""}
                      {i.chipset ? ` · ${i.chipset}` : ""}{isWeakDriver(i) ? " · ⚠ rtw88 (may not capture)" : ""}
                    </option>
                  ))}
                </select>
              ) : (
                <Input mono value={target.interfaceName} onChange={(e) => setTarget({ interfaceName: e.target.value })} />
              )}
            </Field>
          </div>
          <Button variant="primary" onClick={start} disabled={running || wpsScanning} icon={<IconPlay size={16} />}>
            Start scan
          </Button>
          <Button variant="danger" onClick={stop} disabled={!running} icon={<IconStop size={16} />}>
            Stop
          </Button>
          <Button onClick={scanWps} disabled={wpsScanning} icon={<IconWps size={16} />}>
            {wpsScanning ? "Scanning WPS…" : "Scan for WPS"}
          </Button>
        </div>
        <p className="field__hint">
          "Scan for WPS" runs <code>wash</code> (~15s, stops the normal scan) and marks which
          networks have WPS open — those are worth a Pixie Dust attempt. Locked WPS isn't. (Actual
          Pixie vulnerability is only confirmed by attacking.)
        </p>
      </Card>

      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>SSID</th>
              <th>BSSID</th>
              <th>Ch</th>
              <th>Signal</th>
              <th>Clients</th>
              <th>Encryption</th>
              <th>WPS</th>
              <th>Scope</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {accessPoints.length === 0 && (
              <tr>
                <td colSpan={9}>
                  <EmptyState>{running ? "Listening for access points…" : "No access points yet. Start a scan."}</EmptyState>
                </td>
              </tr>
            )}
            {sortedAps.map((ap) => (
              <tr key={ap.bssid} className={target.bssid === ap.bssid ? "is-selected" : ""}>
                <td>
                  {ap.ssid || (
                    <span
                      className="faint"
                      title="Hidden network — this AP doesn't broadcast its name. The SSID appears here once a connected client (re)associates; a deauth burst on its BSSID can force that."
                      style={{ borderBottom: "1px dotted var(--text-faint)", cursor: "help" }}
                    >
                      (hidden)
                    </span>
                  )}
                </td>
                <td className="mono">{ap.bssid}</td>
                <td className="mono">{ap.channel}</td>
                <td><SignalCell dbm={ap.signal_dbm} /></td>
                <td className="mono">{ap.clients > 0 ? ap.clients : <span className="faint">0</span>}</td>
                <td>
                  {ap.encryption}
                  {isPixieCandidate(ap) && (
                    <span
                      title="WPS is open on this AP — a Pixie Dust attack is worth trying. (Only running the attack confirms it's actually vulnerable.)"
                      style={{ marginLeft: 6, whiteSpace: "nowrap" }}
                    >
                      <Pill variant="warn" dot={false}>⚡ Pixie</Pill>
                    </span>
                  )}
                </td>
                <td>{wpsCell(ap)}</td>
                <td>{isInScope(ap) ? <Pill variant="ok" dot={false}>in scope</Pill> : <span className="faint">—</span>}</td>
                <td>
                  {!isInScope(ap) ? (
                    <Button small onClick={() => addToScopeAndSelect(ap)} title="Add to engagement scope and select as target">
                      Add to scope
                    </Button>
                  ) : target.bssid === ap.bssid ? (
                    <Button
                      small
                      variant="primary"
                      onClick={() => removeFromScope(ap)}
                      title="Selected target — click to deselect and remove it from the scope"
                    >
                      Selected ✓
                    </Button>
                  ) : (
                    <Button small variant="ghost" onClick={() => select(ap)} title="Select as target">
                      Select
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {target.bssid && (
        <Banner variant="info">
          Selected target <code>{target.bssid}</code>
          {target.ssid ? ` (${target.ssid})` : ""} on channel <code>{target.channel || "?"}</code> — auto-filled
          into Capture, WPS and Evil Twin.
        </Banner>
      )}
    </div>
  );
}

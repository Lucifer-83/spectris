import { useEffect, useRef, useState } from "react";
import { api, type DeauthState, type ScopeState, type WirelessInterface } from "../api";
import { useTarget } from "../TargetContext";
import { Banner, Button, Card, Field, Input, Pill } from "../components/ui";
import { IconPlay, IconScan, IconStop } from "../components/icons";

export function Deauth() {
  const { target, setTarget } = useTarget();
  const [interfaces, setInterfaces] = useState<WirelessInterface[]>([]);
  const [count, setCount] = useState("0"); // 0 = continuous
  const [client, setClient] = useState("");
  const [status, setStatus] = useState<DeauthState | null>(null);
  const [scope, setScope] = useState<ScopeState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  const startPolling = () => {
    if (pollRef.current) return;
    pollRef.current = window.setInterval(async () => {
      try {
        const s = await api.getDeauthStatus();
        setStatus(s);
        if (!s.running && pollRef.current) {
          window.clearInterval(pollRef.current);
          pollRef.current = null;
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }, 1000);
  };

  useEffect(() => {
    api.getScope().then(setScope).catch(() => {});
    api.getAdapterStatus().then((a) => setInterfaces(a.interfaces)).catch(() => {});
    api.getDeauthStatus().then((s) => { setStatus(s); if (s.running) startPolling(); }).catch(() => {});
    return () => { if (pollRef.current) window.clearInterval(pollRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const running = status?.running ?? false;
  const inScope = !!scope?.is_set && !!target.bssid &&
    scope.bssids.some((b) => b.toLowerCase() === target.bssid.toLowerCase());

  const start = async () => {
    setError(null);
    try {
      await api.startDeauth(
        target.interfaceName, target.bssid, Number(count) || 0,
        target.channel || undefined, client || undefined,
      );
      setStatus((prev) => (prev ? { ...prev, running: true } : prev));
      startPolling();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const stop = async () => {
    await api.stopDeauth().catch(() => {});
    setStatus(await api.getDeauthStatus().catch(() => null));
    if (pollRef.current) { window.clearInterval(pollRef.current); pollRef.current = null; }
  };

  const monitorIfaces = interfaces.filter((i) => i.supports_monitor);
  const startDisabled = running || !target.bssid || !target.interfaceName || (!!scope?.is_set && !inScope);

  return (
    <div className="view">
      <p className="view__intro">
        Deauthenticate clients from a scope-authorized AP — kicks them off so they reconnect (and a
        running Handshake Capture records the 4-way handshake). Set the packet count yourself:
        <strong> 0 = continuous</strong> until you press Stop, or any number for a fixed burst. Target
        auto-fills from Scan &amp; Target; the backend rejects out-of-scope BSSIDs.
      </p>

      {error && <Banner variant="error">{error}</Banner>}
      {!scope?.is_set && <Banner variant="warn">No engagement scope configured — set it in the Scope tab first.</Banner>}
      {scope?.is_set && target.bssid && !inScope && (
        <Banner variant="warn"><code>{target.bssid}</code> is not in the authorized BSSID scope — the backend will reject it.</Banner>
      )}

      <div className="grid-2">
        <Card
          title="Deauth"
          icon={<IconScan size={18} />}
          right={running ? <Pill variant="warn" live>Sending</Pill> : <Pill>Idle</Pill>}
        >
          <Field label="Monitor-mode interface" hint="Must inject (Ralink/Atheros are reliable). Enable monitor in Adapters.">
            {monitorIfaces.length > 0 ? (
              <select className="input" value={target.interfaceName} onChange={(e) => setTarget({ interfaceName: e.target.value })} disabled={running}>
                {monitorIfaces.map((i) => (
                  <option key={i.name} value={i.name}>{i.name} — {i.mode}{i.chipset ? ` · ${i.chipset}` : ""}</option>
                ))}
              </select>
            ) : (
              <Input mono value={target.interfaceName} onChange={(e) => setTarget({ interfaceName: e.target.value })} disabled={running} />
            )}
          </Field>
          <Field label="Target BSSID">
            <Input mono value={target.bssid} onChange={(e) => setTarget({ bssid: e.target.value })} placeholder="AA:BB:CC:DD:EE:FF" disabled={running} />
          </Field>
          <Field label="Channel">
            <Input mono value={target.channel} onChange={(e) => setTarget({ channel: e.target.value })} placeholder="6" disabled={running} />
          </Field>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div style={{ width: 150 }}>
              <Field label="Packet count (0 = continuous)">
                <Input mono type="number" min={0} value={count} onChange={(e) => setCount(e.target.value)} disabled={running} />
              </Field>
            </div>
            <div style={{ flex: 1, minWidth: 200 }}>
              <Field label="Client MAC (optional — blank = all clients)">
                <Input mono value={client} onChange={(e) => setClient(e.target.value)} placeholder="11:22:33:44:55:66" disabled={running} />
              </Field>
            </div>
          </div>
          <div className="toolbar">
            <Button variant="danger" onClick={start} disabled={startDisabled} icon={<IconPlay size={16} />}>
              {Number(count) === 0 ? "Start continuous deauth" : "Send deauth"}
            </Button>
            <Button variant="ghost" onClick={stop} disabled={!running} icon={<IconStop size={16} />}>
              Stop
            </Button>
          </div>
        </Card>

        <Card title="Status" icon={<IconScan size={18} />}>
          <dl className="kv">
            <dt>Running</dt>
            <dd>{running ? <Pill variant="warn" dot={false} live>yes</Pill> : "no"}</dd>
            <dt>Target</dt>
            <dd className="mono">{status?.bssid ?? (target.bssid || "—")}</dd>
            <dt>Interface</dt>
            <dd className="mono">{status?.interface ?? (target.interfaceName || "—")}</dd>
            <dt>Count</dt>
            <dd>{status?.count === 0 ? "continuous" : (status?.count ?? "—")}</dd>
            <dt>Client</dt>
            <dd className="mono">{status?.client ?? "all clients"}</dd>
          </dl>
        </Card>
      </div>

      <Card title="Live output" icon={<IconScan size={18} />}>
        <pre className="console">{status?.output?.join("\n") ?? ""}</pre>
        <p className="field__hint">
          aireplay-ng output. Locks the interface to the target's channel first. A client must be
          connected for a deauth to force a handshake (PMKID needs no client). Continuous runs until Stop.
        </p>
      </Card>
    </div>
  );
}

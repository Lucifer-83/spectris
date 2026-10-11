import { useEffect, useRef, useState } from "react";
import { api, type CaptureState } from "../api";
import { useTarget } from "../TargetContext";
import { Banner, Button, Card, Field, Input, Pill } from "../components/ui";
import { IconBolt, IconDownload, IconPlay, IconStop } from "../components/icons";

export function Action() {
  const { target, setTarget } = useTarget();
  const [status, setStatus] = useState<CaptureState | null>(null);
  const [hashFile, setHashFile] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);
  const convertedRef = useRef(false); // auto-convert once per capture
  const consoleRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => {
    api.getCaptureStatus().then(setStatus).catch(() => {});
    return () => { if (pollRef.current) window.clearInterval(pollRef.current); };
  }, []);

  // keep the log scrolled to the newest line
  useEffect(() => {
    if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [status?.output]);

  const startPolling = () => {
    if (pollRef.current) return;
    pollRef.current = window.setInterval(async () => {
      try {
        const s = await api.getCaptureStatus();
        setStatus(s);
        // FULLY AUTOMATIC: the moment a handshake/PMKID is captured, convert it
        // to .hc22000 so it's ready for cracking / evil-twin verification.
        if (s.hashes > 0 && !convertedRef.current) {
          convertedRef.current = true;
          try {
            const r = await api.convertCapture();
            setHashFile(r.hash_file);
            setNote(`Handshake captured and converted → ${r.hash_file}`);
          } catch {
            convertedRef.current = false; // retry on next tick
          }
        }
        // If the capture process is no longer running (e.g. hcxdumptool exited),
        // stop polling instead of hammering the backend forever.
        if (!s.running && pollRef.current) {
          window.clearInterval(pollRef.current);
          pollRef.current = null;
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }, 1500);
  };

  const start = async () => {
    setError(null);
    setNote(null);
    setHashFile(null);
    convertedRef.current = false;
    try {
      await api.startCapture(target.interfaceName, target.bssid, target.channel);
      setStatus((prev) => (prev ? { ...prev, running: true } : prev));
      startPolling();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const stop = async () => {
    await api.stopCapture().catch(() => {});
    setStatus(await api.getCaptureStatus().catch(() => null));
    if (pollRef.current) { window.clearInterval(pollRef.current); pollRef.current = null; }
  };

  const running = status?.running ?? false;
  const hashes = status?.hashes ?? 0;

  return (
    <div className="view">
      <p className="view__intro">
        Automatic handshake / PMKID capture against a scope-authorized target. Press <strong>Start</strong> —
        hcxdumptool captures on its own and, the instant a handshake lands, it's <strong>auto-converted</strong>
        to the crackable <code>.hc22000</code>. Watch the live log below. If a client won't hand one over,
        use the <strong>Deauth</strong> tab to kick it so it reconnects. Target auto-fills from Scan &amp; Target.
      </p>

      {error && <Banner variant="error">{error}</Banner>}
      {note && <Banner variant="ok">{note}</Banner>}
      {hashes > 0 && !note && (
        <Banner variant="ok">{hashes} crackable handshake/PMKID captured ✓</Banner>
      )}

      <div className="grid-2">
        <Card
          title="Handshake capture"
          icon={<IconBolt size={18} />}
          right={
            hashes > 0 ? <Pill variant="ok">{hashes} handshake{hashes > 1 ? "s" : ""} ✓</Pill>
              : running ? <Pill variant="ok" live>Capturing</Pill> : <Pill>Idle</Pill>
          }
        >
          <Field label="Monitor-mode interface" hint="Enable monitor mode for it in the Adapters tab first.">
            <Input mono value={target.interfaceName} onChange={(e) => setTarget({ interfaceName: e.target.value })} disabled={running} />
          </Field>
          <Field label="Target SSID (network name)" hint="Auto-fills from Scan & Target — just for reference; capture locks onto the BSSID + channel.">
            <Input value={target.ssid} onChange={(e) => setTarget({ ssid: e.target.value })} placeholder="(from Scan & Target)" disabled={running} />
          </Field>
          <Field label="Target BSSID">
            <Input mono value={target.bssid} onChange={(e) => setTarget({ bssid: e.target.value })} placeholder="AA:BB:CC:DD:EE:FF" disabled={running} />
          </Field>
          <Field label="Channel">
            <Input mono value={target.channel} onChange={(e) => setTarget({ channel: e.target.value })} placeholder="6" disabled={running} />
          </Field>

          <div className="toolbar">
            <Button variant="primary" onClick={start} disabled={running || !target.bssid || !target.interfaceName} icon={<IconPlay size={16} />}>
              Start capture
            </Button>
            <Button variant="danger" onClick={stop} disabled={!running} icon={<IconStop size={16} />}>
              Stop
            </Button>
          </div>
        </Card>

        <Card title="Status" icon={<IconBolt size={18} />}>
          <dl className="kv">
            <dt>Running</dt>
            <dd>{running ? <Pill variant="ok" dot={false} live>yes</Pill> : "no"}</dd>
            <dt>Network</dt>
            <dd>{target.ssid || <span className="faint">—</span>}</dd>
            <dt>Target BSSID</dt>
            <dd className="mono">{status?.bssid ?? (target.bssid || "—")}</dd>
            <dt>Handshakes</dt>
            <dd>{hashes > 0 ? <Pill variant="ok" dot={false}>{hashes} ✓</Pill> : "0 (waiting…)"}</dd>
            <dt>Capture file</dt>
            <dd className="mono" style={{ fontSize: "0.75rem" }}>{status?.output_pcapng ?? "—"}</dd>
            <dt>Hashcat file</dt>
            <dd className="mono" style={{ fontSize: "0.75rem" }}>{hashFile ?? "—"}</dd>
          </dl>
          {hashFile && (
            <Button small onClick={() => api.convertCapture().then((r) => setHashFile(r.hash_file)).catch(() => {})} icon={<IconDownload size={14} />}>
              Re-convert
            </Button>
          )}
        </Card>
      </div>

      <Card title="Live log — what's happening" icon={<IconBolt size={18} />}>
        <pre className="console" ref={consoleRef} style={{ maxHeight: 340 }}>
          {status?.output?.join("\n") ?? ""}
        </pre>
        <p className="field__hint">
          Live hcxdumptool output. A handshake isn't instant — leave it running; PMKID often lands within
          seconds, a 4-way handshake needs a client to (re)connect. If it errors immediately, the interface
          isn't in monitor mode (fix it in <strong>Adapters</strong>).
        </p>
      </Card>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { api, type AutoState, type Wordlist } from "../api";
import { useTarget } from "../TargetContext";
import { Banner, Button, Card, Field, Input, PasswordHit, Pill } from "../components/ui";
import { IconBolt, IconPlay, IconStop, IconDownload, IconCheck } from "../components/icons";

function humanSize(bytes: number): string {
  if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GB`;
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  return `${(bytes / (1 << 10)).toFixed(0)} KB`;
}

function isWpa3Only(enc: string): boolean {
  const e = enc.toUpperCase();
  return (e.includes("WPA3") || e.includes("SAE")) && !e.includes("WPA2") && !e.includes("PSK");
}

const STEPS = [
  { key: "capturing", label: "Capture + deauth" },
  { key: "converting", label: "Convert" },
  { key: "cracking", label: "Crack" },
  { key: "done", label: "Done" },
] as const;

const STEP_ORDER: Record<string, number> = { capturing: 0, converting: 1, cracking: 2, done: 3 };

export function Auto() {
  const { target } = useTarget();
  const [wordlists, setWordlists] = useState<Wordlist[]>([]);
  const [decompressing, setDecompressing] = useState(false);
  const [wordlist, setWordlist] = useState<string>("");
  const [captureSeconds, setCaptureSeconds] = useState("60");
  const [status, setStatus] = useState<AutoState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  const selected = wordlists.find((w) => w.path === wordlist);
  const wpa3 = isWpa3Only(target.encryption || "");

  // Decompress a .gz list on the backend (no root), add it to the list, select it.
  const decompressSelected = async () => {
    if (!selected?.path) return;
    setError(null);
    setDecompressing(true);
    try {
      const r = await api.decompressWordlist(selected.path);
      setWordlists((prev) => [
        { path: r.path, size: r.size, needs_gunzip: false, bundled: false },
        ...prev.filter((w) => w.path !== r.path),
      ]);
      setWordlist(r.path);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDecompressing(false);
    }
  };

  useEffect(() => {
    api.getWordlists().then((r) => {
      setWordlists(r.wordlists);
      const ready = r.wordlists.find((w) => !w.needs_gunzip);
      setWordlist((ready ?? r.wordlists[0])?.path ?? "");
    }).catch(() => {});
    api.getAutoStatus().then((s) => { setStatus(s); if (s.running) startPolling(); }).catch(() => {});
    return () => { if (pollRef.current) window.clearInterval(pollRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startPolling = () => {
    if (pollRef.current) return;
    pollRef.current = window.setInterval(async () => {
      try {
        const s = await api.getAutoStatus();
        setStatus(s);
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
    try {
      await api.startAuto(target.interfaceName, target.bssid, target.channel, wordlist, target.encryption, 8, Number(captureSeconds));
      startPolling();
      setStatus(await api.getAutoStatus());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const stop = async () => {
    await api.stopAuto().catch(() => {});
    setStatus(await api.getAutoStatus().catch(() => null));
    if (pollRef.current) { window.clearInterval(pollRef.current); pollRef.current = null; }
  };

  const running = status?.running ?? false;
  const phase = status?.phase ?? "idle";
  const currentStep = STEP_ORDER[phase] ?? -1;
  const failed = phase === "failed";
  const psk = status?.psk ?? null;

  const startDisabled =
    running || wpa3 || !target.bssid || !target.channel || !wordlist || (selected?.needs_gunzip ?? false);

  return (
    <div className="view">
      <p className="view__intro">
        One-click pipeline for a single scope-authorized target: it starts the capture, fires targeted
        deauth bursts to force a handshake, converts it, and runs hashcat — all automatically. Same
        guardrails as the manual tabs: the BSSID is scope-checked before anything starts and every phase
        is logged. Pick the target on Scan &amp; Target first.
      </p>

      {error && <Banner variant="error">{error}</Banner>}
      {wpa3 && (
        <Banner variant="warn">
          Target looks like <strong>WPA3 / SAE</strong> — its handshake isn't crackable this way, so Auto
          mode is disabled for it. Use it on WPA/WPA2-PSK targets.
        </Banner>
      )}
      {psk && <PasswordHit password={psk} target={status?.bssid ?? undefined} />}
      {failed && status?.error && <Banner variant="error">{status.error}</Banner>}

      <div className="grid-2">
        <Card
          title="Auto run"
          icon={<IconBolt size={18} />}
          right={running ? <Pill variant="ok" live>{phase}</Pill> : psk ? <Pill variant="ok">Recovered ✓</Pill> : <Pill>Idle</Pill>}
        >
          <Field label="Target (from Scan & Target)">
            <Input mono value={target.bssid ? `${target.bssid}  ch ${target.channel || "?"}  ${target.encryption || ""}` : ""} readOnly placeholder="select a target on Scan & Target first" />
          </Field>
          <Field label="Interface (monitor mode)">
            <Input mono value={target.interfaceName} readOnly />
          </Field>
          <Field label="Wordlist">
            <select className="input" value={wordlist} onChange={(e) => setWordlist(e.target.value)} disabled={running}>
              {wordlists.length === 0 && <option value="">no wordlists found</option>}
              {wordlists.map((w) => (
                <option key={w.path} value={w.path}>
                  {w.path} ({humanSize(w.size)}){w.needs_gunzip ? " — needs decompress" : ""}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Capture window (seconds to try for a handshake)">
            <Input mono type="number" min={15} max={300} value={captureSeconds} onChange={(e) => setCaptureSeconds(e.target.value)} disabled={running} />
          </Field>

          {selected?.needs_gunzip && (
            <Banner variant="warn">
              Selected list is gzipped. Decompress it first (no root needed) — the result is selected automatically.
              <div className="toolbar" style={{ marginTop: 8 }}>
                <Button small icon={<IconDownload size={14} />} onClick={decompressSelected} disabled={decompressing}>
                  {decompressing ? "Decompressing…" : "Decompress now"}
                </Button>
              </div>
            </Banner>
          )}

          <div className="toolbar">
            <Button variant="primary" onClick={start} disabled={startDisabled} icon={<IconPlay size={16} />}>
              Run auto
            </Button>
            <Button variant="danger" onClick={stop} disabled={!running} icon={<IconStop size={16} />}>
              Stop
            </Button>
          </div>
          <p className="field__hint">
            Needs the interface already in monitor mode (Setup) and passwordless sudo enabled — capture and
            deauth are the same root operations as the manual tabs.
          </p>
        </Card>

        <Card title="Progress" icon={<IconBolt size={18} />}>
          <div className="auto-steps">
            {STEPS.map((s, i) => {
              const state = failed ? (i < currentStep ? "done" : "pending")
                : i < currentStep ? "done" : i === currentStep ? "active" : "pending";
              return (
                <div key={s.key} className={`auto-step auto-step--${state}`}>
                  <span className="auto-step__dot">{state === "done" ? <IconCheck size={12} /> : i + 1}</span>
                  <span>{s.label}</span>
                </div>
              );
            })}
          </div>
          <dl className="kv" style={{ marginTop: 14 }}>
            <dt>Phase</dt>
            <dd>{phase}{failed ? " ✗" : ""}</dd>
            <dt>Detail</dt>
            <dd>{status?.detail || "—"}</dd>
            <dt>Handshakes</dt>
            <dd>{status?.hashes ?? 0}</dd>
            <dt>Recovered</dt>
            <dd>{psk ? <strong>{psk}</strong> : "—"}</dd>
          </dl>
        </Card>
      </div>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { api, type CrackAttackMode, type CrackEngine, type CrackRule, type CrackState, type Wordlist } from "../api";
import { useTarget } from "../TargetContext";
import { Banner, Button, Card, Field, Input, PasswordHit, Pill } from "../components/ui";
import { IconKey, IconPlay, IconStop, IconRefresh, IconAlert, IconDownload } from "../components/icons";

function humanSize(bytes: number): string {
  if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GB`;
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;
  return `${bytes} B`;
}

// WPA3/SAE can't be cracked by this dictionary method (matches backend logic).
function isWpa3Only(enc: string): boolean {
  const e = enc.toUpperCase();
  return (e.includes("WPA3") || e.includes("SAE")) && !e.includes("WPA2") && !e.includes("PSK");
}

const MASK_PRESETS = [
  { label: "8 digits", mask: "?d?d?d?d?d?d?d?d", hint: "common router default (e.g. 88094432)" },
  { label: "10 digits", mask: "?d?d?d?d?d?d?d?d?d?d", hint: "phone-number style PSK" },
  { label: "8 lower", mask: "?l?l?l?l?l?l?l?l", hint: "8 lowercase letters" },
];

// small inline progress bar so we don't depend on extra CSS
function ProgressBar({ pct }: { pct: number }) {
  return (
    <div style={{ height: 8, borderRadius: 6, background: "var(--panel-2, #1c2333)", overflow: "hidden" }}>
      <div style={{ width: `${Math.min(100, pct)}%`, height: "100%", background: "var(--accent, #6ea8fe)", transition: "width .4s ease" }} />
    </div>
  );
}

export function Crack() {
  const { target } = useTarget();
  const [engine, setEngine] = useState<CrackEngine>("hashcat");
  const [attackMode, setAttackMode] = useState<CrackAttackMode>("wordlist");
  const [wordlists, setWordlists] = useState<Wordlist[]>([]);
  const [rules, setRules] = useState<CrackRule[]>([]);
  const [wordlist, setWordlist] = useState<string>("");
  const [customWordlist, setCustomWordlist] = useState<string>("");
  const [ruleFile, setRuleFile] = useState<string>("");
  const [mask, setMask] = useState<string>("?d?d?d?d?d?d?d?d");
  const [status, setStatus] = useState<CrackState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  const selected = wordlists.find((w) => w.path === wordlist);
  // A manually-typed path overrides the dropdown, so users can point at their own list.
  const effectiveWordlist = customWordlist.trim() || wordlist;
  const wpa3 = isWpa3Only(target.encryption || "");
  // aircrack-ng only does straight wordlist; rules/mask are hashcat-only.
  const effectiveMode: CrackAttackMode = engine === "aircrack" ? "wordlist" : attackMode;

  useEffect(() => {
    api.getWordlists().then((r) => {
      setWordlists(r.wordlists);
      setRules(r.rules);
      const ready = r.wordlists.find((w) => !w.needs_gunzip);
      setWordlist((ready ?? r.wordlists[0])?.path ?? "");
      const best64 = r.rules.find((x) => /best64/i.test(x.path));
      setRuleFile((best64 ?? r.rules[0])?.path ?? "");
    }).catch(() => {});
    api.getCrackStatus().then(setStatus).catch(() => {});
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

  const startPolling = () => {
    if (pollRef.current) return;
    pollRef.current = window.setInterval(async () => {
      try {
        const s = await api.getCrackStatus();
        setStatus(s);
        if (!s.running && pollRef.current) {
          window.clearInterval(pollRef.current);
          pollRef.current = null;
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }, 2000);
  };

  const start = async () => {
    setError(null);
    try {
      await api.startCrack(target.bssid, engine, {
        wordlist: effectiveWordlist,
        attackMode: effectiveMode,
        rules: ruleFile,
        mask,
      });
      startPolling();
      setStatus(await api.getCrackStatus());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const stop = async () => {
    await api.stopCrack();
    setStatus(await api.getCrackStatus());
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const refreshWordlists = async () => {
    const r = await api.getWordlists();
    setWordlists(r.wordlists);
    setRules(r.rules);
  };

  // Open a native file dialog (desktop app) so the user can pick their own
  // wordlist without typing the path; the picked absolute path fills the box.
  const hasFilePicker = typeof window.wifiPentestApp?.pickWordlist === "function";
  const pickWordlistFile = async () => {
    setError(null);
    try {
      const path = await window.wifiPentestApp?.pickWordlist?.();
      if (path) setCustomWordlist(path);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  // Decompress a .gz list (rockyou etc.) on the backend, then select the result.
  const [decompressing, setDecompressing] = useState(false);
  const decompressSelected = async () => {
    if (!selected?.path) return;
    setError(null);
    setDecompressing(true);
    try {
      const r = await api.decompressWordlist(selected.path);
      setCustomWordlist(r.path);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDecompressing(false);
    }
  };

  // Build the engagement report on the backend, then save it as a file. No
  // auto-download on recovery — this only fires when the operator asks for it.
  const exportReport = async () => {
    setError(null);
    try {
      const report = await api.getReport();
      const blob = new Blob([report.content], { type: report.mimetype || "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = report.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const running = status?.running ?? false;
  const psk = status?.psk ?? null;
  const pct = status?.progress_pct ?? null;

  const needsWordlist = effectiveMode !== "mask";
  const usingCustom = customWordlist.trim().length > 0;
  const startDisabled =
    running ||
    !target.bssid ||
    (needsWordlist && !usingCustom && (!wordlist || (selected?.needs_gunzip ?? false))) ||
    (needsWordlist && !effectiveWordlist) ||
    (effectiveMode === "rules" && !ruleFile) ||
    (effectiveMode === "mask" && !mask.trim());

  return (
    <div className="view">
      <p className="view__intro">
        Offline PSK recovery — the final step after Capture → Convert. The <code>.hc22000</code> holds
        the handshake MIC, not the password, so this is a dictionary/brute-force attack: each candidate
        is hashed and compared, nothing is decrypted. Runs against the scope-authorized target only,
        needs no root or monitor mode, and every run is logged.
      </p>

      {error && <Banner variant="error">{error}</Banner>}
      {wpa3 && (
        <Banner variant="warn">
          <IconAlert size={14} /> Target encryption looks like <strong>WPA3 / SAE</strong> — this method
          only recovers WPA/WPA2-PSK. A WPA3-only handshake cannot be cracked here. (WPA2/WPA3 transition
          networks are fine — the WPA2 handshake still works.)
        </Banner>
      )}
      {psk && (
        <>
          <PasswordHit password={psk} target={status?.bssid ?? undefined} />
          <div className="toolbar">
            <Button small icon={<IconDownload size={14} />} onClick={exportReport}>
              Export engagement report
            </Button>
          </div>
        </>
      )}
      {status?.exhausted && !psk && (
        <Banner variant="warn">
          Wordlist exhausted — no match. Try a larger wordlist, add rules (mutations), or switch to a
          mask attack for known password shapes.
        </Banner>
      )}

      <div className="grid-2">
        <Card
          title="Crack target"
          icon={<IconKey size={18} />}
          right={
            psk ? <Pill variant="ok">Recovered ✓</Pill> :
            running ? <Pill variant="ok" live>Cracking</Pill> : <Pill>Idle</Pill>
          }
        >
          <Field label="1 · Target BSSID (from Scan &amp; Target)">
            <Input mono value={target.bssid} readOnly placeholder="select a target on Scan & Target first" />
          </Field>

          <Field label="2 · Engine">
            <div className="seg">
              <button className={engine === "hashcat" ? "on" : ""} onClick={() => setEngine("hashcat")} disabled={running}>
                hashcat (GPU/CPU)
              </button>
              <button className={engine === "aircrack" ? "on" : ""} onClick={() => setEngine("aircrack")} disabled={running}>
                aircrack-ng (CPU)
              </button>
            </div>
          </Field>

          {engine === "hashcat" && (
            <Field label="3 · Attack mode">
              <div className="seg">
                <button className={attackMode === "wordlist" ? "on" : ""} onClick={() => setAttackMode("wordlist")} disabled={running}>
                  Wordlist
                </button>
                <button className={attackMode === "rules" ? "on" : ""} onClick={() => setAttackMode("rules")} disabled={running}>
                  Wordlist + rules
                </button>
                <button className={attackMode === "mask" ? "on" : ""} onClick={() => setAttackMode("mask")} disabled={running}>
                  Mask / brute
                </button>
              </div>
            </Field>
          )}

          {needsWordlist && (
            <Field label="4 · Wordlist" hint="A bundled default ships with the app. Pick a discovered list, or type your own path below.">
              <select
                className="input"
                value={wordlist}
                onChange={(e) => setWordlist(e.target.value)}
                disabled={running || usingCustom}
              >
                {wordlists.length === 0 && <option value="">no wordlists found</option>}
                {wordlists.map((w) => (
                  <option key={w.path} value={w.path}>
                    {w.bundled ? "★ bundled — " : ""}{w.path} ({humanSize(w.size)}){w.needs_gunzip ? " — needs decompress" : ""}
                  </option>
                ))}
              </select>
              <Input
                mono
                value={customWordlist}
                onChange={(e) => setCustomWordlist(e.target.value)}
                disabled={running}
                placeholder="…or type a full path to your own wordlist, e.g. /home/you/lists/mylist.txt"
                style={{ marginTop: 8 }}
              />
              {hasFilePicker && (
                <div className="toolbar" style={{ marginTop: 8 }}>
                  <Button
                    small
                    onClick={pickWordlistFile}
                    disabled={running}
                    title="Browse for a wordlist file on this machine"
                    icon={
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                        <path
                          d="M1.75 4.5c0-.7.56-1.25 1.25-1.25h2.9c.33 0 .65.13.88.37l.9.88h4.42c.7 0 1.25.56 1.25 1.25v5.5c0 .7-.56 1.25-1.25 1.25H3c-.7 0-1.25-.56-1.25-1.25v-7Z"
                          stroke="currentColor"
                          strokeWidth="1.3"
                          strokeLinejoin="round"
                        />
                      </svg>
                    }
                  >
                    Select wordlist…
                  </Button>
                </div>
              )}
              {usingCustom && (
                <span className="field__hint">Using your custom path — clear the box to go back to the list above.</span>
              )}
            </Field>
          )}

          {effectiveMode === "rules" && (
            <Field label="4 · Rules (mutations applied to each word)">
              <select className="input" value={ruleFile} onChange={(e) => setRuleFile(e.target.value)} disabled={running}>
                {rules.length === 0 && <option value="">no rule files found</option>}
                {rules.map((r) => (
                  <option key={r.path} value={r.path}>{r.path}</option>
                ))}
              </select>
            </Field>
          )}

          {effectiveMode === "mask" && (
            <Field label="4 · Mask (hashcat: ?d digit ?l lower ?u upper ?s symbol ?a any)">
              <Input mono value={mask} onChange={(e) => setMask(e.target.value)} disabled={running} placeholder="?d?d?d?d?d?d?d?d" />
              <div className="toolbar" style={{ marginTop: 6 }}>
                {MASK_PRESETS.map((p) => (
                  <Button key={p.mask} small onClick={() => setMask(p.mask)} disabled={running} title={p.hint}>
                    {p.label}
                  </Button>
                ))}
              </div>
            </Field>
          )}

          {selected?.needs_gunzip && needsWordlist && !usingCustom && (
            <Banner variant="warn">
              This list is gzipped. Decompress it once (no root needed) — the result is selected automatically.
              <div className="toolbar" style={{ marginTop: 8 }}>
                <Button small icon={<IconDownload size={14} />} onClick={decompressSelected} disabled={decompressing}>
                  {decompressing ? "Decompressing…" : "Decompress now"}
                </Button>
              </div>
            </Banner>
          )}

          <div className="toolbar">
            <Button variant="primary" onClick={start} disabled={startDisabled} icon={<IconPlay size={16} />}>
              Start crack
            </Button>
            <Button variant="danger" onClick={stop} disabled={!running} icon={<IconStop size={16} />}>
              Stop
            </Button>
            <Button onClick={refreshWordlists} disabled={running} icon={<IconRefresh size={16} />}>
              Rescan
            </Button>
            <Button onClick={exportReport} icon={<IconDownload size={16} />} title="Save a Markdown engagement report — scope, recovered credentials, and the full audit timeline">
              Export report
            </Button>
          </div>
        </Card>

        <Card title="Crack status" icon={<IconKey size={18} />}>
          {status ? (
            <>
              {(running || pct != null) && (
                <div style={{ marginBottom: 14 }}>
                  <ProgressBar pct={pct ?? 0} />
                  <div className="field__hint" style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
                    <span>{pct != null ? `${pct}%` : "starting…"}</span>
                    <span>{status.speed ?? ""}{status.eta ? ` · ETA ${status.eta}` : ""}</span>
                  </div>
                </div>
              )}
              <dl className="kv">
                <dt>Running</dt>
                <dd>{status.running ? "yes" : "no"}</dd>
                <dt>Engine</dt>
                <dd>{status.engine ?? "—"}{status.attack_mode ? ` · ${status.attack_mode}` : ""}</dd>
                <dt>Target</dt>
                <dd>{status.bssid ?? "—"}</dd>
                <dt>Wordlist / mask</dt>
                <dd className="mono" style={{ wordBreak: "break-all" }}>{status.wordlist ?? "—"}</dd>
                <dt>Recovered</dt>
                <dd>{status.psk ? <strong>{status.psk}</strong> : "—"}</dd>
              </dl>
            </>
          ) : (
            <p className="muted">No crack yet.</p>
          )}
        </Card>
      </div>

      <Card title="Live output" icon={<IconKey size={18} />}>
        <pre className="console">{status?.output?.join("\n") ?? ""}</pre>
        <p className="field__hint">
          hashcat auto-uses the last converted <code>.hc22000</code>; aircrack-ng reads the original
          <code>.pcapng</code>. If hashcat errors that no <code>.hc22000</code> exists, go back to
          Capture and click "Convert to hashcat".
        </p>
      </Card>
    </div>
  );
}

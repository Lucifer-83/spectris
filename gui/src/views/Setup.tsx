import { useEffect, useState } from "react";
import { api, type HashcatBenchmark, type ToolsStatus } from "../api";
import { Banner, Button, Card, Pill } from "../components/ui";
import { IconChip, IconPlay, IconShield } from "../components/icons";

export function Setup() {
  const [prereqs, setPrereqs] = useState<{ platform: string; wslInstalled: boolean; usbipdInstalled: boolean } | null>(null);
  const [toolsStatus, setToolsStatus] = useState<ToolsStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [waiting, setWaiting] = useState(true);
  const [bench, setBench] = useState<HashcatBenchmark | null>(null);
  const [benchBusy, setBenchBusy] = useState(false);
  const [benchError, setBenchError] = useState<string | null>(null);

  const runBenchmark = async () => {
    setBenchError(null);
    setBenchBusy(true);
    try {
      setBench(await api.runHashcatBenchmark());
    } catch (e) {
      setBenchError(e instanceof Error ? e.message : String(e));
    } finally {
      setBenchBusy(false);
    }
  };

  const hasBridge = typeof window.wifiPentestApp?.checkPrereqs === "function";

  // The backend starts automatically (start.sh, Docker, or the Electron main
  // process on launch) — no "activate the server" step. Poll until it answers,
  // then show tool status. Adapters live in their own tab now.
  useEffect(() => {
    window.wifiPentestApp?.checkPrereqs().then(setPrereqs).catch(() => {});
    let cancelled = false;
    let tries = 0;
    const load = async () => {
      try {
        const t = await api.getToolsStatus();
        if (cancelled) return;
        setToolsStatus(t);
        setWaiting(false);
      } catch {
        tries += 1;
        if (cancelled) return;
        if (tries < 20) window.setTimeout(load, 1500);
        else {
          setWaiting(false);
          setError("Backend is not reachable on 127.0.0.1:8000. Launch the toolkit with start.sh, or check the backend log.");
        }
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="view">
      <p className="view__intro">
        Confirm prerequisites and system tools. The backend starts automatically — no server to
        activate. Manage your Wi-Fi cards and monitor mode in the <strong>Adapters</strong> tab.
      </p>

      {error && <Banner variant="error">{error}</Banner>}

      <Card title="Prerequisites" icon={<IconShield size={18} />}>
        {!hasBridge && (
          <p className="muted">
            Prerequisite checks run in the desktop app. Served over HTTP (Docker/browser) the backend
            and tools are provided by the container.
          </p>
        )}
        {hasBridge && !prereqs && <p className="muted">Checking environment…</p>}
        {prereqs && prereqs.platform === "win32" && (
          <div className="toolbar">
            <Pill variant={prereqs.wslInstalled ? "ok" : "danger"}>
              WSL2 {prereqs.wslInstalled ? "installed" : "not found"}
            </Pill>
            <Pill variant={prereqs.usbipdInstalled ? "ok" : "danger"}>
              usbipd-win {prereqs.usbipdInstalled ? "installed" : "not found"}
            </Pill>
          </div>
        )}
        {prereqs && prereqs.platform !== "win32" && (
          <p className="muted">
            Running on <code>{prereqs.platform}</code> — no WSL2/usbipd passthrough needed, the
            backend runs directly.
          </p>
        )}
      </Card>

      <Card
        title="System tools"
        icon={<IconChip size={18} />}
        subtitle="These CLI tools can't be bundled into the app — they're root-level system packages. Install any that are missing."
        right={
          toolsStatus ? (
            <Pill variant={toolsStatus.all_present ? "ok" : "warn"}>
              {toolsStatus.all_present ? "All present" : `${toolsStatus.missing_packages.length} missing`}
            </Pill>
          ) : undefined
        }
      >
        {!toolsStatus && <p className="muted">{waiting ? "Waiting for the backend…" : "Tool status unavailable."}</p>}
        {toolsStatus && (
          <>
            <div className="toolbar">
              {toolsStatus.tools.map((t) => (
                <Pill key={t.name} variant={t.present ? "ok" : "danger"} dot={false}>
                  {t.present ? "✓" : "✗"} {t.name}
                </Pill>
              ))}
            </div>
            {toolsStatus.install_hint && (
              <>
                <p className="field__hint">Install the missing packages:</p>
                <pre className="console" style={{ color: "#e7ecf4" }}>{toolsStatus.install_hint}</pre>
              </>
            )}

            <div style={{ borderTop: "1px solid var(--border)", paddingTop: 14, marginTop: 4 }}>
              <p className="field__hint" style={{ marginTop: 0 }}>
                Attacks run these tools as root via <code>sudo</code>. Passwordless sudo is granted
                automatically when you launch the toolkit with <code>start.sh</code> — you enter your
                password once at startup, so nothing here prompts again.
              </p>
            </div>
          </>
        )}
      </Card>

      <Card
        title="Crack speed benchmark"
        icon={<IconChip size={18} />}
        subtitle="Run hashcat's WPA (mode 22000) benchmark to see the expected crack rate on this machine — a quick gauge of how fast a real crack will go here. No target, no scope, pure local compute."
        right={bench && bench.speeds.length > 0 ? <Pill variant="ok">{bench.speeds[bench.speeds.length - 1]}</Pill> : undefined}
      >
        <div className="toolbar">
          <Button variant="primary" onClick={runBenchmark} disabled={benchBusy} icon={<IconPlay size={16} />}>
            {benchBusy ? "Benchmarking…" : "Run hashcat benchmark"}
          </Button>
        </div>
        {benchBusy && (
          <p className="field__hint">
            Running <code>hashcat -b -m 22000 --force</code> — this can take up to a minute.
          </p>
        )}
        {benchError && <Banner variant="error">{benchError}</Banner>}
        {bench && !benchBusy && (
          <>
            <p className="field__hint">Mode {bench.mode}</p>
            {bench.speeds.length > 0 ? (
              <div className="toolbar">
                {bench.speeds.map((s, i) => (
                  <Pill key={i} variant="accent" dot={false}>
                    {s}
                  </Pill>
                ))}
              </div>
            ) : (
              <p className="muted">Benchmark finished but no speed line was parsed — see raw output below.</p>
            )}
            <pre className="console">{bench.raw}</pre>
          </>
        )}
      </Card>
    </div>
  );
}

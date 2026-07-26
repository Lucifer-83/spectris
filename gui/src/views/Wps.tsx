import { useEffect, useRef, useState } from "react";
import { api, type ScopeState, type WpsAttack, type WpsEngine, type WpsState } from "../api";
import { useTarget } from "../TargetContext";
import { Banner, Button, Card, Field, Input, PasswordHit, Pill } from "../components/ui";
import { IconPlay, IconStop, IconWps } from "../components/icons";

export function Wps() {
  const { target, setTarget } = useTarget();
  const [attack, setAttack] = useState<WpsAttack>("pixie");
  const [engine, setEngine] = useState<WpsEngine>("reaver");
  const [status, setStatus] = useState<WpsState | null>(null);
  const [scope, setScope] = useState<ScopeState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);
  const consoleRef = useRef<HTMLPreElement | null>(null);

  const startPolling = () => {
    if (pollRef.current) return;
    pollRef.current = window.setInterval(async () => {
      try {
        const s = await api.getWpsStatus();
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

  useEffect(() => {
    api.getScope().then(setScope).catch(() => {});
    api
      .getWpsStatus()
      .then((s) => {
        setStatus(s);
        if (s.running) startPolling();
      })
      .catch(() => {});
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

  // keep the console scrolled to the newest line
  useEffect(() => {
    if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [status?.output]);

  const start = async () => {
    setError(null);
    try {
      await api.startWps(target.interfaceName, target.bssid, target.channel, attack, engine);
      setStatus((prev) => (prev ? { ...prev, running: true } : prev));
      startPolling();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const stop = async () => {
    await api.stopWps();
    setStatus(await api.getWpsStatus());
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const running = status?.running ?? false;
  const gotResult = !!(status?.pin || status?.psk);

  return (
    <div className="view">
      <p className="view__intro">
        WPS Pixie Dust and online PIN attacks against a single scope-authorized router, using
        reaver or bully. The backend rejects out-of-scope BSSIDs before starting. Pixie Dust is
        offline and fast; the online PIN attack is slow and may trigger AP lockouts.
      </p>

      {error && <Banner variant="error">{error}</Banner>}
      {!scope?.is_set && <Banner variant="warn">No engagement scope configured — set it in the Scope tab first.</Banner>}
      {status?.psk && <PasswordHit password={status.psk} target={status.bssid ?? undefined} />}

      <div className="grid-2">
        <Card
          title="WPS attack"
          icon={<IconWps size={18} />}
          right={running ? <Pill variant="ok" live>Running</Pill> : <Pill>Idle</Pill>}
        >
          <Field label="Attack type">
            <div className="seg">
              <button className={attack === "pixie" ? "on" : ""} onClick={() => setAttack("pixie")} disabled={running}>
                Pixie Dust
              </button>
              <button className={attack === "pin" ? "on" : ""} onClick={() => setAttack("pin")} disabled={running}>
                Online PIN
              </button>
            </div>
          </Field>

          <Field label="Engine">
            <div className="seg">
              <button className={engine === "reaver" ? "on" : ""} onClick={() => setEngine("reaver")} disabled={running}>
                reaver
              </button>
              <button className={engine === "bully" ? "on" : ""} onClick={() => setEngine("bully")} disabled={running}>
                bully
              </button>
            </div>
          </Field>

          <Field label="Monitor-mode interface">
            <Input mono value={target.interfaceName} onChange={(e) => setTarget({ interfaceName: e.target.value })} disabled={running} />
          </Field>
          <Field label="Target BSSID">
            <Input mono value={target.bssid} onChange={(e) => setTarget({ bssid: e.target.value })} placeholder="AA:BB:CC:DD:EE:FF" disabled={running} />
          </Field>
          <Field label="Channel">
            <Input mono value={target.channel} onChange={(e) => setTarget({ channel: e.target.value })} placeholder="6" disabled={running} />
          </Field>

          <div className="toolbar">
            <Button variant="primary" onClick={start} disabled={running} icon={<IconPlay size={16} />}>
              Start attack
            </Button>
            <Button variant="danger" onClick={stop} disabled={!running} icon={<IconStop size={16} />}>
              Stop
            </Button>
          </div>
        </Card>

        <Card title="Result" icon={<IconWps size={18} />}>
          {gotResult ? (
            <div className="result-hit">
              {status?.pin && (
                <div>
                  <div className="k">WPS PIN</div>
                  <div className="v">{status.pin}</div>
                </div>
              )}
              {/* the recovered WPA password (PSK) is shown in the green PasswordHit
                  at the top of the view — consistent with every other module */}
            </div>
          ) : (
            <p className="muted">
              {running ? "Attack in progress — PIN/PSK will appear here if recovered." : "No result yet."}
            </p>
          )}

          <dl className="kv">
            <dt>Target</dt>
            <dd>{status?.bssid ?? "—"}</dd>
            <dt>Attack</dt>
            <dd>{status?.attack ?? "—"}</dd>
            <dt>Engine</dt>
            <dd>{status?.engine ?? "—"}</dd>
          </dl>
        </Card>
      </div>

      {status?.diagnostic && !gotResult && (
        <Banner variant="warn">
          <strong>Why nothing happened:</strong> {status.diagnostic}
        </Banner>
      )}

      <Card title="Live output" icon={<IconWps size={18} />}>
        <pre className="console" ref={consoleRef}>
          {status?.output?.join("\n") ?? ""}
        </pre>
      </Card>
    </div>
  );
}

import { useEffect, useState } from "react";
import { api, type ScopeState } from "../api";
import { Banner, Button, Card, Field, Input, Pill } from "../components/ui";
import { IconLock, IconTarget } from "../components/icons";

export function Scope() {
  const [scope, setScope] = useState<ScopeState | null>(null);
  const [bssidInput, setBssidInput] = useState("");
  const [ssidInput, setSsidInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [activity, setActivity] = useState<{ busy: boolean; running: string[] } | null>(null);

  const load = () => api.getScope().then(setScope).catch((e) => setError(e.message));

  useEffect(() => {
    load();
    // Poll activity so scope edits lock while an operation runs — changing scope
    // mid-attack can leave a live attack pointed at an out-of-scope target.
    const tick = () => api.getActivity().then(setActivity).catch(() => {});
    tick();
    const id = window.setInterval(tick, 2000);
    return () => window.clearInterval(id);
  }, []);

  const busy = activity?.busy ?? false;

  const save = async () => {
    setError(null);
    setSaved(false);
    try {
      const bssids = bssidInput.split(",").map((s) => s.trim()).filter(Boolean);
      const ssids = ssidInput.split(",").map((s) => s.trim()).filter(Boolean);
      setScope(await api.setScope(bssids, ssids));
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="view">
      <p className="view__intro">
        Enter every BSSID / SSID this engagement authorizes. Scan and capture actions are rejected
        by the backend for anything outside this list — this is the safety guardrail.
      </p>

      {error && <Banner variant="error">{error}</Banner>}
      {saved && <Banner variant="ok">Scope updated.</Banner>}
      {busy && (
        <Banner variant="warn">
          🔒 Scope is <strong>locked</strong> — an operation is running ({activity?.running.join(", ")}).
          Stop it before changing scope, so a live attack can't end up pointed at an out-of-scope target.
        </Banner>
      )}

      <div className="grid-2">
        <Card title="Define scope" icon={<IconLock size={18} />}>
          <Field
            label="Authorized BSSIDs"
            hint="Comma-separated MAC addresses."
          >
            <Input
              mono
              value={bssidInput}
              onChange={(e) => setBssidInput(e.target.value)}
              placeholder="AA:BB:CC:DD:EE:FF, 11:22:33:44:55:66"
              disabled={busy}
            />
          </Field>

          <Field label="Authorized SSIDs" hint="Comma-separated network names.">
            <Input
              value={ssidInput}
              onChange={(e) => setSsidInput(e.target.value)}
              placeholder="CorpGuest, CorpLab"
              disabled={busy}
            />
          </Field>

          <Button variant="primary" onClick={save} icon={<IconLock size={16} />} disabled={busy}>
            {busy ? "Locked while running" : "Save scope"}
          </Button>
        </Card>

        <Card
          title="Current scope"
          icon={<IconTarget size={18} />}
          right={<Pill variant={scope?.is_set ? "accent" : "warn"}>{scope?.is_set ? "Active" : "Not set"}</Pill>}
        >
          {scope && (
            <dl className="kv">
              <dt>BSSIDs</dt>
              <dd>{scope.bssids.join("\n") || "(none)"}</dd>
              <dt>SSIDs</dt>
              <dd>{scope.ssids.join("\n") || "(none)"}</dd>
            </dl>
          )}
          {!scope && <p className="muted">Loading…</p>}
        </Card>
      </div>
    </div>
  );
}

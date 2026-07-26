import { useEffect, useRef, useState } from "react";
import { api, type CaptureState, type EvilTwinState, type ScopeState, type WirelessInterface } from "../api";
import { useTarget } from "../TargetContext";
import { Banner, Button, Card, Field, Input, PasswordHit, Pill } from "../components/ui";
import { IconClone, IconPlay, IconStop } from "../components/icons";

/** Interface picker — a dropdown of detected adapters (with their current mode),
 *  falling back to a free-text box if the backend hasn't detected any yet. */
function AdapterSelect({
  value,
  onChange,
  disabled,
  interfaces,
}: {
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  interfaces: WirelessInterface[];
}) {
  if (interfaces.length === 0) {
    return (
      <Input mono value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} placeholder="wlan1" />
    );
  }
  return (
    <select className="input" value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled}>
      {interfaces.map((i) => (
        <option key={i.name} value={i.name}>
          {i.name} — {i.connection === "internal" ? "INTERNAL · internet ⚠️" : "external"}
          {i.chipset ? ` · ${i.chipset}` : ""}
        </option>
      ))}
    </select>
  );
}

// rtw88 (in-kernel RTL88xxAU) does monitor mode but usually can't INJECT — bad
// for the deauth role. Detect so we can prefer a real injector and warn.
const isWeakInjector = (i?: WirelessInterface) => !!i && i.driver.startsWith("rtw88");

export function EvilTwin() {
  const { target, setTarget } = useTarget();
  const ssid = target.ssid;
  const bssid = target.bssid;
  const channel = target.channel || "6";

  const [interfaces, setInterfaces] = useState<WirelessInterface[]>([]);
  const [apInterface, setApInterface] = useState("");
  const [deauthInterface, setDeauthInterface] = useState("");
  const [doDeauth, setDoDeauth] = useState(true);

  const [status, setStatus] = useState<EvilTwinState | null>(null);
  const [scope, setScope] = useState<ScopeState | null>(null);
  const [capture, setCapture] = useState<CaptureState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const pollRef = useRef<number | null>(null);
  const portalLogRef = useRef<HTMLPreElement | null>(null);
  const deauthLogRef = useRef<HTMLPreElement | null>(null);

  const startPolling = () => {
    if (pollRef.current) return;
    pollRef.current = window.setInterval(async () => {
      try {
        setStatus(await api.getEvilTwinStatus());
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }, 1000);
  };

  useEffect(() => {
    api.getScope().then(setScope).catch(() => {});
    // Track the current capture so we can require a handshake before starting.
    const pollCapture = () => api.getCaptureStatus().then(setCapture).catch(() => {});
    pollCapture();
    const capId = window.setInterval(pollCapture, 3000);
    // Detect adapters so we can offer role-labelled pickers and pick two
    // DIFFERENT cards by default (AP on one, deauth on a monitor-capable other).
    api
      .getAdapterStatus()
      .then((a) => {
        setInterfaces(a.interfaces);
        // Pick sensible defaults that work with ANY adapters. Prefer external
        // cards, but fall back to the internal one when that's all there is (evil
        // twin needs two adapters — with a single external the internal is the only
        // second option). Deauth prefers a real injector (rtw88 only does monitor);
        // the AP just beacons, so the weaker/internal card is fine there.
        const all = a.interfaces;
        const monitor = all.filter((i) => i.supports_monitor);
        const deauthPick =
          monitor.find((i) => i.connection === "external" && !isWeakInjector(i)) ??
          monitor.find((i) => i.connection === "external") ??
          monitor.find((i) => !isWeakInjector(i)) ??
          monitor[0];
        const deauth = deauthPick?.name ?? "";
        const apPick =
          all.find((i) => i.connection === "external" && i.name !== deauth) ??
          all.find((i) => i.name !== deauth);
        const ap = apPick?.name ?? "";
        setApInterface((prev) => prev || ap);
        setDeauthInterface((prev) => prev || deauth);
      })
      .catch(() => {});
    api
      .getEvilTwinStatus()
      .then((s) => {
        setStatus(s);
        if (s.running) startPolling();
      })
      .catch(() => {});
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
      window.clearInterval(capId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // keep both live logs scrolled to the newest line
  useEffect(() => {
    if (portalLogRef.current) portalLogRef.current.scrollTop = portalLogRef.current.scrollHeight;
    if (deauthLogRef.current) deauthLogRef.current.scrollTop = deauthLogRef.current.scrollHeight;
  }, [status?.log]);

  const running = status?.running ?? false;
  // split the single tagged log into two live outputs: deauth vs captive portal
  const allLog = status?.log ?? [];
  const isDeauthLine = (l: string) => l.startsWith("[deauth]") || l.startsWith("[aireplay]");
  const deauthLog = allLog.filter(isDeauthLine);
  const portalLog = allLog.filter((l) => !isDeauthLine(l));
  const inScope = !!scope?.is_set && !!ssid && scope.ssids.includes(ssid);
  const captured = status?.captured ?? [];
  const sameAdapter = doDeauth && !!apInterface && apInterface === deauthInterface;

  // Using the internal (internet) adapter is ALLOWED — with a single external card
  // it's the only way to get the two adapters evil twin needs — but we warn that it
  // drops the host's internet while the twin runs.
  const isInternal = (name: string) => interfaces.find((i) => i.name === name)?.connection === "internal";
  const internalSelected = isInternal(apInterface) || (doDeauth && isInternal(deauthInterface));
  const needsSecondAdapter = doDeauth && interfaces.length > 0 && interfaces.length < 2;
  // warn if the deauth role is on an rtw88 card (monitor-only, won't inject)
  const weakDeauth = doDeauth && isWeakInjector(interfaces.find((i) => i.name === deauthInterface));

  // Evil twin REQUIRES a captured handshake for the target — without it the portal
  // can't tell the real Wi-Fi password from a wrong one. (The backend also blocks.)
  const captureHashes = capture?.hashes ?? 0;
  const captureBssid = capture?.bssid ?? null;
  const handshakeForTarget = captureHashes > 0 && !!bssid && captureBssid?.toLowerCase() === bssid.toLowerCase();
  const handshakeOtherTarget = captureHashes > 0 && !!bssid && !handshakeForTarget;

  // the winning submission: ONLY a handshake-verified password counts now.
  const confirmed = captured.find((c) => c.verified === true);

  const start = async () => {
    setError(null);
    setNotice(null);
    if (sameAdapter) {
      setError("The AP adapter and the deauth adapter must be two DIFFERENT cards — one broadcasts the twin, the other injects deauth.");
      return;
    }
    if (!handshakeForTarget) {
      setError("No handshake captured for this target — go to the Capture tab and capture the real AP's 4-way handshake first. Evil twin needs it to verify the Wi-Fi password.");
      return;
    }
    if (doDeauth && !bssid) {
      setError("No target BSSID — select the real AP on Scan & Target so its clients can be pushed to the twin.");
      return;
    }
    // Immediate feedback — the backend takes a few seconds (verify handshake +
    // raise the AP), so show a clear "starting" state so the click registers.
    setStarting(true);
    setNotice(`Starting evil twin — broadcasting "${ssid}", verifying the handshake and raising the AP…`);
    try {
      await api.startEvilTwin(apInterface, ssid, channel, {
        deauthInterface: doDeauth ? deauthInterface : undefined,
        targetBssid: doDeauth ? bssid : undefined,
      });
      startPolling();
      const s = await api.getEvilTwinStatus();
      setStatus(s);
      setNotice(
        doDeauth
          ? `Twin is broadcasting "${ssid}" and continuously deauthing the real AP's clients. It stops automatically once someone submits the CORRECT Wi-Fi password (verified against your handshake).`
          : `Twin is broadcasting "${ssid}". Deauth is off — clients won't be pushed over until they roam on their own.`,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setNotice(null);
    } finally {
      setStarting(false);
    }
  };

  const stop = async () => {
    setError(null);
    setNotice(null);
    await api.stopEvilTwin().catch(() => {});
    setStatus(await api.getEvilTwinStatus());
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const startDisabled =
    running || starting || !ssid || !apInterface || sameAdapter ||
    !handshakeForTarget || (!!scope?.is_set && !inScope);

  return (
    <div className="view">
      <p className="view__intro">
        Rogue access point ("evil twin") — broadcast a scope-authorized SSID and funnel clients to a
        captive portal that asks them to re-enter the Wi-Fi password. Uses <strong>two adapters</strong>:
        one becomes the fake AP, the other continuously deauthenticates <em>all</em> clients off the real
        AP so they reconnect to the twin. You may only impersonate an SSID (and deauth a BSSID) that is in
        the engagement scope.
      </p>

      <Banner variant="info">
        <div>
          <strong>How it works</strong>
          <ol style={{ margin: "6px 0 0", paddingLeft: 18, lineHeight: 1.6 }}>
            <li><strong>AP adapter</strong> broadcasts an open network with the target's name (the twin).</li>
            <li><strong>Deauth adapter</strong> (monitor mode) knocks <em>every</em> client off the real AP — continuously.</li>
            <li>Clients reconnect to the open twin → hit the "re-verify for security / MFA" portal.</li>
            <li>The deauth keeps running until someone submits the <strong>correct</strong> Wi-Fi password (checked against your captured handshake), then it stops on its own.</li>
          </ol>
        </div>
      </Banner>

      {error && <Banner variant="error">{error}</Banner>}
      {notice && <Banner variant="ok">{notice}</Banner>}
      {confirmed && (
        <PasswordHit
          password={confirmed.fields.password ?? Object.values(confirmed.fields).join(" ")}
          target={bssid || ssid || undefined}
          label="Wi-Fi password (verified ✓)"
        />
      )}
      {!scope?.is_set && <Banner variant="warn">No engagement scope configured — set authorized SSIDs/BSSIDs on the Scope tab first.</Banner>}
      {scope?.is_set && ssid !== "" && !inScope && (
        <Banner variant="warn">
          <code>{ssid}</code> is not in the authorized SSID scope — the backend will reject it. Add it under Scope first.
        </Banner>
      )}
      {sameAdapter && (
        <Banner variant="warn">
          AP adapter and deauth adapter are the same card. Pick two different adapters, or turn off deauth.
        </Banner>
      )}
      {!running && bssid && !handshakeForTarget && (
        <Banner variant="warn">
          🔑 <strong>Handshake required.</strong> Evil twin can't start without a captured 4-way handshake for
          this target — it needs it to verify the Wi-Fi password.{" "}
          {handshakeOtherTarget
            ? `The current capture is for a different AP (${captureBssid}).`
            : "Nothing captured yet."}{" "}
          Go to the <strong>Capture</strong> tab, capture <code>{bssid}</code>, then come back.
        </Banner>
      )}
      {internalSelected && (
        <Banner variant="warn">
          ⚠️ You're using the <strong>internal adapter</strong> (your internet card) for a role. That's fine
          if it's your only option, but it will <strong>drop this machine's Wi-Fi/internet</strong> while the
          twin runs. It's restored when you disable monitor mode / stop. Prefer an external USB card if you have one.
        </Banner>
      )}
      {needsSecondAdapter && (
        <Banner variant="warn">
          Evil twin needs <strong>two adapters</strong> (one fake AP, one deauth) — only one is detected.
          Plug in a second USB adapter, or turn off deauth to run AP-only.
        </Banner>
      )}
      {weakDeauth && !internalSelected && (
        <Banner variant="warn">
          The chosen <strong>deauth adapter</strong> uses the <code>rtw88</code> driver (RTL88xxAU) — it does monitor
          mode but usually <strong>can't inject</strong>, so the deauth may not work. Use the other external card
          (e.g. the Ralink/RT5370) for deauth and put this one on the fake AP instead.
        </Banner>
      )}
      {running && !status?.verification_active && (
        <Banner variant="warn">
          No usable handshake for verification — the attack <strong>can't tell a right password from a wrong one</strong>,
          so it won't auto-stop. Capture the real AP's handshake (Capture tab) first, then restart the twin.
        </Banner>
      )}
      {status?.deauth_error && (
        <Banner variant="error">
          Deauth isn't running: <code>{status.deauth_error}</code> — usually the deauth adapter can't inject
          (use the Ralink/Atheros USB card, not the internal one) or isn't in monitor mode (enable it in Setup).
        </Banner>
      )}

      <div className="grid-2">
        <Card
          title="Evil-twin setup"
          icon={<IconClone size={18} />}
          right={running ? <Pill variant="ok" live>Broadcasting</Pill> : <Pill>Idle</Pill>}
        >
          <Field
            label="SSID to clone (from Scan &amp; Target)"
            hint={ssid ? `The twin broadcasts "${ssid}" and the portal shows this exact name — it must be the authorized SSID from scope.` : "Must be an authorized SSID from the engagement scope."}
          >
            <Input value={ssid} onChange={(e) => setTarget({ ssid: e.target.value })} placeholder="CorpGuest" disabled={running} />
          </Field>
          <Field label="Channel">
            <Input mono value={channel} onChange={(e) => setTarget({ channel: e.target.value })} disabled={running} />
          </Field>

          {/* Step 1 — the AP */}
          <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12, marginTop: 6 }}>
            <Field label="1 · AP adapter — becomes the fake AP" hint="This card is put into AP mode by hostapd. Use a different card than the deauth one below.">
              <AdapterSelect value={apInterface} onChange={setApInterface} disabled={running} interfaces={interfaces} />
            </Field>
          </div>

          {/* Step 2 — the deauth */}
          <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12, marginTop: 6 }}>
            <label className="field__hint" style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 0, cursor: "pointer" }}>
              <input type="checkbox" checked={doDeauth} onChange={(e) => setDoDeauth(e.target.checked)} disabled={running} />
              <span><strong>2 · Continuously deauth the real AP</strong> so all its clients reconnect to the twin (recommended)</span>
            </label>

            {doDeauth && (
              <>
                <Field label="Real AP BSSID (deauth target, from Scan &amp; Target)" hint={bssid ? "All clients of this AP are kicked, continuously, until the password is verified." : "No BSSID selected — pick the real AP on Scan & Target."}>
                  <Input mono value={bssid} readOnly placeholder="select the real AP on Scan & Target" />
                </Field>
                <Field label="Deauth adapter — must be in monitor mode" hint="A second card in monitor mode (enable it in Setup). Injects the deauth; can't be the AP adapter.">
                  <AdapterSelect value={deauthInterface} onChange={setDeauthInterface} disabled={running} interfaces={interfaces} />
                </Field>
                <p className="field__hint">
                  Verification uses the handshake from the <strong>Capture</strong> step for this BSSID. Capture it
                  first so wrong passwords are rejected and the deauth only stops on the real one.
                </p>
              </>
            )}
          </div>

          <div className="toolbar" style={{ marginTop: 12 }}>
            <Button variant="primary" onClick={start} disabled={startDisabled} icon={<IconPlay size={16} />}>
              {starting ? "Starting…" : running ? "Running" : "Start evil twin"}
            </Button>
            <Button variant="danger" onClick={stop} disabled={!running && !starting} icon={<IconStop size={16} />}>
              Stop
            </Button>
          </div>
          {starting && (
            <p className="field__hint" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="spinner" /> Raising the AP and verifying the handshake — a few seconds…
            </p>
          )}
        </Card>

        <Card title="Live status" icon={<IconClone size={18} />}>
          <dl className="kv">
            <dt>Twin AP</dt>
            <dd>{running ? <Pill variant="ok" dot={false}>broadcasting</Pill> : "idle"}{status?.interface ? ` · ${status.interface}` : ""}</dd>
            <dt>SSID</dt>
            <dd>{(status?.ssid ?? ssid) || "—"}{status?.channel ? ` · ch ${status.channel}` : ""}</dd>
            <dt>Handshake</dt>
            <dd>
              {handshakeForTarget ? (
                <Pill variant="ok" dot={false}>captured ✓ ({captureHashes})</Pill>
              ) : (
                <span className="faint">{captureHashes > 0 ? "for a different AP" : "not captured"}</span>
              )}
            </dd>
            <dt>Deauth</dt>
            <dd>
              {status?.deauth_running ? <Pill variant="ok" dot={false} live>continuous</Pill> : (doDeauth ? (running ? "stopped" : "idle") : "off")}
            </dd>
            <dt>Deauth target</dt>
            <dd className="mono">{status?.deauth_target ?? (doDeauth ? bssid || "—" : "—")}</dd>
            <dt>Connected clients</dt>
            <dd>
              {(status?.clients_connected ?? 0) > 0 ? (
                <Pill variant="accent" dot={false} live>{status!.clients_connected} on the twin</Pill>
              ) : (
                <span className="faint">0</span>
              )}
            </dd>
            <dt>Verification</dt>
            <dd>
              {status?.verification_active ? (
                <Pill variant="accent" dot={false}>handshake — wrong rejected</Pill>
              ) : (
                <span className="faint">capture-only (no handshake)</span>
              )}
            </dd>
            <dt>Wrong attempts</dt>
            <dd className="mono">{status?.attempts ?? 0}</dd>
            <dt>Password captured</dt>
            <dd>{status?.password_captured ? <Pill variant="ok" dot={false}>yes</Pill> : "no"}</dd>
          </dl>

          {/* Submitted passwords — right here in the live-status area */}
          <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12, marginTop: 12 }}>
            <div className="field__label" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Submitted passwords</span>
              <Pill variant={captured.length ? "ok" : "neutral"} dot={false}>{captured.length}</Pill>
            </div>
            {captured.length === 0 ? (
              <p className="muted" style={{ marginTop: 6 }}>{running ? "Waiting for a client to submit…" : "Nothing captured yet."}</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8, maxHeight: 200, overflowY: "auto" }}>
                {captured.map((c, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "space-between", fontSize: "0.82rem" }}>
                    <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      <span className="faint mono" style={{ fontSize: "0.72rem" }}>{new Date(c.timestamp).toLocaleTimeString()} </span>
                      <span className="mono faint">{c.client}</span>{" · "}
                      <strong className="mono">{c.fields.password ?? Object.values(c.fields).join(" ")}</strong>
                    </span>
                    {c.verified === true ? (
                      <Pill variant="ok" dot={false}>✓ correct</Pill>
                    ) : c.verified === false ? (
                      <Pill variant="danger" dot={false}>✗ wrong</Pill>
                    ) : (
                      <Pill variant="warn" dot={false}>?</Pill>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {status?.portal_url && (
            <p className="field__hint" style={{ marginTop: 10 }}>
              Captive portal live at <code>{status.portal_url}</code> — connected clients are redirected here.
            </p>
          )}
          {!running && <p className="muted" style={{ marginTop: 10 }}>Configure both adapters above and start the twin.</p>}
        </Card>
      </div>

      <div className="grid-2">
        <Card
          title="Deauth — live output"
          icon={<IconClone size={18} />}
          right={
            status?.deauth_running ? <Pill variant="warn" dot={false} live>kicking clients</Pill>
            : status?.deauth_target ? <Pill dot={false}>stopped</Pill> : undefined
          }
        >
          <pre className="console" ref={deauthLogRef} style={{ maxHeight: 260 }}>
            {deauthLog.join("\n")}
          </pre>
          <p className="field__hint">
            Continuous deauth against the real AP so its clients drop and reconnect to the twin
            (aireplay-ng output). Stops automatically once the correct Wi-Fi password is captured.
          </p>
        </Card>

        <Card
          title="Captive portal — live output"
          icon={<IconClone size={18} />}
          right={(status?.clients_connected ?? 0) > 0 ? <Pill variant="accent" dot={false} live>{status!.clients_connected} client(s)</Pill> : undefined}
        >
          <pre className="console" ref={portalLogRef} style={{ maxHeight: 260 }}>
            {portalLog.join("\n")}
          </pre>
          <p className="field__hint">
            The fake AP, connected devices, and every portal password submission (green = the real Wi-Fi
            password, which stops the attack).
          </p>
        </Card>
      </div>
    </div>
  );
}

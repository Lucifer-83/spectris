import { useEffect, useState } from "react";
import { api, type AdapterStatus, type WirelessInterface } from "../api";
import { Banner, Button, Card, Pill } from "../components/ui";
import { IconChip, IconRefresh } from "../components/icons";

export function Adapters() {
  const [adapterStatus, setAdapterStatus] = useState<AdapterStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [waiting, setWaiting] = useState(true);

  useEffect(() => {
    let cancelled = false;
    let tries = 0;
    const load = async () => {
      try {
        const a = await api.getAdapterStatus();
        if (cancelled) return;
        setAdapterStatus(a);
        setWaiting(false);
      } catch {
        tries += 1;
        if (cancelled) return;
        if (tries < 20) window.setTimeout(load, 1500);
        else {
          setWaiting(false);
          setError("Backend not reachable on 127.0.0.1:8000 — launch the toolkit with start.sh.");
        }
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const refresh = async () => {
    setError(null);
    try {
      setAdapterStatus(await api.getAdapterStatus());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const toggleMonitorMode = async (interfaceName: string, enable: boolean) => {
    setError(null);
    setNotice(null);
    try {
      await api.setMonitorMode(interfaceName, enable);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const freeFromNM = async (interfaceName: string) => {
    setError(null);
    setNotice(null);
    try {
      const res = await api.killInterferers(interfaceName);
      setNotice(res.output);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const connPill = (iface: WirelessInterface) => {
    if (iface.connection === "external") return <Pill variant="accent" dot={false}>External · USB</Pill>;
    if (iface.connection === "internal") return <Pill variant="warn" dot={false}>Internal · internet</Pill>;
    return <Pill variant="neutral" dot={false}>unknown</Pill>;
  };

  return (
    <div className="view">
      <p className="view__intro">
        Every wireless interface, with whether it's a built-in card or a plugged-in USB dongle, its
        model, driver and bands — so you can tell multiple dongles apart. Scan &amp; Capture need a
        monitor-mode adapter. You <em>can</em> use the <strong>internal</strong> card (e.g. when it's your
        only second adapter for evil twin), but monitor mode on it drops this machine's internet until you
        disable it — prefer an external USB adapter when you have one.
      </p>

      {error && <Banner variant="error">{error}</Banner>}
      {notice && <Banner variant="ok">{notice}</Banner>}

      <Card title="Wireless adapters" icon={<IconChip size={18} />} right={
        <Button small variant="ghost" onClick={refresh} icon={<IconRefresh size={14} />}>Refresh</Button>
      }>
        {!adapterStatus && <p className="muted">{waiting ? "Detecting adapters…" : "No adapter data — press Refresh."}</p>}
        {adapterStatus && (
          <>
            <div>
              <Pill variant={adapterStatus.monitor_capable_found ? "ok" : "danger"}>
                {adapterStatus.monitor_capable_found ? "Monitor-capable adapter found" : "No monitor-capable adapter"}
              </Pill>
            </div>

            {adapterStatus.interfaces.some((i) => i.connection === "internal" && i.mode === "monitor") && (
              <Banner variant="warn">
                ⚠️ An <strong>internal</strong> adapter is in monitor mode — that's your built-in internet card,
                so your connection is likely down. Disable monitor on it and use an <strong>external USB</strong>
                adapter instead.
              </Banner>
            )}

            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Interface</th>
                    <th>Type</th>
                    <th>Model / chipset</th>
                    <th>Driver</th>
                    <th>Bands</th>
                    <th>Mode</th>
                    <th>Monitor</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {adapterStatus.interfaces.map((iface) => {
                    const internal = iface.connection === "internal";
                    return (
                      <tr key={iface.name}>
                        <td className="mono">
                          {iface.name}
                          <div className="faint mono" style={{ fontSize: "0.72rem" }}>{iface.phy}</div>
                        </td>
                        <td>{connPill(iface)}</td>
                        <td>{iface.chipset || <span className="faint">unknown</span>}</td>
                        <td className="mono">{iface.driver || <span className="faint">—</span>}</td>
                        <td>
                          {iface.bands.length ? (
                            <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>
                              {iface.bands.map((b) => (
                                <Pill key={b} variant="neutral" dot={false}>{b.replace(" GHz", "")}</Pill>
                              ))}
                              <span className="faint" style={{ fontSize: "0.72rem" }}>GHz</span>
                            </span>
                          ) : (
                            <span className="faint">—</span>
                          )}
                        </td>
                        <td>
                          <Pill variant={iface.mode === "monitor" ? "accent" : "neutral"} dot={false}>{iface.mode}</Pill>
                        </td>
                        <td>{iface.supports_monitor ? "✓" : "—"}</td>
                        <td>
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                            {iface.supports_monitor &&
                              (iface.mode !== "monitor" ? (
                                <Button
                                  small
                                  variant={internal ? "danger" : "primary"}
                                  onClick={() => toggleMonitorMode(iface.name, true)}
                                  title={internal ? "This is your internet card — monitor mode will drop this machine's Wi-Fi until you disable it." : undefined}
                                >
                                  Enable monitor{internal ? " ⚠️" : ""}
                                </Button>
                              ) : (
                                <Button small variant="ghost" onClick={() => toggleMonitorMode(iface.name, false)}>
                                  Disable
                                </Button>
                              ))}
                            <Button small variant="ghost" onClick={() => freeFromNM(iface.name)} title="Tell NetworkManager to stop managing this adapter (surgical — other adapters untouched)">
                              Free from NM
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <p className="field__hint">
              The interface keeps its name (e.g. <code>wlan1</code>). Scan &amp; Capture need it in
              <strong> monitor</strong> mode. WPS/Pixie and deauth also need an adapter that
              <strong> injects</strong> — Ralink (rt2800usb) and Atheros are reliable; many RTL8821AU
              (<code>rtw88</code>) builds do monitor but can't inject.
            </p>

            <div style={{ borderTop: "1px solid var(--border)", paddingTop: 14, marginTop: 4 }}>
              <p className="field__hint" style={{ marginTop: 0 }}>
                Monitor mode won't stick (reaver/aireplay stuck in a deauth + "Receive timeout" loop)?
                NetworkManager is fighting it. Use <strong>Free from NM</strong> on that external adapter — it's
                surgical (only that card), so your internet stays up. We never touch the internal adapter.
              </p>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}

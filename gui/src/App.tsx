import { Fragment, useEffect, useRef, useState } from "react";
import { Setup } from "./views/Setup";
import { Adapters } from "./views/Adapters";
import { Scope } from "./views/Scope";
import { ScanTarget } from "./views/ScanTarget";
import { Action } from "./views/Action";
import { Crack } from "./views/Crack";
import { Auto } from "./views/Auto";
import { Wps } from "./views/Wps";
import { Deauth } from "./views/Deauth";
import { EvilTwin } from "./views/EvilTwin";
import { ResultsLog } from "./views/ResultsLog";
import { About } from "./views/About";
import { api } from "./api";
import {
  IconAlert,
  IconBolt,
  IconChip,
  IconClone,
  IconKey,
  IconLog,
  IconScan,
  IconSetup,
  IconSpectris,
  IconTarget,
  IconWps,
  IconInfo,
} from "./components/icons";
import { AttackMeta, Pill } from "./components/ui";
import { AppearanceMenu } from "./Appearance";
import { ATTACK_INFO } from "./attackInfo";
import "./App.css";

// Ordered as the engagement actually flows: get ready → find targets → attack →
// review. Within Attack the steps go fastest-path-first: Auto (one click), then
// WPS (quick if WPS is open), then the manual WPA2 chain Capture → Crack (Capture
// MUST precede Crack), then Evil Twin (social, last resort). The `group` drives
// the sidebar section headers so nine tabs read as four short phases.
const TABS = [
  { key: "setup", label: "Setup", title: "Setup — Prerequisites & Tools", Icon: IconSetup, component: Setup, group: "Prepare" },
  { key: "adapters", label: "Adapters", title: "Wireless Adapters", Icon: IconChip, component: Adapters, group: "Prepare" },
  { key: "scope", label: "Scope", title: "Engagement Scope", Icon: IconTarget, component: Scope, group: "Prepare" },
  { key: "scan", label: "Scan & Target", title: "Scan & Target", Icon: IconScan, component: ScanTarget, group: "Recon" },
  { key: "auto", label: "Auto (1-click)", title: "Auto — Capture → Deauth → Convert → Crack", Icon: IconChip, component: Auto, group: "Attack" },
  { key: "wps", label: "WPS Attack", title: "WPS — Pixie Dust / PIN", Icon: IconWps, component: Wps, group: "Attack" },
  { key: "action", label: "Handshake Capture", title: "Handshake Capture — automatic", Icon: IconBolt, component: Action, group: "Attack" },
  { key: "deauth", label: "Deauth", title: "Deauth — kick clients", Icon: IconAlert, component: Deauth, group: "Attack" },
  { key: "crack", label: "Crack", title: "Crack — Offline PSK Recovery", Icon: IconKey, component: Crack, group: "Attack" },
  { key: "eviltwin", label: "Evil Twin", title: "Evil Twin — Rogue AP + Captive Portal", Icon: IconClone, component: EvilTwin, group: "Attack" },
  { key: "log", label: "Results & Log", title: "Results & Audit Log", Icon: IconLog, component: ResultsLog, group: "Utilities" },
  { key: "about", label: "About", title: "About Spectris", Icon: IconInfo, component: About, group: "Utilities" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

/** Polls the backend so the topbar can show live connectivity + scope state.
 *  getScope() needs no hardware, so it doubles as a cheap health check. */
function useEngagementStatus() {
  const [online, setOnline] = useState(false);
  const [scopeSet, setScopeSet] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const scope = await api.getScope();
        if (cancelled) return;
        setOnline(true);
        setScopeSet(scope.is_set);
      } catch {
        if (!cancelled) setOnline(false);
      }
    };
    tick();
    const id = window.setInterval(tick, 4000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  return { online, scopeSet };
}

const SIDEBAR_MIN = 220;
const SIDEBAR_MAX = 620;
const SIDEBAR_DEFAULT = 300;

/** Drag-to-resize sidebar width, persisted across sessions. */
function useSidebarWidth() {
  const [width, setWidth] = useState<number>(() => {
    const saved = Number(localStorage.getItem("wpt.sidebarWidth"));
    return saved >= SIDEBAR_MIN && saved <= SIDEBAR_MAX ? saved : SIDEBAR_DEFAULT;
  });
  const [dragging, setDragging] = useState(false);
  const widthRef = useRef(width);
  widthRef.current = width;

  useEffect(() => {
    if (!dragging) return;
    const onMove = (e: MouseEvent) => setWidth(Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, e.clientX)));
    const onUp = () => {
      setDragging(false);
      localStorage.setItem("wpt.sidebarWidth", String(widthRef.current));
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [dragging]);

  const reset = () => {
    setWidth(SIDEBAR_DEFAULT);
    localStorage.setItem("wpt.sidebarWidth", String(SIDEBAR_DEFAULT));
  };
  return { width, dragging, startDrag: () => setDragging(true), reset };
}

/** Minimize / maximize / close buttons for the frameless desktop window.
 *  Renders nothing in the browser build (no bridge). */
function WindowControls() {
  const bridge = window.wifiPentestApp;
  if (typeof bridge?.closeWindow !== "function") return null;
  return (
    <div className="winctl">
      <button className="winctl__btn" title="Minimize" aria-label="Minimize" onClick={() => bridge.minimizeWindow()}>
        <svg width="12" height="12" viewBox="0 0 12 12"><rect x="1.5" y="5.5" width="9" height="1.2" rx="0.6" fill="currentColor" /></svg>
      </button>
      <button className="winctl__btn" title="Maximize" aria-label="Maximize" onClick={() => bridge.toggleMaximizeWindow()}>
        <svg width="12" height="12" viewBox="0 0 12 12"><rect x="2" y="2" width="8" height="8" rx="1.4" fill="none" stroke="currentColor" strokeWidth="1.2" /></svg>
      </button>
      <button className="winctl__btn winctl__btn--close" title="Close" aria-label="Close" onClick={() => bridge.closeWindow()}>
        <svg width="12" height="12" viewBox="0 0 12 12"><path d="M3 3l6 6M9 3l-6 6" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" /></svg>
      </button>
    </div>
  );
}

function App() {
  const [activeTab, setActiveTab] = useState<TabKey>("setup");
  const active = TABS.find((t) => t.key === activeTab)!;
  const ActiveComponent = active.component;
  const { online, scopeSet } = useEngagementStatus();
  const sidebar = useSidebarWidth();

  return (
    <div className="app" style={{ gridTemplateColumns: `${sidebar.width}px 1fr` }}>
      <aside className="sidebar">
        <div className="sidebar__scroll">
        <div className="brand" title="Nothing on the air stays hidden.">
          <span className="brand__logo">
            <IconSpectris size={20} />
          </span>
          <div>
            <div className="brand__name">Spectris</div>
            <div className="brand__tag">Nothing on the air stays hidden.</div>
          </div>
        </div>

        {TABS.map((tab, i) => (
          <Fragment key={tab.key}>
            {(i === 0 || TABS[i - 1].group !== tab.group) && (
              <div className="nav-label">{tab.group}</div>
            )}
            <button
              className={`nav-item ${tab.key === activeTab ? "active" : ""}`}
              onClick={() => setActiveTab(tab.key)}
            >
              <tab.Icon size={18} />
              <span className="nav-item__body">
                <span className="nav-item__label">{tab.label}</span>
                <span className="nav-item__tag">{ATTACK_INFO[tab.key]?.tagline}</span>
              </span>
            </button>
          </Fragment>
        ))}

        <div className="sidebar__footer">
          Authorized engagements only. Every action is scope-gated and logged.
        </div>
        </div>
      </aside>

      <div className="main">
        <div
          className={`resizer ${sidebar.dragging ? "dragging" : ""}`}
          onMouseDown={sidebar.startDrag}
          onDoubleClick={sidebar.reset}
          title="Drag to resize the sidebar · double-click to reset"
          role="separator"
          aria-orientation="vertical"
        />
        <div className="scroll-area">
          <header className="topbar">
            <div className="topbar__title">{active.title}</div>
            <div className="topbar__status">
              <Pill variant={online ? "ok" : "danger"} live={online}>
                {online ? "Backend online" : "Backend offline"}
              </Pill>
              <Pill variant={scopeSet ? "accent" : "warn"}>
                {scopeSet ? "Scope set" : "No scope"}
              </Pill>
              <AppearanceMenu />
              <WindowControls />
            </div>
          </header>

          <main className="content" key={activeTab}>
            {active.key !== "about" && ATTACK_INFO[active.key] && <AttackMeta info={ATTACK_INFO[active.key]} />}
            <ActiveComponent />
          </main>
        </div>
      </div>
    </div>
  );
}

export default App;

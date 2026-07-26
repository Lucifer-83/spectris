/* Appearance: Light / Dark / Auto theme + a "liquid glass" transparency slider.
 * Theme is applied by toggling `.theme-light` on <html>; the slider drives the
 * --glass-alpha / --glass-blur-px CSS vars. Both persist in localStorage. */
import { useEffect, useRef, useState } from "react";
import { IconContrast } from "./components/icons";

type Theme = "auto" | "light" | "dark";

const THEME_KEY = "wpt.theme";
const GLASS_KEY = "wpt.glass";
const GLASS_DEFAULT = 45;

function readGlass(): number {
  // NOTE: Number(null) === 0, which would wrongly pass a ">= 0" check — so guard
  // the null (unset) case explicitly and fall back to the default.
  const raw = localStorage.getItem(GLASS_KEY);
  const v = raw === null ? NaN : Number(raw);
  return v >= 0 && v <= 100 ? v : GLASS_DEFAULT;
}

function systemIsLight(): boolean {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
}

function applyTheme(theme: Theme) {
  const light = theme === "light" || (theme === "auto" && systemIsLight());
  document.documentElement.classList.toggle("theme-light", light);
}

function applyGlass(pct: number) {
  // Slider 0→100: right = more transparent + more frosted ("liquid glass").
  // ~2x more transparent than before across the whole range: alpha 0.64→0.10
  // (was 0.82→0.30). --panel-alpha / topbar / chrome-bg all derive from this.
  const t = Math.min(100, Math.max(0, pct)) / 100;
  const alpha = (0.64 - t * 0.54).toFixed(3); // 0.64 (mostly solid) → 0.10 (very see-through)
  const blur = Math.round(10 + t * 30); // 10px → 40px (more frost to match the extra transparency)
  const root = document.documentElement;
  root.style.setProperty("--glass-alpha", alpha);
  root.style.setProperty("--glass-blur-px", `${blur}px`);
}

/** Apply saved appearance BEFORE React renders, so there's no flash. Called in main.tsx. */
// eslint-disable-next-line react-refresh/only-export-components
export function initAppearance() {
  const theme = (localStorage.getItem(THEME_KEY) as Theme) || "auto";
  applyTheme(theme);
  applyGlass(readGlass());
}

export function AppearanceMenu() {
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem(THEME_KEY) as Theme) || "auto");
  const [glass, setGlass] = useState<number>(readGlass);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    applyTheme(theme);
    localStorage.setItem(THEME_KEY, theme);
    if (theme !== "auto") return;
    // follow the system while in Auto
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => applyTheme("auto");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme]);

  useEffect(() => {
    applyGlass(glass);
    localStorage.setItem(GLASS_KEY, String(glass));
  }, [glass]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const themes: Theme[] = ["auto", "light", "dark"];

  return (
    <div className="appearance" ref={ref}>
      <button className="appearance__btn" onClick={() => setOpen((o) => !o)} title="Appearance" aria-label="Appearance">
        <IconContrast size={17} />
      </button>
      {open && (
        <div className="appearance__panel glass">
          <div className="appearance__title">Appearance</div>
          <div className="seg" style={{ width: "100%" }}>
            {themes.map((t) => (
              <button key={t} className={theme === t ? "on" : ""} onClick={() => setTheme(t)} style={{ flex: 1 }}>
                {t[0].toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
          <div className="appearance__row">
            <span>Glass transparency</span>
            <span className="faint mono">{glass}%</span>
          </div>
          <input
            className="range"
            type="range"
            min={0}
            max={100}
            value={glass}
            onChange={(e) => setGlass(Number(e.target.value))}
            aria-label="Glass transparency"
          />
          <p className="appearance__hint">Frosts the background through every panel. Windows stay readable (half the transparency).</p>
        </div>
      )}
    </div>
  );
}

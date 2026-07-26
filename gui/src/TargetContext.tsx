/* Shared "current target" across all attack views so selecting an AP in
 * Scan & Target auto-fills Capture / WPS / Evil Twin — and the selection
 * persists when switching tabs instead of resetting per-view. */
import { createContext, useContext, useState, type ReactNode } from "react";

export interface Target {
  interfaceName: string;
  bssid: string;
  ssid: string;
  channel: string;
  encryption: string;
}

const DEFAULT_TARGET: Target = { interfaceName: "wlan1", bssid: "", ssid: "", channel: "", encryption: "" };

interface TargetCtx {
  target: Target;
  setTarget: (patch: Partial<Target>) => void;
}

const Ctx = createContext<TargetCtx | null>(null);

export function TargetProvider({ children }: { children: ReactNode }) {
  const [target, setTargetState] = useState<Target>(DEFAULT_TARGET);
  const setTarget = (patch: Partial<Target>) => setTargetState((t) => ({ ...t, ...patch }));
  return <Ctx.Provider value={{ target, setTarget }}>{children}</Ctx.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTarget(): TargetCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useTarget must be used within a TargetProvider");
  return ctx;
}

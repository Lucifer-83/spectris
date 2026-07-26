const BASE_URL = "http://127.0.0.1:8000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `${path} failed with ${res.status}`);
  }
  return res.json();
}

export interface WirelessInterface {
  name: string;
  phy: string;
  mode: string;
  supports_monitor: boolean;
  driver: string;
  bus: string; // "usb" | "pci" | "unknown"
  connection: string; // "external" | "internal" | "unknown"
  chipset: string; // human model, e.g. "Ralink 802.11n (148f:5370)"
  bands: string[]; // ["2.4 GHz", "5 GHz"]
}

export interface AdapterStatus {
  interfaces: WirelessInterface[];
  monitor_capable_found: boolean;
}

export interface ScopeState {
  bssids: string[];
  ssids: string[];
  is_set: boolean;
}

export interface ToolInfo {
  name: string;
  present: boolean;
  path: string | null;
  capability: string;
  package: string;
}

export interface ToolsStatus {
  tools: ToolInfo[];
  all_present: boolean;
  missing_packages: string[];
  install_hint: string | null;
}

export interface HashcatBenchmark {
  mode: string;
  speeds: string[];
  raw: string;
}

export interface EngagementReport {
  filename: string;
  content: string;
  mimetype: string;
}

export interface AccessPoint {
  bssid: string;
  ssid: string;
  channel: string;
  signal_dbm: string;
  encryption: string;
  clients: number;
}

export interface ScanResults {
  running: boolean;
  access_points: AccessPoint[];
}

export interface WpsScanAp {
  bssid: string;
  locked: boolean;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  action: string;
  target: string | null;
  result: string;
  detail: string;
}

export interface CaptureState {
  running: boolean;
  interface: string | null;
  bssid: string | null;
  output_pcapng: string | null;
  hash_file: string | null;
  hashes: number;
  output: string[];
}

export type WpsAttack = "pixie" | "pin";
export type WpsEngine = "reaver" | "bully";

export interface WpsState {
  running: boolean;
  interface: string | null;
  bssid: string | null;
  attack: WpsAttack | null;
  engine: WpsEngine | null;
  pin: string | null;
  psk: string | null;
  output: string[];
  diagnostic: string | null;
}

export type CrackEngine = "hashcat" | "aircrack";
export type CrackAttackMode = "wordlist" | "rules" | "mask";

export interface Wordlist {
  path: string;
  size: number;
  needs_gunzip: boolean;
  bundled?: boolean;
}

export interface CrackRule {
  path: string;
  size: number;
}

export interface CrackOptions {
  wordlist?: string;
  attackMode?: CrackAttackMode;
  rules?: string;
  mask?: string;
}

export interface CrackState {
  running: boolean;
  engine: CrackEngine | null;
  attack_mode: CrackAttackMode | null;
  bssid: string | null;
  wordlist: string | null;
  hash_file: string | null;
  psk: string | null;
  exhausted: boolean;
  progress_pct: number | null;
  speed: string | null;
  eta: string | null;
  output: string[];
}

export interface AutoState {
  running: boolean;
  phase: string; // idle|capturing|converting|cracking|done|failed|stopped
  interface: string | null;
  bssid: string | null;
  channel: string | null;
  wordlist: string | null;
  detail: string;
  hashes: number;
  psk: string | null;
  error: string | null;
}

export interface DeauthState {
  running: boolean;
  interface: string | null;
  bssid: string | null;
  client: string | null;
  count: number | null;
  output: string[];
}

export interface CapturedCred {
  timestamp: string;
  client: string;
  fields: Record<string, string>;
  verified: boolean | null; // true = confirmed against handshake, false = wrong guess, null = unverified
}

export interface EvilTwinState {
  running: boolean;
  interface: string | null;
  ssid: string | null;
  channel: string | null;
  portal_url: string | null;
  deauth_running: boolean;
  deauth_target: string | null;
  deauth_error: string | null;
  verification_active: boolean;
  password_captured: boolean;
  attempts: number;
  clients_connected: number;
  log: string[];
  captured: CapturedCred[];
}

export interface EvilTwinOptions {
  deauthInterface?: string;
  targetBssid?: string;
  handshakeFile?: string;
}

export const api = {
  getToolsStatus: () => request<ToolsStatus>("/tools/status"),
  getAdapterStatus: () => request<AdapterStatus>("/adapter/status"),
  setMonitorMode: (interfaceName: string, enable: boolean) =>
    request<{ interface: string; mode: string }>("/adapter/monitor-mode", {
      method: "POST",
      body: JSON.stringify({ interface: interfaceName, enable }),
    }),
  killInterferers: (interfaceName: string) =>
    request<{ output: string }>("/adapter/kill-interferers", {
      method: "POST",
      body: JSON.stringify({ interface: interfaceName }),
    }),
  getScope: () => request<ScopeState>("/engagement/scope"),
  getActivity: () => request<{ busy: boolean; running: string[] }>("/engagement/activity"),
  setScope: (bssids: string[], ssids: string[]) =>
    request<ScopeState>("/engagement/scope", {
      method: "POST",
      body: JSON.stringify({ bssids, ssids }),
    }),
  startScan: (interfaceName: string) =>
    request<{ status: string; interface: string }>("/scan/start", {
      method: "POST",
      body: JSON.stringify({ interface: interfaceName }),
    }),
  stopScan: () => request<{ status: string }>("/scan/stop", { method: "POST" }),
  getScanResults: () => request<ScanResults>("/scan/results"),
  scanWps: (interfaceName: string) =>
    request<{ access_points: WpsScanAp[] }>("/scan/wps", {
      method: "POST",
      body: JSON.stringify({ interface: interfaceName }),
    }),
  startCapture: (interfaceName: string, bssid: string, channel: string) =>
    request<{ status: string; bssid: string; output_pcapng: string }>("/capture/start", {
      method: "POST",
      body: JSON.stringify({ interface: interfaceName, bssid, channel }),
    }),
  stopCapture: () => request<{ status: string }>("/capture/stop", { method: "POST" }),
  getCaptureStatus: () => request<CaptureState>("/capture/status"),
  convertCapture: () => request<{ hash_file: string }>("/capture/convert", { method: "POST" }),
  getWordlists: () => request<{ wordlists: Wordlist[]; rules: CrackRule[] }>("/crack/wordlists"),
  decompressWordlist: (path: string) =>
    request<{ path: string; size: number }>("/crack/decompress", {
      method: "POST",
      body: JSON.stringify({ path }),
    }),
  runHashcatBenchmark: () => request<HashcatBenchmark>("/crack/benchmark", { method: "POST" }),
  startCrack: (bssid: string, engine: CrackEngine, opts: CrackOptions) =>
    request<{ status: string; bssid: string; engine: string }>("/crack/start", {
      method: "POST",
      body: JSON.stringify({
        bssid,
        engine,
        wordlist: opts.wordlist || "",
        attack_mode: opts.attackMode || "wordlist",
        rules: opts.rules || null,
        mask: opts.mask || null,
      }),
    }),
  stopCrack: () => request<{ status: string }>("/crack/stop", { method: "POST" }),
  getCrackStatus: () => request<CrackState>("/crack/status"),
  startAuto: (interfaceName: string, bssid: string, channel: string, wordlist: string, encryption?: string, deauthCount = 8, captureSeconds = 60) =>
    request<{ status: string; bssid: string }>("/auto/start", {
      method: "POST",
      body: JSON.stringify({
        interface: interfaceName, bssid, channel, wordlist,
        encryption: encryption || null, deauth_count: deauthCount, capture_seconds: captureSeconds,
      }),
    }),
  stopAuto: () => request<{ status: string }>("/auto/stop", { method: "POST" }),
  getAutoStatus: () => request<AutoState>("/auto/status"),
  startWps: (interfaceName: string, bssid: string, channel: string, attack: WpsAttack, engine: WpsEngine) =>
    request<{ status: string; bssid: string; attack: string; engine: string }>("/wps/start", {
      method: "POST",
      body: JSON.stringify({ interface: interfaceName, bssid, channel, attack, engine }),
    }),
  stopWps: () => request<{ status: string }>("/wps/stop", { method: "POST" }),
  getWpsStatus: () => request<WpsState>("/wps/status"),
  startDeauth: (interfaceName: string, bssid: string, count: number, channel?: string, client?: string) =>
    request<{ status: string; bssid: string; count: number }>("/deauth/start", {
      method: "POST",
      body: JSON.stringify({ interface: interfaceName, bssid, count, channel: channel || null, client: client || null }),
    }),
  stopDeauth: () => request<{ status: string }>("/deauth/stop", { method: "POST" }),
  getDeauthStatus: () => request<DeauthState>("/deauth/status"),
  startEvilTwin: (interfaceName: string, ssid: string, channel: string, opts: EvilTwinOptions = {}) =>
    request<{ status: string; ssid: string }>("/eviltwin/start", {
      method: "POST",
      body: JSON.stringify({
        interface: interfaceName,
        ssid,
        channel,
        deauth_interface: opts.deauthInterface || null,
        target_bssid: opts.targetBssid || null,
        handshake_file: opts.handshakeFile || null,
      }),
    }),
  stopEvilTwin: () => request<{ status: string; captured: number }>("/eviltwin/stop", { method: "POST" }),
  getEvilTwinStatus: () => request<EvilTwinState>("/eviltwin/status"),
  getLog: () => request<LogEntry[]>("/log"),
  clearLog: () => request<{ status: string; removed: number }>("/log/clear", { method: "POST" }),
  getReport: () => request<EngagementReport>("/engagement/report"),
};

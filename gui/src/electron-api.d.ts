export {};

declare global {
  interface Window {
    wifiPentestApp: {
      checkPrereqs: () => Promise<{ platform: string; wslInstalled: boolean; usbipdInstalled: boolean }>;
      listUsbipdDevices: () => Promise<{ supported: boolean; devices: string }>;
      attachAdapter: (busId: string) => Promise<{ supported: boolean; attached?: boolean }>;
      startBackend: () => Promise<{ alreadyRunning: boolean; port: number }>;
      stopBackend: () => Promise<{ stopped: boolean }>;
      getBackendPort: () => Promise<number>;
      minimizeWindow: () => Promise<void>;
      toggleMaximizeWindow: () => Promise<void>;
      closeWindow: () => Promise<void>;
      pickWordlist: () => Promise<string | null>;
    };
  }
}

import { app, BrowserWindow, ipcMain, shell, Menu, dialog, session } from "electron";
import { spawn, execFile, ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";

const isDev = !app.isPackaged;
const BACKEND_PORT = 8000;

// Content-Security-Policy for the renderer (defense in depth). The app loads a
// local bundle and talks ONLY to the localhost backend, so lock everything to
// 'self' + that backend: no remote script/style/image/connection can load, the
// page can't be reframed, and <base> can't be hijacked. script/style keep
// 'unsafe-inline' because Vite's bundle and the app's inline styles need it;
// the high-value restrictions are connect-src (no remote exfiltration),
// object-src 'none', and base-uri/frame-ancestors.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' http://127.0.0.1:8000 http://localhost:8000 ws://localhost:5173 ws://127.0.0.1:5173",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
].join("; ");

let backendProcess: ChildProcessWithoutNullStreams | null = null;
let mainWindow: BrowserWindow | null = null;

function createWindow() {
  // Frameless + transparent so the app can draw its OWN rounded corners (the native
  // WM frame is always square). The window content is opaque (the app paints a solid
  // background clipped to a rounded rectangle); only the 4 corner slivers are
  // transparent, so this does NOT bring back the "muddy see-through" look — it just
  // rounds the corners. The File/Edit/View/Window menu is removed below.
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    frame: false,
    transparent: true,
    backgroundColor: "#00000000",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true, // explicit — don't rely on the Electron-version default
    },
  });

  // "Read more" (and any other http/https link) must open in the user's real
  // browser, not a chromeless Electron window. Anything else (file:, data:,
  // blob:, …) is DENIED — never open a new in-app window for it.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http://") || url.startsWith("https://")) {
      shell.openExternal(url);
    }
    return { action: "deny" };
  });

  // Never let the top frame navigate away from the local bundle / dev server —
  // a dropped or injected link can't turn the privileged renderer into a browser.
  mainWindow.webContents.on("will-navigate", (event, url) => {
    const ok = isDev
      ? url.startsWith("http://localhost:5173")
      : url.startsWith("file://");
    if (!ok) {
      event.preventDefault();
      if (url.startsWith("http://") || url.startsWith("https://")) shell.openExternal(url);
    }
  });

  if (isDev) {
    mainWindow.loadURL("http://localhost:5173");
  } else {
    mainWindow.loadFile(path.join(__dirname, "../dist/index.html"));
  }
}

function execFileAsync(cmd: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 15000 }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr || error.message));
      else resolve({ stdout, stderr });
    });
  });
}

// --- Prerequisite checks -------------------------------------------------
// On Windows this checks for WSL2 + usbipd-win, which are required to pass
// the USB adapter through to the Linux backend. On native Linux none of
// that indirection is needed, so we report those checks as not-applicable.

ipcMain.handle("prereqs:check", async () => {
  if (process.platform === "win32") {
    const checks = await Promise.allSettled([
      execFileAsync("wsl", ["--status"]),
      execFileAsync("usbipd", ["--version"]),
    ]);
    return {
      platform: "win32",
      wslInstalled: checks[0].status === "fulfilled",
      usbipdInstalled: checks[1].status === "fulfilled",
    };
  }
  return {
    platform: process.platform,
    wslInstalled: true, // not applicable
    usbipdInstalled: true, // not applicable
  };
});

// --- Adapter attach (Windows-only passthrough step) ----------------------

ipcMain.handle("adapter:list-usbipd", async () => {
  if (process.platform !== "win32") {
    return { supported: false, devices: [] };
  }
  const { stdout } = await execFileAsync("usbipd", ["list"]);
  return { supported: true, devices: stdout };
});

ipcMain.handle("adapter:attach", async (_event, busId: string) => {
  if (process.platform !== "win32") {
    return { supported: false };
  }
  await execFileAsync("usbipd", ["bind", "--busid", busId]);
  await execFileAsync("usbipd", ["attach", "--wsl", "--busid", busId]);
  return { supported: true, attached: true };
});

// --- Backend lifecycle ----------------------------------------------------
// On Linux the backend runs directly; on Windows it runs inside WSL2.

async function backendAlreadyUp(): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${BACKEND_PORT}/tools/status`, {
      signal: AbortSignal.timeout(1000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function startBackend(): Promise<{ alreadyRunning: boolean; port: number }> {
  if (backendProcess && !backendProcess.killed) {
    return { alreadyRunning: true, port: BACKEND_PORT };
  }
  // a backend may already be running (e.g. started by start.sh) — don't spawn a
  // second one and fight over the port.
  if (await backendAlreadyUp()) {
    return { alreadyRunning: true, port: BACKEND_PORT };
  }

  if (app.isPackaged) {
    // Packaged app: launch the self-contained PyInstaller binary bundled under
    // resources/backend — no Python install needed on the host.
    const exe = path.join(process.resourcesPath, "backend", "wifi-backend");
    backendProcess = spawn(exe, [String(BACKEND_PORT)], { cwd: path.dirname(exe) });
    return { alreadyRunning: false, port: BACKEND_PORT };
  }

  // Development: run the backend from the source venv.
  const backendDir = path.join(__dirname, "../../backend");
  if (process.platform === "win32") {
    backendProcess = spawn(
      "wsl",
      ["-e", "bash", "-lc", `cd "${backendDir}" && .venv/bin/uvicorn app.main:app --port ${BACKEND_PORT}`],
    );
  } else {
    backendProcess = spawn(
      path.join(backendDir, ".venv/bin/uvicorn"),
      ["app.main:app", "--port", String(BACKEND_PORT)],
      { cwd: backendDir },
    );
  }
  return { alreadyRunning: false, port: BACKEND_PORT };
}

// kept for backward compatibility with the preload bridge, but the backend now
// starts automatically on app launch (see app.whenReady below) — the UI no
// longer has to ask for it.
ipcMain.handle("backend:start", () => startBackend());

ipcMain.handle("backend:stop", async () => {
  backendProcess?.kill();
  backendProcess = null;
  return { stopped: true };
});

ipcMain.handle("backend:port", () => BACKEND_PORT);

// --- Custom title-bar window controls (frameless window) ------------------
ipcMain.handle("window:minimize", () => mainWindow?.minimize());
ipcMain.handle("window:maximize", () => {
  if (!mainWindow) return;
  if (mainWindow.isMaximized()) mainWindow.unmaximize();
  else mainWindow.maximize();
});
ipcMain.handle("window:close", () => mainWindow?.close());

// --- Native file picker for choosing a custom wordlist -------------------
// Returns the selected file's absolute path (the backend needs a real path),
// or null if the dialog was cancelled.
ipcMain.handle("dialog:pickWordlist", async () => {
  if (!mainWindow) return null;
  const result = await dialog.showOpenDialog(mainWindow, {
    title: "Select a wordlist",
    properties: ["openFile"],
    filters: [
      { name: "Wordlists", extensions: ["txt", "lst", "dic", "dict", "wordlist", "gz"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  if (result.canceled || result.filePaths.length === 0) return null;
  return result.filePaths[0];
});

// Start the backend as soon as the app launches — no "activate the server"
// step in the UI. If start.sh (or Docker) already brought one up, startBackend
// detects it and won't spawn a second. We don't await it so the window paints
// immediately; the UI polls the API until it answers.
app.whenReady().then(() => {
  // No native application menu (the File/Edit/View/Window bar is useless here).
  Menu.setApplicationMenu(null);
  // Stamp the CSP onto every response the renderer loads.
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: { ...details.responseHeaders, "Content-Security-Policy": [CSP] },
    });
  });
  startBackend().catch((err) => console.error("backend auto-start failed:", err));
  createWindow();
});

// When the window closes, ask the backend to revert everything (stop attacks,
// monitor→managed, undo iptables) so the machine is back to normal and the next
// launch has no conflicts — then stop the backend and quit.
let cleaningUp = false;
async function cleanupBackend() {
  try {
    await fetch(`http://127.0.0.1:${BACKEND_PORT}/engagement/shutdown`, {
      method: "POST",
      signal: AbortSignal.timeout(12000),
    });
  } catch {
    // backend may already be gone — nothing to do
  }
}

app.on("before-quit", (e) => {
  if (cleaningUp) return;
  e.preventDefault();
  cleaningUp = true;
  cleanupBackend().finally(() => {
    backendProcess?.kill();
    app.exit(0);
  });
});

app.on("window-all-closed", () => {
  backendProcess?.kill();
  if (process.platform !== "darwin") app.quit();
});

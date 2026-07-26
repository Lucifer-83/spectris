import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("wifiPentestApp", {
  checkPrereqs: () => ipcRenderer.invoke("prereqs:check"),
  listUsbipdDevices: () => ipcRenderer.invoke("adapter:list-usbipd"),
  attachAdapter: (busId: string) => ipcRenderer.invoke("adapter:attach", busId),
  startBackend: () => ipcRenderer.invoke("backend:start"),
  stopBackend: () => ipcRenderer.invoke("backend:stop"),
  getBackendPort: () => ipcRenderer.invoke("backend:port"),
  // window controls for the custom (frameless) title bar
  minimizeWindow: () => ipcRenderer.invoke("window:minimize"),
  toggleMaximizeWindow: () => ipcRenderer.invoke("window:maximize"),
  closeWindow: () => ipcRenderer.invoke("window:close"),
  // native "open file" dialog for picking a custom wordlist (returns absolute path)
  pickWordlist: () => ipcRenderer.invoke("dialog:pickWordlist"),
});

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { TargetProvider } from './TargetContext.tsx'
import { initAppearance } from './Appearance.tsx'

// apply the saved theme + glass BEFORE the first paint (no flash)
initAppearance()

// Mark the desktop (Electron) build so CSS can round the window corners + use a
// transparent backdrop. In the browser (Docker/HTTP) the page just fills the tab.
if (typeof window.wifiPentestApp?.closeWindow === "function") {
  document.documentElement.classList.add("is-electron")
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TargetProvider>
      <App />
    </TargetProvider>
  </StrictMode>,
)

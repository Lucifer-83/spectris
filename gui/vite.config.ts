import { readFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Single source of truth for the app version: read it from package.json at build
// time and inject as __APP_VERSION__, so the About page can never drift from the
// real packaged version again.
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8'))

// base: "./" makes asset URLs relative so the build works both when Electron
// loads it via file:// (packaged app) and when FastAPI serves it over HTTP
// (Docker/browser). Absolute "/assets/..." paths break under file:// -> blank page.
// https://vite.dev/config/
export default defineConfig({
  base: './',
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  plugins: [react()],
})

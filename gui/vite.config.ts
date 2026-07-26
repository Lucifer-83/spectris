import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// base: "./" makes asset URLs relative so the build works both when Electron
// loads it via file:// (packaged app) and when FastAPI serves it over HTTP
// (Docker/browser). Absolute "/assets/..." paths break under file:// -> blank page.
// https://vite.dev/config/
export default defineConfig({
  base: './',
  plugins: [react()],
})

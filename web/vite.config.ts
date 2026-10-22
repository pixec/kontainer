import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  base: "/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    // Point at a running registry, e.g. KONTAINER_URL=http://127.0.0.1:5555 npm run dev
    proxy: Object.fromEntries(["/api", "/v2", "/auth"].map((p) => [p, process.env.KONTAINER_URL ?? "http://127.0.0.1:5000"])),
  },
  build: { outDir: "dist", emptyOutDir: true },
})

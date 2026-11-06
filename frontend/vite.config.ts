import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/static/react-app/",
  build: { outDir: "../static/react-app", emptyOutDir: true },
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
});

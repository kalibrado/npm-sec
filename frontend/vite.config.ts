import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiPaths = ["/auth", "/users", "/stats", "/history", "/events", "/timeline",
  "/heatmap", "/sparklines", "/threats", "/threat-intel", "/threat-tags",
  "/security-control", "/security-profile", "/blocklist", "/trusted",
  "/health", "/npm-health", "/version", "/config", "/ban-events", "/whois"];

export default defineConfig({
  plugins: [react()],
  base: "/static/react-app/",
  build: { outDir: "../static/react-app", emptyOutDir: true },
  server: { proxy: Object.fromEntries(apiPaths.map(path => [path, "http://127.0.0.1:8000"])) },
});

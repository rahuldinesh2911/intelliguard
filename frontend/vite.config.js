import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";

export default defineConfig({
  plugins: [react()],

  // Required for GitHub Pages
  base: "/intelliguard/",   // <-- MUST MATCH YOUR REPO NAME EXACTLY

  server: {
    port: 5173,
    host: "localhost",
  },

  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "assets",
  },
  publicDir: "public",
});

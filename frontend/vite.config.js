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
    outDir: "../docs",       // <-- IMPORTANT: Build directly into /docs at root
    emptyOutDir: false,      // Do NOT delete root files
    assetsDir: "assets",
  },
  publicDir: "public",
});

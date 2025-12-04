import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  // GitHub Pages fix:
  base: process.env.NODE_ENV === "production"
    ? "/intelliguard/"  // <-- replace with YOUR repo name
    : "/",

  server: {
    port: 5173,
    host: "localhost",
  },

  build: {
    outDir: "dist",
    assetsDir: "assets",
  },
});

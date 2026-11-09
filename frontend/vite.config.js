import { defineConfig, searchForWorkspaceRoot } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
    fs: {
      // The Demo tab bundles the golden demo trace from backend/results so the
      // replay still works when the backend is down (R13.11). Allow exactly
      // that folder in addition to the default workspace root.
      allow: [searchForWorkspaceRoot(process.cwd()), "../backend/results"],
    },
  },
});

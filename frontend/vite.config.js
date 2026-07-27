import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/admin": "http://127.0.0.1:9000",
      "/trace": "http://127.0.0.1:9000",
      "/traces": "http://127.0.0.1:9000",
      "/feedback": "http://127.0.0.1:9000",
      "/switches": "http://127.0.0.1:9000",
      "/pending_approvals": "http://127.0.0.1:9000",
      "/v1": "http://127.0.0.1:9000",
      "/chat": "http://127.0.0.1:9000",
    },
  },
});

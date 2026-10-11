import { defineConfig, devices } from "@playwright/test";
import base, { API_URL } from "./playwright.config";

// tests-e2e-csp/: the same API server as `npm run e2e`, but the production build of the web app,
// so pages run under the production Content-Security-Policy (proxy.ts) and not the relaxed dev one.
// Same ports as playwright.config.ts (the API allows that web origin); run one suite at a time.
const servers = Array.isArray(base.webServer) ? base.webServer : [];

export default defineConfig({
  ...base,
  testDir: "./tests-e2e-csp",
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    servers[0]!, // the e2e API server
    {
      command: "npm run build && npm run start -- --port 3911",
      url: "http://127.0.0.1:3911",
      reuseExistingServer: !process.env.CI,
      timeout: 300_000,
      env: { NEXT_PUBLIC_API_URL: API_URL, BULWARK_E2E: "1" },
    },
  ],
});

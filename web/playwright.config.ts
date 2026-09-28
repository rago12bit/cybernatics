import { defineConfig, devices } from "@playwright/test";

// Deliberately far from any port the real dev stack uses (3000, 3010, 8000, ...): these are
// Playwright's own ephemeral servers (see scripts/e2e_server.py's module docstring), never the
// user's real docker-compose deployment.
const API_PORT = 8811;
const WEB_PORT = 3911;
export const API_URL = `http://127.0.0.1:${API_PORT}`;
const WEB_URL = `http://127.0.0.1:${WEB_PORT}`;
export const E2E_TOKEN = "e2e-test-token-not-a-real-secret-0123456789"; // must match scripts/e2e_server.py

// Which Python to run scripts/e2e_server.py with -- CI's e2e job installs the backend's own deps
// (fastapi, uvicorn, sqlalchemy, ...) via `pip install -e ".[dev]"` the same way the `test` job
// does, onto whatever `python` actions/setup-python put on PATH. Locally, this repo's own .venv.
const PYTHON = process.env.E2E_PYTHON ?? "../.venv/bin/python";

export default defineConfig({
  testDir: "./tests-e2e",
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: WEB_URL,
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `${PYTHON} ../scripts/e2e_server.py --port ${API_PORT} --web-origin ${WEB_URL}`,
      url: `${API_URL}/healthz`,
      reuseExistingServer: !process.env.CI,
      stdout: "pipe",
      timeout: 30_000,
    },
    {
      command: `npm run dev -- --port ${WEB_PORT}`,
      url: WEB_URL,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: { NEXT_PUBLIC_API_URL: API_URL },
    },
  ],
});

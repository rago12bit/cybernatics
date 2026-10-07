import { defineConfig, devices } from "@playwright/test";

// Deliberately far from any port the real dev stack uses (3000, 3010, 8000, ...): these are
// Playwright's own ephemeral servers (see scripts/e2e_server.py's module docstring), never the
// user's real docker-compose deployment.
const API_PORT = 8811;
const WEB_PORT = 3911;
export const API_URL = `http://127.0.0.1:${API_PORT}`;
const WEB_URL = `http://127.0.0.1:${WEB_PORT}`;
export const E2E_TOKEN = "e2e-test-token-not-a-real-secret-0123456789"; // must match scripts/e2e_server.py
// A personal token the e2e server seeds as "Priya N." (the shared token can't approve a risk
// acceptance: Week 62's four-eyes rule). Fake, checksum-valid; must match scripts/e2e_server.py.
export const E2E_APPROVER_TOKEN = "bulwark_e2e0approver0not0a0real0secret0000000000_0XGUOc";

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
  // A real GitHub Actions run of these tests (not just this repo's own local Docker
  // verification, run on Apple Silicon through virtualization -- a different CPU architecture
  // than GitHub's real x86_64 runners) showed small, consistent ~1% pixel diffs on every visual
  // snapshot: font hinting/anti-aliasing genuinely isn't guaranteed byte-identical across
  // different physical machines, even with the identical pinned browser build. A small tolerance
  // is Playwright's own documented answer to this, not a way to hide a real regression -- a
  // broken layout produces a far larger diff than 1-2%.
  expect: { toHaveScreenshot: { maxDiffPixelRatio: 0.02 } },
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
      env: { NEXT_PUBLIC_API_URL: API_URL, BULWARK_E2E: "1" },
    },
  ],
});

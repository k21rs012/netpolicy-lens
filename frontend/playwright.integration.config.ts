import { defineConfig, devices } from "@playwright/test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Each run owns its database and ports; never reuse a running user instance.
const dataDirectory = process.env.NETPOLICY_TEST_DATA ||= mkdtempSync(join(tmpdir(), "netpolicy-integration-"));
export default defineConfig({
  testDir: "./integration",
  workers: 1,
  fullyParallel: false,
  timeout: 30000,
  reporter: "list",
  metadata: { dataDirectory },
  globalTeardown: "./integration/teardown.ts",
  outputDir: "./test-results/integration",
  use: { baseURL: "http://127.0.0.1:15173", trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [{ name: "chromium-real-api", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: '"$NETPOLICY_TEST_PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port 18000',
      cwd: "../backend",
      env: { NETPOLICY_TEST_PYTHON: process.env.NETPOLICY_TEST_PYTHON || "python3", DATABASE_PATH: join(dataDirectory, "test.db") },
      url: "http://127.0.0.1:18000/api/health",
      reuseExistingServer: false,
    },
    {
      command: "npm run dev -- --host 127.0.0.1 --port 15173 --strictPort",
      env: { NETPOLICY_API_TARGET: "http://127.0.0.1:18000" },
      url: "http://127.0.0.1:15173",
      reuseExistingServer: false,
    },
  ],
});

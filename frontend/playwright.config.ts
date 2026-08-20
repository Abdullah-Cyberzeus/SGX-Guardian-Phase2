import { defineConfig, devices } from '@playwright/test';
import { execSync } from 'child_process';

const LIVE_API = 'https://d2c8-202-163-107-192.ngrok-free.app/api/v1';
const LOCAL_API = 'http://localhost:8443/api/v1';

function detectLiveBackend(): boolean {
  // 1. Respect an explicit VITE_API_URL pointing outside localhost
  const envUrl = process.env.VITE_API_URL;
  if (envUrl && !envUrl.includes('localhost') && !envUrl.includes('127.0.0.1')) {
    return true;
  }
  // 2. Probing a real external device tunnel by default is a CI-breaking
  // dependency (an unreachable/expired ngrok URL can still return a 2xx
  // interstitial page, tricking this into "live" while every API call then
  // fails against it) — Phase 12 default is the local backend (either the
  // real dev backend or `test_guardian_server`, see src/bin/test_guardian_server.rs),
  // unless a developer explicitly opts in.
  if (process.env.SGX_E2E_ALLOW_LIVE_BACKEND !== '1') {
    return false;
  }
  // 3. Probe the known live device (best-effort; falls back gracefully on Windows)
  try {
    const code = execSync(
      `curl -sk --connect-timeout 3 --max-time 5 "${LIVE_API}/node/status" -o /dev/null -w "%{http_code}"`,
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    return parseInt(code, 10) >= 200;
  } catch {
    return false;
  }
}

const LIVE_BACKEND = detectLiveBackend();
const API_URL = LIVE_BACKEND ? LIVE_API : (process.env.VITE_API_URL ?? LOCAL_API);

// Expose to test worker processes
process.env.BACKEND_IS_LIVE = LIVE_BACKEND ? '1' : '0';
process.env.VITE_API_URL = API_URL;

// eslint-disable-next-line no-console
console.log(
  LIVE_BACKEND
    ? `\n🌐  Live backend: ${API_URL}\n`
    : `\n🧪  Local testdata backend: ${API_URL}\n`
);

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 1,
  workers: 1,
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['list'],
  ],
  timeout: 30000,
  expect: {
    timeout: 10000,
  },

  // Logs in once (against whichever backend API_URL resolved to above) and
  // seeds every test's browser context with the resulting session token —
  // see e2e/global-setup.ts for why this is a global setup rather than a
  // per-spec fixture.
  globalSetup: './e2e/global-setup.ts',

  use: {
    baseURL: 'http://localhost:3000',
    storageState: './e2e/storageState.json',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 10000,
    navigationTimeout: 15000,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: true,
    timeout: 60000,
    env: { VITE_API_URL: API_URL },
  },
});

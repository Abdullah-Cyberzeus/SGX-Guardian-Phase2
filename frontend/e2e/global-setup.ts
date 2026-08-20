import { request } from '@playwright/test';
import { writeFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Every existing Admin Console spec navigates directly (no login step of its
// own) and expects an already-authenticated browser — true against the old
// external testdata backend, which ran with auth effectively bypassed, but
// not against `test_guardian_server` (src/bin/test_guardian_server.rs),
// which enforces real auth like production. Rather than touching all 14+
// spec files individually, this global setup performs one real login and
// seeds the resulting bearer token into `AuthContext`'s expected
// localStorage key before any test's `page` first navigates — Playwright's
// `storageState` mechanism applies it automatically per test via the
// `use.storageState` config option.
export default async function globalSetup() {
  const apiUrl = process.env.VITE_API_URL || 'http://localhost:8443/api/v1';
  const email = process.env.TEST_GUARDIAN_ADMIN_EMAIL || 'admin@sgx-guardian.local';
  const password = process.env.TEST_GUARDIAN_ADMIN_PASSWORD || 'AdminTest123!';

  const context = await request.newContext();
  const response = await context.post(`${apiUrl}/auth/login`, {
    data: { email, password },
    failOnStatusCode: false,
  });

  if (!response.ok()) {
    // Admin login is unavailable (e.g. a non-test_guardian_server backend
    // with a different/unseeded admin account) — leave storage empty rather
    // than failing the whole run; specs relying on auth will simply fail
    // with a clear "redirected to /login" error instead of a setup crash.
    console.warn(
      `[global-setup] admin login against ${apiUrl} failed (${response.status()}) — ` +
        `tests will run unauthenticated.`,
    );
    await context.dispose();
    return;
  }

  const body = await response.json();
  const token = body?.token;
  await context.dispose();

  const baseURL = 'http://localhost:3000';
  const storageState = token
    ? {
        cookies: [],
        origins: [
          {
            origin: baseURL,
            localStorage: [{ name: 'sgx_auth_token', value: token }],
          },
        ],
      }
    : { cookies: [], origins: [] };

  writeFileSync(path.join(__dirname, 'storageState.json'), JSON.stringify(storageState));
}

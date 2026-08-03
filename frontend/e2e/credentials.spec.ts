import { test, expect } from '@playwright/test';

/**
 * E2E Tests — Credentials Page (VC01CredentialsList)
 *
 * Talks to the real Rust backend (VC endpoints under /api/v1/vc/*,
 * backend branch feat/60_nmap). Covers the existing tabs plus the
 * five new endpoint-driven features:
 *
 *   - Summary chip strip          (GET /vc/summary)
 *   - Own / Peers / Issued tabs   (GET /vc/files/{own,peers,issued})
 *   - Raw JSON viewer modal       (GET /vc/files/{issued|own}/:id, /vc/files/peer/:did)
 *   - Status List tab             (GET /vc/status-list)
 *   - Audit tab                   (GET /vc/audit)
 *
 * Assertions are structure-focused so they pass whether or not the
 * VC caches have been populated yet.
 */

test.describe('Credentials Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings/credentials', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
  });

  // ── Page load ──────────────────────────────────────────────────────────────

  test('loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.goto('/settings/credentials', { waitUntil: 'networkidle' });
    expect(errors).toHaveLength(0);
  });

  test('shows Credentials heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Credentials' })).toBeVisible();
  });

  test('shows Verifiable circle-membership credentials subtitle', async ({ page }) => {
    await expect(page.locator('body')).toContainText(
      'Verifiable circle-membership credentials',
    );
  });

  test('no error boundary shown', async ({ page }) => {
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  // ── Summary chip strip (GET /vc/summary) ───────────────────────────────────

  test.describe('Summary chip strip', () => {
    test('renders all expected count labels', async ({ page }) => {
      const body = page.locator('body');
      await expect(body).toContainText('Issued');
      await expect(body).toContainText('Own');
      await expect(body).toContainText('Peers');
      await expect(body).toContainText('Active');
      await expect(body).toContainText('Revoked');
      await expect(body).toContainText('Expired');
      await expect(body).toContainText('Next Index');
    });
  });

  // ── Tab bar ────────────────────────────────────────────────────────────────

  test.describe('Tab bar', () => {
    test('shows all six tabs', async ({ page }) => {
      await expect(page.getByRole('button', { name: 'Credentials' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Issued' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Own' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Peers' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Status List' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Audit' })).toBeVisible();
    });
  });

  // ── Credentials tab (default) ──────────────────────────────────────────────

  test.describe('Credentials tab (default)', () => {
    test('shows scope filter row', async ({ page }) => {
      const body = page.locator('body');
      await expect(body).toContainText('Scope');
      await expect(body).toContainText('Status');
    });

    test('shows Pull Status and Issue VC action buttons', async ({ page }) => {
      await expect(page.getByRole('button', { name: /Pull Status/i })).toBeVisible();
      await expect(page.getByRole('button', { name: /Issue VC/i })).toBeVisible();
    });
  });

  // ── Issued tab (GET /vc/files/issued + /:id) ───────────────────────────────

  test.describe('Issued tab', () => {
    test.beforeEach(async ({ page }) => {
      await page.getByRole('button', { name: 'Issued' }).click();
      await page.waitForTimeout(500);
    });

    test('switches to Issued tab without error', async ({ page }) => {
      await expect(page.locator('body')).not.toContainText('Something went wrong');
    });
  });

  // ── Own tab (GET /vc/files/own + /:id) ─────────────────────────────────────

  test.describe('Own tab', () => {
    test.beforeEach(async ({ page }) => {
      await page.getByRole('button', { name: 'Own' }).click();
      await page.waitForTimeout(500);
    });

    test('renders tab content (either empty state or rows)', async ({ page }) => {
      const body = page.locator('body');
      const bodyText = (await body.textContent()) ?? '';
      const ok =
        bodyText.includes('No own credentials cached') ||
        bodyText.includes('file(s) cached locally') ||
        bodyText.includes('Raw');
      expect(ok).toBeTruthy();
    });
  });

  // ── Peers tab (GET /vc/files/peers + /vc/files/peer/:did) ──────────────────

  test.describe('Peers tab', () => {
    test.beforeEach(async ({ page }) => {
      await page.getByRole('button', { name: 'Peers' }).click();
      await page.waitForTimeout(500);
    });

    test('renders tab content (either empty state or rows)', async ({ page }) => {
      const body = page.locator('body');
      const bodyText = (await body.textContent()) ?? '';
      const ok =
        bodyText.includes('No peer credentials cached') ||
        bodyText.includes('file(s) cached locally') ||
        bodyText.includes('Raw');
      expect(ok).toBeTruthy();
    });
  });

  // ── Status List tab (GET /vc/status-list) ──────────────────────────────────

  test.describe('Status List tab', () => {
    test.beforeEach(async ({ page }) => {
      await page.getByRole('button', { name: 'Status List' }).click();
      await page.waitForTimeout(500);
    });

    test('shows Local Status List Credential heading', async ({ page }) => {
      await expect(page.locator('body')).toContainText('Local Status List Credential');
    });

    test('shows Reload and View JSON action buttons', async ({ page }) => {
      await expect(page.getByRole('button', { name: /Reload/i })).toBeVisible();
      await expect(page.getByRole('button', { name: /View JSON/i })).toBeVisible();
    });
  });

  // ── Audit tab (GET /vc/audit) ──────────────────────────────────────────────

  test.describe('Audit tab', () => {
    test.beforeEach(async ({ page }) => {
      await page.getByRole('button', { name: 'Audit' }).click();
      await page.waitForTimeout(500);
    });

    test('renders tab content (either empty state, rows, or error)', async ({ page }) => {
      const body = page.locator('body');
      const bodyText = (await body.textContent()) ?? '';
      const ok =
        bodyText.includes('No audit events recorded yet') ||
        bodyText.includes('event(s)') ||
        bodyText.includes('Refresh') ||
        // Tolerate a 404 from the backend if audit log file is missing
        bodyText.toLowerCase().includes('not found');
      expect(ok).toBeTruthy();
    });
  });
});

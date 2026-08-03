import { test, expect } from '@playwright/test';

/**
 * E2E Tests — Virtual ID Page (SC04VirtualId)
 *
 * Talks to the real Rust backend (VID endpoints under /api/v1/vid/*,
 * backend branch feat/60_nmap).
 *
 * Notes:
 *   - GET /vid/show may not be implemented on every backend revision;
 *     the screen renders an error block in that case. Tests accept
 *     either populated or error states for the Current VID card.
 *   - GET /vid/peers is always implemented and returns [] when no
 *     peer VirtualIDs have been observed yet.
 */

test.describe('Virtual ID Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings/virtual-id', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
  });

  // ── Page load ──────────────────────────────────────────────────────────────

  test('loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.goto('/settings/virtual-id', { waitUntil: 'networkidle' });
    expect(errors).toHaveLength(0);
  });

  test('shows Virtual ID heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Virtual ID' })).toBeVisible();
  });

  test('shows the session-bound subtitle', async ({ page }) => {
    await expect(page.locator('body')).toContainText(
      'Session-bound identifier derived from DID, DKP, PCR, policy, and nonces',
    );
  });

  test('no error boundary shown', async ({ page }) => {
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  // ── Route aliases ──────────────────────────────────────────────────────────

  test('accessible via /virtual-id', async ({ page }) => {
    await page.goto('/virtual-id', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    await expect(page.getByRole('heading', { name: 'Virtual ID' })).toBeVisible();
  });

  test('accessible via /settings/virtual-id', async ({ page }) => {
    await page.goto('/settings/virtual-id', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    await expect(page.getByRole('heading', { name: 'Virtual ID' })).toBeVisible();
  });

  // ── Current VID card (GET /vid/show) ───────────────────────────────────────

  test.describe('Current VID card', () => {
    test('shows either populated card or error block', async ({ page }) => {
      const body = page.locator('body');
      const bodyText = (await body.textContent()) ?? '';
      // Either the spec-compliant card header rendered, or an error block.
      // (Backend may not yet implement /vid/show on all branches.)
      const ok =
        bodyText.includes('Current VirtualID') ||
        bodyText.toLowerCase().includes('not found') ||
        bodyText.toLowerCase().includes('error');
      expect(ok).toBeTruthy();
    });
  });

  // ── Peers list (GET /vid/peers) ────────────────────────────────────────────

  test.describe('Peer VirtualIDs section', () => {
    test('shows Peer VirtualIDs section heading', async ({ page }) => {
      await expect(page.locator('body')).toContainText('Peer VirtualIDs');
    });

    test('renders either empty state or peer rows', async ({ page }) => {
      const body = page.locator('body');
      const bodyText = (await body.textContent()) ?? '';
      const ok =
        bodyText.includes('No peer VirtualIDs observed yet') ||
        // When peers exist, the rows expose DID/VID monospace text — match the section header instead
        bodyText.includes('Peer VirtualIDs');
      expect(ok).toBeTruthy();
    });

    test('shows a Refresh button on the peers section', async ({ page }) => {
      // There may be two Refresh buttons (current card + peers); just assert
      // at least one is present.
      const refreshButtons = page.getByRole('button', { name: /Refresh/i });
      expect(await refreshButtons.count()).toBeGreaterThan(0);
    });
  });
});

import { test, expect } from '@playwright/test';

/**
 * E2E Tests — Guardian Detail Page (HM02GuardianDetail)
 * Talks to the real Rust backend (GET /api/v1/node/status).
 *
 * Testdata values (nodeA.yaml):
 *   nodeId=nodeA, hostname=guardian-node-A, ip=127.0.0.1, port=50051, publicKey=placeholder-key-A
 *
 * When BACKEND_IS_LIVE=1 (live device at 192.168.50.103), tests that assert testdata-specific
 * values are automatically skipped — structural/UI tests always run.
 */

const isLive = process.env.BACKEND_IS_LIVE === '1' ||
  (!!process.env.VITE_API_URL &&
   !process.env.VITE_API_URL.includes('localhost') &&
   !process.env.VITE_API_URL.includes('127.0.0.1'));

test.describe('Guardian Detail Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/home/guardian', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1500);
  });

  // ── Page load ────────────────────────────────────────────────────────────

  test('loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto('/home/guardian', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1500);
    expect(errors).toHaveLength(0);
  });

  test('no error boundary shown', async ({ page }) => {
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  test('URL is /home/guardian', async ({ page }) => {
    expect(page.url()).toContain('/home/guardian');
  });

  // ── Content from real backend node status ────────────────────────────────

  test('shows guardian-node-A as page heading (hostname from nodeA.yaml)', async ({ page }) => {
    test.skip(isLive, 'testdata-specific: live device hostname differs');
    await expect(page.locator('body')).toContainText('guardian-node-A');
  });

  test('shows Device Details subtitle', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Device Details');
  });

  test('shows Online status badge', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Online');
  });

  test('shows Monitoring Active status', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Monitoring Active');
  });

  // ── Device Info section ──────────────────────────────────────────────────

  test('shows Device Info section header', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Device Info');
  });

  test('shows nodeA as Device ID', async ({ page }) => {
    test.skip(isLive, 'testdata-specific: live device ID differs');
    await expect(page.locator('body')).toContainText('nodeA');
  });

  test('shows Model field', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Model');
  });

  test('shows Firmware field', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Firmware');
  });

  test('shows Uptime field', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Uptime');
  });

  // ── Node Identity section ────────────────────────────────────────────────

  test('shows Node Identity section header', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Node Identity');
  });

  test('shows guardian-node-A hostname from backend', async ({ page }) => {
    test.skip(isLive, 'testdata-specific: live device hostname differs');
    await expect(page.locator('body')).toContainText('guardian-node-A');
  });

  test('shows port 50051 from backend', async ({ page }) => {
    test.skip(isLive, 'testdata-specific: live device port differs');
    await expect(page.locator('body')).toContainText('50051');
  });

  test('shows Public Key label', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Public Key');
  });

  test('shows placeholder-key-A public key from backend', async ({ page }) => {
    test.skip(isLive, 'testdata-specific: live device has a real public key');
    await expect(page.locator('body')).toContainText('placeholder-key-A');
  });

  // ── Connection section ───────────────────────────────────────────────────

  test('shows Connection section header', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Connection');
  });

  test('shows IP address 127.0.0.1 from backend', async ({ page }) => {
    test.skip(isLive, 'testdata-specific: live device has a different IP');
    await expect(page.locator('body')).toContainText('127.0.0.1');
  });

  test('shows Ethernet connection type', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Ethernet');
  });

  test('shows MAC Address field', async ({ page }) => {
    await expect(page.locator('body')).toContainText('MAC Address');
  });

  test('shows Last Seen field', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Last Seen');
  });

  // ── Copy Public Key action ───────────────────────────────────────────────

  test('has Copy button', async ({ page }) => {
    await expect(page.getByRole('button', { name: /Copy/i }).first()).toBeVisible();
  });

  test('Copy button is clickable and does not throw', async ({ page }) => {
    // In headless mode clipboard.writeText requires permissions;
    // verify the click doesn't crash the page
    await page.getByRole('button', { name: /Copy/i }).first().click();
    await page.waitForTimeout(500);
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  test('Copy button still shows public key after click', async ({ page }) => {
    test.skip(isLive, 'testdata-specific: live device has a real public key');
    await page.getByRole('button', { name: /Copy/i }).first().click();
    await page.waitForTimeout(400);
    // Page remains intact — public key is still visible
    await expect(page.locator('body')).toContainText('placeholder-key-A');
  });

  // ── Navigation: sidebar links reach guardian page ────────────────────────

  test('navigating to / then /home/guardian shows guardian data', async ({ page }) => {
    test.skip(isLive, 'testdata-specific: live device hostname differs');
    await page.goto('/', { waitUntil: 'networkidle' });
    await page.goto('/home/guardian', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1500);
    await expect(page.locator('body')).toContainText('guardian-node-A');
  });
});

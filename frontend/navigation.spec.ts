import { test, expect } from '@playwright/test';

/**
 * E2E Tests — Network Discovery Page (NW07Discovery)
 * Talks to the real Rust backend (NMAP discovery endpoints under
 * /api/v1/discovery/*, backend branch feat/60_nmap).
 *
 * These tests assert on UI structure (headings, tabs, controls) so they
 * pass whether or not a discovery inventory has been populated yet.
 */

test.describe('Network Discovery Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/network/discovery', { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(1000);
  });

  // ── Page load ────────────────────────────────────────────────────────────

  test('loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto('/network/discovery', { waitUntil: 'domcontentloaded' });
    expect(errors).toHaveLength(0);
  });

  test('shows Network Discovery heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Network Discovery' })).toBeVisible();
  });

  test('shows NMAP Inventory subtitle', async ({ page }) => {
    await expect(page.locator('body')).toContainText('NMAP Inventory');
  });

  test('no error boundary shown', async ({ page }) => {
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  // ── Route aliases ────────────────────────────────────────────────────────

  test('accessible via /discovery', async ({ page }) => {
    await page.goto('/discovery', { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(500);
    await expect(page.getByRole('heading', { name: 'Network Discovery' })).toBeVisible();
  });

  test('accessible via /settings/discovery', async ({ page }) => {
    await page.goto('/settings/discovery', { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(500);
    await expect(page.getByRole('heading', { name: 'Network Discovery' })).toBeVisible();
  });

  // ── Tabs ─────────────────────────────────────────────────────────────────

  test('shows Inventory, Whitelist and Schedule tabs', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Inventory' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Whitelist' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Schedule' })).toBeVisible();
  });

  // ── Inventory tab (default) ──────────────────────────────────────────────

  test('shows the four scan intensity buttons', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Default' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Stealth' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Standard' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Aggressive' })).toBeVisible();
  });

  test('shows inventory stat cards', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Total');
    await expect(page.locator('body')).toContainText('Approved');
    await expect(page.locator('body')).toContainText('Flagged');
  });

  // ── Whitelist tab ────────────────────────────────────────────────────────

  test('Whitelist tab reveals the editor and save control', async ({ page }) => {
    await page.getByRole('button', { name: 'Whitelist' }).click();
    await page.waitForTimeout(500);
    await expect(page.locator('body')).toContainText('Discovery whitelist');
    await expect(page.getByRole('button', { name: 'Save whitelist' })).toBeVisible();
  });

  // ── Schedule tab ─────────────────────────────────────────────────────────

  test('Schedule tab reveals the config form and save control', async ({ page }) => {
    await page.getByRole('button', { name: 'Schedule' }).click();
    await page.waitForTimeout(500);
    await expect(page.locator('body')).toContainText('Scheduled discovery');
    await expect(page.getByRole('button', { name: 'Save schedule' })).toBeVisible();
  });

  // ── Runs tab (GET /discovery/runs?view=history) ──────────────────────────

  test('shows the Runs tab', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Runs', exact: true })).toBeVisible();
  });

  test('Runs tab shows schedule status and run history', async ({ page }) => {
    await page.getByRole('button', { name: 'Runs', exact: true }).click();
    await page.waitForTimeout(600);
    await expect(page.locator('body')).toContainText('Schedule status');
    await expect(page.locator('body')).toContainText('Run history');
  });

  // ── Inventory: last-run card + summary ───────────────────────────────────

  test('Inventory shows the Last run card', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Last run');
  });
});

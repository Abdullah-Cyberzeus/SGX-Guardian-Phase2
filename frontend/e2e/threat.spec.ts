import { test, expect } from '@playwright/test';

/**
 * E2E — Threat Protection / Suricata IDS (AL08ThreatProtection).
 * Talks to the real Rust backend (/api/v1/threat/*, backend task #66).
 *
 * These tests assert on UI structure (header, tabs, controls) so they pass
 * whether or not Suricata has produced alerts yet. Data-dependent checks
 * (e.g. opening an alert modal) skip themselves when no data is present.
 */

test.describe('Threat Protection (Suricata IDS)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/alerts/threat', { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(1000);
  });

  // ── Page load ──────────────────────────────────────────────────────────

  test('loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto('/alerts/threat', { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(500);
    expect(errors).toHaveLength(0);
  });

  test('shows the Threat Protection header', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Threat Protection' })).toBeVisible();
  });

  test('no error boundary shown', async ({ page }) => {
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  // ── Tabs ───────────────────────────────────────────────────────────────

  test('shows the four tabs', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Overview', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'IDS Alerts', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Blocked IPs', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Config', exact: true })).toBeVisible();
  });

  // ── Overview tab ─────────────────────────────────────────────────────────

  test('Overview shows the Suricata engine card and actions', async ({ page }) => {
    // Always rendered, even on a status error.
    await expect(page.getByText('Guardian engine')).toBeVisible();

    // The action buttons only render once GET /threat/status resolves; if the
    // endpoint is unreachable the tab shows an error banner instead. Skip the
    // data-dependent assertions in that case rather than fail on a down backend.
    const statusFailed = await page.getByText(/Couldn't load threat status/i).isVisible();
    test.skip(statusFailed, 'threat status endpoint unreachable');

    await expect(page.getByRole('button', { name: /Validate config/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Update rules/i })).toBeVisible();
  });

  // ── IDS Alerts tab ───────────────────────────────────────────────────────

  test('IDS Alerts tab loads with a Refresh control', async ({ page }) => {
    await page.getByRole('button', { name: 'IDS Alerts', exact: true }).click();
    await page.waitForTimeout(500);
    await expect(page.locator('body')).toContainText('IDS alerts');
    await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible();
  });

  test('opens an IDS alert detail modal when alerts exist', async ({ page }) => {
    await page.getByRole('button', { name: 'IDS Alerts', exact: true }).click();
    await page.waitForTimeout(800);

    // Alert cards are role=button and contain the "→" src→dst flow.
    const cards = page.locator('div[role="button"]');
    const count = await cards.count();
    let clicked = false;
    for (let i = 0; i < count; i++) {
      const c = cards.nth(i);
      if ((await c.textContent())?.includes('→')) {
        await c.click();
        clicked = true;
        break;
      }
    }
    test.skip(!clicked, 'no Suricata alerts present to open');

    await page.waitForTimeout(400);
    await expect(page.locator('body')).toContainText('Alert ID');
    await expect(page.locator('body')).toContainText('Signature ID');
  });

  // ── Blocked IPs tab ──────────────────────────────────────────────────────

  test('Blocked IPs tab shows the block control', async ({ page }) => {
    await page.getByRole('button', { name: 'Blocked IPs', exact: true }).click();
    await page.waitForTimeout(500);
    await expect(page.getByRole('button', { name: /Block IP/i })).toBeVisible();
    await expect(page.getByPlaceholder(/192\.168/)).toBeVisible();
  });

  // ── Config tab ───────────────────────────────────────────────────────────

  test('Config tab loads the threat configuration', async ({ page }) => {
    await page.getByRole('button', { name: 'Config', exact: true }).click();
    // The config form only renders once GET /threat/config resolves; on an
    // unreachable backend the tab shows a "Couldn't load config" box instead.
    const heading = page.getByText('Threat configuration');
    const failed = page.getByText(/Couldn't load config/i);
    await expect(heading.or(failed)).toBeVisible();
    test.skip(await failed.isVisible(), 'threat config endpoint unreachable');
    await expect(heading).toBeVisible();
  });
});

test.describe('Alerts — Threat Protection segmented tab', () => {
  test('switches from Events to the Threat Protection panel', async ({ page }) => {
    await page.goto('/alerts', { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(800);

    // Events view is the default; the Threat Protection tab reveals the panel.
    await page.getByRole('button', { name: /Threat Protection/ }).click();
    await page.waitForTimeout(600);
    await expect(page.getByRole('button', { name: 'Overview', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Blocked IPs', exact: true })).toBeVisible();
  });
});

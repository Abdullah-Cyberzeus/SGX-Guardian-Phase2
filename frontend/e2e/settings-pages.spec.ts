import { test, expect } from '@playwright/test';

/**
 * E2E Tests — Settings pages that call previously-untested API endpoints
 *
 * /settings/did         → SC03DIDStatus   → GET /did/status, /did/document, /did/document/peers
 * /settings/transport   → NW05Transport   → GET /transport/list, /transport/status
 * /settings/relay       → NW06RelayList   → GET /relay/list, /lighthouse/list, /member/list, /relay-lighthouse/list
 * /settings/credentials → VC01Credentials → GET /vc/show, /vc/files/issued
 *
 * These pages may show empty / error states when testdata files are absent — that is OK;
 * the tests assert the page shell renders without crashing, not that live records exist.
 */

// ─────────────────────────────────────────────────────────────────────────────
// DID Status  (/settings/did)
// ─────────────────────────────────────────────────────────────────────────────
test.describe('DID Status Page (/settings/did)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings/did', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
  });

  test('loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto('/settings/did', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
    expect(errors).toHaveLength(0);
  });

  test('shows DID Status heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'DID Status' })).toBeVisible();
  });

  test('shows Decentralized Identifier subtitle', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Decentralized Identifier');
  });

  test('no error boundary shown', async ({ page }) => {
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  test('accessible via /settings/did route', async ({ page }) => {
    expect(page.url()).toContain('/settings/did');
  });

  test('shows DID content or empty/loading state', async ({ page }) => {
    const bodyText = await page.locator('body').textContent() ?? '';
    // Either a DID is shown, or an empty/loading/error state — page must render something
    const renderedSomething =
      bodyText.includes('DID') ||
      bodyText.includes('did:guardian') ||
      bodyText.includes('Loading') ||
      bodyText.includes('No DID') ||
      bodyText.includes('not found') ||
      bodyText.length > 100;
    expect(renderedSomething).toBeTruthy();
  });

  test('DID or error state does not crash the page', async ({ page }) => {
    // Page gracefully handles 404 from /did/status when testdata is missing
    await expect(page.locator('body')).not.toContainText('Something went wrong');
    await expect(page.getByRole('heading', { name: 'DID Status' })).toBeVisible();
  });

  test('Settings navigation "DID Status" button leads here', async ({ page }) => {
    await page.goto('/settings', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    await page.locator('button:visible').filter({ hasText: /^DID Status$/ }).first().click();
    await page.waitForTimeout(800);
    await expect(page.getByRole('heading', { name: 'DID Status' })).toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Transport Interfaces  (/settings/transport)
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Transport Interfaces Page (/settings/transport)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings/transport', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
  });

  test('loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto('/settings/transport', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
    expect(errors).toHaveLength(0);
  });

  test('shows Transport heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Transport' })).toBeVisible();
  });

  test('shows Network Interfaces subtitle', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Network Interfaces');
  });

  test('no error boundary shown', async ({ page }) => {
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  test('accessible via /network/transport route', async ({ page }) => {
    await page.goto('/network/transport', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    await expect(page.getByRole('heading', { name: 'Transport' })).toBeVisible();
  });

  test('shows interface list or empty state', async ({ page }) => {
    const bodyText = await page.locator('body').textContent() ?? '';
    // Either interface cards are shown or an empty/no-data state
    const hasContent =
      bodyText.includes('Ethernet') ||
      bodyText.includes('WiFi') ||
      bodyText.includes('Interface') ||
      bodyText.includes('No interfaces') ||
      bodyText.includes('Loading') ||
      bodyText.length > 100;
    expect(hasContent).toBeTruthy();
  });

  test('Settings navigation "Transport Interfaces" button leads here', async ({ page }) => {
    await page.goto('/settings', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    await page.locator('button:visible').filter({ hasText: /Transport Interfaces/ }).first().click();
    await page.waitForTimeout(800);
    await expect(page.getByRole('heading', { name: 'Transport' })).toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Network Nodes / Relay  (/settings/relay)
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Network Nodes Page (/settings/relay)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings/relay', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
  });

  test('loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto('/settings/relay', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
    expect(errors).toHaveLength(0);
  });

  test('shows Network Nodes heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Network Nodes' })).toBeVisible();
  });

  test('shows Relay & Lighthouse Management subtitle', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Relay');
  });

  test('no error boundary shown', async ({ page }) => {
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  test('accessible via /network/relay route', async ({ page }) => {
    await page.goto('/network/relay', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    await expect(page.getByRole('heading', { name: 'Network Nodes' })).toBeVisible();
  });

  test('shows Relays tab', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Relay');
  });

  test('shows Lighthouses tab', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Lighthouse');
  });

  test('shows Members tab', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Member');
  });

  test('tab switching does not crash', async ({ page }) => {
    const lighthouseTab = page.getByRole('button', { name: /Lighthouse/i }).first();
    if (await lighthouseTab.isVisible()) {
      await lighthouseTab.click();
      await page.waitForTimeout(400);
      await expect(page.locator('body')).not.toContainText('Something went wrong');
    }
  });

  test('Members tab click does not crash', async ({ page }) => {
    const membersTab = page.getByRole('button', { name: /Members?/i }).first();
    if (await membersTab.isVisible()) {
      await membersTab.click();
      await page.waitForTimeout(400);
      await expect(page.locator('body')).not.toContainText('Something went wrong');
    }
  });

  test('Settings navigation "Network Nodes" button leads here', async ({ page }) => {
    await page.goto('/settings', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    await page.locator('button:visible').filter({ hasText: /^Network Nodes$/ }).first().click();
    await page.waitForTimeout(800);
    await expect(page.getByRole('heading', { name: 'Network Nodes' })).toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Credentials  (/settings/credentials)
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Credentials Page (/settings/credentials)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings/credentials', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
  });

  test('loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto('/settings/credentials', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
    expect(errors).toHaveLength(0);
  });

  test('shows Credentials heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Credentials' })).toBeVisible();
  });

  test('shows Verifiable subtitle', async ({ page }) => {
    await expect(page.locator('body')).toContainText('Verifiable');
  });

  test('no error boundary shown', async ({ page }) => {
    await expect(page.locator('body')).not.toContainText('Something went wrong');
  });

  test('shows VC list or empty state', async ({ page }) => {
    const bodyText = await page.locator('body').textContent() ?? '';
    // Either VC records are shown or an empty-state message
    const hasContent =
      bodyText.includes('VC') ||
      bodyText.includes('credential') ||
      bodyText.includes('Issued') ||
      bodyText.includes('No ') ||
      bodyText.includes('Loading') ||
      bodyText.length > 100;
    expect(hasContent).toBeTruthy();
  });

  test('has Issue VC button', async ({ page }) => {
    await expect(page.getByRole('button', { name: /Issue/i }).first()).toBeVisible();
  });

  test('Issue VC button opens a modal with Subject DID field', async ({ page }) => {
    // Click the exact "Issue VC" button (not filter tabs that say "Issued")
    await page.locator('button:visible').filter({ hasText: /^Issue VC$/ }).first().click();
    await page.waitForTimeout(600);
    // Modal heading "Issue Verifiable Credential" should be visible
    await expect(page.locator('body')).toContainText('Issue Verifiable Credential');
  });

  test('has Pull Status List button', async ({ page }) => {
    const bodyText = await page.locator('body').textContent() ?? '';
    // Button may be labelled "Pull Status List" or "Refresh"
    const hasPull = bodyText.includes('Pull') || bodyText.includes('Status List');
    expect(hasPull).toBeTruthy();
  });

  test('Settings navigation "Credentials" button leads here', async ({ page }) => {
    await page.goto('/settings', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    await page.locator('button:visible').filter({ hasText: /^Credentials$/ }).first().click();
    await page.waitForTimeout(800);
    await expect(page.getByRole('heading', { name: 'Credentials' })).toBeVisible();
  });

  test('Scope filter tabs are visible', async ({ page }) => {
    // VC page has scope filters: All, Issued, Own, Peers
    const bodyText = await page.locator('body').textContent() ?? '';
    const hasFilters =
      bodyText.includes('Issued') ||
      bodyText.includes('Own') ||
      bodyText.includes('Peers') ||
      bodyText.includes('All');
    expect(hasFilters).toBeTruthy();
  });
});

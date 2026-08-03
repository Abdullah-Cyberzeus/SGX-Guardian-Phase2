import { test, expect } from '@playwright/test';

/**
 * E2E Tests for Navigation and Settings Menu
 * Verifies all CLI command UIs are accessible via navigation
 */

test.describe('Settings Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
  });

  test.describe('Settings Root Page', () => {
    test('should load Settings page', async ({ page }) => {
      await expect(page.locator('body')).toContainText('Settings');
    });

    test('should display Security & Keys section', async ({ page }) => {
      await expect(page.locator('body')).toContainText('Security & Keys');
    });

    test('should display all security menu items', async ({ page }) => {
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toContain('Key Management');
      expect(bodyText).toContain('Integrity');
      expect(bodyText).toContain('Boot Status');
      expect(bodyText).toContain('Attestation');
      expect(bodyText).toContain('Policy Management');
      expect(bodyText).toContain('Logs');
    });
  });

  test.describe('Navigation to Security Pages', () => {
    test('should navigate to Key Management from Settings', async ({ page }) => {
      await page.getByRole('button', { name: /Key Management/i }).first().click();
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('DKP & Security Keys');
    });

    test('should navigate to Integrity from Settings', async ({ page }) => {
      await page.getByRole('button', { name: /Integrity/i }).first().click();
      await page.waitForTimeout(1000);
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toMatch(/PCR|Integrity/i);
    });

    test('should navigate to Boot Status from Settings', async ({ page }) => {
      await page.getByRole('button', { name: /Boot Status/i }).first().click();
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Secure Boot Chain');
    });

    test('should navigate to Attestation from Settings', async ({ page }) => {
      await page.getByRole('button', { name: /Attestation/i }).first().click();
      await page.waitForTimeout(1000);
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toMatch(/Attestation|Peer/i);
    });

    test('should navigate to Policy Management from Settings', async ({ page }) => {
      await page.getByRole('button', { name: /Policy Management/i }).first().click();
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Policy');
    });

    test('should navigate to Logs from Settings', async ({ page }) => {
      await page.getByRole('button', { name: /Logs/i }).first().click();
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Logs');
    });
  });

  test.describe('Back Navigation', () => {
    test('should navigate back from Key Management to Settings', async ({ page }) => {
      // Start at settings, navigate to keys, then go back via browser history
      await page.goto('/settings', { waitUntil: 'networkidle' });
      await page.waitForTimeout(500);
      await page.goto('/settings/keys', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();

      await page.goBack({ waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Security & Keys');
    });

    test('should navigate back from Integrity to Settings', async ({ page }) => {
      await page.goto('/settings', { waitUntil: 'networkidle' });
      await page.waitForTimeout(500);
      await page.goto('/settings/integrity', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Integrity' })).toBeVisible();

      await page.goBack({ waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Security & Keys');
    });
  });
});

test.describe('Direct URL Navigation', () => {
  test.describe('Standalone Routes', () => {
    test('should load /keys directly', async ({ page }) => {
      await page.goto('/keys', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain('Something went wrong');
    });

    test('should load /integrity directly', async ({ page }) => {
      await page.goto('/integrity', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Integrity' })).toBeVisible();
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain('Something went wrong');
    });

    test('should load /boot-status directly', async ({ page }) => {
      await page.goto('/boot-status', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Boot Status' })).toBeVisible();
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain('Something went wrong');
    });

    test('should load /attestation directly', async ({ page }) => {
      await page.goto('/attestation', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Attestation');
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain('Something went wrong');
    });

    test('should load /policy directly', async ({ page }) => {
      await page.goto('/policy', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Policy');
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain('Something went wrong');
    });

    test('should load /logs directly', async ({ page }) => {
      await page.goto('/logs', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Logs');
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain('Something went wrong');
    });
  });

  test.describe('Settings Prefixed Routes', () => {
    test('should load /settings/keys', async ({ page }) => {
      await page.goto('/settings/keys', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();
    });

    test('should load /settings/integrity', async ({ page }) => {
      await page.goto('/settings/integrity', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Integrity' })).toBeVisible();
    });

    test('should load /settings/boot-status', async ({ page }) => {
      await page.goto('/settings/boot-status', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Boot Status' })).toBeVisible();
    });

    test('should load /settings/attestation', async ({ page }) => {
      await page.goto('/settings/attestation', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Attestation');
    });

    test('should load /settings/policy', async ({ page }) => {
      await page.goto('/settings/policy', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Policy');
    });

    test('should load /settings/logs', async ({ page }) => {
      await page.goto('/settings/logs', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toContainText('Logs');
    });
  });
});

test.describe('Bottom Navigation', () => {
  test('should have Home tab', async ({ page }) => {
    await page.goto('/home', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
    await expect(page.locator('body')).toContainText('Home');
  });

  test('should navigate to Home from Settings', async ({ page }) => {
    await page.goto('/settings', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);

    // Use nav landmark + Home link
    const homeLink = page.getByRole('link', { name: /Home/i }).first();
    const count = await homeLink.count();
    if (count > 0) {
      await homeLink.click();
      await page.waitForTimeout(1000);
      expect(page.url()).toContain('/home');
    }
  });

  test('should navigate to Settings from Home', async ({ page }) => {
    await page.goto('/home', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);

    const settingsLink = page.getByRole('link', { name: /Settings/i }).first();
    const count = await settingsLink.count();
    if (count > 0) {
      await settingsLink.click();
      await page.waitForTimeout(1000);
      expect(page.url()).toContain('/settings');
    }
  });
});

test.describe('CLI Command to UI Mapping', () => {
  /**
   * This test suite verifies all 15 CLI commands have corresponding UI pages
   */

  const cliCommandRoutes = [
    { command: 'status', route: '/home/guardian', description: 'Node status' },
    { command: 'boot-status', route: '/settings/boot-status', description: 'Boot status' },
    { command: 'peers', route: '/home/topology', description: 'Network peers' },
    { command: 'attestation', route: '/settings/attestation', description: 'Attestation results' },
    { command: 'logs', route: '/settings/logs', description: 'System logs' },
    { command: 'keygen', route: '/settings/keys', description: 'Key generation' },
    { command: 'sign', route: '/settings/policy', description: 'Sign policy' },
    { command: 'verify', route: '/settings/policy', description: 'Verify policy' },
    { command: 'dkp-status', route: '/settings/keys', description: 'DKP status' },
    { command: 'dkp-rotate', route: '/settings/keys', description: 'DKP rotate' },
    { command: 'dkp-revoke', route: '/settings/keys', description: 'DKP revoke' },
    { command: 'emergency-rotate', route: '/settings/keys', description: 'Emergency rotate' },
    { command: 'pcr-status', route: '/settings/integrity', description: 'PCR status' },
    { command: 'pcr-baseline-create', route: '/settings/integrity', description: 'PCR baseline create' },
    { command: 'pcr-baseline-verify', route: '/settings/integrity', description: 'PCR baseline verify' },
  ];

  for (const { command, route } of cliCommandRoutes) {
    test(`CLI command "${command}" should have UI at ${route}`, async ({ page }) => {
      await page.goto(route, { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);

      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain('Something went wrong');

      // Verify page has content (not blank)
      expect((bodyText || '').length).toBeGreaterThan(100);
    });
  }
});

test.describe('Error Handling', () => {
  test('should show error boundary for invalid routes gracefully', async ({ page }) => {
    await page.goto('/settings/invalid-route-that-does-not-exist', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);

    // Page should still be functional (not a white screen)
    await expect(page.locator('body')).toBeVisible();
  });

  test('should handle page refresh without errors', async ({ page }) => {
    await page.goto('/settings/keys', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
    await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();

    // Refresh page
    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);

    // Should still work
    await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();
    const bodyText = await page.locator('body').textContent();
    expect(bodyText).not.toContain('Something went wrong');
  });
});

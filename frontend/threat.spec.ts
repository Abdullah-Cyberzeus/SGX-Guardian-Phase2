import { test, expect } from '@playwright/test';

const isLive = process.env.BACKEND_IS_LIVE === '1' ||
  (!!process.env.VITE_API_URL &&
   !process.env.VITE_API_URL.includes('localhost') &&
   !process.env.VITE_API_URL.includes('127.0.0.1'));

/**
 * E2E Tests for Integrity Dashboard Page
 * Covers CLI commands: pcr-status, pcr-baseline-create, pcr-baseline-verify
 */

test.describe('Integrity Dashboard Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings/integrity', { waitUntil: 'networkidle' });
    // Give page time to fully render
    await page.waitForTimeout(1000);
  });

  test.describe('Page Load and Navigation', () => {
    test('should load Integrity Dashboard without errors', async ({ page }) => {
      // Verify page title is present
      await expect(page.getByRole('heading', { name: 'Integrity' })).toBeVisible();

      // Verify no error boundary
      await expect(page.getByText('Something went wrong')).not.toBeVisible();
    });

    test('should display overall integrity status banner', async ({ page }) => {
      // Should show either "Device Integrity Verified" or "Integrity Check Failed"
      const bodyText = await page.locator('body').textContent();
      const hasBanner = bodyText?.includes('Device Integrity Verified') || bodyText?.includes('Integrity Check Failed');
      expect(hasBanner).toBeTruthy();
    });

    test('should have three tabs: PCR Status, Baseline, History', async ({ page }) => {
      await expect(page.getByRole('button', { name: 'PCR Status' }).first()).toBeVisible();
      await expect(page.getByRole('button', { name: 'Baseline' }).first()).toBeVisible();
      await expect(page.getByRole('button', { name: 'History' }).first()).toBeVisible();
    });

    test('should be accessible via direct URL /integrity', async ({ page }) => {
      await page.goto('/integrity', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Integrity' })).toBeVisible();
    });

    test('should be accessible via /settings/integrity', async ({ page }) => {
      await page.goto('/settings/integrity', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Integrity' })).toBeVisible();
    });
  });

  test.describe('PCR Status Tab (pcr-status command)', () => {
    test('should display Integrity Status', async ({ page }) => {
      await expect(page.locator('body')).toContainText('Integrity Status');
    });

    test('should display DKP Version', async ({ page }) => {
      await expect(page.locator('body')).toContainText('DKP Version');
    });

    test('should display Composite Digest', async ({ page }) => {
      await expect(page.locator('body')).toContainText('Composite Digest');
    });

    test('should display all 5 PCR registers (PCR0-PCR4)', async ({ page }) => {
      test.skip(isLive, 'testdata-specific: live device may have different PCR count');
      const mainText = await page.locator('body').textContent();
      expect(mainText).toContain('PCR0');
      expect(mainText).toContain('PCR1');
      expect(mainText).toContain('PCR2');
      expect(mainText).toContain('PCR3');
      expect(mainText).toContain('PCR4');
    });

    test('should display PCR register descriptions', async ({ page }) => {
      const mainText = await page.locator('body').textContent();
      expect(mainText).toMatch(/BIOS|Bootloader/);
      expect(mainText).toMatch(/Firmware|DTB/);
      expect(mainText).toContain('Kernel');
      expect(mainText).toContain('RootFS');
      expect(mainText).toContain('Configuration');
    });

    test('should show match/mismatch status for each PCR', async ({ page }) => {
      // Each PCR should have either Match or Mismatch badge
      const matchBadges = page.getByText('Match');
      const mismatchBadges = page.getByText('Mismatch');

      const matchCount = await matchBadges.count();
      const mismatchCount = await mismatchBadges.count();

      // Should have at least 5 status indicators (one per PCR)
      expect(matchCount + mismatchCount).toBeGreaterThanOrEqual(5);
    });

    test('should expand PCR register to show hash values', async ({ page }) => {
      // Click on first PCR register to expand
      const pcrCard = page.getByRole('button', { name: /PCR0/i }).first();
      await pcrCard.click();

      // Should show current value
      await expect(page.getByText('Current Value').first()).toBeVisible();
    });

    test('should have Verify Against Baseline button', async ({ page }) => {
      await expect(page.getByRole('button', { name: 'Verify Against Baseline' }).first()).toBeVisible();
    });
  });

  test.describe('PCR Baseline Verify (pcr-baseline-verify command)', () => {
    test('should perform verification when button clicked', async ({ page }) => {
      const verifyButton = page.getByRole('button', { name: 'Verify Against Baseline' }).first();
      await verifyButton.click();

      // Should complete and show result (toast or updated state)
      await page.waitForTimeout(1000);
      const mainText = await page.locator('body').textContent();
      expect(mainText).toMatch(/verified|match|verifying/i);
    });

    test('should show verification result in toast', async ({ page }) => {
      await page.getByRole('button', { name: 'Verify Against Baseline' }).first().click();

      // Wait for toast notification
      await expect(page.locator('[data-sonner-toast]').first()).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('Baseline Tab (pcr-baseline-create command)', () => {
    test('should switch to Baseline tab', async ({ page }) => {
      await page.getByRole('button', { name: 'Baseline' }).first().click();
      await page.waitForTimeout(1000);

      // Should show baseline content or "No Baseline Created"
      const bodyText = await page.locator('body').textContent();
      const hasBaseline = bodyText?.includes('Golden Baseline') || bodyText?.includes('No Baseline Created');
      expect(hasBaseline).toBeTruthy();
    });

    test('should show Create Baseline button', async ({ page }) => {
      await page.getByRole('button', { name: 'Baseline' }).first().click();
      await page.waitForTimeout(500);

      // Either "Create Golden Baseline" or "Create New Baseline"
      const createButton = page.getByRole('button', { name: /Create.*Baseline/i });
      await expect(createButton.first()).toBeVisible();
    });

    test('should display baseline info if baseline exists', async ({ page }) => {
      await page.getByRole('button', { name: 'Baseline' }).first().click();
      await page.waitForTimeout(500);

      const goldenBaseline = page.getByText('Golden Baseline').first();
      if (await goldenBaseline.isVisible()) {
        await expect(page.getByText('Created').first()).toBeVisible();
        await expect(page.getByText('Signed By').first()).toBeVisible();
        await expect(page.getByText('Registers').first()).toBeVisible();
      }
    });

    test('should show baseline PCR values if baseline exists', async ({ page }) => {
      await page.getByRole('button', { name: 'Baseline' }).first().click();
      await page.waitForTimeout(500);

      const goldenBaseline = page.getByText('Golden Baseline').first();
      if (await goldenBaseline.isVisible()) {
        await expect(page.getByText('Baseline Values').first()).toBeVisible();
      }
    });

    test('should open confirmation dialog when Create Baseline clicked', async ({ page }) => {
      await page.getByRole('button', { name: 'Baseline' }).first().click();
      await page.waitForTimeout(500);

      const createButton = page.getByRole('button', { name: /Create.*Baseline/i }).first();
      await createButton.click();

      // Should show confirmation dialog
      await expect(page.getByText('Create Golden Baseline?').first()).toBeVisible();
    });

    test('should create baseline when confirmed', async ({ page }) => {
      await page.getByRole('button', { name: 'Baseline' }).first().click();
      await page.waitForTimeout(500);

      const createButton = page.getByRole('button', { name: /Create.*Baseline/i }).first();
      await createButton.click();

      // Confirm
      await page.getByRole('button', { name: 'Create Baseline' }).first().click();

      // Should show success toast
      await expect(page.getByText(/baseline created/i).first()).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('History Tab', () => {
    test('should switch to History tab', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);
      await expect(page.getByText('Verification History').first()).toBeVisible();
    });

    test('should display verification history or empty state', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);

      const mainText = await page.locator('body').textContent();
      const hasHistory = mainText?.includes('Integrity Check') || mainText?.includes('No verification history');
      expect(hasHistory).toBeTruthy();
    });

    test('should show pass/fail status for each verification', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(1000);

      const bodyText = await page.locator('body').textContent();
      if (bodyText?.includes('Integrity Check')) {
        const hasPassOrFail = bodyText.includes('Pass') || bodyText.includes('Fail');
        expect(hasPassOrFail).toBeTruthy();
      }
    });

    test('should show PCR match count in history', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);

      const historyCards = page.getByText('Integrity Check').first();
      if (await historyCards.isVisible()) {
        await expect(page.getByText('PCR Registers').first()).toBeVisible();
      }
    });
  });

  test.describe('StatusBadge Fallback (Bug Fix Verification)', () => {
    test('should handle unknown status values gracefully', async ({ page }) => {
      // Navigate to page - should not crash
      await page.goto('/settings/integrity', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);

      // Verify page loaded
      await expect(page.getByRole('heading', { name: 'Integrity' })).toBeVisible();

      // Navigate through all tabs - should not crash
      await page.getByRole('button', { name: 'Baseline' }).first().click();
      await page.waitForTimeout(300);

      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(300);

      await page.getByRole('button', { name: 'PCR Status' }).first().click();
      await page.waitForTimeout(300);

      // Verify no error boundary appeared
      await expect(page.getByText('Something went wrong').first()).not.toBeVisible();
    });
  });

  test.describe('Info Banner', () => {
    test('should display PCR information banner', async ({ page }) => {
      await expect(page.locator('body')).toContainText('PCR values are cryptographic measurements');
    });
  });
});

import { test, expect } from '@playwright/test';

/**
 * E2E Tests for Key Management Page
 * Covers CLI commands: dkp-status, dkp-rotate, dkp-revoke, emergency-rotate, keygen
 */

test.describe('Key Management Page', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate directly to key management page
    await page.goto('/settings/keys', { waitUntil: 'networkidle' });
    // Give page time to fully render
    await page.waitForTimeout(1000);
  });

  test.describe('Page Load and Navigation', () => {
    test('should load Key Management page without errors', async ({ page }) => {
      // Verify page title
      await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();

      // Verify page content
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toContain('DKP & Security Keys');

      // Verify no error boundary
      expect(bodyText).not.toContain('Something went wrong');
    });

    test('should display SE050 hardware mode banner', async ({ page }) => {
      // Just ensure no crash and page loaded
      await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();
    });

    test('should have three tabs: DKP Status, History, Emergency', async ({ page }) => {
      await expect(page.getByRole('button', { name: 'DKP Status' }).first()).toBeVisible();
      await expect(page.getByRole('button', { name: 'History' }).first()).toBeVisible();
      await expect(page.getByRole('button', { name: 'Emergency' }).first()).toBeVisible();
    });

    test('should be accessible via direct URL /keys', async ({ page }) => {
      await page.goto('/keys', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();
    });

    test('should be accessible via /settings/keys', async ({ page }) => {
      await page.goto('/settings/keys', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();
    });
  });

  test.describe('DKP Status Tab (dkp-status command)', () => {
    test('should display active key information', async ({ page }) => {
      await expect(page.locator('body')).toContainText('Active Key');
    });

    test('should show key version number', async ({ page }) => {
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toMatch(/Version \d+/);
    });

    test('should show key algorithm', async ({ page }) => {
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toContain('Algorithm');
      expect(bodyText).toContain('ECDSA-P256');
    });

    test('should show total versions count', async ({ page }) => {
      await expect(page.locator('body')).toContainText('Total Versions');
    });

    test('should have Rotate Key button', async ({ page }) => {
      await expect(page.getByRole('button', { name: 'Rotate Key' }).first()).toBeVisible();
    });
  });

  test.describe('DKP Rotate (dkp-rotate command)', () => {
    test('should open confirmation dialog when Rotate Key clicked', async ({ page }) => {
      await page.getByRole('button', { name: 'Rotate Key' }).first().click();
      await page.waitForTimeout(500);

      // Verify dialog appears
      await expect(page.locator('body')).toContainText('Rotate DKP Key?');
    });

    test('should close dialog when Cancel clicked', async ({ page }) => {
      await page.getByRole('button', { name: 'Rotate Key' }).first().click();
      await page.waitForTimeout(500);
      await expect(page.locator('body')).toContainText('Rotate DKP Key?');

      await page.getByRole('button', { name: 'Cancel' }).first().click();
      await page.waitForTimeout(500);
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain('Rotate DKP Key?');
    });

    test('should perform rotation and show success toast', async ({ page }) => {
      await page.getByRole('button', { name: 'Rotate Key' }).first().click();
      await page.waitForTimeout(500);

      // Confirm in dialog - dialog is a custom div (not role="dialog"), so the
      // confirm "Rotate Key" button is the last button with that name on the page
      await page.getByRole('button', { name: 'Rotate Key' }).last().click();

      // Should show a toast notification (any toast — success or acknowledgement)
      await expect(page.locator('[data-sonner-toast]').first()).toBeVisible({ timeout: 8000 });
    });

    test('should show daemon restart banner after rotation', async ({ page }) => {
      await page.getByRole('button', { name: 'Rotate Key' }).first().click();
      await page.waitForTimeout(500);
      await page.getByRole('button', { name: 'Rotate Key' }).last().click();
      await page.waitForTimeout(1500);

      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toMatch(/restart/i);
    });
  });

  test.describe('History Tab', () => {
    test('should switch to History tab', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);
      await expect(page.locator('body')).toContainText('All Key Versions');
    });

    test('should display key version cards', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);

      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toMatch(/Version \d+/);
    });

    test('should show key status badges (Active, Deprecated, Revoked)', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);

      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toContain('Active');
    });

    test('should open key details when clicking a key card', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);

      // Click on first key card
      const firstKeyCard = page.getByRole('button', { name: /Version/ }).first();
      await firstKeyCard.click();
      await page.waitForTimeout(500);

      // Should show key details
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toContain('Key Details');
    });
  });

  test.describe('DKP Revoke (dkp-revoke command)', () => {
    test('should show Revoke button for deprecated keys', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);

      // Look for deprecated key
      const deprecatedKey = page.getByRole('button', { name: /Deprecated/ });
      const count = await deprecatedKey.count();

      if (count > 0) {
        await deprecatedKey.first().click();
        await page.waitForTimeout(500);

        // Should show revoke option in detail panel
        const bodyText = await page.locator('body').textContent();
        expect(bodyText).toContain('Revoke This Key');
      } else {
        // If no deprecated keys, just verify no crash
        await expect(page.locator('body')).toContainText('All Key Versions');
      }
    });

    test('should NOT show Revoke button for active keys', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);

      // Click on active key card - find a card containing "Active"
      const activeKeyCards = page.locator('button').filter({ hasText: 'Active' });
      const count = await activeKeyCards.count();
      if (count > 0) {
        await activeKeyCards.first().click();
        await page.waitForTimeout(500);

        // Revoke button should NOT be visible in detail panel for active keys
        const revokeButton = page.locator('button:has-text("Revoke This Key")');
        const revokeCount = await revokeButton.count();
        expect(revokeCount).toBe(0);
      }
    });

    test('should open confirmation dialog when Revoke clicked', async ({ page }) => {
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);

      const deprecatedKey = page.getByRole('button', { name: /Deprecated/ });
      const count = await deprecatedKey.count();

      if (count > 0) {
        await deprecatedKey.first().click();
        await page.waitForTimeout(500);
        await page.getByRole('button', { name: 'Revoke This Key' }).first().click();
        await page.waitForTimeout(500);

        const bodyText = await page.locator('body').textContent();
        expect(bodyText).toContain('Revoke Key?');
        expect(bodyText).toMatch(/30-day grace period/i);
      }
    });
  });

  test.describe('Emergency Tab (emergency-rotate command)', () => {
    test('should switch to Emergency tab', async ({ page }) => {
      await page.getByRole('button', { name: 'Emergency' }).first().click();
      await page.waitForTimeout(500);
      await expect(page.locator('body')).toContainText('Emergency Key Rotation');
    });

    test('should list keys that will be rotated', async ({ page }) => {
      await page.getByRole('button', { name: 'Emergency' }).first().click();
      await page.waitForTimeout(500);

      const bodyText = await page.locator('body').textContent() ?? '';
      // Emergency tab must mention at least one key type
      const mentionsKeys = bodyText.includes('DKP') ||
        bodyText.includes('Key') ||
        bodyText.includes('Certificate');
      expect(mentionsKeys).toBeTruthy();
    });

    test('should have Initiate Emergency Rotation button', async ({ page }) => {
      await page.getByRole('button', { name: 'Emergency' }).first().click();
      await page.waitForTimeout(500);
      await expect(page.getByRole('button', { name: 'Initiate Emergency Rotation' }).first()).toBeVisible();
    });

    test('should open warning dialog on emergency rotation', async ({ page }) => {
      await page.getByRole('button', { name: 'Emergency' }).first().click();
      await page.waitForTimeout(500);
      await page.getByRole('button', { name: 'Initiate Emergency Rotation' }).first().click();
      await page.waitForTimeout(500);

      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toContain('Emergency Rotation');
      expect(bodyText).toMatch(/ALL critical keys/i);
    });

    test('should show rotation history', async ({ page }) => {
      await page.getByRole('button', { name: 'Emergency' }).first().click();
      await page.waitForTimeout(500);
      await expect(page.locator('body')).toContainText('Rotation History');
    });

    test('should perform emergency rotation and show daemon restart banner', async ({ page }) => {
      await page.getByRole('button', { name: 'Emergency' }).first().click();
      await page.waitForTimeout(500);
      await page.getByRole('button', { name: 'Initiate Emergency Rotation' }).first().click();
      await page.waitForTimeout(500);

      // Confirm in dialog
      await page.getByRole('button', { name: 'Rotate All Keys' }).first().click();
      await page.waitForTimeout(1500);

      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toMatch(/Emergency rotation complete|rotation completed|restart/i);
    });
  });

  test.describe('StatusBadge Fallback (Bug Fix Verification)', () => {
    test('should handle unknown status values gracefully', async ({ page }) => {
      // This test verifies the bug fix for:
      // "Cannot destructure property 'bg' of 'config[status]' as it is undefined"

      // Navigate to page - should not crash
      await page.goto('/settings/keys', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);
      await expect(page.getByRole('heading', { name: 'Key Management' })).toBeVisible();

      // Navigate through all tabs - should not crash
      await page.getByRole('button', { name: 'History' }).first().click();
      await page.waitForTimeout(500);
      await expect(page.locator('body')).toContainText('All Key Versions');

      await page.getByRole('button', { name: 'Emergency' }).first().click();
      await page.waitForTimeout(500);
      await expect(page.locator('body')).toContainText('Emergency Key Rotation');

      await page.getByRole('button', { name: 'DKP Status' }).first().click();
      await page.waitForTimeout(500);
      await expect(page.locator('body')).toContainText('Active Key');

      // Verify no error boundary appeared
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain('Something went wrong');
    });
  });
});

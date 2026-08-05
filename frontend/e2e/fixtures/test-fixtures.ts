import { test as base, expect } from '@playwright/test';

/**
 * Extended test fixtures for SGX Guardian E2E tests
 */
export const test = base.extend({
  // Auto-login and navigate to home before each test
  authenticatedPage: async ({ page }, use) => {
    // Navigate to app and wait for load
    await page.goto('/');

    // Wait for splash screen to complete (auto-redirects to login or home)
    await page.waitForURL(/\/(home|login|onboarding)/);

    // If redirected to login, perform login
    if (page.url().includes('/login')) {
      await page.fill('input[type="email"]', 'admin@sgx-guardian.local');
      await page.fill('input[type="password"]', 'admin123');
      await page.click('button[type="submit"]');
      await page.waitForURL('/home');
    }

    await use(page);
  },
});

export { expect };

/**
 * Helper to navigate to Settings > Security & Keys section
 */
export async function navigateToSecuritySettings(page: any) {
  await page.click('text=Settings');
  await page.waitForSelector('text=Security & Keys');
}

/**
 * Helper to navigate to a specific security page
 */
export async function navigateToSecurityPage(page: any, pageName: string) {
  await navigateToSecuritySettings(page);
  await page.click(`text=${pageName}`);
}

/**
 * Helper to check for page load without errors
 */
export async function assertNoErrors(page: any) {
  // Check that error boundary is not shown
  const errorElement = page.locator('text=Something went wrong');
  await expect(errorElement).not.toBeVisible();

  // Check console for JavaScript errors
  const errors: string[] = [];
  page.on('pageerror', (error: Error) => errors.push(error.message));

  return errors;
}

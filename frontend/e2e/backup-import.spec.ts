import { expect, test, type Page } from '@playwright/test';

test.use({ serviceWorkers: 'block' });

const baseHistory = {
  records: [
    {
      id: 'backup-existing',
      created_at: '2026-08-04T09:00:00.000Z',
      portable: true,
      components: ['policy', 'config'],
      size_bytes: 2048,
    },
  ],
};

const importedHistory = {
  records: [
    ...baseHistory.records,
    {
      id: 'backup-imported',
      created_at: '2026-08-04T10:00:00.000Z',
      portable: true,
      components: ['policy', 'config', 'credentials', 'crl'],
      size_bytes: 4096,
    },
  ],
};

type HistoryFixture = typeof baseHistory;

async function routeBackupPage(page: Page, historyResponses: HistoryFixture[] | (() => HistoryFixture) = [baseHistory]) {
  let historyIndex = 0;
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, '');

    if (path === '/backup/history') {
      const response = typeof historyResponses === 'function'
        ? historyResponses()
        : historyResponses[Math.min(historyIndex, historyResponses.length - 1)];
      historyIndex += 1;
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
      return;
    }
    if (path === '/restore/status') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 'idle', journal: null }) });
      return;
    }
    if (path === '/auth/session') {
      await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { message: 'No active session' } }) });
      return;
    }
    if (path === '/node/status') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ nodeId: 'node-test' }) });
      return;
    }
    if (path === '/calls/active' || path === '/calls') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ calls: [], total: 0 }) });
      return;
    }
    if (path === '/calls/ice-servers') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ice_servers: [], configured: false }) });
      return;
    }
    if (path === '/calls/events' || path === '/notifications/stream') {
      await route.fulfill({ status: 200, contentType: 'text/event-stream', body: '' });
      return;
    }
    if (path === '/cert/requests') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      return;
    }

    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({}) });
  });
}

test.describe('Backup import', () => {
  test('selects a .sgxbak file', async ({ page }) => {
    await routeBackupPage(page);
    await page.goto('/settings/backup');

    await page.getByRole('button', { name: 'Import backup' }).click();
    const fileInput = page.locator('input[type="file"]');
    await expect(fileInput).toBeVisible();
    await expect(fileInput).toHaveAttribute('accept', '.sgxbak');

    await fileInput.setInputFiles({
      name: 'guardian.sgxbak',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('backup-content'),
    });

    await expect(fileInput).toHaveJSProperty('files.length', 1);
  });

  test('sends the import request as multipart/form-data', async ({ page }) => {
    await routeBackupPage(page);
    let sawImportRequest = false;
    await page.route('**/api/v1/backup/import', async (route, request) => {
      sawImportRequest = true;
      expect(request.method()).toBe('POST');
      expect(request.headers()['content-type']).toContain('multipart/form-data');
      const body = request.postDataBuffer()?.toString('utf8') ?? '';
      expect(body).toContain('name="file"');
      expect(body).toContain('filename="guardian.sgxbak"');
      expect(body).toContain('name="passphrase"');
      expect(body).toContain('correct horse');
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(importedHistory.records[1]),
      });
    });

    await page.goto('/settings/backup');
    await page.getByRole('button', { name: 'Import backup' }).click();
    const importDialog = page.getByRole('dialog', { name: 'Import Backup' });
    await importDialog.locator('input[type="file"]').setInputFiles({
      name: 'guardian.sgxbak',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('backup-content'),
    });
    await importDialog.locator('input[type="password"]').fill('correct horse');
    await importDialog.getByRole('button', { name: /^Import$/ }).click();

    await expect.poll(() => sawImportRequest).toBe(true);
  });

  test('refreshes backup history after successful import', async ({ page }) => {
    let importCompleted = false;
    await routeBackupPage(page, () => importCompleted ? importedHistory : baseHistory);
    await page.route('**/api/v1/backup/import', async (route) => {
      importCompleted = true;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(importedHistory.records[1]),
      });
    });

    await page.goto('/settings/backup');
    await expect(page.locator('p[title="backup-existing"]').last()).toBeVisible();
    await expect(page.locator('p[title="backup-imported"]')).toHaveCount(0);

    await page.getByRole('button', { name: 'Import backup' }).click();
    const importDialog = page.getByRole('dialog', { name: 'Import Backup' });
    await importDialog.locator('input[type="file"]').setInputFiles({
      name: 'guardian.sgxbak',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('backup-content'),
    });
    await importDialog.locator('input[type="password"]').fill('correct horse');
    await importDialog.getByRole('button', { name: /^Import$/ }).click();

    await expect(page.getByText('Backup imported')).toBeVisible();
    await expect(page.locator('p[title="backup-imported"]').last()).toBeVisible();
  });

  test('shows backend error for invalid passphrase', async ({ page }) => {
    await routeBackupPage(page);
    await page.route('**/api/v1/backup/import', async (route) => {
      await route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({ error: { message: 'Invalid passphrase' } }),
      });
    });

    await page.goto('/settings/backup');
    await page.getByRole('button', { name: 'Import backup' }).click();
    const importDialog = page.getByRole('dialog', { name: 'Import Backup' });
    await importDialog.locator('input[type="file"]').setInputFiles({
      name: 'guardian.sgxbak',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('backup-content'),
    });
    await importDialog.locator('input[type="password"]').fill('wrong passphrase');
    await importDialog.getByRole('button', { name: /^Import$/ }).click();

    await expect(page.getByText('Import failed')).toBeVisible();
    await expect(page.getByText('Invalid passphrase')).toBeVisible();
  });
});

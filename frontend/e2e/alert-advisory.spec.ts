import { expect, test, type Page, type Route } from '@playwright/test';

test.use({ serviceWorkers: 'block' });

const alert = {
  alert_id: 'alert-advisory-1',
  timestamp: '2026-08-06T08:30:00Z',
  src_ip: '10.0.0.25',
  src_port: 51514,
  dst_ip: '10.0.0.10',
  dst_port: 22,
  protocol: 'TCP',
  signature_id: 10000132,
  signature: 'SGX TEST ALERT CVE RCE',
  category: 'exploit',
  severity: 'critical',
  event_type: 'alert',
  blocked: false,
  gid: 1,
  rev: 3,
};

const recommendation = {
  rec_id: 'rec-1',
  alert_id: alert.alert_id,
  title: 'Contain suspected exploit attempt',
  summary: 'Review the SSH exposure and validate whether the target accepted exploit traffic.',
  severity: 'critical',
  confidence: 0.91,
  source: 'signature-kb',
  generated_at: '2026-08-06T08:31:00Z',
  context: ['Device has CVE-2023-38408 (CVSS 9.8)', 'Risk: exposed SSH service on target device'],
  references: ['SID-10000132', 'CVE-2023-38408'],
  steps: [
    { order: 1, action: 'Verify affected SSH service exposure', rationale: 'Confirms whether the detected exploit path is reachable.', automatable: true },
    { order: 2, action: 'Schedule firmware or package remediation', rationale: 'Patch planning requires operator validation.', automatable: false },
  ],
};

const rules = { version: '1', rules: [], fallback: { title: 'Fallback advisory' } };

async function routeAlerts(
  page: Page,
  recommendationRoute: (route: Route) => Promise<void>,
  recentRecommendations = [recommendation],
) {
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, '');

    if (path === '/threat/alerts') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([alert]) });
      return;
    }
    if (path === `/threat/alerts/${alert.alert_id}/recommendation`) {
      await recommendationRoute(route);
      return;
    }
    if (path === '/advisory/recommendations') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(recentRecommendations) });
      return;
    }
    if (path === '/advisory/rules') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(rules) });
      return;
    }
    if (path === '/managed-devices') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            device_id: 'dev-ssh-1',
            ip: '10.0.0.10',
            vendor: 'SG-X Lab',
            hostname: 'ssh-target',
            display_name: 'SSH Target',
            manual: false,
            monitoring_enabled: true,
            blocked: false,
            rejected: false,
            status: 'authorized',
            os_fingerprint: 'Linux 5.x',
            os_cpe: [],
            open_ports: [{ port: 22, protocol: 'tcp', service: 'ssh', cpe: [], scripts: [] }],
            host_scripts: [],
            security_score: 42,
            security_reasons: ['exposed remote administration service'],
            privacy_score: 90,
            privacy_reasons: [],
            privacy_basis: 'scan',
            risk_level: 'high',
            computed_at: '2026-08-06T08:00:00Z',
          },
        ]),
      });
      return;
    }
    if (path === '/threat/status') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ suricata: 'active', enabled: true, block_mode: 'alert_only', alert_count: 1, block_count: 0 }) });
      return;
    }
    if (path === '/auth/session') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ token: 'test-token', user: { id: 'user-test', email: 'test@example.com', name: 'Test User' } }) });
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
    if (path === '/notifications/prefs') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          alerts: { high: true, medium: true, low: true },
          devices: { new_device: true, pending_approval: true, guardian_offline: true },
          circles: { new_message: true, incoming_call: true, member_joined: true },
        }),
      });
      return;
    }

    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({}) });
  });
}

async function openAlert(page: Page) {
  await page.addInitScript(() => {
    window.localStorage.setItem('sgx_auth_token', 'test-token');
  });
  await page.goto('/alerts');
  await page.locator('span:visible', { hasText: 'SGX TEST ALERT CVE RCE' }).first().click();
}

test.describe('Alerts advisory recommendation panel', () => {
  test('shows loading skeleton while recommendation is fetched', async ({ page }) => {
    let resolveRecommendation: (() => void) | null = null;
    await routeAlerts(page, async (route) => {
      await new Promise<void>((resolve) => { resolveRecommendation = resolve; });
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(recommendation) });
    });

    await openAlert(page);
    await expect(page.locator('.animate-pulse:visible').first()).toBeVisible();
    resolveRecommendation?.();
    await expect(page.getByText('Contain suspected exploit attempt')).toBeVisible();
  });

  test('renders recommendation success details', async ({ page }) => {
    await routeAlerts(page, async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(recommendation) });
    });

    await openAlert(page);
    await expect(page.getByText('AI REMEDIATION RECOMMENDATION').last()).toBeVisible();
    await expect(page.getByText('91%').last()).toBeVisible();
    await expect(page.getByText('Verify affected SSH service exposure').last()).toBeVisible();
    await expect(page.getByText('Automatable').last()).toBeVisible();
    await expect(page.getByText('Manual').last()).toBeVisible();
    await expect(page.getByText('CVE-2023-38408').last()).toBeVisible();
    await expect(page.getByText('dev-ssh-1').last()).toBeVisible();
  });

  test('shows fallback recommendation state', async ({ page }) => {
    await routeAlerts(page, async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...recommendation, source: 'fallback' }) });
    });

    await openAlert(page);
    await expect(page.getByText('Fallback recommendation').last()).toBeVisible();
    await expect(page.getByText('fallback').last()).toBeVisible();
  });

  test('shows no recommendation found for 404', async ({ page }) => {
    await routeAlerts(page, async (route) => {
      await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: 'no recommendation for alert' }) });
    }, []);

    await openAlert(page);
    await expect(page.getByText('No recommendation found').last()).toBeVisible();
  });

  test('shows clean unauthorized state for 401', async ({ page }) => {
    await routeAlerts(page, async (route) => {
      await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'missing bearer token' }) });
    });

    await openAlert(page);
    await expect(page.getByText('Unauthorized', { exact: true }).last()).toBeVisible();
    await expect(page.getByText('Session expired or unauthorized').last()).toBeVisible();
    await expect(page.getByText('missing bearer token')).toHaveCount(0);
  });
});

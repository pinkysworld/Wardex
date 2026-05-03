const { test, expect } = require('@playwright/test');

const BASE = process.env.WARDEX_BASE_URL || 'http://127.0.0.1:8095';
const TOKEN = process.env.WARDEX_ADMIN_TOKEN || '';

test('advanced admin console workflows smoke', async ({ page }) => {
  test.skip(!TOKEN, 'Set WARDEX_ADMIN_TOKEN to run the advanced admin smoke.');

  const huntName = `Credential Storm Pivot ${Date.now()}`;
  const huntQuery = 'severity:critical credential storm';

  const consoleErrors = [];
  const pageErrors = [];
  const badResponses = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => pageErrors.push(String(err)));
  page.on('response', (response) => {
    if (response.url().startsWith(BASE + '/api/') && response.status() >= 400) {
      badResponses.push(`${response.status()} ${response.url()}`);
    }
  });

  await page.route(`${BASE}/api/storage/events/historical**`, async (route) => {
    const url = new URL(route.request().url());
    const userName = url.searchParams.get('user_name') || 'alice@example.com';

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        enabled: true,
        count: 1,
        total: 1,
        limit: Number(url.searchParams.get('limit') || '25'),
        offset: Number(url.searchParams.get('offset') || '0'),
        events: [
          {
            timestamp: '2026-04-20T10:17:00Z',
            severity: 7,
            event_class: 401,
            device_id: 'agent-01',
            user_name: userName,
            src_ip: '203.0.113.10',
            dst_ip: '198.51.100.15',
            raw_json: '{"event":"ConsoleLogin"}',
          },
        ],
        clickhouse: {
          database: 'wardex',
        },
      }),
    });
  });

  await page.route(`${BASE}/api/incidents/7`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        id: '7',
        title: 'Credential replay escalation',
        severity: 'high',
        status: 'investigating',
      }),
    });
  });

  await page.goto(`${BASE}/admin/`, { waitUntil: 'domcontentloaded' });
  await expect(page).toHaveURL(/\/admin\/?$/);
  await page.getByPlaceholder('API token').fill(TOKEN);
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('.auth-badge')).toContainText(/Connected/);

  const onboardingDialog = page.getByRole('dialog', {
    name: 'Set up the Wardex admin console',
  });
  if (await onboardingDialog.isVisible().catch(() => false)) {
    await onboardingDialog.getByRole('button', { name: 'Skip for now' }).click();
    await expect(onboardingDialog).toBeHidden();
  }

  // The unauthenticated shell probes session and SSO config before the token is applied.
  // Start error assertions once the console is connected and ready for authenticated workflows.
  consoleErrors.length = 0;
  badResponses.length = 0;
  pageErrors.length = 0;

  const sidebar = page.locator('#sidebar-nav');

  await sidebar.getByRole('link', { name: 'Dashboard', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible();

  await page.goto(
    `${BASE}/admin/detection?intent=run-hunt&huntName=${encodeURIComponent(huntName)}&huntQuery=${encodeURIComponent(huntQuery)}`,
    { waitUntil: 'domcontentloaded' },
  );
  await expect(page.getByRole('heading', { name: 'Threat Detection' })).toBeVisible();
  await expect(page.locator('.auth-badge')).toContainText(/Connected/);
  await expect(page.locator('#hunt-name')).toBeVisible({ timeout: 15000 });
  await expect(page.locator('#hunt-name')).toHaveValue(huntName);
  await expect(page.locator('#hunt-query')).toHaveValue(huntQuery);
  await page.getByRole('button', { name: 'Run Hunt' }).click();
  await expect(page.getByText('Hunt completed.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Save Hunt' }).click();
  await expect(page.getByText('Hunt saved.', { exact: true })).toBeVisible();
  await page.goto(`${BASE}/admin/soc`, { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Workbench Overview')).toBeVisible();
  await expect(page.getByText('Investigations In Flight')).toBeVisible();
  await page.getByRole('button', { name: 'Response', exact: true }).click();
  await expect(page.getByText('Pending Responses', { exact: true })).toBeVisible();
  await expect(page.getByText('Response Stats', { exact: true })).toBeVisible();
  await expect(page.getByText('Response Requests', { exact: true })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Security Policy', exact: true }).click();
  await page.getByRole('button', { name: 'Policy', exact: true }).click();
  await expect(page.getByText('Current Policy')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Compose and Preview' })).toBeVisible();
  await page.getByRole('button', { name: 'Deception', exact: true }).click();
  const deceptionCard = page.locator('.card').filter({
    has: page.getByText('Deception Posture', { exact: true }),
  });
  await expect(
    deceptionCard.locator('.card-title').filter({ hasText: /^Attacker Profiles$/ }).first(),
  ).toBeVisible();
  await expect(
    deceptionCard
      .locator('.card-title')
      .filter({ hasText: /^Recent Decoy Interactions$/ })
      .first(),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Enforcement', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Quarantine Target' })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('tab', { name: 'Integrations' }).click();
  await expect(page.getByText('IdP Providers')).toBeVisible();
  await expect(page.getByText('Cloud Collectors & Secrets')).toBeVisible();
  await expect(page.getByText('Collector Routing & Health')).toBeVisible();
  await expect(page.getByText('Identity Telemetry Lane')).toBeVisible();
  await expect(page.getByText('SaaS Activity Lane')).toBeVisible();
  await page.getByRole('tab', { name: 'Admin' }).click();
  await expect(page.getByText('Long-Retention History')).toBeVisible();
  const retentionCard = page.locator('.card').filter({
    has: page.getByText('Long-Retention History', { exact: true }),
  });
  await expect(retentionCard.getByText('ConsoleLogin', { exact: true })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Fleet & Agents', exact: true }).click();
  await page.getByRole('button', { name: 'Updates', exact: true }).click();
  await expect(page.getByText('Updates focus', { exact: true })).toBeVisible();
  await expect(page.getByText('Recent Rollout History', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Recovery', exact: true }).click();
  await expect(page.getByText('Recovery Watchlist', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Deployment Health', exact: true }).click();
  await expect(page.locator('.card-title').filter({ hasText: /^Deployment Health$/ })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Infrastructure', exact: true }).click();
  await page.getByRole('tab', { name: 'Assets', exact: true }).click();
  await expect(page.getByText('Saved Views', { exact: true })).toBeVisible();
  await expect(
    page.getByText('Select an asset to review posture, related evidence, and subsystem details.'),
  ).toBeVisible();
  await page.getByRole('tab', { name: 'Integrity', exact: true }).click();
  await expect(page.getByText('Recent Malware Triage', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Observability', exact: true }).click();
  const telemetryCard = page.locator('.card').filter({
    has: page.getByText('Telemetry Detail', { exact: true }),
  });
  await expect(telemetryCard.getByText('Trace Samples', { exact: true })).toBeVisible();

  await page.goto(
    `${BASE}/admin/reports?tab=templates&case=42&incident=7&investigation=inv-7&source=case`,
    { waitUntil: 'domcontentloaded' },
  );
  await expect(page.getByText('Reusable Templates', { exact: true })).toBeVisible();
  const reportPreviewCard = page.locator('.triage-detail .card').filter({
    has: page.getByText('Preview Scope', { exact: true }),
  });
  await expect(reportPreviewCard.getByText('Case #42', { exact: true })).toBeVisible();
  await expect(reportPreviewCard.getByText('Incident #7', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Compliance', exact: true }).click();
  await expect(page.getByText('Compliance Snapshot', { exact: true })).toBeVisible();
  await expect(page.getByText('Priority Findings Snapshot', { exact: true })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Help & Docs', exact: true }).click();
  await expect(page.getByText('Documentation Center', { exact: true })).toBeVisible();
  await expect(page.getByText('GraphQL Explorer', { exact: true })).toBeVisible();
  const parityCard = page.locator('.card').filter({
    has: page.getByText('Contract Parity', { exact: true }),
  });
  await expect(parityCard.getByText('Report Workflow Coverage', { exact: true })).toBeVisible();
  await expect(parityCard.getByText('Runtime routes', { exact: true })).toBeVisible();
  await page.getByLabel('Search docs').fill('sdk');
  await expect(page.getByRole('button', { name: 'Open SDK guide' })).toBeVisible();
  await page.getByRole('button', { name: 'Run Query' }).click();
  await expect(page.getByText('GraphQL response')).toBeVisible();

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});
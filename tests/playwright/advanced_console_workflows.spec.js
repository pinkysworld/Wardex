const { test, expect } = require('@playwright/test');

const BASE = process.env.WARDEX_BASE_URL || 'http://127.0.0.1:8095';
const TOKEN = process.env.WARDEX_ADMIN_TOKEN || '';

test('advanced admin console workflows smoke', async ({ page }) => {
  test.skip(!TOKEN, 'Set WARDEX_ADMIN_TOKEN to run the advanced admin smoke.');

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

  await sidebar.getByRole('link', { name: 'SOC Workbench', exact: true }).click();
  await expect(page.getByText('Workbench Overview')).toBeVisible();
  await expect(page.getByText('Investigations In Flight')).toBeVisible();

  await sidebar.getByRole('link', { name: 'Security Policy', exact: true }).click();
  await page.getByRole('button', { name: 'Policy', exact: true }).click();
  await expect(page.getByText('Current Policy')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Compose and Preview' })).toBeVisible();
  await page.getByRole('button', { name: 'Enforcement', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Quarantine Target' })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Integrations' }).click();
  await expect(page.getByText('IdP Providers')).toBeVisible();
  await expect(page.getByText('Cloud Collectors & Secrets')).toBeVisible();
  await page.getByRole('button', { name: 'Admin' }).click();
  await expect(page.getByText('Long-Retention History')).toBeVisible();

  await sidebar.getByRole('link', { name: 'Help & Docs', exact: true }).click();
  await expect(page.getByText('Documentation Center', { exact: true })).toBeVisible();
  await expect(page.getByText('GraphQL Explorer', { exact: true })).toBeVisible();
  await page.getByLabel('Search docs').fill('sdk');
  await expect(page.getByRole('button', { name: 'Open SDK guide' })).toBeVisible();
  await page.getByRole('button', { name: 'Run Query' }).click();
  await expect(page.getByText('GraphQL response')).toBeVisible();

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});
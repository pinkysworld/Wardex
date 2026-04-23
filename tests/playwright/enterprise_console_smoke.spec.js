const { test, expect } = require('@playwright/test');

const BASE = process.env.WARDEX_BASE_URL || 'http://127.0.0.1:8095';
const TOKEN = process.env.WARDEX_ADMIN_TOKEN || '';

test('enterprise admin console smoke', async ({ page }) => {
  test.skip(!TOKEN, 'Set WARDEX_ADMIN_TOKEN to run the live enterprise smoke.');

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

  consoleErrors.length = 0;
  badResponses.length = 0;
  pageErrors.length = 0;

  const sidebar = page.locator('#sidebar-nav');

  await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible();
  await expect(page.getByText(/Process Analysis/i)).toBeVisible();

  await sidebar.getByRole('link', { name: 'Live Monitor', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Live Alert Stream' })).toBeVisible();
  await page.getByRole('tab', { name: 'Processes', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Running Processes' })).toBeVisible();
  await expect(page.getByText('Process Count')).toBeVisible();

  await sidebar.getByRole('link', { name: 'Threat Detection', exact: true }).click();
  await expect(page.getByText('Detection Engineering Workspace')).toBeVisible();
  await expect(page.getByText('Rule Queues')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Test Selected' })).toBeVisible();

  await sidebar.getByRole('link', { name: 'SOC Workbench', exact: true }).click();
  await expect(page.getByRole('button', { name: /Process tree/i })).toBeVisible();
  await page.getByRole('button', { name: /Process tree/i }).click();
  await expect(page.getByText(/Live Processes \(/)).toBeVisible();
  await expect(page.getByText('Deep Process Chains', { exact: true })).toBeVisible();

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});

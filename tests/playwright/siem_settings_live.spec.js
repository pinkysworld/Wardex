const { test, expect } = require('@playwright/test');

const BASE = process.env.WARDEX_BASE_URL || 'http://127.0.0.1:8080';
const TOKEN = process.env.WARDEX_ADMIN_TOKEN || '';

test('siem settings live workflow', async ({ page }) => {
  test.skip(!TOKEN, 'Set WARDEX_ADMIN_TOKEN to run the live SIEM smoke.');
  test.setTimeout(60000);

  const consoleErrors = [];
  const pageErrors = [];
  const badResponses = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => pageErrors.push(String(err)));
  page.on('response', (response) => {
    if (response.url().startsWith(`${BASE}/api/`) && response.status() >= 400) {
      badResponses.push(`${response.status()} ${response.url()}`);
    }
  });

  await page.goto(`${BASE}/admin/`, { waitUntil: 'domcontentloaded' });
  await expect(page).toHaveURL(/\/admin\/?$/);

  await page.getByPlaceholder('API token').fill(TOKEN);
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('.auth-badge')).toContainText(/Connected/i);

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
  await sidebar.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Integrations' }).click();
  await expect(page.getByText('SIEM Integration')).toBeVisible();

  const siemCard = page.locator('.card').filter({
    has: page.locator('.card-title', { hasText: 'SIEM Integration' }),
  });

  const siemSwitch = siemCard.getByRole('switch', { name: /Enable SIEM/ });
  if ((await siemSwitch.getAttribute('aria-checked')) !== 'true') {
    await siemSwitch.click();
  }

  await siemCard.getByRole('combobox', { name: 'SIEM Type' }).selectOption('splunk');
  await siemCard
    .getByRole('textbox', { name: 'SIEM Endpoint' })
    .fill('https://siem.example.test/hec-live');
  await siemCard.getByRole('textbox', { name: 'Auth Token' }).fill('live-siem-token');
  await siemCard.getByRole('textbox', { name: 'Index or Stream' }).fill('wardex-live');
  await siemCard.getByRole('textbox', { name: 'Source Type' }).fill('wardex:live');
  await siemCard.getByRole('spinbutton', { name: 'Poll Interval' }).fill('120');
  await siemCard.getByRole('spinbutton', { name: 'Batch Size' }).fill('25');

  const pullSwitch = siemCard.getByRole('switch', { name: /Enable Pull Queries/ });
  if ((await pullSwitch.getAttribute('aria-checked')) !== 'true') {
    await pullSwitch.click();
  }
  await siemCard
    .getByRole('textbox', { name: 'Pull Query' })
    .fill('search index=wardex-live sourcetype=wardex:live');

  await siemCard.getByRole('button', { name: 'Validate SIEM' }).click();
  await expect(page.getByText('SIEM configuration is valid and ready to save.')).toBeVisible();

  await siemCard.getByRole('button', { name: 'Save SIEM Setup' }).click();
  await expect(
    page.getByText(
      'A SIEM auth token or secret reference is already stored. Leave the token field blank to keep it.',
    ),
  ).toBeVisible();

  await page.screenshot({
    path: 'output/playwright/live-siem-settings.png',
    fullPage: true,
  });

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});
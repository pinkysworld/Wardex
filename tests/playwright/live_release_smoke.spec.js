const { test, expect } = require('@playwright/test');

const BASE = process.env.WARDEX_BASE_URL || 'http://127.0.0.1:8080';
const TOKEN = process.env.WARDEX_ADMIN_TOKEN || 'wardex-live-token';

test('wardex live admin smoke', async ({ page }) => {
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

  const proofResponse = await page.request.post(`${BASE}/api/support/first-run-proof`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  expect(proofResponse.ok()).toBeTruthy();
  const proof = await proofResponse.json();
  expect(proof.proof.status).toBe('completed');
  expect(proof.proof.response_status).toBe('DryRunCompleted');
  expect(proof.digest).toBeTruthy();

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

  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Live Monitor', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Live Monitor' })).toBeVisible();
  await expect(page.getByRole('tablist', { name: 'Monitor views' })).toBeVisible();
  await page.getByRole('tab', { name: 'Processes', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Running Processes' })).toBeVisible();
  await expect(page.getByText('Process Count')).toBeVisible();

  await page.screenshot({
    path: 'output/playwright/live-console-smoke.png',
    fullPage: true,
  });

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});

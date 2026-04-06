const { test, expect } = require('playwright/test');

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

  await page.goto(`${BASE}/admin.html`, { waitUntil: 'domcontentloaded' });
  await expect(page.locator('#alert-tbody')).not.toContainText(/cargo run -- serve/i);

  await page.locator('#auth-token').fill(TOKEN);
  await page.locator('#btn-connect').click();
  await expect(page.locator('#auth-status')).toHaveText(/Authenticated/i);

  await page.locator('#dash-sample-severity').selectOption('critical');
  await page.locator('#btn-send-sample-alert').click();
  await expect(page.locator('#dash-action-result')).toContainText(/sample .*alert injected/i);

  await page.locator('[data-section="live-monitor"]').click();
  await expect(page.locator('#sec-live-monitor')).toBeVisible();
  await page.locator('#btn-refresh-alerts').click();
  await expect(page.locator('#alert-tbody')).toContainText(
    /sample_alert|\[sample\]|credential brute force|suspicious process injection|cpu load spike/i
  );

  await page.screenshot({
    path: 'output/playwright/live-console-smoke.png',
    fullPage: true,
  });

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});

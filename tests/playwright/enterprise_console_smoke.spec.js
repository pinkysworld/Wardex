const { test, expect } = require('@playwright/test');

const BASE = process.env.WARDEX_BASE_URL || 'http://127.0.0.1:8095';
const TOKEN = process.env.WARDEX_ADMIN_TOKEN || '';
const INCIDENT_ID = process.env.WARDEX_SMOKE_INCIDENT_ID || '5';

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

  await page.goto(`${BASE}/admin.html`, { waitUntil: 'domcontentloaded' });
  await page.locator('#auth-token').fill(TOKEN);
  await page.locator('#btn-connect').click();
  await expect(page.locator('#auth-status')).toHaveText(/Authenticated/);
  await expect(page.locator('#sec-dashboard')).toBeVisible();
  await page.locator('#dash-sample-severity').selectOption('critical');
  await page.locator('#btn-send-sample-alert').click();
  await expect(page.locator('#dash-action-result')).toContainText(/Sample critical alert injected/i);

  await page.locator('[data-section="live-monitor"]').click();
  await expect(page.locator('#sec-live-monitor')).toBeVisible();
  await page.locator('#btn-refresh-alerts').click();
  await expect(page.locator('#alert-tbody')).toContainText(/sample alert|credential brute force|suspicious process injection|cpu load spike/i);

  await page.locator('[data-section="threat-detection"]').click();
  await expect(page.locator('#sec-threat-detection')).toBeVisible();
  await page.locator('#btn-refresh-detection-engineering').click();
  await expect(page.locator('#det-hunts-total')).not.toHaveText('0');
  const huntName = `UI Hunt ${Date.now()}`;
  await page.locator('#hunt-name').fill(huntName);
  await page.locator('#hunt-host').fill('enterprise-agent-1');
  await page.locator('#hunt-text').fill('test_reason');
  await page.locator('#btn-save-hunt').click();
  await expect(page.locator('#hunt-list')).toContainText(huntName);
  const ruleTestButton = page.locator('[data-rule-test]').first();
  await expect(ruleTestButton).toBeVisible();
  await ruleTestButton.click();

  await page.locator('[data-section="fleet-agents"]').click();
  await expect(page.locator('#sec-fleet-agents')).toBeVisible();
  await page.locator('[data-tab="fleet-agents"]').click();
  await expect(page.locator('#xdr-agent-table')).toContainText('enterprise-agent-1');

  await page.locator('[data-section="security-policy"]').click();
  await expect(page.locator('#sec-security-policy')).toBeVisible();

  await page.locator('[data-section="incident-response"]').click();
  await expect(page.locator('#sec-incident-response')).toBeVisible();
  await page.locator('[data-tab="ir-investigation"]').click();
  await page.locator('#entity-kind').selectOption('host');
  await page.locator('#entity-id').fill('enterprise-agent-1');
  await page.locator('#btn-load-entity').click();
  await expect(page.locator('#entity-profile-summary')).toContainText('enterprise-agent-1');
  await page.locator('#timeline-incident-id').fill(INCIDENT_ID);
  await page.locator('#ticket-summary').fill('Enterprise smoke ticket sync');
  await page.locator('#btn-load-storyline').click();
  await expect(page.locator('#storyline-summary')).toContainText(/Evidence Package|Narrative/);
  await page.locator('#btn-sync-ticket').click();

  await page.locator('[data-tab="ir-response"]').click();
  await expect(page.locator('#resp-tbody')).toContainText(/Kill process|credential-theft.bin/i);

  await page.locator('[data-section="infrastructure"]').click();
  await expect(page.locator('#sec-infrastructure')).toBeVisible();

  await page.locator('[data-section="reports-exports"]').click();
  await expect(page.locator('#sec-reports-exports')).toBeVisible();
  await page.locator('#btn-refresh-manager-summary').click();
  await expect(page.locator('#mgr-report-coverage')).not.toHaveText('0%');

  await page.locator('[data-section="settings"]').click();
  await expect(page.locator('#sec-settings')).toBeVisible();
  await page.locator('#btn-refresh-enterprise-admin').click();
  await expect(page.locator('#idp-provider-list')).toContainText('Okta Workforce');
  const connectorName = `Whois ${Date.now()}`;
  await page.locator('#connector-kind').fill('whois');
  await page.locator('#connector-name').fill(connectorName);
  await page.locator('#connector-endpoint').fill('https://whois.example.test');
  await page.locator('#btn-save-connector').click();
  await expect(page.locator('#connector-list')).toContainText(connectorName);

  await page.locator('[data-section="help-docs"]').click();
  await expect(page.locator('#sec-help-docs')).toBeVisible();
  await expect(page.locator('#api-endpoint-list')).toContainText('/api/hunts');

  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('#sidebar-toggle').click();
  await page.locator('[data-section="threat-detection"]').click();
  await expect(page.locator('#btn-save-hunt')).toBeVisible();

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});

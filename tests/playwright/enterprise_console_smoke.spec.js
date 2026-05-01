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

  await sidebar.getByRole('link', { name: 'Command Center', exact: true }).click();
  await expect(page.getByRole('heading', { name: /Operate incidents/i })).toBeVisible();
  await expect(page.getByText('Connector Onboarding Wizard')).toBeVisible();
  await expect(page.getByText('Release and Upgrade Center')).toBeVisible();

  await page.getByRole('button', { name: 'Validate connectors' }).click();
  const connectorDrawer = page.getByRole('dialog', { name: 'Connector Validation' });
  await expect(connectorDrawer).toBeVisible();
  await connectorDrawer.getByRole('link', { name: 'Open settings' }).click();
  await expect(page).toHaveURL(/\/admin\/settings/);
  await expect(page.getByRole('tablist', { name: 'Settings sections' })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Command Center', exact: true }).click();
  await page.getByRole('button', { name: 'Review changes' }).click();
  const remediationDrawer = page.getByRole('dialog', { name: 'Remediation Approval' });
  await expect(remediationDrawer).toBeVisible();
  await remediationDrawer.getByRole('link', { name: 'Open infrastructure' }).click();
  await expect(page).toHaveURL(/\/admin\/infrastructure/);
  await expect(page.getByRole('tablist', { name: 'Infrastructure sections' })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Command Center', exact: true }).click();
  await page.getByRole('button', { name: 'Check readiness' }).click();
  const releaseDrawer = page.getByRole('dialog', { name: 'Release Readiness' });
  await expect(releaseDrawer).toBeVisible();
  await releaseDrawer.getByRole('link', { name: 'Open rollouts' }).click();
  await expect(page).toHaveURL(/\/admin\/infrastructure/);
  await expect(page.getByRole('tablist', { name: 'Infrastructure sections' })).toBeVisible();

  await sidebar.getByRole('link', { name: 'Command Center', exact: true }).click();
  await page.getByRole('button', { name: 'Create evidence pack' }).click();
  const evidenceDrawer = page.getByRole('dialog', { name: 'Compliance Evidence Pack' });
  await expect(evidenceDrawer).toBeVisible();
  await evidenceDrawer.getByRole('link', { name: 'Open reports' }).click();
  await expect(page).toHaveURL(/\/admin\/reports/);
  await expect(page.getByRole('tablist', { name: 'Reports & exports sections' })).toBeVisible();

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
  await expect(page.getByText('Workbench Overview')).toBeVisible();
  const processTreeLink = page.getByRole('link', { name: 'Open Process Tree' });
  await expect(processTreeLink).toBeVisible();
  await processTreeLink.click();
  await expect(page).toHaveURL(/\/admin\/soc.*#process-tree$/);
  await expect(page.getByText(/Live Processes \(/)).toBeVisible();
  await expect(page.getByText('Deep Process Chains', { exact: true })).toBeVisible();

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});

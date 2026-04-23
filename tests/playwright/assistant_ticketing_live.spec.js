const { test, expect } = require('@playwright/test');

const BASE = process.env.WARDEX_BASE_URL || 'http://127.0.0.1:8080';
const TOKEN = process.env.WARDEX_ADMIN_TOKEN || 'wardex-live-token';
const RUN_ID = Date.now().toString(36);
const CASE_TITLE = `Live Playwright identity case ${RUN_ID}`;

test.beforeAll(async ({ request }) => {
  const headers = { Authorization: `Bearer ${TOKEN}` };

  await request.post(`${BASE}/api/idp/providers`, {
    headers,
    data: {
      id: 'playwright-sso',
      kind: 'oidc',
      display_name: 'Corporate SSO',
      issuer_url: 'https://issuer.example.com',
      client_id: 'wardex-admin',
      client_secret: 'playwright-secret',
      redirect_uri: `${BASE}/api/auth/sso/callback`,
      enabled: true,
      group_role_mappings: { Security: 'admin' },
    },
  });

  await request.post(`${BASE}/api/cases`, {
    headers,
    data: {
      title: CASE_TITLE,
      description: 'Case created for assistant and ticket sync live validation.',
      priority: 'high',
    },
  });
});

test('assistant and ticket sync live workflow', async ({ page }) => {
  test.setTimeout(60000);

  const consoleErrors = [];
  const pageErrors = [];
  const badResponses = [];

  page.on('console', (msg) => {
    if (
      msg.type() === 'error' &&
      !msg.text().includes('Failed to load resource: the server responded with a status of 401 (Unauthorized)')
    ) {
      consoleErrors.push(msg.text());
    }
  });
  page.on('pageerror', (err) => pageErrors.push(String(err)));
  page.on('response', (response) => {
    if (response.url().startsWith(`${BASE}/api/`) && response.status() >= 400) {
      const pathname = new URL(response.url()).pathname;
      if (
        response.status() === 401 &&
        (pathname === '/api/auth/check' || pathname === '/api/auth/session')
      ) {
        return;
      }
      badResponses.push(`${response.status()} ${response.url()}`);
    }
  });

  await page.goto(`${BASE}/admin/`, { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('button', { name: 'Sign in with Corporate SSO' }).first()).toBeVisible();

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

  await page.locator('#sidebar-nav').getByRole('link', { name: 'Analyst Assistant' }).click();
  await expect(page.getByRole('heading', { name: 'Analyst Assistant' })).toBeVisible();

  const caseSelect = page.locator('#assistant-case-select');
  const findCaseValue = async () => {
    const options = await caseSelect.locator('option').evaluateAll((nodes) =>
      nodes.map((node) => ({ value: node.value, text: node.textContent || '' })),
    );
    return options.find((option) => option.text.includes(CASE_TITLE))?.value || '';
  };
  await expect.poll(findCaseValue).not.toBe('');
  const selectedCaseValue = await findCaseValue();
  await caseSelect.selectOption(selectedCaseValue);
  await page.getByLabel('Question').fill('Summarize this case and cite the strongest evidence.');
  await page.getByRole('button', { name: 'Ask Assistant' }).click();
  const caseContextCard = page.locator('.card').filter({
    has: page.getByRole('link', { name: 'Open Case in SOC' }),
  });
  await expect(page.getByRole('link', { name: 'Open Case in SOC' })).toBeVisible();
  await expect(caseContextCard.getByText(CASE_TITLE)).toBeVisible();

  await page.locator('#sidebar-nav').getByRole('link', { name: 'SOC Workbench' }).click();
  await page.getByRole('button', { name: 'Cases' }).click();
  await expect(page.getByText('Ticket Sync')).toBeVisible();
  await page.getByLabel('Project or queue').fill('SECOPS');
  await page.getByLabel('Sync summary').fill('Live Playwright ticket sync validation');
  await page.getByRole('button', { name: 'Sync Case' }).click();
  await expect(page.getByText('Last ticket sync')).toBeVisible();

  expect(pageErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(badResponses).toEqual([]);
});
import { test, expect } from '@playwright/test';
import {
  installAppMocks,
  loginThroughForm,
  seedAuthenticatedSession,
  TOKEN,
  VERSION,
} from './support/mockApi.js';

test.describe('Admin console smoke', () => {
  test('authenticates through the welcome form and can disconnect again', async ({ page }) => {
    await installAppMocks(page);
    await page.goto('./');
    await page.evaluate(() => {
      localStorage.removeItem('wardex_token');
      localStorage.setItem('wardex_onboarded', '1');
    });
    await page.reload({ waitUntil: 'load' });

    await expect(page.getByText('Welcome to Wardex Admin Console')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Connect' })).toBeDisabled();

    await page.getByLabel('API token').fill(TOKEN);
    await page.getByRole('button', { name: 'Connect' }).click();

    await expect(page.locator('.auth-badge')).toContainText('Connected');
    await expect(page.locator('.role-badge')).toContainText('admin');
    await expect(page.locator('.version-badge')).toHaveText(`v${VERSION}`);

    await page.getByRole('button', { name: 'Disconnect' }).click();
    await expect(page.getByText('Welcome to Wardex Admin Console')).toBeVisible();
  });

  test('navigates core admin workspaces without page crashes', async ({ page }) => {
    await installAppMocks(page);
    await seedAuthenticatedSession(page);

    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));

    const routes = [
      {
        title: 'Dashboard',
        navTitle: 'Dashboard',
        marker: () => page.getByText('Security Overview'),
      },
      {
        title: 'Live Monitor',
        navTitle: 'Live Monitor',
        marker: () => page.locator('button.tab').filter({ hasText: 'Alert Stream' }),
      },
      {
        title: 'Operator Launchpad',
        navTitle: 'Operator Launchpad',
        marker: () => page.locator('#deployment-confidence').getByText('Ship readiness matrix'),
      },
      {
        title: 'Threat Detection',
        navTitle: 'Threat Detection',
        marker: () => page.getByText('Detection Engineering Workspace'),
      },
      {
        title: 'Reports & Exports',
        navTitle: 'Reports & Exports',
        marker: () => page.getByText('Report Center'),
      },
      {
        title: 'Settings',
        navTitle: 'Settings',
        marker: () => page.locator('button.tab').filter({ hasText: 'Config' }),
      },
      {
        title: 'Help & Docs',
        navTitle: 'Help & Docs',
        marker: () => page.getByText('Suggested Workflow'),
      },
    ];

    for (const route of routes) {
      await page.getByTitle(route.navTitle).click();
      await expect(page.locator('.topbar-title')).toHaveText(route.title);
      await expect(route.marker()).toBeVisible({ timeout: 15000 });
    }

    expect(pageErrors).toEqual([]);
  });

  test('supports search, contextual help, theme toggle, pinning, shortcuts, and share link', async ({
    page,
  }) => {
    await installAppMocks(page);
    await loginThroughForm(page);
    await page.evaluate(() => {
      Object.defineProperty(window.navigator, 'clipboard', {
        configurable: true,
        value: {
          writeText: async () => {},
        },
      });
    });

    const pinButton = page.locator('.topbar-right').getByRole('button', { name: 'Pin Dashboard' });
    await pinButton.click();
    await expect(
      page.locator('.topbar-right').getByRole('button', { name: 'Unpin Dashboard' }),
    ).toHaveText('Pinned');

    await page.getByRole('button', { name: 'Search' }).click();
    const searchInput = page.getByRole('combobox', { name: 'Global search' });
    await expect(searchInput).toBeVisible();
    await expect(page.getByRole('button', { name: /Connect First Agent/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Deployment Confidence/i })).toBeVisible();
    await searchInput.fill('ssh');
    await expect(page.getByText('SSH burst detection')).toBeVisible({ timeout: 10000 });
    await page.getByText('SSH burst detection').click();
    await expect(page.locator('.topbar-title')).toHaveText('Threat Detection');
    // Wait for the lazy-loaded Threat Detection route to fully commit before
    // navigating again. Clicking "Help For View" while the /detection chunk is
    // still suspended lets the late-resolving route mount and re-navigate via
    // its mount effect, overriding the /help navigation (a CI-only race).
    await expect(page).toHaveURL(/\/detection/);
    await expect(page.getByText('Detection Engineering Workspace')).toBeVisible({ timeout: 15000 });

    await page.getByRole('button', { name: 'Help For View' }).click();
    await expect(page).toHaveURL(/\/help/);
    await expect(page.locator('.topbar-title')).toHaveText('Help & Docs');
    await expect(page.getByText('Detection Support')).toBeVisible();

    await page.keyboard.press('?');
    await expect(page.getByText('Keyboard Shortcuts')).toBeVisible();
    await page.getByRole('button', { name: '✕' }).click();
    await expect(page.getByText('Keyboard Shortcuts')).toHaveCount(0);

    await page.getByRole('button', { name: 'Share Link' }).click();
    await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible();

    const initialTheme = await page.locator('html').getAttribute('data-theme');
    await page.locator('button[title="Light mode"], button[title="Dark mode"]').click();
    await expect(page.locator('html')).not.toHaveAttribute('data-theme', initialTheme || 'light');
  });

  test('opens the global search palette via the ⌘K / Ctrl+K keyboard shortcut', async ({
    page,
    browserName,
  }) => {
    await installAppMocks(page);
    await loginThroughForm(page);
    // Drop focus off any topbar control so the global keydown handler runs.
    await page.evaluate(() => {
      if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    });
    const modifier = browserName === 'webkit' ? 'Meta' : 'Control';
    await page.keyboard.press(`${modifier}+k`);
    await expect(page.getByRole('combobox', { name: 'Global search' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('combobox', { name: 'Global search' })).toHaveCount(0);
  });

  test('dashboard refresh re-fetches grouped overview and signal endpoints', async ({ page }) => {
    const trackedKeys = [
      'GET /api/status',
      'GET /api/fleet/dashboard',
      'GET /api/alerts',
      'GET /api/telemetry/current',
      'GET /api/health',
      'GET /api/detection/summary',
      'GET /api/threat-intel/status',
      'GET /api/queue/stats',
      'GET /api/response/stats',
      'GET /api/processes/analysis',
      'GET /api/malware/stats',
      'GET /api/coverage/gaps',
      'GET /api/quarantine/stats',
      'GET /api/lifecycle/stats',
      'GET /api/feeds/stats',
      'GET /api/manager/queue-digest',
      'GET /api/dns-threat/summary',
    ];
    const counts = Object.fromEntries(trackedKeys.map((key) => [key, 0]));

    await installAppMocks(page, {
      onRequest: async ({ key }) => {
        if (Object.prototype.hasOwnProperty.call(counts, key)) {
          counts[key] += 1;
        }
        return false;
      },
    });
    await seedAuthenticatedSession(page);

    await expect(page.getByText('Security Overview')).toBeVisible();
    await expect.poll(() => trackedKeys.every((key) => counts[key] > 0)).toBe(true);

    const initialCounts = { ...counts };

    await page.getByRole('button', { name: '↻ Refresh' }).click();

    await expect
      .poll(() => trackedKeys.every((key) => counts[key] === initialCounts[key] + 1))
      .toBe(true);
  });
});

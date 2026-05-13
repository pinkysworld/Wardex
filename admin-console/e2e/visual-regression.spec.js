import { test, expect } from '@playwright/test';
import { installAppMocks, seedAuthenticatedSession } from './support/mockApi.js';

test.describe('Visual regression gate', () => {
  test('captures the Launchpad continuity board screenshot artifact', async ({
    page,
  }, testInfo) => {
    await installAppMocks(page);
    await seedAuthenticatedSession(page);

    await page.goto('./');
    await page.getByTitle('Operator Launchpad').click();

    await expect(page.locator('#visual-regression-gate')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#shift-handoff-workspace')).toContainText('Handoff workspace');
    await expect(page.locator('#incident-timeline-builder')).toContainText('Timeline builder');
    await expect(page.locator('#safe-assistant')).toContainText('Safe assistant boundaries');

    const screenshot = await page.locator('.operator-launchpad').screenshot();
    expect(screenshot.byteLength).toBeGreaterThan(10000);
    await testInfo.attach('launchpad-visual-regression-gate', {
      body: screenshot,
      contentType: 'image/png',
    });
  });
});

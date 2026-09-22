import { test } from '@playwright/test';
import { installAppMocks, seedAuthenticatedSession } from './support/mockApi.js';

const OUT = process.env.SHOT_DIR || '/tmp/console-shots';
const PREFIX = process.env.SHOT_PREFIX || 'before';

const views = [
  { name: 'dashboard', path: '/' },
  { name: 'live-monitor', path: '/monitor' },
  { name: 'fleet', path: '/fleet' },
  { name: 'detection', path: '/detection' },
  { name: 'soc', path: '/soc' },
  { name: 'settings', path: '/settings' },
];

const sizes = [
  { name: '1440', width: 1440, height: 900 },
  { name: '390', width: 390, height: 844 },
];

const themes = ['light', 'dark'];

for (const size of sizes) {
  for (const theme of themes) {
    test(`shots ${size.name} ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width: size.width, height: size.height });
      await installAppMocks(page);
      await seedAuthenticatedSession(page);
      await page.addInitScript((t) => {
        try {
          localStorage.setItem('wardex_theme', t);
        } catch {
          /* ignore */
        }
      }, theme);
      for (const view of views) {
        await page.goto(`.${view.path}`);
        await page.waitForTimeout(900);
        await page.screenshot({
          path: `${OUT}/${view.name}-${PREFIX}-${size.name}-${theme}.png`,
          fullPage: false,
        });
      }
    });
  }
}

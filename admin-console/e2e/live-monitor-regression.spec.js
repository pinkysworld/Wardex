import { test, expect } from '@playwright/test';
import { installAppMocks, loginThroughForm } from './support/mockApi.js';

function buildProcesses(count = 80) {
  return Array.from({ length: count }, (_, index) => ({
    pid: 400 + index,
    ppid: index === 0 ? 399 : 399 + index,
    name: index === 0 ? '/bin/bash' : `/usr/bin/process-${index}`,
    user: 'playwright',
    group: 'staff',
    cpu_percent: Math.max(0.2, 40 - index * 0.4),
    mem_percent: Math.max(0.1, 12 - index * 0.08),
    reason: index === 0 ? 'Suspicious parent chain' : undefined,
  }));
}

test('preserves process context and falls back when live monitor detail and analysis fail over', async ({
  page,
}) => {
  const processes = buildProcesses();
  let postAnalysisAttempts = 0;
  let getAnalysisAttempts = 0;

  await installAppMocks(page, {
    responses: {
      'GET /api/processes/live': {
        count: processes.length,
        total_cpu_percent: 96.4,
        total_mem_percent: 31.2,
        processes,
      },
      'GET /api/processes/analysis': {
        total: 1,
        findings: [
          {
            pid: 400,
            name: 'bash',
            user: 'playwright',
            group: 'staff',
            cpu_percent: 39.6,
            mem_percent: 11.9,
            risk_level: 'severe',
            reason: 'Suspicious parent chain',
          },
        ],
      },
      'GET /api/process-tree': {
        processes: [
          { pid: 1, ppid: 0, name: 'launchd', user: 'root' },
          { pid: 399, ppid: 1, name: 'login', user: 'playwright' },
          { pid: 400, ppid: 399, name: 'bash', user: 'playwright' },
          { pid: 401, ppid: 400, name: 'python3', user: 'playwright' },
        ],
      },
      'GET /api/process-tree/deep-chains': {
        deep_chains: [
          {
            pid: 400,
            name: 'bash',
            cmd_line: 'bash -> python3',
            depth: 2,
            summary: 'bash · bash -> python3',
          },
        ],
      },
    },
    onRequest: async ({ key, route, json }) => {
      if (key === 'GET /api/processes/detail') {
        await route.fulfill(json({ error: 'live inspection unavailable' }, 500));
        return true;
      }

      if (key === 'GET /api/processes/threads') {
        await route.fulfill(json({ threads: [] }));
        return true;
      }

      if (key === 'POST /api/alerts/analysis') {
        postAnalysisAttempts += 1;
        await route.fulfill(json({ error: 'analysis pipeline unavailable' }, 500));
        return true;
      }

      if (key === 'GET /api/alerts/analysis') {
        getAnalysisAttempts += 1;
        await route.fulfill(
          json({
            summary: 'Queue pressure is concentrated around repeated SSH failures.',
            total_alerts: 3,
            score_trend: 'Stable',
            dominant_reasons: [['Repeated SSH failures', 3]],
            isolation_guidance: [
              {
                reason: 'Repeated SSH failures',
                threat_description: 'Investigate the source host before isolating it.',
                steps: ['Inspect the originating host.'],
              },
            ],
          }),
        );
        return true;
      }

      return false;
    },
  });

  await page.setViewportSize({ width: 1280, height: 600 });
  await loginThroughForm(page);
  await page.goto('./monitor?monitorTab=processes');

  await expect(page.locator('.topbar-title')).toHaveText('Live Monitor');
  await expect(page.getByText('All Processes')).toBeVisible();

  const runningCard = page.locator('.card').filter({ has: page.getByText('Running Processes') });
  const allProcessesCard = page.locator('.card').filter({ has: page.getByText('All Processes') });
  const processTable = allProcessesCard.locator('.table-wrap').first();

  await page.evaluate(() => window.scrollTo(0, 420));
  await processTable.evaluate((element) => {
    element.scrollTop = 215;
  });

  const beforeWindowScroll = await page.evaluate(() => window.scrollY);
  const beforeTableScroll = await processTable.evaluate((element) => element.scrollTop);

  await runningCard.getByRole('button', { name: '↻ Refresh' }).click();

  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(beforeWindowScroll);
  await expect.poll(() => processTable.evaluate((element) => element.scrollTop)).toBe(
    beforeTableScroll,
  );

  await allProcessesCard.getByRole('button', { name: 'Investigate' }).first().click();

  await expect(
    page.getByText('Live inspection is temporarily unavailable. Showing the last known snapshot from the process table while Wardex retries this PID.'),
  ).toBeVisible();
  await expect(page.getByText('Investigation Context')).toBeVisible();

  const beforeDrawerRefreshWindowScroll = await page.evaluate(() => window.scrollY);

  await runningCard.getByRole('button', { name: '↻ Refresh' }).click({ force: true });

  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(beforeDrawerRefreshWindowScroll);

  await page.getByRole('button', { name: 'Close' }).click();

  await page.getByRole('tab', { name: 'Analysis' }).click();
  await page.getByRole('button', { name: 'Run Analysis' }).click();

  await expect(
    page.getByText('Queue pressure is concentrated around repeated SSH failures.').first(),
  ).toBeVisible();
  await expect(page.getByText('Analysis complete')).toBeVisible();
  expect(postAnalysisAttempts).toBe(1);
  expect(getAnalysisAttempts).toBe(1);
});
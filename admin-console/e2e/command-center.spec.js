import { test, expect } from '@playwright/test';
import { installAppMocks, TOKEN } from './support/mockApi.js';

async function openAuthenticatedCommandCenter(page, path = './command') {
  await page.goto(path);
  await page.evaluate((token) => {
    localStorage.setItem('wardex_token', token);
    localStorage.setItem('wardex_onboarded', '1');
  }, TOKEN);
  await page.reload({ waitUntil: 'load' });
}

test.describe('Command Center smoke', () => {
  test('opens command center action drawers and keeps lane data visible', async ({ page }) => {
    await installAppMocks(page);
    await openAuthenticatedCommandCenter(page);

    await expect(page.getByRole('heading', { name: /Operate incidents/i })).toBeVisible();
    await expect(page.getByText('Credential storm on gateway').first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'GitHub Audit Log' })).toBeVisible();

    await page.getByRole('button', { name: /Connector gaps/i }).click();
    await expect(page.getByRole('dialog', { name: 'Connector Validation' })).toBeVisible();
    await page.getByRole('button', { name: 'Validate now' }).click();
    await expect(page.getByText(/Validation complete|Validation failed/)).toBeVisible();
    await page.getByRole('button', { name: 'Close' }).click();

    await page.getByRole('button', { name: /Pending approvals/i }).click();
    const remediationDrawer = page.getByRole('dialog', { name: 'Remediation Approval' });
    await expect(remediationDrawer).toBeVisible();
    await expect(remediationDrawer.getByLabel('Change review')).toHaveValue(
      'review-credential-storm-1',
    );
    await page.getByRole('button', { name: 'Close' }).click();

    await page.getByRole('button', { name: /Noisy rules/i }).click();
    const replayDrawer = page.getByRole('dialog', { name: 'Rule Replay and Promotion' });
    await expect(replayDrawer).toBeVisible();
    await expect(replayDrawer.getByLabel('Rule')).toHaveValue('rule-ssh-burst');
    await page.getByRole('button', { name: 'Close' }).click();

    await page.getByRole('button', { name: /Compliance packs/i }).click();
    const evidenceDrawer = page.getByRole('dialog', { name: 'Compliance Evidence Pack' });
    await expect(evidenceDrawer).toBeVisible();
    await evidenceDrawer.getByRole('button', { name: 'Create evidence pack' }).click();
    await expect(page.getByText(/Evidence pack queued|Evidence export failed/)).toBeVisible();
  });

  test('supports the mobile command layout without overlapping primary controls', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await installAppMocks(page);
    await openAuthenticatedCommandCenter(page);

    await expect(page.getByRole('heading', { name: /Operate incidents/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Refresh Center/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Connector gaps/i })).toBeVisible();
  });

  test('honors routed drawer deep links and refreshes command lanes', async ({ page }) => {
    let summaryRequests = 0;
    let incidentsRequests = 0;
    let reviewRequests = 0;

    await installAppMocks(page, {
      onRequest: async ({ key }) => {
        if (key === 'GET /api/command/summary') summaryRequests += 1;
        if (key === 'GET /api/incidents') incidentsRequests += 1;
        if (key === 'GET /api/remediation/change-reviews') reviewRequests += 1;
        return false;
      },
    });

    await openAuthenticatedCommandCenter(page, './command?drawer=connectors');

    await expect(page.getByRole('dialog', { name: 'Connector Validation' })).toBeVisible();
    await expect(page).toHaveURL(/drawer=connectors/);

    const initialSummaryRequests = summaryRequests;
    const initialIncidentsRequests = incidentsRequests;
    const initialReviewRequests = reviewRequests;

    await page.getByRole('button', { name: 'Close' }).click();
    await expect(page).not.toHaveURL(/drawer=connectors/);

    await page.getByRole('button', { name: /Refresh Center/i }).click();

    await expect.poll(() => summaryRequests).toBeGreaterThan(initialSummaryRequests);
    await expect.poll(() => incidentsRequests).toBeGreaterThan(initialIncidentsRequests);
    await expect.poll(() => reviewRequests).toBeGreaterThan(initialReviewRequests);
  });

  test('supports remediation and release handoffs from command drawers', async ({ page }) => {
    await installAppMocks(page, {
      responses: {
        'GET /api/updates/releases': [
          {
            version: '0.55.2',
            status: 'candidate',
            created_at: '2026-04-20T06:25:00.000Z',
            notes: 'Canary rollout is ready for analyst review.',
          },
        ],
      },
    });

    await openAuthenticatedCommandCenter(page);

    await page.getByRole('button', { name: /Pending approvals/i }).click();
    const remediationDrawer = page.getByRole('dialog', { name: 'Remediation Approval' });
    await expect(remediationDrawer).toBeVisible();
    await remediationDrawer.getByRole('button', { name: 'Approve' }).click();
    await expect(page.getByText(/Approval recorded|Review update failed/)).toBeVisible();
    await remediationDrawer.getByRole('link', { name: 'Open infrastructure' }).click();
    await expect(page).toHaveURL(/\/infrastructure/);

    await openAuthenticatedCommandCenter(page, './command?drawer=release');

    const releaseDrawer = page.getByRole('dialog', { name: 'Release Readiness' });
    await expect(releaseDrawer).toBeVisible();
    await expect(releaseDrawer.getByText('0.55.2').first()).toBeVisible();
    await releaseDrawer.getByRole('link', { name: 'Open rollouts' }).click();
    await expect(page).toHaveURL(/\/infrastructure/);
  });
});

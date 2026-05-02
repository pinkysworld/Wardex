import { test, expect } from '@playwright/test';
import { installAppMocks, TOKEN } from './support/mockApi.js';

async function openAuthenticatedRoute(page, path) {
  await page.goto(path);
  await page.evaluate((token) => {
    localStorage.setItem('wardex_token', token);
    localStorage.setItem('wardex_onboarded', '1');
  }, TOKEN);
  await page.reload({ waitUntil: 'load' });
}

function collectorLaneCard(page, title) {
  return page
    .getByText(title, { exact: true })
    .locator('xpath=ancestor::*[contains(concat(" ", normalize-space(@class), " "), " card ")][1]');
}

function createReviewState() {
  return {
    id: 'review-routed-e2e-1',
    title: 'Quarantine gateway session token',
    asset_id: 'playwright-host.local',
    change_type: 'malware_containment',
    source: 'agent',
    summary: 'Review the proposed containment and rollback evidence.',
    risk: 'high',
    approval_status: 'pending_review',
    recovery_status: 'not_started',
    required_approvers: 1,
    approvals: [],
    approval_chain_digest: null,
    rollback_proof: null,
    requested_at: '2026-04-20T06:27:45.809Z',
    evidence: {
      path: '/tmp/session-token.cache',
      rollback_source: '/var/quarantine/session-token.cache',
    },
  };
}

function reviewPayload(review) {
  const approvals = Array.isArray(review.approvals) ? review.approvals : [];
  return {
    summary: {
      pending: review.approval_status === 'pending_review' ? 1 : 0,
      recovery_ready: review.rollback_proof ? 1 : 0,
      signed: approvals.filter((entry) => entry.decision === 'approve').length,
      rollback_proofs: review.rollback_proof ? 1 : 0,
    },
    reviews: [review],
  };
}

test.describe('Routed workflow coverage', () => {
  test('executes approval and rollback actions from the infrastructure route', async ({ page }) => {
    const approvalBodies = [];
    const rollbackBodies = [];
    let review = createReviewState();

    await installAppMocks(page, {
      onRequest: async ({ route, request, key, json }) => {
        if (key === 'GET /api/remediation/change-reviews') {
          await route.fulfill(json(reviewPayload(review)));
          return true;
        }

        if (key === `POST /api/remediation/change-reviews/${review.id}/approval`) {
          approvalBodies.push(request.postDataJSON());
          review = {
            ...review,
            approval_status: 'approved',
            approvals: [
              {
                approver: 'playwright',
                decision: 'approve',
                signed_at: '2026-04-20T06:30:00.000Z',
                signature: 'signature-playwright',
              },
            ],
            approval_chain_digest: 'digest-playwright-1234',
            rollback_proof: {
              proof_id: 'rollback-proof-playwright',
              status: 'ready',
              recovery_plan: [
                'Retain quarantine artifact hash and restore from clean backup if validation fails',
              ],
            },
          };
          await route.fulfill(json({ status: 'approved', review }));
          return true;
        }

        if (key === `POST /api/remediation/change-reviews/${review.id}/rollback`) {
          const body = request.postDataJSON();
          rollbackBodies.push(body);
          if (body?.dry_run) {
            review = {
              ...review,
              recovery_status: 'verified',
              rollback_proof: {
                ...review.rollback_proof,
                status: 'dry_run_verified',
                execution_result: {
                  dry_run: true,
                  platform: 'Linux',
                  live_execution: 'dry_run',
                },
              },
            };
          } else {
            review = {
              ...review,
              recovery_status: 'executed',
              rollback_proof: {
                ...review.rollback_proof,
                status: 'executed',
                execution_result: {
                  dry_run: false,
                  platform: 'Linux',
                  live_execution: 'executed',
                  command_executions: [{ program: 'cp', executed: true, exit_code: 0 }],
                },
              },
            };
          }
          await route.fulfill(json({ status: 'rollback_recorded', review }));
          return true;
        }

        return false;
      },
    });

    await openAuthenticatedRoute(page, './infrastructure');

    const reviewCard = page.locator('.stat-box').filter({ hasText: review.title }).first();

    await expect(page.getByText('Change Review & Recovery')).toBeVisible();
    await expect(reviewCard).toContainText('pending_review');

    await reviewCard.getByRole('button', { name: 'Sign Approval' }).click();
    await expect(page.getByText(/Signed approval recorded/)).toBeVisible();
    await expect(reviewCard).toContainText('approved');
    await expect(approvalBodies).toHaveLength(1);
    expect(approvalBodies[0]).toMatchObject({ decision: 'approve' });

    await reviewCard.getByRole('button', { name: 'Verify Rollback' }).click();
    await expect(page.getByText(/Rollback proof verified/)).toBeVisible();
    await expect(reviewCard).toContainText('verified');
    await expect(rollbackBodies).toHaveLength(1);
    expect(rollbackBodies[0]).toMatchObject({ dry_run: true, platform: 'linux' });

    page.once('dialog', async (dialog) => {
      await dialog.accept('playwright-host.local');
    });
    await reviewCard.getByRole('button', { name: /Live Rollback/i }).click();

    await expect(page.getByText(/Live rollback executed/)).toBeVisible();
    await expect(reviewCard).toContainText('executed');
    await expect(rollbackBodies).toHaveLength(2);
    expect(rollbackBodies[1]).toMatchObject({
      dry_run: false,
      platform: 'linux',
      confirm_hostname: 'playwright-host.local',
    });
  });

  test('supports collector pivots and SSO validation from settings integrations', async ({ page }) => {
    await installAppMocks(page, {
      responses: {
        'GET /api/collectors/status': {
          collectors: [
            {
              provider: 'aws_cloudtrail',
              label: 'AWS CloudTrail',
              enabled: true,
              freshness: 'stale',
              events_ingested: 24,
              checkpoint_id: 'aws-checkpoint-123456',
              retry_count: 2,
              backoff_seconds: 60,
              last_success_at: '2026-04-20T06:20:00.000Z',
              last_error_at: '2026-04-20T06:24:00.000Z',
              validation: { status: 'ready', issues: [] },
              lifecycle_analytics: {
                total_runs: 4,
                success_rate: 0.75,
                events_last_24h: 120,
                recent_failure_streak: 2,
              },
              timeline: [
                {
                  stage: 'Scope',
                  status: 'ready',
                  title: 'Collection scope',
                  detail: 'CloudTrail management events are routed into infrastructure review.',
                },
              ],
              ingestion_evidence: {
                pivots: [
                  {
                    surface: 'SOC Workbench',
                    href: '/soc?collector=aws_cloudtrail&lane=cloud',
                  },
                  {
                    surface: 'Infrastructure',
                    href: '/infrastructure?tab=observability&collector=aws_cloudtrail',
                  },
                ],
                recent_runs: [
                  {
                    recorded_at: '2026-04-20T06:24:00.000Z',
                    success: false,
                    error_category: 'credentials',
                    event_count: 0,
                  },
                ],
              },
            },
            {
              provider: 'okta_identity',
              label: 'Okta Identity',
              enabled: true,
              total_collected: 3,
              validation: { status: 'ready', issues: [] },
              timeline: [
                {
                  stage: 'Routing',
                  status: 'ready',
                  title: 'Downstream pivots',
                  detail: 'User session start telemetry is routed into UEBA and SOC triage workflows.',
                },
              ],
            },
            {
              provider: 'github_audit',
              label: 'GitHub Audit Log',
              enabled: true,
              total_collected: 8,
              validation: { status: 'ready', issues: [] },
              timeline: [
                {
                  stage: 'Routing',
                  status: 'ready',
                  title: 'Downstream pivots',
                  detail: 'GitHub audit activity is ready for assistant and report pivots.',
                },
              ],
            },
            {
              provider: 'generic_syslog',
              label: 'Generic Syslog',
              enabled: true,
              freshness: 'fresh',
              events_ingested: 12,
              validation: { status: 'ready', issues: [] },
              timeline: [
                {
                  stage: 'Routing',
                  status: 'ready',
                  title: 'Downstream pivots',
                  detail: 'Syslog activity is routed into observability and triage workflows.',
                },
              ],
              ingestion_evidence: {
                pivots: [
                  {
                    surface: 'Infrastructure',
                    href: '/infrastructure?tab=observability&collector=generic_syslog',
                  },
                ],
              },
            },
          ],
        },
        'GET /api/auth/sso/config': {
          providers: [
            {
              id: 'corp-sso',
              display_name: 'Corporate SSO',
              kind: 'oidc',
              login_path: '/api/auth/sso/login?provider_id=corp-sso',
            },
          ],
          scim: {
            enabled: true,
            status: 'configured',
            mapping_count: 2,
          },
        },
        'GET /api/idp/providers': {
          providers: [
            {
              id: 'corp-sso',
              display_name: 'Corporate SSO',
              enabled: true,
              kind: 'oidc',
              validation: { status: 'ready', issues: [] },
            },
          ],
        },
      },
    });

    await openAuthenticatedRoute(page, './settings');
    await expect(page.locator('.topbar-title')).toHaveText('Settings');
    await page.getByRole('tab', { name: 'Integrations' }).click();

    await expect(page.getByText('Collector Routing & Health')).toBeVisible();
    await expect(page.getByText('Endpoint & Syslog Lane')).toBeVisible();
    const awsCard = page.locator('.stat-box').filter({ hasText: 'AWS CloudTrail' }).first();
    await expect(awsCard).toContainText('stale');
    await expect(awsCard).toContainText('Retries 2');
    await expect(awsCard).toContainText('Backoff 1m');
    await expect(awsCard).toContainText('Success 75%');
    await expect(awsCard).toContainText('Failure streak 2');
    await expect(awsCard).toContainText('credentials');

    const identityLane = collectorLaneCard(page, 'Identity Telemetry Lane').first();
    await identityLane.getByRole('link', { name: 'Review UEBA' }).click();
    await expect(page).toHaveURL(/\/ueba$/);

    await openAuthenticatedRoute(page, './settings');
    await page.getByRole('tab', { name: 'Integrations' }).click();

    const saasLane = collectorLaneCard(page, 'SaaS Activity Lane').first();
    await expect(saasLane).toContainText('GitHub Audit Log');
    await saasLane.getByRole('link', { name: 'Open Assistant' }).click();
    await expect(page).toHaveURL(/\/assistant\?source=collector-saas/);

    const cloudLane = collectorLaneCard(page, 'Cloud Audit Lane').first();
    await openAuthenticatedRoute(page, './settings');
    await page.getByRole('tab', { name: 'Integrations' }).click();

    await awsCard.getByRole('link', { name: 'SOC Workbench' }).click();
    await expect(page).toHaveURL(/\/soc\?collector=aws_cloudtrail&lane=cloud/);

    await openAuthenticatedRoute(page, './settings');
    await page.getByRole('tab', { name: 'Integrations' }).click();

    await cloudLane.getByRole('link', { name: 'Open Infrastructure' }).click();
    await expect(page).toHaveURL(/\/infrastructure\?tab=observability/);

    await openAuthenticatedRoute(page, './settings');
    await page.getByRole('tab', { name: 'Integrations' }).click();

    const edgeLane = collectorLaneCard(page, 'Endpoint & Syslog Lane').first();
    await expect(edgeLane).toContainText('Generic Syslog');
    const syslogCard = page.locator('.stat-box').filter({ hasText: 'Generic Syslog' }).first();
    await syslogCard.getByRole('link', { name: 'Infrastructure' }).click();
    await expect(page).toHaveURL(/\/infrastructure\?tab=observability&collector=generic_syslog/);

    await openAuthenticatedRoute(page, './settings');
    await page.getByRole('tab', { name: 'Integrations' }).click();

    const providerCard = page.locator('.stat-box').filter({ hasText: 'Corporate SSO' }).first();
    await expect(providerCard).toContainText('ready for callback validation');
    await expect(providerCard).toContainText(
      '/api/auth/sso/login?provider_id=corp-sso&redirect=%2Fsettings',
    );
    await expect(page.getByText(/\/api\/auth\/sso\/callback$/).first()).toBeVisible();
    await providerCard.getByRole('button', { name: 'Start SSO Test' }).click();
    await page.waitForURL(/\/api\/auth\/sso\/login/);

    const loginUrl = new URL(page.url());
    expect(loginUrl.pathname).toBe('/api/auth/sso/login');
    expect(loginUrl.searchParams.get('provider_id')).toBe('corp-sso');
    expect(loginUrl.searchParams.get('redirect')).toBe('/settings');
  });
});
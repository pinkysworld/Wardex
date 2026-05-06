import { test, expect } from '@playwright/test';
import { TEST_APP_VERSION } from '../test-support/appVersion.js';

function json(data, status = 200) {
  return {
    status,
    contentType: 'application/json',
    body: JSON.stringify(data),
  };
}

async function installApiMocks(page, overrides = {}) {
  let sessionAuthenticated = false;
  const rule = {
    id: 'rule-credential-storm',
    title: 'Credential Storm Analytics',
    description: 'Detect repeated authentication failure spikes across accounts.',
    severity_mapping: 'high',
    owner: 'secops',
    enabled: true,
    lifecycle: 'test',
    last_test_at: '2026-04-15T09:00:00Z',
    last_test_match_count: 3,
    attack: [{ technique_id: 'T1110', technique_name: 'Brute Force', tactic: 'credential-access' }],
    pack_ids: ['pack-core'],
  };

  const suggestion = {
    id: 'credential-storm',
    name: 'Investigate Credential Storm',
    description: 'Step-by-step investigation for brute-force or credential stuffing attacks',
    severity: 'High',
    mitre_techniques: ['T1110'],
    estimated_minutes: 30,
    steps: [{ order: 1, title: 'Identify affected accounts' }],
  };

  const incident = {
    id: 'inc-1',
    title: 'Credential storm against finance users',
    severity: 'critical',
    status: 'open',
    created: '2026-04-15T08:30:00Z',
    summary: 'Multiple finance identities are receiving repeated authentication failures.',
    rule_id: 'rule-credential-storm',
  };

  const alert = {
    id: 'alert-1',
    severity: 'critical',
    summary: 'Credential storm alert on finance identities',
    message: 'Credential storm alert on finance identities',
    rule_id: 'rule-credential-storm',
    host: 'finance-gateway-1',
    agent_id: 'agent-finance-1',
  };

  const routes = {
    'GET /api/auth/check': { ok: true },
    'GET /api/health': { status: 'ok', version: TEST_APP_VERSION },
    'GET /api/inbox': { items: [] },
    'GET /api/detection/profile': {
      profile: 'balanced',
      threshold_multiplier: 1.0,
      learn_threshold: 5,
    },
    'GET /api/detection/summary': { total_rules: 1, noisy_rules: 1 },
    'GET /api/detection/weights': { weights: { 'rule-credential-storm': 0.5 } },
    'GET /api/fp-feedback/stats': { items: [] },
    'GET /api/content/rules': { rules: [rule] },
    'GET /api/content/packs': { packs: [{ id: 'pack-core', name: 'Core Content Pack' }] },
    'GET /api/hunts': {
      hunts: [
        {
          id: 'hunt-1',
          name: 'Credential Storm Hunt',
          severity: 'high',
          threshold: 1,
          suppression_window_secs: 0,
          schedule_interval_secs: null,
          query: { text: 'severity:critical credential storm', level: 'high', limit: 250 },
          latest_run: { started_at: '2026-04-15T09:30:00Z', match_count: 2 },
        },
      ],
      count: 1,
    },
    'GET /api/suppressions': { suppressions: [] },
    'GET /api/coverage/mitre': { coverage_pct: 41, covered_techniques: 12 },
    'POST /api/investigations/suggest': { suggestions: [suggestion] },
    'GET /api/workbench/overview': { incidents_open: 1, queue_open: 1 },
    'GET /api/incidents': { incidents: [incident] },
    'GET /api/cases': { cases: [] },
    'GET /api/cases/stats': { open_cases: 0 },
    'GET /api/queue/alerts': { alerts: [alert] },
    'GET /api/queue/stats': { open_alerts: 1 },
    'GET /api/ws/stats': { connected_subscribers: 3, events_emitted: 21 },
    'GET /api/response/pending': { pending: [], count: 0 },
    'GET /api/response/requests': { requests: [], count: 0, ready_to_execute: 0 },
    'GET /api/response/audit': { audit_log: [] },
    'GET /api/response/stats': {
      auto_executed: 0,
      executed: 0,
      pending: 0,
      pending_approval: 0,
      ready_to_execute: 0,
      approved_ready: 0,
      total_requests: 0,
      denied: 0,
      protected_assets: 0,
    },
    'GET /api/process-tree': { nodes: [] },
    'GET /api/process-tree/deep-chains': { chains: [] },
    'GET /api/processes/live': { processes: [], count: 0 },
    'GET /api/processes/analysis': { findings: [], total: 0, risk_summary: {} },
    'GET /api/correlation/campaigns': { campaigns: [] },
    'GET /api/rbac/users': { users: [] },
    'GET /api/timeline/host': { events: [] },
    'GET /api/escalation/policies': { policies: [] },
    'GET /api/escalation/active': { escalations: [] },
    'GET /api/investigations/workflows': [suggestion],
    'GET /api/investigations/active': [],
    'GET /api/efficacy/summary': { tp_rate: 0.8 },
    'GET /api/incidents/inc-1': incident,
    'GET /api/incidents/inc-1/storyline': {
      events: [
        { timestamp: '2026-04-15T08:31:00Z', description: 'Initial brute-force cluster detected' },
      ],
    },
  };

  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const key = `${request.method()} ${url.pathname}`;

    if (key === 'GET /api/auth/session') {
      await route.fulfill(
        json({
          authenticated: sessionAuthenticated,
          role: sessionAuthenticated ? 'admin' : 'viewer',
          username: sessionAuthenticated ? 'playwright' : 'anonymous',
          user_id: sessionAuthenticated ? 'playwright' : 'anonymous',
          source: sessionAuthenticated ? 'session' : 'anonymous',
          groups: [],
        }),
      );
      return;
    }

    if (key === 'POST /api/auth/session') {
      sessionAuthenticated = true;
      await route.fulfill(json({ authenticated: true, role: 'admin', username: 'playwright' }));
      return;
    }

    if (key === 'POST /api/auth/logout') {
      sessionAuthenticated = false;
      await route.fulfill(json({ ok: true }));
      return;
    }

    const handler = overrides[key] ?? routes[key];

    if (typeof handler === 'function') {
      const result = await handler(request);
      if (result && 'status' in result && 'body' in result) {
        await route.fulfill(json(result.body, result.status));
      } else {
        await route.fulfill(json(result));
      }
      return;
    }

    await route.fulfill(json(handler ?? {}));
  });
}

async function login(page) {
  await page.goto('./');
  await page.evaluate(() => {
    localStorage.setItem('wardex_onboarded', '1');
    localStorage.removeItem('wardex_token');
  });
  await page.reload({ waitUntil: 'load' });
  await page.getByLabel('API token').fill('playwright-token');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('.auth-badge')).toContainText(/connected/i);
  await expect(page.locator('.role-badge')).toContainText(/admin/i);
}

test('run-hunt route opens the hunt drawer and saves/runs a hunt', async ({ page }) => {
  const requests = { hunt: null, save: null };

  await installApiMocks(page, {
    'POST /api/hunt': async (request) => {
      requests.hunt = JSON.parse(request.postData() || '{}');
      return [{ id: 'match-1', message: 'Credential storm match' }];
    },
    'POST /api/hunts': async (request) => {
      requests.save = JSON.parse(request.postData() || '{}');
      return { status: 'saved' };
    },
  });

  await login(page);
  await page.goto(
    './detection?intent=run-hunt&huntQuery=severity%3Acritical%20credential%20storm&huntName=Credential%20Storm%20Pivot',
  );

  await expect(page.locator('#hunt-name')).toHaveValue('Credential Storm Pivot');
  await expect(page.locator('#hunt-query')).toHaveValue('severity:critical credential storm');
  await expect(page.getByText('Investigate Credential Storm')).toBeVisible();

  await page.getByRole('button', { name: 'Run Hunt' }).click();
  await expect.poll(() => requests.hunt?.query).toBe('severity:critical credential storm');
  await expect(page.getByText(/1 matching event/i)).toBeVisible();

  await page.getByRole('button', { name: 'Save Hunt' }).click();
  await expect.poll(() => requests.save?.query?.text).toBe('severity:critical credential storm');
  await expect.poll(() => requests.save?.name).toBe('Credential Storm Pivot');
});

test('incident planner suggests and starts an investigation workflow', async ({ page }) => {
  let startPayload = null;

  await installApiMocks(page, {
    'POST /api/investigations/start': async (request) => {
      startPayload = JSON.parse(request.postData() || '{}');
      return { status: 'started' };
    },
  });

  await login(page);
  await page.goto('/admin/soc#incidents');
  await expect(page.locator('h1.topbar-title')).toContainText('SOC Workbench');

  const incidentRow = page
    .locator('table tbody tr')
    .filter({ hasText: 'Credential storm against finance users' });
  await incidentRow.getByRole('button', { name: 'View' }).click();
  await expect(page.getByRole('button', { name: 'Plan Investigation' })).toBeVisible();
  await page.getByRole('button', { name: 'Plan Investigation' }).click();

  const planner = page.locator('.card-header').filter({ hasText: 'Planner Context' }).locator('..');
  await expect(planner).toBeVisible();
  await expect(planner.getByText('Investigate Credential Storm')).toBeVisible();

  await planner.getByRole('button', { name: 'Start' }).click();
  await expect.poll(() => startPayload?.workflow_id).toBe('credential-storm');
  await expect(page).toHaveURL(/\/soc#investigations$/);
});

test('queue and insight refresh actions re-fetch grouped SOC endpoints', async ({ page }) => {
  const counts = {
    queue: 0,
    queueStats: 0,
    wsStats: 0,
    efficacy: 0,
    timeline: 0,
  };
  const alert = {
    id: 'alert-1',
    severity: 'critical',
    summary: 'Credential storm alert on finance identities',
    message: 'Credential storm alert on finance identities',
    rule_id: 'rule-credential-storm',
    host: 'finance-gateway-1',
    agent_id: 'agent-finance-1',
  };

  await installApiMocks(page, {
    'GET /api/queue/alerts': async () => {
      counts.queue += 1;
      return { alerts: [alert] };
    },
    'GET /api/queue/stats': async () => {
      counts.queueStats += 1;
      return { open_alerts: 1 };
    },
    'GET /api/ws/stats': async () => {
      counts.wsStats += 1;
      return { connected_subscribers: 3, events_emitted: 21 };
    },
    'GET /api/efficacy/summary': async () => {
      counts.efficacy += 1;
      return {
        total_alerts_triaged: 10,
        overall_tp_rate: 0.7,
        overall_precision: 0.66,
      };
    },
    'GET /api/timeline/host': async (request) => {
      counts.timeline += 1;
      const host = new URL(request.url()).searchParams.get('hostname') || 'finance-gateway-1';
      return {
        events: [
          {
            timestamp: '2026-04-15T09:00:00Z',
            host,
            severity: 'high',
            event: 'Suspicious PowerShell launched',
          },
        ],
      };
    },
  });

  await login(page);
  await page.goto('./soc#queue');

  const queueCard = page.locator('.card').filter({ hasText: 'SOC Queue (1 alerts)' }).first();
  await expect(queueCard).toBeVisible();
  await expect(page.getByText('Live (3)')).toBeVisible();

  await expect.poll(() => counts.queue).toBeGreaterThan(0);
  await expect.poll(() => counts.queueStats).toBeGreaterThan(0);
  await expect.poll(() => counts.wsStats).toBeGreaterThan(0);

  const initialQueue = counts.queue;
  const initialQueueStats = counts.queueStats;
  const initialWsStats = counts.wsStats;

  await queueCard.getByRole('button', { name: '↻ Refresh' }).click();

  await expect.poll(() => counts.queue).toBe(initialQueue + 1);
  await expect.poll(() => counts.queueStats).toBe(initialQueueStats + 1);
  await expect.poll(() => counts.wsStats).toBe(initialWsStats + 1);

  await page.getByRole('button', { name: 'Efficacy' }).click();

  const efficacyCard = page.locator('.card').filter({ hasText: 'Detection Efficacy' }).first();
  await expect(efficacyCard).toBeVisible();
  await expect.poll(() => counts.efficacy).toBeGreaterThan(0);
  await expect.poll(() => counts.timeline).toBeGreaterThan(0);

  const initialEfficacy = counts.efficacy;
  const initialTimeline = counts.timeline;

  await efficacyCard.getByRole('button', { name: '↻ Refresh' }).click();

  await expect.poll(() => counts.efficacy).toBe(initialEfficacy + 1);
  await expect.poll(() => counts.timeline).toBe(initialTimeline + 1);

  await page.getByRole('button', { name: 'Timeline', exact: true }).click();

  const timelineCard = page.locator('.card').filter({ hasText: 'Host Timeline' }).first();
  await expect(timelineCard).toBeVisible();
  await expect(page.getByText('Suspicious PowerShell launched')).toBeVisible();

  await timelineCard.getByRole('button', { name: '↻ Refresh' }).click();

  await expect.poll(() => counts.efficacy).toBe(initialEfficacy + 2);
  await expect.poll(() => counts.timeline).toBe(initialTimeline + 2);
});

test('queue hunt pivot opens detection with prefilled hunt context', async ({ page }) => {
  await installApiMocks(page);
  await login(page);
  await page.goto('./soc#queue');

  await page.getByRole('button', { name: 'Hunt' }).click();
  await expect(page).toHaveURL(/\/detection\?intent=run-hunt/);
  await expect(page.locator('#hunt-name')).toHaveValue(
    /Hunt Credential storm alert on finance identities/i,
  );
  await expect(page.locator('#hunt-query')).toHaveValue(/severity:critical/i);
  await expect(page.locator('#hunt-query')).toHaveValue(/rule-credential-storm/i);
});

test('visible process tree pivot opens the SOC process tree workspace', async ({ page }) => {
  await installApiMocks(page);
  await login(page);
  await page.goto('./soc#overview');

  await expect(page.locator('h1.topbar-title')).toContainText('SOC Workbench');

  const processTreeLink = page.getByRole('link', { name: 'Open Process Tree' });
  await expect(processTreeLink).toBeVisible();
  await processTreeLink.click();

  await expect(page).toHaveURL(/\/soc(?:\?.*)?#process-tree$/);
  await expect(page.getByText('Live Processes (0)')).toBeVisible();
  await expect(
    page.locator('.card-title').filter({ hasText: /^Deep Process Chains$/ }),
  ).toBeVisible();
});

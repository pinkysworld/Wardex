import { test, expect } from '@playwright/test';

const TOKEN = 'playwright-local-token';
const VERSION = '1.0.3';

function json(body, status = 200) {
  return {
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  };
}

async function installShellFleetMocks(page) {
  let sessionAuthenticated = false;
  const localAgent = {
    id: 'local-console',
    hostname: 'playwright-host.local',
    platform: 'macOS',
    version: VERSION,
    current_version: VERSION,
    enrolled_at: '2026-04-20T06:27:15.449Z',
    last_seen: '2026-04-20T06:27:45.809Z',
    last_seen_age_secs: 3,
    status: 'online',
    labels: {
      local_console: 'true',
      role: 'control-plane',
    },
    health: {
      pending_alerts: 0,
      telemetry_queue_depth: 6,
      update_state: null,
      update_target_version: null,
      last_update_error: null,
      last_update_at: null,
    },
    pending_alerts: 0,
    telemetry_queue_depth: 6,
    target_version: null,
    rollout_group: null,
    deployment_status: null,
    scope_override: false,
    local_console: true,
    local_monitoring: true,
    source: 'local',
    os_version: 'macOS 26.5',
    arch: 'x86_64',
    telemetry_samples: 6,
    process_count: 677,
  };

  const agentDetail = {
    agent: {
      id: 'local-console',
      hostname: 'playwright-host.local',
      platform: 'macOS',
      version: VERSION,
      enrolled_at: '2026-04-20T06:27:15.449Z',
      last_seen: '2026-04-20T06:27:45.809Z',
      status: 'online',
      labels: {
        local_console: 'true',
        role: 'control-plane',
      },
      health: {
        pending_alerts: 0,
        telemetry_queue_depth: 6,
      },
      monitor_scope: null,
    },
    local_console: true,
    computed_status: 'online',
    heartbeat_age_secs: 3,
    deployment: null,
    scope_override: false,
    effective_scope: {
      process_tree: true,
      filesystem: true,
      network: true,
      users: true,
      services: true,
      persistence: true,
      file_integrity: true,
    },
    health: {
      pending_alerts: 0,
      telemetry_queue_depth: 6,
    },
    analytics: {
      event_count: 0,
      correlated_count: 0,
      critical_count: 0,
      average_score: 0,
      max_score: 0,
      highest_level: 'Nominal',
      risk: 'Nominal',
      top_reasons: [],
    },
    timeline: [],
    risk_transitions: [],
    inventory: null,
    log_summary: {
      total_records: 0,
      last_timestamp: null,
      by_level: {},
    },
  };

  const routeMap = new Map([
    ['GET /api/auth/check', { ok: true }],
    ['GET /api/health', { status: 'ok', version: VERSION }],
    ['GET /api/inbox', { items: [] }],
    ['GET /api/fleet/status', { status: 'healthy', collectors: 1 }],
    ['GET /api/fleet/dashboard', {
      fleet: {
        total_agents: 1,
        status_counts: { online: 1 },
        coverage_pct: 100,
      },
      events: {
        total: 0,
        recent_correlations: 0,
        correlations: [],
        analytics: {},
        triage: { counts: {}, persistent: true, storage_path: 'var/events.json' },
      },
      policy: { current_version: 1, history_depth: 1 },
      updates: {
        available_releases: 1,
        pending_deployments: 0,
        release_catalog: [],
        deployments: [],
        active_deployments: [],
        rollout_groups: {},
      },
      siem: {
        enabled: false,
        pending: 0,
        total_pushed: 0,
        total_pulled: 0,
      },
    }],
    ['GET /api/agents', [localAgent]],
    ['GET /api/agents/local-console/details', agentDetail],
    ['GET /api/swarm/posture', {}],
    ['GET /api/swarm/intel', {}],
    ['GET /api/platform', { os: 'macOS', platform: 'macOS' }],
    ['GET /api/events', { events: [] }],
    ['GET /api/events/summary', {}],
    ['GET /api/policy/history', []],
    ['GET /api/updates/releases', []],
    ['GET /api/rollout/config', {}],
  ]);

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

    await route.fulfill(json(routeMap.get(key) ?? {}));
  });
}

async function loginThroughForm(page) {
  await page.goto('./');
  await page.evaluate(() => {
    localStorage.removeItem('wardex_token');
    localStorage.setItem('wardex_onboarded', '1');
  });
  await page.reload({ waitUntil: 'load' });
  if (await page.locator('.auth-badge').filter({ hasText: 'Connected' }).count()) {
    await expect(page.locator('.role-badge')).toContainText('admin');
    return;
  }
  await page.getByLabel('API token').fill(TOKEN);
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('.auth-badge')).toContainText('Connected');
  await expect(page.locator('.role-badge')).toContainText('admin');
}

test.describe('Shell and Fleet regressions', () => {
  test('collapsed desktop sidebar badges stay readable and in-bounds', async ({ page }) => {
    await installShellFleetMocks(page);
    await loginThroughForm(page);

    await page.getByTitle('Toggle sidebar').click();
    await expect(page.locator('.app')).toHaveClass(/sidebar-collapsed/);

    const badgeGeometry = await page.locator('.nav-icon-text').evaluateAll((nodes) => {
      return nodes.map((node) => {
        const rect = node.getBoundingClientRect();
        const sidebarRect = node.closest('.sidebar')?.getBoundingClientRect();
        return {
          text: node.textContent?.trim(),
          overflowX: node.scrollWidth - node.clientWidth,
          overflowY: node.scrollHeight - node.clientHeight,
          insideSidebar: Boolean(
            sidebarRect && rect.left >= sidebarRect.left && rect.right <= sidebarRect.right,
          ),
        };
      });
    });

    expect(badgeGeometry.length).toBeGreaterThan(8);
    for (const badge of badgeGeometry) {
      expect(badge.overflowX, `${badge.text} overflows horizontally`).toBeLessThanOrEqual(1);
      expect(badge.overflowY, `${badge.text} overflows vertically`).toBeLessThanOrEqual(1);
      expect(badge.insideSidebar, `${badge.text} spills outside sidebar bounds`).toBe(true);
    }
  });

  test('narrow layout keeps login usable and recovers navigation from topbar', async ({ page }) => {
    await installShellFleetMocks(page);
    await page.setViewportSize({ width: 390, height: 844 });

    await page.goto('./');
    await page.evaluate(() => {
      localStorage.removeItem('wardex_token');
      localStorage.removeItem('wardex_onboarded');
    });
    await page.reload({ waitUntil: 'load' });

    await expect(page.getByText('Set up the Wardex admin console')).toHaveCount(0);
    await page.getByLabel('API token').fill(TOKEN);
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('.auth-badge')).toContainText('Connected');

    const navToggle = page.getByRole('button', { name: 'Toggle navigation menu' });
    await expect(navToggle).toHaveText('Hide Menu');
    await navToggle.click();
    await expect(page.locator('.app')).toHaveClass(/sidebar-collapsed/);
    await expect(navToggle).toHaveText('Show Menu');
    await navToggle.click();
    await expect(page.locator('.app')).not.toHaveClass(/sidebar-collapsed/);
  });

  test('fleet shows the local console host as protected inventory', async ({ page }) => {
    await installShellFleetMocks(page);
    await loginThroughForm(page);

    await page.goto('./fleet?fleetTab=agents');
    await expect(page.getByText(/Registered Agents \(1\)/)).toBeVisible();
    await expect(page.getByText('Local Console Host')).toBeVisible();

    const protectedCheckbox = page.locator('input[aria-label*="managed by the local console"]');
    await expect(protectedCheckbox).toBeDisabled();

    await page
      .locator('.desktop-table-only tbody tr')
      .filter({ hasText: 'playwright-host.local' })
      .first()
      .click();
    await expect(page.locator('.triage-detail')).toContainText(
      'Local Wardex console host with direct process and telemetry access',
    );
    await expect(page.locator('.triage-detail button:has-text("Remove")')).toHaveCount(0);
  });
});

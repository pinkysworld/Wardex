import { expect } from '@playwright/test';

export const TOKEN = 'playwright-local-token';
export const VERSION = '1.0.4';

const NOW = '2026-04-20T06:27:45.809Z';

const LOCAL_AGENT = {
  id: 'local-console',
  hostname: 'playwright-host.local',
  platform: 'macOS',
  version: VERSION,
  current_version: VERSION,
  enrolled_at: '2026-04-20T06:27:15.449Z',
  last_seen: NOW,
  last_seen_age_secs: 3,
  status: 'online',
  labels: {
    local_console: 'true',
    role: 'control-plane',
  },
  health: {
    pending_alerts: 1,
    telemetry_queue_depth: 6,
    update_state: null,
    update_target_version: null,
    last_update_error: null,
    last_update_at: null,
  },
  pending_alerts: 1,
  telemetry_queue_depth: 6,
  target_version: null,
  rollout_group: 'local',
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

const SECOND_AGENT = {
  id: 'agent-ops-01',
  hostname: 'ops-gateway-01',
  platform: 'Linux',
  version: VERSION,
  current_version: VERSION,
  enrolled_at: '2026-04-19T20:13:02.000Z',
  last_seen: '2026-04-20T06:26:17.000Z',
  last_seen_age_secs: 12,
  status: 'online',
  labels: {
    role: 'gateway',
  },
  health: {
    pending_alerts: 2,
    telemetry_queue_depth: 3,
  },
  pending_alerts: 2,
  telemetry_queue_depth: 3,
  scope_override: false,
};

const LOCAL_AGENT_DETAIL = {
  agent: {
    id: 'local-console',
    hostname: 'playwright-host.local',
    platform: 'macOS',
    version: VERSION,
    enrolled_at: '2026-04-20T06:27:15.449Z',
    last_seen: NOW,
    status: 'online',
    labels: {
      local_console: 'true',
      role: 'control-plane',
    },
    health: {
      pending_alerts: 1,
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
    pending_alerts: 1,
    telemetry_queue_depth: 6,
  },
  analytics: {
    event_count: 4,
    correlated_count: 1,
    critical_count: 1,
    average_score: 0.84,
    max_score: 0.97,
    highest_level: 'Elevated',
    risk: 'Elevated',
    top_reasons: ['ssh burst'],
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

function json(body, status = 200) {
  return {
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  };
}

function buildResponses() {
  return {
    'GET /api/auth/check': { ok: true },
    'GET /api/health': { status: 'ok', version: VERSION },
    'GET /api/status': {
      version: VERSION,
      uptime_secs: 86400,
      mode: 'local',
      hostname: 'playwright-host.local',
    },
    'GET /api/host/info': {
      hostname: 'playwright-host.local',
      platform: 'macOS',
      os_version: 'macOS 26.5',
      arch: 'x86_64',
    },
    'GET /api/platform': { os: 'macOS', platform: 'macOS' },
    'GET /api/endpoints': {
      endpoints: [
        { method: 'GET', path: '/api/health' },
        { method: 'GET', path: '/api/agents' },
        { method: 'GET', path: '/api/report-runs' },
      ],
    },
    'GET /api/openapi.json': {
      openapi: '3.1.0',
      info: { title: 'Wardex API', version: VERSION },
      paths: {
        '/api/health': {},
        '/api/agents': {},
        '/api/report-runs': {},
      },
      components: {
        schemas: {
          Agent: { type: 'object' },
          ReportRun: { type: 'object' },
        },
      },
    },
    'GET /api/inbox': {
      items: [
        {
          id: 'inbox-1',
          title: 'Review rollout plan',
          summary: 'One deployment is waiting for operator approval.',
          severity: 'medium',
          path: '/fleet?fleetTab=rollouts',
          acknowledged: false,
          created_at: '2026-04-20T05:40:00.000Z',
        },
      ],
    },
    'GET /api/fleet/status': { status: 'healthy', collectors: 1 },
    'GET /api/fleet/dashboard': {
      fleet: {
        total_agents: 2,
        status_counts: { online: 2 },
        coverage_pct: 100,
      },
      events: {
        total: 4,
        recent_correlations: 1,
        correlations: [],
        analytics: {},
        triage: { counts: {}, persistent: true, storage_path: 'var/events.json' },
      },
      policy: { current_version: 7, history_depth: 4 },
      updates: {
        available_releases: 1,
        pending_deployments: 1,
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
    },
    'GET /api/agents': [LOCAL_AGENT, SECOND_AGENT],
    'GET /api/agents/local-console/details': LOCAL_AGENT_DETAIL,
    'GET /api/agents/local-console/inventory': {
      collected_at: NOW,
      software: [],
      services: [],
      network: [],
      users: [],
      hardware: { cpu: 'Apple M4', memory_gb: 24 },
    },
    'GET /api/swarm/posture': {},
    'GET /api/swarm/intel': {},
    'GET /api/policy/history': [],
    'GET /api/updates/releases': [],
    'GET /api/command/summary': {
      generated_at: NOW,
      metrics: {
        open_incidents: 1,
        active_cases: 1,
        pending_remediation_reviews: 1,
        connector_issues: 1,
        noisy_rules: 1,
        stale_rules: 1,
        release_candidates: 1,
        compliance_packs: 1,
      },
      lanes: {
        connectors: {
          planned: ['github_audit', 'crowdstrike_falcon', 'generic_syslog'],
          readiness: {
            collectors: [
              {
                provider: 'aws_cloudtrail',
                label: 'AWS CloudTrail',
                enabled: true,
                last_success_at: NOW,
              },
              {
                provider: 'github_audit',
                label: 'GitHub Audit Log',
                enabled: true,
                last_error_at: NOW,
                error_category: 'credentials',
              },
              {
                provider: 'crowdstrike_falcon',
                label: 'CrowdStrike Falcon',
                enabled: true,
              },
              {
                provider: 'generic_syslog',
                label: 'Generic Syslog',
                enabled: true,
              },
            ],
          },
        },
      },
    },
    'GET /api/rollout/config': {},
    'GET /api/events': { events: [] },
    'GET /api/events/summary': {},
    'GET /api/alerts': [
      {
        id: 'alert-ssh-burst',
        timestamp: NOW,
        severity: 'critical',
        category: 'Credential Access',
        hostname: 'playwright-host.local',
        source: 'agent',
        message: 'Unauthorized SSH burst from 203.0.113.42',
        reasons: ['ssh burst', 'password spray'],
        score: 0.97,
      },
      {
        id: 'alert-script-child',
        timestamp: '2026-04-20T06:18:15.000Z',
        severity: 'medium',
        category: 'Execution',
        hostname: 'ops-gateway-01',
        source: 'agent',
        message: 'Unexpected shell child process from deployment hook',
        reasons: ['shell child'],
        score: 0.61,
      },
    ],
    'GET /api/alerts/count': { total: 2, critical: 1, medium: 1 },
    'GET /api/alerts/grouped': {
      groups: [
        { label: 'Credential Access', count: 1 },
        { label: 'Execution', count: 1 },
      ],
    },
    'GET /api/telemetry/current': { events_per_sec: 42, total_events: 1024 },
    'GET /api/telemetry/history': [
      { timestamp: '2026-04-20T06:05:00.000Z', events_per_sec: 18 },
      { timestamp: '2026-04-20T06:10:00.000Z', events_per_sec: 27 },
      { timestamp: '2026-04-20T06:15:00.000Z', events_per_sec: 34 },
      { timestamp: NOW, events_per_sec: 42 },
    ],
    'GET /api/detection/profile': { profile: 'balanced', mode: 'adaptive' },
    'GET /api/detection/summary': {
      rules_total: 42,
      active_rules: 40,
      coverage_pct: 86,
      latest_run_at: NOW,
    },
    'GET /api/detection/weights': { weights: { 'rule-ssh-burst': 0.74 } },
    'GET /api/fp-feedback/stats': { total_feedback: 5, false_positive_rate: 0.2 },
    'GET /api/content/rules': {
      rules: [
        {
          id: 'rule-ssh-burst',
          title: 'SSH burst detection',
          description: 'Detects repeated SSH failures across a short interval.',
          lifecycle: 'active',
          enabled: true,
          severity_mapping: 'high',
          owner: 'detection',
          last_test_at: NOW,
          last_promotion_at: NOW,
          last_test_match_count: 2,
          attack: [
            {
              technique_id: 'T1110',
              technique_name: 'Brute Force',
              tactic: 'Credential Access',
            },
          ],
        },
        {
          id: 'rule-credential-storm',
          title: 'Credential storm detection',
          description: 'Detects clustered authentication failures across identities.',
          lifecycle: 'test',
          enabled: true,
          severity_mapping: 'high',
          owner: 'detection',
          last_test_at: null,
          last_promotion_at: null,
          last_test_match_count: 8,
          attack: [
            {
              technique_id: 'T1110',
              technique_name: 'Brute Force',
              tactic: 'Credential Access',
            },
          ],
        },
      ],
    },
    'GET /api/content/packs': {
      packs: [{ id: 'pack-core-linux', name: 'Core Linux Detections', rules: ['rule-ssh-burst'] }],
    },
    'GET /api/hunts': { hunts: [] },
    'GET /api/suppressions': {
      suppressions: [{ id: 'suppression-credential-storm', rule_id: 'rule-credential-storm' }],
    },
    'GET /api/coverage/mitre': {
      tactics: [{ tactic: 'Credential Access', coverage_pct: 86 }],
    },
    'GET /api/threat-intel/status': { feeds_online: 2, last_sync_at: NOW },
    'GET /api/queue/stats': { open: 3, assigned: 1, sla_breaches: 0 },
    'GET /api/response/stats': {
      auto_executed: 4,
      executed: 4,
      pending: 1,
      pending_approval: 1,
      ready_to_execute: 1,
      approved_ready: 1,
      total_requests: 5,
      denied: 0,
      protected_assets: 2,
    },
    'GET /api/processes/analysis': {
      findings: [
        {
          pid: 880,
          name: 'bash',
          verdict: 'review',
        },
      ],
    },
    'GET /api/processes/live': {
      processes: [
        { pid: 880, name: 'bash', cpu: 12.4, memory: 3.1, user: 'playwright' },
        { pid: 512, name: 'wardex', cpu: 7.2, memory: 9.8, user: 'playwright' },
      ],
    },
    'GET /api/incidents': [
      {
        id: 'incident-1',
        title: 'Credential storm on gateway',
        severity: 'high',
        status: 'open',
      },
    ],
    'GET /api/cases': {
      cases: [{ id: 1, title: 'Gateway credential storm', status: 'investigating' }],
    },
    'GET /api/remediation/change-reviews': {
      reviews: [
        {
          id: 'review-credential-storm-1',
          title: 'Quarantine gateway session token',
          asset_id: 'playwright-host.local',
          change_type: 'malware_containment',
          approval_status: 'pending_review',
          recovery_status: 'not_started',
          required_approvers: 2,
          approvals: [],
          evidence: { alert_id: 'alert-ssh-burst' },
        },
      ],
    },
    'GET /api/detection/rules': [
      {
        id: 'rule-ssh-burst',
        title: 'SSH burst detection',
        description: 'Detects repeated SSH failures across a short interval.',
      },
    ],
    'GET /api/feeds': [
      { id: 'feed-misp-primary', name: 'MISP primary', status: 'online' },
      { id: 'feed-bazaar', name: 'MalwareBazaar', status: 'online' },
    ],
    'GET /api/feeds/stats': { total_sources: 2, active_sources: 2 },
    'GET /api/malware/stats': { matches: 1, recent: 1 },
    'GET /api/coverage/gaps': { gaps: [{ tactic: 'Impact', coverage_pct: 78 }] },
    'GET /api/quarantine/stats': { active: 1, released_today: 0 },
    'GET /api/lifecycle/stats': { active: 40, canary: 2, deprecated: 1 },
    'GET /api/dns-threat/summary': { detections: 1, top_domains: ['example-bad.test'] },
    'GET /api/reports': [
      {
        id: 'report-1',
        name: 'Weekly Ops Digest',
        created_at: '2026-04-19T09:00:00.000Z',
      },
    ],
    'GET /api/reports/executive-summary': { total_reports: 5, generated_at: NOW },
    'GET /api/report-templates': {
      templates: [
        {
          id: 'template-executive-status',
          name: 'Executive Status',
          kind: 'executive_status',
          scope: 'global',
          format: 'json',
          audience: 'Leadership',
          description: 'Weekly executive posture snapshot.',
          status: 'active',
        },
      ],
    },
    'GET /api/report-runs': {
      runs: [
        {
          id: 'run-1',
          name: 'Executive Status',
          kind: 'executive_status',
          scope: 'global',
          format: 'json',
          audience: 'Leadership',
          summary: 'Weekly snapshot',
          status: 'completed',
          created_at: '2026-04-19T09:00:00.000Z',
          finished_at: '2026-04-19T09:02:00.000Z',
        },
      ],
    },
    'GET /api/report-schedules': {
      schedules: [
        {
          id: 'schedule-1',
          name: 'Monday Executive Status',
          cadence: 'weekly',
          target: 'ops@wardex.local',
          status: 'active',
          next_run_at: '2026-04-27T08:00:00.000Z',
        },
      ],
    },
    'GET /api/config/current': {
      server: { port: 8080 },
      monitor: {
        scope: {
          process_tree: true,
          filesystem: true,
          network: true,
        },
      },
      ui: { theme: 'light' },
    },
    'GET /api/monitoring/options': {
      modes: ['balanced', 'strict'],
      available_scopes: ['process_tree', 'filesystem', 'network'],
    },
    'GET /api/monitoring/paths': {
      paths: ['/Applications', '/Users/playwright'],
    },
    'GET /api/feature-flags': {
      flags: [
        { key: 'deep_hunts', enabled: true },
        { key: 'experimental_search', enabled: true },
      ],
    },
    'GET /api/siem/status': { enabled: false, pending: 0, total_pushed: 0 },
    'GET /api/siem/config': {},
    'GET /api/taxii/status': { connected: false, collections: 0 },
    'GET /api/taxii/config': {},
    'GET /api/enrichments/connectors': { connectors: [] },
    'GET /api/idp/providers': { providers: [] },
    'GET /api/scim/config': { enabled: false },
    'GET /api/sbom': { components: [{ name: 'wardex', version: VERSION }] },
    'GET /api/compliance/status': { status: 'ready', score: 91 },
    'GET /api/assistant/status': { mode: 'retrieval-only', model: 'retrieval-only' },
    'GET /api/collectors/status': {
      collectors: [
        { provider: 'aws_cloudtrail', label: 'AWS CloudTrail', enabled: true, freshness: 'fresh' },
        { provider: 'github_audit', label: 'GitHub Audit Log', enabled: true, freshness: 'fresh' },
        {
          provider: 'crowdstrike_falcon',
          label: 'CrowdStrike Falcon',
          enabled: true,
          freshness: 'unknown',
        },
        { provider: 'generic_syslog', label: 'Generic Syslog', enabled: true, freshness: 'fresh' },
      ],
    },
    'GET /api/collectors/aws': {
      config: { provider: 'aws_cloudtrail', enabled: true },
      validation: { status: 'ready', issues: [] },
    },
    'GET /api/collectors/azure': {
      config: { provider: 'azure_activity', enabled: true },
      validation: { status: 'ready', issues: [] },
    },
    'GET /api/collectors/gcp': {
      config: { provider: 'gcp_audit', enabled: true },
      validation: { status: 'ready', issues: [] },
    },
    'GET /api/collectors/okta': {
      config: { provider: 'okta_identity', enabled: true },
      validation: { status: 'ready', issues: [] },
    },
    'GET /api/collectors/entra': {
      config: { provider: 'entra_identity', enabled: true },
      validation: { status: 'ready', issues: [] },
    },
    'GET /api/collectors/m365': {
      config: { provider: 'm365_saas', enabled: true },
      validation: { status: 'ready', issues: [] },
    },
    'GET /api/collectors/workspace': {
      config: { provider: 'workspace_saas', enabled: true },
      validation: { status: 'ready', issues: [] },
    },
    'GET /api/collectors/github': {
      config: { provider: 'github_audit', enabled: true, organization: 'wardex-labs' },
      validation: { status: 'ready', issues: [] },
    },
    'GET /api/collectors/crowdstrike': {
      config: { provider: 'crowdstrike_falcon', enabled: true, cloud: 'us-1' },
      validation: { status: 'warning', issues: [{ field: 'client_secret_ref' }] },
    },
    'GET /api/collectors/syslog': {
      config: { provider: 'generic_syslog', enabled: true, protocol: 'udp' },
      validation: { status: 'ready', issues: [] },
    },
    'GET /api/admin/db/version': { schema_version: 53, app_version: VERSION },
    'GET /api/dlq/stats': { pending: 0 },
    'GET /api/admin/db/sizes': {
      items: [{ name: 'events', size_bytes: 2048 }],
    },
    'GET /api/storage/stats': { used_bytes: 2048, total_bytes: 4096 },
    'GET /api/rbac/users': {
      users: [{ username: 'playwright', role: 'admin', status: 'active' }],
    },
    'GET /api/research-tracks': {
      tracks: [{ id: 'operator-workflows', title: 'Operator workflows' }],
    },
    'GET /api/manager/overview': {
      initiatives: [{ id: 'ops-readiness', status: 'on-track' }],
    },
  };
}

export async function installAppMocks(page, options = {}) {
  const responses = {
    ...buildResponses(),
    ...(options.responses || {}),
  };
  let sessionAuthenticated = Boolean(options.sessionAuthenticated);
  const sessionPayload = () => ({
    authenticated: sessionAuthenticated,
    role: sessionAuthenticated ? 'admin' : 'viewer',
    username: sessionAuthenticated ? 'playwright' : 'anonymous',
    user_id: sessionAuthenticated ? 'playwright' : 'anonymous',
    source: sessionAuthenticated ? 'session' : 'anonymous',
    groups: sessionAuthenticated ? [] : [],
  });

  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const key = `${request.method()} ${pathname}`;

    if (typeof options.onRequest === 'function') {
      const handled = await options.onRequest({ route, request, pathname, key, responses, json });
      if (handled) {
        return;
      }
    }

    if (key === 'GET /api/auth/session') {
      await route.fulfill(json(sessionPayload()));
      return;
    }

    if (key === 'GET /api/session/info') {
      await route.fulfill(
        json({ authenticated: sessionAuthenticated, role: sessionPayload().role }),
      );
      return;
    }

    if (key === 'POST /api/auth/session') {
      sessionAuthenticated = true;
      await route.fulfill(json(sessionPayload()));
      return;
    }

    if (key === 'POST /api/auth/logout') {
      sessionAuthenticated = false;
      await route.fulfill(json({ ok: true }));
      return;
    }

    if (Object.prototype.hasOwnProperty.call(responses, key)) {
      await route.fulfill(json(responses[key]));
      return;
    }

    if (request.method() === 'POST' || request.method() === 'PUT' || request.method() === 'PATCH') {
      await route.fulfill(json({ ok: true }));
      return;
    }

    if (request.method() === 'DELETE') {
      await route.fulfill(json({ ok: true }));
      return;
    }

    await route.fulfill(json({}));
  });
}

export async function resetStoredSession(page, { onboarded = true } = {}) {
  await page.goto('./');
  await page.evaluate(
    ({ onboarded }) => {
      localStorage.removeItem('wardex_token');
      localStorage.removeItem('wardex_recent');
      localStorage.removeItem('wardex_saved_searches');
      localStorage.removeItem('wardex_pinned_sections');
      if (onboarded) {
        localStorage.setItem('wardex_onboarded', '1');
      } else {
        localStorage.removeItem('wardex_onboarded');
      }
    },
    { onboarded },
  );
  await page.reload({ waitUntil: 'load' });
}

export async function seedAuthenticatedSession(page, { token = TOKEN, onboarded = true } = {}) {
  await page.goto('./');
  await page.evaluate(
    ({ token, onboarded }) => {
      localStorage.setItem('wardex_token', token);
      localStorage.removeItem('wardex_recent');
      localStorage.removeItem('wardex_saved_searches');
      localStorage.removeItem('wardex_pinned_sections');
      if (onboarded) {
        localStorage.setItem('wardex_onboarded', '1');
      } else {
        localStorage.removeItem('wardex_onboarded');
      }
    },
    { token, onboarded },
  );
  await page.reload({ waitUntil: 'load' });
  await expect(page.locator('.auth-badge')).toContainText('Connected');
  await expect(page.locator('.role-badge')).toContainText('admin');
}

export async function loginThroughForm(page, { token = TOKEN, onboarded = true } = {}) {
  await resetStoredSession(page, { onboarded });
  if (await page.locator('.auth-badge').filter({ hasText: 'Connected' }).count()) {
    await expect(page.locator('.role-badge')).toContainText('admin');
    return;
  }
  await page.getByLabel('API token').fill(token);
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('.auth-badge')).toContainText('Connected');
  await expect(page.locator('.role-badge')).toContainText('admin');
}

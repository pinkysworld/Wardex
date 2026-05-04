import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import CommandCenter from '../components/CommandCenter.jsx';
import { AuthProvider, RoleProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';

function jsonOk(data) {
  return {
    ok: true,
    status: 200,
    headers: { get: (header) => (header === 'content-type' ? 'application/json' : null) },
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location-probe">{`${location.pathname}${location.search}`}</div>;
}

function renderWithProviders(route = '/command') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <LocationProbe />
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>
              <CommandCenter />
            </ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function currentSearchParams() {
  const location = screen.getByTestId('location-probe').textContent || '/command';
  return new URL(`http://localhost${location}`).searchParams;
}

const COMMAND_FIXTURES = {
  commandSummary: {
    shift_board: {
      status: 'attention',
      active_owner: { name: 'analyst-1', work_items: 3 },
      open_incidents: 1,
      active_cases: 1,
      unassigned_cases: 1,
      unassigned_queue: 2,
      pending_approvals: 2,
      ready_to_execute: 1,
      sla_age_buckets: {
        under_1h: 1,
        between_1h_4h: 1,
        between_4h_24h: 0,
        over_24h: 0,
        breached: 1,
      },
      blockers: ['2 queue item(s) and 1 case(s) need an owner', '1 alert(s) breached SLA'],
      lanes: [
        {
          id: 'queue',
          label: 'Alert queue',
          owner: 'shift lead',
          open: 3,
          unassigned: 2,
          blockers: 3,
          next_action: 'Assign the oldest critical alert and confirm SLA pressure.',
          href: '/soc#queue',
        },
        {
          id: 'cases',
          label: 'Cases',
          owner: 'case lead',
          open: 1,
          unassigned: 1,
          blockers: 1,
          next_action: 'Assign open cases and capture unresolved questions.',
          href: '/soc#cases',
        },
      ],
    },
    metrics: {
      open_incidents: 1,
      active_cases: 1,
      pending_remediation_reviews: 1,
      connector_issues: 1,
      noisy_rules: 1,
      stale_rules: 0,
      release_candidates: 1,
      compliance_packs: 1,
    },
    lanes: {
      incidents: {
        annotation: 'Incident lane is ready for active operator review.',
        next_step: 'Use the SOC workspace to verify ownership and export readiness.',
        status: 'info',
      },
      connectors: {
        annotation: 'Connector evidence should stay tied to saved config and validation.',
        next_step: 'Validate the highest-risk ingestion lane before downstream handoffs.',
        status: 'warning',
        readiness: {
          collectors: [
            {
              provider: 'github',
              status: 'warning',
              detail: 'Sample GitHub audit proof is stale.',
              sample_event: 'git.push',
            },
          ],
        },
      },
      rule_tuning: {
        annotation: 'Replay debt is visible before any promotion decision.',
        next_step: 'Run replay against the noisiest active rule before widening rollout.',
        status: 'warning',
        review_calendar: {
          overdue: 1,
          due_this_week: 1,
          replay_blockers: 1,
          noisy_owners: 1,
          items: [
            {
              id: 'rule-ssh-burst',
              title: 'SSH burst',
              owner: 'detections',
              lifecycle: 'test',
              next_review_at: '2026-05-03T18:30:00Z',
              due_status: 'overdue',
              last_test_match_count: 6,
              active_suppressions: 1,
              promotion_blockers: ['replay_noise', 'suppression_review'],
              href: '/detection?rule=rule-ssh-burst&rulePanel=promotion',
            },
          ],
        },
      },
      release: {
        annotation: 'Release readiness stays tied to SBOM and rollback posture.',
        next_step: 'Review rollout evidence before any deploy handoff leaves the Command Center.',
        status: 'info',
      },
      remediation: {
        annotation: 'Rollback proof and approval quorum belong together.',
        next_step: 'Verify rollback proof before approving live execution.',
        status: 'warning',
      },
      evidence: {
        annotation: 'Evidence exports should reflect current operational truth.',
        next_step: 'Generate packs only after compliance and release context are current.',
        status: 'info',
      },
    },
  },
  incidents: [
    {
      id: 'incident-7',
      title: 'Credential storm on gateway',
      status: 'open',
      severity: 'critical',
      updated_at: '2026-05-02T09:00:00Z',
    },
  ],
  cases: [{ id: 'case-42', title: 'Gateway case', status: 'open' }],
  queueStats: { queued: 3 },
  responseStats: { active: 1 },
  remediationReviews: [
    {
      id: 'review-credential-storm-1',
      title: 'Gateway rollback review',
      asset_id: 'gateway-1',
      approval_status: 'pending_review',
      approvals: [{ reviewer: 'analyst-1' }],
      required_approvers: 2,
      rollback_proof: 'snapshot-1',
    },
  ],
  efficacySummary: { replay_backlog: 1 },
  contentRules: [
    {
      id: 'rule-ssh-burst',
      name: 'SSH burst',
      lifecycle: 'review',
      enabled: true,
      last_test_match_count: 6,
      last_test_at: '2026-05-01T18:30:00Z',
    },
  ],
  suppressions: [{ id: 'supp-1', rule_id: 'rule-ssh-burst' }],
  updatesReleases: [
    {
      version: '0.55.2',
      status: 'candidate',
      created_at: '2026-05-01T18:00:00Z',
      notes: 'Canary rollout is ready for analyst review.',
    },
  ],
  sbomData: { component_count: 12 },
  configData: { version: '0.56.0' },
  assistantStatus: {
    mode: 'retrieval-only',
    model: 'local-rag',
    provider: 'local',
    active_conversations: 1,
  },
  rbacUsers: [{ username: 'analyst-1', role: 'analyst', groups: ['soc-analysts'] }],
  complianceData: { status: 'warning' },
  reportTemplates: [
    {
      id: 'command-center-pack',
      name: 'Command Center Evidence Pack',
      kind: 'command_center_evidence',
      scope: 'global',
      format: 'json',
      audience: 'operations',
    },
  ],
};

function installCommandCenterFetchMock(tracker = {}) {
  globalThis.fetch = vi.fn((url, options = {}) => {
    const requestUrl = new URL(String(url), 'http://localhost');
    const { pathname } = requestUrl;
    const method = String(options.method || 'GET').toUpperCase();
    const body = options.body ? JSON.parse(options.body) : null;

    if (pathname === '/api/auth/check') return Promise.resolve(jsonOk({ authenticated: true }));
    if (pathname === '/api/auth/session') {
      return Promise.resolve(
        jsonOk({
          authenticated: true,
          role: 'analyst',
          groups: ['soc-analysts'],
          user_id: 'command-tester',
          source: 'session',
        }),
      );
    }
    if (pathname === '/api/command/summary') {
      tracker.commandSummaryCalls = (tracker.commandSummaryCalls || 0) + 1;
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.commandSummary));
    }
    if (pathname === '/api/incidents') return Promise.resolve(jsonOk(COMMAND_FIXTURES.incidents));
    if (pathname === '/api/cases') return Promise.resolve(jsonOk(COMMAND_FIXTURES.cases));
    if (pathname === '/api/queue/stats')
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.queueStats));
    if (pathname === '/api/response/stats')
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.responseStats));
    if (pathname === '/api/remediation/change-reviews') {
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.remediationReviews));
    }
    if (pathname === '/api/detection/efficacy/summary') {
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.efficacySummary));
    }
    if (pathname === '/api/content/rules')
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.contentRules));
    if (pathname === '/api/suppressions')
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.suppressions));
    if (pathname === '/api/updates/releases')
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.updatesReleases));
    if (pathname === '/api/sbom') return Promise.resolve(jsonOk(COMMAND_FIXTURES.sbomData));
    if (pathname === '/api/config/current')
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.configData));
    if (pathname === '/api/assistant/status')
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.assistantStatus));
    if (pathname === '/api/rbac/users') return Promise.resolve(jsonOk(COMMAND_FIXTURES.rbacUsers));
    if (pathname === '/api/compliance/status')
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.complianceData));
    if (pathname === '/api/report-templates')
      return Promise.resolve(jsonOk(COMMAND_FIXTURES.reportTemplates));

    if (pathname === '/api/collectors/github/config' && method === 'POST') {
      tracker.githubConfigBodies = [...(tracker.githubConfigBodies || []), body];
      return Promise.resolve(jsonOk({ status: 'saved', config: body }));
    }
    if (pathname === '/api/collectors/github/validate' && method === 'POST') {
      tracker.githubValidateCalls = (tracker.githubValidateCalls || 0) + 1;
      return Promise.resolve(jsonOk({ status: 'validated', sample_event_type: 'git.push' }));
    }

    if (
      pathname === '/api/remediation/change-reviews/review-credential-storm-1/approval' &&
      method === 'POST'
    ) {
      tracker.remediationApprovalBodies = [...(tracker.remediationApprovalBodies || []), body];
      return Promise.resolve(
        jsonOk({ status: 'approved', review_id: 'review-credential-storm-1' }),
      );
    }
    if (pathname === '/api/content/rules/rule-ssh-burst/test' && method === 'POST') {
      tracker.ruleReplayBodies = [...(tracker.ruleReplayBodies || []), body];
      return Promise.resolve(jsonOk({ status: 'completed', replay_hits: 6 }));
    }
    if (pathname === '/api/report-runs' && method === 'POST') {
      tracker.reportRunBodies = [...(tracker.reportRunBodies || []), body];
      return Promise.resolve(jsonOk({ id: 'run-1', status: 'queued' }));
    }

    return Promise.resolve(jsonOk({}));
  });
}

describe('CommandCenter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('wardex_token', 'command-token');
    installCommandCenterFetchMock();
  });

  it.each([
    ['connectors', 'Connector Validation'],
    ['remediation', 'Remediation Approval'],
    ['rules', 'Rule Replay and Promotion'],
    ['release', 'Release Readiness'],
    ['evidence', 'Compliance Evidence Pack'],
  ])('restores the %s drawer from the route and closes it cleanly', async (drawer, title) => {
    const user = userEvent.setup();
    const view = renderWithProviders(`/command?drawer=${drawer}`);

    expect(await screen.findByRole('dialog', { name: title })).toBeInTheDocument();
    expect(currentSearchParams().get('drawer')).toBe(drawer);

    await user.click(screen.getByRole('button', { name: 'Close' }));

    await waitFor(() => {
      expect(screen.queryByRole('dialog', { name: title })).not.toBeInTheDocument();
    });
    expect(currentSearchParams().has('drawer')).toBe(false);
    expect(screen.getByRole('heading', { name: /Operate incidents/i })).toBeInTheDocument();
    expect(screen.getAllByText('Credential storm on gateway').length).toBeGreaterThan(0);

    view.unmount();
  });

  it('opens each command drawer from lane trigger buttons and updates route state', async () => {
    const user = userEvent.setup();
    renderWithProviders('/command');

    expect(await screen.findByRole('heading', { name: /Operate incidents/i })).toBeInTheDocument();

    const drawerTriggers = [
      ['Validate connectors', 'Connector Validation', 'connectors'],
      ['Review changes', 'Remediation Approval', 'remediation'],
      ['Open checklist', 'Rule Replay and Promotion', 'rules'],
      ['Check readiness', 'Release Readiness', 'release'],
      ['Create evidence pack', 'Compliance Evidence Pack', 'evidence'],
    ];

    for (const [buttonName, dialogTitle, drawerParam] of drawerTriggers) {
      await user.click(screen.getByRole('button', { name: buttonName }));

      expect(await screen.findByRole('dialog', { name: dialogTitle })).toBeInTheDocument();
      expect(currentSearchParams().get('drawer')).toBe(drawerParam);

      await user.click(screen.getByRole('button', { name: 'Close' }));

      await waitFor(() => {
        expect(screen.queryByRole('dialog', { name: dialogTitle })).not.toBeInTheDocument();
      });
      expect(currentSearchParams().has('drawer')).toBe(false);
    }
  });

  it('renders the shift command board with ownership, blockers, and lane next actions', async () => {
    renderWithProviders('/command');

    expect(await screen.findByRole('heading', { name: /Keep ownership/i })).toBeInTheDocument();
    expect(screen.getAllByText('analyst-1').length).toBeGreaterThan(0);
    expect(screen.getByText('1 alert(s) breached SLA')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Alert queue' })).toHaveAttribute('href', '/soc#queue');
    expect(
      screen.getByText('Assign the oldest critical alert and confirm SLA pressure.'),
    ).toBeInTheDocument();
  });

  it('surfaces compact detection review calendar signals with a pivot into detection', async () => {
    renderWithProviders('/command');

    expect((await screen.findAllByText('Detection Quality Dashboard')).length).toBeGreaterThan(0);
    expect(screen.getByText('Overdue reviews')).toBeInTheDocument();
    expect(screen.getByText('Owners under noise')).toBeInTheDocument();
    expect(screen.getAllByText('SSH burst').length).toBeGreaterThan(0);
    expect(screen.getByText('detections • test • overdue')).toBeInTheDocument();
    expect(
      screen.getByText('2 blocker(s) • 6 replay hits • 1 suppression(s)'),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /SSH burst/ })).toHaveAttribute(
      'href',
      '/detection?rule=rule-ssh-burst&rulePanel=promotion',
    );
  });

  it('saves and validates GitHub connector drafts with settings handoff and reloads command data', async () => {
    const tracker = {};
    const user = userEvent.setup();

    installCommandCenterFetchMock(tracker);
    renderWithProviders('/command');

    expect(await screen.findByRole('heading', { name: /Operate incidents/i })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'GitHub Audit Log' }));

    const drawer = await screen.findByRole('dialog', { name: 'Connector Validation' });
    expect(within(drawer).getByRole('link', { name: 'Open settings' })).toHaveAttribute(
      'href',
      '/settings',
    );

    const initialCommandSummaryCalls = tracker.commandSummaryCalls || 0;

    await user.click(within(drawer).getByRole('button', { name: 'Save setup draft' }));

    expect(await screen.findByText('Setup draft saved')).toBeInTheDocument();
    expect(tracker.githubConfigBodies).toEqual([
      {
        enabled: true,
        organization: 'example-org',
        token_ref: 'vault://wardex/github-audit-token',
        poll_interval_secs: 300,
      },
    ]);

    await waitFor(() => {
      expect(tracker.commandSummaryCalls).toBeGreaterThan(initialCommandSummaryCalls);
    });

    const afterSaveCommandSummaryCalls = tracker.commandSummaryCalls;

    await user.click(within(drawer).getByRole('button', { name: 'Validate now' }));

    expect(await screen.findByText('Validation complete')).toBeInTheDocument();
    expect(tracker.githubValidateCalls).toBe(1);

    await waitFor(() => {
      expect(tracker.commandSummaryCalls).toBeGreaterThan(afterSaveCommandSummaryCalls);
    });

    await user.click(screen.getByRole('button', { name: 'Close' }));
    await user.click(screen.getByRole('button', { name: 'AWS CloudTrail' }));

    const awsDrawer = await screen.findByRole('dialog', { name: 'Connector Validation' });
    expect(within(awsDrawer).getByRole('link', { name: 'Open settings' })).toHaveAttribute(
      'href',
      '/settings?settingsTab=collectors&collector=aws',
    );
  });

  it('approves remediation reviews and preserves infrastructure handoffs while reloading command data', async () => {
    const tracker = {};
    const user = userEvent.setup();

    installCommandCenterFetchMock(tracker);
    renderWithProviders('/command?drawer=remediation');

    const remediationDrawer = await screen.findByRole('dialog', { name: 'Remediation Approval' });
    expect(
      within(remediationDrawer).getByRole('link', { name: 'Open infrastructure' }),
    ).toHaveAttribute('href', '/infrastructure');

    const initialCommandSummaryCalls = tracker.commandSummaryCalls || 0;

    await user.click(within(remediationDrawer).getByRole('button', { name: 'Approve' }));

    expect(await screen.findByText('Approval recorded')).toBeInTheDocument();
    expect(tracker.remediationApprovalBodies).toEqual([
      {
        decision: 'approve',
        comment: 'Reviewed in Command Center.',
      },
    ]);

    await waitFor(() => {
      expect(tracker.commandSummaryCalls).toBeGreaterThan(initialCommandSummaryCalls);
    });

    await user.click(screen.getByRole('button', { name: 'Close' }));
    await user.click(screen.getByRole('button', { name: 'Check readiness' }));

    const releaseDrawer = await screen.findByRole('dialog', { name: 'Release Readiness' });
    expect(within(releaseDrawer).getByRole('link', { name: 'Open rollouts' })).toHaveAttribute(
      'href',
      '/infrastructure',
    );
  });

  it('runs rule replay and creates evidence packs with downstream handoffs and reloads', async () => {
    const tracker = {};
    const user = userEvent.setup();

    installCommandCenterFetchMock(tracker);
    renderWithProviders('/command?drawer=rules');

    const rulesDrawer = await screen.findByRole('dialog', { name: 'Rule Replay and Promotion' });
    expect(within(rulesDrawer).getByRole('link', { name: 'Promotion view' })).toHaveAttribute(
      'href',
      '/detection?rule=rule-ssh-burst&panel=promotion',
    );

    const initialCommandSummaryCalls = tracker.commandSummaryCalls || 0;

    await user.click(within(rulesDrawer).getByRole('button', { name: 'Run replay' }));

    expect(await screen.findByText('Replay complete')).toBeInTheDocument();
    expect(tracker.ruleReplayBodies).toEqual([{ source: 'command_center' }]);

    await waitFor(() => {
      expect(tracker.commandSummaryCalls).toBeGreaterThan(initialCommandSummaryCalls);
    });

    const afterReplayCommandSummaryCalls = tracker.commandSummaryCalls;

    await user.click(screen.getByRole('button', { name: 'Close' }));
    await user.click(screen.getByRole('button', { name: 'Create evidence pack' }));

    const evidenceDrawer = await screen.findByRole('dialog', { name: 'Compliance Evidence Pack' });
    expect(within(evidenceDrawer).getByRole('link', { name: 'Open reports' })).toHaveAttribute(
      'href',
      '/reports',
    );

    await user.click(within(evidenceDrawer).getByRole('button', { name: 'Create evidence pack' }));

    expect(await screen.findByText('Evidence pack queued')).toBeInTheDocument();
    expect(tracker.reportRunBodies).toHaveLength(1);
    expect(tracker.reportRunBodies[0]).toMatchObject({
      name: 'Command Center Evidence Pack',
      kind: 'command_center_evidence',
      scope: 'global',
      format: 'json',
      audience: 'operations',
      source: 'command_center',
      summary: 'Evidence pack generated from Command Center lane health.',
    });

    await waitFor(() => {
      expect(tracker.commandSummaryCalls).toBeGreaterThan(afterReplayCommandSummaryCalls);
    });
  });
});

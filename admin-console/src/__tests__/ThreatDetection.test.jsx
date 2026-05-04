import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import ThreatDetection from '../components/ThreatDetection.jsx';
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

function RoutedTestHost() {
  return (
    <>
      <LocationProbe />
      <Routes>
        <Route path="/detection" element={<ThreatDetection />} />
        <Route path="/settings" element={<div data-testid="route-target">settings</div>} />
        <Route path="/soc" element={<div data-testid="route-target">soc</div>} />
      </Routes>
    </>
  );
}

function renderWithProviders(route = '/detection', options = {}) {
  const { useRoutes = false } = options;
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <ThemeProvider>
          <ToastProvider>
            {useRoutes ? (
              <RoutedTestHost />
            ) : (
              <>
                <LocationProbe />
                <ThreatDetection />
              </>
            )}
          </ToastProvider>
        </ThemeProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function currentLocation() {
  return new URL(
    screen.getByTestId('location-probe').textContent || '/detection',
    'http://localhost',
  );
}

function currentSearchParams() {
  return currentLocation().searchParams;
}

const THREAT_FIXTURES = {
  detectionProfile: {
    active_rules: 1,
    draft_rules: 0,
    last_updated_at: '2024-01-01T00:00:00Z',
  },
  detectionSummary: {
    rule_count: 1,
    pack_count: 1,
    hunt_count: 1,
  },
  detectionWeights: {
    weights: {
      'rule-1': 0.5,
    },
  },
  rules: [
    {
      id: 'rule-1',
      title: 'Suspicious PowerShell',
      description: 'PowerShell execution with credential access patterns.',
      lifecycle: 'test',
      version: 2,
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
      last_promotion_at: '2024-01-03T00:00:00Z',
      lifecycle_history: [
        {
          changed_at: '2024-01-02T00:00:00Z',
          changed_by: 'threat-tester',
          from: 'draft',
          to: 'test',
          reason: 'Replay corpus passed for canary rollout.',
        },
      ],
    },
  ],
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
  efficacySummary: {
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
    best_rules: [],
    by_severity: {
      high: {
        total: 10,
        tp_rate: 0.7,
        fp_rate: 0.2,
        mean_triage_secs: 160,
      },
    },
  },
  replayCorpus: {
    status: 'ready',
    summary: {
      total_samples: 6,
      precision: 0.83,
      recall: 0.75,
      false_positive_rate: 0.2,
    },
    acceptance_targets: {
      precision_min: 0.7,
      recall_min: 0.7,
      false_positive_rate_max: 0.35,
    },
    categories: [
      {
        id: 'benign_admin',
        label: 'Benign admin activity',
        expected: 'benign',
        predicted: 'benign',
        score: 1.2,
        confidence: 0.8,
        passed: true,
        platform: 'linux',
        platform_label: 'Linux',
        signal_type: 'admin_activity',
        signal_type_label: 'Admin Activity',
      },
      {
        id: 'lateral_movement',
        label: 'Lateral movement',
        expected: 'malicious',
        predicted: 'malicious',
        score: 7.8,
        confidence: 0.91,
        passed: true,
        platform: 'windows',
        platform_label: 'Windows',
        signal_type: 'lateral_movement',
        signal_type_label: 'Lateral Movement',
      },
    ],
    platform_deltas: [
      {
        id: 'linux',
        label: 'Linux',
        sample_count: 3,
        passed_samples: 3,
        failed_samples: 0,
        delta: { precision: 0.05, recall: 0.08, false_positive_rate: -0.04 },
      },
      {
        id: 'windows',
        label: 'Windows',
        sample_count: 3,
        passed_samples: 2,
        failed_samples: 1,
        delta: { precision: -0.08, recall: -0.05, false_positive_rate: 0.06 },
        failed_examples: ['Credential theft and lateral movement'],
      },
    ],
    signal_type_deltas: [
      {
        id: 'admin_activity',
        label: 'Admin Activity',
        sample_count: 1,
        passed_samples: 1,
        failed_samples: 0,
        delta: { precision: 0.02, recall: 0.0, false_positive_rate: -0.02 },
      },
      {
        id: 'lateral_movement',
        label: 'Lateral Movement',
        sample_count: 1,
        passed_samples: 1,
        failed_samples: 0,
        delta: { precision: 0.03, recall: 0.04, false_positive_rate: -0.01 },
      },
    ],
  },
  ruleEfficacy: {
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
  mitreCoverage: {
    covered_techniques: 14,
    coverage_pct: 61,
  },
  coverageGaps: {
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
      {
        tactic: 'credential-access',
        total: 4,
        covered: 1,
        uncovered: 3,
        pct: 25,
        gap_ids: ['T1003'],
      },
      {
        tactic: 'execution',
        total: 5,
        covered: 2,
        uncovered: 3,
        pct: 40,
        gap_ids: ['T1059'],
      },
    ],
    top_recommendations: [
      '[T1059] Command and Scripting Interpreter: Add Sigma rules for command-line interpreter usage',
    ],
  },
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
  investigationSuggestions: [
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
  canaryPromotionResults: [
    {
      rule_id: 'rule-1',
      rule_name: 'Suspicious PowerShell',
      action: 'promoted',
      reason: '12 alerts, 0 FPs, canary duration satisfied',
    },
  ],
  workbenchOverview: {
    rollouts: {
      canary_rules: 1,
      canary_hunts: 1,
      promotion_ready_rules: 1,
      active_hunts: 0,
      rollout_targets: 1,
      average_canary_percentage: 10,
      historical_events: 3,
      rollback_events: 1,
      last_rollout_at: '2024-01-03T00:00:00Z',
      recent_history: [
        {
          id: 'rollout-1',
          action: 'content-promote',
          version: 'Suspicious PowerShell v2',
          platform: 'content-rule',
          agent_id: 'rule-1',
          rollout_group: 'canary',
          status: 'succeeded',
          requested_by: 'threat-tester',
          notes: 'Rule rule-1 moved from draft to canary: Replay corpus passed for canary rollout.',
          recorded_at: '2024-01-03T00:00:00Z',
        },
        {
          id: 'rollout-2',
          action: 'content-rollback',
          version: 'Retired Identity Rule v4',
          platform: 'content-rule',
          agent_id: 'rule-2',
          rollout_group: 'test',
          status: 'succeeded',
          requested_by: 'threat-tester',
          notes: 'Rule rule-2 rolled back from canary to test.',
          recorded_at: '2024-01-01T00:00:00Z',
        },
      ],
    },
  },
};

function installThreatDetectionFetchMock(tracker = {}) {
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
          user_id: 'threat-tester',
          source: 'session',
        }),
      );
    }
    if (pathname === '/api/detection/profile') {
      return Promise.resolve(jsonOk(THREAT_FIXTURES.detectionProfile));
    }
    if (pathname === '/api/detection/summary') {
      return Promise.resolve(jsonOk(THREAT_FIXTURES.detectionSummary));
    }
    if (pathname === '/api/detection/replay-corpus' && method === 'POST') {
      tracker.replayBodies = [...(tracker.replayBodies || []), body];
      return Promise.resolve(jsonOk(THREAT_FIXTURES.replayCorpus));
    }
    if (pathname === '/api/detection/replay-corpus') {
      return Promise.resolve(jsonOk(THREAT_FIXTURES.replayCorpus));
    }
    if (pathname === '/api/workbench/overview') {
      tracker.workbenchOverviewCalls = (tracker.workbenchOverviewCalls || 0) + 1;
      return Promise.resolve(jsonOk(THREAT_FIXTURES.workbenchOverview));
    }
    if (pathname === '/api/efficacy/summary') {
      return Promise.resolve(jsonOk(THREAT_FIXTURES.efficacySummary));
    }
    if (pathname === '/api/efficacy/canary-promote' && method === 'POST') {
      tracker.canaryPromoteCalls = (tracker.canaryPromoteCalls || 0) + 1;
      return Promise.resolve(jsonOk(THREAT_FIXTURES.canaryPromotionResults));
    }
    if (pathname === '/api/detection/weights') {
      return Promise.resolve(jsonOk(THREAT_FIXTURES.detectionWeights));
    }
    if (pathname === '/api/content/rules') {
      tracker.contentRuleCalls = (tracker.contentRuleCalls || 0) + 1;
      return Promise.resolve(jsonOk({ rules: THREAT_FIXTURES.rules }));
    }
    if (pathname === '/api/content/packs') {
      return Promise.resolve(jsonOk({ packs: THREAT_FIXTURES.packs }));
    }
    if (pathname === '/api/hunts' && method === 'POST') {
      tracker.huntBodies = [...(tracker.huntBodies || []), body];
      return Promise.resolve(jsonOk({ id: body?.id || 'hunt-1', status: 'saved' }));
    }
    if (pathname === '/api/hunts') {
      return Promise.resolve(jsonOk({ hunts: THREAT_FIXTURES.hunts }));
    }
    if (pathname === '/api/hunts/hunt-1/run' && method === 'POST') {
      tracker.runHuntBodies = [...(tracker.runHuntBodies || []), body];
      return Promise.resolve(
        jsonOk({
          matches: [{ hostname: 'host-9', agent_id: 'agent-9', score: 0.92 }],
          total: 1,
        }),
      );
    }
    if (pathname === '/api/cases' && method === 'POST') {
      tracker.caseBodies = [...(tracker.caseBodies || []), body];
      return Promise.resolve(jsonOk({ id: 88, status: 'created' }));
    }
    if (pathname === '/api/efficacy/rule/rule-1') {
      return Promise.resolve(jsonOk(THREAT_FIXTURES.ruleEfficacy));
    }
    if (pathname === '/api/coverage/mitre') {
      return Promise.resolve(jsonOk(THREAT_FIXTURES.mitreCoverage));
    }
    if (pathname === '/api/coverage/gaps') {
      return Promise.resolve(jsonOk(THREAT_FIXTURES.coverageGaps));
    }
    if (pathname === '/api/suppressions') {
      return Promise.resolve(jsonOk({ suppressions: [] }));
    }
    if (pathname === '/api/investigations/suggest') {
      return Promise.resolve(jsonOk({ suggestions: THREAT_FIXTURES.investigationSuggestions }));
    }

    return Promise.resolve(jsonOk({}));
  });
}

describe('ThreatDetection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('wardex_token', 'threat-token');
    installThreatDetectionFetchMock();
  });

  it('restores workspace and rule drilldowns from the route and keeps them URL-backed', async () => {
    renderWithProviders('/detection?panel=rollout&rulePanel=hunts&rule=rule-1&queue=noisy');

    const rolloutFocus = await screen.findByRole('button', { name: 'Pack Rollout' });
    expect(rolloutFocus.className).toContain('active');

    const huntsPanel = screen.getByRole('button', { name: 'Hunts & Investigations' });
    expect(huntsPanel.className).toContain('active');

    expect(await screen.findByText('Hunts and Investigations')).toBeInTheDocument();
    expect(await screen.findByText('Edit Primary Bundle')).toBeInTheDocument();
    expect(screen.getByText('URL-backed drilldown focus')).toBeInTheDocument();

    expect(currentSearchParams().get('panel')).toBe('rollout');
    expect(currentSearchParams().get('rulePanel')).toBe('hunts');
    expect(currentSearchParams().get('rule')).toBe('rule-1');

    fireEvent.click(screen.getByRole('button', { name: 'ATT&CK Gaps' }));
    await waitFor(() => {
      expect(currentSearchParams().get('panel')).toBe('coverage');
      expect(currentSearchParams().get('rule')).toBe('rule-1');
    });

    fireEvent.click(screen.getByRole('button', { name: 'Promotion' }));
    await waitFor(() => {
      expect(currentSearchParams().get('rulePanel')).toBe('promotion');
      expect(currentSearchParams().get('rule')).toBe('rule-1');
    });
  });

  it('hydrates hunt drilldowns from route intent without losing the seeded query state', async () => {
    renderWithProviders(
      '/detection?rule=rule-1&rulePanel=hunts&intent=run-hunt&huntQuery=hostname:gateway-7&huntName=Gateway%20Hunt',
    );

    expect(await screen.findByText('Latest Hunt Result')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByLabelText('Hunt Name')).toHaveValue('Gateway Hunt');
      expect(screen.getByLabelText('Query')).toHaveValue('hostname:gateway-7');
    });

    expect(currentSearchParams().get('intent')).toBe('run-hunt');
    expect(currentSearchParams().get('huntQuery')).toBe('hostname:gateway-7');
    expect(currentSearchParams().get('huntName')).toBe('Gateway Hunt');
  });

  it('renders efficacy, ATT&CK gap, suppression, and rollout drilldowns', async () => {
    renderWithProviders('/detection?panel=efficacy&rulePanel=efficacy');

    expect(await screen.findByText('Detection Efficacy Drilldown')).toBeInTheDocument();
    expect(await screen.findByText('Suppression Noise Signals')).toBeInTheDocument();
    expect(await screen.findByText('Content Pack Rollout Signals')).toBeInTheDocument();
    expect((await screen.findAllByText('Rule Efficacy')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('T1003 • OS Credential Dumping')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Degrading')).length).toBeGreaterThan(0);
  });

  it('runs replay validation and surfaces the latest replay corpus deltas', async () => {
    const tracker = {};
    installThreatDetectionFetchMock(tracker);

    renderWithProviders('/detection');

    expect(await screen.findByText('Replay validation runner')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Run Replay Validation' }));

    await waitFor(() => {
      expect(tracker.replayBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            source: 'retained_events',
            threshold: 2,
            limit: 100,
          }),
        ]),
      );
    });

    expect(await screen.findByText('Latest validation platform deltas')).toBeInTheDocument();
    expect((await screen.findAllByText('Platform deltas')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Signal-type deltas')).length).toBeGreaterThan(0);
  });

  it('surfaces rollout history, distribution analytics, and refreshed lifecycle evidence', async () => {
    const tracker = {};
    installThreatDetectionFetchMock(tracker);

    renderWithProviders('/detection?panel=rollout&rule=rule-1&rulePanel=promotion');

    expect(await screen.findByText('Content Pack Rollout Signals')).toBeInTheDocument();
    expect(screen.getByText('Lifecycle Distribution')).toBeInTheDocument();
    expect(screen.getByText('Target Group Distribution')).toBeInTheDocument();
    expect(screen.getByText('Recent Rollout Activity')).toBeInTheDocument();
    expect(screen.getByText('Lifecycle Evidence')).toBeInTheDocument();
    expect(screen.getAllByText('soc-analysts').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Rule Promotion').length).toBeGreaterThan(0);
    expect(
      screen.getAllByText(
        'Rule rule-1 moved from draft to canary: Replay corpus passed for canary rollout.',
      ).length,
    ).toBeGreaterThan(0);
    expect(screen.getByText('Draft -> Test')).toBeInTheDocument();
    expect(currentSearchParams().get('panel')).toBe('rollout');
    expect(currentSearchParams().get('rulePanel')).toBe('promotion');

    const initialOverviewCalls = tracker.workbenchOverviewCalls || 0;
    fireEvent.click(screen.getByRole('button', { name: 'Run Canary Auto-Promotion' }));

    await waitFor(() => {
      expect(tracker.canaryPromoteCalls).toBe(1);
      expect(tracker.workbenchOverviewCalls).toBeGreaterThan(initialOverviewCalls);
    });
  });

  it('runs canary auto-promotion from the promotion panel and surfaces lifecycle analytics', async () => {
    const tracker = {};
    installThreatDetectionFetchMock(tracker);

    renderWithProviders('/detection?rule=rule-1&rulePanel=promotion');

    expect(await screen.findByText('Promotion checklist')).toBeInTheDocument();
    expect(currentSearchParams().get('rulePanel')).toBe('promotion');

    const initialRuleCalls = tracker.contentRuleCalls || 0;

    fireEvent.click(screen.getByRole('button', { name: 'Run Canary Auto-Promotion' }));

    await waitFor(() => {
      expect(tracker.canaryPromoteCalls).toBe(1);
      expect(tracker.contentRuleCalls).toBeGreaterThan(initialRuleCalls);
    });

    const automationCard = screen.getByText('Canary Rollout Automation').closest('.card');
    expect(automationCard).toBeTruthy();
    expect(
      within(automationCard).getByText('12 alerts, 0 FPs, canary duration satisfied'),
    ).toBeInTheDocument();
    expect(within(automationCard).getByText('Promoted')).toBeInTheDocument();
  });

  it('pivots retained-event replay context into long-retention search', async () => {
    renderWithProviders('/detection', { useRoutes: true });

    expect(await screen.findByText('Replay validation runner')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Retained Limit'), { target: { value: '42' } });
    fireEvent.click(screen.getByRole('button', { name: 'Open retained events' }));

    await waitFor(() => {
      const location = currentLocation();
      expect(location.pathname).toBe('/settings');
      expect(location.searchParams.get('tab')).toBe('admin');
      expect(location.searchParams.get('historical_limit')).toBe('42');
    });
  });

  it('preserves the saved hunt id when reopening an existing hunt without reapplying run intent', async () => {
    const tracker = {};
    installThreatDetectionFetchMock(tracker);

    renderWithProviders('/detection?rulePanel=hunts');

    const huntName = (await screen.findAllByText('Credential Storm Hunt')).find(
      (element) => element.className === 'row-primary',
    );
    expect(huntName).toBeTruthy();
    const huntRow = huntName.parentElement?.parentElement;
    expect(huntRow).toBeTruthy();

    fireEvent.click(within(huntRow).getByText('Open'));

    expect(await screen.findByLabelText('Hunt Name')).toHaveValue('Credential Storm Hunt');
    expect(screen.getByLabelText('Query')).toHaveValue('credential');
    expect(currentSearchParams().get('intent')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Save Hunt' }));

    await waitFor(() => {
      expect(tracker.huntBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'hunt-1',
            name: 'Credential Storm Hunt',
          }),
        ]),
      );
    });
  });

  it('routes saved-hunt response pivots through the SOC response view', async () => {
    renderWithProviders('/detection?rulePanel=hunts', { useRoutes: true });

    const huntName = (await screen.findAllByText('Credential Storm Hunt')).find(
      (element) => element.className === 'row-primary',
    );
    expect(huntName).toBeTruthy();
    const huntRow = huntName.parentElement?.parentElement;
    expect(huntRow).toBeTruthy();

    fireEvent.click(within(huntRow).getByText('Run'));
    expect(await screen.findByText('Latest Hunt Result')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Open Response' }));

    await waitFor(() => {
      const location = currentLocation();
      expect(location.pathname).toBe('/soc');
      expect(location.hash).toBe('#response');
      expect(location.searchParams.get('source')).toBe('hunt');
      expect(location.searchParams.get('target')).toBe('host-9');
    });
  });

  it('promotes current hunt results into cases from the hunt drawer', async () => {
    const tracker = {};
    installThreatDetectionFetchMock(tracker);

    renderWithProviders('/detection?rulePanel=hunts', { useRoutes: true });

    const huntName = (await screen.findAllByText('Credential Storm Hunt')).find(
      (element) => element.className === 'row-primary',
    );
    expect(huntName).toBeTruthy();
    const huntRow = huntName.parentElement?.parentElement;
    expect(huntRow).toBeTruthy();

    fireEvent.click(within(huntRow).getByText('Run'));
    expect(await screen.findByText('Latest Hunt Result')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Promote to Case' }));

    await waitFor(() => {
      expect(tracker.caseBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            priority: 'high',
            title: 'Hunt Suspicious PowerShell',
          }),
        ]),
      );
    });

    await waitFor(() => {
      const location = currentLocation();
      expect(location.pathname).toBe('/soc');
      expect(location.hash).toBe('#cases');
      expect(location.searchParams.get('case')).toBe('88');
      expect(location.searchParams.get('source')).toBe('hunt');
    });
  }, 10000);
});

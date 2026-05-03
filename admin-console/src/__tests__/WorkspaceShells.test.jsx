import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { AuthProvider, ToastProvider, ThemeProvider } from '../hooks.jsx';
import ThreatDetection from '../components/ThreatDetection.jsx';
import SOCWorkbench from '../components/SOCWorkbench.jsx';
import Infrastructure from '../components/Infrastructure.jsx';
import ReportsExports from '../components/ReportsExports.jsx';
import HelpDocs from '../components/HelpDocs.jsx';

globalThis.fetch = vi.fn();

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location-probe">{`${location.pathname}${location.search}${location.hash}`}</div>;
}

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
          action_hint: 'Review IdP and SCIM mappings before widening automated response coverage.',
        },
      ],
    });
  if (String(url).includes('/api/detection/replay-corpus'))
    return jsonResponse({
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
  if (String(url).includes('/api/ws/stats'))
    return jsonResponse({ connected_subscribers: 2, events_emitted: 14 });
  if (String(url).includes('/api/rbac/users')) return jsonResponse({ users: [] });
  if (String(url).includes('/api/correlation/campaigns')) return jsonResponse({ campaigns: [] });
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
      <LocationProbe />
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
    expect(await screen.findByText('Replay Corpus Gate')).toBeInTheDocument();
    expect(await screen.findByText('Replay validation runner')).toBeInTheDocument();
    expect((await screen.findAllByText('Platform deltas')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Signal-type deltas')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Linux')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Admin Activity')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Benign admin activity')).length).toBeGreaterThan(0);
    expect(await screen.findByText('Automation Target')).toBeInTheDocument();
    expect(await screen.findByText('Route-backed rule panel')).toBeInTheDocument();
  });

  it('renders the SOC workbench program overview', async () => {
    renderWithProviders(<SOCWorkbench />, '/soc');
    expect(await screen.findByText('Recommendation Queue')).toBeInTheDocument();
    expect((await screen.findAllByText('Complete identity routing')).length).toBeGreaterThan(0);
    expect(await screen.findByText('Historical Runs')).toBeInTheDocument();
  });

  it('pivots rollout history into long-retention search', async () => {
    renderWithProviders(<SOCWorkbench />, '/soc');

    expect(await screen.findByText('Recommendation Queue')).toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: 'Open retained events' }));

    await waitFor(() => {
      const currentUrl = new URL(
        screen.getByTestId('location-probe').textContent || '/',
        'http://localhost',
      );
      expect(currentUrl.pathname).toBe('/settings');
      expect(currentUrl.searchParams.get('tab')).toBe('admin');
      expect(currentUrl.searchParams.get('historical_device_id')).toBe('agent-1');
      expect(currentUrl.searchParams.get('historical_since')).toBe('2024-01-01T01:00:00Z');
      expect(currentUrl.searchParams.get('historical_limit')).toBe('25');
    });
  });

  it('does not seed device filters from content-rule rollout history', async () => {
    globalThis.fetch.mockImplementation((url) => {
      if (String(url).includes('/api/workbench/overview')) {
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
                requested_by: 'analyst-1',
                notes: 'Rule rule-1 moved from draft to canary.',
                recorded_at: '2024-01-03T00:00:00Z',
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
            recent_history: [],
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
              action_hint: 'Review IdP and SCIM mappings before widening automated response coverage.',
            },
          ],
        });
      }

      return defaultFetchImplementation(url);
    });

    renderWithProviders(<SOCWorkbench />, '/soc');

    expect(await screen.findByText('Recommendation Queue')).toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: 'Open retained events' }));

    await waitFor(() => {
      const currentUrl = new URL(
        screen.getByTestId('location-probe').textContent || '/',
        'http://localhost',
      );
      expect(currentUrl.pathname).toBe('/settings');
      expect(currentUrl.searchParams.get('tab')).toBe('admin');
      expect(currentUrl.searchParams.get('historical_device_id')).toBeNull();
      expect(currentUrl.searchParams.get('historical_since')).toBe('2024-01-03T00:00:00Z');
      expect(currentUrl.searchParams.get('historical_limit')).toBe('25');
    });
  });

  it('renders the infrastructure explorer shell', async () => {
    renderWithProviders(<Infrastructure />, '/infrastructure');
    expect(await screen.findByText('Attention Queues')).toBeInTheDocument();
  });

  it('renders the report center shell', async () => {
    renderWithProviders(<ReportsExports />, '/reports');
    expect(await screen.findByText('Report Center')).toBeInTheDocument();
  });
});

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

beforeEach(() => {
  vi.clearAllMocks();
  globalThis.fetch.mockImplementation(async (url) => ({
    ok: true,
    headers: { get: () => 'application/json' },
    json: async () => {
      if (String(url).includes('/api/content/rules'))
        return {
          rules: [
            {
              id: 'rule-1',
              title: 'Suspicious PowerShell',
              description: 'PowerShell execution with credential access patterns.',
              lifecycle: 'test',
              enabled: true,
              attack: [],
              owner: 'secops',
              pack_ids: ['identity-attacks'],
              last_test_match_count: 2,
            },
          ],
        };
      if (String(url).includes('/api/content/packs'))
        return {
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
            },
          ],
        };
      if (String(url).includes('/api/hunts'))
        return {
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
        };
      if (String(url).includes('/api/investigation/suggest'))
        return {
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
        };
      if (String(url).includes('/api/workbench/overview'))
        return {
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
        };
      if (String(url).includes('/api/report-templates'))
        return {
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
        };
      if (String(url).includes('/api/inbox')) return { items: [] };
      return {};
    },
  }));
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

  it('renders the SOC workbench program overview', async () => {
    renderWithProviders(<SOCWorkbench />, '/soc');
    expect(await screen.findByText('Recommendation Queue')).toBeInTheDocument();
    expect((await screen.findAllByText('Complete identity routing')).length).toBeGreaterThan(0);
    expect(await screen.findByText('Historical Runs')).toBeInTheDocument();
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

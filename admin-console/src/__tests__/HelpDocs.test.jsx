import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, useLocation } from 'react-router-dom';
import HelpDocs from '../components/HelpDocs.jsx';
import { AuthProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';

function jsonOk(data) {
  return {
    ok: true,
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location-probe">{`${location.pathname}${location.search}`}</div>;
}

function renderWithProviders(route = '/help') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <ThemeProvider>
          <ToastProvider>
            <LocationProbe />
            <HelpDocs />
          </ToastProvider>
        </ThemeProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function currentLocation() {
  return new URL(screen.getByTestId('location-probe').textContent || '/', 'http://localhost');
}

describe('HelpDocs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    let failoverDrill = {
      drill_type: 'warm_standby_restore_dry_run',
      orchestration_scope: 'standalone_reference',
      status: 'not_run',
      last_run_at: null,
      actor: null,
      summary: 'No automated failover drill has been recorded yet.',
      artifact_source: 'none',
      durable_storage_verified: false,
      backup_artifact_verified: false,
      checkpoint_artifact_verified: false,
    };
    globalThis.fetch = vi.fn((url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const path = parsed.pathname;
      const method = options.method || 'GET';
      const docs = [
        {
          path: 'runbooks/deployment.md',
          title: 'Deployment & Upgrade Runbook',
          section: 'runbooks',
          kind: 'runbook',
          tags: ['deployment', 'runbooks'],
          summary: 'Deploy and upgrade Wardex safely.',
          headings: ['Deployment & Upgrade Runbook', 'Prerequisites'],
        },
        {
          path: 'SDK_GUIDE.md',
          title: 'SDK Guide',
          section: 'api',
          kind: 'guide',
          tags: ['api', 'guides'],
          summary: 'Use generated Python and TypeScript SDKs.',
          headings: ['SDK Guide', 'TypeScript SDK'],
        },
      ];

      if (path === '/api/endpoints') {
        return Promise.resolve(
          jsonOk([
            {
              method: 'GET',
              path: '/api/support/parity',
              auth: true,
              description: 'API, SDK, and GraphQL parity diagnostics',
            },
            {
              method: 'POST',
              path: '/api/graphql',
              auth: true,
              description: 'Execute GraphQL queries',
            },
          ]),
        );
      }
      if (path === '/api/research-tracks') return Promise.resolve(jsonOk({ tracks: [] }));
      if (path === '/api/openapi.json') {
        return Promise.resolve(
          jsonOk({
            info: { title: 'Wardex API', version: '0.53.1-local' },
            paths: {
              '/api/support/parity': {
                get: { summary: 'API, SDK, and GraphQL parity diagnostics' },
              },
              '/api/graphql': { post: { summary: 'Execute GraphQL queries' } },
            },
            components: { schemas: { Status: {}, Error: {} } },
          }),
        );
      }
      if (path === '/api/host/info') return Promise.resolve(jsonOk({ hostname: 'wardex-host' }));
      if (path === '/api/status') return Promise.resolve(jsonOk({ version: '0.53.1-local' }));
      if (path === '/api/inbox') return Promise.resolve(jsonOk({ items: [] }));
      if (path === '/api/manager/overview') {
        return Promise.resolve(
          jsonOk({ queue: { pending: 2 }, automation: { active_investigations: 1 } }),
        );
      }
      if (path === '/api/support/diagnostics') {
        return Promise.resolve(
          jsonOk({
            bundle: {
              operations: {
                request_count: 12,
                error_count: 1,
                queue_depth: 3,
                event_count: 44,
              },
            },
          }),
        );
      }
      if (path === '/api/support/parity') {
        return Promise.resolve(
          jsonOk({
            runtime: { version: '0.53.1-local' },
            rest: {
              openapi_version: '0.53.1-local',
              openapi_path_count: 2,
              endpoint_catalog_count: 2,
            },
            graphql: { types: 6, root_fields: ['alerts', 'status'] },
            sdk: {
              python: { version: '0.53.0' },
              typescript: { version: '0.53.0' },
            },
            report_workflow: {
              aligned: true,
              required_operations: [
                'GET /api/report-templates',
                'POST /api/report-templates',
                'GET /api/report-runs',
                'POST /api/report-runs',
                'GET /api/report-schedules',
                'POST /api/report-schedules',
              ],
              required_sdk_endpoints: [
                '/api/report-templates',
                '/api/report-runs',
                '/api/report-schedules',
              ],
              runtime_routes: {
                present: [
                  'GET /api/report-templates',
                  'POST /api/report-templates',
                  'GET /api/report-runs',
                  'POST /api/report-runs',
                  'GET /api/report-schedules',
                  'POST /api/report-schedules',
                ],
                missing: [],
              },
              runtime_openapi: {
                present: [
                  'GET /api/report-templates',
                  'POST /api/report-templates',
                  'GET /api/report-runs',
                  'POST /api/report-runs',
                  'GET /api/report-schedules',
                  'POST /api/report-schedules',
                ],
                missing: [],
              },
              docs_openapi: {
                present: [
                  'GET /api/report-templates',
                  'POST /api/report-templates',
                  'GET /api/report-runs',
                  'POST /api/report-runs',
                  'GET /api/report-schedules',
                  'POST /api/report-schedules',
                ],
                missing: [],
              },
              typescript_sdk: {
                present: [
                  '/api/report-templates',
                  '/api/report-runs',
                  '/api/report-schedules',
                ],
                missing: [],
              },
              python_sdk: {
                present: [
                  '/api/report-templates',
                  '/api/report-runs',
                  '/api/report-schedules',
                ],
                missing: [],
              },
            },
            issues: ['TypeScript SDK version 0.53.0 differs from runtime release 0.53.1.'],
          }),
        );
      }
      if (path === '/api/support/readiness-evidence') {
        const knownLimitations = ['No cloud, identity, or SaaS collectors are enabled yet.'];
        if (failoverDrill.status !== 'passed') {
          knownLimitations.unshift(
            'No automated failover drill has been recorded yet; run the control-plane failover drill before relying on the documented failover path.',
          );
        }
        return Promise.resolve(
          jsonOk({
            digest: 'readiness-digest-123456',
            evidence: {
              status: 'review',
              version: { runtime: '0.53.1-local' },
              collectors: { enabled: 2 },
              audit_chain: { status: 'verified' },
              contracts: { status: 'aligned' },
              response_history: { closed_or_reopenable: 4 },
              evidence: { reports_with_artifact_metadata: 3 },
              backup: {
                observed_backups: 2,
                schedule_cron: '0 2 * * *',
                latest_backup_at: '2026-04-30T11:40:00Z',
              },
              control_plane: {
                topology: 'standalone',
                orchestration_scope: 'standalone_reference',
                ha_mode: 'active_passive_reference',
                leader: true,
                durable_storage: true,
                event_store_path: 'var/events.db',
                backup_schedule_cron: '0 2 * * *',
                observed_backups: 2,
                latest_backup_at: '2026-04-30T11:40:00Z',
                checkpoint_count: 3,
                latest_checkpoint_at: '2026-04-30T11:58:00Z',
                restore_ready: true,
                recovery_status: 'ready_for_documented_failover',
                documented_failover: 'warm_standby_restore',
                cluster: null,
                failover_drill: failoverDrill,
                failover_drill_history: failoverDrill.status === 'passed' ? [failoverDrill] : [],
              },
              known_limitations: knownLimitations,
            },
          }),
        );
      }
      if (path === '/api/support/first-run-proof' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            digest: 'first-run-proof-digest',
            proof: {
              status: 'completed',
              case_id: 42,
              report_id: 7,
              response_request_id: 'resp-1',
            },
          }),
        );
      }
      if (path === '/api/control/failover-drill' && method === 'POST') {
        failoverDrill = {
          drill_type: 'warm_standby_restore_dry_run',
          orchestration_scope: 'standalone_reference',
          status: 'passed',
          last_run_at: '2026-04-30T12:02:00Z',
          actor: 'admin',
          summary:
            'Validated durable event storage with checkpoint artifacts for the documented failover path.',
          artifact_source: 'checkpoint',
          durable_storage_verified: true,
          backup_artifact_verified: false,
          checkpoint_artifact_verified: true,
        };
        return Promise.resolve(
          jsonOk({
            digest: 'failover-drill-digest',
            drill: failoverDrill,
          }),
        );
      }
      if (path === '/api/docs/index') {
        const query = parsed.searchParams.get('q') || '';
        const section = parsed.searchParams.get('section') || 'all';
        const lowered = query.toLowerCase();
        const filtered = docs.filter((entry) => {
          const matchesSection =
            section === 'all' ||
            (section === 'runbooks' && entry.path.startsWith('runbooks/')) ||
            (section === 'api' && entry.tags.includes('api')) ||
            (section === 'deployment' && entry.tags.includes('deployment')) ||
            (section === 'guides' && !entry.path.startsWith('runbooks/'));
          const matchesQuery =
            !lowered ||
            `${entry.title} ${entry.summary} ${entry.path}`.toLowerCase().includes(lowered);
          return matchesSection && matchesQuery;
        });
        return Promise.resolve(
          jsonOk({
            version: '0.53.1-local',
            total: filtered.length,
            items: filtered,
          }),
        );
      }
      if (path === '/api/docs/content') {
        const docPath = parsed.searchParams.get('path');
        if (docPath === 'SDK_GUIDE.md') {
          return Promise.resolve(
            jsonOk({
              path: 'SDK_GUIDE.md',
              title: 'SDK Guide',
              section: 'api',
              tags: ['api', 'guides'],
              headings: ['SDK Guide', 'TypeScript SDK'],
              summary: 'Use generated clients.',
              content:
                '# SDK Guide\nUse generated clients.\n\n## TypeScript SDK\n```ts\nimport { WardexClient } from "@wardex/sdk";\n```',
            }),
          );
        }
        return Promise.resolve(
          jsonOk({
            path: 'runbooks/deployment.md',
            title: 'Deployment & Upgrade Runbook',
            section: 'runbooks',
            tags: ['deployment', 'runbooks'],
            headings: ['Deployment & Upgrade Runbook', 'Prerequisites'],
            summary: 'Deploy and upgrade Wardex safely.',
            content:
              '# Deployment & Upgrade Runbook\nDeploy and upgrade Wardex safely.\n\n## Prerequisites\n- Access token\n- Backup',
          }),
        );
      }
      if (path === '/api/graphql' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            data: {
              status: {
                version: '0.53.1-local',
              },
            },
          }),
        );
      }
      return Promise.resolve(jsonOk({}));
    });
  });

  it('searches embedded docs, shows parity diagnostics, and runs GraphQL queries', async () => {
    const user = userEvent.setup();

    renderWithProviders();

    expect(await screen.findByText('Documentation Center')).toBeInTheDocument();
    expect(
      (
        await screen.findAllByText(
          'TypeScript SDK version 0.53.0 differs from runtime release 0.53.1.',
        )
      ).length,
    ).toBeGreaterThan(0);
    expect(await screen.findByText('Report Workflow Coverage')).toBeInTheDocument();
    expect((await screen.findAllByText('Runtime routes')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Live OpenAPI')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Docs OpenAPI')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('TypeScript SDK')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Python SDK')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('6 checks covered for this surface.')).length).toBe(3);
    expect((await screen.findAllByText('3 checks covered for this surface.')).length).toBe(2);
    expect(await screen.findByText('Production Readiness')).toBeInTheDocument();
    expect(await screen.findByText('Control-plane posture')).toBeInTheDocument();
    expect(await screen.findByText('2 backups / 3 checkpoints')).toBeInTheDocument();
    expect(
      (
        await screen.findAllByText(
          'No automated failover drill has been recorded yet; run the control-plane failover drill before relying on the documented failover path.',
        )
      ).length,
    ).toBeGreaterThan(0);
    expect(
      (await screen.findAllByText('No cloud, identity, or SaaS collectors are enabled yet.'))
        .length,
    ).toBeGreaterThan(0);

    await user.click(screen.getByRole('button', { name: 'Run Failover Drill' }));
    expect(await screen.findByText('Automated failover drill result')).toBeInTheDocument();
    expect(await screen.findByText(/failover-drill-digest/)).toBeInTheDocument();
    expect(await screen.findByText('Recent drill history')).toBeInTheDocument();
    expect(await screen.findByText('warm standby restore dry run')).toBeInTheDocument();
    await waitFor(() => {
      expect(
        screen.queryAllByText(
          'No automated failover drill has been recorded yet; run the control-plane failover drill before relying on the documented failover path.',
        ),
      ).toHaveLength(0);
    });

    await user.click(screen.getByRole('button', { name: 'Run Proof' }));
    expect(await screen.findByText('First-run proof result')).toBeInTheDocument();
    expect(await screen.findByText(/first-run-proof-digest/)).toBeInTheDocument();

    const docsSearch = screen.getByLabelText('Search docs');
    await user.clear(docsSearch);
    await user.type(docsSearch, 'sdk');

    const sdkCardSummary = await screen.findByText('Use generated Python and TypeScript SDKs.');
    await user.click(sdkCardSummary.closest('button'));

    expect(
      await screen.findByText((content, element) => {
        return element?.tagName.toLowerCase() === 'h3' && content === 'TypeScript SDK';
      }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText((content, element) => {
        return element?.tagName.toLowerCase() === 'pre' && content.includes('WardexClient');
      }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Run Query' }));

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url, options]) =>
            String(url) === '/api/graphql' && (options?.method || 'GET') === 'POST',
        ),
      ).toBe(true);
    });
  });

  it('restores contextual support state from the route and preserves scope through runbook pivots', async () => {
    const user = userEvent.setup();

    renderWithProviders(
      '/help?context=infrastructure&asset=Critical%20asset%20host&docs_q=deploy&docs_section=deployment&doc=runbooks/deployment.md&graphql_sample=alerts&api_q=graphql&api_auth=authenticated',
    );

    expect(await screen.findByText('Infrastructure Support')).toBeInTheDocument();
    expect(await screen.findByText('Critical asset host')).toBeInTheDocument();
    expect(screen.getByLabelText('Search docs')).toHaveValue('deploy');
    expect(screen.getByLabelText('Docs section')).toHaveValue('deployment');
    expect(
      await screen.findByRole('heading', { name: 'Deployment & Upgrade Runbook' }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('GraphQL sample')).toHaveValue('alerts');
    expect(screen.getByLabelText('GraphQL query').value).toContain('alerts(limit: 5)');
    expect(screen.getByLabelText('Filter endpoints')).toHaveValue('graphql');
    expect(screen.getByLabelText('Endpoint auth')).toHaveValue('authenticated');
    expect(await screen.findByText('/api/graphql')).toBeInTheDocument();

    expect(currentLocation().searchParams.get('context')).toBe('infrastructure');
    expect(currentLocation().searchParams.get('asset')).toBe('Critical asset host');
    expect(currentLocation().searchParams.get('doc')).toBe('runbooks/deployment.md');
    expect(currentLocation().searchParams.get('graphql_sample')).toBe('alerts');

    await user.click(screen.getByRole('button', { name: 'Open SDK guide' }));

    await waitFor(() => {
      expect(currentLocation().searchParams.get('context')).toBe('reports-exports');
      expect(currentLocation().searchParams.get('asset')).toBe('Critical asset host');
      expect(currentLocation().searchParams.get('docs_section')).toBe('api');
      expect(currentLocation().searchParams.get('doc')).toBe('SDK_GUIDE.md');
    });

    expect(await screen.findByText('Reporting Support')).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'SDK Guide' })).toBeInTheDocument();
    expect(
      await screen.findByText((content, element) => {
        return element?.tagName.toLowerCase() === 'h3' && content === 'TypeScript SDK';
      }),
    ).toBeInTheDocument();
  });
});

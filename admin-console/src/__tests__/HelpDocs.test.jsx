import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
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

function renderWithProviders(route = '/help') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <ThemeProvider>
          <ToastProvider>
            <HelpDocs />
          </ToastProvider>
        </ThemeProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('HelpDocs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
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
              '/api/support/parity': { get: { summary: 'API, SDK, and GraphQL parity diagnostics' } },
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
        return Promise.resolve(jsonOk({ queue: { pending: 2 }, automation: { active_investigations: 1 } }));
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
            issues: ['TypeScript SDK version 0.53.0 differs from runtime release 0.53.1.'],
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
              content: '# SDK Guide\nUse generated clients.\n\n## TypeScript SDK\n```ts\nimport { WardexClient } from "@wardex/sdk";\n```',
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
            content: '# Deployment & Upgrade Runbook\nDeploy and upgrade Wardex safely.\n\n## Prerequisites\n- Access token\n- Backup',
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
});
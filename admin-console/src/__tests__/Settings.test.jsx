import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import Settings from '../components/Settings.jsx';
import { ToastProvider } from '../hooks.jsx';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (header) => (header === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

describe('Settings', () => {
  beforeEach(() => {
    let idpState = {
      providers: [
        {
          id: 'idp-1',
          display_name: 'Corporate SSO',
          kind: 'oidc',
          enabled: true,
          issuer_url: 'https://issuer.example.com',
          client_id: 'wardex-admin',
          group_role_mappings: {},
          validation: {
            status: 'warning',
            issues: [
              {
                level: 'warning',
                field: 'group_role_mappings',
                message:
                  'No group-to-role mappings configured; users may fall back to viewer access.',
              },
            ],
            mapping_count: 0,
          },
        },
      ],
      count: 1,
      healthy: 0,
    };
    let scimState = {
      config: {
        enabled: true,
        base_url: 'https://scim.example.com',
        bearer_token: 'super-secret-token',
        provisioning_mode: 'automatic',
        default_role: 'admin',
        group_role_mappings: { Security: 'admin' },
        status: 'configured',
      },
      validation: {
        status: 'warning',
        issues: [
          {
            level: 'warning',
            field: 'default_role',
            message:
              'Default role is admin; review whether all newly provisioned users should be privileged.',
          },
        ],
        mapping_count: 1,
      },
    };

    vi.clearAllMocks();
    localStorage.clear();
    globalThis.URL.createObjectURL = vi.fn(() => 'blob:wardex-audit');
    globalThis.URL.revokeObjectURL = vi.fn();
    globalThis.fetch = vi.fn((url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const path = parsed.pathname;
      const params = parsed.searchParams;
      const method = options.method || 'GET';

      if (path === '/api/idp/providers' && method === 'GET') {
        return Promise.resolve(jsonOk(idpState));
      }
      if (path === '/api/idp/providers' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const mappingCount = Object.keys(body.group_role_mappings || {}).length;
        const validation = {
          status: mappingCount > 0 ? 'ready' : 'warning',
          issues:
            mappingCount > 0
              ? []
              : [
                  {
                    level: 'warning',
                    field: 'group_role_mappings',
                    message:
                      'No group-to-role mappings configured; users may fall back to viewer access.',
                  },
                ],
          mapping_count: mappingCount,
        };
        const provider = {
          id: body.id || 'idp-1',
          display_name: body.display_name,
          kind: body.kind,
          enabled: body.enabled ?? true,
          issuer_url: body.issuer_url || null,
          sso_url: body.sso_url || null,
          client_id: body.client_id || null,
          entity_id: body.entity_id || null,
          group_role_mappings: body.group_role_mappings || {},
          validation,
        };
        idpState = {
          providers: [provider],
          count: 1,
          healthy: validation.status === 'ready' ? 1 : 0,
        };
        return Promise.resolve(
          jsonOk({
            status: 'saved',
            provider: {
              id: provider.id,
              display_name: provider.display_name,
              kind: provider.kind,
              enabled: provider.enabled,
              issuer_url: provider.issuer_url,
              sso_url: provider.sso_url,
              client_id: provider.client_id,
              entity_id: provider.entity_id,
              group_role_mappings: provider.group_role_mappings,
            },
            validation,
          }),
        );
      }
      if (path === '/api/scim/config' && method === 'GET') {
        return Promise.resolve(jsonOk(scimState));
      }
      if (path === '/api/scim/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const mappingCount = Object.keys(body.group_role_mappings || {}).length;
        const validation = {
          status: body.default_role === 'admin' ? 'warning' : 'ready',
          issues:
            body.default_role === 'admin'
              ? [
                  {
                    level: 'warning',
                    field: 'default_role',
                    message:
                      'Default role is admin; review whether all newly provisioned users should be privileged.',
                  },
                ]
              : [],
          mapping_count: mappingCount,
        };
        const config = {
          enabled: body.enabled ?? false,
          base_url: body.base_url || null,
          bearer_token: body.bearer_token || null,
          provisioning_mode: body.provisioning_mode,
          default_role: body.default_role,
          group_role_mappings: body.group_role_mappings || {},
          status: body.enabled ? 'configured' : 'disabled',
        };
        scimState = { config, validation };
        return Promise.resolve(
          jsonOk({
            status: 'saved',
            config,
            validation,
          }),
        );
      }
      if (
        path === '/api/audit/log' &&
        params.get('limit') === '25' &&
        params.get('offset') === '0' &&
        !params.get('q') &&
        !params.get('method') &&
        !params.get('status') &&
        !params.get('auth')
      ) {
        return Promise.resolve(
          jsonOk({
            entries: [
              {
                timestamp: '2026-04-20T10:15:00Z',
                method: 'GET',
                path: '/api/platform',
                source_ip: '127.0.0.1',
                status_code: 200,
                auth_used: true,
              },
            ],
            total: 26,
            offset: 0,
            limit: 25,
            count: 1,
            has_more: true,
          }),
        );
      }
      if (
        path === '/api/audit/log' &&
        params.get('limit') === '25' &&
        params.get('offset') === '25' &&
        !params.get('q') &&
        !params.get('method') &&
        !params.get('status') &&
        !params.get('auth')
      ) {
        return Promise.resolve(
          jsonOk({
            entries: [
              {
                timestamp: '2026-04-19T08:00:00Z',
                method: 'POST',
                path: '/api/status',
                source_ip: '10.0.0.5',
                status_code: 500,
                auth_used: false,
              },
            ],
            total: 26,
            offset: 25,
            limit: 25,
            count: 1,
            has_more: false,
          }),
        );
      }
      if (
        path === '/api/audit/log' &&
        params.get('limit') === '25' &&
        params.get('offset') === '0' &&
        params.get('q') === 'alerts' &&
        params.get('method') === 'POST' &&
        params.get('status') === '2xx' &&
        params.get('auth') === 'authenticated'
      ) {
        return Promise.resolve(
          jsonOk({
            entries: [
              {
                timestamp: '2026-04-20T10:17:00Z',
                method: 'POST',
                path: '/api/alerts/sample',
                source_ip: '127.0.0.1',
                status_code: 200,
                auth_used: true,
              },
            ],
            total: 1,
            offset: 0,
            limit: 25,
            count: 1,
            has_more: false,
          }),
        );
      }
      if (
        path === '/api/audit/log/export' &&
        params.get('q') === 'alerts' &&
        params.get('method') === 'POST' &&
        params.get('status') === '2xx' &&
        params.get('auth') === 'authenticated'
      ) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: {
            get: (header) => (header === 'content-type' ? 'text/csv; charset=utf-8' : null),
          },
          text: async () =>
            'timestamp,method,path,source_ip,status_code,auth_state\n"\'2026-04-20T10:17:00Z","\'POST","\'/api/alerts/sample","\'127.0.0.1",200,"\'authenticated"\n',
        });
      }
      return Promise.resolve(jsonOk({}));
    });
  });

  it('renders paginated audit entries on the admin tab', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Admin' }));

    expect(await screen.findByText('API Audit Trail')).toBeInTheDocument();
    expect(await screen.findByText('/api/platform')).toBeInTheDocument();
    expect(screen.getByText('Showing 1-1 of 26 entries')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Newer' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Older' })).not.toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Older' }));

    const statusCell = await screen.findByText('/api/status');
    const statusRow = statusCell.closest('tr');
    expect(statusRow).not.toBeNull();
    expect(screen.getByText('Showing 26-26 of 26 entries')).toBeInTheDocument();
    expect(within(statusRow).getByText('Anonymous')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Newer' })).not.toBeDisabled();
    expect(screen.getByRole('button', { name: 'Older' })).toBeDisabled();

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url]) => String(url) === '/api/audit/log?limit=25&offset=25',
        ),
      ).toBe(true);
    });
  });

  it('filters the audit trail and exports the filtered csv', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Admin' }));
    await screen.findByText('API Audit Trail');

    await user.type(screen.getByLabelText('Search'), 'alerts');
    await user.selectOptions(screen.getByLabelText('Method'), 'POST');
    await user.selectOptions(screen.getByLabelText('Status'), '2xx');
    await user.selectOptions(screen.getByLabelText('Auth'), 'authenticated');

    expect(await screen.findByText('/api/alerts/sample')).toBeInTheDocument();
    expect(screen.getByText('Showing 1-1 of 1 entries')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Clear Filters' })).not.toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Export CSV' }));

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url]) =>
            String(url) ===
            '/api/audit/log/export?q=alerts&method=POST&status=2xx&auth=authenticated',
        ),
      ).toBe(true);
    });
    expect(globalThis.URL.createObjectURL).toHaveBeenCalled();
  });

  it('surfaces identity validation state on the integrations tab', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Integrations' }));

    const idpCard = (await screen.findByText('IdP Providers')).closest('.card');
    expect(idpCard).not.toBeNull();

    const providerCell = within(idpCard).getByRole('cell', { name: 'Corporate SSO' });
    const providerRow = providerCell.closest('tr');
    expect(providerRow).not.toBeNull();
    expect(within(providerRow).getByText('OIDC')).toBeInTheDocument();
    expect(within(providerRow).getByText('Review')).toBeInTheDocument();
    expect(within(providerRow).getByText('1 issue • 0 mappings')).toBeInTheDocument();
    expect(
      screen.getByText(
        'No group-to-role mappings configured; users may fall back to viewer access.',
      ),
    ).toBeInTheDocument();

    const scimCard = screen.getByText('SCIM Config').closest('.card');
    expect(scimCard).not.toBeNull();
    expect(within(scimCard).getByText('Review')).toBeInTheDocument();
    expect(within(scimCard).getByText('1 group mapping configured')).toBeInTheDocument();
    expect(
      Array.from(scimCard.querySelectorAll('.stat-box')).some((node) =>
        node.textContent?.includes(
          'Default role is admin; review whether all newly provisioned users should be privileged.',
        ),
      ),
    ).toBe(true);

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(([url]) => String(url) === '/api/idp/providers'),
      ).toBe(true);
      expect(globalThis.fetch.mock.calls.some(([url]) => String(url) === '/api/scim/config')).toBe(
        true,
      );
    });
  });

  it('saves provider and scim edits from the integrations tab', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Integrations' }));
    await screen.findByText('IdP Providers');

    await user.click(screen.getByRole('button', { name: 'Edit Provider' }));
    const providerNameInput = await screen.findByLabelText('Provider Name');
    await user.clear(providerNameInput);
    await user.type(providerNameInput, 'Workforce SSO');
    const providerMappingsInput = screen.getByLabelText('Provider Group Mappings');
    await user.clear(providerMappingsInput);
    await user.type(providerMappingsInput, 'Security=admin');
    await user.click(screen.getByRole('button', { name: 'Save Provider' }));

    await waitFor(() => {
      const idpCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/idp/providers' && (options?.method || 'GET') === 'POST',
      );
      expect(idpCall).toBeDefined();
      expect(JSON.parse(idpCall[1].body)).toMatchObject({
        display_name: 'Workforce SSO',
        group_role_mappings: { Security: 'admin' },
      });
    });

    const idpCard = screen.getByText('IdP Providers').closest('.card');
    expect(idpCard).not.toBeNull();
    const updatedProviderCell = within(idpCard).getByRole('cell', { name: 'Workforce SSO' });
    const updatedProviderRow = updatedProviderCell.closest('tr');
    expect(updatedProviderRow).not.toBeNull();
    expect(within(updatedProviderRow).getByText('Ready')).toBeInTheDocument();
    expect(within(updatedProviderRow).getByText('0 issues • 1 mapping')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Edit SCIM' }));
    const defaultRoleInput = await screen.findByLabelText('Default Role');
    await user.selectOptions(defaultRoleInput, 'viewer');
    const scimMappingsInput = screen.getByLabelText('SCIM Group Mappings');
    await user.clear(scimMappingsInput);
    await user.type(scimMappingsInput, 'Security=viewer');
    await user.click(screen.getByRole('button', { name: 'Save SCIM' }));

    await waitFor(() => {
      const scimCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/scim/config' && (options?.method || 'GET') === 'POST',
      );
      expect(scimCall).toBeDefined();
      expect(JSON.parse(scimCall[1].body)).toMatchObject({
        default_role: 'viewer',
        group_role_mappings: { Security: 'viewer' },
      });
    });

    const scimCard = screen.getByText('SCIM Config').closest('.card');
    expect(scimCard).not.toBeNull();
    expect(within(scimCard).getByText('Ready')).toBeInTheDocument();
    expect(within(scimCard).getByText('1 group mapping configured')).toBeInTheDocument();
  });
});

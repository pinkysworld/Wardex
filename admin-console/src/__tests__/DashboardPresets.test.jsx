import { describe, it, expect, beforeEach, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from '../components/Dashboard.jsx';
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

function renderWithProviders(node, route = '/') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>{node}</ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('Dashboard presets', () => {
  let preferenceState;
  let putBodies;

  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem('wardex_token', 'preset-token');
    preferenceState = {
      dashboard_presets: [
        {
          name: 'My Morning Queue',
          widgets: ['recent-alerts', 'threat-overview', 'system-health'],
          hidden: ['dns-threats'],
        },
      ],
      active_dashboard_preset: 'saved:My Morning Queue',
      updated_at: '2026-04-21T10:00:00Z',
    };
    putBodies = [];

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url, options = {}) => {
        const href = String(url);
        const method = options?.method || 'GET';

        if (href.includes('/api/auth/check')) return jsonOk({ authenticated: true });
        if (href.includes('/api/auth/session')) {
          return jsonOk({
            authenticated: true,
            role: 'analyst',
            user_id: 'analyst-1',
            groups: ['soc-analysts'],
            source: 'session',
          });
        }
        if (href.includes('/api/user/preferences') && method === 'GET') {
          return jsonOk(preferenceState);
        }
        if (href.includes('/api/user/preferences') && method === 'PUT') {
          const body = JSON.parse(options.body);
          putBodies.push(body);
          preferenceState = {
            ...preferenceState,
            ...body,
            dashboard_presets: body.dashboard_presets || preferenceState.dashboard_presets,
            active_dashboard_preset:
              body.active_dashboard_preset || preferenceState.active_dashboard_preset,
          };
          return jsonOk(preferenceState);
        }

        return jsonOk({});
      }),
    );
  });

  it('hydrates and persists dashboard presets through user preferences', async () => {
    renderWithProviders(<Dashboard />);

    expect(await screen.findByText('Dashboard Layout Presets')).toBeInTheDocument();
    expect(await screen.findByText('My Morning Queue')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Dashboard preset'), {
      target: { value: 'shared:noc-wall' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Preset' }));

    await waitFor(() => {
      expect(putBodies).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ active_dashboard_preset: 'shared:noc-wall' }),
        ]),
      );
    });

    fireEvent.change(screen.getByLabelText('Preset name'), {
      target: { value: 'Case Queue Focus' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save Current Layout' }));

    await waitFor(() => {
      expect(
        putBodies.some(
          (body) =>
            body.active_dashboard_preset === 'saved:Case Queue Focus' &&
            body.dashboard_presets?.some((preset) => preset.name === 'Case Queue Focus'),
        ),
      ).toBe(true);
    });
  });
});
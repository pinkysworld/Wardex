import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import UEBADashboard from '../components/UEBADashboard.jsx';
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

function renderWithProviders(route = '/ueba') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <LocationProbe />
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>
              <UEBADashboard />
            </ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function currentSearchParams() {
  const location = screen.getByTestId('location-probe').textContent || '/ueba';
  return new URL(`http://localhost${location}`).searchParams;
}

const RISKY_ENTITIES = {
  items: [
    {
      entity_id: 'user-a',
      entity_kind: 'user',
      risk_score: 92,
      anomaly_count: 4,
      peer_group: 'admins',
    },
    {
      entity_id: 'user-b',
      entity_kind: 'user',
      risk_score: 67,
      anomaly_count: 2,
      peer_group: 'engineering',
    },
  ],
};

const ENTITY_DETAILS = {
  'user-a': {
    entity_id: 'user-a',
    entity_kind: 'user',
    risk_score: 92,
    observation_count: 15,
    last_seen_ms: 1714392000000,
    anomaly_count: 4,
    peer_group: 'admins',
  },
  'user-b': {
    entity_id: 'user-b',
    entity_kind: 'user',
    risk_score: 67,
    observation_count: 12,
    last_seen_ms: 1714392000000,
    anomaly_count: 2,
    peer_group: 'engineering',
  },
};

function installUebaFetchMock(requestCounts = { risky: 0, entity: {} }) {
  globalThis.fetch = vi.fn((url) => {
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/auth/check') return Promise.resolve(jsonOk({ ok: true }));
    if (path === '/api/auth/session') {
      return Promise.resolve(
        jsonOk({
          authenticated: true,
          role: 'analyst',
          groups: ['soc'],
          user_id: 'ueba-tester',
          source: 'session',
        }),
      );
    }
    if (path === '/api/ueba/risky') {
      requestCounts.risky += 1;
      return Promise.resolve(jsonOk(RISKY_ENTITIES));
    }
    if (path.startsWith('/api/ueba/entity/')) {
      const entityId = decodeURIComponent(path.split('/').pop() || '');
      requestCounts.entity[entityId] = (requestCounts.entity[entityId] || 0) + 1;
      return Promise.resolve(jsonOk(ENTITY_DETAILS[entityId] || null));
    }
    return Promise.resolve(jsonOk({}));
  });
  return requestCounts;
}

describe('UEBADashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('wardex_token', 'ueba-token');
    installUebaFetchMock();
  });

  it('hydrates entity playbooks and analytics handoffs from route params', async () => {
    renderWithProviders('/ueba?entity=user-b&sort=entity_id&range=6h');

    expect(await screen.findByText('Entity: user-b')).toBeInTheDocument();
    expect(screen.getByText('Response Playbook')).toBeInTheDocument();
    expect(screen.getByText(/2 anomaly flags across 12 observations/i)).toBeInTheDocument();
    expect(screen.getByText('Immediate case escalation')).toBeInTheDocument();
    expect(screen.getByText('Identity or IAM owner')).toBeInTheDocument();
    expect(screen.getAllByRole('meter', { name: 'Risk score 67' }).length).toBeGreaterThan(0);

    const params = currentSearchParams();
    expect(params.get('entity')).toBe('user-b');
    expect(params.get('sort')).toBe('entity_id');
    expect(params.get('range')).toBe('6h');

    const attackGraphCard = (await screen.findByText('Validate Attack Paths')).closest('article');
    expect(attackGraphCard).toBeTruthy();
    expect(within(attackGraphCard).getByRole('link', { name: 'Open' })).toHaveAttribute(
      'href',
      '/attack-graph?node=user-b',
    );

    const reportsCard = screen.getByText('Capture Privacy And Evidence').closest('article');
    expect(reportsCard).toBeTruthy();
    expect(within(reportsCard).getByRole('link', { name: 'Open' })).toHaveAttribute(
      'href',
      '/reports?tab=privacy&source=ueba&target=user-b',
    );

    const packageEvidenceLink = screen.getByRole('link', { name: 'Package evidence' });
    const packageEvidenceUrl = new URL(
      packageEvidenceLink.getAttribute('href'),
      'http://localhost',
    );
    expect(packageEvidenceUrl.pathname).toBe('/reports');
    expect(packageEvidenceUrl.searchParams.get('tab')).toBe('delivery');
    expect(packageEvidenceUrl.searchParams.get('source')).toBe('ueba');
    expect(packageEvidenceUrl.searchParams.get('target')).toBe('user-b');
  });

  it('preserves route-backed UEBA context across refresh and entity pivots', async () => {
    const user = userEvent.setup();
    const requestCounts = installUebaFetchMock({ risky: 0, entity: {} });

    renderWithProviders('/ueba?entity=user-b&sort=entity_id&range=6h');

    expect(await screen.findByText('Entity: user-b')).toBeInTheDocument();

    await waitFor(() => {
      expect(requestCounts.risky).toBeGreaterThan(0);
      expect(requestCounts.entity['user-b']).toBeGreaterThan(0);
    });

    const beforeRefresh = {
      risky: requestCounts.risky,
      entity: requestCounts.entity['user-b'],
    };

    await user.click(screen.getByRole('button', { name: 'Refresh risky entities' }));

    await waitFor(() => {
      expect(requestCounts.risky).toBe(beforeRefresh.risky + 1);
      expect(requestCounts.entity['user-b']).toBe(beforeRefresh.entity + 1);
    });

    let params = currentSearchParams();
    expect(params.get('entity')).toBe('user-b');
    expect(params.get('sort')).toBe('entity_id');
    expect(params.get('range')).toBe('6h');

    await user.click(screen.getByRole('button', { name: 'Close entity detail' }));

    await waitFor(() => {
      expect(screen.queryByText('Entity: user-b')).not.toBeInTheDocument();
    });

    params = currentSearchParams();
    expect(params.has('entity')).toBe(false);
    expect(params.get('sort')).toBe('entity_id');
    expect(params.get('range')).toBe('6h');

    const userARow = screen.getByText('user-a').closest('tr');
    expect(userARow).toBeTruthy();
    await user.click(userARow);

    expect(await screen.findByText('Entity: user-a')).toBeInTheDocument();

    params = currentSearchParams();
    expect(params.get('entity')).toBe('user-a');
    expect(params.get('sort')).toBe('entity_id');
    expect(params.get('range')).toBe('6h');

    const huntCard = screen.getByText('Launch A Focused Hunt').closest('article');
    expect(huntCard).toBeTruthy();
    const huntUrl = new URL(
      within(huntCard).getByRole('link', { name: 'Open' }).getAttribute('href'),
      'http://localhost',
    );
    expect(huntUrl.pathname).toBe('/detection');
    expect(huntUrl.searchParams.get('intent')).toBe('run-hunt');
    expect(huntUrl.searchParams.get('huntQuery')).toBe('user:user-a ueba anomaly');
    expect(huntUrl.searchParams.get('huntName')).toBe('Hunt user-a');
  });
});

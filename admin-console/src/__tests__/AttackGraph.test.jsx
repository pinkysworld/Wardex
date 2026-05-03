import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import AttackGraph from '../components/AttackGraph.jsx';
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

function renderWithProviders(route = '/attack-graph') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <LocationProbe />
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>
              <AttackGraph />
            </ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function currentSearchParams() {
  const location = screen.getByTestId('location-probe').textContent || '/attack-graph';
  return new URL(`http://localhost${location}`).searchParams;
}

function installCanvasStub() {
  Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', {
    configurable: true,
    value: vi.fn(() => ({
      clearRect: vi.fn(),
      beginPath: vi.fn(),
      moveTo: vi.fn(),
      lineTo: vi.fn(),
      stroke: vi.fn(),
      fill: vi.fn(),
      closePath: vi.fn(),
      fillText: vi.fn(),
      arc: vi.fn(),
      save: vi.fn(),
      restore: vi.fn(),
      strokeStyle: '',
      fillStyle: '',
      lineWidth: 1,
      globalAlpha: 1,
      font: '',
      textAlign: 'left',
      textBaseline: 'alphabetic',
    })),
  });
}

const CAMPAIGN_DATA = {
  summary: {
    campaign_count: 3,
    total_alerts: 8,
    fleet_coverage: 0.82,
    temporal_chain_count: 2,
  },
  sequence_summaries: [
    {
      campaign_id: 'campaign-1',
      name: 'Credential campaign across 2 hosts',
      severity: 'Critical',
      host_count: 2,
      alert_count: 2,
      shared_techniques: ['T1078'],
      sequence_signals: ['Credential-access precursor observed in the detection reasons.'],
    },
  ],
  temporal_chains: [
    {
      chain_id: 'chain-1',
      host: 'host-1',
      alert_count: 2,
      first_seen_ms: 1714226400000,
      last_seen_ms: 1714226760000,
      avg_score: 4.2,
      max_score: 4.9,
      severity: 'Critical',
      shared_techniques: ['T1078'],
      shared_reasons: ['Credential-access precursor observed'],
      alert_ids: ['alert-1', 'alert-2'],
    },
    {
      chain_id: 'chain-2',
      host: 'host-2',
      alert_count: 3,
      first_seen_ms: 1714227000000,
      last_seen_ms: 1714227360000,
      avg_score: 3.8,
      max_score: 4.1,
      severity: 'Severe',
      shared_techniques: ['T1059'],
      shared_reasons: ['Privilege escalation fan-out'],
      alert_ids: ['alert-3', 'alert-4', 'alert-5'],
    },
  ],
  graph: {
    nodes: [
      { id: 'user-1', label: 'user-1', type: 'user', risk_score: 72 },
      { id: 'host-1', label: 'host-1', type: 'host', risk_score: 55 },
    ],
    edges: [{ source: 'user-1', target: 'host-1', type: 'lateral_movement' }],
  },
};

function installAttackGraphFetchMock() {
  globalThis.fetch = vi.fn((url) => {
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/auth/check') return Promise.resolve(jsonOk({ authenticated: true }));
    if (path === '/api/auth/session') {
      return Promise.resolve(
        jsonOk({
          authenticated: true,
          role: 'analyst',
          user_id: 'graph-tester',
          groups: ['soc-analysts'],
          source: 'session',
        }),
      );
    }
    if (path === '/api/correlation/campaigns') return Promise.resolve(jsonOk(CAMPAIGN_DATA));
    if (path === '/api/coverage/gaps') {
      return Promise.resolve(
        jsonOk({ gaps: [{ technique_id: 'T1078', technique_name: 'Valid Accounts' }] }),
      );
    }
    return Promise.resolve(jsonOk({}));
  });
}

describe('AttackGraph', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('wardex_token', 'attack-token');
    installCanvasStub();
    installAttackGraphFetchMock();
  });

  it('hydrates campaign drilldowns and graph pivots from the route', async () => {
    renderWithProviders('/attack-graph?node=user-1&chain=chain-1');

    expect(await screen.findByText('Attack Graph Pivots')).toBeInTheDocument();
    expect(await screen.findByText('Open Campaign Investigation')).toBeInTheDocument();
    expect(screen.getByText('Campaign Intelligence')).toBeInTheDocument();
    expect(screen.getByText('Credential campaign across 2 hosts')).toBeInTheDocument();
    expect(screen.getByText('Temporal Chain Drilldown')).toBeInTheDocument();
    expect(screen.getAllByText('Credential-access precursor observed').length).toBeGreaterThan(0);
    expect(screen.getByText('alert-1')).toBeInTheDocument();
    expect(screen.getByText('alert-2')).toBeInTheDocument();
    expect(screen.getByText('Node Detail')).toBeInTheDocument();
    expect(screen.getAllByText('user-1').length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /Focus host-1 burst/i })).toHaveAttribute(
      'aria-pressed',
      'true',
    );

    const params = currentSearchParams();
    expect(params.get('node')).toBe('user-1');
    expect(params.get('chain')).toBe('chain-1');

    const socCard = screen.getByText('Open Campaign Investigation').closest('article');
    expect(socCard).toBeTruthy();
    expect(within(socCard).getByRole('link', { name: 'Open' })).toHaveAttribute(
      'href',
      '/soc#campaigns',
    );

    const uebaCard = screen.getByText('Inspect UEBA Risk').closest('article');
    expect(uebaCard).toBeTruthy();
    const uebaUrl = new URL(
      within(uebaCard).getByRole('link', { name: 'Open' }).getAttribute('href'),
      'http://localhost',
    );
    expect(uebaUrl.pathname).toBe('/ueba');
    expect(uebaUrl.searchParams.get('entity')).toBe('user-1');

    const ndrCard = screen.getByText('Validate Network Side').closest('article');
    expect(ndrCard).toBeTruthy();
    const ndrUrl = new URL(
      within(ndrCard).getByRole('link', { name: 'Open' }).getAttribute('href'),
      'http://localhost',
    );
    expect(ndrUrl.pathname).toBe('/ndr');
    expect(ndrUrl.searchParams.get('tab')).toBe('overview');

    const reportsCard = screen.getByText('Export Evidence Bundle').closest('article');
    expect(reportsCard).toBeTruthy();
    const reportsUrl = new URL(
      within(reportsCard).getByRole('link', { name: 'Open' }).getAttribute('href'),
      'http://localhost',
    );
    expect(reportsUrl.pathname).toBe('/reports');
    expect(reportsUrl.searchParams.get('tab')).toBe('evidence');
    expect(reportsUrl.searchParams.get('source')).toBe('attack-graph');
    expect(reportsUrl.searchParams.get('target')).toBe('user-1');
  });

  it('preserves node context while switching temporal chains and clearing node detail', async () => {
    const user = userEvent.setup();

    renderWithProviders('/attack-graph?node=user-1&chain=chain-1');

    expect(await screen.findByText('Temporal Chain Drilldown')).toBeInTheDocument();
    expect(await screen.findByText('Open Campaign Investigation')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Focus host-2 burst/i }));

    expect(await screen.findByText('Privilege escalation fan-out')).toBeInTheDocument();
    expect(screen.getByText('alert-5')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Focus host-2 burst/i })).toHaveAttribute(
      'aria-pressed',
      'true',
    );

    let params = currentSearchParams();
    expect(params.get('node')).toBe('user-1');
    expect(params.get('chain')).toBe('chain-2');

    await user.click(screen.getByRole('button', { name: 'Close node detail' }));

    await waitFor(() => {
      expect(screen.queryByText('Node Detail')).not.toBeInTheDocument();
    });

    params = currentSearchParams();
    expect(params.has('node')).toBe(false);
    expect(params.get('chain')).toBe('chain-2');
  });
});
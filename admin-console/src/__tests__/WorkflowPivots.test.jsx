import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import UEBADashboard from '../components/UEBADashboard.jsx';
import NDRDashboard from '../components/NDRDashboard.jsx';
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

function mockApiRoutes(routes = {}) {
  const mock = vi.fn((url) => {
    for (const [pattern, handler] of Object.entries(routes)) {
      if (String(url).includes(pattern)) {
        return Promise.resolve(typeof handler === 'function' ? handler(url) : handler);
      }
    }
    return Promise.resolve(jsonOk({}));
  });
  vi.stubGlobal('fetch', mock);
  return mock;
}

function renderWithProviders(ui, { route = '/' } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>{ui}</ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
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

function mockSharedRoutes(extraRoutes = {}) {
  return mockApiRoutes({
    '/api/auth/check': jsonOk({ authenticated: true }),
    '/api/auth/session': jsonOk({
      authenticated: true,
      role: 'analyst',
      user_id: 'analyst-1',
      groups: ['soc-analysts'],
      source: 'session',
    }),
    ...extraRoutes,
  });
}

describe('Workflow pivots', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('wardex_token', 'test-token');
    installCanvasStub();
  });

  it('restores UEBA selection from the route and renders entity pivots', async () => {
    mockSharedRoutes({
      '/api/ueba/risky': jsonOk({
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
      }),
      '/api/ueba/anomalies': jsonOk({
        items: [
          {
            entity_id: 'user-b',
            anomaly_type: 'ImpossibleTravel',
            score: 81,
            description: 'Unusual travel detected',
            mitre_technique: 'T1078',
          },
        ],
      }),
      '/api/ueba/peer-groups': jsonOk([{ group: 'engineering', entity_count: 12, avg_risk: 23 }]),
      '/api/ueba/entity/user-b': jsonOk({
        entity_id: 'user-b',
        entity_kind: 'user',
        risk_score: 67,
        observation_count: 12,
        peer_group: 'engineering',
        peer_avg_risk: 22,
        anomalies: [{ anomaly_type: 'ImpossibleTravel', score: 81, description: 'Unusual travel detected' }],
      }),
    });

    renderWithProviders(<UEBADashboard />, {
      route: '/ueba?entity=user-b&sort=entity_id&anomaly=ImpossibleTravel',
    });

    expect(await screen.findByText('Entity Pivots')).toBeInTheDocument();
    expect(await screen.findByText('Entity: user-b')).toBeInTheDocument();
    expect(screen.getByText('Capture Privacy And Evidence')).toBeInTheDocument();
  });

  it('restores NDR tab state from the route and renders network pivots', async () => {
    mockSharedRoutes({
      '/api/ndr/report': jsonOk({
        total_flows_analysed: 42,
        total_bytes: 2048,
        unique_external_destinations: 3,
        connections_per_second: 1.5,
        encrypted_traffic: { encrypted_ratio: 0.94 },
        top_talkers: [{ addr: '10.0.0.5', total_bytes: 1024, flow_count: 4, unique_destinations: 2, protocols: ['HTTPS'] }],
        unusual_destinations: [{ dst_addr: '203.0.113.9', dst_port: 443, total_bytes: 512, risk_score: 8, reason: 'Rare destination' }],
        protocol_anomalies: [],
        beaconing_anomalies: [{ host: '10.0.0.5', dst: '203.0.113.9', interval_seconds: 60, confidence: 0.9 }],
        entropy_anomalies: [],
        self_signed_certs: [],
      }),
      '/api/ndr/tls-anomalies': jsonOk([]),
      '/api/ndr/dpi-anomalies': jsonOk([]),
    });

    renderWithProviders(<NDRDashboard />, { route: '/ndr?tab=beaconing' });

    expect(await screen.findByText('Network Pivots')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Beaconing \(1\)/ })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    expect(screen.getByText('Package Delivery Evidence')).toBeInTheDocument();
  });

  it('restores selected attack-graph node from the route and renders graph pivots', async () => {
    mockSharedRoutes({
      '/api/correlation/campaigns': jsonOk({
        graph: {
          nodes: [
            { id: 'user-1', label: 'user-1', type: 'user', risk_score: 72 },
            { id: 'host-1', label: 'host-1', type: 'host', risk_score: 55 },
          ],
          edges: [{ source: 'user-1', target: 'host-1', type: 'lateral_movement' }],
        },
      }),
      '/api/coverage/gaps': jsonOk({ gaps: [{ technique_id: 'T1078', technique_name: 'Valid Accounts' }] }),
    });

    renderWithProviders(<AttackGraph />, { route: '/attack-graph?node=user-1' });

    expect(await screen.findByText('Attack Graph Pivots')).toBeInTheDocument();
    expect(screen.getByText('Node Detail')).toBeInTheDocument();
    expect(screen.getAllByText('user-1').length).toBeGreaterThan(0);
    expect(screen.getByText('Export Evidence Bundle')).toBeInTheDocument();
  });
});
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from '../components/Dashboard.jsx';
import UEBADashboard from '../components/UEBADashboard.jsx';
import NDRDashboard from '../components/NDRDashboard.jsx';
import AttackGraph from '../components/AttackGraph.jsx';
import Infrastructure from '../components/Infrastructure.jsx';
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

  it('routes the dashboard reporting pivot with priority-alert context', async () => {
    mockSharedRoutes({
      '/api/status': jsonOk({ version: '0.53.5', uptime_secs: 3600 }),
      '/api/fleet/dashboard': jsonOk({
        fleet: { total_agents: 2, status_counts: { online: 2 } },
      }),
      '/api/alerts': jsonOk([
        {
          id: 'alert-1',
          timestamp: '2026-04-23T10:00:00Z',
          severity: 'critical',
          category: 'Credential Access',
          hostname: 'playwright-host.local',
          message: 'Credential spray against the local console host',
        },
      ]),
      '/api/telemetry/current': jsonOk({
        cpu: 22,
        memory: 48,
        disk: 61,
        network: 1200,
        auth_failures: 4,
        processes: 188,
      }),
      '/api/health': jsonOk({ status: 'ok', version: '0.53.5' }),
      '/api/detection/summary': jsonOk({}),
      '/api/threat-intel/status': jsonOk({ ioc_count: 4 }),
      '/api/queue/stats': jsonOk({}),
      '/api/response/stats': jsonOk({ pending: 2 }),
      '/api/detection/profile': jsonOk({}),
      '/api/processes/analysis': jsonOk({ status: 'clean' }),
      '/api/host/info': jsonOk({
        hostname: 'playwright-host.local',
        platform: 'macOS',
        os_version: '14.5',
        arch: 'arm64',
      }),
      '/api/telemetry/history': jsonOk([]),
      '/api/user/preferences': jsonOk({}),
      '/api/malware/stats': jsonOk({}),
      '/api/coverage/gaps': jsonOk({ gaps: [{ technique_id: 'T1059' }] }),
      '/api/quarantine/stats': jsonOk({}),
      '/api/lifecycle/stats': jsonOk({}),
      '/api/feeds/stats': jsonOk({}),
      '/api/manager/queue-digest': jsonOk({}),
      '/api/dns-threat/summary': jsonOk({}),
    });

    renderWithProviders(<Dashboard />);

    const reportCard = (await screen.findByText('Package Evidence')).closest('article');
    expect(reportCard).toBeTruthy();
    expect(within(reportCard).getByRole('link', { name: 'Open' })).toHaveAttribute(
      'href',
      '/reports?tab=delivery&source=dashboard&target=playwright-host.local',
    );
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
      '/api/ueba/entity/user-b': jsonOk({
        entity_id: 'user-b',
        entity_kind: 'user',
        risk_score: 67,
        observation_count: 12,
        last_seen_ms: 1714392000000,
        anomaly_count: 2,
        peer_group: 'engineering',
      }),
    });

    renderWithProviders(<UEBADashboard />, {
      route: '/ueba?entity=user-b&sort=entity_id&anomaly=ImpossibleTravel',
    });

    expect(await screen.findByText('Entity Pivots')).toBeInTheDocument();
    expect(await screen.findByText('Entity: user-b')).toBeInTheDocument();
    expect(screen.getByText('Response Playbook')).toBeInTheDocument();
    expect(screen.getByText('Capture Privacy And Evidence')).toBeInTheDocument();
  });

  it('refreshes grouped UEBA overview data from the risky entities workspace', async () => {
    const callCounts = {
      risky: 0,
      entity: 0,
    };
    const user = userEvent.setup();

    mockSharedRoutes({
      '/api/ueba/risky': () => {
        callCounts.risky += 1;
        return jsonOk({
          items: [
            {
              entity_id: 'user-a',
              entity_kind: 'user',
              risk_score: 92,
              anomaly_count: 4,
              peer_group: 'admins',
            },
          ],
        });
      },
      '/api/ueba/entity/user-a': () => {
        callCounts.entity += 1;
        return jsonOk({
          entity_id: 'user-a',
          entity_kind: 'user',
          risk_score: 92,
          observation_count: 15,
          last_seen_ms: 1714392000000,
          anomaly_count: 4,
          peer_group: 'admins',
        });
      },
    });

    renderWithProviders(<UEBADashboard />, { route: '/ueba' });

    expect(await screen.findByText('Risky Entities')).toBeInTheDocument();

    await waitFor(() => {
      expect(callCounts.risky).toBeGreaterThan(0);
      expect(callCounts.entity).toBeGreaterThan(0);
    });

    const initialCounts = { ...callCounts };

    await user.click(screen.getByRole('button', { name: 'Refresh risky entities' }));

    await waitFor(() => {
      expect(callCounts.risky).toBe(initialCounts.risky + 1);
      expect(callCounts.entity).toBe(initialCounts.entity + 1);
    });
  });

  it('restores NDR tab state from the route and renders network pivots', async () => {
    mockSharedRoutes({
      '/api/ndr/report': jsonOk({
        total_flows_analysed: 42,
        total_bytes: 2048,
        unique_external_destinations: 3,
        connections_per_second: 1.5,
        encrypted_traffic: { encrypted_ratio: 0.94 },
        top_talkers: [
          {
            addr: '10.0.0.5',
            total_bytes: 1024,
            flow_count: 4,
            unique_destinations: 2,
            protocols: ['HTTPS'],
          },
        ],
        unusual_destinations: [
          {
            dst_addr: '203.0.113.9',
            dst_port: 443,
            total_bytes: 512,
            risk_score: 8,
            reason: 'Rare destination',
          },
        ],
        protocol_anomalies: [],
        beaconing_anomalies: [
          { host: '10.0.0.5', dst: '203.0.113.9', interval_seconds: 60, confidence: 0.9 },
        ],
        entropy_anomalies: [],
        self_signed_certs: [],
      }),
      '/api/ndr/tls-anomalies': jsonOk([]),
      '/api/ndr/dpi-anomalies': jsonOk([]),
    });

    renderWithProviders(<NDRDashboard />, { route: '/ndr?tab=beaconing' });

    expect(await screen.findByText('Network Pivots')).toBeInTheDocument();
    expect(screen.getByText('Network Response Playbook')).toBeInTheDocument();
    expect(screen.getByText('Beaconing cadence')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Beaconing \(1\)/ })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    expect(screen.getByText('Package Delivery Evidence')).toBeInTheDocument();
  });

  it('restores infrastructure asset scope and renders remediation guidance', async () => {
    mockSharedRoutes({
      '/api/assets/summary': jsonOk({
        assets: [
          {
            id: 'host-1',
            name: 'host-1',
            kind: 'asset',
            status: 'tracked',
            severity: 'medium',
            priority: 'critical',
          },
        ],
      }),
      '/api/vulnerability/summary': jsonOk({
        findings: [
          {
            id: 'vuln-1',
            asset_name: 'host-1',
            cve: 'CVE-2026-0001',
            severity: 'critical',
            status: 'open',
          },
        ],
      }),
      '/api/certs/summary': jsonOk({ certificates: [] }),
      '/api/certs/alerts': jsonOk({ alerts: [] }),
      '/api/malware/recent': jsonOk({ items: [] }),
      '/api/malware/stats': jsonOk({}),
      '/api/drift/status': jsonOk({ changes: [] }),
      '/api/container/stats': jsonOk({ containers: [] }),
      '/api/monitor/status': jsonOk({ health_gate: 'healthy' }),
      '/api/threads/status': jsonOk({}),
      '/api/slo/status': jsonOk({ health_gate: 'healthy' }),
      '/api/system/deps': jsonOk({ dependencies: [] }),
      '/api/ndr/report': jsonOk({ findings: [] }),
      '/api/compliance/summary': jsonOk({}),
      '/api/analytics/api': jsonOk({}),
      '/api/traces': jsonOk([]),
    });

    renderWithProviders(<Infrastructure />, {
      route: '/infrastructure?tab=assets&view=critical&asset=host-1',
    });

    expect(await screen.findByText('Infrastructure Pivots')).toBeInTheDocument();
    expect(await screen.findByText('Guided Remediation Brief')).toBeInTheDocument();
    expect(screen.getByText('Open compliance evidence')).toBeInTheDocument();
  });

  it('restores selected attack-graph node from the route and renders graph pivots', async () => {
    const user = userEvent.setup();
    mockSharedRoutes({
      '/api/correlation/campaigns': jsonOk({
        summary: {
          campaign_count: 1,
          temporal_chain_count: 2,
          total_alerts: 2,
          unclustered_alerts: 0,
          fleet_coverage: 0.5,
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
      }),
      '/api/coverage/gaps': jsonOk({
        gaps: [{ technique_id: 'T1078', technique_name: 'Valid Accounts' }],
      }),
    });

    renderWithProviders(<AttackGraph />, { route: '/attack-graph?node=user-1' });

    expect(await screen.findByText('Attack Graph Pivots')).toBeInTheDocument();
    expect(screen.getByText('Campaign Intelligence')).toBeInTheDocument();
    expect(screen.getByText('Credential campaign across 2 hosts')).toBeInTheDocument();
    expect(screen.getByText('Temporal Chain Drilldown')).toBeInTheDocument();
    expect(screen.getAllByText('Credential-access precursor observed').length).toBeGreaterThan(0);
    expect(screen.getByText('Node Detail')).toBeInTheDocument();
    expect(screen.getAllByText('user-1').length).toBeGreaterThan(0);
    expect(screen.getByText('Export Evidence Bundle')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Focus host-2 burst/i }));

    expect(await screen.findByText('Privilege escalation fan-out')).toBeInTheDocument();
    expect(screen.getByText('alert-5')).toBeInTheDocument();
  });
});

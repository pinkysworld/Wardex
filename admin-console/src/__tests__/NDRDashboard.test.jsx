import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import NDRDashboard from '../components/NDRDashboard.jsx';
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

function renderWithProviders(node, route = '/ndr') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <LocationProbe />
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

function currentSearchParams() {
  const location = screen.getByTestId('location-probe').textContent || '/ndr';
  return new URL(`http://localhost${location}`).searchParams;
}

const REPORT = {
  total_flows_analysed: 12345,
  total_bytes: 52_428_800,
  unique_external_destinations: 42,
  connections_per_second: 17.5,
  encrypted_traffic: { encrypted_ratio: 0.93 },
  top_talkers: [
    {
      addr: '10.0.0.5',
      total_bytes: 1_048_576,
      flow_count: 128,
      unique_destinations: 12,
      protocols: ['TCP', 'HTTPS'],
    },
  ],
  unusual_destinations: [
    {
      dst_addr: '198.51.100.7',
      dst_port: 443,
      total_bytes: 204_800,
      risk_score: 7.5,
      reason: 'New external destination with high volume',
    },
  ],
  protocol_anomalies: [],
  tls_anomalies: [{ dst_addr: 'tls-edge.example', tls_sni: 'tls-edge.example', risk_score: 6.0 }],
  dpi_anomalies: [],
  entropy_anomalies: [],
  beaconing_anomalies: [],
  self_signed_certs: [],
};

const BEACONING_REPORT = {
  ...REPORT,
  unusual_destinations: [
    {
      dst_addr: '203.0.113.9',
      dst_port: 443,
      total_bytes: 512,
      risk_score: 8,
      reason: 'Rare destination',
    },
  ],
  beaconing_anomalies: [
    {
      host: '10.0.0.5',
      dst_addr: '203.0.113.9',
      dst_port: 443,
      interval_seconds: 60,
      confidence: 0.9,
    },
  ],
};

describe('NDRDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('wardex_token', 'ndr-token');

    globalThis.fetch = vi.fn((url) => {
      const path = new URL(String(url), 'http://localhost').pathname;
      if (path === '/api/ndr/report') return Promise.resolve(jsonOk(REPORT));
      if (path === '/api/ndr/tls-anomalies') return Promise.resolve(jsonOk(REPORT.tls_anomalies));
      if (path === '/api/ndr/dpi-anomalies') return Promise.resolve(jsonOk(REPORT.dpi_anomalies));
      return Promise.resolve(jsonOk({}));
    });
  });

  it('renders overview summary cards and top-talkers from the NDR report', async () => {
    renderWithProviders(<NDRDashboard />);

    expect(await screen.findByText('12345')).toBeInTheDocument();
    expect(screen.getByText('50.0 MB')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('93%')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument();
    expect(screen.getAllByText('198.51.100.7').length).toBeGreaterThan(0);
  });

  it('refetches the NDR report when the refresh button is clicked', async () => {
    const user = userEvent.setup();
    renderWithProviders(<NDRDashboard />);

    await waitFor(() => {
      const calls = globalThis.fetch.mock.calls.filter(
        ([url]) => new URL(String(url), 'http://localhost').pathname === '/api/ndr/report',
      );
      expect(calls.length).toBeGreaterThanOrEqual(1);
    });

    const before = globalThis.fetch.mock.calls.filter(
      ([url]) => new URL(String(url), 'http://localhost').pathname === '/api/ndr/report',
    ).length;

    await user.click(screen.getByRole('button', { name: 'Refresh NDR data' }));

    await waitFor(() => {
      const after = globalThis.fetch.mock.calls.filter(
        ([url]) => new URL(String(url), 'http://localhost').pathname === '/api/ndr/report',
      ).length;
      expect(after).toBeGreaterThan(before);
    });
  });

  it('switches to the TLS tab via query parameter', async () => {
    renderWithProviders(<NDRDashboard />, '/ndr?tab=tls');

    expect(await screen.findByRole('tab', { name: /TLS \(1\)/ })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    expect(screen.getByText('TLS fingerprinting')).toBeInTheDocument();
    expect(currentSearchParams().get('tab')).toBe('tls');
  });

  it('updates the route when analysts switch active network sections', async () => {
    const user = userEvent.setup();
    renderWithProviders(<NDRDashboard />);

    expect(await screen.findByRole('tab', { name: 'Overview' })).toHaveAttribute(
      'aria-selected',
      'true',
    );

    await user.click(screen.getByRole('tab', { name: /TLS \(1\)/ }));

    await waitFor(() => {
      expect(currentSearchParams().get('tab')).toBe('tls');
    });
    expect(screen.getByText('TLS fingerprinting')).toBeInTheDocument();
  });

  it('preserves beaconing tab context across refresh and keeps delivery handoffs seeded', async () => {
    const user = userEvent.setup();
    const requestCounts = { report: 0 };

    globalThis.fetch = vi.fn((url) => {
      const path = new URL(String(url), 'http://localhost').pathname;
      if (path === '/api/ndr/report') {
        requestCounts.report += 1;
        return Promise.resolve(jsonOk(BEACONING_REPORT));
      }
      if (path === '/api/ndr/tls-anomalies') return Promise.resolve(jsonOk([]));
      if (path === '/api/ndr/dpi-anomalies') return Promise.resolve(jsonOk([]));
      return Promise.resolve(jsonOk({}));
    });

    renderWithProviders(<NDRDashboard />, '/ndr?tab=beaconing');

    expect(await screen.findByRole('tab', { name: /Beaconing \(1\)/ })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    expect(screen.getByText('Beaconing cadence')).toBeInTheDocument();
    expect(screen.getByText('Containment and evidence capture')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.9:443')).toBeInTheDocument();

    const assetTelemetryUrl = new URL(
      screen.getByRole('link', { name: 'Review asset telemetry' }).getAttribute('href'),
      'http://localhost',
    );
    expect(assetTelemetryUrl.pathname).toBe('/infrastructure');
    expect(assetTelemetryUrl.searchParams.get('tab')).toBe('observability');
    expect(assetTelemetryUrl.searchParams.get('q')).toBe('203.0.113.9');

    const deliveryEvidenceUrl = new URL(
      screen.getByRole('link', { name: 'Export delivery evidence' }).getAttribute('href'),
      'http://localhost',
    );
    expect(deliveryEvidenceUrl.pathname).toBe('/reports');
    expect(deliveryEvidenceUrl.searchParams.get('tab')).toBe('delivery');
    expect(deliveryEvidenceUrl.searchParams.get('source')).toBe('ndr');
    expect(deliveryEvidenceUrl.searchParams.get('target')).toBe('203.0.113.9');

    const beforeRefresh = requestCounts.report;

    await user.click(screen.getByRole('button', { name: 'Refresh NDR data' }));

    await waitFor(() => {
      expect(requestCounts.report).toBe(beforeRefresh + 1);
    });
    expect(currentSearchParams().get('tab')).toBe('beaconing');
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
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

function renderWithProviders(node, route = '/ndr') {
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
  });
});

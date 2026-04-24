import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import InvestigationTimeline from '../components/InvestigationTimeline.jsx';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (header) => (header === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

const nowIso = () => new Date().toISOString();

const ALERTS = [
  {
    id: 'a-crit',
    severity: 'critical',
    type: 'malware',
    timestamp: nowIso(),
    message: 'Ransomware detonation detected',
    hostname: 'host-alpha',
    user: 'svc_admin',
    process_name: 'encryptor.exe',
  },
  {
    id: 'a-med',
    severity: 'medium',
    type: 'access',
    timestamp: nowIso(),
    message: 'Suspicious login anomaly',
    hostname: 'host-beta',
    user: 'alice',
  },
];

describe('InvestigationTimeline', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.fetch = vi.fn((url) => {
      const path = new URL(String(url), 'http://localhost').pathname;
      if (path === '/api/alerts') return Promise.resolve(jsonOk(ALERTS));
      return Promise.resolve(jsonOk({}));
    });
  });

  it('renders merged timeline events from api.alerts with filter controls', async () => {
    render(<InvestigationTimeline />);

    expect(await screen.findByText('Ransomware detonation detected')).toBeInTheDocument();
    expect(screen.getByText('Suspicious login anomaly')).toBeInTheDocument();
    expect(screen.getByText(/2 events/)).toBeInTheDocument();
    expect(screen.getByRole('toolbar', { name: 'Timeline filters' })).toBeInTheDocument();
  });

  it('narrows visible events when severity filter is applied', async () => {
    const user = userEvent.setup();
    render(<InvestigationTimeline />);

    expect(await screen.findByText('Ransomware detonation detected')).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText('Severity filter'), 'critical');

    expect(screen.getByText('Ransomware detonation detected')).toBeInTheDocument();
    expect(screen.queryByText('Suspicious login anomaly')).not.toBeInTheDocument();
    expect(screen.getByText(/1 event /)).toBeInTheDocument();
  });

  it('shows empty state when the search filter matches nothing', async () => {
    const user = userEvent.setup();
    render(<InvestigationTimeline />);

    expect(await screen.findByText('Ransomware detonation detected')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Search timeline events'), 'zzz-no-such-event');

    expect(screen.getByText('No events match filters')).toBeInTheDocument();
  });

  it('re-groups visible events when a group-by dimension is selected', async () => {
    const user = userEvent.setup();
    render(<InvestigationTimeline />);

    expect(await screen.findByText('Ransomware detonation detected')).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText('Group by'), 'host');

    expect(screen.getByText(/host: host-alpha/)).toBeInTheDocument();
    expect(screen.getByText(/host: host-beta/)).toBeInTheDocument();
  });

  it('fetches alerts on mount', async () => {
    render(<InvestigationTimeline />);

    await waitFor(() => {
      const calls = globalThis.fetch.mock.calls.filter(
        ([url]) => new URL(String(url), 'http://localhost').pathname === '/api/alerts',
      );
      expect(calls.length).toBeGreaterThanOrEqual(1);
    });
  });
});

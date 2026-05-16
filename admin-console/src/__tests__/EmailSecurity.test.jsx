import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import EmailSecurity from '../components/EmailSecurity.jsx';
import { ToastProvider } from '../hooks.jsx';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (header) => (header === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

const QUARANTINE_ITEM = {
  id: 'qmail-1',
  from: 'attacker@evil.example',
  subject: 'Urgent password reset',
  phishing_score: 0.82,
  spf: 'fail',
  dkim: 'fail',
  indicators: ['lookalike_domain', 'urgency_language'],
};

const STATS = {
  total_scanned: 1248,
  phishing_detected: 37,
  attachments_flagged: 4,
};

const POLICIES = [
  {
    name: 'Executive Protection',
    quarantine_threshold: 0.6,
    block_dangerous_attachments: true,
    require_spf: true,
    require_dkim: true,
  },
];

describe('EmailSecurity', () => {
  let quarantineState;

  function LocationProbe() {
    const location = useLocation();
    return <div data-testid="email-location">{`${location.pathname}${location.search}`}</div>;
  }

  function renderEmail(route = '/email-security') {
    return render(
      <MemoryRouter initialEntries={[route]}>
        <ToastProvider>
          <EmailSecurity />
          <LocationProbe />
        </ToastProvider>
      </MemoryRouter>,
    );
  }

  beforeEach(() => {
    vi.clearAllMocks();

    quarantineState = [QUARANTINE_ITEM];

    globalThis.fetch = vi.fn((url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const path = parsed.pathname;
      const method = options.method || 'GET';

      if (path === '/api/email/quarantine' && method === 'GET') {
        return Promise.resolve(jsonOk(quarantineState));
      }
      if (path === '/api/email/stats' && method === 'GET') {
        return Promise.resolve(jsonOk(STATS));
      }
      if (path === '/api/email/policies' && method === 'GET') {
        return Promise.resolve(jsonOk(POLICIES));
      }
      if (path === '/api/email/quarantine/qmail-1/release' && method === 'POST') {
        quarantineState = [];
        return Promise.resolve(jsonOk({ status: 'released' }));
      }
      if (path === '/api/email/quarantine/qmail-1' && method === 'DELETE') {
        quarantineState = [];
        return Promise.resolve(jsonOk({ status: 'deleted' }));
      }
      if (path === '/api/email/analyze' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            phishing_score: 0.91,
            auth_results: { spf: 'fail', dkim: 'fail', dmarc: 'fail' },
            sender_mismatch: true,
            urgency_score: 0.75,
            indicators: ['suspicious_url', 'urgency_language'],
          }),
        );
      }
      return Promise.resolve(jsonOk({}));
    });
  });

  it('renders summary cards and the quarantine table from the email APIs', async () => {
    renderEmail();

    expect(await screen.findByText('attacker@evil.example')).toBeInTheDocument();
    expect(screen.getByText('Current email focus')).toBeInTheDocument();
    expect(screen.getByText('Urgent password reset')).toBeInTheDocument();
    expect(screen.getAllByText('1248').length).toBeGreaterThan(0);
    expect(screen.getAllByText('37').length).toBeGreaterThan(0);
    expect(screen.getAllByText('4').length).toBeGreaterThan(0);
    expect(screen.getByText(/lookalike_domain/)).toBeInTheDocument();
  });

  it('releases a quarantined email and reloads the quarantine list', async () => {
    const user = userEvent.setup();

    renderEmail();

    expect(await screen.findByText('attacker@evil.example')).toBeInTheDocument();

    await user.click(
      screen.getByRole('button', { name: 'Release email from attacker@evil.example' }),
    );

    await waitFor(() => {
      const releaseCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/email/quarantine/qmail-1/release' && options?.method === 'POST',
      );
      expect(releaseCall).toBeDefined();
    });

    await waitFor(() => {
      expect(screen.getByText('Quarantine is empty')).toBeInTheDocument();
    });
  });

  it('deletes a quarantined email and reloads the quarantine list', async () => {
    const user = userEvent.setup();

    renderEmail();

    expect(await screen.findByText('attacker@evil.example')).toBeInTheDocument();

    await user.click(
      screen.getByRole('button', { name: 'Delete email from attacker@evil.example' }),
    );

    await waitFor(() => {
      const deleteCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/email/quarantine/qmail-1' && options?.method === 'DELETE',
      );
      expect(deleteCall).toBeDefined();
    });

    await waitFor(() => {
      expect(screen.getByText('Quarantine is empty')).toBeInTheDocument();
    });
  });

  it('analyzes a pasted email payload and renders the phishing verdict', async () => {
    const user = userEvent.setup();

    renderEmail('/email-security?tab=analyze');

    expect(screen.getByTestId('email-location')).toHaveTextContent('/email-security?tab=analyze');

    const input = screen.getByLabelText('Email JSON input');
    await user.click(input);
    await user.paste('{"from":"attacker@evil.example","subject":"Urgent!"}');

    await user.click(screen.getByRole('button', { name: 'Analyze' }));

    await waitFor(() => {
      const analyzeCall = globalThis.fetch.mock.calls.find(
        ([url, options]) => String(url) === '/api/email/analyze' && options?.method === 'POST',
      );
      expect(analyzeCall).toBeDefined();
      expect(JSON.parse(analyzeCall[1].body)).toMatchObject({
        from: 'attacker@evil.example',
        subject: 'Urgent!',
      });
    });

    expect(await screen.findByText('Analysis Result')).toBeInTheDocument();
    expect(screen.getByText('suspicious_url')).toBeInTheDocument();
  });

  it('renders configured policies from the email policies API', async () => {
    renderEmail('/email-security?tab=policies');

    expect(screen.getByTestId('email-location')).toHaveTextContent('/email-security?tab=policies');

    expect(await screen.findByText('Executive Protection')).toBeInTheDocument();
    const policyCard = screen.getByText('Executive Protection').parentElement;
    expect(within(policyCard).getByText('0.60')).toBeInTheDocument();
  });

  it('keeps email focus actions route-backed', async () => {
    const user = userEvent.setup();

    renderEmail('/email-security?tab=policies');

    expect(await screen.findByText('Current email focus')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Review Quarantine' }));
    expect(screen.getByRole('tab', { name: 'quarantine' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('email-location')).toHaveTextContent('/email-security');

    await user.click(screen.getByRole('button', { name: 'Review Policies' }));
    expect(screen.getByRole('tab', { name: 'policies' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('email-location')).toHaveTextContent('/email-security?tab=policies');

    await user.click(screen.getByRole('button', { name: 'Open Priority Lane' }));
    expect(screen.getByRole('tab', { name: 'quarantine' })).toHaveAttribute('aria-selected', 'true');
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { AuthProvider, RoleProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';
import App from '../App.jsx';

const fetchMock = vi.fn();

vi.stubGlobal('fetch', fetchMock);

beforeEach(() => {
  vi.clearAllMocks();
  fetchMock.mockReset();
  localStorage.clear();
  // Default stub: return empty JSON for any api call
  fetchMock.mockResolvedValue({
    ok: true,
    headers: { get: () => 'application/json' },
    json: async () => ({}),
  });
});

function LocationProbe() {
  const location = useLocation();
  return (
    <div data-testid="location-probe">{`${location.pathname}${location.search}${location.hash}`}</div>
  );
}

async function renderApp(initialRoute = '/') {
  let view;
  await act(async () => {
    view = render(
      <MemoryRouter initialEntries={[initialRoute]}>
        <LocationProbe />
        <AuthProvider>
          <ThemeProvider>
            <RoleProvider>
              <ToastProvider>
                <App />
              </ToastProvider>
            </RoleProvider>
          </ThemeProvider>
        </AuthProvider>
      </MemoryRouter>,
    );
  });
  return view;
}

describe('App', () => {
  it('renders without crashing', async () => {
    await renderApp();
    // App should render the sidebar brand
    expect(screen.getByText('Wardex')).toBeInTheDocument();
  });

  it('shows auth form when unauthenticated', async () => {
    await renderApp();
    // Should show the Connect button
    expect(screen.getByText('Connect')).toBeInTheDocument();
  });

  it('shows SSO entry points when enterprise SSO is configured', async () => {
    fetchMock.mockImplementation(async (url) => ({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => {
        if (url === '/api/auth/session') return { authenticated: false };
        if (url === '/api/auth/sso/config') {
          return {
            providers: [{ id: 'idp-1', display_name: 'Corporate SSO' }],
            scim: { enabled: true, status: 'ready', mapping_count: 2 },
          };
        }
        return {};
      },
    }));

    await renderApp();

    expect((await screen.findAllByText('Sign in with Corporate SSO')).length).toBeGreaterThan(0);
    expect(screen.getByText('Federated Sign-In Ready')).toBeInTheDocument();
    expect(screen.getByText('2 group mappings ready for lifecycle sync.')).toBeInTheDocument();
  });

  it('preserves hash-backed route scope in SSO launch redirects while stripping callback errors', async () => {
    const assignSpy = vi.spyOn(window.location, 'assign').mockImplementation(() => {});

    try {
      fetchMock.mockImplementation(async (url) => ({
        ok: true,
        headers: { get: () => 'application/json' },
        json: async () => {
          if (url === '/api/auth/session') return { authenticated: false };
          if (url === '/api/auth/sso/config') {
            return {
              providers: [{ id: 'idp-1', display_name: 'Corporate SSO' }],
              scim: { enabled: true, status: 'ready', mapping_count: 2 },
            };
          }
          return {};
        },
      }));

      await renderApp('/soc?case=42&sso_error=Callback%20failed#cases');

      await userEvent.click((await screen.findAllByRole('button', { name: 'Sign in with Corporate SSO' }))[0]);

      expect(assignSpy).toHaveBeenCalledTimes(1);

      const loginUrl = new URL(assignSpy.mock.calls[0][0], 'http://localhost');
      expect(loginUrl.pathname).toBe('/api/auth/sso/login');
      expect(loginUrl.searchParams.get('provider_id')).toBe('idp-1');
      expect(loginUrl.searchParams.get('redirect')).toBe('/soc?case=42#cases');
    } finally {
      assignSpy.mockRestore();
    }
  });

  it('recovers an existing SSO session after a stale saved token fails authCheck', async () => {
    localStorage.setItem('wardex_token', 'stale-token');
    fetchMock.mockImplementation(async (url) => {
      if (url === '/api/auth/check') {
        return {
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          headers: { get: () => 'application/json' },
          json: async () => ({ error: 'unauthorized' }),
          text: async () => '{"error":"unauthorized"}',
        };
      }
      if (url === '/api/auth/session') {
        return {
          ok: true,
          headers: { get: () => 'application/json' },
          json: async () => ({ authenticated: true, role: 'admin', user_id: 'sso-user@example.com' }),
        };
      }
      return {
        ok: true,
        headers: { get: () => 'application/json' },
        json: async () => ({}),
      };
    });

    await renderApp('/settings?tab=integrations');

    expect(await screen.findByRole('heading', { name: 'Settings' })).toBeInTheDocument();
    expect(screen.queryByText('Welcome to Wardex Admin Console')).not.toBeInTheDocument();
    expect(localStorage.getItem('wardex_token')).toBeNull();
  });

  it('keeps SSO entry points visible when authCheck fails and no session can be restored', async () => {
    localStorage.setItem('wardex_token', 'stale-token');
    fetchMock.mockImplementation(async (url) => {
      if (url === '/api/auth/check') {
        return {
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          headers: { get: () => 'application/json' },
          json: async () => ({ error: 'unauthorized' }),
          text: async () => '{"error":"unauthorized"}',
        };
      }
      if (url === '/api/auth/session') {
        return {
          ok: true,
          headers: { get: () => 'application/json' },
          json: async () => ({ authenticated: false }),
        };
      }
      if (url === '/api/auth/sso/config') {
        return {
          ok: true,
          headers: { get: () => 'application/json' },
          json: async () => ({
            providers: [{ id: 'idp-1', display_name: 'Corporate SSO' }],
            scim: { enabled: false, status: 'disabled', mapping_count: 0 },
          }),
        };
      }
      return {
        ok: true,
        headers: { get: () => 'application/json' },
        json: async () => ({}),
      };
    });

    await renderApp();

    expect(await screen.findByText('Welcome to Wardex Admin Console')).toBeInTheDocument();
    expect((await screen.findAllByText('Sign in with Corporate SSO')).length).toBeGreaterThan(0);
    expect(localStorage.getItem('wardex_token')).toBeNull();
  });

  it('renders sidebar navigation items', async () => {
    await renderApp();
    // Check that navigation labels exist
    expect(screen.getAllByText('Dashboard').length).toBeGreaterThanOrEqual(1);
  });

  it('disables Connect button when token input is empty', async () => {
    await renderApp();
    const btn = screen.getByText('Connect');
    expect(btn).toBeDisabled();
  });

  it('enables Connect button when token is entered', async () => {
    await renderApp();
    const input = screen.getAllByPlaceholderText('Paste API token…')[0];
    await userEvent.type(input, 'my-secret-token');
    expect(screen.getByText('Connect')).not.toBeDisabled();
  });

  it('shows auth error on failed connection', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        headers: { get: () => null },
        json: async () => ({}),
        text: async () => '{"error":"unauthorized"}',
      }),
    );
    await renderApp();
    const input = screen.getAllByPlaceholderText('Paste API token…')[0];
    await userEvent.type(input, 'bad-token');
    await userEvent.click(screen.getByText('Connect'));
    await waitFor(
      () => {
        expect(screen.getAllByText(/Authentication failed/).length).toBeGreaterThan(0);
      },
      { timeout: 3000 },
    );
  });

  it('displays skip-to-content link for accessibility', async () => {
    await renderApp();
    const skipLink = screen.getByText('Skip to main content');
    expect(skipLink).toBeInTheDocument();
    expect(skipLink.getAttribute('href')).toBe('#main-content');
  });

  it('renders theme toggle button', async () => {
    await renderApp();
    const themeBtn = screen.getByTitle(/mode/i);
    expect(themeBtn).toBeInTheDocument();
  });

  it('navigates to unknown route and redirects to /', async () => {
    await renderApp('/nonexistent');
    // Should redirect to dashboard
    expect(screen.getAllByText('Dashboard').length).toBeGreaterThanOrEqual(1);
  });

  it('renders welcome message when unauthenticated', async () => {
    await renderApp();
    expect(screen.getByText('Welcome to Wardex Admin Console')).toBeInTheDocument();
  });

  it('does not block unauthenticated login with onboarding', async () => {
    await renderApp();
    expect(screen.queryByText('Set up the Wardex admin console')).not.toBeInTheDocument();
  });

  it('keeps a recovery navigation toggle after collapsing the sidebar', async () => {
    await renderApp();
    await userEvent.click(screen.getByLabelText('Toggle sidebar'));
    const recoveryToggle = screen.getByRole('button', { name: 'Toggle navigation menu' });
    expect(recoveryToggle).toBeInTheDocument();
    expect(recoveryToggle).toHaveTextContent('Show Menu');
    await userEvent.click(recoveryToggle);
    expect(screen.getByRole('button', { name: 'Toggle navigation menu' })).toHaveTextContent(
      'Hide Menu',
    );
  });

  it('hydrates pinned views from persisted user preferences', async () => {
    localStorage.setItem('wardex_token', 'persisted-token');
    fetchMock.mockImplementation(async (url) => ({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => {
        if (url === '/api/user/preferences') {
          return {
            pinned_sections: ['live-monitor'],
            updated_at: '2026-04-20T09:00:00Z',
          };
        }
        if (url === '/api/auth/session') return { role: 'viewer' };
        return {};
      },
    }));

    await renderApp();

    expect(await screen.findByText('Pinned Views')).toBeInTheDocument();
  });

  it('renders the analyst assistant route for authenticated analysts', async () => {
    localStorage.setItem('wardex_token', 'persisted-token');
    fetchMock.mockImplementation(async (url) => ({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => {
        if (url === '/api/auth/session') {
          return { authenticated: true, role: 'analyst' };
        }
        if (url === '/api/assistant/status') {
          return { mode: 'retrieval-only', model: 'retrieval-only' };
        }
        if (url === '/api/cases') {
          return {
            cases: [{ id: 42, title: 'Identity escalation case', status: 'investigating' }],
          };
        }
        return {};
      },
    }));

    await renderApp('/assistant');

    expect(await screen.findByRole('heading', { name: 'Analyst Assistant' })).toBeInTheDocument();
    expect(screen.getAllByText('Analyst Assistant').length).toBeGreaterThan(0);
  });

  it('renders the command center route for authenticated analysts', async () => {
    localStorage.setItem('wardex_token', 'persisted-token');
    const requestedUrls = [];
    fetchMock.mockImplementation(async (url) => {
      requestedUrls.push(String(url));
      return {
        ok: true,
        headers: { get: () => 'application/json' },
        json: async () => {
          if (url === '/api/auth/session') {
            return { authenticated: true, role: 'analyst' };
          }
          if (url === '/api/command/summary') {
            return {
              metrics: {
                open_incidents: 1,
                active_cases: 1,
                pending_remediation_reviews: 1,
                connector_issues: 2,
                noisy_rules: 1,
                stale_rules: 1,
                release_candidates: 1,
                compliance_packs: 1,
              },
              lanes: {
                incidents: {
                  annotation:
                    'Active incidents need operator attention before additional pivots or rollout work.',
                  next_step:
                    'Use the SOC workspace to confirm ownership, response pressure, and evidence export state.',
                },
                connectors: {
                  annotation:
                    'One or more collector lanes still need credentials, validation, or fresh ingestion proof.',
                  next_step:
                    'Validate connector credentials and recent evidence before operators depend on the lane.',
                  readiness: {
                    collectors: [
                      {
                        provider: 'aws_cloudtrail',
                        label: 'AWS CloudTrail',
                        enabled: true,
                        last_success_at: '2026-04-28T09:00:00Z',
                      },
                      {
                        provider: 'github_audit',
                        label: 'GitHub Audit Log',
                        enabled: true,
                        last_error_at: '2026-04-28T09:10:00Z',
                        error_category: 'credentials',
                      },
                      {
                        provider: 'crowdstrike_falcon',
                        label: 'CrowdStrike Falcon',
                        enabled: true,
                      },
                      {
                        provider: 'generic_syslog',
                        label: 'Generic Syslog',
                        enabled: true,
                      },
                    ],
                  },
                },
                release: {
                  annotation:
                    'Candidate metadata is available for rollout review, SBOM checks, and rollback planning.',
                  next_step:
                    'Review candidate notes, SBOM context, and rollout readiness before promotion.',
                },
              },
            };
          }
          if (url === '/api/incidents') {
            return {
              incidents: [
                {
                  id: 7,
                  title: 'Credential storm containment',
                  status: 'investigating',
                  severity: 'high',
                },
              ],
            };
          }
          if (url === '/api/remediation/change-reviews') {
            return {
              reviews: [
                {
                  id: 'review-1',
                  title: 'Rollback endpoint package',
                  asset_id: 'edge-host-1',
                  approval_status: 'pending_review',
                  required_approvers: 2,
                  approvals: [],
                },
              ],
            };
          }
          if (url === '/api/content/rules') {
            return {
              rules: [
                {
                  id: 'rule-1',
                  name: 'Noisy credential spray',
                  lifecycle: 'test',
                  last_test_match_count: 8,
                },
              ],
            };
          }
          if (url === '/api/suppressions') {
            return { suppressions: [{ id: 'sup-1', rule_id: 'rule-1' }] };
          }
          if (url === '/api/assistant/status') {
            return { mode: 'retrieval-only', model: 'retrieval-only' };
          }
          if (url === '/api/report-templates') {
            return { templates: [{ id: 'soc2', name: 'SOC 2 evidence pack' }] };
          }
          return {};
        },
      };
    });

    await renderApp('/command');

    expect(await screen.findByRole('heading', { name: /Operate incidents/i })).toBeInTheDocument();
    expect(screen.getAllByText('Command Center').length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Credential storm containment')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('AWS CloudTrail').length).toBeGreaterThan(0);
    expect(screen.getAllByText('GitHub Audit Log').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Guided Remediation Approval Flow').length).toBeGreaterThan(0);
    expect(
      screen.getByText(
        'One or more collector lanes still need credentials, validation, or fresh ingestion proof.',
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText('Review candidate notes, SBOM context, and rollout readiness before promotion.'),
    ).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Connector gaps/i }));
    expect(await screen.findByText('Connector Validation')).toBeInTheDocument();
    expect(requestedUrls).toContain('/api/incidents');
    expect(requestedUrls).toContain('/api/command/summary');
    expect(requestedUrls).toContain('/api/remediation/change-reviews');
    expect(requestedUrls).toContain('/api/content/rules');
    expect(requestedUrls).not.toContain('/api/collectors/github');
    expect(requestedUrls).not.toContain('/api/collectors/crowdstrike');
    expect(requestedUrls).not.toContain('/api/collectors/syslog');
  });

  it('preserves route scope through mobile help and share actions', async () => {
    localStorage.setItem('wardex_token', 'persisted-token');
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(window.navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });

    fetchMock.mockImplementation(async (url) => ({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => {
        if (url === '/api/auth/session') {
          return { authenticated: true, role: 'admin', username: 'tester' };
        }
        if (url === '/api/health') {
          return { status: 'ok', version: '0.53.5' };
        }
        return {};
      },
    }));

    await renderApp('/detection?intent=run-hunt&huntName=Credential%20Storm%20Pivot');

    await userEvent.click(await screen.findByRole('button', { name: 'More' }));
    await userEvent.click(screen.getByRole('menuitem', { name: 'Share Link' }));

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const sharedUrl = new URL(writeText.mock.calls[0][0]);
    expect(sharedUrl.pathname).toBe('/detection');
    expect(sharedUrl.searchParams.get('intent')).toBe('run-hunt');
    expect(sharedUrl.searchParams.get('huntName')).toBe('Credential Storm Pivot');

    await userEvent.click(screen.getByRole('button', { name: 'More' }));
    await userEvent.click(screen.getByRole('menuitem', { name: 'Help For View' }));

    await waitFor(() => {
      const currentUrl = new URL(
        `http://localhost${screen.getByTestId('location-probe').textContent || '/'}`,
      );
      expect(currentUrl.pathname).toBe('/help');
      expect(currentUrl.searchParams.get('intent')).toBe('run-hunt');
      expect(currentUrl.searchParams.get('huntName')).toBe('Credential Storm Pivot');
      expect(currentUrl.searchParams.get('context')).toBe('threat-detection');
    });
  });
});

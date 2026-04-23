import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
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

async function renderApp(initialRoute = '/') {
  let view;
  await act(async () => {
    view = render(
      <MemoryRouter initialEntries={[initialRoute]}>
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
          return { providers: [{ id: 'idp-1', display_name: 'Corporate SSO' }] };
        }
        return {};
      },
    }));

    await renderApp();

    expect((await screen.findAllByText('Sign in with Corporate SSO')).length).toBeGreaterThan(0);
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
        expect(screen.getByText(/Authentication failed/)).toBeInTheDocument();
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
          return { cases: [{ id: 42, title: 'Identity escalation case', status: 'investigating' }] };
        }
        return {};
      },
    }));

    await renderApp('/assistant');

    expect(await screen.findByRole('heading', { name: 'Analyst Assistant' })).toBeInTheDocument();
    expect(screen.getAllByText('Analyst Assistant').length).toBeGreaterThan(0);
  });
});

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
        <ThemeProvider>
          <AuthProvider>
            <RoleProvider>
              <ToastProvider>
                <App />
              </ToastProvider>
            </RoleProvider>
          </AuthProvider>
        </ThemeProvider>
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
});

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from '../components/Dashboard.jsx';
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

function renderDashboard() {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>
              <Dashboard />
            </ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('Dashboard heading', () => {
  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem('wardex_token', 'dashboard-heading-token');
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url) => {
        const href = String(url);
        if (href.includes('/api/auth/check')) return jsonOk({ authenticated: true });
        if (href.includes('/api/auth/session')) {
          return jsonOk({ authenticated: true, role: 'admin', user_id: 'admin-1' });
        }
        return jsonOk({});
      }),
    );
  });

  it('gives the dashboard content region a heading landmark', async () => {
    renderDashboard();
    // PageHeader renders the title as an <h2>, so the page content has a
    // real heading landmark instead of an empty PageHeader.
    expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
  });
});

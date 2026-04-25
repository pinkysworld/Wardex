import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import EmailSecurity from '../components/EmailSecurity.jsx';
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

function renderWithProviders(node, route = '/') {
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

describe('Workspace tab strip a11y', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('wardex_token', 'a11y-token');
    globalThis.fetch = vi.fn(() => Promise.resolve(jsonOk({})));
  });

  it('exposes EmailSecurity tab strip as a labeled tablist with aria-selected tabs', () => {
    renderWithProviders(<EmailSecurity />);

    const tablist = screen.getByRole('tablist', { name: 'Email security sections' });
    expect(tablist).toBeInTheDocument();

    const tabs = screen.getAllByRole('tab');
    expect(tabs.length).toBeGreaterThanOrEqual(3);
    const selected = tabs.filter((t) => t.getAttribute('aria-selected') === 'true');
    expect(selected.length).toBe(1);
  });

  it('exposes NDRDashboard tab strip as a labeled tablist with aria-selected tabs', () => {
    renderWithProviders(<NDRDashboard />, '/ndr');

    const tablist = screen.getByRole('tablist', { name: 'NDR sections' });
    expect(tablist).toBeInTheDocument();

    const tabs = screen.getAllByRole('tab');
    expect(tabs.length).toBeGreaterThanOrEqual(6);
    const selected = tabs.filter((t) => t.getAttribute('aria-selected') === 'true');
    expect(selected.length).toBe(1);
  });
});

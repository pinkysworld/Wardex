import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider, RoleProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';
import { setToken } from '../api.js';
import FleetAgents from '../components/FleetAgents.jsx';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (h) => (h === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

const AGENTS = [
  {
    id: 'a-1',
    hostname: 'web-01',
    os: 'linux',
    version: '0.53.0',
    status: 'online',
    last_seen: new Date().toISOString(),
  },
  {
    id: 'a-2',
    hostname: 'db-01',
    os: 'linux',
    version: '0.52.0',
    status: 'offline',
    last_seen: '2025-01-01T00:00:00Z',
  },
  {
    id: 'a-3',
    hostname: 'win-01',
    os: 'windows',
    version: '0.53.0',
    status: 'online',
    last_seen: new Date().toISOString(),
  },
];

function Wrapper({ children }) {
  return (
    <MemoryRouter>
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>{children}</ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('FleetAgents', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    setToken('');
    globalThis.fetch = vi.fn((url) => {
      const u = String(url);
      if (u.includes('/api/agents')) return Promise.resolve(jsonOk(AGENTS));
      if (u.includes('/api/fleet/status')) return Promise.resolve(jsonOk({ status: 'ok' }));
      if (u.includes('/api/fleet/dashboard'))
        return Promise.resolve(jsonOk({ total_agents: 3, agents: 3 }));
      if (u.includes('/api/swarm')) return Promise.resolve(jsonOk({}));
      if (u.includes('/api/events')) return Promise.resolve(jsonOk([]));
      if (u.includes('/api/platform')) return Promise.resolve(jsonOk({ os: 'linux' }));
      if (u.includes('/api/updates')) return Promise.resolve(jsonOk({}));
      if (u.includes('/api/rollout')) return Promise.resolve(jsonOk({}));
      if (u.includes('/api/policy')) return Promise.resolve(jsonOk({}));
      return Promise.resolve(jsonOk({}));
    });
  });

  it('renders fleet tab by default with metric cards', async () => {
    await act(async () => {
      render(<FleetAgents />, { wrapper: Wrapper });
    });
    expect(screen.getByText('Total Agents')).toBeInTheDocument();
    expect(screen.getByText('Offline Now')).toBeInTheDocument();
  });

  it('switches to agents tab and shows agent table', async () => {
    await act(async () => {
      render(<FleetAgents />, { wrapper: Wrapper });
    });
    const agentsTab = screen.getAllByText('Agents').find((el) => el.classList.contains('tab'));
    await act(async () => {
      fireEvent.click(agentsTab);
    });
    expect(screen.getByText(/Registered Agents/)).toBeInTheDocument();
  });

  it('shows empty state when filters match nothing', async () => {
    // Return empty list for agents
    globalThis.fetch = vi.fn(() => Promise.resolve(jsonOk([])));
    await act(async () => {
      render(<FleetAgents />, { wrapper: Wrapper });
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Agents'));
    });
    expect(screen.getByText('No agents match the current view')).toBeInTheDocument();
  });

  it('renders tab buttons', async () => {
    await act(async () => {
      render(<FleetAgents />, { wrapper: Wrapper });
    });
    const tabs = document.querySelectorAll('.tab');
    const tabLabels = [...tabs].map((t) => t.textContent);
    expect(tabLabels).toContain('Fleet');
    expect(tabLabels).toContain('Agents');
    expect(tabLabels).toContain('Events');
    expect(tabLabels).toContain('Updates');
    expect(tabLabels).toContain('Swarm');
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
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

const createAgents = (count) =>
  Array.from({ length: count }, (_, index) => ({
    id: `a-${index + 1}`,
    hostname: `host-${String(index + 1).padStart(2, '0')}`,
    os: index % 2 === 0 ? 'linux' : 'windows',
    version: '0.53.1',
    status: 'online',
    last_seen: new Date(Date.now() - index * 60_000).toISOString(),
  }));

function installFleetFetchMock(agents = AGENTS) {
  globalThis.fetch = vi.fn((url) => {
    const u = String(url);
    const detailMatch = u.match(/\/api\/agents\/([^/]+)\/details$/);
    if (detailMatch) {
      const agent = agents.find((candidate) => candidate.id === decodeURIComponent(detailMatch[1]));
      return Promise.resolve(jsonOk(agent ?? {}));
    }
    if (u.includes('/api/agents')) return Promise.resolve(jsonOk(agents));
    if (u.includes('/api/fleet/status')) return Promise.resolve(jsonOk({ status: 'ok' }));
    if (u.includes('/api/fleet/dashboard')) {
      return Promise.resolve(jsonOk({ total_agents: agents.length, agents: agents.length }));
    }
    if (u.includes('/api/ws/stats')) {
      return Promise.resolve(jsonOk({ connected_subscribers: 2, events_emitted: 7 }));
    }
    if (u.includes('/api/swarm')) return Promise.resolve(jsonOk({}));
    if (u.includes('/api/events')) return Promise.resolve(jsonOk([]));
    if (u.includes('/api/platform')) return Promise.resolve(jsonOk({ os: 'linux' }));
    if (u.includes('/api/updates'))
      return Promise.resolve(
        jsonOk({
          items: [{ version: '0.53.5', channel: 'stable', notes: 'Current release train' }],
        }),
      );
    if (u.includes('/api/rollout'))
      return Promise.resolve(
        jsonOk({
          rollout_targets: 2,
          rollback_events: 1,
          last_rollout_at: '2026-04-22T10:00:00Z',
          recent_history: [
            {
              id: 'rollout-1',
              agent_id: 'a-2',
              status: 'rolled-back',
              rollout_group: 'canary',
              timestamp: '2026-04-22T10:00:00Z',
              notes: 'Rollback after agent health regression',
            },
          ],
        }),
      );
    if (u.includes('/api/policy'))
      return Promise.resolve(
        jsonOk({
          recent_history: [
            {
              id: 'policy-1',
              actor: 'ops',
              action: 'tightened canary gate',
              timestamp: '2026-04-22T09:30:00Z',
            },
          ],
        }),
      );
    return Promise.resolve(jsonOk({}));
  });
}

async function renderAgentsView(agents = AGENTS) {
  installFleetFetchMock(agents);
  let view;
  await act(async () => {
    view = render(<FleetAgents />, { wrapper: Wrapper });
  });
  const agentsTab = screen.getAllByText('Agents').find((el) => el.classList.contains('tab'));
  await act(async () => {
    fireEvent.click(agentsTab);
  });
  const table = view.container.querySelector('.split-list-table');
  if (!table) {
    throw new Error('split-list-table not rendered');
  }
  return { ...view, table };
}

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

function renderFleet(route = '/') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>
              <FleetAgents />
            </ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('FleetAgents', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    setToken('');
    installFleetFetchMock();
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

  it('clamps keyboard focus after filtering shrinks the visible rows', async () => {
    const { container, table } = await renderAgentsView();
    const desktopTable = container.querySelector('.desktop-table-only');

    await act(async () => {
      fireEvent.keyDown(table, { key: 'j' });
      fireEvent.keyDown(table, { key: 'j' });
    });

    await act(async () => {
      fireEvent.change(screen.getByLabelText('Search agents'), {
        target: { value: 'web-01' },
      });
    });

    expect(desktopTable).not.toBeNull();
    expect(
      within(desktopTable).getByText('web-01').closest('tr')?.classList.contains('row-active'),
    ).toBe(true);

    await act(async () => {
      fireEvent.keyDown(table, { key: 'Enter' });
    });

    const detailPanel = container.querySelector('.triage-detail');
    expect(detailPanel).not.toBeNull();
    expect(
      await within(detailPanel).findByText('web-01', { selector: '.detail-hero-title' }),
    ).toBeInTheDocument();
  });

  it('clamps keyboard focus to the last visible row after pagination narrows the page', async () => {
    const { container, table } = await renderAgentsView(createAgents(26));

    await act(async () => {
      fireEvent.change(screen.getByLabelText('Rows per page'), {
        target: { value: '10' },
      });
    });

    for (let index = 0; index < 9; index += 1) {
      // Mirror real user key repeats so each step observes the latest focused row.
      await act(async () => {
        fireEvent.keyDown(table, { key: 'j' });
      });
    }

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Next' }));
      fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    });

    await act(async () => {
      fireEvent.keyDown(table, { key: 'Enter' });
    });

    const detailPanel = container.querySelector('.triage-detail');
    expect(detailPanel).not.toBeNull();
    expect(
      await within(detailPanel).findByText('host-26', { selector: '.detail-hero-title' }),
    ).toBeInTheDocument();
  });

  it('restores rollout-history focus from the route', async () => {
    await act(async () => {
      renderFleet('/?fleetTab=updates&updatesPanel=rollout');
    });

    const rolloutButton = screen.getByRole('button', { name: 'Rollout History' });
    expect(rolloutButton.className).toContain('active');
    expect(screen.getByText('Recent Rollout History')).toBeInTheDocument();
    expect(screen.getByText('Rollback after agent health regression')).toBeInTheDocument();
  });

  it('opens the offline-agent recovery scope from the updates workspace', async () => {
    await act(async () => {
      renderFleet('/?fleetTab=updates&updatesPanel=recovery');
    });

    expect(screen.getByText('Recovery Watchlist')).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Open Offline Agents' }));
    });

    expect(screen.getByText(/Registered Agents/)).toBeInTheDocument();
    expect(screen.getByText('Status: offline')).toBeInTheDocument();
  });

  it('refreshes grouped fleet surface data from the agents workspace', async () => {
    const callCounts = {
      fleetStatus: 0,
      fleetDashboard: 0,
      agents: 0,
      wsStats: 0,
    };

    globalThis.fetch = vi.fn((url) => {
      const u = String(url);
      if (u.includes('/api/fleet/status')) {
        callCounts.fleetStatus += 1;
        return Promise.resolve(jsonOk({ status: 'ok' }));
      }
      if (u.includes('/api/fleet/dashboard')) {
        callCounts.fleetDashboard += 1;
        return Promise.resolve(jsonOk({ total_agents: AGENTS.length, agents: AGENTS.length }));
      }
      if (u.includes('/api/agents')) {
        callCounts.agents += 1;
        return Promise.resolve(jsonOk(AGENTS));
      }
      if (u.includes('/api/ws/stats')) {
        callCounts.wsStats += 1;
        return Promise.resolve(jsonOk({ connected_subscribers: 2, events_emitted: 7 }));
      }
      if (u.includes('/api/swarm')) return Promise.resolve(jsonOk({}));
      if (u.includes('/api/events')) return Promise.resolve(jsonOk([]));
      if (u.includes('/api/platform')) return Promise.resolve(jsonOk({ os: 'linux' }));
      if (u.includes('/api/updates')) {
        return Promise.resolve(
          jsonOk({
            items: [{ version: '0.53.5', channel: 'stable', notes: 'Current release train' }],
          }),
        );
      }
      if (u.includes('/api/rollout')) {
        return Promise.resolve(
          jsonOk({
            rollout_targets: 2,
            rollback_events: 1,
            last_rollout_at: '2026-04-22T10:00:00Z',
            recent_history: [],
          }),
        );
      }
      if (u.includes('/api/policy')) return Promise.resolve(jsonOk({ recent_history: [] }));
      return Promise.resolve(jsonOk({}));
    });

    await act(async () => {
      render(<FleetAgents />, { wrapper: Wrapper });
    });

    const agentsTab = screen.getAllByText('Agents').find((el) => el.classList.contains('tab'));
    await act(async () => {
      fireEvent.click(agentsTab);
    });

    expect(screen.getByText('Live (2)')).toBeInTheDocument();

    const initialFleetStatusCalls = callCounts.fleetStatus;
    const initialFleetDashboardCalls = callCounts.fleetDashboard;
    const initialAgentCalls = callCounts.agents;
    const initialWsStatsCalls = callCounts.wsStats;

    expect(initialFleetStatusCalls).toBeGreaterThan(0);
    expect(initialFleetDashboardCalls).toBeGreaterThan(0);
    expect(initialAgentCalls).toBeGreaterThan(0);
    expect(initialWsStatsCalls).toBeGreaterThan(0);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    });

    expect(callCounts.fleetStatus).toBe(initialFleetStatusCalls + 1);
    expect(callCounts.fleetDashboard).toBe(initialFleetDashboardCalls + 1);
    expect(callCounts.agents).toBe(initialAgentCalls + 1);
    expect(callCounts.wsStats).toBe(initialWsStatsCalls + 1);
  });
});

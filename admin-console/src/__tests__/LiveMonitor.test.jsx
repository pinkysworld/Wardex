import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, useLocation } from 'react-router-dom';
import LiveMonitor from '../components/LiveMonitor.jsx';
import { AuthProvider, RoleProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';
import { setToken } from '../api.js';
import { wsStatsFixture } from './wsFixtures.js';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (h) => (h === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

const jsonError = (status, data, statusText = 'Error') => ({
  ok: false,
  status,
  statusText,
  headers: { get: (h) => (h === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location-probe">{`${location.pathname}${location.search}`}</div>;
}

function renderMonitor(route = '/monitor') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>
              <LocationProbe />
              <LiveMonitor />
            </ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function currentLocation() {
  return new URL(
    screen.getByTestId('location-probe').textContent || '/monitor',
    'http://localhost',
  );
}

describe('LiveMonitor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    setToken('');
    delete globalThis.WebSocket;
    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('/api/alerts/count')) {
        return Promise.resolve(jsonOk({ total: 0, critical: 0, severe: 0, elevated: 0 }));
      }
      if (String(url).includes('/api/ws/stats')) {
        return Promise.resolve(jsonOk(wsStatsFixture()));
      }
      if (String(url).includes('/api/alerts/grouped')) return Promise.resolve(jsonOk([]));
      if (String(url).includes('/api/alerts')) return Promise.resolve(jsonOk([]));
      if (String(url).includes('/api/processes/live')) {
        return Promise.resolve(jsonOk({ processes: [] }));
      }
      if (String(url).includes('/api/processes/analysis')) {
        return Promise.resolve(jsonOk({ findings: [] }));
      }
      if (String(url).includes('/api/fp-feedback/stats')) return Promise.resolve(jsonOk([]));
      if (String(url).includes('/api/health')) return Promise.resolve(jsonOk({ status: 'ok' }));
      return Promise.resolve(jsonOk({}));
    });
  });

  it('renders alert events pushed over the live feed', async () => {
    const user = userEvent.setup();
    const sockets = [];

    globalThis.WebSocket = class MockWebSocket {
      constructor(url) {
        this.url = url;
        sockets.push(this);
      }

      close() {}

      emitOpen() {
        this.onopen?.();
      }

      emitMessage(payload) {
        this.onmessage?.({ data: payload });
      }
    };

    render(
      <MemoryRouter>
        <AuthProvider>
          <RoleProvider>
            <ThemeProvider>
              <ToastProvider>
                <LiveMonitor />
              </ToastProvider>
            </ThemeProvider>
          </RoleProvider>
        </AuthProvider>
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(sockets).toHaveLength(1);
    });

    await act(async () => {
      sockets[0].emitOpen();
      sockets[0].emitMessage(
        JSON.stringify({
          type: 'alert',
          timestamp: new Date().toISOString(),
          data: {
            id: 42,
            timestamp: new Date().toISOString(),
            hostname: 'edge-1',
            level: 'Critical',
            score: 9.2,
            confidence: 0.95,
            platform: 'linux',
            reasons: ['network burst detected'],
            action: 'alert',
          },
        }),
      );
      sockets[0].emitMessage(
        JSON.stringify({
          event_type: 'incident',
          timestamp: new Date().toISOString(),
          data: {
            id: 'inc-17',
            title: 'Credential misuse follow-up',
            severity: 'high',
          },
        }),
      );
    });

    expect((await screen.findAllByText('network burst detected')).length).toBeGreaterThan(0);
    expect(screen.getByText('Live feed: WebSocket')).toBeInTheDocument();
    expect(screen.getByText('Transport and Recovery')).toBeInTheDocument();
    expect(screen.getAllByText('critical').length).toBeGreaterThan(0);

    await user.click(screen.getByRole('button', { name: /incident \(1\)/i }));

    expect(await screen.findByText('Credential misuse follow-up')).toBeInTheDocument();
  });

  it('refreshes grouped alert summaries and process data from the existing controls', async () => {
    const user = userEvent.setup();
    const callCounts = {
      alerts: 0,
      alertCounts: 0,
      alertGroups: 0,
      processLive: 0,
      processAnalysis: 0,
      processTree: 0,
      processDeepChains: 0,
    };

    globalThis.fetch = vi.fn((url) => {
      const href = String(url);

      if (href.includes('/api/alerts/count')) {
        callCounts.alertCounts += 1;
        return Promise.resolve(jsonOk({ total: 1, critical: 1, severe: 0, elevated: 0 }));
      }
      if (href.includes('/api/alerts/grouped')) {
        callCounts.alertGroups += 1;
        return Promise.resolve(
          jsonOk([
            {
              fingerprint: 'ssh-burst',
              alert_count: 1,
              severity: 'critical',
              reasons: ['Repeated SSH failures'],
            },
          ]),
        );
      }
      if (href.includes('/api/alerts')) {
        callCounts.alerts += 1;
        return Promise.resolve(
          jsonOk([
            {
              id: 'alert-1',
              timestamp: new Date().toISOString(),
              hostname: 'edge-1',
              severity: 'critical',
              source: 'sensor',
              message: 'SSH burst detected',
              reasons: ['Repeated SSH failures'],
            },
          ]),
        );
      }
      if (href.includes('/api/processes/live')) {
        callCounts.processLive += 1;
        return Promise.resolve(
          jsonOk({
            count: 1,
            processes: [
              {
                pid: 1337,
                ppid: 1,
                name: 'sshd',
                user: 'root',
                group: 'wheel',
                cpu_percent: 8.4,
                mem_percent: 2.1,
              },
            ],
          }),
        );
      }
      if (href.includes('/api/process-tree/deep-chains')) {
        callCounts.processDeepChains += 1;
        return Promise.resolve(
          jsonOk({
            deep_chains: [
              {
                pid: 1337,
                name: 'sshd',
                cmd_line: 'sshd -> bash -> curl',
                depth: 3,
              },
            ],
          }),
        );
      }
      if (href.includes('/api/process-tree')) {
        callCounts.processTree += 1;
        return Promise.resolve(
          jsonOk({
            processes: [
              { pid: 1, ppid: 0, name: 'launchd', user: 'root' },
              { pid: 1337, ppid: 1, name: 'sshd', user: 'root' },
            ],
          }),
        );
      }
      if (href.includes('/api/processes/analysis')) {
        callCounts.processAnalysis += 1;
        return Promise.resolve(
          jsonOk({
            total: 1,
            findings: [
              {
                pid: 1337,
                name: 'sshd',
                verdict: 'review',
                reason: 'Unusual remote login burst',
              },
            ],
          }),
        );
      }
      if (href.includes('/api/ws/stats')) {
        return Promise.resolve(jsonOk(wsStatsFixture()));
      }
      if (href.includes('/api/fp-feedback/stats')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/health')) return Promise.resolve(jsonOk({ status: 'ok' }));
      return Promise.resolve(jsonOk({}));
    });

    render(
      <MemoryRouter>
        <AuthProvider>
          <RoleProvider>
            <ThemeProvider>
              <ToastProvider>
                <LiveMonitor />
              </ToastProvider>
            </ThemeProvider>
          </RoleProvider>
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(callCounts.alerts).toBeGreaterThan(0);
      expect(callCounts.alertCounts).toBeGreaterThan(0);
      expect(callCounts.alertGroups).toBeGreaterThan(0);
    });

    const initialAlerts = callCounts.alerts;
    const initialAlertCounts = callCounts.alertCounts;
    const initialAlertGroups = callCounts.alertGroups;

    await user.click(screen.getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(callCounts.alerts).toBe(initialAlerts + 1);
      expect(callCounts.alertCounts).toBe(initialAlertCounts + 1);
      expect(callCounts.alertGroups).toBe(initialAlertGroups + 1);
    });

    await user.click(screen.getByRole('tab', { name: 'Processes' }));
    await screen.findByRole('button', { name: 'Export JSON' });

    const initialProcessLive = callCounts.processLive;
    const initialProcessAnalysis = callCounts.processAnalysis;
    const initialProcessTree = callCounts.processTree;
    const initialProcessDeepChains = callCounts.processDeepChains;

    const processCard = screen.getByRole('button', { name: 'Export JSON' }).closest('.card');
    if (!processCard) throw new Error('running processes card not found');
    expect(await screen.findByText('Process Graph Context')).toBeInTheDocument();
    expect(screen.getByText('sshd · sshd -> bash -> curl')).toBeInTheDocument();

    await user.click(within(processCard).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(callCounts.processLive).toBe(initialProcessLive + 1);
      expect(callCounts.processAnalysis).toBe(initialProcessAnalysis + 1);
      expect(callCounts.processTree).toBe(initialProcessTree + 1);
      expect(callCounts.processDeepChains).toBe(initialProcessDeepChains + 1);
    });
  });

  it('falls back to the GET alert analysis route when the POST request fails', async () => {
    const user = userEvent.setup();
    let postAttempts = 0;
    let getAttempts = 0;

    globalThis.fetch = vi.fn((url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/alerts/analysis') && method === 'POST') {
        postAttempts += 1;
        return Promise.resolve(
          jsonError(500, { error: 'analysis pipeline unavailable' }, 'Internal Server Error'),
        );
      }
      if (href.includes('/api/alerts/analysis') && method === 'GET') {
        getAttempts += 1;
        return Promise.resolve(
          jsonOk({
            summary: 'Queue pressure is concentrated around repeated SSH failures.',
            recommended_actions: ['Inspect the originating host.'],
          }),
        );
      }
      if (href.includes('/api/alerts/count')) {
        return Promise.resolve(jsonOk({ total: 0, critical: 0, severe: 0, elevated: 0 }));
      }
      if (href.includes('/api/ws/stats')) return Promise.resolve(jsonOk(wsStatsFixture()));
      if (href.includes('/api/alerts/grouped')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/alerts')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/processes/live')) return Promise.resolve(jsonOk({ processes: [] }));
      if (href.includes('/api/processes/analysis')) return Promise.resolve(jsonOk({ findings: [] }));
      if (href.includes('/api/fp-feedback/stats')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/health')) return Promise.resolve(jsonOk({ status: 'ok' }));
      return Promise.resolve(jsonOk({}));
    });

    renderMonitor('/monitor?monitorTab=analysis');

    await user.click(await screen.findByRole('button', { name: 'Run Analysis' }));

    expect(
      await screen.findAllByText('Queue pressure is concentrated around repeated SSH failures.'),
    ).toHaveLength(2);
    expect(postAttempts).toBe(1);
    expect(getAttempts).toBe(1);
  });

  it('restores the current monitor scroll position after refreshing process data', async () => {
    const user = userEvent.setup();

    globalThis.fetch = vi.fn((url) => {
      const href = String(url);

      if (href.includes('/api/alerts/count')) {
        return Promise.resolve(jsonOk({ total: 1, critical: 1, severe: 0, elevated: 0 }));
      }
      if (href.includes('/api/ws/stats')) return Promise.resolve(jsonOk(wsStatsFixture()));
      if (href.includes('/api/alerts/grouped')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/alerts')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/processes/live')) {
        return Promise.resolve(
          jsonOk({
            count: 1,
            processes: [
              {
                pid: 1337,
                ppid: 1,
                name: 'sshd',
                user: 'root',
                group: 'wheel',
                cpu_percent: 8.4,
                mem_percent: 2.1,
              },
            ],
          }),
        );
      }
      if (href.includes('/api/process-tree/deep-chains')) {
        return Promise.resolve(jsonOk({ deep_chains: [] }));
      }
      if (href.includes('/api/process-tree')) {
        return Promise.resolve(jsonOk({ processes: [{ pid: 1, ppid: 0, name: 'launchd' }] }));
      }
      if (href.includes('/api/processes/analysis')) {
        return Promise.resolve(jsonOk({ total: 0, findings: [] }));
      }
      if (href.includes('/api/fp-feedback/stats')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/health')) return Promise.resolve(jsonOk({ status: 'ok' }));
      return Promise.resolve(jsonOk({}));
    });

    Object.defineProperty(window, 'scrollY', {
      value: 420,
      writable: true,
      configurable: true,
    });
    window.scrollTo = vi.fn((x, y) => {
      window.scrollY = typeof y === 'number' ? y : Number(x?.top ?? window.scrollY);
    });

    renderMonitor('/monitor?monitorTab=processes');

    await screen.findByText('All Processes');
    const refreshButton = screen.getAllByRole('button', { name: '↻ Refresh' })[0];
    const processCard = screen.getByText('All Processes').closest('.card');
    const processTable = processCard?.querySelector('.table-wrap');
    if (!processTable) throw new Error('process table not found');

    processTable.scrollTop = 215;
    await user.click(refreshButton);

    await waitFor(() => {
      expect(window.scrollTo).toHaveBeenCalledWith(0, 420);
    });
    expect(processTable.scrollTop).toBe(215);
  });

  it('restores route-backed monitor scope and preserves filters across tab and drawer changes', async () => {
    const user = userEvent.setup();

    globalThis.fetch = vi.fn((url) => {
      const href = String(url);

      if (href.includes('/api/alerts/count')) {
        return Promise.resolve(jsonOk({ total: 1, critical: 1, severe: 0, elevated: 0 }));
      }
      if (href.includes('/api/ws/stats')) {
        return Promise.resolve(jsonOk(wsStatsFixture()));
      }
      if (href.includes('/api/alerts/grouped')) {
        return Promise.resolve(
          jsonOk([
            {
              fingerprint: 'ssh-burst',
              alert_count: 1,
              severity: 'critical',
              reasons: ['Repeated SSH failures'],
            },
          ]),
        );
      }
      if (href.includes('/api/alerts')) {
        return Promise.resolve(
          jsonOk([
            {
              id: 'alert-1',
              timestamp: new Date().toISOString(),
              hostname: 'edge-1',
              severity: 'critical',
              source: 'sensor',
              category: 'auth',
              message: 'SSH burst detected',
              reasons: ['Repeated SSH failures'],
            },
          ]),
        );
      }
      if (href.includes('/api/processes/live')) {
        return Promise.resolve(
          jsonOk({
            count: 1,
            processes: [
              {
                pid: 1337,
                ppid: 1,
                name: 'sshd',
                user: 'root',
                group: 'wheel',
                cpu_percent: 8.4,
                mem_percent: 2.1,
              },
            ],
          }),
        );
      }
      if (href.includes('/api/process-tree/deep-chains')) {
        return Promise.resolve(
          jsonOk({
            deep_chains: [
              {
                pid: 1337,
                name: 'sshd',
                cmd_line: 'sshd -> bash -> curl',
                depth: 3,
              },
            ],
          }),
        );
      }
      if (href.includes('/api/process-tree')) {
        return Promise.resolve(
          jsonOk({
            processes: [
              { pid: 1, ppid: 0, name: 'launchd', user: 'root' },
              { pid: 1337, ppid: 1, name: 'sshd', user: 'root' },
            ],
          }),
        );
      }
      if (href.includes('/api/processes/analysis')) {
        return Promise.resolve(
          jsonOk({
            total: 1,
            findings: [
              {
                pid: 1337,
                name: 'sshd',
                verdict: 'review',
                reason: 'Unusual remote login burst',
              },
            ],
          }),
        );
      }
      if (href.includes('/api/fp-feedback/stats')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/health')) return Promise.resolve(jsonOk({ status: 'ok' }));
      return Promise.resolve(jsonOk({}));
    });

    renderMonitor(
      '/monitor?monitorTab=processes&alert=alert-1&sev=critical&source=sensor&host=edge-1&q=SSH',
    );

    const processesTab = await screen.findByRole('tab', { name: 'Processes' });
    expect(processesTab).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByText('Process Graph Context')).toBeInTheDocument();

    let params = currentLocation().searchParams;
    expect(params.get('monitorTab')).toBe('processes');
    expect(params.get('alert')).toBe('alert-1');
    expect(params.get('sev')).toBe('critical');
    expect(params.get('source')).toBe('sensor');
    expect(params.get('host')).toBe('edge-1');
    expect(params.get('q')).toBe('SSH');

    await user.click(screen.getByRole('tab', { name: 'Alert Stream' }));

    await waitFor(() => {
      expect(currentLocation().searchParams.get('monitorTab')).toBe('stream');
    });

    expect(await screen.findByText('Source: sensor')).toBeInTheDocument();
    expect(await screen.findByText('Host: edge-1')).toBeInTheDocument();
    expect(await screen.findByText('Query: SSH')).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Close Drawer' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Close Drawer' }));

    await waitFor(() => {
      const nextParams = currentLocation().searchParams;
      expect(nextParams.get('monitorTab')).toBe('stream');
      expect(nextParams.has('alert')).toBe(false);
      expect(nextParams.get('sev')).toBe('critical');
      expect(nextParams.get('source')).toBe('sensor');
      expect(nextParams.get('host')).toBe('edge-1');
      expect(nextParams.get('q')).toBe('SSH');
    });

    expect(screen.getByRole('button', { name: 'Open Drawer' })).toBeInTheDocument();
  });

  it('supports keyboard-first alert triage shortcuts', async () => {
    const bulkTriageCalls = [];

    globalThis.fetch = vi.fn((url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/alerts/count')) {
        return Promise.resolve(jsonOk({ total: 1, critical: 1, severe: 0, elevated: 0 }));
      }
      if (href.includes('/api/ws/stats')) {
        return Promise.resolve(jsonOk(wsStatsFixture()));
      }
      if (href.includes('/api/alerts/grouped')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/alerts')) {
        return Promise.resolve(
          jsonOk([
            {
              id: 'alert-1',
              timestamp: new Date().toISOString(),
              hostname: 'edge-1',
              severity: 'critical',
              source: 'sensor',
              category: 'auth',
              message: 'SSH burst detected',
              reasons: ['Repeated SSH failures'],
            },
          ]),
        );
      }
      if (href.includes('/api/processes/live')) {
        return Promise.resolve(jsonOk({ processes: [] }));
      }
      if (href.includes('/api/processes/analysis')) {
        return Promise.resolve(jsonOk({ findings: [] }));
      }
      if (href.includes('/api/fp-feedback/stats')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/fp-feedback') && method === 'POST') {
        return Promise.resolve(jsonOk({ status: 'ok' }));
      }
      if (href.includes('/api/events/bulk-triage') && method === 'POST') {
        bulkTriageCalls.push(JSON.parse(options.body));
        return Promise.resolve(jsonOk({ status: 'ok' }));
      }
      if (href.includes('/api/health')) return Promise.resolve(jsonOk({ status: 'ok' }));
      return Promise.resolve(jsonOk({}));
    });

    render(
      <MemoryRouter>
        <AuthProvider>
          <RoleProvider>
            <ThemeProvider>
              <ToastProvider>
                <LiveMonitor />
              </ToastProvider>
            </ThemeProvider>
          </RoleProvider>
        </AuthProvider>
      </MemoryRouter>,
    );

    const alertCheckbox = await screen.findByLabelText('Select alert alert-1');
    expect(screen.getByText(/Shortcuts:/i)).toBeInTheDocument();

    fireEvent.keyDown(window, { key: '/' });
    expect(document.activeElement).toHaveAttribute(
      'placeholder',
      'Search message, host, user, category…',
    );

    document.activeElement.blur();
    fireEvent.keyDown(window, { key: 'ArrowDown' });

    await waitFor(() => {
      expect(alertCheckbox.closest('tr')).toHaveClass('row-active');
    });

    fireEvent.keyDown(window, { key: 'x' });

    await waitFor(() => {
      expect(alertCheckbox).toBeChecked();
    });

    fireEvent.keyDown(window, { key: 't' });

    await waitFor(() => {
      expect(bulkTriageCalls).toHaveLength(1);
      expect(bulkTriageCalls[0]).toEqual({ event_ids: ['alert-1'], verdict: 'acknowledged' });
    });
  });

  it('opens the shortcut guide from the keyboard', async () => {
    globalThis.fetch = vi.fn((url) => {
      const href = String(url);
      if (href.includes('/api/alerts/count')) {
        return Promise.resolve(jsonOk({ total: 1, critical: 1, severe: 0, elevated: 0 }));
      }
      if (href.includes('/api/ws/stats')) {
        return Promise.resolve(jsonOk(wsStatsFixture()));
      }
      if (href.includes('/api/alerts/grouped')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/alerts')) {
        return Promise.resolve(
          jsonOk([
            {
              id: 'alert-1',
              timestamp: new Date().toISOString(),
              hostname: 'edge-1',
              severity: 'critical',
              source: 'sensor',
              message: 'SSH burst detected',
              reasons: ['Repeated SSH failures'],
            },
          ]),
        );
      }
      if (href.includes('/api/processes/live')) {
        return Promise.resolve(jsonOk({ processes: [] }));
      }
      if (href.includes('/api/processes/analysis')) {
        return Promise.resolve(jsonOk({ findings: [] }));
      }
      if (href.includes('/api/fp-feedback/stats')) return Promise.resolve(jsonOk([]));
      if (href.includes('/api/health')) return Promise.resolve(jsonOk({ status: 'ok' }));
      return Promise.resolve(jsonOk({}));
    });

    render(
      <MemoryRouter>
        <AuthProvider>
          <RoleProvider>
            <ThemeProvider>
              <ToastProvider>
                <LiveMonitor />
              </ToastProvider>
            </ThemeProvider>
          </RoleProvider>
        </AuthProvider>
      </MemoryRouter>,
    );

    await screen.findByLabelText('Select alert alert-1');
    fireEvent.keyDown(window, { key: '?' });

    expect(await screen.findByRole('dialog', { name: 'Keyboard shortcuts' })).toBeInTheDocument();
    expect(screen.getByText('Queue navigation')).toBeInTheDocument();
    expect(screen.getByText('Selection and triage')).toBeInTheDocument();
  });
});

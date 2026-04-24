import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import LiveMonitor from '../components/LiveMonitor.jsx';
import { AuthProvider, RoleProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';
import { setToken } from '../api.js';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (h) => (h === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

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
        return Promise.resolve(
          jsonOk({ connected_clients: 1, total_events: 2, subscribers: 1, connections: [] }),
        );
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
    expect(sockets).toHaveLength(1);

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
        return Promise.resolve(
          jsonOk({ connected_clients: 1, total_events: 2, subscribers: 1, connections: [] }),
        );
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

    const processCard = screen.getByRole('button', { name: 'Export JSON' }).closest('.card');
    if (!processCard) throw new Error('running processes card not found');

    await user.click(within(processCard).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(callCounts.processLive).toBe(initialProcessLive + 1);
      expect(callCounts.processAnalysis).toBe(initialProcessAnalysis + 1);
    });
  });
});

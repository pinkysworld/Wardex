import { act, render, screen } from '@testing-library/react';
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
});

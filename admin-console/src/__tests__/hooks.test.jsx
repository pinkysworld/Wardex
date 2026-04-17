import { render, renderHook, screen, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider, RoleProvider, ThemeProvider, ToastProvider, useAuth, useTheme, useToast, useWebSocket } from '../hooks.jsx';

// Stub fetch globally
const fetchMock = vi.fn();
vi.stubGlobal('fetch', fetchMock);

const jsonOk = (data) => ({
  ok: true,
  headers: { get: () => 'application/json' },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

beforeEach(() => {
  vi.clearAllMocks();
  fetchMock.mockReset();
  // Default: return a valid JSON response for any call
  fetchMock.mockImplementation(() => Promise.resolve(jsonOk({})));
  localStorage.clear();
});

// Helper to wrap components with all providers
function Providers({ children }) {
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

describe('AuthProvider', () => {
  it('starts unauthenticated', () => {
    const { result } = renderHook(() => useAuth(), { wrapper: Providers });
    expect(result.current.authenticated).toBe(false);
  });

  it('connect sets authenticated on success', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper: Providers });
    expect(result.current.authenticated).toBe(false);

    await act(async () => {
      await result.current.connect('valid-token');
    });
    expect(result.current.authenticated).toBe(true);
  });

  it('disconnect clears authentication', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper: Providers });
    await act(async () => { await result.current.connect('tok'); });
    expect(result.current.authenticated).toBe(true);

    act(() => { result.current.disconnect(); });
    expect(result.current.authenticated).toBe(false);
  });
});

describe('ThemeProvider', () => {
  it('defaults to system preference', () => {
    const { result } = renderHook(() => useTheme(), { wrapper: Providers });
    expect(typeof result.current.dark).toBe('boolean');
  });

  it('toggle flips dark mode', () => {
    const { result } = renderHook(() => useTheme(), { wrapper: Providers });
    const initial = result.current.dark;

    act(() => { result.current.toggle(); });
    const toggled = result.current.dark;
    expect(toggled).not.toBe(initial);
  });
});

describe('ToastProvider', () => {
  it('renders toast messages', async () => {
    const { result } = renderHook(() => useToast(), { wrapper: Providers });
    act(() => { result.current('Test notification', 'info'); });
    expect(screen.getByText('Test notification')).toBeInTheDocument();
  });
});

describe('useWebSocket', () => {
  beforeEach(() => {
    vi.useRealTimers();
    delete globalThis.WebSocket;
  });

  function WebSocketProbe({ interval = 2000 }) {
    const { connected, events } = useWebSocket(interval);
    return (
      <>
        <div data-testid="ws-connected">{String(connected)}</div>
        <div data-testid="ws-events">{String(events.length)}</div>
      </>
    );
  }

  it('falls back to polling only once when websocket connection fails before open', async () => {
    vi.useFakeTimers();
    const sockets = [];

    globalThis.WebSocket = class MockWebSocket {
      constructor(url) {
        this.url = url;
        this.readyState = 0;
        sockets.push(this);
      }
      close() {
        this.readyState = 3;
        this.onclose?.();
      }
      emitError() {
        this.onerror?.(new Event('error'));
      }
    };

    fetchMock.mockImplementation((url) => {
      if (url === '/api/ws/connect') return Promise.resolve(jsonOk({ subscriber_id: 7 }));
      if (url === '/api/ws/disconnect') return Promise.resolve(jsonOk({ ok: true }));
      if (url === '/api/ws/poll') return Promise.resolve(jsonOk([]));
      return Promise.resolve(jsonOk({}));
    });

    render(<WebSocketProbe interval={10_000} />);
    expect(sockets).toHaveLength(1);

    act(() => {
      sockets[0].emitError();
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });

    const connectCalls = fetchMock.mock.calls.filter(([url]) => url === '/api/ws/connect');
    expect(connectCalls).toHaveLength(1);
  });

  it('falls back to polling after a later websocket reconnect failure', async () => {
    vi.useFakeTimers();
    const sockets = [];

    globalThis.WebSocket = class MockWebSocket {
      constructor(url) {
        this.url = url;
        this.readyState = 0;
        sockets.push(this);
      }
      close() {
        this.readyState = 3;
        this.onclose?.();
      }
      emitOpen() {
        this.readyState = 1;
        this.onopen?.();
      }
      emitError() {
        this.onerror?.(new Event('error'));
      }
    };

    fetchMock.mockImplementation((url) => {
      if (url === '/api/ws/connect') return Promise.resolve(jsonOk({ subscriber_id: 9 }));
      if (url === '/api/ws/disconnect') return Promise.resolve(jsonOk({ ok: true }));
      if (url === '/api/ws/poll') return Promise.resolve(jsonOk([]));
      return Promise.resolve(jsonOk({}));
    });

    render(<WebSocketProbe interval={10_000} />);
    expect(sockets).toHaveLength(1);

    act(() => {
      sockets[0].emitOpen();
    });
    expect(screen.getByTestId('ws-connected').textContent).toBe('true');

    act(() => {
      sockets[0].close();
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000);
    });

    expect(sockets).toHaveLength(2);

    act(() => {
      sockets[1].emitError();
    });

    await act(async () => {
      await Promise.resolve();
    });

    const connectCalls = fetchMock.mock.calls.filter(([url]) => url === '/api/ws/connect');
    expect(connectCalls).toHaveLength(1);
  });

  it('releases a polling subscriber when the component unmounts during connect', async () => {
    vi.useFakeTimers();
    const sockets = [];
    let resolveConnect;

    globalThis.WebSocket = class MockWebSocket {
      constructor(url) {
        this.url = url;
        this.readyState = 0;
        sockets.push(this);
      }
      close() {
        this.readyState = 3;
        this.onclose?.();
      }
      emitError() {
        this.onerror?.(new Event('error'));
      }
    };

    fetchMock.mockImplementation((url) => {
      if (url === '/api/ws/connect') {
        return new Promise((resolve) => {
          resolveConnect = () => resolve(jsonOk({ subscriber_id: 11 }));
        });
      }
      if (url === '/api/ws/disconnect') return Promise.resolve(jsonOk({ ok: true }));
      if (url === '/api/ws/poll') return Promise.resolve(jsonOk([]));
      return Promise.resolve(jsonOk({}));
    });

    const view = render(<WebSocketProbe interval={10_000} />);
    expect(sockets).toHaveLength(1);

    act(() => {
      sockets[0].emitError();
    });

    view.unmount();

    await act(async () => {
      resolveConnect();
      await Promise.resolve();
    });

    const disconnectCalls = fetchMock.mock.calls.filter(([url]) => url === '/api/ws/disconnect');
    expect(disconnectCalls).toHaveLength(1);
  });
});

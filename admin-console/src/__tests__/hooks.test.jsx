import { render, renderHook, screen, act, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import {
  AuthProvider,
  RoleProvider,
  ThemeProvider,
  ToastProvider,
  useAuth,
  useTheme,
  useToast,
  useWebSocket,
} from '../hooks.jsx';
import { setToken } from '../api.js';

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
  setToken('');
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
  it('starts unauthenticated', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper: Providers });

    await waitFor(() => {
      expect(result.current.checking).toBe(false);
    });

    expect(result.current.authenticated).toBe(false);
  });

  it('restores an existing authenticated session', async () => {
    fetchMock.mockImplementation((url) => {
      if (url === '/api/auth/session') {
        return Promise.resolve(jsonOk({ authenticated: true, role: 'analyst', source: 'session' }));
      }
      return Promise.resolve(jsonOk({}));
    });

    const { result } = renderHook(() => useAuth(), { wrapper: Providers });

    await waitFor(() => {
      expect(result.current.authenticated).toBe(true);
    });
  });

  it('connect sets authenticated on success', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper: Providers });

    await waitFor(() => {
      expect(result.current.checking).toBe(false);
    });

    expect(result.current.authenticated).toBe(false);

    await act(async () => {
      await result.current.connect('valid-token');
    });
    expect(result.current.authenticated).toBe(true);
  });

  it('disconnect clears authentication', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper: Providers });

    await waitFor(() => {
      expect(result.current.checking).toBe(false);
    });

    await act(async () => {
      await result.current.connect('tok');
    });
    expect(result.current.authenticated).toBe(true);

    act(() => {
      result.current.disconnect();
    });
    expect(result.current.authenticated).toBe(false);
  });
});

describe('ThemeProvider', () => {
  it('defaults to system preference', async () => {
    const { result } = renderHook(() => ({ auth: useAuth(), theme: useTheme() }), {
      wrapper: Providers,
    });

    await waitFor(() => {
      expect(result.current.auth.checking).toBe(false);
    });

    expect(typeof result.current.theme.dark).toBe('boolean');
  });

  it('toggle flips dark mode', async () => {
    const { result } = renderHook(() => ({ auth: useAuth(), theme: useTheme() }), {
      wrapper: Providers,
    });

    await waitFor(() => {
      expect(result.current.auth.checking).toBe(false);
    });

    const initial = result.current.theme.dark;

    act(() => {
      result.current.theme.toggle();
    });
    const toggled = result.current.theme.dark;
    expect(toggled).not.toBe(initial);
  });

  it('loads persisted theme after authentication', async () => {
    localStorage.setItem('wardex_theme', 'light');
    fetchMock.mockImplementation((url) => {
      if (url === '/api/user/preferences') return Promise.resolve(jsonOk({ theme: 'dark' }));
      if (url === '/api/auth/session') return Promise.resolve(jsonOk({ role: 'viewer' }));
      return Promise.resolve(jsonOk({}));
    });

    const { result } = renderHook(() => ({ auth: useAuth(), theme: useTheme() }), {
      wrapper: Providers,
    });

    await act(async () => {
      await result.current.auth.connect('valid-token');
    });

    await waitFor(() => {
      expect(result.current.theme.dark).toBe(true);
    });
  });
});

describe('ToastProvider', () => {
  it('renders toast messages', async () => {
    const { result } = renderHook(() => ({ auth: useAuth(), toast: useToast() }), {
      wrapper: Providers,
    });

    await waitFor(() => {
      expect(result.current.auth.checking).toBe(false);
    });

    act(() => {
      result.current.toast('Test notification', 'info');
    });
    expect(screen.getByText('Test notification')).toBeInTheDocument();
  });
});

describe('useWebSocket', () => {
  beforeEach(() => {
    vi.useRealTimers();
    delete globalThis.WebSocket;
  });

  function WebSocketProbe({ interval = 2000 }) {
    const { connected, events, status, recoveryAttempts } = useWebSocket(interval);
    return (
      <>
        <div data-testid="ws-connected">{String(connected)}</div>
        <div data-testid="ws-events">{String(events.length)}</div>
        <div data-testid="ws-status">{status}</div>
        <div data-testid="ws-recovery-attempts">{String(recoveryAttempts)}</div>
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
    expect(screen.getByTestId('ws-status').textContent).toBe('connected');
    expect(Number(screen.getByTestId('ws-recovery-attempts').textContent)).toBeGreaterThan(0);
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
    expect(screen.getByTestId('ws-status').textContent).toBe('connected');
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

  it('skips native websocket when a bearer token is active', async () => {
    const sockets = [];

    setToken('active-token');
    globalThis.WebSocket = class MockWebSocket {
      constructor() {
        sockets.push(this);
      }
    };

    fetchMock.mockImplementation((url) => {
      if (url === '/api/ws/connect') return Promise.resolve(jsonOk({ subscriber_id: 17 }));
      if (url === '/api/ws/poll') return Promise.resolve(jsonOk([]));
      if (url === '/api/ws/disconnect') return Promise.resolve(jsonOk({ ok: true }));
      return Promise.resolve(jsonOk({}));
    });

    await act(async () => {
      render(<WebSocketProbe interval={10_000} />);
      await Promise.resolve();
    });

    expect(sockets).toHaveLength(0);
    expect(fetchMock.mock.calls.some(([url]) => url === '/api/ws/connect')).toBe(true);
  });
});

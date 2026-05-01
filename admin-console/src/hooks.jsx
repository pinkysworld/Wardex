/* eslint-disable react-refresh/only-export-components */
import { useState, useEffect, useCallback, useRef, createContext, useContext } from 'react';
import {
  getToken,
  setToken,
  authCheck,
  authLogout,
  authSession,
  createAuthSession,
  userPreferences as getUserPreferences,
  setUserPreferences as updateUserPreferences,
  wsConnect,
  wsDisconnect,
  wsPoll,
  withSignal,
} from './api.js';

// ── Auth Context ─────────────────────────────────────────────

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [authenticated, setAuthenticated] = useState(false);
  const [checking, setChecking] = useState(false);

  const connect = useCallback(async (token) => {
    const trimmed = token.trim();
    setToken(trimmed);
    setChecking(true);
    try {
      await authCheck();
      await createAuthSession();
      setToken('');
      setAuthenticated(true);
      localStorage.removeItem('wardex_token');
      return true;
    } catch {
      setAuthenticated(false);
      setToken('');
      localStorage.removeItem('wardex_token');
      return false;
    } finally {
      setChecking(false);
    }
  }, []);

  const disconnect = useCallback(() => {
    void authLogout().catch((error) => {
      void error;
    });
    setToken('');
    setAuthenticated(false);
    localStorage.removeItem('wardex_token');
  }, []);

  // Auto-reconnect from an existing HttpOnly session cookie. Older console
  // builds persisted bearer tokens in localStorage, so migrate and delete one.
  useEffect(() => {
    const saved = localStorage.getItem('wardex_token');
    let cancelled = false;

    const restoreSession = async () => {
      setChecking(true);
      try {
        const session = await authSession();
        if (!cancelled) {
          setAuthenticated((current) => current || Boolean(session?.authenticated));
        }
      } catch {
        if (!cancelled) {
          setAuthenticated(false);
        }
      } finally {
        if (!cancelled) {
          setChecking(false);
        }
      }
    };

    if (saved) {
      void connect(saved).then((connected) => {
        if (!connected && !cancelled) {
          void restoreSession();
        }
      });
      return undefined;
    }

    void restoreSession();

    return () => {
      cancelled = true;
    };
  }, [connect]);

  return (
    <AuthContext.Provider value={{ authenticated, checking, connect, disconnect }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}

// ── Role Context ─────────────────────────────────────────────

const RoleContext = createContext({
  role: 'viewer',
  groups: [],
  userId: 'anonymous',
  source: 'anonymous',
});

export function RoleProvider({ children }) {
  const { authenticated } = useAuth();
  const [role, setRole] = useState('viewer');
  const [groups, setGroups] = useState([]);
  const [userId, setUserId] = useState('anonymous');
  const [source, setSource] = useState('anonymous');

  useEffect(() => {
    if (!authenticated) return undefined;
    let cancelled = false;
    let retryTimer = null;
    const fetchRole = (retries = 2) => {
      authSession()
        .then((data) => {
          if (cancelled) return;
          setRole(data.role || 'viewer');
          setGroups(Array.isArray(data.groups) ? data.groups : []);
          setUserId(data.user_id || 'anonymous');
          setSource(data.source || 'session');
        })
        .catch(() => {
          if (!cancelled && retries > 0) {
            retryTimer = setTimeout(() => fetchRole(retries - 1), 1000);
          } else if (!cancelled) {
            setRole('viewer');
            setGroups([]);
            setUserId('anonymous');
            setSource('anonymous');
          }
        });
    };
    fetchRole();
    return () => {
      cancelled = true;
      if (retryTimer) clearTimeout(retryTimer);
    };
  }, [authenticated]);

  return (
    <RoleContext.Provider
      value={{
        role: authenticated ? role : 'viewer',
        groups: authenticated ? groups : [],
        userId: authenticated ? userId : 'anonymous',
        source: authenticated ? source : 'anonymous',
        setRole,
      }}
    >
      {children}
    </RoleContext.Provider>
  );
}

export function useRole() {
  return useContext(RoleContext);
}

// ── Theme Context ────────────────────────────────────────────

const ThemeContext = createContext(null);

export function ThemeProvider({ children }) {
  const { authenticated } = useAuth();
  const [dark, setDark] = useState(() => {
    const saved = localStorage.getItem('wardex_theme');
    if (saved) return saved === 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  });
  const darkRef = useRef(dark);

  useEffect(() => {
    darkRef.current = dark;
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
    localStorage.setItem('wardex_theme', dark ? 'dark' : 'light');
  }, [dark]);

  useEffect(() => {
    if (!authenticated) return undefined;
    let cancelled = false;
    const loadThemePreference = async () => {
      try {
        const prefs = await getUserPreferences();
        if (!cancelled && (prefs?.theme === 'dark' || prefs?.theme === 'light')) {
          const nextDark = prefs.theme === 'dark';
          darkRef.current = nextDark;
          setDark(nextDark);
        }
      } catch (error) {
        void error;
      }
    };
    void loadThemePreference();
    return () => {
      cancelled = true;
    };
  }, [authenticated]);

  const persistTheme = useCallback(
    (nextDark) => {
      if (!authenticated) return;
      void updateUserPreferences({ theme: nextDark ? 'dark' : 'light' }).catch((error) => {
        void error;
      });
    },
    [authenticated],
  );

  const toggle = useCallback(() => {
    const nextDark = !darkRef.current;
    darkRef.current = nextDark;
    setDark(nextDark);
    persistTheme(nextDark);
  }, [persistTheme]);

  return <ThemeContext.Provider value={{ dark, toggle }}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  return useContext(ThemeContext);
}

// ── Toast Context ────────────────────────────────────────────

const ToastContext = createContext(null);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const idRef = useRef(0);

  const toast = useCallback((message, kind = 'info') => {
    const id = ++idRef.current;
    setToasts((t) => [...t, { id, message, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
  }, []);

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div className="toast-container" aria-live="polite" aria-atomic="false">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`} role="status">
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

// ── useApi hook ──────────────────────────────────────────────

/**
 * @template T
 * @typedef {Object} UseApiResult
 * @property {T | null} data
 * @property {boolean} loading
 * @property {unknown} error
 * @property {() => Promise<void>} reload
 */

/**
 * @template T
 * @param {() => Promise<T>} fn
 * @param {Array<unknown>} deps
 * @param {{skip?: boolean}} opts
 * @returns {UseApiResult<T>}
 */

export function useApi(fn, deps = [], opts = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(!opts.skip);
  const [error, setError] = useState(null);
  const { skip = false } = opts;
  const fnRef = useRef(fn);
  useEffect(() => {
    fnRef.current = fn;
  });
  const controllerRef = useRef(null);

  const load = useCallback(async () => {
    if (skip) {
      setLoading(false);
      return;
    }
    if (controllerRef.current) controllerRef.current.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setLoading(true);
    setError(null);
    try {
      const result = await withSignal(controller.signal, () => fnRef.current());
      if (!controller.signal.aborted) setData(result);
    } catch (e) {
      if (!controller.signal.aborted) setError(e);
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, skip]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    return () => {
      if (controllerRef.current) controllerRef.current.abort();
    };
  }, []);

  return { data, loading, error, reload: load };
}

export function useApiGroup(requests, deps = [], opts = {}) {
  const [data, setData] = useState({});
  const [loading, setLoading] = useState(!opts.skip);
  const [errors, setErrors] = useState({});
  const { skip = false } = opts;
  const requestsRef = useRef(requests);
  useEffect(() => {
    requestsRef.current = requests;
  });
  const controllerRef = useRef(null);

  const load = useCallback(async () => {
    if (controllerRef.current) controllerRef.current.abort();
    if (skip) {
      setLoading(false);
      return;
    }

    const entries = Object.entries(requestsRef.current || {});
    if (entries.length === 0) {
      setData({});
      setErrors({});
      setLoading(false);
      return;
    }

    const controller = new AbortController();
    controllerRef.current = controller;
    setLoading(true);
    setErrors({});

    try {
      const results = await Promise.all(
        entries.map(async ([key, request]) => {
          try {
            const value = await withSignal(controller.signal, () => request());
            return { key, value, error: null };
          } catch (error) {
            return { key, value: undefined, error };
          }
        }),
      );

      if (!controller.signal.aborted) {
        const nextData = {};
        const nextErrors = {};

        results.forEach(({ key, value, error }) => {
          if (error) {
            nextErrors[key] = error;
            return;
          }
          nextData[key] = value;
        });

        setData((current) => ({ ...current, ...nextData }));
        setErrors(nextErrors);
      }
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, skip]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    return () => {
      if (controllerRef.current) controllerRef.current.abort();
    };
  }, []);

  return { data, loading, errors, reload: load };
}

// ── useInterval hook ─────────────────────────────────────────

export function useInterval(callback, delayMs) {
  const savedCallback = useRef(callback);
  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);
  useEffect(() => {
    if (delayMs == null) return;
    const tick = () => {
      if (typeof document !== 'undefined' && document.hidden) return;
      savedCallback.current();
    };
    const id = setInterval(tick, delayMs);
    return () => clearInterval(id);
  }, [delayMs]);
}

// ── useWebSocket hook (long-poll fallback) ───────────────────

/**
 * Real-time event stream via native WebSocket with long-poll fallback.
 * Bearer-token sessions skip native WebSocket because browsers cannot attach
 * Authorization headers to the handshake, and session-backed consoles only
 * attempt native WebSocket when the backend advertises support.
 * Returns connection metadata plus { events, connected, transport, clearEvents, reconnect }.
 */
export function useWebSocket(pollIntervalMs = 2000, { nativeSupported = true } = {}) {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [transport, setTransport] = useState('connecting');
  const [status, setStatus] = useState('connecting');
  const [subscriberId, setSubscriberId] = useState(null);
  const [recoveryAttempts, setRecoveryAttempts] = useState(0);
  const [lastEventAt, setLastEventAt] = useState(null);
  const [lastConnectAt, setLastConnectAt] = useState(null);
  const [lastDisconnectAt, setLastDisconnectAt] = useState(null);
  const [lastError, setLastError] = useState('');
  const [reconnectToken, setReconnectToken] = useState(0);
  const subscriberIdRef = useRef(null);
  const wsRef = useRef(null);
  const mountedRef = useRef(true);

  const reconnect = useCallback(() => {
    setConnected(false);
    setTransport('connecting');
    setStatus('connecting');
    setSubscriberId(null);
    setLastError('');
    setReconnectToken((current) => current + 1);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    setConnected(false);
    setTransport('connecting');
    setStatus('connecting');
    setSubscriberId(null);
    let pollTimer = null;
    let retryDelay = 2000;
    let retryTimer = null;
    let handshakeTimer = null;
    let pollingConnecting = false;
    let pollingConnectRequestId = 0;

    const clearRetry = () => {
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
    };

    const clearHandshake = () => {
      if (handshakeTimer) {
        clearTimeout(handshakeTimer);
        handshakeTimer = null;
      }
    };

    const stopPolling = (disconnectSubscriber = false) => {
      pollingConnectRequestId += 1;
      pollingConnecting = false;
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
      const subscriberId = subscriberIdRef.current;
      subscriberIdRef.current = null;
      setSubscriberId(null);
      if (disconnectSubscriber && subscriberId != null) {
        wsDisconnect(subscriberId).catch((error) => {
          void error;
        });
      }
    };

    const recordRecovery = (message) => {
      if (!mountedRef.current) return;
      setConnected(false);
      setStatus('reconnecting');
      setLastDisconnectAt(new Date().toISOString());
      if (message) setLastError(message);
      setRecoveryAttempts((count) => count + 1);
    };

    const schedulePollingReconnect = () => {
      if (!mountedRef.current) return;
      setStatus('reconnecting');
      clearRetry();
      const delay = Math.min(retryDelay, 30000);
      retryDelay = Math.min(retryDelay * 2, 30000);
      retryTimer = setTimeout(connectPolling, delay);
    };

    const tryNativeWebSocket = () => {
      if (!mountedRef.current) return;
      try {
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${proto}//${window.location.host}/ws/events`;
        const ws = new WebSocket(wsUrl);
        let opened = false;
        wsRef.current = ws;
        clearHandshake();
        handshakeTimer = setTimeout(() => {
          if (!mountedRef.current || wsRef.current !== ws || opened) return;
          wsRef.current = null;
          try {
            ws.close();
          } catch {
            /* ignore close errors during handshake fallback */
          }
          recordRecovery('native websocket handshake timed out');
          setTransport('connecting');
          connectPolling();
        }, 3000);

        ws.onopen = () => {
          if (!mountedRef.current || wsRef.current !== ws) {
            ws.close();
            return;
          }
          opened = true;
          clearHandshake();
          stopPolling(true);
          setConnected(true);
          setStatus('connected');
          setTransport('websocket');
          setSubscriberId(null);
          setLastConnectAt(new Date().toISOString());
          setLastError('');
          retryDelay = 2000;
        };

        ws.onmessage = (e) => {
          if (!mountedRef.current) return;
          try {
            const data = JSON.parse(e.data);
            const newEvents = Array.isArray(data) ? data : [data];
            setEvents((prev) => [...newEvents, ...prev].slice(0, 500));
            setLastEventAt(new Date().toISOString());
          } catch {
            /* ignore malformed frames */
          }
        };

        ws.onerror = () => {
          if (!mountedRef.current || wsRef.current !== ws || opened) return;
          clearHandshake();
          wsRef.current = null;
          try {
            ws.close();
          } catch {
            /* ignore close errors after websocket failure */
          }
          recordRecovery('native websocket unavailable, falling back to polling');
          setTransport('connecting');
          connectPolling();
        };

        ws.onclose = () => {
          if (wsRef.current === ws) {
            wsRef.current = null;
          }
          clearHandshake();
          if (!mountedRef.current) return;
          if (opened) {
            recordRecovery('websocket connection closed');
            setTransport('connecting');
            const delay = Math.min(retryDelay, 30000);
            retryDelay = Math.min(retryDelay * 2, 30000);
            clearRetry();
            retryTimer = setTimeout(tryNativeWebSocket, delay);
          } else if (!pollTimer && subscriberIdRef.current == null && !pollingConnecting) {
            connectPolling();
          }
        };
      } catch {
        connectPolling();
      }
    };

    const connectPolling = async () => {
      if (
        !mountedRef.current ||
        pollingConnecting ||
        pollTimer ||
        subscriberIdRef.current != null
      ) {
        return;
      }
      const requestId = ++pollingConnectRequestId;
      pollingConnecting = true;
      try {
        const result = await wsConnect();
        if (!result?.subscriber_id) {
          throw new Error('Invalid ws connect response');
        }
        if (!mountedRef.current || requestId !== pollingConnectRequestId) {
          wsDisconnect(result.subscriber_id).catch((error) => {
            void error;
          });
          return;
        }
        if (!result?.subscriber_id) {
          throw new Error('Invalid ws connect response');
        }
        subscriberIdRef.current = result.subscriber_id;
        setSubscriberId(result.subscriber_id);
        setConnected(true);
        setStatus('connected');
        setTransport('polling');
        setLastConnectAt(new Date().toISOString());
        setLastError('');
        retryDelay = 2000;
        startPolling();
      } catch {
        if (mountedRef.current && requestId === pollingConnectRequestId) {
          recordRecovery('polling transport unavailable');
          setTransport('connecting');
          stopPolling(false);
          schedulePollingReconnect();
        }
      } finally {
        if (requestId === pollingConnectRequestId) {
          pollingConnecting = false;
        }
      }
    };

    const startPolling = () => {
      if (pollTimer || subscriberIdRef.current == null) return;
      pollTimer = setInterval(async () => {
        if (!mountedRef.current || subscriberIdRef.current == null) return;
        try {
          const newEvents = await wsPoll(subscriberIdRef.current);
          if (!mountedRef.current) return;
          if (Array.isArray(newEvents) && newEvents.length > 0) {
            setEvents((prev) => [...newEvents, ...prev].slice(0, 500));
            setLastEventAt(new Date().toISOString());
          }
        } catch {
          if (mountedRef.current) {
            recordRecovery('polling subscriber interrupted');
            stopPolling(false);
            schedulePollingReconnect();
          }
        }
      }, pollIntervalMs);
    };

    if (getToken() || !nativeSupported) {
      connectPolling();
    } else {
      tryNativeWebSocket();
    }

    return () => {
      mountedRef.current = false;
      clearRetry();
      clearHandshake();
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      stopPolling(true);
    };
  }, [nativeSupported, pollIntervalMs, reconnectToken]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return {
    events,
    connected,
    transport,
    status,
    subscriberId,
    recoveryAttempts,
    lastEventAt,
    lastConnectAt,
    lastDisconnectAt,
    lastError,
    clearEvents,
    reconnect,
  };
}

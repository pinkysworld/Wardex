import { useState, useEffect, useCallback, useRef, createContext, useContext } from 'react';
import { setToken, authCheck, authSession, wsConnect, wsDisconnect, wsPoll, withSignal } from './api.js';

// ── Auth Context ─────────────────────────────────────────────

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [authenticated, setAuthenticated] = useState(false);
  const [checking, setChecking] = useState(false);

  const connect = useCallback(async (token) => {
    setToken(token);
    setChecking(true);
    try {
      await authCheck();
      setAuthenticated(true);
      localStorage.setItem('wardex_token', token);
      return true;
    } catch {
      setAuthenticated(false);
      setToken('');
      return false;
    } finally {
      setChecking(false);
    }
  }, []);

  const disconnect = useCallback(() => {
    setToken('');
    setAuthenticated(false);
    localStorage.removeItem('wardex_token');
  }, []);

  // auto-reconnect from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('wardex_token');
    if (saved) connect(saved);
  }, [connect]);

  return (
    <AuthContext.Provider value={{ authenticated, checking, connect, disconnect }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() { return useContext(AuthContext); }

// ── Role Context ─────────────────────────────────────────────

const RoleContext = createContext({ role: 'viewer' });

export function RoleProvider({ children }) {
  const { authenticated } = useAuth();
  const [role, setRole] = useState('viewer');

  useEffect(() => {
    if (!authenticated) { setRole('viewer'); return; }
    let cancelled = false;
    const fetchRole = (retries = 2) => {
      authSession()
        .then(data => { if (!cancelled && data.role) setRole(data.role); })
        .catch(() => {
          if (!cancelled && retries > 0) {
            setTimeout(() => fetchRole(retries - 1), 1000);
          } else if (!cancelled) {
            setRole('viewer');
          }
        });
    };
    fetchRole();
    return () => { cancelled = true; };
  }, [authenticated]);

  return (
    <RoleContext.Provider value={{ role, setRole }}>
      {children}
    </RoleContext.Provider>
  );
}

export function useRole() { return useContext(RoleContext); }

// ── Theme Context ────────────────────────────────────────────

const ThemeContext = createContext(null);

export function ThemeProvider({ children }) {
  const [dark, setDark] = useState(() => {
    const saved = localStorage.getItem('wardex_theme');
    if (saved) return saved === 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
    localStorage.setItem('wardex_theme', dark ? 'dark' : 'light');
  }, [dark]);

  const toggle = useCallback(() => setDark(d => !d), []);

  return (
    <ThemeContext.Provider value={{ dark, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() { return useContext(ThemeContext); }

// ── Toast Context ────────────────────────────────────────────

const ToastContext = createContext(null);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const idRef = useRef(0);

  const toast = useCallback((message, kind = 'info') => {
    const id = ++idRef.current;
    setToasts(t => [...t, { id, message, kind }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 5000);
  }, []);

  return (
      <ToastContext.Provider value={toast}>
        {children}
      <div className="toast-container" aria-live="polite" aria-atomic="false">
        {toasts.map(t => (
          <div key={t.id} className={`toast toast-${t.kind}`} role="status">
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() { return useContext(ToastContext); }

// ── useApi hook ──────────────────────────────────────────────

export function useApi(fn, deps = [], opts = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(!opts.skip);
  const [error, setError] = useState(null);
  const { skip = false } = opts;
  const fnRef = useRef(fn);
  useEffect(() => { fnRef.current = fn; });
  const controllerRef = useRef(null);

  const load = useCallback(async () => {
    if (skip) { setLoading(false); return; }
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

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    return () => { if (controllerRef.current) controllerRef.current.abort(); };
  }, []);

  return { data, loading, error, reload: load };
}

// ── useInterval hook ─────────────────────────────────────────

export function useInterval(callback, delayMs) {
  const savedCallback = useRef(callback);
  useEffect(() => { savedCallback.current = callback; }, [callback]);
  useEffect(() => {
    if (delayMs == null) return;
    const id = setInterval(() => savedCallback.current(), delayMs);
    return () => clearInterval(id);
  }, [delayMs]);
}

// ── useDraftAutosave hook ────────────────────────────────────

/**
 * Persist draft state to localStorage with debounced writes.
 * @param {string} key - Unique storage key (prefixed with `wardex_draft_`)
 * @param {*} initialValue - Default value if no draft exists
 * @returns {[value, setValue, clearDraft]}
 */
export function useDraftAutosave(key, initialValue) {
  const storageKey = `wardex_draft_${key}`;
  const [value, setValue] = useState(() => {
    try {
      const saved = localStorage.getItem(storageKey);
      return saved ? JSON.parse(saved) : initialValue;
    } catch {
      return initialValue;
    }
  });
  const timerRef = useRef(null);

  useEffect(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      try {
        if (value === initialValue || value === null || value === undefined) {
          localStorage.removeItem(storageKey);
        } else {
          localStorage.setItem(storageKey, JSON.stringify(value));
        }
      } catch { /* quota exceeded — ignore */ }
    }, 500);
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, [value, storageKey, initialValue]);

  const clearDraft = useCallback(() => {
    localStorage.removeItem(storageKey);
    setValue(initialValue);
  }, [storageKey, initialValue]);

  return [value, setValue, clearDraft];
}

// ── useWebSocket hook (long-poll fallback) ───────────────────

/**
 * Real-time event stream via native WebSocket with long-poll fallback.
 * Attempts WebSocket first; if unavailable, falls back to EventBus polling.
 * Returns { events, connected, clearEvents }.
 */
export function useWebSocket(pollIntervalMs = 2000) {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const subscriberIdRef = useRef(null);
  const wsRef = useRef(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
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
      if (disconnectSubscriber && subscriberId != null) {
        wsDisconnect(subscriberId).catch(() => {});
      }
    };

    const schedulePollingReconnect = () => {
      if (!mountedRef.current) return;
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
          try { ws.close(); } catch {
            /* ignore close errors during handshake fallback */
          }
          connectPolling();
        }, 3000);

        ws.onopen = () => {
          if (!mountedRef.current || wsRef.current !== ws) { ws.close(); return; }
          opened = true;
          clearHandshake();
          stopPolling(true);
          setConnected(true);
          retryDelay = 2000;
        };

        ws.onmessage = (e) => {
          if (!mountedRef.current) return;
          try {
            const data = JSON.parse(e.data);
            const newEvents = Array.isArray(data) ? data : [data];
            setEvents(prev => [...newEvents, ...prev].slice(0, 500));
          } catch { /* ignore malformed frames */ }
        };

        ws.onerror = () => {
          if (!mountedRef.current || wsRef.current !== ws || opened) return;
          clearHandshake();
          wsRef.current = null;
          try { ws.close(); } catch {
            /* ignore close errors after websocket failure */
          }
          connectPolling();
        };

        ws.onclose = () => {
          if (wsRef.current === ws) {
            wsRef.current = null;
          }
          clearHandshake();
          if (!mountedRef.current) return;
          if (opened) {
            setConnected(false);
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
      if (!mountedRef.current || pollingConnecting || pollTimer || subscriberIdRef.current != null) {
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
          wsDisconnect(result.subscriber_id).catch(() => {});
          return;
        }
        if (!result?.subscriber_id) {
          throw new Error('Invalid ws connect response');
        }
        subscriberIdRef.current = result.subscriber_id;
        setConnected(true);
        retryDelay = 2000;
        startPolling();
      } catch {
        if (mountedRef.current && requestId === pollingConnectRequestId) {
          setConnected(false);
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
            setEvents(prev => [...newEvents, ...prev].slice(0, 500));
          }
        } catch {
          if (mountedRef.current) {
            setConnected(false);
            stopPolling(false);
            schedulePollingReconnect();
          }
        }
      }, pollIntervalMs);
    };

    // Try native WebSocket first
    tryNativeWebSocket();

    return () => {
      mountedRef.current = false;
      clearRetry();
      clearHandshake();
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
      stopPolling(true);
    };
  }, [pollIntervalMs]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, connected, clearEvents };
}

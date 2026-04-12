import { useState, useEffect, useCallback, useRef, createContext, useContext } from 'react';
import { setToken, getToken, authCheck, authSession, wsConnect, wsDisconnect, wsPoll } from './api.js';

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
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast toast-${t.kind}`}>
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

  const load = useCallback(async () => {
    if (skip) { setLoading(false); return; }
    setLoading(true);
    setError(null);
    try {
      const result = await fnRef.current();
      setData(result);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, skip]);

  useEffect(() => { load(); }, [load]);

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

// ── useWebSocket hook (long-poll fallback) ───────────────────

/**
 * Real-time event stream via server-side EventBus polling.
 * Connects on mount, disconnects on unmount.
 * Returns { events, connected, clientCount }.
 */
export function useWebSocket(pollIntervalMs = 2000) {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const subscriberIdRef = useRef(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    let pollTimer = null;
    let retryDelay = 2000;
    let retryTimer = null;

    const connect = async () => {
      try {
        const result = await wsConnect();
        if (!mountedRef.current) return;
        if (!result?.subscriber_id) {
          throw new Error('Invalid ws connect response');
        }
        subscriberIdRef.current = result.subscriber_id;
        setConnected(true);
        retryDelay = 2000;
        startPolling();
      } catch {
        if (mountedRef.current) {
          setConnected(false);
          const delay = Math.min(retryDelay, 30000);
          retryDelay = Math.min(retryDelay * 2, 30000);
          retryTimer = setTimeout(connect, delay);
        }
      }
    };

    const startPolling = () => {
      pollTimer = setInterval(async () => {
        if (!mountedRef.current || subscriberIdRef.current == null) return;
        try {
          const newEvents = await wsPoll(subscriberIdRef.current);
          if (!mountedRef.current) return;
          if (Array.isArray(newEvents) && newEvents.length > 0) {
            setEvents(prev => [...newEvents, ...prev].slice(0, 500));
          }
        } catch {
          // Connection lost — attempt reconnect with backoff
          if (mountedRef.current) {
            setConnected(false);
            subscriberIdRef.current = null;
            clearInterval(pollTimer);
            const delay = Math.min(retryDelay, 30000);
            retryDelay = Math.min(retryDelay * 2, 30000);
            retryTimer = setTimeout(connect, delay);
          }
        }
      }, pollIntervalMs);
    };

    connect();

    return () => {
      mountedRef.current = false;
      if (retryTimer) clearTimeout(retryTimer);
      if (pollTimer) clearInterval(pollTimer);
      if (subscriberIdRef.current != null) {
        wsDisconnect(subscriberIdRef.current).catch(() => {});
      }
    };
  }, [pollIntervalMs]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, connected, clearEvents };
}

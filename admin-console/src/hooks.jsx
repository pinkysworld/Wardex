import { useState, useEffect, useCallback, useRef, createContext, useContext } from 'react';
import { setToken, getToken, authCheck } from './api.js';

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

const RoleContext = createContext({ role: 'admin' });

export function RoleProvider({ children }) {
  const { authenticated } = useAuth();
  const [role, setRole] = useState('admin');

  useEffect(() => {
    if (!authenticated) { setRole('viewer'); return; }
    // Fetch role from session endpoint
    fetch('/api/auth/session', { headers: { 'Authorization': `Bearer ${getToken()}` } })
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(data => { if (data.role) setRole(data.role); })
      .catch(() => setRole('viewer'));
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

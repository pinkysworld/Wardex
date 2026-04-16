/**
 * Shared test utilities for admin-console Vitest tests.
 * Provides mock API helpers, test data factories, and render wrappers.
 */
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider, RoleProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';
import { vi } from 'vitest';

// ── Mock fetch helpers ───────────────────────────────────────

/** Create a successful JSON response mock */
export function jsonOk(data) {
  return {
    ok: true,
    status: 200,
    headers: { get: (h) => h === 'content-type' ? 'application/json' : null },
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

/** Create an error response mock */
export function jsonError(status, body = {}) {
  return {
    ok: false,
    status,
    headers: { get: (h) => h === 'content-type' ? 'application/json' : null },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

/** Set up fetch mock to respond with given handlers per URL pattern */
export function mockApiRoutes(routes = {}) {
  const mock = vi.fn((url) => {
    for (const [pattern, handler] of Object.entries(routes)) {
      if (url.includes(pattern)) {
        return Promise.resolve(typeof handler === 'function' ? handler() : handler);
      }
    }
    return Promise.resolve(jsonOk({}));
  });
  global.fetch = mock;
  return mock;
}

// ── Test data factories ──────────────────────────────────────

let idCounter = 0;

export function createAlert(overrides = {}) {
  idCounter++;
  return {
    id: `alert-${idCounter}`,
    alert_id: `alert-${idCounter}`,
    timestamp: new Date().toISOString(),
    hostname: `host-${idCounter}`,
    severity: 'elevated',
    source: 'detector',
    category: 'anomaly',
    message: `Test alert ${idCounter}`,
    score: 0.75,
    ...overrides,
  };
}

export function createAgent(overrides = {}) {
  idCounter++;
  return {
    id: `agent-${idCounter}`,
    hostname: `agent-host-${idCounter}`,
    os: 'linux',
    version: '0.52.2',
    status: 'online',
    last_heartbeat: new Date().toISOString(),
    ...overrides,
  };
}

export function createCase(overrides = {}) {
  idCounter++;
  return {
    id: `case-${idCounter}`,
    title: `Test case ${idCounter}`,
    status: 'open',
    severity: 'medium',
    assignee: null,
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

export function createPlaybook(overrides = {}) {
  idCounter++;
  return {
    id: `playbook-${idCounter}`,
    name: `Test playbook ${idCounter}`,
    status: 'active',
    steps: [],
    ...overrides,
  };
}

// ── Render wrapper ───────────────────────────────────────────

/**
 * Render a component wrapped in all required providers.
 * @param {import('react').ReactElement} ui - Component to render
 * @param {object} options - Additional render options
 * @param {string} options.route - Initial route path (default: '/')
 */
export function renderWithProviders(ui, { route = '/', ...options } = {}) {
  function Wrapper({ children }) {
    return (
      <MemoryRouter initialEntries={[route]}>
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
  return render(ui, { wrapper: Wrapper, ...options });
}

// ── Reset helper ─────────────────────────────────────────────

export function resetTestState() {
  idCounter = 0;
  vi.clearAllMocks();
  localStorage.clear();
  if (global.fetch?.mockReset) global.fetch.mockReset();
}

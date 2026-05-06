import { useState, useCallback, useEffect, useRef, lazy, Suspense } from 'react';
import { Routes, Route, useNavigate, useLocation, Navigate, NavLink, Link } from 'react-router-dom';
import { useAuth, useTheme, useRole, useApi, useInterval } from './hooks.jsx';
import * as api from './api.js';
import ErrorBoundary from './components/ErrorBoundary.jsx';
import SearchPalette from './components/SearchPalette.jsx';
import NotificationToast from './components/NotificationToast.jsx';
import OnboardingWizard from './components/OnboardingWizard.jsx';
import { copyTextToClipboard } from './components/clipboard.js';
import {
  buildCommandHref,
  buildContextualHelpHref,
  describeSearchScope,
} from './components/workflowPivots.js';

// ── Recent Items (persisted in localStorage) ─────────────────
const MAX_RECENT = 10;
const MAX_PINNED_SECTIONS = 6;
const MAX_INLINE_SSO_PROVIDERS = 3;

function ssoProviderLabel(provider) {
  const displayName = String(provider?.display_name ?? '').trim();
  if (displayName) return displayName;
  const id = String(provider?.id ?? '').trim();
  return id || 'Corporate SSO';
}

function normalizeSsoProviders(providers) {
  if (!Array.isArray(providers)) return [];
  const seen = new Set();
  return providers.filter((provider) => {
    if (!provider?.id) return false;
    const key = [
      ssoProviderLabel(provider).toLowerCase(),
      String(provider.kind || '').toLowerCase(),
      String(provider.status || '').toLowerCase(),
      String(provider.validation_status || '').toLowerCase(),
    ].join(':');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function useRecentItems() {
  const [items, setItems] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('wardex_recent') || '[]');
    } catch {
      return [];
    }
  });
  const add = useCallback((path, label) => {
    setItems((prev) => {
      const next = [{ path, label, ts: Date.now() }, ...prev.filter((i) => i.path !== path)].slice(
        0,
        MAX_RECENT,
      );
      localStorage.setItem('wardex_recent', JSON.stringify(next));
      return next;
    });
  }, []);
  return { items, add };
}

function normalizePinnedSections(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((entry) => String(entry || '').trim()).filter(Boolean))].slice(
    0,
    MAX_PINNED_SECTIONS,
  );
}

function readStoredPinnedSections() {
  try {
    return normalizePinnedSections(
      JSON.parse(localStorage.getItem('wardex_pinned_sections') || '[]'),
    );
  } catch {
    return [];
  }
}

// ── Breadcrumbs ──────────────────────────────────────────────
function Breadcrumbs({ sections, pathname }) {
  const current = sections.find((s) => s.path === pathname);
  if (!current || current.path === '/') return null;
  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      <ol
        style={{
          display: 'flex',
          gap: 4,
          listStyle: 'none',
          margin: 0,
          padding: 0,
          fontSize: 12,
          color: 'var(--text-secondary)',
        }}
      >
        <li>
          <Link className="btn-link" to="/">
            Dashboard
          </Link>
        </li>
        <li aria-hidden="true" style={{ margin: '0 2px' }}>
          ›
        </li>
        <li aria-current="page" style={{ fontWeight: 600, color: 'var(--text)' }}>
          {current.label}
        </li>
      </ol>
    </nav>
  );
}

const Dashboard = lazy(() => import('./components/Dashboard.jsx'));
const LiveMonitor = lazy(() => import('./components/LiveMonitor.jsx'));
const ThreatDetection = lazy(() => import('./components/ThreatDetection.jsx'));
const FleetAgents = lazy(() => import('./components/FleetAgents.jsx'));
const SecurityPolicy = lazy(() => import('./components/SecurityPolicy.jsx'));
const SOCWorkbench = lazy(() => import('./components/SOCWorkbench.jsx'));
const CommandCenter = lazy(() => import('./components/CommandCenter.jsx'));
const AssistantWorkspace = lazy(() => import('./components/AssistantWorkspace.jsx'));
const Infrastructure = lazy(() => import('./components/Infrastructure.jsx'));
const ReportsExports = lazy(() => import('./components/ReportsExports.jsx'));
const Settings = lazy(() => import('./components/Settings.jsx'));
const HelpDocs = lazy(() => import('./components/HelpDocs.jsx'));
const UEBADashboard = lazy(() => import('./components/UEBADashboard.jsx'));
const NDRDashboard = lazy(() => import('./components/NDRDashboard.jsx'));
const EmailSecurity = lazy(() => import('./components/EmailSecurity.jsx'));
const AttackGraph = lazy(() => import('./components/AttackGraph.jsx'));

const SECTIONS = [
  { id: 'dashboard', path: '/', label: 'Dashboard', shortLabel: 'DB', minRole: 'viewer' },
  {
    id: 'live-monitor',
    path: '/monitor',
    label: 'Live Monitor',
    shortLabel: 'LM',
    minRole: 'viewer',
  },
  {
    id: 'threat-detection',
    path: '/detection',
    label: 'Threat Detection',
    shortLabel: 'TD',
    minRole: 'analyst',
  },
  {
    id: 'fleet-agents',
    path: '/fleet',
    label: 'Fleet & Agents',
    shortLabel: 'FA',
    minRole: 'viewer',
  },
  {
    id: 'security-policy',
    path: '/policy',
    label: 'Security Policy',
    shortLabel: 'SP',
    minRole: 'analyst',
  },
  {
    id: 'soc-workbench',
    path: '/soc',
    label: 'SOC Workbench',
    shortLabel: 'SOC',
    minRole: 'analyst',
  },
  {
    id: 'command-center',
    path: '/command',
    label: 'Command Center',
    shortLabel: 'CMD',
    minRole: 'analyst',
  },
  {
    id: 'assistant-workspace',
    path: '/assistant',
    label: 'Analyst Assistant',
    shortLabel: 'AST',
    minRole: 'analyst',
  },
  {
    id: 'infrastructure',
    path: '/infrastructure',
    label: 'Infrastructure',
    shortLabel: 'INF',
    minRole: 'analyst',
  },
  {
    id: 'reports-exports',
    path: '/reports',
    label: 'Reports & Exports',
    shortLabel: 'REP',
    minRole: 'viewer',
  },
  { id: 'settings', path: '/settings', label: 'Settings', shortLabel: 'CFG', minRole: 'admin' },
  { id: 'help-docs', path: '/help', label: 'Help & Docs', shortLabel: 'DOC', minRole: 'viewer' },
  { id: 'ueba', path: '/ueba', label: 'UEBA', shortLabel: 'UBA', minRole: 'analyst' },
  { id: 'ndr', path: '/ndr', label: 'NDR', shortLabel: 'NDR', minRole: 'analyst' },
  {
    id: 'email-security',
    path: '/email-security',
    label: 'Email Security',
    shortLabel: 'EML',
    minRole: 'analyst',
  },
  {
    id: 'attack-graph',
    path: '/attack-graph',
    label: 'Attack Graph',
    shortLabel: 'ATK',
    minRole: 'analyst',
  },
];

const WORKFLOW_GROUPS = [
  { id: 'command', label: 'Command', sections: ['command-center'] },
  { id: 'monitor', label: 'Monitor', sections: ['dashboard', 'live-monitor', 'reports-exports'] },
  {
    id: 'investigate',
    label: 'Investigate',
    sections: [
      'soc-workbench',
      'assistant-workspace',
      'threat-detection',
      'infrastructure',
      'ueba',
      'ndr',
      'attack-graph',
    ],
  },
  {
    id: 'respond',
    label: 'Respond',
    sections: ['fleet-agents', 'security-policy', 'email-security'],
  },
  { id: 'manage', label: 'Manage', sections: ['settings', 'help-docs'] },
];

const ROLE_LEVEL = { viewer: 0, analyst: 1, admin: 2 };

function RequireRole({ minRole, children }) {
  const { role } = useRole();
  if (ROLE_LEVEL[role] >= ROLE_LEVEL[minRole]) return children;
  return (
    <div className="access-denied">
      <h2>Access Denied</h2>
      <p>
        You need the <strong>{minRole}</strong> role or higher to view this section.
      </p>
    </div>
  );
}

export default function App() {
  const { authenticated, checking, connect, disconnect } = useAuth();
  const { dark, toggle } = useTheme();
  const { role } = useRole();
  const { data: hp } = useApi(api.health);
  const { data: inboxData, reload: reloadInbox } = useApi(api.inbox, [authenticated], {
    skip: !authenticated,
  });
  const navigate = useNavigate();
  const location = useLocation();
  const { items: recentItems, add: addRecent } = useRecentItems();
  const [showRecent, setShowRecent] = useState(false);

  const [tokenInput, setTokenInput] = useState('');
  const [authError, setAuthError] = useState('');
  const [ssoConfig, setSsoConfig] = useState(null);
  const [ssoProviders, setSsoProviders] = useState([]);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [linkCopied, setLinkCopied] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [showOnboarding, setShowOnboarding] = useState(
    () => !localStorage.getItem('wardex_onboarded'),
  );
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [showInboxLocationKey, setShowInboxLocationKey] = useState(null);
  const [showTopbarActionsLocationKey, setShowTopbarActionsLocationKey] = useState(null);
  const [pinnedSections, setPinnedSections] = useState(() => readStoredPinnedSections());
  const pinnedSectionsRef = useRef(pinnedSections);
  const showInbox = showInboxLocationKey === location.key;
  const showTopbarActions = showTopbarActionsLocationKey === location.key;

  useEffect(() => {
    pinnedSectionsRef.current = pinnedSections;
  }, [pinnedSections]);

  useEffect(() => {
    if (authenticated) return undefined;
    let cancelled = false;
    api
      .authSsoConfig()
      .then((config) => {
        if (!cancelled) {
          setSsoConfig(config || null);
          setSsoProviders(normalizeSsoProviders(config?.providers));
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSsoConfig(null);
          setSsoProviders([]);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [authenticated]);

  useEffect(() => {
    if (authenticated) return;
    const params = new URLSearchParams(location.search);
    const error = params.get('sso_error');
    if (error) {
      // SSO redirect surfaces auth errors via URL params; mirroring into state
      // is the only way to display them in the auth form below.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setAuthError(error);
    }
  }, [authenticated, location.search]);

  const applyPinnedSections = useCallback(
    (nextSections, persistRemote = false) => {
      const normalized = normalizePinnedSections(nextSections);
      pinnedSectionsRef.current = normalized;
      setPinnedSections(normalized);
      localStorage.setItem('wardex_pinned_sections', JSON.stringify(normalized));
      if (persistRemote && authenticated) {
        void api.setUserPreferences({ pinned_sections: normalized }).catch((error) => {
          void error;
        });
      }
    },
    [authenticated],
  );

  useEffect(() => {
    if (!authenticated) return undefined;
    let cancelled = false;
    const loadPinnedSections = async () => {
      try {
        const prefs = await api.userPreferences();
        if (cancelled) return;
        const serverPinned = normalizePinnedSections(prefs?.pinned_sections);
        if (serverPinned.length > 0 || prefs?.updated_at) {
          applyPinnedSections(serverPinned);
          return;
        }
        const localPinned = readStoredPinnedSections();
        if (localPinned.length > 0) {
          applyPinnedSections(localPinned);
          void api.setUserPreferences({ pinned_sections: localPinned }).catch((error) => {
            void error;
          });
        }
      } catch (error) {
        void error;
      }
    };
    void loadPinnedSections();
    return () => {
      cancelled = true;
    };
  }, [authenticated, applyPinnedSections]);

  // Track page visits for recent items
  useEffect(() => {
    const section = SECTIONS.find((s) => s.path === location.pathname);
    if (section) addRecent(section.path, section.label);
  }, [location.pathname, addRecent]);

  useInterval(
    () => {
      if (authenticated) reloadInbox();
    },
    authenticated ? 30000 : null,
  );

  // ── Global Keyboard Shortcuts ──
  useEffect(() => {
    const handler = (e) => {
      // Ignore if user is typing in an input/textarea
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
      const key = e.key.toLowerCase();
      if (key === '?') {
        setShowShortcuts((s) => !s);
        return;
      }
      if (!authenticated) return;
      switch (key) {
        case 'd':
          navigate('/');
          break;
        case 'm':
          navigate('/monitor');
          break;
        case 't':
          navigate('/detection');
          break;
        case 'f':
          navigate('/fleet');
          break;
        case 's':
          navigate('/soc');
          break;
        case 'c':
          navigate('/command');
          break;
        case 'g':
          navigate('/settings');
          break;
        case 'u':
          navigate('/ueba');
          break;
        case 'n':
          navigate('/ndr');
          break;
        case 'e':
          navigate('/email-security');
          break;
        case 'a':
          navigate('/attack-graph');
          break;
        default:
          break;
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [navigate, authenticated]);

  const currentSection = SECTIONS.find((s) => s.path === location.pathname) || SECTIONS[0];
  const currentGroup = WORKFLOW_GROUPS.find((group) => group.sections.includes(currentSection.id));
  const routeScopeTokens = describeSearchScope(location.search);
  const primaryDestination =
    role === 'admin'
      ? {
          label: 'System Status',
          path: '/fleet',
          description: 'Fleet health, rollouts, and platform posture.',
        }
      : role === 'analyst'
        ? {
            label: 'Command Center',
            path: '/command',
            description: 'Incidents, approvals, connector gaps, and evidence actions.',
          }
        : {
            label: 'Live Monitor',
            path: '/monitor',
            description: 'Current alerts and system activity.',
          };
  const scopeTokens = [
    currentGroup?.label,
    role === 'admin'
      ? 'Admin Workspace'
      : role === 'analyst'
        ? 'Analyst Workspace'
        : 'Viewer Workspace',
    ...routeScopeTokens.slice(0, 3),
    routeScopeTokens.length > 3 ? `+${routeScopeTokens.length - 3} more` : null,
  ].filter(Boolean);
  const inboxItems = Array.isArray(inboxData) ? inboxData : inboxData?.items || [];
  const inboxPending = inboxItems.filter((item) => !item.acknowledged).length;
  const visibleSsoProviders = ssoProviders.slice(0, MAX_INLINE_SSO_PROVIDERS);
  const ssoOverflowCount = Math.max(0, ssoProviders.length - visibleSsoProviders.length);
  const rawSsoProviderCount = Array.isArray(ssoConfig?.providers)
    ? ssoConfig.providers.length
    : ssoProviders.length;
  const ssoDuplicateCount = Math.max(0, rawSsoProviderCount - ssoProviders.length);
  const ssoProviderNames = ssoProviders.map((provider) => ssoProviderLabel(provider)).join(', ');
  const ssoProviderMeta = [
    ssoProviderNames,
    ssoDuplicateCount > 0
      ? `${ssoDuplicateCount} duplicate label${ssoDuplicateCount === 1 ? '' : 's'} hidden`
      : null,
  ]
    .filter(Boolean)
    .join('; ');

  const togglePinnedSection = useCallback(
    (sectionId) => {
      const current = pinnedSectionsRef.current;
      const next = current.includes(sectionId)
        ? current.filter((id) => id !== sectionId)
        : [sectionId, ...current].slice(0, MAX_PINNED_SECTIONS);
      applyPinnedSections(next, true);
    },
    [applyPinnedSections],
  );

  const copyShareLink = useCallback(async () => {
    const url = window.location.origin + location.pathname + location.search;
    const copied = await copyTextToClipboard(url);
    if (copied) {
      setLinkCopied(true);
      setTimeout(() => setLinkCopied(false), 2000);
    }
  }, [location.pathname, location.search]);

  const handleConnect = useCallback(
    async (e) => {
      e.preventDefault();
      setAuthError('');
      const ok = await connect(tokenInput);
      if (!ok) setAuthError('Authentication failed — check your token');
    },
    [tokenInput, connect],
  );

  const handleSsoLogin = useCallback(
    (providerId) => {
      setAuthError('');
      const redirectParams = new URLSearchParams(location.search);
      redirectParams.delete('sso_error');
      const redirect = `${location.pathname}${redirectParams.toString() ? `?${redirectParams.toString()}` : ''}${location.hash || ''}`;
      const params = new URLSearchParams();
      if (providerId) params.set('provider_id', providerId);
      params.set('redirect', redirect || '/');
      window.location.assign(`/api/auth/sso/login?${params.toString()}`);
    },
    [location.hash, location.pathname, location.search],
  );

  // Filter sidebar items by role
  const visibleSections = SECTIONS.filter((s) => ROLE_LEVEL[role] >= ROLE_LEVEL[s.minRole]);
  const pinnedVisibleSections = pinnedSections
    .map((id) => visibleSections.find((section) => section.id === id))
    .filter(Boolean);
  const groupedSections = WORKFLOW_GROUPS.map((group) => ({
    ...group,
    sections: group.sections
      .map((id) => visibleSections.find((section) => section.id === id))
      .filter(Boolean),
  })).filter((group) => group.sections.length > 0);

  return (
    <div className={`app ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      <a href="#main-content" className="sr-only focus-visible-only">
        Skip to main content
      </a>
      {/* Sidebar */}
      <aside className="sidebar" role="navigation" aria-label="Main navigation">
        <div className="sidebar-header">
          <span className="logo" aria-hidden="true">
            SE
          </span>
          {!sidebarCollapsed && <span className="brand">Wardex</span>}
          <button
            className="btn-icon collapse-btn"
            onClick={() => setSidebarCollapsed((c) => !c)}
            title="Toggle sidebar"
            aria-label="Toggle sidebar"
            aria-expanded={!sidebarCollapsed}
            aria-controls="sidebar-nav"
          >
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>
        <nav className="sidebar-nav" id="sidebar-nav" aria-label="Page sections">
          {!sidebarCollapsed && authenticated && (
            <div className="sidebar-primary">
              <div className="sidebar-group-title">Primary</div>
              <NavLink
                className={({ isActive }) => `primary-destination ${isActive ? 'active' : ''}`}
                to={primaryDestination.path}
              >
                <span className="primary-destination-label">{primaryDestination.label}</span>
                <span className="primary-destination-copy">{primaryDestination.description}</span>
              </NavLink>
            </div>
          )}
          {!sidebarCollapsed && authenticated && pinnedVisibleSections.length > 0 && (
            <div className="sidebar-group">
              <div className="sidebar-group-title">Pinned Views</div>
              {pinnedVisibleSections.map((section) => (
                <NavLink
                  key={section.id}
                  className={({ isActive }) =>
                    `nav-item nav-item-pinned ${isActive ? 'active' : ''}`
                  }
                  to={section.path}
                  title={section.label}
                >
                  <span className="nav-icon nav-icon-text" aria-hidden="true">
                    {section.shortLabel}
                  </span>
                  <span className="nav-label">{section.label}</span>
                </NavLink>
              ))}
            </div>
          )}
          {groupedSections.map((group) => (
            <div key={group.id} className="sidebar-group">
              {!sidebarCollapsed && <div className="sidebar-group-title">{group.label}</div>}
              {group.sections.map((section) => (
                <div key={section.id} className="nav-item-shell">
                  <NavLink
                    className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    to={section.path}
                    title={section.label}
                    aria-current={location.pathname === section.path ? 'page' : undefined}
                  >
                    <span className="nav-icon nav-icon-text" aria-hidden="true">
                      {section.shortLabel}
                    </span>
                    {!sidebarCollapsed && <span className="nav-label">{section.label}</span>}
                  </NavLink>
                  {!sidebarCollapsed && authenticated && (
                    <button
                      className={`pin-toggle ${pinnedSections.includes(section.id) ? 'active' : ''}`}
                      type="button"
                      onClick={() => togglePinnedSection(section.id)}
                      aria-label={
                        pinnedSections.includes(section.id)
                          ? `Unpin ${section.label}`
                          : `Pin ${section.label}`
                      }
                      title={pinnedSections.includes(section.id) ? 'Unpin' : 'Pin'}
                    >
                      ★
                    </button>
                  )}
                </div>
              ))}
            </div>
          ))}
        </nav>
        {/* Recent Items */}
        {!sidebarCollapsed && authenticated && recentItems.length > 0 && (
          <div className="sidebar-recent">
            <button
              className="btn-link"
              onClick={() => setShowRecent((r) => !r)}
              style={{
                fontSize: 11,
                padding: '4px 12px',
                width: '100%',
                textAlign: 'left',
                opacity: 0.7,
              }}
            >
              {showRecent ? '▾' : '▸'} Recent
            </button>
            {showRecent && (
              <ul style={{ listStyle: 'none', margin: 0, padding: '0 8px', fontSize: 12 }}>
                {recentItems.slice(0, 5).map((r) => (
                  <li key={r.path}>
                    <NavLink
                      className="btn-link nav-item recent-link"
                      style={{ fontSize: 12, padding: '2px 8px', width: '100%', textAlign: 'left' }}
                      to={r.path}
                    >
                      {r.label}
                    </NavLink>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        <div className="sidebar-footer">
          {authenticated && !sidebarCollapsed && (
            <span className="role-badge" title="Current role">
              {role}
            </span>
          )}
          <button
            className="btn-icon"
            onClick={toggle}
            title={dark ? 'Light mode' : 'Dark mode'}
            aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {dark ? '☀' : '🌙'}
          </button>
          {authenticated && (
            <button
              className="btn-icon"
              onClick={disconnect}
              title="Disconnect"
              aria-label="Disconnect"
            >
              ⎋
            </button>
          )}
          <button
            className="shortcut-hint"
            type="button"
            title="Press ? for keyboard shortcuts"
            onClick={() => setShowShortcuts(true)}
          >
            ⌘?
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="main" role="main" aria-label="Main content">
        {/* Top Bar */}
        <header className="topbar" role="banner">
          <div className="topbar-left">
            <button
              className="btn btn-sm sidebar-toggle-topbar"
              type="button"
              onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}
              aria-label="Toggle navigation menu"
              aria-expanded={!sidebarCollapsed}
              aria-controls="sidebar-nav"
            >
              {sidebarCollapsed ? 'Show Menu' : 'Hide Menu'}
            </button>
            <div className="topbar-title-group">
              <h1 className="topbar-title">{currentSection.label}</h1>
              <Breadcrumbs sections={SECTIONS} pathname={location.pathname} />
            </div>
          </div>
          <div className={`topbar-right ${showTopbarActions ? 'topbar-menu-open' : ''}`}>
            {hp?.version && (
              <span className="version-badge" title="Wardex version">
                v{hp.version}
              </span>
            )}
            {authenticated && (
              <div style={{ position: 'relative' }}>
                <button
                  className="btn btn-sm"
                  type="button"
                  onClick={() =>
                    setShowInboxLocationKey((current) =>
                      current === location.key ? null : location.key,
                    )
                  }
                  aria-expanded={showInbox}
                  aria-haspopup="dialog"
                >
                  Inbox{inboxPending > 0 ? ` (${inboxPending})` : ''}
                </button>
                {showInbox && (
                  <div
                    className="card"
                    style={{
                      position: 'absolute',
                      right: 0,
                      top: 'calc(100% + 8px)',
                      width: 'min(360px, calc(100vw - 24px))',
                      zIndex: 20,
                      padding: 0,
                    }}
                  >
                    <div
                      style={{
                        padding: 14,
                        borderBottom: '1px solid var(--border)',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div>
                        <div className="card-title">Operator Inbox</div>
                        <div className="hint" style={{ marginTop: 4 }}>
                          Persistent approvals, degraded feeds, and follow-up work.
                        </div>
                      </div>
                      <button className="btn btn-sm" onClick={() => setShowInboxLocationKey(null)}>
                        Close
                      </button>
                    </div>
                    <div
                      style={{
                        maxHeight: 320,
                        overflowY: 'auto',
                        padding: 12,
                        display: 'grid',
                        gap: 10,
                      }}
                    >
                      {inboxItems.length === 0 ? (
                        <div className="empty" style={{ padding: 20 }}>
                          No active inbox items.
                        </div>
                      ) : (
                        inboxItems.map((item) => (
                          <div
                            key={item.id}
                            style={{
                              border: '1px solid var(--border)',
                              borderRadius: 12,
                              padding: 12,
                              opacity: item.acknowledged ? 0.65 : 1,
                            }}
                          >
                            <div
                              style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                gap: 8,
                                alignItems: 'flex-start',
                              }}
                            >
                              <div>
                                <div style={{ fontWeight: 700, fontSize: 13 }}>{item.title}</div>
                                <div className="hint" style={{ marginTop: 4 }}>
                                  {item.summary}
                                </div>
                              </div>
                              <span
                                className={`badge ${item.severity === 'high' ? 'badge-err' : item.severity === 'medium' ? 'badge-warn' : 'badge-info'}`}
                              >
                                {item.severity}
                              </span>
                            </div>
                            <div
                              style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}
                            >
                              <button
                                className="btn btn-sm btn-primary"
                                onClick={() => {
                                  navigate(item.path);
                                  setShowInboxLocationKey(null);
                                }}
                              >
                                Open
                              </button>
                              {!item.acknowledged && (
                                <button
                                  className="btn btn-sm"
                                  onClick={async () => {
                                    await api.ackInbox({ id: item.id });
                                    reloadInbox();
                                  }}
                                >
                                  Acknowledge
                                </button>
                              )}
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
            {authenticated && (
              <div className="topbar-secondary-actions">
                <button
                  className="btn btn-sm"
                  onClick={() => setSearchOpen(true)}
                  title="Global search (⌘K)"
                  aria-label="Open global search (⌘K)"
                >
                  Search
                </button>
                {currentSection.path !== '/help' && (
                  <button
                    className="btn btn-sm"
                    onClick={() =>
                      navigate(buildContextualHelpHref(currentSection.id, location.search))
                    }
                    title="Open contextual help for this workspace"
                    type="button"
                  >
                    Help For View
                  </button>
                )}
                <button
                  className="btn btn-sm"
                  onClick={copyShareLink}
                  title="Copy shareable deep-link to clipboard"
                >
                  {linkCopied ? 'Copied' : 'Share Link'}
                </button>
                <button
                  className={`btn btn-sm ${pinnedSections.includes(currentSection.id) ? 'btn-primary' : ''}`}
                  type="button"
                  onClick={() => togglePinnedSection(currentSection.id)}
                  aria-label={
                    pinnedSections.includes(currentSection.id)
                      ? `Unpin ${currentSection.label}`
                      : `Pin ${currentSection.label}`
                  }
                >
                  {pinnedSections.includes(currentSection.id) ? 'Pinned' : 'Pin View'}
                </button>
              </div>
            )}
            {authenticated && (
              <div className="mobile-topbar-actions">
                <button
                  className="btn btn-sm"
                  type="button"
                  onClick={() =>
                    setShowTopbarActionsLocationKey((current) =>
                      current === location.key ? null : location.key,
                    )
                  }
                  aria-expanded={showTopbarActions}
                  aria-haspopup="menu"
                >
                  More
                </button>
                {showTopbarActions && (
                  <div
                    className="card mobile-topbar-actions-menu"
                    role="menu"
                    aria-label="More actions"
                  >
                    <button
                      className="btn btn-sm"
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        setSearchOpen(true);
                        setShowTopbarActionsLocationKey(null);
                      }}
                    >
                      Search
                    </button>
                    {currentSection.path !== '/help' && (
                      <button
                        className="btn btn-sm"
                        type="button"
                        role="menuitem"
                        onClick={() => {
                          navigate(buildContextualHelpHref(currentSection.id, location.search));
                          setShowTopbarActionsLocationKey(null);
                        }}
                      >
                        Help For View
                      </button>
                    )}
                    <button
                      className="btn btn-sm"
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        copyShareLink();
                        setShowTopbarActionsLocationKey(null);
                      }}
                    >
                      {linkCopied ? 'Copied' : 'Share Link'}
                    </button>
                    <button
                      className={`btn btn-sm ${pinnedSections.includes(currentSection.id) ? 'btn-primary' : ''}`}
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        togglePinnedSection(currentSection.id);
                        setShowTopbarActionsLocationKey(null);
                      }}
                    >
                      {pinnedSections.includes(currentSection.id) ? 'Pinned' : 'Pin View'}
                    </button>
                  </div>
                )}
              </div>
            )}
            {!authenticated ? (
              <form className="auth-form" onSubmit={handleConnect}>
                <label className="sr-only" htmlFor="api-token-input">
                  API token
                </label>
                {/* Keeps password managers from treating the API token field as a username/password login. */}
                <input
                  type="text"
                  name="username"
                  autoComplete="username"
                  aria-hidden="true"
                  tabIndex={-1}
                  style={{ position: 'absolute', width: 1, height: 1, opacity: 0, pointerEvents: 'none' }}
                  value="api-token"
                  readOnly
                />
                <input
                  id="api-token-input"
                  name="api_token"
                  type="password"
                  placeholder="Paste API token…"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  className="auth-input"
                  autoComplete="current-password"
                />
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={checking || !tokenInput}
                >
                  {checking ? 'Connecting…' : 'Connect'}
                </button>
                {ssoProviders.length > 0 && (
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {visibleSsoProviders.map((provider) => (
                      <button
                        key={provider.id}
                        type="button"
                        className="btn"
                        onClick={() => handleSsoLogin(provider.id)}
                        disabled={checking}
                      >
                        {ssoProviders.length === 1
                          ? `Sign in with ${ssoProviderLabel(provider)}`
                          : ssoProviderLabel(provider)}
                      </button>
                    ))}
                    {ssoOverflowCount > 0 && (
                      <span className="badge badge-info">+{ssoOverflowCount} more</span>
                    )}
                  </div>
                )}
                {authError && <span className="auth-error">{authError}</span>}
              </form>
            ) : (
              <span className="auth-badge" aria-label="Connected to Wardex">
                <span className="auth-badge-full">● Connected</span>
                <span className="auth-badge-compact" aria-hidden="true">
                  ● On
                </span>
              </span>
            )}
          </div>
        </header>
        {authenticated && (
          <div className="scope-bar" aria-label="Current workspace scope">
            <div className="scope-copy">
              <span className="scope-title">{primaryDestination.label}</span>
              <span className="scope-separator">•</span>
              <span>{currentSection.label}</span>
            </div>
            <div className="scope-chips">
              {scopeTokens.map((token) => (
                <span key={token} className="scope-chip">
                  {token}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Content */}
        <div className="content" id="main-content">
          {!authenticated ? (
            <div className="auth-prompt">
              <h2>Welcome to Wardex Admin Console</h2>
              <p>Enter your API token to connect to the Wardex backend.</p>
              <p className="hint">
                Read it from var/.wardex_token, or start Wardex with WARDEX_ADMIN_TOKEN.
              </p>
              {ssoProviders.length > 0 && (
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 16 }}>
                  {visibleSsoProviders.map((provider) => (
                    <button
                      key={`prompt-${provider.id}`}
                      type="button"
                      className="btn btn-primary"
                      onClick={() => handleSsoLogin(provider.id)}
                    >
                      {`Sign in with ${ssoProviderLabel(provider)}`}
                    </button>
                  ))}
                  {ssoOverflowCount > 0 && (
                    <span className="badge badge-info">+{ssoOverflowCount} more configured</span>
                  )}
                </div>
              )}
              {ssoProviders.length > 0 && (
                <div className="card" style={{ marginTop: 16, textAlign: 'left' }}>
                  <div className="card-title" style={{ marginBottom: 10 }}>
                    Federated Sign-In Ready
                  </div>
                  <div className="summary-grid">
                    <div className="summary-card">
                      <div className="summary-label">Ready providers</div>
                      <div className="summary-value">{ssoProviders.length}</div>
                      <div className="summary-meta">{ssoProviderMeta}</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-label">SCIM status</div>
                      <div className="summary-value">
                        {ssoConfig?.scim?.enabled
                          ? ssoConfig?.scim?.status || 'configured'
                          : 'disabled'}
                      </div>
                      <div className="summary-meta">
                        {ssoConfig?.scim?.mapping_count ?? 0} group mapping
                        {(ssoConfig?.scim?.mapping_count ?? 0) === 1 ? '' : 's'} ready for lifecycle
                        sync.
                      </div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-label">Callback handoff</div>
                      <div className="summary-value" style={{ fontSize: 13 }}>
                        /api/auth/sso/callback
                      </div>
                      <div className="summary-meta">
                        After external sign-in, Wardex returns here through the configured callback
                        route.
                      </div>
                    </div>
                  </div>
                  <div className="hint" style={{ marginTop: 12 }}>
                    Use the provider buttons above to validate the external redirect and callback
                    flow with the same routes the live console uses.
                  </div>
                </div>
              )}
              {authError && (
                <div className="auth-error" style={{ marginTop: 16 }}>
                  {authError}
                </div>
              )}
            </div>
          ) : (
            <Routes key={location.pathname}>
              <Route
                path="/"
                element={
                  <ErrorBoundary>
                    <Suspense fallback={<div className="loading">Loading…</div>}>
                      <Dashboard />
                    </Suspense>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/monitor"
                element={
                  <ErrorBoundary>
                    <Suspense fallback={<div className="loading">Loading…</div>}>
                      <LiveMonitor />
                    </Suspense>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/detection"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <ThreatDetection />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/fleet"
                element={
                  <ErrorBoundary>
                    <Suspense fallback={<div className="loading">Loading…</div>}>
                      <FleetAgents />
                    </Suspense>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/policy"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <SecurityPolicy />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/soc"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <SOCWorkbench />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/command"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <CommandCenter />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/assistant"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <AssistantWorkspace />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/infrastructure"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <Infrastructure />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/reports"
                element={
                  <ErrorBoundary>
                    <Suspense fallback={<div className="loading">Loading…</div>}>
                      <ReportsExports />
                    </Suspense>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/settings"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="admin">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <Settings />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/help"
                element={
                  <ErrorBoundary>
                    <Suspense fallback={<div className="loading">Loading…</div>}>
                      <HelpDocs />
                    </Suspense>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/ueba"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <UEBADashboard />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/ndr"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <NDRDashboard />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/email-security"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <EmailSecurity />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route
                path="/attack-graph"
                element={
                  <ErrorBoundary>
                    <RequireRole minRole="analyst">
                      <Suspense fallback={<div className="loading">Loading…</div>}>
                        <AttackGraph />
                      </Suspense>
                    </RequireRole>
                  </ErrorBoundary>
                }
              />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          )}
        </div>
      </main>
      <SearchPalette
        open={searchOpen}
        onClose={(v) => setSearchOpen(typeof v === 'boolean' ? v : false)}
        onNavigate={(item) => {
          const targetPath = item.path || (item.action ? buildCommandHref(item.action) : '');
          if (targetPath) navigate(targetPath);
        }}
      />
      <NotificationToast active={authenticated} />
      {authenticated && showOnboarding && (
        <OnboardingWizard
          onComplete={() => {
            localStorage.setItem('wardex_onboarded', '1');
            setShowOnboarding(false);
          }}
        />
      )}
      {showShortcuts && (
        <div className="search-palette-overlay" onClick={() => setShowShortcuts(false)}>
          <div
            className="search-palette"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: 400 }}
          >
            <div style={{ padding: 16 }}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 12,
                }}
              >
                <h3 style={{ margin: 0 }}>Keyboard Shortcuts</h3>
                <button className="btn btn-sm" onClick={() => setShowShortcuts(false)}>
                  ✕
                </button>
              </div>
              {[
                ['?', 'Toggle this help'],
                ['D', 'Go to Dashboard'],
                ['M', 'Go to Live Monitor'],
                ['T', 'Go to Threat Detection'],
                ['F', 'Go to Fleet & Agents'],
                ['S', 'Go to SOC Workbench'],
                ['C', 'Go to Command Center'],
                ['U', 'Go to UEBA'],
                ['N', 'Go to NDR'],
                ['E', 'Go to Email Security'],
                ['A', 'Go to Attack Graph'],
                ['G', 'Go to Settings'],
                ['⌘K', 'Open search palette'],
              ].map(([key, desc]) => (
                <div
                  key={key}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    padding: '6px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <span style={{ fontSize: 13 }}>{desc}</span>
                  <kbd
                    style={{
                      fontSize: 11,
                      padding: '2px 8px',
                      borderRadius: 4,
                      background: 'var(--bg)',
                      border: '1px solid var(--border)',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {key}
                  </kbd>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

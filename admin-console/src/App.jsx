import { useState, useCallback, useEffect } from 'react';
import { Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom';
import { useAuth, useTheme, useRole, useApi } from './hooks.jsx';
import * as api from './api.js';
import Dashboard from './components/Dashboard.jsx';
import LiveMonitor from './components/LiveMonitor.jsx';
import ThreatDetection from './components/ThreatDetection.jsx';
import FleetAgents from './components/FleetAgents.jsx';
import SecurityPolicy from './components/SecurityPolicy.jsx';
import SOCWorkbench from './components/SOCWorkbench.jsx';
import Infrastructure from './components/Infrastructure.jsx';
import ReportsExports from './components/ReportsExports.jsx';
import Settings from './components/Settings.jsx';
import HelpDocs from './components/HelpDocs.jsx';
import SearchPalette from './components/SearchPalette.jsx';
import NotificationToast from './components/NotificationToast.jsx';
import OnboardingWizard from './components/OnboardingWizard.jsx';

const SECTIONS = [
  { id: 'dashboard',        path: '/',                 label: 'Dashboard',        icon: '📊', minRole: 'viewer' },
  { id: 'live-monitor',     path: '/monitor',          label: 'Live Monitor',     icon: '🔴', minRole: 'viewer' },
  { id: 'threat-detection', path: '/detection',        label: 'Threat Detection', icon: '🛡', minRole: 'analyst' },
  { id: 'fleet-agents',     path: '/fleet',            label: 'Fleet & Agents',   icon: '🖥', minRole: 'viewer' },
  { id: 'security-policy',  path: '/policy',           label: 'Security Policy',  icon: '📋', minRole: 'analyst' },
  { id: 'soc-workbench',    path: '/soc',              label: 'SOC Workbench',    icon: '🔬', minRole: 'analyst' },
  { id: 'infrastructure',   path: '/infrastructure',   label: 'Infrastructure',   icon: '⚙', minRole: 'analyst' },
  { id: 'reports-exports',  path: '/reports',          label: 'Reports & Exports',icon: '📄', minRole: 'viewer' },
  { id: 'settings',         path: '/settings',         label: 'Settings',         icon: '⚡', minRole: 'admin' },
  { id: 'help-docs',        path: '/help',             label: 'Help & Docs',      icon: '❓', minRole: 'viewer' },
];

const ROLE_LEVEL = { viewer: 0, analyst: 1, admin: 2 };

function RequireRole({ minRole, children }) {
  const { role } = useRole();
  if (ROLE_LEVEL[role] >= ROLE_LEVEL[minRole]) return children;
  return (
    <div className="access-denied">
      <h2>Access Denied</h2>
      <p>You need the <strong>{minRole}</strong> role or higher to view this section.</p>
    </div>
  );
}

export default function App() {
  const { authenticated, checking, connect, disconnect } = useAuth();
  const { dark, toggle } = useTheme();
  const { role } = useRole();
  const { data: hp } = useApi(api.health);
  const navigate = useNavigate();
  const location = useLocation();

  const [tokenInput, setTokenInput] = useState('');
  const [authError, setAuthError] = useState('');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [linkCopied, setLinkCopied] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [showOnboarding, setShowOnboarding] = useState(() => !localStorage.getItem('wardex_onboarded'));
  const [showShortcuts, setShowShortcuts] = useState(false);

  // ── Global Keyboard Shortcuts ──
  useEffect(() => {
    const handler = (e) => {
      // Ignore if user is typing in an input/textarea
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
      switch (e.key) {
        case '?': setShowShortcuts(s => !s); break;
        case 'd': navigate('/'); break;
        case 'm': navigate('/monitor'); break;
        case 't': navigate('/detection'); break;
        case 'f': navigate('/fleet'); break;
        case 's': navigate('/soc'); break;
        case 'g': navigate('/settings'); break;
        default: break;
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [navigate]);

  const currentSection = SECTIONS.find(s => s.path === location.pathname) || SECTIONS[0];

  const handleNavigate = useCallback((path) => {
    navigate(path);
  }, [navigate]);

  const copyShareLink = useCallback(() => {
    const url = window.location.origin + location.pathname;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(url).then(() => {
        setLinkCopied(true);
        setTimeout(() => setLinkCopied(false), 2000);
      });
    }
  }, [location.pathname]);

  const handleConnect = useCallback(async (e) => {
    e.preventDefault();
    setAuthError('');
    const ok = await connect(tokenInput);
    if (!ok) setAuthError('Authentication failed — check your token');
  }, [tokenInput, connect]);

  // Filter sidebar items by role
  const visibleSections = SECTIONS.filter(s => ROLE_LEVEL[role] >= ROLE_LEVEL[s.minRole]);

  return (
    <div className={`app ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      <a href="#main-content" className="sr-only focus-visible-only">Skip to main content</a>
      {/* Sidebar */}
      <aside className="sidebar" role="navigation" aria-label="Main navigation">
        <div className="sidebar-header">
          <span className="logo">🛡</span>
          {!sidebarCollapsed && <span className="brand">Wardex</span>}
          <button className="btn-icon collapse-btn" onClick={() => setSidebarCollapsed(c => !c)} title="Toggle sidebar" aria-expanded={!sidebarCollapsed} aria-controls="sidebar-nav">
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>
        <nav className="sidebar-nav" id="sidebar-nav" aria-label="Page sections">
          {visibleSections.map(s => (
            <button
              key={s.id}
              className={`nav-item ${location.pathname === s.path ? 'active' : ''}`}
              onClick={() => handleNavigate(s.path)}
              title={s.label}
            >
              <span className="nav-icon">{s.icon}</span>
              {!sidebarCollapsed && <span className="nav-label">{s.label}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          {authenticated && !sidebarCollapsed && (
            <span className="role-badge" title="Current role">{role}</span>
          )}
          <button className="btn-icon" onClick={toggle} title={dark ? 'Light mode' : 'Dark mode'}>
            {dark ? '☀' : '🌙'}
          </button>
          {authenticated && (
            <button className="btn-icon" onClick={disconnect} title="Disconnect">🔌</button>
          )}
        </div>
      </aside>

      {/* Main */}
      <main className="main" role="main" aria-label="Main content">
        {/* Top Bar */}
        <header className="topbar" role="banner">
          <h1 className="topbar-title">{currentSection.label}</h1>
          <div className="topbar-right">
            {hp?.version && (
              <span className="version-badge" title="Wardex version">v{hp.version}</span>
            )}
            {authenticated && (
              <button className="btn btn-sm" onClick={() => setSearchOpen(true)} title="Global search (⌘K)">
                🔍 Search
              </button>
            )}
            {authenticated && (
              <button className="btn btn-sm" onClick={copyShareLink} title="Copy shareable deep-link to clipboard">
                {linkCopied ? '✓ Copied' : '🔗 Share Link'}
              </button>
            )}
            {!authenticated ? (
              <form className="auth-form" onSubmit={handleConnect}>
                <input
                  type="password"
                  placeholder="API token"
                  value={tokenInput}
                  onChange={e => setTokenInput(e.target.value)}
                  className="auth-input"
                  autoComplete="off"
                />
                <button type="submit" className="btn btn-primary" disabled={checking || !tokenInput}>
                  {checking ? 'Connecting…' : 'Connect'}
                </button>
                {authError && <span className="auth-error">{authError}</span>}
              </form>
            ) : (
              <span className="auth-badge">● Connected</span>
            )}
          </div>
        </header>

        {/* Content */}
        <div className="content" id="main-content">
          {!authenticated ? (
            <div className="auth-prompt">
              <h2>Welcome to Wardex Admin Console</h2>
              <p>Enter your API token to connect to the Wardex backend.</p>
              <p className="hint">The token is displayed in the terminal when you start Wardex.</p>
            </div>
          ) : (
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/monitor" element={<LiveMonitor />} />
              <Route path="/detection" element={<RequireRole minRole="analyst"><ThreatDetection /></RequireRole>} />
              <Route path="/fleet" element={<FleetAgents />} />
              <Route path="/policy" element={<RequireRole minRole="analyst"><SecurityPolicy /></RequireRole>} />
              <Route path="/soc" element={<RequireRole minRole="analyst"><SOCWorkbench /></RequireRole>} />
              <Route path="/infrastructure" element={<RequireRole minRole="analyst"><Infrastructure /></RequireRole>} />
              <Route path="/reports" element={<ReportsExports />} />
              <Route path="/settings" element={<RequireRole minRole="admin"><Settings /></RequireRole>} />
              <Route path="/help" element={<HelpDocs />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          )}
        </div>
      </main>
      <SearchPalette
        open={searchOpen}
        onClose={(v) => setSearchOpen(typeof v === 'boolean' ? v : false)}
        onNavigate={(item) => {
          // Navigate to the appropriate section based on category
          if (item.category === 'Alerts') navigate('/');
          else if (item.category === 'Agents') navigate('/fleet');
          else if (item.category === 'Detection Rules') navigate('/detection');
          else if (item.category === 'Quarantine') navigate('/soc');
          else if (item.category === 'Feed Sources') navigate('/infrastructure');
        }}
      />
      <NotificationToast />
      {showOnboarding && (
        <OnboardingWizard onComplete={() => {
          localStorage.setItem('wardex_onboarded', '1');
          setShowOnboarding(false);
        }} />
      )}
      {showShortcuts && (
        <div className="search-palette-overlay" onClick={() => setShowShortcuts(false)}>
          <div className="search-palette" onClick={e => e.stopPropagation()} style={{ maxWidth: 400 }}>
            <div style={{ padding: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <h3 style={{ margin: 0 }}>Keyboard Shortcuts</h3>
                <button className="btn btn-sm" onClick={() => setShowShortcuts(false)}>✕</button>
              </div>
              {[
                ['?', 'Toggle this help'],
                ['D', 'Go to Dashboard'],
                ['M', 'Go to Live Monitor'],
                ['T', 'Go to Threat Detection'],
                ['F', 'Go to Fleet & Agents'],
                ['S', 'Go to SOC Workbench'],
                ['G', 'Go to Settings'],
                ['⌘K', 'Open search palette'],
              ].map(([key, desc]) => (
                <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <span style={{ fontSize: 13 }}>{desc}</span>
                  <kbd style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4, background: 'var(--bg)', border: '1px solid var(--border)', fontFamily: 'var(--font-mono)' }}>{key}</kbd>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

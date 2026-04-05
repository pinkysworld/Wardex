import { useState, useCallback } from 'react';
import { useAuth, useTheme } from './hooks.jsx';
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

const SECTIONS = [
  { id: 'dashboard',        label: 'Dashboard',        icon: '📊' },
  { id: 'live-monitor',     label: 'Live Monitor',     icon: '🔴' },
  { id: 'threat-detection', label: 'Threat Detection',  icon: '🛡' },
  { id: 'fleet-agents',     label: 'Fleet & Agents',   icon: '🖥' },
  { id: 'security-policy',  label: 'Security Policy',  icon: '📋' },
  { id: 'soc-workbench',    label: 'SOC Workbench',    icon: '🔬' },
  { id: 'infrastructure',   label: 'Infrastructure',   icon: '⚙' },
  { id: 'reports-exports',  label: 'Reports & Exports', icon: '📄' },
  { id: 'settings',         label: 'Settings',         icon: '⚡' },
  { id: 'help-docs',        label: 'Help & Docs',      icon: '❓' },
];

const SECTION_COMPONENTS = {
  'dashboard': Dashboard,
  'live-monitor': LiveMonitor,
  'threat-detection': ThreatDetection,
  'fleet-agents': FleetAgents,
  'security-policy': SecurityPolicy,
  'soc-workbench': SOCWorkbench,
  'infrastructure': Infrastructure,
  'reports-exports': ReportsExports,
  'settings': Settings,
  'help-docs': HelpDocs,
};

export default function App() {
  const { authenticated, checking, connect, disconnect } = useAuth();
  const { dark, toggle } = useTheme();
  const [section, setSection] = useState('dashboard');
  const [tokenInput, setTokenInput] = useState('');
  const [authError, setAuthError] = useState('');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const handleConnect = useCallback(async (e) => {
    e.preventDefault();
    setAuthError('');
    const ok = await connect(tokenInput);
    if (!ok) setAuthError('Authentication failed — check your token');
  }, [tokenInput, connect]);

  const SectionComponent = SECTION_COMPONENTS[section];

  return (
    <div className={`app ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="logo">🛡</span>
          {!sidebarCollapsed && <span className="brand">Wardex</span>}
          <button className="btn-icon collapse-btn" onClick={() => setSidebarCollapsed(c => !c)} title="Toggle sidebar">
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>
        <nav className="sidebar-nav">
          {SECTIONS.map(s => (
            <button
              key={s.id}
              className={`nav-item ${section === s.id ? 'active' : ''}`}
              onClick={() => setSection(s.id)}
              title={s.label}
            >
              <span className="nav-icon">{s.icon}</span>
              {!sidebarCollapsed && <span className="nav-label">{s.label}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <button className="btn-icon" onClick={toggle} title={dark ? 'Light mode' : 'Dark mode'}>
            {dark ? '☀' : '🌙'}
          </button>
          {authenticated && (
            <button className="btn-icon" onClick={disconnect} title="Disconnect">🔌</button>
          )}
        </div>
      </aside>

      {/* Main */}
      <main className="main">
        {/* Top Bar */}
        <header className="topbar">
          <h1 className="topbar-title">{SECTIONS.find(s => s.id === section)?.label}</h1>
          <div className="topbar-right">
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
        <div className="content">
          {!authenticated ? (
            <div className="auth-prompt">
              <h2>Welcome to Wardex Admin Console</h2>
              <p>Enter your API token to connect to the Wardex backend.</p>
              <p className="hint">The token is displayed in the terminal when you start Wardex.</p>
            </div>
          ) : (
            SectionComponent && <SectionComponent />
          )}
        </div>
      </main>
    </div>
  );
}

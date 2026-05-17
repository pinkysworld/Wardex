import { useState, useEffect, useRef } from 'react';
import * as api from '../api.js';
import { useRole } from '../hooks.jsx';
import { safeStorageJsonGet, safeStorageJsonSet } from '../safeStorage.js';
import { SEARCH_COMMANDS } from './workflowPivots.js';

const SAVED_KEY = 'wardex_saved_searches';
function loadSaved() {
  return safeStorageJsonGet(SAVED_KEY, []);
}
function persistSaved(list) {
  safeStorageJsonSet(SAVED_KEY, list);
}

const CATEGORIES = [
  {
    key: 'alerts',
    label: 'Alerts',
    icon: 'AL',
    search: api.alerts,
    path: '/monitor',
    kind: 'entity',
  },
  {
    key: 'incidents',
    label: 'Incidents',
    icon: 'IN',
    search: api.incidents,
    path: '/soc',
    kind: 'entity',
  },
  {
    key: 'agents',
    label: 'Agents',
    icon: 'AG',
    search: api.agents,
    path: '/fleet',
    kind: 'entity',
  },
  {
    key: 'rules',
    label: 'Detection Rules',
    icon: 'RL',
    search: api.detectionRules,
    path: '/detection',
    kind: 'entity',
  },
  {
    key: 'feeds',
    label: 'Feed Sources',
    icon: 'FD',
    search: api.feeds,
    path: '/infrastructure',
    kind: 'entity',
  },
];

const COMMANDS = SEARCH_COMMANDS;
const FEATURED_COMMANDS = [
  'Connect First Agent',
  'Connect Agent Drawer',
  'Shift Handoff Workspace',
  'Incident Timeline Builder',
  'Guided Incident Path',
  'Fleet Risk Heatmap',
  'Open SOC Queue',
  'Deployment Confidence',
  'Safe Assistant',
];

const ANALYST_RESTRICTED_ACTIONS = new Set([
  'connect-first-agent',
  'connect-agent-drawer',
  'collector-onboarding-center',
  'release-gate',
  'release-acceptance-report',
  'deployment-confidence',
  'evidence-surface-coverage',
  'visual-regression-gate',
]);

const ROUTE_PRIORITY_ACTIONS = [
  {
    match: (path) => path === '/launchpad' || path === '/',
    actions: [
      'shift-handoff-workspace',
      'morning-brief',
      'guided-incident',
      'operator-task-queue',
      'incident-timeline-builder',
      'fleet-risk-heatmap',
    ],
  },
  {
    match: (path) => path === '/soc',
    actions: [
      'open-soc-queue',
      'guided-incident',
      'incident-timeline-builder',
      'shift-handoff-workspace',
      'open-process-workbench',
      'safe-assistant',
    ],
  },
  {
    match: (path) => path === '/detection' || path === '/detection-lab',
    actions: ['detection-quality', 'run-hunt', 'start-detection-lab', 'demo-scenarios'],
  },
  {
    match: (path) => path === '/fleet',
    actions: [
      'connect-agent-drawer',
      'review-offline-agents',
      'fleet-health-drilldown',
      'fleet-risk-heatmap',
      'collector-onboarding-center',
    ],
  },
  {
    match: (path) => ['/operations-health', '/reports', '/settings'].includes(path),
    actions: [
      'deployment-confidence',
      'release-gate',
      'release-acceptance-report',
      'evidence-surface-coverage',
      'visual-regression-gate',
    ],
  },
];

const CONTEXT_COMMANDS = [
  {
    label: 'Launchpad actions',
    match: (path) => path === '/launchpad' || path === '/',
    actions: [
      'shift-handoff-workspace',
      'incident-timeline-builder',
      'morning-brief',
      'guided-incident',
      'operator-task-queue',
      'collector-onboarding-center',
      'release-gate',
      'release-acceptance-report',
      'fleet-risk-heatmap',
      'evidence-freshness',
      'safe-assistant',
      'visual-regression-gate',
    ],
  },
  {
    label: 'Fleet actions',
    match: (path) => path === '/fleet',
    actions: [
      'connect-agent-drawer',
      'fleet-health-drilldown',
      'fleet-risk-heatmap',
      'collector-onboarding-center',
      'review-offline-agents',
    ],
  },
  {
    label: 'SOC actions',
    match: (path) => path === '/soc',
    actions: [
      'incident-timeline-builder',
      'shift-handoff-workspace',
      'guided-incident',
      'open-soc-queue',
      'response-playbook-simulator',
      'safe-assistant',
      'open-process-workbench',
    ],
  },
  {
    label: 'Release actions',
    match: (path) => ['/operations-health', '/reports', '/settings'].includes(path),
    actions: [
      'release-acceptance-report',
      'release-gate',
      'deployment-confidence',
      'evidence-surface-coverage',
      'visual-regression-gate',
    ],
  },
  {
    label: 'Detection actions',
    match: (path) => path === '/detection' || path === '/detection-lab',
    actions: ['detection-quality', 'run-hunt', 'start-detection-lab', 'demo-scenarios'],
  },
];

function uniqueCommandsByAction(commands) {
  const seen = new Set();
  return commands.filter((command) => {
    const key = command.action || command.title;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// eslint-disable-next-line react-refresh/only-export-components
export function filterCommandsForRole(commands, role = 'viewer') {
  const commandList = Array.isArray(commands) ? commands : [];
  if (role !== 'analyst') return commandList;
  return commandList.filter((command) => !ANALYST_RESTRICTED_ACTIONS.has(command.action));
}

function routePriorityForPath(pathname = '') {
  return ROUTE_PRIORITY_ACTIONS.find((entry) => entry.match(pathname))?.actions || [];
}

// eslint-disable-next-line react-refresh/only-export-components
export function prioritizeCommandsForPath(commands, pathname = '') {
  const commandList = Array.isArray(commands) ? commands : [];
  const actionPriority = new Map(
    routePriorityForPath(pathname).map((action, index) => [action, index]),
  );
  const originalOrder = new Map(
    commandList.map((command, index) => [command.action || command.title, index]),
  );

  return [...commandList].sort((left, right) => {
    const leftPriority = actionPriority.get(left.action) ?? Number.MAX_SAFE_INTEGER;
    const rightPriority = actionPriority.get(right.action) ?? Number.MAX_SAFE_INTEGER;

    if (leftPriority !== rightPriority) return leftPriority - rightPriority;

    return (
      (originalOrder.get(left.action || left.title) ?? Number.MAX_SAFE_INTEGER) -
      (originalOrder.get(right.action || right.title) ?? Number.MAX_SAFE_INTEGER)
    );
  });
}

function contextualCommandsForPath(pathname = '', role = 'viewer') {
  const context = CONTEXT_COMMANDS.find((entry) => entry.match(pathname));
  if (!context) return { label: '', commands: [] };
  const commands = context.actions
    .map((action) =>
      filterCommandsForRole(COMMANDS, role).find((command) => command.action === action),
    )
    .filter(Boolean);
  return { label: context.label, commands: uniqueCommandsByAction(commands) };
}

function SearchPaletteDialog({ onClose, onNavigate, saved, setSaved, currentPath, role }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef(null);
  const searchGenRef = useRef(0);
  const visibleCommands = filterCommandsForRole(COMMANDS, role);
  const contextualCommands = contextualCommandsForPath(currentPath, role);
  const contextualActions = new Set(contextualCommands.commands.map((command) => command.action));
  const featuredCommands = prioritizeCommandsForPath(
    visibleCommands.filter(
      (command) =>
        FEATURED_COMMANDS.includes(command.title) && !contextualActions.has(command.action),
    ),
    currentPath,
  );
  const remainingCommands = prioritizeCommandsForPath(
    visibleCommands.filter(
      (command) =>
        !FEATURED_COMMANDS.includes(command.title) && !contextualActions.has(command.action),
    ),
    currentPath,
  );

  useEffect(() => {
    const focusTimer = window.setTimeout(() => inputRef.current?.focus(), 50);
    return () => window.clearTimeout(focusTimer);
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      async function runSearch() {
        if (!query || query.length < 2) {
          setResults([]);
          setLoading(false);
          return;
        }
        setLoading(true);
        const gen = ++searchGenRef.current;
        const ql = query.toLowerCase();
        const allResults = visibleCommands.filter((command) =>
          `${command.title} ${command.subtitle}`.toLowerCase().includes(ql),
        );

        await Promise.allSettled(
          CATEGORIES.map(async (cat) => {
            try {
              const data = await cat.search();
              const items = Array.isArray(data)
                ? data
                : data?.items ||
                  data?.alerts ||
                  data?.agents ||
                  data?.incidents ||
                  data?.rules ||
                  [];
              items.forEach((item) => {
                const text = JSON.stringify(item).toLowerCase();
                if (text.includes(ql)) {
                  const title =
                    item.name ||
                    item.hostname ||
                    item.title ||
                    item.id ||
                    item.alert_id ||
                    item.message ||
                    'Unknown';
                  const subtitle =
                    item.severity ||
                    item.status ||
                    item.protocol ||
                    item.hostname ||
                    item.category ||
                    '';
                  allResults.push({
                    category: cat.label,
                    icon: cat.icon,
                    title,
                    subtitle,
                    raw: item,
                    kind: cat.kind,
                    path: cat.path,
                  });
                }
              });
            } catch {
              /* ignore category errors */
            }
          }),
        );

        if (gen !== searchGenRef.current) return;
        setResults(allResults.slice(0, 20));
        setSelectedIdx(0);
        setLoading(false);
      }

      void runSearch();
    }, 300);
    return () => clearTimeout(timer);
  }, [query, visibleCommands]);

  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIdx((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter' && results[selectedIdx]) {
      onNavigate?.(results[selectedIdx]);
      onClose?.(false);
    } else if (e.key === 'Escape') onClose?.(false);
  };

  return (
    <div className="search-palette-overlay" onClick={() => onClose?.(false)}>
      <div
        className="search-palette"
        role="dialog"
        aria-modal="true"
        aria-label="Global search"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="search-palette-input-wrap">
          <span className="search-palette-icon" aria-hidden="true">
            ⌕
          </span>
          <input
            ref={inputRef}
            type="text"
            placeholder="Search alerts, incidents, agents, hosts, commands…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="search-palette-input"
            aria-label="Global search"
            role="combobox"
            aria-expanded={results.length > 0}
            aria-controls="search-results"
            aria-activedescendant={results.length > 0 ? `search-result-${selectedIdx}` : undefined}
          />
          <kbd
            style={{
              fontSize: 11,
              padding: '2px 6px',
              borderRadius: 4,
              background: 'var(--bg)',
              border: '1px solid var(--border)',
            }}
          >
            ESC
          </kbd>
          {query.length >= 2 && !saved.includes(query) && (
            <button
              style={{
                fontSize: 11,
                padding: '2px 8px',
                borderRadius: 4,
                background: 'var(--primary)',
                color: '#fff',
                border: 'none',
                cursor: 'pointer',
                marginLeft: 4,
                whiteSpace: 'nowrap',
              }}
              onClick={() => {
                const next = [query, ...saved].slice(0, 20);
                setSaved(next);
                persistSaved(next);
              }}
            >
              Save
            </button>
          )}
        </div>
        {/* Saved searches shown when query is empty */}
        {query.length < 2 && saved.length > 0 && (
          <div style={{ padding: '8px 12px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6 }}>
              Saved searches
            </div>
            {saved.map((s, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '4px 0',
                  fontSize: 13,
                }}
              >
                <button className="search-saved-link" type="button" onClick={() => setQuery(s)}>
                  Saved: {s}
                </button>
                <button
                  style={{
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    color: 'var(--text-secondary)',
                    fontSize: 11,
                  }}
                  onClick={() => {
                    const next = saved.filter((_, j) => j !== i);
                    setSaved(next);
                    persistSaved(next);
                  }}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        )}
        {query.length < 2 && (
          <>
            {contextualCommands.commands.length > 0 && (
              <>
                <div className="search-section-heading">
                  <span>{contextualCommands.label}</span>
                  <span>{contextualCommands.commands.length} actions</span>
                </div>
                <div className="search-command-grid search-command-grid-featured">
                  {contextualCommands.commands.map((command) => (
                    <button
                      key={command.title}
                      type="button"
                      className="search-command-card search-command-card-featured"
                      onClick={() => {
                        onNavigate?.(command);
                        onClose?.(false);
                      }}
                    >
                      <span className="search-command-icon" aria-hidden="true">
                        {command.icon}
                      </span>
                      <span className="search-command-label">{command.title}</span>
                      <span className="search-command-copy">{command.subtitle}</span>
                    </button>
                  ))}
                </div>
              </>
            )}
            <div className="search-section-heading">
              <span>Operator quick actions</span>
              <span>{featuredCommands.length} actions</span>
            </div>
            <div className="search-command-grid search-command-grid-featured">
              {featuredCommands.map((command) => (
                <button
                  key={command.title}
                  type="button"
                  className="search-command-card search-command-card-featured"
                  onClick={() => {
                    onNavigate?.(command);
                    onClose?.(false);
                  }}
                >
                  <span className="search-command-icon" aria-hidden="true">
                    {command.icon}
                  </span>
                  <span className="search-command-label">{command.title}</span>
                  <span className="search-command-copy">{command.subtitle}</span>
                </button>
              ))}
            </div>
            <div className="search-section-heading">
              <span>All commands</span>
              <span>{remainingCommands.length} more</span>
            </div>
            <div className="search-command-grid">
              {remainingCommands.map((command) => (
                <button
                  key={command.title}
                  type="button"
                  className="search-command-card"
                  onClick={() => {
                    onNavigate?.(command);
                    onClose?.(false);
                  }}
                >
                  <span className="search-command-icon" aria-hidden="true">
                    {command.icon}
                  </span>
                  <span className="search-command-label">{command.title}</span>
                  <span className="search-command-copy">{command.subtitle}</span>
                </button>
              ))}
            </div>
          </>
        )}
        {loading && (
          <div
            style={{ padding: 12, textAlign: 'center', color: 'var(--text-secondary)' }}
            role="status"
            aria-label="Searching"
          >
            Searching…
          </div>
        )}
        {!loading && results.length === 0 && query.length >= 2 && (
          <div style={{ padding: 16, textAlign: 'center', color: 'var(--text-secondary)' }}>
            No results found
          </div>
        )}
        {results.length > 0 && (
          <div className="search-palette-results" id="search-results" role="listbox">
            <div className="search-section-heading search-results-heading">
              <span>Top matches</span>
              <span>{results.length} shown</span>
            </div>
            {results.map((r, i) => (
              <div
                key={i}
                id={`search-result-${i}`}
                role="option"
                aria-selected={i === selectedIdx}
                className={`search-palette-item${i === selectedIdx ? ' selected' : ''}`}
                onClick={() => {
                  onNavigate?.(r);
                  onClose?.(false);
                }}
                onMouseEnter={() => setSelectedIdx(i)}
              >
                <span className="search-result-icon" aria-hidden="true">
                  {r.icon}
                </span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 500, fontSize: 13 }}>{r.title}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    {r.category}
                    {r.subtitle ? ` · ${r.subtitle}` : ''}
                  </div>
                </div>
                <span className={`search-result-kind search-result-kind-${r.kind}`}>
                  {r.kind === 'action' ? 'Action' : 'Entity'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function SearchPalette({ open, onClose, onNavigate, currentPath = '' }) {
  const [saved, setSaved] = useState(loadSaved);
  const { role } = useRole();

  useEffect(() => {
    const handler = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === 'k') {
        event.preventDefault();
        onClose?.(!open);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <SearchPaletteDialog
      onClose={onClose}
      onNavigate={onNavigate}
      saved={saved}
      setSaved={setSaved}
      currentPath={currentPath}
      role={role}
    />
  );
}

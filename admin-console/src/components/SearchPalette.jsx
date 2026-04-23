import { useState, useEffect, useRef, useCallback } from 'react';
import * as api from '../api.js';

const SAVED_KEY = 'wardex_saved_searches';
function loadSaved() {
  try {
    return JSON.parse(localStorage.getItem(SAVED_KEY) || '[]');
  } catch {
    return [];
  }
}
function persistSaved(list) {
  localStorage.setItem(SAVED_KEY, JSON.stringify(list));
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

const COMMANDS = [
  {
    title: 'Create Incident',
    subtitle: 'Open the SOC workbench with a create flow',
    icon: 'CMD',
    action: 'create-incident',
    path: '/soc?intent=create-incident',
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Open Quarantine',
    subtitle: 'Jump to active response and quarantine work',
    icon: 'CMD',
    action: 'open-quarantine',
    path: '/soc?focus=quarantine',
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Run Hunt',
    subtitle: 'Open threat detection and start a hunt',
    icon: 'CMD',
    action: 'run-hunt',
    path: '/detection?intent=run-hunt',
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Ask Assistant',
    subtitle: 'Open the analyst assistant with case-aware context',
    icon: 'CMD',
    action: 'open-assistant',
    path: '/assistant',
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Review Offline Agents',
    subtitle: 'Open fleet with the offline status view',
    icon: 'CMD',
    path: '/fleet?status=offline',
    category: 'Command',
    kind: 'action',
  },
];

function SearchPaletteDialog({ onClose, onNavigate, saved, setSaved }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef(null);
  const searchGenRef = useRef(0);

  useEffect(() => {
    const focusTimer = window.setTimeout(() => inputRef.current?.focus(), 50);
    return () => window.clearTimeout(focusTimer);
  }, []);

  const doSearch = useCallback(async (q) => {
    if (!q || q.length < 2) {
      setResults([]);
      return;
    }
    setLoading(true);
    const gen = ++searchGenRef.current;
    const ql = q.toLowerCase();
    const allResults = COMMANDS.filter((command) =>
      `${command.title} ${command.subtitle}`.toLowerCase().includes(ql),
    );

    await Promise.allSettled(
      CATEGORIES.map(async (cat) => {
        try {
          const data = await cat.search();
          const items = Array.isArray(data)
            ? data
            : data?.items || data?.alerts || data?.agents || data?.incidents || data?.rules || [];
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
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => doSearch(query), 300);
    return () => clearTimeout(timer);
  }, [query, doSearch]);

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
          <div className="search-command-grid">
            {COMMANDS.map((command) => (
              <button
                key={command.title}
                type="button"
                className="search-command-card"
                onClick={() => {
                  onNavigate?.(command);
                  onClose?.(false);
                }}
              >
                <span className="search-command-label">{command.title}</span>
                <span className="search-command-copy">{command.subtitle}</span>
              </button>
            ))}
          </div>
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

export default function SearchPalette({ open, onClose, onNavigate }) {
  const [saved, setSaved] = useState(loadSaved);

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
    />
  );
}

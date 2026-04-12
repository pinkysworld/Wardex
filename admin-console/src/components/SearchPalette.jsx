import { useState, useEffect, useRef, useCallback } from 'react';
import * as api from '../api.js';

const SAVED_KEY = 'wardex_saved_searches';
function loadSaved() { try { return JSON.parse(localStorage.getItem(SAVED_KEY) || '[]'); } catch { return []; } }
function persistSaved(list) { localStorage.setItem(SAVED_KEY, JSON.stringify(list)); }

const CATEGORIES = [
  { key: 'alerts', label: 'Alerts', icon: '🔔', search: api.alerts },
  { key: 'agents', label: 'Agents', icon: '🖥', search: api.agents },
  { key: 'rules', label: 'Detection Rules', icon: '📜', search: api.detectionRules },
  { key: 'quarantine', label: 'Quarantine', icon: '🔒', search: api.quarantineList },
  { key: 'feeds', label: 'Feed Sources', icon: '📡', search: api.feeds },
];

export default function SearchPalette({ open, onClose, onNavigate }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [saved, setSaved] = useState(loadSaved);
  const inputRef = useRef(null);

  useEffect(() => {
    if (open) {
      setQuery('');
      setResults([]);
      setSelectedIdx(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  // Keyboard shortcut: Cmd/Ctrl+K
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        onClose ? onClose(!open) : null;
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onClose]);

  const searchGenRef = useRef(0);

  const doSearch = useCallback(async (q) => {
    if (!q || q.length < 2) { setResults([]); return; }
    setLoading(true);
    const gen = ++searchGenRef.current;
    const ql = q.toLowerCase();
    const allResults = [];

    await Promise.allSettled(
      CATEGORIES.map(async (cat) => {
        try {
          const data = await cat.search();
          const items = Array.isArray(data) ? data : data?.items || data?.alerts || data?.agents || [];
          items.forEach(item => {
            const text = JSON.stringify(item).toLowerCase();
            if (text.includes(ql)) {
              allResults.push({
                category: cat.label,
                icon: cat.icon,
                title: item.name || item.hostname || item.id || item.alert_id || item.message || 'Unknown',
                subtitle: item.severity || item.status || item.protocol || '',
                raw: item,
              });
            }
          });
        } catch { /* ignore category errors */ }
      })
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
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelectedIdx(i => Math.min(i + 1, results.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSelectedIdx(i => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter' && results[selectedIdx]) {
      onNavigate?.(results[selectedIdx]);
      onClose?.(false);
    }
    else if (e.key === 'Escape') onClose?.(false);
  };

  if (!open) return null;

  return (
    <div className="search-palette-overlay" onClick={() => onClose?.(false)}>
      <div className="search-palette" onClick={e => e.stopPropagation()}>
        <div className="search-palette-input-wrap">
          <span style={{ fontSize: 18, marginRight: 8 }}>🔍</span>
          <input
            ref={inputRef}
            type="text"
            placeholder="Search alerts, agents, rules, quarantine…"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="search-palette-input"
          />
          <kbd style={{ fontSize: 11, padding: '2px 6px', borderRadius: 4, background: 'var(--bg)', border: '1px solid var(--border)' }}>ESC</kbd>
          {query.length >= 2 && !saved.includes(query) && (
            <button style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4, background: 'var(--primary)', color: '#fff', border: 'none', cursor: 'pointer', marginLeft: 4, whiteSpace: 'nowrap' }}
              onClick={() => { const next = [query, ...saved].slice(0, 20); setSaved(next); persistSaved(next); }}>Save</button>
          )}
        </div>
        {/* Saved searches shown when query is empty */}
        {query.length < 2 && saved.length > 0 && (
          <div style={{ padding: '8px 12px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6 }}>Saved searches</div>
            {saved.map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', fontSize: 13 }}>
                <span style={{ cursor: 'pointer', flex: 1 }} onClick={() => setQuery(s)}>🔖 {s}</span>
                <button style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', fontSize: 11 }}
                  onClick={() => { const next = saved.filter((_, j) => j !== i); setSaved(next); persistSaved(next); }}>✕</button>
              </div>
            ))}
          </div>
        )}
        {loading && <div style={{ padding: 12, textAlign: 'center', color: 'var(--text-secondary)' }}>Searching…</div>}
        {!loading && results.length === 0 && query.length >= 2 && (
          <div style={{ padding: 16, textAlign: 'center', color: 'var(--text-secondary)' }}>No results found</div>
        )}
        {results.length > 0 && (
          <div className="search-palette-results">
            {results.map((r, i) => (
              <div
                key={i}
                className={`search-palette-item${i === selectedIdx ? ' selected' : ''}`}
                onClick={() => { onNavigate?.(r); onClose?.(false); }}
                onMouseEnter={() => setSelectedIdx(i)}
              >
                <span style={{ marginRight: 8 }}>{r.icon}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 500, fontSize: 13 }}>{r.title}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{r.category}{r.subtitle ? ` · ${r.subtitle}` : ''}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

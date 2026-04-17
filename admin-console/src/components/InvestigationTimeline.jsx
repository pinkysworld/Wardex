import { useState, useMemo, useCallback } from 'react';
import { useApi, useInterval } from '../hooks.jsx';
import * as api from '../api.js';

/**
 * InvestigationTimeline — visual timeline of alert/incident events
 * for forensic investigation. Shows events chronologically with
 * severity indicators and expandable detail panels.
 */

function TimelineEvent({ event, expanded, onToggle }) {
  const sevClass = `sev-${(event.severity || 'info').toLowerCase()}`;
  const time = event.timestamp || event.time || '';
  const parsed = time ? new Date(time) : null;
  const displayTime = parsed && !isNaN(parsed) ? parsed.toLocaleString() : '—';

  return (
    <div className={`timeline-event ${expanded ? 'expanded' : ''}`} role="listitem">
      <div className="timeline-marker">
        <span className={`timeline-dot ${sevClass}`} aria-label={event.severity || 'info'} />
        <span className="timeline-line" aria-hidden="true" />
      </div>
      <div className="timeline-body">
        <button
          className="timeline-header"
          onClick={onToggle}
          aria-expanded={expanded}
          aria-label={`${event.type || 'Event'} at ${displayTime}`}
        >
          <span className="timeline-time">{displayTime}</span>
          <span className={`timeline-sev ${sevClass}`}>{event.severity || 'info'}</span>
          <span className="timeline-type">{event.type || event.category || 'Event'}</span>
          <span className="timeline-summary">{event.message || event.summary || event.description || '—'}</span>
          <span className="timeline-chevron">{expanded ? '▾' : '▸'}</span>
        </button>
        {expanded && (
          <div className="timeline-detail">
            {event.source && <div><strong>Source:</strong> {event.source}</div>}
            {event.host && <div><strong>Host:</strong> {event.host}</div>}
            {event.user && <div><strong>User:</strong> {event.user}</div>}
            {event.pid && <div><strong>PID:</strong> {event.pid}</div>}
            {event.process_name && <div><strong>Process:</strong> {event.process_name}</div>}
            {event.action && <div><strong>Action:</strong> {event.action}</div>}
            {event.mitre_ids && <div><strong>MITRE:</strong> {Array.isArray(event.mitre_ids) ? event.mitre_ids.join(', ') : event.mitre_ids}</div>}
            {event.risk_score != null && <div><strong>Risk Score:</strong> {Number(event.risk_score).toFixed(2)}</div>}
            {event.details && (
              <details style={{ marginTop: 8 }}>
                <summary style={{ cursor: 'pointer', fontSize: 12, color: 'var(--text-secondary)' }}>Raw Details</summary>
                <pre style={{ fontSize: 11, maxHeight: 200, overflow: 'auto', padding: 8, background: 'var(--code-bg)', borderRadius: 4, marginTop: 4 }}>
                  {typeof event.details === 'string' ? event.details : JSON.stringify(event.details, null, 2)}
                </pre>
              </details>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function InvestigationTimeline() {
  const { data: alertData, reload: rAlerts } = useApi(api.alerts);
  const { data: tlHost } = useApi(api.timelineHost);
  const [expandedId, setExpandedId] = useState(null);
  const [sevFilter, setSevFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [useRegex, setUseRegex] = useState(false);
  const [timeRange, setTimeRange] = useState('24h');
  const [groupBy, setGroupBy] = useState('none');
  const [visibleCount, setVisibleCount] = useState(200);

  useInterval(rAlerts, 30000);

  const zoomIn = useCallback(() => setVisibleCount(c => Math.max(25, Math.floor(c / 2))), []);
  const zoomOut = useCallback(() => setVisibleCount(c => Math.min(2000, c * 2)), []);
  const resetZoom = useCallback(() => setVisibleCount(200), []);

  // Combine alert and timeline data into unified events
  const events = useMemo(() => {
    const items = [];

    // Add alerts
    const alertList = Array.isArray(alertData) ? alertData : alertData?.alerts || [];
    alertList.forEach((a, i) => {
      items.push({
        id: a.id || a.alert_id || `alert-${i}`,
        type: 'Alert',
        category: a.category || a.type || a.alert_origin || 'Signal',
        severity: (a.severity || a.level || a.risk_level || 'medium').toLowerCase(),
        timestamp: a.timestamp || a.time,
        message: a.message || a.description || a.summary || a.action || '',
        source: a.alert_origin || a.source,
        host: a.hostname,
        user: a.user,
        pid: a.pid,
        process_name: a.process_name,
        action: a.action,
        mitre_ids: a.mitre_attack_ids || a.mitre_ids,
        risk_score: a.score || a.risk_score,
        details: a,
      });
    });

    // Add timeline events if available
    const tlEvents = Array.isArray(tlHost) ? tlHost : tlHost?.events || [];
    tlEvents.forEach((e, i) => {
      items.push({
        id: e.id || `tl-${i}`,
        type: e.event_type || 'Timeline',
        category: e.category || 'System',
        severity: (e.severity || 'info').toLowerCase(),
        timestamp: e.timestamp || e.time,
        message: e.description || e.message || e.summary || '',
        source: e.source,
        host: e.hostname,
        user: e.user,
        pid: e.pid,
        process_name: e.process_name,
        action: e.action,
        details: e,
      });
    });

    // Sort by timestamp descending
    items.sort((a, b) => {
      const ta = new Date(a.timestamp).getTime() || 0;
      const tb = new Date(b.timestamp).getTime() || 0;
      return tb - ta;
    });

    return items;
  }, [alertData, tlHost]);

  // Extract unique types for filter dropdown
  const eventTypes = useMemo(() => {
    const types = new Set(events.map(e => e.type));
    return ['all', ...Array.from(types).sort()];
  }, [events]);

  // Apply filters
  const filtered = useMemo(() => {
    const now = Date.now();
    const rangeMs = {
      '1h': 3600_000,
      '6h': 6 * 3600_000,
      '24h': 24 * 3600_000,
      '7d': 7 * 24 * 3600_000,
      'all': Infinity,
    }[timeRange] || 24 * 3600_000;

    return events.filter(e => {
      if (sevFilter !== 'all' && e.severity !== sevFilter) return false;
      if (typeFilter !== 'all' && e.type !== typeFilter) return false;
      if (rangeMs !== Infinity) {
        const t = new Date(e.timestamp || 0).getTime();
        if (now - t > rangeMs) return false;
      }
      if (search) {
        const searchable = `${e.message} ${e.type} ${e.host || ''} ${e.user || ''} ${e.process_name || ''}`;
        if (useRegex) {
          try {
            if (search.length > 200) return false;
            // Block patterns with nested quantifiers that cause catastrophic backtracking
            if (/\([^)]*[+*][^)]*\)[+*?{]/.test(search)) return false;
            if (!new RegExp(search, 'i').test(searchable)) return false;
          } catch { return false; }
        } else {
          if (!searchable.toLowerCase().includes(search.toLowerCase())) return false;
        }
      }
      return true;
    });
  }, [events, sevFilter, typeFilter, timeRange, search, useRegex]);

  const sevCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    filtered.forEach(e => { counts[e.severity] = (counts[e.severity] || 0) + 1; });
    return counts;
  }, [filtered]);

  // Group events
  const grouped = useMemo(() => {
    if (groupBy === 'none') return null;
    const groups = {};
    filtered.forEach(e => {
      const key = groupBy === 'host' ? (e.host || 'Unknown') :
                  groupBy === 'user' ? (e.user || 'Unknown') :
                  groupBy === 'severity' ? (e.severity || 'info') :
                  groupBy === 'process' ? (e.process_name || 'Unknown') : 'All';
      (groups[key] ||= []).push(e);
    });
    return groups;
  }, [filtered, groupBy]);

  return (
    <div>
      {/* Filter bar */}
      <div className="timeline-filters" role="toolbar" aria-label="Timeline filters">
        <label>
          <span className="sr-only">Search events</span>
          <input
            type="search"
            placeholder={useRegex ? 'Regex search…' : 'Search events…'}
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="input"
            aria-label="Search timeline events"
            style={{ minWidth: 180 }}
          />
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
          <input type="checkbox" checked={useRegex} onChange={e => setUseRegex(e.target.checked)} /> Regex
        </label>

        <label>
          <span className="sr-only">Severity filter</span>
          <select value={sevFilter} onChange={e => setSevFilter(e.target.value)} className="input" aria-label="Severity filter">
            <option value="all">All Severities</option>
            <option value="critical">Critical ({sevCounts.critical})</option>
            <option value="high">High ({sevCounts.high})</option>
            <option value="medium">Medium ({sevCounts.medium})</option>
            <option value="low">Low ({sevCounts.low})</option>
            <option value="info">Info ({sevCounts.info})</option>
          </select>
        </label>

        <label>
          <span className="sr-only">Event type filter</span>
          <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className="input" aria-label="Event type filter">
            {eventTypes.map(t => <option key={t} value={t}>{t === 'all' ? 'All Types' : t}</option>)}
          </select>
        </label>

        <label>
          <span className="sr-only">Time range</span>
          <select value={timeRange} onChange={e => setTimeRange(e.target.value)} className="input" aria-label="Time range">
            <option value="1h">Last 1 hour</option>
            <option value="6h">Last 6 hours</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="all">All time</option>
          </select>
        </label>

        <label>
          <span className="sr-only">Group by</span>
          <select value={groupBy} onChange={e => setGroupBy(e.target.value)} className="input" aria-label="Group by">
            <option value="none">No Grouping</option>
            <option value="host">Host</option>
            <option value="user">User</option>
            <option value="severity">Severity</option>
            <option value="process">Process</option>
          </select>
        </label>

        <div className="btn-group" style={{ marginLeft: 4 }}>
          <button className="btn btn-sm" onClick={zoomIn} title="Zoom in (fewer events)">🔍+</button>
          <button className="btn btn-sm" onClick={zoomOut} title="Zoom out (more events)">🔍−</button>
          <button className="btn btn-sm" onClick={resetZoom} title="Reset zoom">↺</button>
        </div>

        <span className="timeline-count">{filtered.length} event{filtered.length !== 1 ? 's' : ''} (showing {Math.min(visibleCount, filtered.length)})</span>
      </div>

      {/* Timeline */}
      <div className="timeline" role="list" aria-label="Investigation timeline">
        {filtered.length === 0 ? (
          <div className="empty">No events match filters</div>
        ) : grouped ? (
          Object.entries(grouped).map(([key, items]) => (
            <details key={key} open>
              <summary style={{ cursor: 'pointer', fontWeight: 600, padding: '8px 0', fontSize: 13, borderBottom: '1px solid var(--border)' }}>
                {groupBy}: {key} ({items.length})
              </summary>
              {items.slice(0, visibleCount).map(event => (
                <TimelineEvent
                  key={event.id}
                  event={event}
                  expanded={expandedId === event.id}
                  onToggle={() => setExpandedId(expandedId === event.id ? null : event.id)}
                />
              ))}
            </details>
          ))
        ) : (
          filtered.slice(0, visibleCount).map(event => (
            <TimelineEvent
              key={event.id}
              event={event}
              expanded={expandedId === event.id}
              onToggle={() => setExpandedId(expandedId === event.id ? null : event.id)}
            />
          ))
        )}
        {filtered.length > visibleCount && (
          <div className="empty" style={{ padding: 8 }}>
            Showing {visibleCount} of {filtered.length} events
            <button className="btn btn-sm" style={{ marginLeft: 8 }} onClick={() => setVisibleCount(c => c + 200)}>Load more</button>
          </div>
        )}
      </div>
    </div>
  );
}

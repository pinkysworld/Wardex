import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useApiGroup, useInterval, useToast, useWebSocket } from '../hooks.jsx';
import * as api from '../api.js';
import AlertDrawer from './AlertDrawer.jsx';
import ProcessDrawer from './ProcessDrawer.jsx';
import { JsonDetails, SummaryGrid } from './operator.jsx';
import { downloadCsv, downloadData, formatDateTime, formatRelativeTime } from './operatorUtils.js';

const ALERT_VIEWS = [
  {
    id: 'critical-linux',
    label: 'Critical Linux alerts',
    severity: 'critical',
    host: 'linux',
    source: 'all',
    query: '',
  },
  {
    id: 'unassigned',
    label: 'Untriaged alerts',
    severity: 'all',
    host: 'all',
    source: 'all',
    query: 'acknowledged',
  },
  { id: 'all', label: 'All alerts', severity: 'all', host: 'all', source: 'all', query: '' },
];

const MONITOR_VIEW_META = {
  stream: {
    title: 'Live Alert Stream',
    description:
      'Track current queue pressure, transport recovery, and live event flow without leaving the active alert scope.',
  },
  grouped: {
    title: 'Grouped Alert Patterns',
    description:
      'Review recurring fingerprints, score concentration, and first-to-last seen windows before promoting or suppressing rules.',
  },
  analysis: {
    title: 'Alert Analysis',
    description:
      'Run an operator-facing pattern summary and isolation guidance across the current queue instead of comparing raw rows by hand.',
  },
  processes: {
    title: 'Running Processes',
    description:
      'Inspect live process inventory and suspicious findings directly inside the monitor so empty collectors and real process risk look distinct.',
  },
};

function alertIdFor(alert, index) {
  return String(alert.id ?? alert.alert_id ?? alert._index ?? `${alert.timestamp}-${index}`);
}

function normalizeAlert(alert, fallbackIndex) {
  const reasons = Array.isArray(alert?.reasons) ? alert.reasons.filter(Boolean) : [];
  const severity = String(alert?.severity || alert?.level || 'unknown').toLowerCase();
  const narrativeHeadline = alert?.narrative?.headline || alert?.narrative?.summary || '';
  const category = alert?.category || alert?.type || reasons[0] || 'anomaly';
  const message =
    alert?.message ||
    alert?.description ||
    narrativeHeadline ||
    reasons[0] ||
    `${String(alert?.level || 'Anomaly')} detected on ${alert?.hostname || 'host'}`;

  return {
    ...alert,
    id: alert?.id ?? alert?.alert_id ?? alert?._index ?? fallbackIndex,
    alert_id: alert?.alert_id ?? alert?.id ?? alert?._index ?? fallbackIndex,
    severity,
    source: alert?.source || (alert?.platform === 'sample' ? 'sample' : 'local-monitor'),
    category,
    type: alert?.type || 'anomaly',
    message,
    description: alert?.description || narrativeHeadline || reasons.join('; '),
    time: alert?.time || alert?.timestamp,
  };
}

function alertDedupKey(alert, index) {
  const primaryId = alert.id ?? alert.alert_id ?? alert._index;
  if (primaryId != null) return String(primaryId);
  return `${alert.timestamp || alert.time || 'unknown'}:${alert.hostname || 'host'}:${alert.message || alert.description || index}`;
}

function normalizeLiveEvent(event, index) {
  const eventType = String(event?.type || event?.event_type || 'event').toLowerCase();
  const data = event?.data || {};
  const timestamp = event?.timestamp || data?.timestamp || data?.time || null;

  if (eventType === 'alert') {
    const alert = normalizeAlert(data, index);
    return {
      id: `${eventType}-${alertDedupKey(alert, index)}`,
      eventType,
      timestamp: timestamp || alert.timestamp || alert.time || null,
      summary: alert.message || alert.description || 'Alert event',
      subject: alert.hostname || alert.origin_agent_id || alert.source || 'local monitor',
      severity: alert.severity || 'unknown',
    };
  }

  if (eventType === 'incident') {
    return {
      id: `${eventType}-${data.id || index}`,
      eventType,
      timestamp,
      summary: data.title || 'Incident update',
      subject: data.id || data.severity || 'incident',
      severity: data.severity || 'info',
    };
  }

  if (eventType === 'agent') {
    return {
      id: `${eventType}-${data.agent_id || index}`,
      eventType,
      timestamp,
      summary: data.action ? `Agent ${data.action}` : 'Agent activity',
      subject: data.agent_id || data.hostname || 'agent',
      severity: 'info',
    };
  }

  if (eventType === 'heartbeat') {
    return {
      id: `${eventType}-${index}`,
      eventType,
      timestamp,
      summary: 'Transport heartbeat',
      subject: 'stream',
      severity: 'info',
    };
  }

  return {
    id: `${eventType}-${index}`,
    eventType,
    timestamp,
    summary: data.message || data.title || data.action || `${eventType.replace(/_/g, ' ')} event`,
    subject: data.hostname || data.device_id || data.agent_id || data.id || 'stream',
    severity: data.severity || 'info',
  };
}

function TriageEmptyState({ title, description, actionLabel, onAction }) {
  return (
    <div className="triage-empty">
      <div className="triage-empty-title">{title}</div>
      <div className="triage-empty-copy">{description}</div>
      {actionLabel && onAction && (
        <button className="btn btn-sm" onClick={onAction}>
          {actionLabel}
        </button>
      )}
    </div>
  );
}

function MobileAlertCard({ alert, index, active, onPreview, onOpen, onMarkFP }) {
  const alertId = alertIdFor(alert, index);
  return (
    <article
      className={`mobile-stack-card ${active ? 'active' : ''}`}
      role="button"
      tabIndex={0}
      onClick={() => onPreview(alertId)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onPreview(alertId);
        }
      }}
    >
      <div className="mobile-card-header">
        <div>
          <div className="mobile-card-title">{alert.message || alert.description || 'Alert'}</div>
          <div className="row-secondary">
            {alert.hostname || alert.origin_agent_id || 'No host context'}
          </div>
        </div>
        <span
          className={`badge ${(alert.severity || '').toLowerCase() === 'critical' ? 'badge-err' : (alert.severity || '').toLowerCase() === 'low' ? 'badge-info' : 'badge-warn'}`}
        >
          {alert.severity || 'unknown'}
        </span>
      </div>
      <div className="mobile-card-meta">
        <span>{alert.source || 'unknown source'}</span>
        <span>{alert.category || alert.type || 'uncategorized'}</span>
        <span>{formatRelativeTime(alert.timestamp || alert.time)}</span>
      </div>
      <div className="mobile-card-actions">
        <button
          className="btn btn-sm btn-primary"
          onClick={(event) => {
            event.stopPropagation();
            onOpen(alertId);
          }}
        >
          Open Drawer
        </button>
        <button
          className="btn btn-sm"
          onClick={(event) => {
            event.stopPropagation();
            onMarkFP(alert);
          }}
        >
          Mark FP
        </button>
      </div>
    </article>
  );
}

export default function LiveMonitor() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const {
    events: streamEvents,
    connected: streamConnected,
    transport: streamTransport,
    status: streamStatus,
    subscriberId: pollingSubscriberId,
    recoveryAttempts,
    lastEventAt,
    lastConnectAt,
    lastDisconnectAt,
    lastError,
    clearEvents: clearStreamEvents,
    reconnect: reconnectStream,
  } = useWebSocket(2000);
  const { data: alertData, loading, reload } = useApi(api.alerts);
  const { data: alertSummaryData, reload: reloadAlertSummary } = useApiGroup({
    countData: api.alertsCount,
    grouped: api.alertsGrouped,
  });
  const { countData, grouped } = alertSummaryData;
  const { data: wsStats, reload: reloadWsStats } = useApi(api.wsStats);
  const { data: hp } = useApi(api.health);
  const { data: processData, reload: reloadProcessData } = useApiGroup({
    procData: api.processesLive,
    procAnalysis: api.processesAnalysis,
  });
  const { procData, procAnalysis } = processData;
  const { data: fpStats, reload: reloadFP } = useApi(api.fpFeedbackStats);
  const [selectedId, setSelectedId] = useState(() => searchParams.get('alert'));
  const [hoveredId, setHoveredId] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [tab, setTab] = useState(() => searchParams.get('monitorTab') || 'stream');
  const [procSort, setProcSort] = useState('cpu');
  const [procFilter, setProcFilter] = useState('');
  const [sevFilter, setSevFilter] = useState(() => searchParams.get('sev') || 'all');
  const [sourceFilter, setSourceFilter] = useState(() => searchParams.get('source') || 'all');
  const [hostFilter, setHostFilter] = useState(() => searchParams.get('host') || 'all');
  const [searchFilter, setSearchFilter] = useState(() => searchParams.get('q') || '');
  const [liveEventTypeFilter, setLiveEventTypeFilter] = useState(
    () => searchParams.get('eventType') || 'all',
  );
  const [liveEventQuery, setLiveEventQuery] = useState(() => searchParams.get('eventQuery') || '');
  const [selectedAlerts, setSelectedAlerts] = useState(new Set());
  const [bulkAction, setBulkAction] = useState('');
  const [selectedProcess, setSelectedProcess] = useState(null);

  const updateMonitorParams = useCallback(
    (updates) => {
      const next = new URLSearchParams(searchParams);
      Object.entries(updates).forEach(([key, value]) => {
        if (!value || value === 'all') next.delete(key);
        else next.set(key, value);
      });
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  useEffect(() => {
    const alertParam = searchParams.get('alert');
    setSelectedId((current) => (current === alertParam ? current : alertParam));
  }, [searchParams]);

  useEffect(() => {
    const currentParam = searchParams.get('alert');
    const nextParam = selectedId == null ? null : String(selectedId);
    if ((currentParam ?? null) === nextParam) return;
    updateMonitorParams({ alert: nextParam });
  }, [searchParams, selectedId, updateMonitorParams]);

  const reloadAll = () => {
    reload();
    reloadAlertSummary();
  };
  useInterval(reloadAll, 10000);
  useInterval(
    () => {
      if (tab === 'processes') {
        reloadProcessData();
      }
    },
    tab === 'processes' ? 10000 : null,
  );

  const liveAlertEvents = useMemo(
    () => streamEvents.filter((event) => (event?.type || event?.event_type) === 'alert'),
    [streamEvents],
  );
  const liveEvents = useMemo(
    () => streamEvents.map((event, index) => normalizeLiveEvent(event, index)),
    [streamEvents],
  );
  const streamAlertList = useMemo(
    () => liveAlertEvents.map((event, index) => normalizeAlert(event.data || {}, index)),
    [liveAlertEvents],
  );
  const alertList = useMemo(() => {
    const baseAlerts = (Array.isArray(alertData) ? alertData : alertData?.alerts || []).map(
      (alert, index) => normalizeAlert(alert, index),
    );
    if (streamAlertList.length === 0) return baseAlerts;
    const merged = [...streamAlertList, ...baseAlerts];
    const seen = new Set();
    return merged.filter((alert, index) => {
      const key = alertDedupKey(alert, index);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [alertData, streamAlertList]);

  const latestStreamAlertKey =
    streamAlertList.length > 0 ? alertDedupKey(streamAlertList[0], 0) : null;

  useEffect(() => {
    if (!latestStreamAlertKey) return;
    reloadAlertSummary();
    reloadWsStats();
  }, [latestStreamAlertKey, reloadAlertSummary, reloadWsStats]);

  useInterval(
    () => {
      if (tab === 'stream') reloadWsStats();
    },
    tab === 'stream' ? 10000 : null,
  );

  const liveEventTypeCounts = useMemo(
    () =>
      liveEvents.reduce((counts, event) => {
        counts[event.eventType] = (counts[event.eventType] || 0) + 1;
        return counts;
      }, {}),
    [liveEvents],
  );
  const liveEventTypeOptions = useMemo(
    () => ['all', ...Object.keys(liveEventTypeCounts)],
    [liveEventTypeCounts],
  );
  const filteredLiveEvents = useMemo(() => {
    const query = liveEventQuery.trim().toLowerCase();
    return liveEvents.filter((event) => {
      const typeMatch = liveEventTypeFilter === 'all' || event.eventType === liveEventTypeFilter;
      const queryMatch =
        !query ||
        `${event.summary} ${event.subject} ${event.eventType}`.toLowerCase().includes(query);
      return typeMatch && queryMatch;
    });
  }, [liveEventQuery, liveEventTypeFilter, liveEvents]);

  const streamStatusLabel =
    streamStatus === 'connected'
      ? 'Connected'
      : streamStatus === 'reconnecting'
        ? 'Recovering'
        : 'Connecting';
  const streamTransportLabel =
    streamTransport === 'websocket'
      ? 'WebSocket'
      : streamTransport === 'polling'
        ? 'Polling'
        : 'Negotiating';
  const streamStatusBadgeClass = streamConnected
    ? 'badge-ok'
    : streamStatus === 'reconnecting'
      ? 'badge-warn'
      : 'badge-info';
  const wsConnectionCount = Array.isArray(wsStats?.connections) ? wsStats.connections.length : 0;

  const sourceOptions = ['all', ...new Set(alertList.map((alert) => alert.source).filter(Boolean))];
  const hostOptions = ['all', ...new Set(alertList.map((alert) => alert.hostname).filter(Boolean))];

  const filteredAlerts = useMemo(() => {
    return alertList.filter((alert) => {
      const matchesSeverity =
        sevFilter === 'all' || (alert.severity || '').toLowerCase() === sevFilter;
      const matchesSource = sourceFilter === 'all' || alert.source === sourceFilter;
      const matchesHost =
        hostFilter === 'all' ||
        alert.hostname === hostFilter ||
        String(alert.hostname || '')
          .toLowerCase()
          .includes(hostFilter.toLowerCase());
      const matchesQuery =
        !searchFilter || JSON.stringify(alert).toLowerCase().includes(searchFilter.toLowerCase());
      return matchesSeverity && matchesSource && matchesHost && matchesQuery;
    });
  }, [alertList, hostFilter, searchFilter, sevFilter, sourceFilter]);

  // Bulk selection helpers
  const toggleSelect = (aid) => {
    setSelectedAlerts((prev) => {
      const next = new Set(prev);
      next.has(aid) ? next.delete(aid) : next.add(aid);
      return next;
    });
  };
  const toggleSelectAll = () => {
    if (selectedAlerts.size === filteredAlerts.length) {
      setSelectedAlerts(new Set());
    } else {
      setSelectedAlerts(new Set(filteredAlerts.map((alert, index) => alertIdFor(alert, index))));
    }
  };

  // FP feedback handler
  const markFP = async (alert) => {
    const pattern = (alert.reasons || [alert.category || alert.type || 'unknown']).join(', ');
    try {
      await api.fpFeedback({
        alert_id: alert.id || alert.alert_id,
        pattern,
        is_false_positive: true,
      });
      toast(`Marked as FP: ${pattern}`, 'success');
      reloadFP();
    } catch {
      toast('FP feedback failed', 'error');
    }
  };

  // Bulk actions
  const executeBulk = async () => {
    if (!selectedAlerts.size) {
      toast('No alerts selected', 'error');
      return;
    }
    const ids = [...selectedAlerts];
    if (bulkAction === 'fp') {
      for (const aid of ids) {
        const alert = filteredAlerts.find(
          (candidate, index) => alertIdFor(candidate, index) === aid,
        );
        if (alert) await markFP(alert);
      }
      toast(`Marked ${ids.length} alerts as false positive`, 'success');
    } else if (bulkAction === 'triage') {
      try {
        await api.bulkTriage({ event_ids: ids, verdict: 'acknowledged' });
        toast(`Triaged ${ids.length} alerts`, 'success');
      } catch {
        toast('Bulk triage failed', 'error');
      }
    } else if (bulkAction === 'incident') {
      try {
        await api.createIncident({
          title: `Bulk incident (${ids.length} alerts)`,
          severity: 'medium',
          event_ids: ids,
        });
        toast('Incident created from selected alerts', 'success');
      } catch {
        toast('Incident creation failed', 'error');
      }
    }
    setSelectedAlerts(new Set());
    setBulkAction('');
    reload();
  };

  // Process list with sorting and filtering
  const procList = (() => {
    let list = procData?.processes || [];
    if (procFilter) {
      const f = procFilter.toLowerCase();
      list = list.filter(
        (p) =>
          p.name?.toLowerCase().includes(f) ||
          p.user?.toLowerCase().includes(f) ||
          String(p.pid).includes(f),
      );
    }
    if (procSort === 'cpu')
      list = [...list].sort((a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0));
    else if (procSort === 'mem')
      list = [...list].sort((a, b) => (b.mem_percent || 0) - (a.mem_percent || 0));
    else if (procSort === 'name')
      list = [...list].sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    else if (procSort === 'pid') list = [...list].sort((a, b) => a.pid - b.pid);
    return list;
  })();
  const currentTabMeta = MONITOR_VIEW_META[tab] || MONITOR_VIEW_META.stream;
  const hasProcessSnapshot = procData?.count != null || procList.length > 0;

  const currentView = ALERT_VIEWS.find(
    (view) =>
      view.severity === sevFilter &&
      view.host === hostFilter &&
      view.source === sourceFilter &&
      view.query === searchFilter,
  );
  const hasAlertFilters =
    sevFilter !== 'all' || sourceFilter !== 'all' || hostFilter !== 'all' || Boolean(searchFilter);
  const criticalAlertCount = filteredAlerts.filter(
    (alert) => String(alert.severity || '').toLowerCase() === 'critical',
  ).length;

  const selectedAlert =
    selectedId == null
      ? null
      : filteredAlerts.find((alert, index) => alertIdFor(alert, index) === selectedId);
  const previewAlert = useMemo(() => {
    if (selectedAlert) return selectedAlert;
    if (!hoveredId) return null;
    return filteredAlerts.find((alert, index) => alertIdFor(alert, index) === hoveredId) || null;
  }, [filteredAlerts, hoveredId, selectedAlert]);
  const selectedAlertIndex =
    selectedId == null
      ? -1
      : filteredAlerts.findIndex((alert, index) => alertIdFor(alert, index) === selectedId);
  const previewAlertId = selectedAlert ? selectedId : hoveredId;
  const previewAlertIndex =
    previewAlertId == null
      ? -1
      : filteredAlerts.findIndex((alert, index) => alertIdFor(alert, index) === previewAlertId);

  const clearAlertFilters = () => {
    setSevFilter('all');
    setSourceFilter('all');
    setHostFilter('all');
    setSearchFilter('');
    setSelectedAlerts(new Set());
    updateMonitorParams({ sev: 'all', source: 'all', host: 'all', q: '' });
  };

  const moveAlert = (direction, pinned = selectedId != null) => {
    if (filteredAlerts.length === 0) return;
    const currentIndex = pinned ? selectedAlertIndex : previewAlertIndex;
    const rawIndex =
      currentIndex === -1
        ? direction > 0
          ? 0
          : filteredAlerts.length - 1
        : currentIndex + direction;
    const nextIndex = Math.max(0, Math.min(filteredAlerts.length - 1, rawIndex));
    const nextId = alertIdFor(filteredAlerts[nextIndex], nextIndex);
    setHoveredId(nextId);
    if (pinned) setSelectedId(nextId);
  };

  const exportAlerts = (format) => {
    if (format === 'csv') {
      const rows = [
        ['id', 'timestamp', 'severity', 'source', 'category', 'hostname', 'message'],
        ...filteredAlerts.map((alert, index) => [
          alert.id || alert.alert_id || index,
          alert.timestamp || alert.time || '',
          alert.severity || '',
          alert.source || '',
          alert.category || alert.type || '',
          alert.hostname || '',
          alert.message || alert.description || '',
        ]),
      ];
      downloadCsv(rows, 'wardex-alert-stream.csv');
      return;
    }
    downloadData(filteredAlerts, 'wardex-alert-stream.json');
  };

  const exportProcesses = (format) => {
    if (format === 'csv') {
      const rows = [
        ['pid', 'ppid', 'name', 'user', 'group', 'cpu_percent', 'mem_percent'],
        ...procList.map((proc) => [
          proc.pid,
          proc.ppid ?? '',
          proc.name || '',
          proc.user || '',
          proc.group || '',
          proc.cpu_percent ?? '',
          proc.mem_percent ?? '',
        ]),
      ];
      downloadCsv(rows, 'wardex-processes.csv');
      return;
    }
    downloadData(
      { processes: procList, findings: procAnalysis?.findings || [] },
      'wardex-processes.json',
    );
  };

  const openProcess = (process) => setSelectedProcess(process ? { ...process } : null);

  return (
    <div>
      <div className="section-header">
        <div>
          <h2>{currentTabMeta.title}</h2>
          <div className="hint" style={{ marginTop: 4 }}>
            {currentTabMeta.description}
          </div>
        </div>
        <div className="btn-group">
          <span className={`badge ${hp?.status === 'ok' ? 'badge-ok' : 'badge-err'}`}>
            {hp?.status === 'ok' ? 'System Healthy' : 'Degraded'}
          </span>
          <span className={`badge ${streamStatusBadgeClass}`}>
            {streamConnected
              ? `Live feed: ${streamTransportLabel}`
              : `Live feed ${streamStatusLabel.toLowerCase()}`}
          </span>
          <span className="badge badge-info">
            {countData == null
              ? '…'
              : typeof countData === 'object'
                ? (countData.total ?? countData.count ?? filteredAlerts.length)
                : countData}{' '}
            alerts
          </span>
          <button className="btn btn-sm" onClick={reloadAll}>
            ↻ Refresh
          </button>
        </div>
      </div>

      <div className="tabs" role="tablist" aria-label="Monitor views">
        <button
          className={`tab ${tab === 'stream' ? 'active' : ''}`}
          role="tab"
          aria-selected={tab === 'stream'}
          onClick={() => {
            setTab('stream');
            updateMonitorParams({ monitorTab: 'stream' });
          }}
        >
          Alert Stream
        </button>
        <button
          className={`tab ${tab === 'grouped' ? 'active' : ''}`}
          role="tab"
          aria-selected={tab === 'grouped'}
          onClick={() => {
            setTab('grouped');
            updateMonitorParams({ monitorTab: 'grouped' });
          }}
        >
          Grouped
        </button>
        <button
          className={`tab ${tab === 'analysis' ? 'active' : ''}`}
          role="tab"
          aria-selected={tab === 'analysis'}
          onClick={() => {
            setTab('analysis');
            updateMonitorParams({ monitorTab: 'analysis' });
          }}
        >
          Analysis
        </button>
        <button
          className={`tab ${tab === 'processes' ? 'active' : ''}`}
          role="tab"
          aria-selected={tab === 'processes'}
          onClick={() => {
            setTab('processes');
            updateMonitorParams({ monitorTab: 'processes' });
          }}
        >
          Processes
        </button>
      </div>

      {loading && (
        <div className="loading" role="status" aria-label="Loading alerts">
          <div className="spinner" />
        </div>
      )}

      {tab === 'stream' && !loading && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Transport and Recovery</span>
              <div className="btn-group">
                <button
                  className="btn btn-sm"
                  onClick={() => {
                    reconnectStream();
                    reloadWsStats();
                  }}
                >
                  Reconnect now
                </button>
                <button
                  className="btn btn-sm"
                  onClick={() => {
                    clearStreamEvents();
                    reloadWsStats();
                  }}
                >
                  Clear live buffer
                </button>
              </div>
            </div>
            <div className="summary-grid triage-summary-grid">
              <div className="summary-card">
                <div className="summary-label">Transport State</div>
                <div className="summary-value">{streamStatusLabel}</div>
                <div className="summary-meta">
                  {streamTransportLabel} transport is currently active.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Recovery Attempts</div>
                <div className="summary-value">{recoveryAttempts}</div>
                <div className="summary-meta">Reconnects attempted since this monitor mounted.</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Live Buffer</div>
                <div className="summary-value">{liveEvents.length}</div>
                <div className="summary-meta">Buffered live events awaiting analyst review.</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Polling Session</div>
                <div className="summary-value">{pollingSubscriberId ?? 'n/a'}</div>
                <div className="summary-meta">
                  Active only when the transport is using authenticated polling.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Server Subscribers</div>
                <div className="summary-value">{wsStats?.subscribers ?? 0}</div>
                <div className="summary-meta">
                  {wsConnectionCount} native websocket client{wsConnectionCount === 1 ? '' : 's'}{' '}
                  connected.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Last Live Event</div>
                <div className="summary-value">
                  {lastEventAt ? formatRelativeTime(lastEventAt) : 'None yet'}
                </div>
                <div className="summary-meta">
                  {lastConnectAt
                    ? `Connected ${formatRelativeTime(lastConnectAt)}.`
                    : 'No successful connection yet.'}
                  {lastDisconnectAt
                    ? ` Last disconnect ${formatRelativeTime(lastDisconnectAt)}.`
                    : ''}
                </div>
              </div>
            </div>
            <div className="triage-toolbar" style={{ marginTop: 16 }}>
              <div className="triage-toolbar-group">
                {liveEventTypeOptions.map((eventType) => (
                  <button
                    key={eventType}
                    className={`btn btn-sm ${liveEventTypeFilter === eventType ? 'btn-primary' : ''}`}
                    onClick={() => {
                      setLiveEventTypeFilter(eventType);
                      updateMonitorParams({ eventType });
                    }}
                  >
                    {eventType === 'all'
                      ? `All live events (${liveEvents.length})`
                      : `${eventType} (${liveEventTypeCounts[eventType] || 0})`}
                  </button>
                ))}
              </div>
              <div className="triage-toolbar-group triage-toolbar-group-right">
                <input
                  className="form-input triage-search"
                  placeholder="Filter live event summaries, hosts, or ids…"
                  value={liveEventQuery}
                  onChange={(event) => {
                    const value = event.target.value;
                    setLiveEventQuery(value);
                    updateMonitorParams({ eventQuery: value });
                  }}
                />
              </div>
            </div>
            {filteredLiveEvents.length === 0 ? (
              <TriageEmptyState
                title="No live events match the current scope"
                description="The transport is healthy, but the current live-event filter removed every buffered event from view. Clear the live scope or wait for the next event batch."
              />
            ) : (
              <div className="table-wrap" style={{ marginTop: 16 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Time</th>
                      <th>Summary</th>
                      <th>Subject</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLiveEvents.slice(0, 8).map((event) => (
                      <tr key={event.id}>
                        <td>
                          <span className="badge badge-info">{event.eventType}</span>
                        </td>
                        <td>
                          <div className="row-primary">
                            {event.timestamp ? formatRelativeTime(event.timestamp) : 'No timestamp'}
                          </div>
                          <div className="row-secondary">
                            {event.timestamp ? formatDateTime(event.timestamp) : 'Unknown'}
                          </div>
                        </td>
                        <td>{event.summary}</td>
                        <td>{event.subject}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {lastError && (
              <div className="detail-callout" style={{ marginTop: 16 }}>
                <strong>Last transport error</strong>
                <div style={{ marginTop: 6 }}>{lastError}</div>
              </div>
            )}
          </div>

          <div className="triage-layout">
            <section className="triage-list card">
              <div className="card-header">
                <span className="card-title">Alert Queue ({filteredAlerts.length})</span>
                <div className="btn-group">
                  <button className="btn btn-sm" onClick={() => exportAlerts('json')}>
                    Export JSON
                  </button>
                  <button className="btn btn-sm" onClick={() => exportAlerts('csv')}>
                    Export CSV
                  </button>
                </div>
              </div>
              <div className="triage-toolbar">
                <div className="triage-toolbar-group">
                  {ALERT_VIEWS.map((view) => (
                    <button
                      key={view.id}
                      className={`btn btn-sm ${view.id === ALERT_VIEWS.find((candidate) => candidate.severity === sevFilter && candidate.host === hostFilter && candidate.source === sourceFilter && candidate.query === searchFilter)?.id ? 'btn-primary' : ''}`}
                      onClick={() => {
                        setSevFilter(view.severity);
                        setHostFilter(view.host);
                        setSourceFilter(view.source);
                        setSearchFilter(view.query);
                        updateMonitorParams({
                          sev: view.severity,
                          host: view.host,
                          source: view.source,
                          q: view.query,
                        });
                      }}
                    >
                      {view.label}
                    </button>
                  ))}
                </div>
                <div className="triage-toolbar-group triage-toolbar-group-right">
                  <input
                    className="form-input triage-search"
                    placeholder="Search message, host, user, category…"
                    value={searchFilter}
                    onChange={(event) => {
                      const value = event.target.value;
                      setSearchFilter(value);
                      updateMonitorParams({ q: value });
                    }}
                  />
                  <select
                    className="form-select"
                    value={sourceFilter}
                    onChange={(event) => {
                      const value = event.target.value;
                      setSourceFilter(value);
                      updateMonitorParams({ source: value });
                    }}
                  >
                    {sourceOptions.map((source) => (
                      <option key={source} value={source}>
                        {source === 'all' ? 'All sources' : source}
                      </option>
                    ))}
                  </select>
                  <select
                    className="form-select"
                    value={hostFilter}
                    onChange={(event) => {
                      const value = event.target.value;
                      setHostFilter(value);
                      updateMonitorParams({ host: value });
                    }}
                  >
                    {hostOptions.map((host) => (
                      <option key={host} value={host}>
                        {host === 'all' ? 'All hosts' : host}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="summary-grid triage-summary-grid">
                <div className="summary-card">
                  <div className="summary-label">Visible Alerts</div>
                  <div className="summary-value">{filteredAlerts.length}</div>
                  <div className="summary-meta">Queue size after the current scope filters</div>
                </div>
                <div className="summary-card">
                  <div className="summary-label">Critical</div>
                  <div className="summary-value">{criticalAlertCount}</div>
                  <div className="summary-meta">Priority items still waiting in the queue</div>
                </div>
                <div className="summary-card">
                  <div className="summary-label">Selected</div>
                  <div className="summary-value">{selectedAlerts.size}</div>
                  <div className="summary-meta">Alerts pinned for bulk actions</div>
                </div>
                <div className="summary-card">
                  <div className="summary-label">Saved View</div>
                  <div className="summary-value">{currentView?.label || 'Custom'}</div>
                  <div className="summary-meta">Preset scope or operator-defined mix</div>
                </div>
              </div>
              <div className="active-filter-chips">
                {['all', 'critical', 'severe', 'elevated', 'low'].map((severity) => (
                  <button
                    key={severity}
                    className={`filter-chip-button ${sevFilter === severity ? 'active' : ''}`}
                    onClick={() => {
                      setSevFilter(severity);
                      updateMonitorParams({ sev: severity });
                    }}
                  >
                    {severity === 'all' ? 'All severities' : severity}
                  </button>
                ))}
                {sourceFilter !== 'all' && (
                  <span className="scope-chip">Source: {sourceFilter}</span>
                )}
                {hostFilter !== 'all' && <span className="scope-chip">Host: {hostFilter}</span>}
                {searchFilter && <span className="scope-chip">Query: {searchFilter}</span>}
                {hasAlertFilters && (
                  <button className="filter-chip-button" onClick={clearAlertFilters}>
                    Reset filters
                  </button>
                )}
              </div>
              <div className="triage-meta-bar">
                <div className="hint">
                  {filteredAlerts.length} alert{filteredAlerts.length === 1 ? '' : 's'} in scope.{' '}
                  {criticalAlertCount} critical.{' '}
                  {currentView?.label ? `Preset: ${currentView.label}.` : 'Custom scope active.'}
                </div>
                {hasAlertFilters && (
                  <button className="btn btn-sm" onClick={clearAlertFilters}>
                    Clear Scope
                  </button>
                )}
              </div>
              <div className="sticky-bulk-bar">
                <div>{selectedAlerts.size} selected</div>
                <select
                  value={bulkAction}
                  onChange={(e) => setBulkAction(e.target.value)}
                  className="form-select"
                  style={{ maxWidth: 200 }}
                >
                  <option value="">Bulk Action…</option>
                  <option value="fp">Mark as False Positive</option>
                  <option value="triage">Acknowledge / Triage</option>
                  <option value="incident">Create Incident</option>
                </select>
                <button
                  className="btn btn-sm btn-primary"
                  disabled={!bulkAction || selectedAlerts.size === 0}
                  onClick={executeBulk}
                >
                  Apply
                </button>
              </div>
              {filteredAlerts.length === 0 ? (
                <TriageEmptyState
                  title="No alerts match the current scope"
                  description="The queue is healthy, but the current search, source, or host scope narrowed this view to zero items. Clear the scope or switch presets to continue triage."
                  actionLabel={hasAlertFilters ? 'Clear Filters' : null}
                  onAction={hasAlertFilters ? clearAlertFilters : null}
                />
              ) : (
                <div className="split-list-table">
                  <div className="desktop-table-only">
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: 30 }}>
                            <input
                              type="checkbox"
                              checked={
                                selectedAlerts.size === filteredAlerts.length &&
                                filteredAlerts.length > 0
                              }
                              onChange={toggleSelectAll}
                              aria-label="Select all visible alerts"
                            />
                          </th>
                          <th>Time</th>
                          <th>Severity</th>
                          <th>Source</th>
                          <th>Category</th>
                          <th>Message</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredAlerts.map((alert, index) => {
                          const aid = alertIdFor(alert, index);
                          const isSelected = selectedAlerts.has(aid);
                          const isActive = selectedId === aid || hoveredId === aid;
                          return (
                            <tr
                              key={aid}
                              className={isActive ? 'row-active' : ''}
                              tabIndex={0}
                              onMouseEnter={() => setHoveredId(aid)}
                              onFocus={() => setHoveredId(aid)}
                              onClick={() => setSelectedId(selectedId === aid ? null : aid)}
                            >
                              <td onClick={(event) => event.stopPropagation()}>
                                <input
                                  type="checkbox"
                                  checked={isSelected}
                                  onChange={() => toggleSelect(aid)}
                                  aria-label={`Select alert ${aid}`}
                                />
                              </td>
                              <td>
                                <div className="row-primary">
                                  {formatRelativeTime(alert.timestamp || alert.time)}
                                </div>
                                <div className="row-secondary">
                                  {formatDateTime(alert.timestamp || alert.time)}
                                </div>
                              </td>
                              <td>
                                <span
                                  className={`badge ${(alert.severity || '').toLowerCase() === 'critical' ? 'badge-err' : (alert.severity || '').toLowerCase() === 'low' ? 'badge-info' : 'badge-warn'}`}
                                >
                                  {alert.severity || 'unknown'}
                                </span>
                              </td>
                              <td>{alert.source || '—'}</td>
                              <td>{alert.category || alert.type || '—'}</td>
                              <td>
                                <div className="row-primary">
                                  {alert.message || alert.description || '—'}
                                </div>
                                <div className="row-secondary">
                                  {alert.hostname || alert.origin_agent_id || 'No host context'}
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  <div className="mobile-stack">
                    {filteredAlerts.map((alert, index) => {
                      const aid = alertIdFor(alert, index);
                      return (
                        <MobileAlertCard
                          key={aid}
                          alert={alert}
                          index={index}
                          active={selectedId === aid || hoveredId === aid}
                          onPreview={(nextId) => {
                            setHoveredId(nextId);
                            setSelectedId(nextId);
                          }}
                          onOpen={(nextId) => setSelectedId(nextId)}
                          onMarkFP={markFP}
                        />
                      );
                    })}
                  </div>
                </div>
              )}
              {Array.isArray(fpStats) && fpStats.length > 0 && (
                <div className="detail-callout" style={{ marginTop: 16 }}>
                  FP feedback trends:{' '}
                  {fpStats
                    .slice(0, 3)
                    .map((item) => `${item.pattern} ${(item.fp_ratio * 100).toFixed(0)}%`)
                    .join(' · ')}
                </div>
              )}
            </section>

            <aside className="triage-detail card">
              <div className="card-header">
                <span className="card-title">
                  {previewAlert
                    ? previewAlert.message || previewAlert.category || 'Alert Preview'
                    : 'Alert Preview'}
                </span>
                {previewAlert && (
                  <div className="btn-group">
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        setSelectedId(
                          selectedAlert ? null : alertIdFor(previewAlert, previewAlertIndex),
                        )
                      }
                    >
                      {selectedAlert ? 'Close Drawer' : 'Open Drawer'}
                    </button>
                    <button className="btn btn-sm" onClick={() => markFP(previewAlert)}>
                      Mark FP
                    </button>
                  </div>
                )}
              </div>
              {previewAlert ? (
                <>
                  <div className="triage-detail-nav">
                    <span className="scope-chip">
                      {previewAlertIndex + 1} of {filteredAlerts.length}
                    </span>
                    <div className="btn-group">
                      <button
                        className="btn btn-sm"
                        onClick={() => moveAlert(-1, selectedAlert != null)}
                        disabled={previewAlertIndex <= 0}
                      >
                        Previous
                      </button>
                      <button
                        className="btn btn-sm"
                        onClick={() => moveAlert(1, selectedAlert != null)}
                        disabled={previewAlertIndex >= filteredAlerts.length - 1}
                      >
                        Next
                      </button>
                      {!selectedAlert && (
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={() => setSelectedId(alertIdFor(previewAlert, previewAlertIndex))}
                        >
                          Pin Preview
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="detail-hero">
                    <div>
                      <div className="detail-hero-title">
                        {previewAlert.category || previewAlert.type || 'Alert context'}
                      </div>
                      <div className="detail-hero-copy">
                        {previewAlert.message ||
                          previewAlert.description ||
                          'Open alert context available in this preview.'}
                      </div>
                    </div>
                    <span
                      className={`badge ${(previewAlert.severity || '').toLowerCase() === 'critical' ? 'badge-err' : (previewAlert.severity || '').toLowerCase() === 'low' ? 'badge-info' : 'badge-warn'}`}
                    >
                      {previewAlert.severity || 'unknown'}
                    </span>
                  </div>
                  <SummaryGrid
                    data={{
                      source: previewAlert.source,
                      host: previewAlert.hostname || previewAlert.origin_agent_id,
                      time: formatDateTime(previewAlert.timestamp || previewAlert.time),
                      relative_time: formatRelativeTime(
                        previewAlert.timestamp || previewAlert.time,
                      ),
                      score: previewAlert.score,
                      status: previewAlert.status || 'open',
                    }}
                    limit={6}
                  />
                  <div className="detail-callout" style={{ marginTop: 16 }}>
                    {previewAlert.hostname
                      ? `Current scope: ${previewAlert.hostname}. Use this preview to inspect host, source, and severity without losing the surrounding queue.`
                      : 'This alert has limited host context. Use the full drawer when you need deeper pivoting or raw evidence.'}
                  </div>
                  <JsonDetails data={previewAlert} label="Expanded alert context" />
                </>
              ) : (
                <TriageEmptyState
                  title="No alert preview yet"
                  description="Hover a row on desktop or tap a card on mobile to keep the surrounding queue visible while you inspect each alert."
                />
              )}
            </aside>
          </div>
        </>
      )}

      {tab === 'grouped' && (
        <div className="card">
          {!grouped || (Array.isArray(grouped) && grouped.length === 0) ? (
            <div className="empty">No grouped data</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Group</th>
                    <th>Severity</th>
                    <th>Count</th>
                    <th>Avg Score</th>
                    <th>Max Score</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {(Array.isArray(grouped) ? grouped : []).map((g) => (
                    <tr key={g.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>#{g.id}</td>
                      <td>
                        <span className={`sev-${(g.level || 'low').toLowerCase()}`}>{g.level}</span>
                      </td>
                      <td>
                        <strong>{g.count}</strong>
                      </td>
                      <td>{g.avg_score?.toFixed(2)}</td>
                      <td>{g.max_score?.toFixed(2)}</td>
                      <td
                        style={{
                          whiteSpace: 'nowrap',
                          fontFamily: 'var(--font-mono)',
                          fontSize: 12,
                        }}
                      >
                        {g.first_seen || '—'}
                      </td>
                      <td
                        style={{
                          whiteSpace: 'nowrap',
                          fontFamily: 'var(--font-mono)',
                          fontSize: 12,
                        }}
                      >
                        {g.last_seen || '—'}
                      </td>
                      <td style={{ fontSize: 12 }}>
                        {(g.representative_reasons || []).join(', ') || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'analysis' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Alert Analysis</span>
            <button
              className="btn btn-sm btn-primary"
              onClick={async () => {
                try {
                  const r = await api.alertsAnalysis({});
                  setAnalysisResult(r);
                  toast('Analysis complete', 'success');
                } catch {
                  toast('Analysis failed', 'error');
                }
              }}
            >
              Run Analysis
            </button>
          </div>
          {analysisResult ? (
            <div>
              {analysisResult.summary && (
                <div
                  style={{
                    padding: '12px 16px',
                    background: 'var(--bg)',
                    borderRadius: 'var(--radius)',
                    marginBottom: 16,
                    lineHeight: 1.6,
                  }}
                >
                  {analysisResult.summary}
                </div>
              )}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                  gap: 12,
                  marginBottom: 16,
                }}
              >
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Total Alerts</div>
                  <div style={{ fontSize: 24, fontWeight: 700 }}>{analysisResult.total_alerts}</div>
                </div>
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Pattern</div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>
                    {typeof analysisResult.pattern === 'string'
                      ? analysisResult.pattern
                      : analysisResult.pattern?.Sustained?.severity
                        ? `Sustained ${analysisResult.pattern.Sustained.severity}`
                        : JSON.stringify(analysisResult.pattern)}
                  </div>
                </div>
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Score Trend</div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>
                    {analysisResult.score_trend?.Rising
                      ? `Rising (+${analysisResult.score_trend.Rising.slope})`
                      : analysisResult.score_trend?.Falling
                        ? `Declining (${analysisResult.score_trend.Falling.slope})`
                        : analysisResult.score_trend === 'Volatile'
                          ? 'Volatile'
                          : 'Stable'}
                  </div>
                </div>
                {analysisResult.severity_breakdown && (
                  <div className="card" style={{ padding: 12 }}>
                    <div className="metric-label">Severity</div>
                    <div style={{ fontSize: 13 }}>
                      <span className="sev-critical">
                        {analysisResult.severity_breakdown.critical}
                      </span>{' '}
                      critical,{' '}
                      <span className="sev-severe">{analysisResult.severity_breakdown.severe}</span>{' '}
                      severe,{' '}
                      <span className="sev-elevated">
                        {analysisResult.severity_breakdown.elevated}
                      </span>{' '}
                      elevated
                    </div>
                  </div>
                )}
              </div>
              {analysisResult.dominant_reasons?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>
                    Top Detection Reasons
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Reason</th>
                          <th>Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        {analysisResult.dominant_reasons.map(([reason, count], i) => (
                          <tr key={i}>
                            <td>{reason}</td>
                            <td>{count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              {analysisResult.isolation_guidance?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>
                    Isolation &amp; Response Guidance
                  </div>
                  {analysisResult.isolation_guidance.map((g, i) => (
                    <div
                      key={i}
                      style={{
                        padding: '10px 14px',
                        background: 'var(--bg)',
                        borderRadius: 'var(--radius)',
                        marginBottom: 8,
                        borderLeft: '3px solid var(--warning)',
                      }}
                    >
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>{g.reason}</div>
                      <div
                        style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 6 }}
                      >
                        {g.threat_description}
                      </div>
                      <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
                        {g.steps.map((step, j) => (
                          <li key={j}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}
              <JsonDetails data={analysisResult} label="Full analysis breakdown" />
            </div>
          ) : (
            <div className="empty">
              Click &quot;Run Analysis&quot; to analyze current alert patterns
            </div>
          )}
        </div>
      )}

      {tab === 'processes' && (
        <div>
          {/* Process summary + controls */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Running Processes</span>
              <div className="btn-group">
                <button className="btn btn-sm" onClick={reloadProcessData}>
                  ↻ Refresh
                </button>
                <button className="btn btn-sm" onClick={() => exportProcesses('json')}>
                  Export JSON
                </button>
                <button className="btn btn-sm" onClick={() => exportProcesses('csv')}>
                  Export CSV
                </button>
              </div>
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                gap: 12,
                marginBottom: 12,
              }}
            >
              <div className="card" style={{ padding: 10 }}>
                <div className="metric-label">Process Count</div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>
                  {procData?.count ?? procList.length}
                </div>
              </div>
              <div className="card" style={{ padding: 10 }}>
                <div className="metric-label">Total CPU</div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>
                  {procData?.total_cpu_percent != null
                    ? `${procData.total_cpu_percent.toFixed(1)}%`
                    : hasProcessSnapshot
                      ? '0.0%'
                      : 'Pending'}
                </div>
              </div>
              <div className="card" style={{ padding: 10 }}>
                <div className="metric-label">Total Memory</div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>
                  {procData?.total_mem_percent != null
                    ? `${procData.total_mem_percent.toFixed(1)}%`
                    : hasProcessSnapshot
                      ? '0.0%'
                      : 'Pending'}
                </div>
              </div>
              <div className="card" style={{ padding: 10 }}>
                <div className="metric-label">Findings</div>
                <div
                  style={{
                    fontSize: 22,
                    fontWeight: 700,
                    color: (procAnalysis?.total || 0) > 0 ? 'var(--danger)' : 'var(--success)',
                  }}
                >
                  {procAnalysis?.total ?? '—'}
                </div>
              </div>
            </div>

            {/* Sort + Filter controls */}
            <div
              style={{
                display: 'flex',
                gap: 8,
                alignItems: 'center',
                flexWrap: 'wrap',
                marginBottom: 12,
              }}
            >
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Sort:</span>
              {['cpu', 'mem', 'name', 'pid'].map((s) => (
                <button
                  key={s}
                  className={`btn btn-sm ${procSort === s ? 'btn-primary' : ''}`}
                  onClick={() => setProcSort(s)}
                >
                  {s === 'cpu'
                    ? 'CPU ↓'
                    : s === 'mem'
                      ? 'Memory ↓'
                      : s === 'name'
                        ? 'Name A-Z'
                        : 'PID'}
                </button>
              ))}
              <input
                type="text"
                placeholder="Filter by name, user, or PID…"
                value={procFilter}
                onChange={(e) => setProcFilter(e.target.value)}
                style={{
                  marginLeft: 'auto',
                  padding: '4px 10px',
                  borderRadius: 'var(--radius)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg)',
                  color: 'var(--text)',
                  fontSize: 13,
                  minWidth: 200,
                }}
              />
            </div>
          </div>

          {/* Security findings */}
          {procAnalysis?.findings?.length > 0 && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>
                Security Findings
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Risk</th>
                      <th>PID</th>
                      <th>Process</th>
                      <th>User</th>
                      <th>CPU</th>
                      <th>Mem</th>
                      <th>Reason</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {procAnalysis.findings.map((f, i) => (
                      <tr
                        key={i}
                        style={{
                          background:
                            f.risk_level === 'critical'
                              ? 'rgba(239,68,68,.06)'
                              : f.risk_level === 'high'
                                ? 'rgba(249,115,22,.06)'
                                : undefined,
                          cursor: 'pointer',
                        }}
                        onClick={() => openProcess(f)}
                      >
                        <td>
                          <span className={`sev-${f.risk_level}`}>{f.risk_level}</span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{f.pid}</td>
                        <td style={{ fontWeight: 600 }}>{f.name}</td>
                        <td>{f.user}</td>
                        <td>{f.cpu_percent?.toFixed(1)}%</td>
                        <td>{f.mem_percent?.toFixed(1)}%</td>
                        <td style={{ fontSize: 12 }}>{f.reason}</td>
                        <td>
                          <button
                            className="btn btn-sm"
                            onClick={(event) => {
                              event.stopPropagation();
                              openProcess(f);
                            }}
                          >
                            Investigate
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Process table */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>
              All Processes{' '}
              {procFilter && (
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  ({procList.length} matching)
                </span>
              )}
            </div>
            {procList.length === 0 ? (
              <TriageEmptyState
                title={procFilter ? 'No processes match this filter' : 'No process inventory yet'}
                description={
                  procFilter
                    ? 'The current process filter removed every row from view. Clear the filter or wait for the next live snapshot.'
                    : procData?.message ||
                      'The local collector has not returned a current process snapshot yet. Refresh this view once telemetry is available.'
                }
                actionLabel={procFilter ? 'Clear Filter' : 'Refresh Processes'}
                onAction={procFilter ? () => setProcFilter('') : reloadProcessData}
              />
            ) : (
              <div className="table-wrap" style={{ maxHeight: 500, overflowY: 'auto' }}>
                <table>
                  <thead
                    style={{ position: 'sticky', top: 0, background: 'var(--card-bg)', zIndex: 1 }}
                  >
                    <tr>
                      <th style={{ cursor: 'pointer' }} onClick={() => setProcSort('pid')}>
                        PID{procSort === 'pid' ? ' ↓' : ''}
                      </th>
                      <th>PPID</th>
                      <th style={{ cursor: 'pointer' }} onClick={() => setProcSort('name')}>
                        Name{procSort === 'name' ? ' ↓' : ''}
                      </th>
                      <th>User</th>
                      <th>Group</th>
                      <th style={{ cursor: 'pointer' }} onClick={() => setProcSort('cpu')}>
                        CPU %{procSort === 'cpu' ? ' ↓' : ''}
                      </th>
                      <th style={{ cursor: 'pointer' }} onClick={() => setProcSort('mem')}>
                        Mem %{procSort === 'mem' ? ' ↓' : ''}
                      </th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {procList.slice(0, 200).map((p) => (
                      <tr key={p.pid} style={{ cursor: 'pointer' }} onClick={() => openProcess(p)}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{p.pid}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                          {p.ppid ?? '—'}
                        </td>
                        <td style={{ fontWeight: p.cpu_percent > 50 ? 700 : 400 }}>
                          {p.name?.split('/').pop() || p.name}
                        </td>
                        <td>{p.user}</td>
                        <td>{p.group || '—'}</td>
                        <td style={{ color: p.cpu_percent > 50 ? 'var(--danger)' : undefined }}>
                          {p.cpu_percent?.toFixed(1)}
                        </td>
                        <td style={{ color: p.mem_percent > 30 ? 'var(--warning)' : undefined }}>
                          {p.mem_percent?.toFixed(1)}
                        </td>
                        <td>
                          <button
                            className="btn btn-sm"
                            onClick={(event) => {
                              event.stopPropagation();
                              openProcess(p);
                            }}
                          >
                            Investigate
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {procList.length > 200 && (
                  <div
                    style={{
                      padding: 8,
                      textAlign: 'center',
                      fontSize: 12,
                      color: 'var(--text-secondary)',
                    }}
                  >
                    Showing 200 of {procList.length} processes. Use filter to narrow results.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
      <AlertDrawer
        alert={selectedAlert}
        onClose={() => setSelectedId(null)}
        onUpdated={reloadAll}
        onPrevious={() => moveAlert(-1, true)}
        onNext={() => moveAlert(1, true)}
        canPrevious={selectedAlertIndex > 0}
        canNext={selectedAlertIndex !== -1 && selectedAlertIndex < filteredAlerts.length - 1}
        positionLabel={
          selectedAlertIndex === -1 ? null : `${selectedAlertIndex + 1} of ${filteredAlerts.length}`
        }
      />
      <ProcessDrawer
        pid={selectedProcess?.pid}
        snapshot={selectedProcess}
        onClose={() => setSelectedProcess(null)}
        onPrevious={() => {
          const currentIndex = procList.findIndex((proc) => proc.pid === selectedProcess?.pid);
          if (currentIndex > 0) openProcess(procList[currentIndex - 1]);
        }}
        onNext={() => {
          const currentIndex = procList.findIndex((proc) => proc.pid === selectedProcess?.pid);
          if (currentIndex !== -1 && currentIndex < procList.length - 1)
            openProcess(procList[currentIndex + 1]);
        }}
        canPrevious={procList.findIndex((proc) => proc.pid === selectedProcess?.pid) > 0}
        canNext={(() => {
          const currentIndex = procList.findIndex((proc) => proc.pid === selectedProcess?.pid);
          return currentIndex !== -1 && currentIndex < procList.length - 1;
        })()}
        positionLabel={(() => {
          const currentIndex = procList.findIndex((proc) => proc.pid === selectedProcess?.pid);
          return currentIndex === -1 ? null : `${currentIndex + 1} of ${procList.length}`;
        })()}
        onUpdated={reloadProcessData}
      />
    </div>
  );
}

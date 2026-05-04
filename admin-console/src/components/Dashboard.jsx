import { useState, useMemo, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApi, useApiGroup, useInterval, useToast, useRole } from '../hooks.jsx';
import * as api from '../api.js';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import AlertDrawer from './AlertDrawer.jsx';
import ProcessDrawer from './ProcessDrawer.jsx';
import DashboardWidget from './DashboardWidget.jsx';
import WorkflowGuidance from './WorkflowGuidance.jsx';
import Tip from './Tooltip.jsx';
import { SkeletonCard } from './Skeleton.jsx';
import { formatDateTime, formatNumber, formatRelativeTime } from './operatorUtils.js';
import { useWidgetLayout } from './useWidgetLayout.js';
import { buildHref } from './workflowPivots.js';

function Metric({ label, value, sub, accent, onClick, tip }) {
  return (
    <div
      className={`card metric${accent ? ' metric-accent' : ''}`}
      style={onClick ? { cursor: 'pointer' } : undefined}
      onClick={onClick}
    >
      <div className="metric-label">
        {label}
        {tip && (
          <>
            {' '}
            <Tip text={tip} />
          </>
        )}
      </div>
      <div className="metric-value">{value ?? '—'}</div>
      {sub && <div className="metric-sub">{sub}</div>}
    </div>
  );
}

const SEV_COLORS = {
  critical: '#ef4444',
  severe: '#f97316',
  elevated: '#eab308',
  high: '#f97316',
  medium: '#3b82f6',
  low: '#6b7280',
};

const DASHBOARD_WIDGETS = [
  'system-health',
  'collector-health',
  'telemetry',
  'threat-overview',
  'charts',
  'process-security',
  'detection-engine',
  'malware-ti',
  'dns-threats',
  'lifecycle',
  'manager-digest',
  'recent-alerts',
];

const SHARED_DASHBOARD_PRESETS = [
  {
    id: 'analyst-triage',
    name: 'Analyst Triage',
    description:
      'Prioritize queue pressure, recent alerts, and tuning signals for active analysts.',
    widgets: [
      'threat-overview',
      'recent-alerts',
      'detection-engine',
      'collector-health',
      'charts',
      'process-security',
      'system-health',
      'telemetry',
      'lifecycle',
      'manager-digest',
      'malware-ti',
      'dns-threats',
    ],
    hidden: [],
    audience: 'analyst',
  },
  {
    id: 'admin-operations',
    name: 'Admin Operations',
    description:
      'Balance platform health, telemetry, lifecycle, and response readiness for operators.',
    widgets: [
      'system-health',
      'collector-health',
      'telemetry',
      'lifecycle',
      'threat-overview',
      'charts',
      'recent-alerts',
      'detection-engine',
      'process-security',
      'manager-digest',
      'malware-ti',
      'dns-threats',
    ],
    hidden: [],
    audience: 'admin',
  },
  {
    id: 'noc-wall',
    name: 'NOC Wall',
    description:
      'Keep the wallboard focused on posture, alert pressure, and broad telemetry trends.',
    widgets: [
      'system-health',
      'collector-health',
      'threat-overview',
      'telemetry',
      'charts',
      'lifecycle',
      'manager-digest',
      'recent-alerts',
      'detection-engine',
      'process-security',
      'malware-ti',
      'dns-threats',
    ],
    hidden: ['dns-threats'],
    audience: 'shared',
  },
];

function sharedPresetKey(id) {
  return `shared:${id}`;
}

function savedPresetKey(name) {
  return `saved:${name}`;
}

function isSavedPresetKey(key) {
  return String(key || '').startsWith('saved:');
}

function getSavedPresetName(key) {
  return String(key || '').replace(/^saved:/, '');
}

function findPresetByKey(key, savedPresets) {
  const normalized = String(key || '').trim();
  if (!normalized) return null;
  if (normalized.startsWith('shared:')) {
    const id = normalized.replace(/^shared:/, '');
    return SHARED_DASHBOARD_PRESETS.find((preset) => preset.id === id) || null;
  }
  if (normalized.startsWith('saved:')) {
    const name = getSavedPresetName(normalized);
    return (
      (Array.isArray(savedPresets) ? savedPresets : []).find((preset) => preset.name === name) ||
      null
    );
  }
  return null;
}

function alertSeverity(alert) {
  return (alert?.severity || alert?.level || alert?.risk_level || 'unknown').toLowerCase();
}

function alertCategory(alert) {
  return alert?.category || alert?.type || alert?.alert_origin || alert?.action || 'Signal';
}

function alertNarrative(alert) {
  if (!alert) return 'Open alert details';
  if (alert.message) return alert.message;
  if (alert.description) return alert.description;
  if (alert.summary) return alert.summary;
  if (Array.isArray(alert.reasons) && alert.reasons.length > 0) return alert.reasons.join(', ');
  if (alert.reason) return alert.reason;
  if (alert.action && alert.score != null)
    return `${alert.action} · score ${Number(alert.score).toFixed(2)}`;
  if (alert.action) return alert.action;
  if (alert.alert_origin) return `Origin: ${alert.alert_origin}`;
  return 'Open alert details';
}

function alertReportTarget(alert) {
  if (!alert) return '';
  return (
    alert.hostname ||
    alert.target_hostname ||
    alert.target?.hostname ||
    alert.agent_uid ||
    alert.target_agent_uid ||
    alert.target?.agent_uid ||
    alert.id ||
    alert.alert_id ||
    ''
  );
}

function formatLagDuration(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 0) return '—';
  if (value < 60) return `${Math.round(value)}s`;
  if (value < 3600) return `${Math.round(value / 60)}m`;
  const hours = value / 3600;
  return `${hours >= 10 ? Math.round(hours) : hours.toFixed(1)}h`;
}

function collectorFreshnessRank(freshness) {
  switch (freshness) {
    case 'error':
      return 3;
    case 'stale':
      return 2;
    case 'unknown':
      return 1;
    default:
      return 0;
  }
}

function collectorTimelineSeverityClass(status) {
  switch (String(status || '').toLowerCase()) {
    case 'error':
      return 'sev-critical';
    case 'warning':
    case 'review':
      return 'sev-severe';
    case 'disabled':
      return 'sev-low';
    case 'ready':
      return 'sev-info';
    default:
      return 'sev-elevated';
  }
}

export default function Dashboard() {
  const toast = useToast();
  const navigate = useNavigate();
  const { role } = useRole();
  const {
    data: dashboardOverviewData,
    loading: l1,
    reload: reloadDashboardOverview,
  } = useApiGroup({
    st: api.status,
    fleet: api.fleetDashboard,
    telem: api.telemetryCurrent,
    hp: api.health,
  });
  const { st, fleet, telem, hp } = dashboardOverviewData;
  const { data: dashboardAlertsData, reload: reloadDashboardAlerts } = useApiGroup({
    alertData: api.alerts,
  });
  const { alertData } = dashboardAlertsData;
  const { data: profile } = useApi(api.detectionProfile);
  const { data: hostInf } = useApi(api.hostInfo);
  const { data: telemHistory } = useApi(api.telemetryHistory);
  const { data: userPrefs } = useApi(api.userPreferences);
  const { data: collectorsStatus, reload: reloadCollectorsStatus } = useApi(api.collectorsStatus);
  const { data: dashboardSignalsData, reload: reloadDashboardSignals } = useApiGroup({
    detSum: api.detectionSummary,
    tiStatus: api.threatIntelStatus,
    qStats: api.queueStats,
    respStats: api.responseStats,
    procAnalysis: api.processesAnalysis,
    mwStats: api.malwareStats,
    gaps: api.coverageGaps,
    qrStats: api.quarantineStats,
    lcStats: api.lifecycleStats,
    fdStats: api.feedStats,
    managerDigest: api.managerQueueDigest,
    dnsSummary: api.dnsThreatSummary,
  });
  const {
    detSum,
    tiStatus,
    qStats,
    respStats,
    procAnalysis,
    mwStats,
    gaps,
    qrStats,
    lcStats,
    fdStats,
    managerDigest,
    dnsSummary,
  } = dashboardSignalsData;
  const [refreshing, setRefreshing] = useState(false);
  const [expandedAlert, setExpandedAlert] = useState(null);
  const [sevFilter, setSevFilter] = useState('all');
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [nocMode, setNocMode] = useState(false);
  const [nocWidget, setNocWidget] = useState(0);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [presetName, setPresetName] = useState('');
  const [savedPresets, setSavedPresets] = useState([]);
  const [selectedPresetKey, setSelectedPresetKey] = useState('');
  const [savingPreset, setSavingPreset] = useState(false);
  const hasLocalLayoutRef = useRef(
    Boolean(localStorage.getItem('dashboard') || localStorage.getItem('dashboard_hidden')),
  );
  const hydratedPresetsRef = useRef(false);

  const recommendedSharedPresetId = role === 'admin' ? 'admin-operations' : 'analyst-triage';
  const activePreset = useMemo(
    () => findPresetByKey(selectedPresetKey, savedPresets),
    [savedPresets, selectedPresetKey],
  );
  const fleetSummary = fleet?.fleet || fleet || {};
  const fleetStatusCounts = fleetSummary.status_counts || fleet?.status_counts || {};
  const fleetOnline = fleetStatusCounts.online ?? fleet?.online;
  const presetOptions = useMemo(
    () => [
      ...SHARED_DASHBOARD_PRESETS.map((preset) => ({
        key: sharedPresetKey(preset.id),
        label: `Shared · ${preset.name}`,
      })),
      ...savedPresets.map((preset) => ({
        key: savedPresetKey(preset.name),
        label: `Personal · ${preset.name}`,
      })),
    ],
    [savedPresets],
  );
  const {
    order,
    hidden,
    moveWidget,
    removeWidget,
    restoreWidget,
    resetLayout,
    applyLayout,
    snapshot,
  } = useWidgetLayout(DASHBOARD_WIDGETS, 'dashboard');

  useEffect(() => {
    if (hydratedPresetsRef.current || !userPrefs) return;
    const nextSavedPresets = Array.isArray(userPrefs.dashboard_presets)
      ? userPrefs.dashboard_presets
      : [];
    const persistedActivePreset = String(userPrefs.active_dashboard_preset || '').trim();
    const fallbackPresetKey = sharedPresetKey(recommendedSharedPresetId);
    setSavedPresets(nextSavedPresets);
    setSelectedPresetKey(persistedActivePreset || fallbackPresetKey);

    if (!hasLocalLayoutRef.current && persistedActivePreset) {
      const preset = findPresetByKey(persistedActivePreset, nextSavedPresets);
      if (preset) applyLayout(preset);
    }

    hydratedPresetsRef.current = true;
  }, [applyLayout, recommendedSharedPresetId, userPrefs]);

  useEffect(() => {
    if (selectedPresetKey) return;
    setSelectedPresetKey(sharedPresetKey(recommendedSharedPresetId));
  }, [recommendedSharedPresetId, selectedPresetKey]);

  const updatePresetPreferences = useCallback(
    async (patch, successMessage) => {
      setSavingPreset(true);
      try {
        const updated = await api.setUserPreferences(patch);
        const nextSavedPresets = Array.isArray(updated?.dashboard_presets)
          ? updated.dashboard_presets
          : Array.isArray(patch.dashboard_presets)
            ? patch.dashboard_presets
            : savedPresets;
        const nextActivePreset =
          typeof updated?.active_dashboard_preset === 'string'
            ? updated.active_dashboard_preset
            : patch.active_dashboard_preset || selectedPresetKey;

        setSavedPresets(nextSavedPresets);
        setSelectedPresetKey(nextActivePreset || sharedPresetKey(recommendedSharedPresetId));
        if (successMessage) toast(successMessage, 'success');
        return true;
      } catch {
        toast('Failed to update dashboard presets.', 'error');
        return false;
      } finally {
        setSavingPreset(false);
      }
    },
    [recommendedSharedPresetId, savedPresets, selectedPresetKey, toast],
  );

  const applySelectedPreset = useCallback(async () => {
    const preset = findPresetByKey(selectedPresetKey, savedPresets);
    if (!preset) {
      toast('Select a dashboard preset first.', 'warning');
      return;
    }
    applyLayout(preset);
    hasLocalLayoutRef.current = false;
    await updatePresetPreferences(
      { active_dashboard_preset: selectedPresetKey },
      `${preset.name} applied.`,
    );
  }, [applyLayout, savedPresets, selectedPresetKey, toast, updatePresetPreferences]);

  const saveCurrentPreset = useCallback(async () => {
    const trimmedName = presetName.trim();
    if (!trimmedName) {
      toast('Preset name is required.', 'warning');
      return;
    }

    const nextPreset = {
      name: trimmedName,
      widgets: snapshot.widgets,
      hidden: snapshot.hidden,
    };
    const nextPresets = [
      ...savedPresets.filter((preset) => preset.name.toLowerCase() !== trimmedName.toLowerCase()),
      nextPreset,
    ];
    const nextPresetKey = savedPresetKey(trimmedName);
    const updated = await updatePresetPreferences(
      {
        dashboard_presets: nextPresets,
        active_dashboard_preset: nextPresetKey,
      },
      `Saved ${trimmedName}.`,
    );
    if (updated) {
      setPresetName('');
      setSelectedPresetKey(nextPresetKey);
    }
  }, [presetName, savedPresets, snapshot.hidden, snapshot.widgets, toast, updatePresetPreferences]);

  const deleteSelectedPreset = useCallback(async () => {
    if (!isSavedPresetKey(selectedPresetKey)) return;
    const presetToDelete = getSavedPresetName(selectedPresetKey);
    const nextPresets = savedPresets.filter((preset) => preset.name !== presetToDelete);
    const fallbackPresetKey = sharedPresetKey(recommendedSharedPresetId);
    const updated = await updatePresetPreferences(
      {
        dashboard_presets: nextPresets,
        active_dashboard_preset: fallbackPresetKey,
      },
      `Removed ${presetToDelete}.`,
    );
    if (updated) {
      setSelectedPresetKey(fallbackPresetKey);
      const fallbackPreset = findPresetByKey(fallbackPresetKey, nextPresets);
      if (fallbackPreset) applyLayout(fallbackPreset);
    }
  }, [
    applyLayout,
    recommendedSharedPresetId,
    savedPresets,
    selectedPresetKey,
    updatePresetPreferences,
  ]);

  // Per-widget auto-refresh toggle
  const [pausedWidgets, setPausedWidgets] = useState(() => {
    try {
      return new Set(JSON.parse(localStorage.getItem('wardex_paused_widgets') || '[]'));
    } catch {
      return new Set();
    }
  });
  const toggleWidgetRefresh = (widgetId) => {
    setPausedWidgets((prev) => {
      const next = new Set(prev);
      next.has(widgetId) ? next.delete(widgetId) : next.add(widgetId);
      localStorage.setItem('wardex_paused_widgets', JSON.stringify([...next]));
      return next;
    });
  };

  const reloadAll = async () => {
    if (pausedWidgets.size >= DASHBOARD_WIDGETS.length) return;
    setRefreshing(true);
    await Promise.allSettled([
      reloadDashboardOverview(),
      reloadDashboardAlerts(),
      reloadCollectorsStatus(),
      reloadDashboardSignals(),
    ]);
    setRefreshing(false);
  };

  useInterval(reloadAll, 30000);
  useInterval(() => setNowMs(Date.now()), 60000);

  // NOC wall rotate & Escape exit
  useEffect(() => {
    if (!nocMode) return;
    const esc = (e) => {
      if (e.key === 'Escape') {
        document.exitFullscreen?.().catch(() => {});
        setNocMode(false);
      }
    };
    const onFullscreenChange = () => {
      if (!document.fullscreenElement) setNocMode(false);
    };
    window.addEventListener('keydown', esc);
    document.addEventListener('fullscreenchange', onFullscreenChange);
    const rotateId = setInterval(() => setNocWidget((p) => p + 1), 30000);
    return () => {
      window.removeEventListener('keydown', esc);
      document.removeEventListener('fullscreenchange', onFullscreenChange);
      clearInterval(rotateId);
    };
  }, [nocMode]);

  const alertList = useMemo(
    () => (Array.isArray(alertData) ? alertData : alertData?.alerts || []),
    [alertData],
  );
  const critical = alertList.filter((a) => alertSeverity(a) === 'critical').length;
  const elevated = alertList.filter((a) =>
    ['elevated', 'severe', 'high'].includes(alertSeverity(a)),
  ).length;

  // Severity breakdown for pie chart
  const sevBreakdown = useMemo(() => {
    const counts = {};
    alertList.forEach((a) => {
      const s = alertSeverity(a);
      counts[s] = (counts[s] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [alertList]);

  // Alert timeline data (last 24 hours bucketed into ~12 intervals)
  const alertTimeline = useMemo(() => {
    if (!alertList.length) return [];
    const buckets = 12;
    const interval = 2 * 60 * 60 * 1000; // 2 hours
    const data = [];
    for (let i = buckets - 1; i >= 0; i--) {
      const start = nowMs - (i + 1) * interval;
      const end = nowMs - i * interval;
      const count = alertList.filter((a) => {
        const t = new Date(a.timestamp || a.time || 0).getTime();
        return t >= start && t < end;
      }).length;
      const label = new Date(end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      data.push({ time: label, alerts: count });
    }
    return data;
  }, [alertList, nowMs]);

  // Telemetry history for area chart
  const telemChart = useMemo(() => {
    if (!telemHistory) return [];
    const arr = Array.isArray(telemHistory)
      ? telemHistory
      : telemHistory?.samples || telemHistory?.history || [];
    return arr.slice(-30).map((s, i) => ({
      t: i,
      cpu: s.cpu_load_pct ?? s.cpu,
      mem: s.memory_load_pct ?? s.memory,
      net: s.network_kbps ?? s.network,
    }));
  }, [telemHistory]);

  // Filtered alerts
  const filteredAlerts = useMemo(
    () =>
      sevFilter === 'all' ? alertList : alertList.filter((a) => alertSeverity(a) === sevFilter),
    [alertList, sevFilter],
  );
  const collectorList = useMemo(
    () => (Array.isArray(collectorsStatus?.collectors) ? collectorsStatus.collectors : []),
    [collectorsStatus],
  );
  const enabledCollectors = useMemo(
    () => collectorList.filter((collector) => collector.enabled),
    [collectorList],
  );
  const collectorFreshnessCounts = useMemo(() => {
    return enabledCollectors.reduce((counts, collector) => {
      const key = collector.freshness || 'unknown';
      counts[key] = (counts[key] || 0) + 1;
      return counts;
    }, {});
  }, [enabledCollectors]);
  const degradedCollectors = useMemo(
    () => enabledCollectors.filter((collector) => ['error', 'stale'].includes(collector.freshness)),
    [enabledCollectors],
  );
  const totalCollectorEvents = useMemo(
    () =>
      enabledCollectors.reduce((sum, collector) => sum + Number(collector.events_ingested || 0), 0),
    [enabledCollectors],
  );
  const atRiskCollectors = useMemo(() => {
    return [...enabledCollectors].sort((left, right) => {
      const freshnessDelta =
        collectorFreshnessRank(right.freshness) - collectorFreshnessRank(left.freshness);
      if (freshnessDelta !== 0) return freshnessDelta;
      const lagDelta = Number(right.lag_seconds || 0) - Number(left.lag_seconds || 0);
      if (lagDelta !== 0) return lagDelta;
      return Number(right.retry_count || 0) - Number(left.retry_count || 0);
    });
  }, [enabledCollectors]);
  const topCollector = atRiskCollectors[0] || null;
  const selectedAlert =
    expandedAlert == null
      ? null
      : filteredAlerts.find((a, i) => (a.id || a.alert_id || `alert-${i}`) === expandedAlert);
  const openProcess = (process) => setSelectedProcess(process ? { ...process } : null);
  const staleAlerts = useMemo(
    () =>
      alertList.filter((alert) => {
        const timestamp = new Date(alert.timestamp || alert.time || 0).getTime();
        return timestamp > 0 && nowMs - timestamp > 30 * 60 * 1000;
      }),
    [alertList, nowMs],
  );
  const priorityAlerts = useMemo(
    () =>
      [...alertList]
        .sort((left, right) => {
          const severityRank = { critical: 4, severe: 3, elevated: 2, high: 2, medium: 1, low: 0 };
          return (
            (severityRank[alertSeverity(right)] || 0) - (severityRank[alertSeverity(left)] || 0)
          );
        })
        .slice(0, 5),
    [alertList],
  );
  const leadPriorityAlert = priorityAlerts[0] || filteredAlerts[0] || alertList[0] || null;
  const dashboardReportTarget = alertReportTarget(leadPriorityAlert);
  const dashboardReportTab = (respStats?.pending ?? 0) > 0 ? 'delivery' : 'evidence';
  const dashboardReportSubject = dashboardReportTarget || 'the current priority stack';
  const situationCards = [
    {
      title: 'Critical Now',
      value: formatNumber(critical),
      detail:
        critical > 0
          ? `${critical} alert${critical === 1 ? '' : 's'} need immediate review.`
          : 'No critical alerts are active.',
      action: 'Open Live Monitor',
      onAction: () => navigate('/monitor?sev=critical'),
    },
    {
      title: 'Stale Untriaged',
      value: formatNumber(staleAlerts.length),
      detail:
        staleAlerts.length > 0
          ? 'Older than 30 minutes and still visible in the queue.'
          : 'No alerts are waiting beyond the stale threshold.',
      action: 'Open SOC Workbench',
      onAction: () => navigate('/soc'),
    },
    {
      title: 'Response Pending Approval',
      value: formatNumber(respStats?.pending ?? 0),
      detail:
        (respStats?.pending ?? 0) > 0
          ? 'Response actions are waiting for operator approval.'
          : 'No response actions are blocked right now.',
      action: 'Review Response',
      onAction: () => navigate('/soc#response'),
    },
  ];
  const coverageGapCount = Array.isArray(gaps?.gaps)
    ? gaps.gaps.length
    : Array.isArray(gaps)
      ? gaps.length
      : 0;
  const workflowItems = [
    {
      id: 'soc-triage',
      title: 'Open SOC Triage',
      description: `${critical} critical and ${staleAlerts.length} stale alerts are ready for queue or case coordination.`,
      to: '/soc#queue',
      minRole: 'analyst',
      tone: 'primary',
      badge: 'Triage',
    },
    {
      id: 'threat-detection',
      title: 'Tune Detection Coverage',
      description: `${coverageGapCount} ATT&CK gaps and ${tiStatus?.ioc_count || 0} tracked indicators can be pulled straight into detection review.`,
      to: buildHref('/detection', { params: { queue: 'noisy' } }),
      minRole: 'analyst',
      badge: 'Detect',
    },
    {
      id: 'infrastructure',
      title: 'Review Critical Assets',
      description:
        'Use infrastructure queues to validate drift, malware, and observability hotspots behind the current posture.',
      to: buildHref('/infrastructure', { params: { tab: 'assets', view: 'critical' } }),
      minRole: 'analyst',
      badge: 'Asset',
    },
    {
      id: 'attack-graph',
      title: 'Map Campaign Paths',
      description: 'Check whether the priority stack is part of a broader lateral-movement chain.',
      to: '/attack-graph',
      minRole: 'analyst',
      badge: 'Graph',
    },
    {
      id: 'reports',
      title: 'Package Evidence',
      description:
        dashboardReportTab === 'delivery'
          ? `Package response posture and evidence for ${dashboardReportSubject} into delivery workflows.`
          : `Export evidence, compliance posture, and delivery artifacts for ${dashboardReportSubject}.`,
      to: buildHref('/reports', {
        params: {
          tab: dashboardReportTab,
          source: 'dashboard',
          target: dashboardReportTarget || undefined,
        },
      }),
      minRole: 'viewer',
      badge: 'Report',
    },
  ];

  if (l1)
    return (
      <div style={{ padding: 20 }}>
        <SkeletonCard height={60} />
        <SkeletonCard height={120} />
        <SkeletonCard height={80} />
        <SkeletonCard height={200} />
      </div>
    );

  return (
    <div>
      <div className="section-header">
        <h2>Security Overview</h2>
        <div className="btn-group">
          {hostInf && (
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {hostInf.hostname} · {hostInf.platform} {hostInf.os_version} · {hostInf.arch}
            </span>
          )}
          <button className="btn btn-sm" onClick={reloadAll} disabled={refreshing}>
            {refreshing ? 'Refreshing…' : '↻ Refresh'}
          </button>
          <button className="btn btn-sm" onClick={resetLayout} title="Reset widget layout">
            ⊞ Reset Layout
          </button>
          <button
            className="btn btn-sm"
            onClick={() => {
              setNocMode(true);
              document.documentElement.requestFullscreen?.().catch(() => {});
            }}
            title="NOC wall display (fullscreen)"
          >
            📺 NOC
          </button>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <span className="card-title">Dashboard Layout Presets</span>
          <span className="badge badge-info">
            {savedPresets.length} personal • {SHARED_DASHBOARD_PRESETS.length} shared
          </span>
        </div>
        <div className="summary-grid" style={{ marginBottom: 12 }}>
          <div className="summary-card">
            <div className="summary-label">Selected Layout</div>
            <div className="summary-value">{activePreset?.name || 'Custom Layout'}</div>
            <div className="summary-meta">
              {activePreset?.description ||
                'The current widget order is running from local layout state.'}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Audience</div>
            <div className="summary-value">
              {activePreset?.audience || (isSavedPresetKey(selectedPresetKey) ? 'personal' : role)}
            </div>
            <div className="summary-meta">
              Recommended shared preset for this role:{' '}
              {role === 'admin' ? 'Admin Operations' : 'Analyst Triage'}.
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Hidden Widgets</div>
            <div className="summary-value">{hidden.size}</div>
            <div className="summary-meta">
              Hidden widgets remain restorable below the dashboard grid.
            </div>
          </div>
        </div>
        <div className="triage-toolbar" style={{ marginBottom: 10 }}>
          <div className="triage-toolbar-group" style={{ flexWrap: 'wrap' }}>
            <select
              className="form-select"
              aria-label="Dashboard preset"
              value={selectedPresetKey}
              onChange={(event) => setSelectedPresetKey(event.target.value)}
            >
              {presetOptions.map((option) => (
                <option key={option.key} value={option.key}>
                  {option.label}
                </option>
              ))}
            </select>
            <button className="btn btn-sm" onClick={applySelectedPreset} disabled={savingPreset}>
              Apply Preset
            </button>
            {isSavedPresetKey(selectedPresetKey) && (
              <button className="btn btn-sm" onClick={deleteSelectedPreset} disabled={savingPreset}>
                Delete Preset
              </button>
            )}
          </div>
          <div className="triage-toolbar-group" style={{ flexWrap: 'wrap' }}>
            <input
              className="form-input"
              aria-label="Preset name"
              value={presetName}
              placeholder="Save current layout as…"
              onChange={(event) => setPresetName(event.target.value)}
            />
            <button
              className="btn btn-sm btn-primary"
              onClick={saveCurrentPreset}
              disabled={savingPreset}
            >
              {savingPreset ? 'Saving…' : 'Save Current Layout'}
            </button>
          </div>
        </div>
        <div className="hint">
          Shared presets give analysts and admins a consistent starting point. Personal presets sync
          through the user preferences API so your layout survives new sessions.
        </div>
      </div>

      <div className="situation-grid">
        {situationCards.map((card) => (
          <article key={card.title} className="situation-card">
            <div className="situation-eyebrow">{card.title}</div>
            <div className="situation-value">{card.value}</div>
            <p className="situation-copy">{card.detail}</p>
            <button className="btn btn-sm btn-primary" onClick={card.onAction}>
              {card.action}
            </button>
          </article>
        ))}
      </div>

      <WorkflowGuidance
        title="Console Pivots"
        description="Use the overview to jump directly into the next operator workflow instead of re-finding the same context in each workspace."
        items={workflowItems}
      />

      <div className="card priority-stack">
        <div className="card-header">
          <span className="card-title">Priority Stack</span>
          <span className="hint">Updated {formatRelativeTime(new Date())}</span>
        </div>
        {priorityAlerts.length === 0 ? (
          <div className="empty">No alerts are waiting in the priority stack.</div>
        ) : (
          <div className="priority-stack-list">
            {priorityAlerts.map((alert, index) => {
              const alertId = alert.id || alert.alert_id || `priority-${index}`;
              return (
                <button
                  key={alertId}
                  type="button"
                  className="priority-stack-item"
                  onClick={() => setExpandedAlert(alertId)}
                >
                  <div className="priority-stack-main">
                    <span
                      className={`badge ${alertSeverity(alert) === 'critical' ? 'badge-err' : 'badge-warn'}`}
                    >
                      {alertSeverity(alert)}
                    </span>
                    <span className="priority-stack-title">{alertCategory(alert)}</span>
                  </div>
                  <div className="priority-stack-copy">{alertNarrative(alert)}</div>
                  <div className="priority-stack-meta">
                    {formatRelativeTime(alert.timestamp || alert.time)} ·{' '}
                    {formatDateTime(alert.timestamp || alert.time)}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* ── NOC Wall Display ─────────── */}
      {nocMode &&
        (() => {
          const nocWidgets = order.filter((w) => !hidden.has(w));
          const idx = nocWidget % Math.max(nocWidgets.length, 1);
          const wid = nocWidgets[idx] || nocWidgets[0];
          return (
            <div className="noc-wall" onClick={() => setNocWidget((p) => p + 1)}>
              <div className="noc-header">
                <span>Wardex NOC — {new Date().toLocaleString()}</span>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                  <span style={{ fontSize: 16, opacity: 0.6 }}>
                    {idx + 1}/{nocWidgets.length}
                  </span>
                  <button
                    className="btn btn-sm"
                    style={{ fontSize: 14 }}
                    onClick={(e) => {
                      e.stopPropagation();
                      document.exitFullscreen?.().catch(() => {});
                      setNocMode(false);
                    }}
                  >
                    ✕ Exit
                  </button>
                </div>
              </div>
              <div className="noc-body">
                <div className="card-grid" style={{ fontSize: 18 }}>
                  <Metric
                    label="System Status"
                    value={hp?.status === 'ok' ? '✓ Healthy' : hp?.status || '—'}
                    sub={`Uptime: ${st?.uptime || '—'}`}
                    accent
                  />
                  <Metric
                    label="Active Agents"
                    value={fleetSummary?.total_agents ?? fleet?.agents ?? '—'}
                    sub={fleetOnline ? `${fleetOnline} online` : undefined}
                  />
                  <Metric
                    label="Total Alerts"
                    value={alertList.length}
                    sub={`${critical} critical · ${elevated} elevated`}
                  />
                  <Metric label="Events/sec" value={telem?.events_per_sec ?? telem?.rate ?? '—'} />
                </div>
              </div>
              <div className="noc-footer">
                Widget: {wid?.replace(/-/g, ' ')} — Click to advance · ESC to exit
              </div>
            </div>
          );
        })()}

      {order.map((wid) => {
        const widgetPaused = pausedWidgets.has(wid);
        if (wid === 'system-health')
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="System Health"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card-grid">
                <Metric
                  label="System Status"
                  value={hp?.status === 'ok' ? '✓ Healthy' : hp?.status || '—'}
                  sub={`Uptime: ${st?.uptime || '—'}`}
                  accent
                />
                <Metric
                  label="Active Agents"
                  value={fleetSummary?.total_agents ?? fleet?.agents ?? '—'}
                  sub={fleetOnline ? `${fleetOnline} online` : undefined}
                />
                <Metric
                  label="Events/sec"
                  value={telem?.events_per_sec ?? telem?.rate ?? '—'}
                  sub={telem?.total_events ? `Total: ${telem.total_events}` : undefined}
                  tip="Telemetry ingest rate from all connected agents"
                />
                <Metric
                  label="Queue Pending"
                  value={qStats?.pending ?? qStats?.total ?? '—'}
                  sub={qStats?.assigned ? `${qStats.assigned} assigned` : undefined}
                />
              </div>
            </DashboardWidget>
          );
        if (wid === 'collector-health' && collectorList.length > 0)
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="Collector Health"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card-grid">
                <Metric
                  label="Fresh Collectors"
                  value={collectorFreshnessCounts.fresh ?? 0}
                  sub={
                    enabledCollectors.length
                      ? `${enabledCollectors.length} enabled`
                      : 'None enabled'
                  }
                />
                <Metric
                  label="Degraded"
                  value={degradedCollectors.length}
                  sub={`${collectorFreshnessCounts.error ?? 0} error · ${collectorFreshnessCounts.stale ?? 0} stale`}
                  accent={degradedCollectors.length > 0}
                />
                <Metric
                  label="Max Lag"
                  value={formatLagDuration(topCollector?.lag_seconds)}
                  sub={
                    topCollector
                      ? `${topCollector.label} ${topCollector.freshness}`
                      : 'No collector lag'
                  }
                  accent={collectorFreshnessRank(topCollector?.freshness) > 0}
                />
                <Metric
                  label="Events Ingested"
                  value={formatNumber(totalCollectorEvents)}
                  sub={`${enabledCollectors.filter((collector) => Number(collector.events_ingested || 0) > 0).length} collectors reporting`}
                />
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: 12,
                  marginTop: 16,
                }}
              >
                {(degradedCollectors.length > 0 ? degradedCollectors : atRiskCollectors)
                  .slice(0, 3)
                  .map((collector) => {
                    const pivots = Array.isArray(collector.ingestion_evidence?.pivots)
                      ? collector.ingestion_evidence.pivots
                      : [];
                    const readinessTimeline = Array.isArray(collector.timeline)
                      ? collector.timeline
                      : [];
                    const lifecycleAnalytics = collector.lifecycle_analytics || {};
                    const successRate = Math.round(
                      Number(lifecycleAnalytics.success_rate || 0) * 100,
                    );
                    return (
                      <div key={collector.name} className="card">
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                          <div>
                            <div className="card-title">{collector.label}</div>
                            <div className="hint">{collector.lane || collector.provider}</div>
                          </div>
                          <span
                            className={`badge ${collector.freshness === 'fresh' ? 'badge-ok' : collector.freshness === 'error' ? 'badge-err' : 'badge-warn'}`}
                          >
                            {collector.freshness}
                          </span>
                        </div>
                        <div className="chip-row" style={{ marginTop: 8 }}>
                          <span className="scope-chip">
                            Lag {formatLagDuration(collector.lag_seconds)}
                          </span>
                          <span className="scope-chip">Retries {collector.retry_count ?? 0}</span>
                          {collector.backoff_seconds ? (
                            <span className="scope-chip">
                              Backoff {formatLagDuration(collector.backoff_seconds)}
                            </span>
                          ) : null}
                        </div>
                        <div className="chip-row" style={{ marginTop: 8 }}>
                          <span className="scope-chip">Success {successRate}%</span>
                          <span className="scope-chip">
                            24h events {formatNumber(lifecycleAnalytics.events_last_24h ?? 0)}
                          </span>
                          {(lifecycleAnalytics.recent_failure_streak ?? 0) > 0 ? (
                            <span className="scope-chip">
                              Failure streak {lifecycleAnalytics.recent_failure_streak}
                            </span>
                          ) : null}
                        </div>
                        {Array.isArray(collector.route_targets) &&
                          collector.route_targets.length > 0 && (
                            <div className="chip-row" style={{ marginTop: 8 }}>
                              {collector.route_targets.map((target) => (
                                <span key={target} className="scope-chip">
                                  {target}
                                </span>
                              ))}
                            </div>
                          )}
                        <div className="hint" style={{ marginTop: 8 }}>
                          {collector.last_error_at
                            ? `Last error ${formatRelativeTime(collector.last_error_at)}`
                            : collector.last_success_at
                              ? `Last success ${formatRelativeTime(collector.last_success_at)}`
                              : 'No successful run recorded yet.'}
                        </div>
                        {pivots.length > 0 && (
                          <div className="btn-group" style={{ marginTop: 12 }}>
                            {pivots.slice(0, 2).map((pivot) => (
                              <button
                                key={pivot.href}
                                className="btn btn-sm"
                                onClick={() => navigate(pivot.href)}
                              >
                                {pivot.label || 'Open collector context'}
                              </button>
                            ))}
                          </div>
                        )}
                        {readinessTimeline.length > 0 && (
                          <div style={{ marginTop: 14 }}>
                            <div className="hint" style={{ marginBottom: 8 }}>
                              Readiness timeline
                            </div>
                            <div className="timeline">
                              {readinessTimeline.slice(0, 4).map((entry, index) => (
                                <div
                                  key={`${collector.name}-${entry.stage || entry.title}-${index}`}
                                  className="timeline-event"
                                >
                                  <div className="timeline-marker">
                                    <span
                                      className={`timeline-dot ${collectorTimelineSeverityClass(entry.status)}`}
                                    />
                                    {index < readinessTimeline.slice(0, 4).length - 1 ? (
                                      <span className="timeline-line" />
                                    ) : null}
                                  </div>
                                  <div className="timeline-body" style={{ cursor: 'default' }}>
                                    <div className="timeline-header">
                                      <strong>
                                        {entry.title || entry.stage || 'Collector stage'}
                                      </strong>
                                      <span className="timeline-sev">{entry.status || 'info'}</span>
                                    </div>
                                    <div className="hint" style={{ marginTop: 8 }}>
                                      {entry.detail ||
                                        'No detail published for this collector stage yet.'}
                                    </div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
              </div>
            </DashboardWidget>
          );
        if (wid === 'telemetry' && telemChart.length > 0)
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="System Telemetry"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card" style={{ padding: '12px 8px', marginBottom: 16 }}>
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart data={telemChart}>
                    <XAxis dataKey="t" tick={false} />
                    <YAxis width={35} tick={{ fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{
                        background: 'var(--card-bg)',
                        border: '1px solid var(--border)',
                        borderRadius: 6,
                        fontSize: 12,
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="cpu"
                      name="CPU %"
                      stroke="#3b82f6"
                      fill="#3b82f680"
                      strokeWidth={2}
                    />
                    <Area
                      type="monotone"
                      dataKey="mem"
                      name="Memory %"
                      stroke="#8b5cf6"
                      fill="#8b5cf680"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </DashboardWidget>
          );
        if (wid === 'threat-overview')
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="Threat Overview"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card-grid">
                <Metric
                  label="Total Alerts"
                  value={alertList.length}
                  sub={`${critical} critical · ${elevated} elevated`}
                />
                <Metric
                  label="Detection Profile"
                  value={profile?.profile || '—'}
                  sub={profile?.description}
                  tip="Active anomaly detection sensitivity — aggressive, balanced, or quiet"
                />
                <Metric
                  label="Threat Intel IoCs"
                  value={tiStatus?.total_iocs ?? tiStatus?.ioc_count ?? '—'}
                  sub={tiStatus?.active_feeds ? `${tiStatus.active_feeds} feeds` : undefined}
                />
                <Metric
                  label="Response Actions"
                  value={respStats?.total ?? '—'}
                  sub={respStats?.pending ? `${respStats.pending} pending` : undefined}
                />
              </div>
            </DashboardWidget>
          );
        if (wid === 'charts' && (alertTimeline.length > 0 || sevBreakdown.length > 0))
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="Alert Charts"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card-grid" style={{ marginTop: 12, marginBottom: 16 }}>
                {alertTimeline.length > 0 && (
                  <div
                    className="card"
                    style={{
                      padding: '12px 8px',
                      gridColumn: sevBreakdown.length > 0 ? 'span 2' : 'span 3',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 8, paddingLeft: 8 }}>
                      Alert Timeline (24h)
                    </div>
                    <ResponsiveContainer width="100%" height={140}>
                      <BarChart data={alertTimeline}>
                        <XAxis dataKey="time" tick={{ fontSize: 10 }} interval={1} />
                        <YAxis width={25} tick={{ fontSize: 10 }} allowDecimals={false} />
                        <Tooltip
                          contentStyle={{
                            background: 'var(--card-bg)',
                            border: '1px solid var(--border)',
                            borderRadius: 6,
                            fontSize: 12,
                          }}
                        />
                        <Bar dataKey="alerts" fill="#3b82f6" radius={[3, 3, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
                {sevBreakdown.length > 0 && (
                  <div className="card" style={{ padding: '12px 8px' }}>
                    <div className="card-title" style={{ marginBottom: 8, paddingLeft: 8 }}>
                      By Severity
                    </div>
                    <div aria-hidden="true">
                      <ResponsiveContainer width="100%" height={140}>
                        <PieChart>
                          <Pie
                            data={sevBreakdown}
                            cx="50%"
                            cy="50%"
                            outerRadius={50}
                            innerRadius={25}
                            paddingAngle={2}
                            dataKey="value"
                            label={({ name, value }) => `${name} (${value})`}
                            style={{ fontSize: 10 }}
                          >
                            {sevBreakdown.map((entry, i) => (
                              <Cell key={i} fill={SEV_COLORS[entry.name] || '#6b7280'} />
                            ))}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}
              </div>
            </DashboardWidget>
          );
        if (wid === 'process-security' && procAnalysis)
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="Process Security"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="card-header">
                  <span className="card-title">
                    Process Analysis — {procAnalysis.process_count || 0} running
                  </span>
                  <span
                    className={`badge ${procAnalysis.status === 'clean' ? 'badge-ok' : procAnalysis.status === 'critical' ? 'badge-err' : 'badge-warn'}`}
                  >
                    {procAnalysis.status === 'clean'
                      ? '✓ Clean'
                      : `⚠ ${procAnalysis.total || 0} finding(s)`}
                  </span>
                </div>
                {procAnalysis.findings?.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>PID</th>
                          <th>Process</th>
                          <th>User</th>
                          <th>Risk</th>
                          <th>Reason</th>
                          <th>CPU%</th>
                          <th>Mem%</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {procAnalysis.findings.map((f, i) => (
                          <tr key={i} style={{ cursor: 'pointer' }} onClick={() => openProcess(f)}>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                              {f.pid}
                            </td>
                            <td>
                              <strong>{f.name}</strong>
                            </td>
                            <td>{f.user}</td>
                            <td>
                              <span className={`sev-${f.risk_level}`}>{f.risk_level}</span>
                            </td>
                            <td style={{ fontSize: 12 }}>{f.reason}</td>
                            <td>{f.cpu_percent?.toFixed(1)}</td>
                            <td>{f.mem_percent?.toFixed(1)}</td>
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
                ) : (
                  <div className="empty" style={{ padding: 12 }}>
                    No suspicious processes detected
                  </div>
                )}
              </div>
            </DashboardWidget>
          );
        if (wid === 'detection-engine' && detSum)
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="Detection Engine"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="card-header">
                  <span className="card-title">Detection Summary</span>
                </div>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
                    gap: 10,
                    padding: '12px 0',
                  }}
                >
                  {Object.entries(detSum)
                    .filter(([k]) => typeof detSum[k] !== 'object')
                    .map(([k, v]) => (
                      <div key={k} style={{ textAlign: 'center' }}>
                        <div className="metric-label">{k.replace(/_/g, ' ')}</div>
                        <div style={{ fontSize: 18, fontWeight: 600 }}>
                          {typeof v === 'boolean' ? (v ? '✓' : '✗') : v}
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </DashboardWidget>
          );
        if (wid === 'malware-ti')
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="Malware & Threat Intelligence"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card-grid">
                <Metric
                  label="Malware DB"
                  value={mwStats?.database?.total_entries ?? '—'}
                  sub={
                    mwStats?.scanner?.total_scans
                      ? `${mwStats.scanner.total_scans} scans`
                      : undefined
                  }
                />
                <Metric
                  label="YARA Rules"
                  value={mwStats?.yara_rules ?? '—'}
                  sub={
                    mwStats?.scanner?.malicious_count
                      ? `${mwStats.scanner.malicious_count} detections`
                      : undefined
                  }
                />
                <Metric
                  label="Quarantined"
                  value={qrStats?.total ?? '—'}
                  sub={
                    qrStats?.pending_review ? `${qrStats.pending_review} pending review` : undefined
                  }
                  accent={qrStats?.total > 0}
                />
                <Metric
                  label="Feed Sources"
                  value={fdStats?.total_sources ?? '—'}
                  sub={fdStats?.active_sources ? `${fdStats.active_sources} active` : undefined}
                />
              </div>
            </DashboardWidget>
          );
        if (wid === 'dns-threats')
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="DNS Threat Intelligence"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card-grid">
                <Metric
                  label="Domains Analyzed"
                  value={dnsSummary?.domains_analyzed ?? '—'}
                  sub={
                    dnsSummary?.threats_detected
                      ? `${dnsSummary.threats_detected} threats`
                      : undefined
                  }
                />
                <Metric
                  label="DGA Suspects"
                  value={dnsSummary?.dga_suspects ?? '—'}
                  accent={dnsSummary?.dga_suspects > 0}
                  tip="Domains flagged by the DGA detection algorithm"
                />
                <Metric
                  label="Tunnel Suspects"
                  value={dnsSummary?.tunnel_suspects ?? '—'}
                  accent={dnsSummary?.tunnel_suspects > 0}
                />
                <Metric
                  label="Fast-Flux"
                  value={dnsSummary?.fast_flux_suspects ?? '—'}
                  accent={dnsSummary?.fast_flux_suspects > 0}
                />
              </div>
            </DashboardWidget>
          );
        if (wid === 'lifecycle' && (lcStats || gaps))
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="Fleet Lifecycle & Coverage"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card-grid">
                {lcStats && (
                  <Metric
                    label="Active Agents"
                    value={lcStats.active ?? '—'}
                    sub={
                      lcStats.stale
                        ? `${lcStats.stale} stale · ${lcStats.offline ?? 0} offline`
                        : undefined
                    }
                  />
                )}
                {lcStats && (
                  <Metric
                    label="Archived"
                    value={lcStats.archived ?? 0}
                    sub={
                      lcStats.decommissioned
                        ? `${lcStats.decommissioned} decommissioned`
                        : undefined
                    }
                  />
                )}
                {gaps && (
                  <Metric
                    label="ATT&CK Gaps"
                    value={gaps.total_gaps ?? gaps.gaps?.length ?? '—'}
                    sub={gaps.critical_gaps != null ? `${gaps.critical_gaps} critical` : undefined}
                    accent={gaps.total_gaps > 0 || gaps.gaps?.length > 0}
                  />
                )}
                {fdStats && (
                  <Metric
                    label="IoCs Ingested"
                    value={fdStats.total_iocs_ingested ?? '—'}
                    sub={
                      fdStats.total_hashes_imported
                        ? `${fdStats.total_hashes_imported} hashes`
                        : undefined
                    }
                  />
                )}
              </div>
            </DashboardWidget>
          );
        if (wid === 'manager-digest' && managerDigest)
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="Morning Brief"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card-grid">
                <Metric
                  label="Pending Queue"
                  value={managerDigest.queue?.pending ?? '—'}
                  sub={
                    managerDigest.queue?.sla_breached
                      ? `${managerDigest.queue.sla_breached} past SLA`
                      : 'No SLA breaches'
                  }
                  accent={managerDigest.queue?.sla_breached > 0}
                />
                <Metric
                  label="Stale Cases"
                  value={managerDigest.stale_cases ?? '—'}
                  sub="Open cases with no recent analyst update"
                  accent={managerDigest.stale_cases > 0}
                />
                <Metric
                  label="Degraded Collectors"
                  value={managerDigest.degraded_collectors ?? '—'}
                  sub="Agents currently stale or offline"
                  accent={managerDigest.degraded_collectors > 0}
                />
                <Metric
                  label="Dry-Run Approvals"
                  value={managerDigest.pending_dry_run_approvals ?? '—'}
                  sub={
                    managerDigest.ready_to_execute
                      ? `${managerDigest.ready_to_execute} ready to execute`
                      : undefined
                  }
                />
              </div>
              <div
                style={{
                  display: 'grid',
                  gap: 12,
                  gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                  marginTop: 16,
                }}
              >
                <div className="card">
                  <div className="card-title" style={{ marginBottom: 8 }}>
                    What Changed
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7, fontSize: 13 }}>
                    {(managerDigest.changes_since_last_shift || [])
                      .slice(0, 4)
                      .map((item, index) => (
                        <li key={index}>{item}</li>
                      ))}
                  </ul>
                </div>
                <div className="card">
                  <div className="card-title" style={{ marginBottom: 8 }}>
                    Noisy Reasons
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7, fontSize: 13 }}>
                    {(managerDigest.noisy_reasons || []).slice(0, 4).map((item, index) => (
                      <li key={index}>{item}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </DashboardWidget>
          );
        if (wid === 'recent-alerts')
          return (
            <DashboardWidget
              key={wid}
              id={wid}
              title="Recent Alerts"
              index={order.indexOf(wid)}
              onMove={moveWidget}
              onRemove={removeWidget}
              paused={widgetPaused}
              onTogglePause={toggleWidgetRefresh}
            >
              <div className="card">
                <div className="card-header">
                  <span className="card-title">
                    Latest ({Math.min(filteredAlerts.length, 25)} of {alertList.length})
                  </span>
                  <div className="btn-group">
                    {['all', 'critical', 'severe', 'elevated', 'low'].map((s) => (
                      <button
                        key={s}
                        className={`btn btn-sm ${sevFilter === s ? 'btn-primary' : ''}`}
                        onClick={() => setSevFilter(s)}
                      >
                        {s.charAt(0).toUpperCase() + s.slice(1)}
                      </button>
                    ))}
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={async () => {
                        try {
                          await api.alertsClear();
                          toast('Alerts cleared', 'success');
                          reloadDashboardAlerts();
                        } catch {
                          toast('Failed to clear alerts', 'error');
                        }
                      }}
                    >
                      Clear All
                    </button>
                  </div>
                </div>
                {filteredAlerts.length === 0 ? (
                  <div className="empty">
                    No alerts{sevFilter !== 'all' ? ` matching "${sevFilter}"` : ''} — system is
                    quiet
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Severity</th>
                          <th>Category</th>
                          <th>Message</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredAlerts.slice(0, 25).map((a, i) => {
                          const aid = a.id || a.alert_id || `alert-${i}`;
                          return (
                            <tr
                              key={aid}
                              style={{
                                cursor: 'pointer',
                                background:
                                  expandedAlert === aid ? 'rgba(59,130,246,.08)' : undefined,
                              }}
                              onClick={() => setExpandedAlert(aid)}
                            >
                              <td
                                style={{
                                  whiteSpace: 'nowrap',
                                  fontFamily: 'var(--font-mono)',
                                  fontSize: 12,
                                }}
                              >
                                {a.timestamp || a.time || '—'}
                              </td>
                              <td>
                                <span className={`sev-${alertSeverity(a)}`}>
                                  {alertSeverity(a)}
                                </span>
                              </td>
                              <td>{alertCategory(a)}</td>
                              <td style={{ fontSize: 13 }}>{alertNarrative(a)}</td>
                              <td>
                                <button
                                  className="btn btn-sm"
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    setExpandedAlert(aid);
                                  }}
                                >
                                  Investigate
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </DashboardWidget>
          );
        return null;
      })}

      {/* Restore removed widgets */}
      {hidden.size > 0 && (
        <div
          style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}
        >
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Hidden widgets:</span>
          {[...hidden].map((w) => (
            <button key={w} className="btn btn-sm" onClick={() => restoreWidget(w)}>
              + {w.replace(/-/g, ' ')}
            </button>
          ))}
        </div>
      )}

      <AlertDrawer
        alert={selectedAlert}
        onClose={() => setExpandedAlert(null)}
        onUpdated={reloadAll}
        onSelectProcess={(process) => {
          setExpandedAlert(null);
          setSelectedProcess(process ? { ...process } : null);
        }}
      />
      <ProcessDrawer
        pid={selectedProcess?.pid}
        snapshot={selectedProcess}
        onClose={() => setSelectedProcess(null)}
        onUpdated={reloadAll}
        onSelectProcess={(process) => setSelectedProcess(process ? { ...process } : null)}
      />
    </div>
  );
}

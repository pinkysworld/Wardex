import { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApi, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import ProcessDrawer from './ProcessDrawer.jsx';
import { JsonDetails, SummaryGrid } from './operator.jsx';
import InvestigationTimeline from './InvestigationTimeline.jsx';
import { downloadData, formatDateTime, formatRelativeTime } from './operatorUtils.js';

import PlaybookEditor from './PlaybookEditor.jsx';

// ── Tab Groups ─────────────────────────────────────────────────
const TAB_GROUPS = [
  { label: 'Triage', tabs: ['overview', 'incidents', 'queue', 'entity'] },
  {
    label: 'Investigate',
    tabs: [
      'cases',
      'investigations',
      'process-tree',
      'timeline',
      'investigation-timeline',
      'campaigns',
      'analyst',
    ],
  },
  { label: 'Respond', tabs: ['response', 'escalation', 'playbooks', 'rbac'] },
  { label: 'Measure', tabs: ['efficacy'] },
];

// ── Investigation Checklist Templates ──────────────────────────
const CHECKLIST_TEMPLATES = {
  ransomware: [
    'Isolate affected hosts from network',
    'Identify ransomware family and variant',
    'Check for data exfiltration before encryption',
    'Locate backup integrity and availability',
    'Engage incident response team and legal',
  ],
  credential_storm: [
    'Identify targeted accounts and lock compromised ones',
    'Trace source IPs and check for VPN/proxy usage',
    'Review auth logs for successful logins post-spray',
    'Reset credentials for affected accounts',
  ],
  lateral_movement: [
    'Map affected hosts via process tree analysis',
    'Identify initial access vector',
    'Check for persistence mechanisms installed',
    'Verify no data staging or exfil activity',
  ],
  c2_beacon: [
    'Identify C2 domain/IP and block at firewall',
    'Locate all hosts communicating with C2',
    'Analyze beacon interval and protocol',
    'Check for secondary payloads downloaded',
  ],
  container_escape: [
    'Identify escaped container and host impact',
    'Check for privilege escalation on host',
    'Review container runtime configuration',
  ],
};

const buildPlannerReasons = (context) =>
  [
    context?.title,
    context?.summary,
    context?.message,
    context?.description,
    context?.severity,
    context?.reason,
    context?.rule_id,
    ...(Array.isArray(context?.tags) ? context.tags : []),
    ...(Array.isArray(context?.reasons) ? context.reasons : []),
  ].filter(Boolean);

const buildPlannerHuntQuery = (context) => {
  const severity = context?.severity ? `severity:${String(context.severity).toLowerCase()}` : '';
  const terms = [
    context?.rule_id,
    context?.title,
    context?.summary,
    context?.message,
    context?.host,
    context?.agent_id,
  ].filter(Boolean);
  return [severity, ...terms].join(' ').trim() || 'severity:high';
};

const buildPlannerHuntName = (context) => {
  const label = context?.title || context?.summary || context?.message || context?.id || 'Signal';
  return `Hunt ${label}`;
};

const formatPct = (value) => `${Math.round((Number(value) || 0) * 100)}%`;

const formatMs = (value) => {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? `${Math.round(numeric)} ms` : '—';
};

// ── Campaign Correlation Graph (SVG) ───────────────────────────
function CampaignGraph() {
  const { data: campaignData } = useApi(api.campaigns);
  const campaigns = Array.isArray(campaignData)
    ? campaignData
    : campaignData?.campaigns || campaignData?.groups || [];

  if (!campaigns.length) {
    return (
      <div className="card">
        <div className="card-title" style={{ marginBottom: 12 }}>
          Campaign View
        </div>
        <div className="empty">No active campaigns detected.</div>
      </div>
    );
  }

  const svgW = 700,
    svgH = 400;
  const nodes = [];
  const edges = [];
  const nodeMap = {};

  campaigns.forEach((c, ci) => {
    const hosts = c.hosts || c.agents || c.involved_agents || [];
    const technique = c.technique || c.shared_technique || c.name || `Campaign ${ci + 1}`;
    hosts.forEach((h, hi) => {
      const hostId = typeof h === 'string' ? h : h.host_id || h.agent_id || `host-${ci}-${hi}`;
      if (!nodeMap[hostId]) {
        const angle =
          (Object.keys(nodeMap).length /
            Math.max(
              1,
              campaigns.reduce(
                (s, c2) => s + (c2.hosts || c2.agents || c2.involved_agents || []).length,
                0,
              ),
            )) *
          2 *
          Math.PI;
        const r = 140;
        nodeMap[hostId] = {
          id: hostId,
          x: svgW / 2 + r * Math.cos(angle),
          y: svgH / 2 + r * Math.sin(angle),
          severity: c.severity || 'medium',
        };
        nodes.push(nodeMap[hostId]);
      }
    });
    // edges between hosts in same campaign (cap at 200 edges to prevent DOM bloat)
    for (let i = 0; i < hosts.length && edges.length < 200; i++) {
      for (let j = i + 1; j < hosts.length && edges.length < 200; j++) {
        const a = typeof hosts[i] === 'string' ? hosts[i] : hosts[i].host_id || hosts[i].agent_id;
        const b = typeof hosts[j] === 'string' ? hosts[j] : hosts[j].host_id || hosts[j].agent_id;
        if (nodeMap[a] && nodeMap[b]) {
          edges.push({ from: nodeMap[a], to: nodeMap[b], label: technique });
        }
      }
    }
  });

  const sevColor = (s) =>
    ({ critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' })[s] || '#64748b';

  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 12 }}>
        Campaign Correlation Graph
      </div>
      <svg
        width={svgW}
        height={svgH}
        style={{
          background: 'var(--bg)',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--border)',
        }}
      >
        {edges.map((e, i) => (
          <g key={`e-${i}`}>
            <line
              x1={e.from.x}
              y1={e.from.y}
              x2={e.to.x}
              y2={e.to.y}
              stroke="var(--border)"
              strokeWidth={1.5}
            />
            <text
              x={(e.from.x + e.to.x) / 2}
              y={(e.from.y + e.to.y) / 2 - 4}
              fill="var(--text-secondary)"
              fontSize={9}
              textAnchor="middle"
            >
              {e.label}
            </text>
          </g>
        ))}
        {nodes.map((n) => (
          <g key={n.id}>
            <circle cx={n.x} cy={n.y} r={18} fill={sevColor(n.severity)} opacity={0.8} />
            <text x={n.x} y={n.y + 4} fill="#fff" fontSize={9} textAnchor="middle" fontWeight={600}>
              {n.id.length > 8 ? n.id.slice(0, 8) + '…' : n.id}
            </text>
          </g>
        ))}
      </svg>
      <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-secondary)' }}>
        {campaigns.length} campaign(s) • {nodes.length} host(s) • {edges.length} connection(s)
      </div>
    </div>
  );
}

export default function SOCWorkbench() {
  const toast = useToast();
  const navigate = useNavigate();

  // Persist active tab in URL hash
  const [tab, setTabRaw] = useState(() => {
    const h = window.location.hash.replace('#', '');
    return TAB_GROUPS.some((g) => g.tabs.includes(h)) ? h : 'overview';
  });
  const setTab = useCallback((t) => {
    setTabRaw(t);
    window.location.hash = t;
  }, []);
  useEffect(() => {
    const onHash = () => {
      const h = window.location.hash.replace('#', '');
      if (TAB_GROUPS.some((g) => g.tabs.includes(h))) setTabRaw(h);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  const [collapsedGroups, setCollapsedGroups] = useState({});
  const toggleGroup = useCallback(
    (label) => setCollapsedGroups((p) => ({ ...p, [label]: !p[label] })),
    [],
  );

  const { data: overview, reload: rOverview } = useApi(api.workbenchOverview);
  const { data: incList, reload: rInc } = useApi(api.incidents);
  const { data: caseList, reload: rCases } = useApi(api.cases);
  const { data: caseStats } = useApi(api.casesStats);
  const { data: queue, reload: rQueue } = useApi(api.queueAlerts);
  const { data: qStats } = useApi(api.queueStats);
  const { data: pending } = useApi(api.responsePending);
  const { data: respReq } = useApi(api.responseRequests);
  const { data: respAudit } = useApi(api.responseAudit);
  const { data: respStats } = useApi(api.responseStats);
  const { data: procs } = useApi(api.processTree);
  const { data: deepCh } = useApi(api.deepChains);
  const { data: liveProcs, reload: rLive } = useApi(api.processesLive);
  const { data: procFindings, reload: rProcFindings } = useApi(api.processesAnalysis);
  const { data: rbacData, reload: rRbac } = useApi(api.rbacUsers);
  const { data: tlHost } = useApi(api.timelineHost);
  const { data: escPolicies, reload: rEsc } = useApi(api.escalationPolicies);
  const { data: escActive, reload: rEscActive } = useApi(api.escalationActive);
  const { data: workflows } = useApi(api.investigationWorkflows);
  const { data: activeInvestigations, reload: rInv } = useApi(api.investigationActive);
  const { data: efficacyData, reload: rEfficacy } = useApi(api.efficacySummary);
  const { data: wsStats } = useApi(api.wsStats);
  const [selectedInc, setSelectedInc] = useState(null);
  const [incDetail, setIncDetail] = useState(null);
  const [incStoryline, setIncStoryline] = useState(null);
  const [entityInput, setEntityInput] = useState('');
  const [entityResult, setEntityResult] = useState(null);
  const [escForm, setEscForm] = useState({
    name: '',
    severity: 'critical',
    channel: 'email',
    targets: '',
    timeout_minutes: 30,
  });
  const [showEscForm, setShowEscForm] = useState(false);
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [investigationContext, setInvestigationContext] = useState(null);
  const [plannerSuggestions, setPlannerSuggestions] = useState([]);
  const [plannerLoading, setPlannerLoading] = useState(false);
  const [startingWorkflowId, setStartingWorkflowId] = useState(null);
  const [caseTitleDrafts, setCaseTitleDrafts] = useState({});
  const [analystPrompt, setAnalystPrompt] = useState('show me high severity alerts from this week');
  const [analystResult, setAnalystResult] = useState(null);
  const [analystLoading, setAnalystLoading] = useState(false);
  const [queueFilterText, setQueueFilterText] = useState('');
  const [savedQueueFilters, setSavedQueueFilters] = useState(() => {
    try {
      const parsed = JSON.parse(localStorage.getItem('wardex_saved_queue_filters') || '[]');
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  });
  const [selectedCaseIds, setSelectedCaseIds] = useState(new Set());
  const [bulkCaseStatus, setBulkCaseStatus] = useState('investigating');

  // ── Case Comments ──
  const [commentText, setCommentText] = useState('');
  const [caseComments, setCaseComments] = useState([]);

  const openOverviewAction = useCallback(
    (category) => {
      if (category === 'rollout' || category === 'content') {
        navigate('/detection');
        return;
      }
      if (category === 'identity') {
        navigate('/settings');
        return;
      }
      if (category === 'analytics') {
        navigate('/infrastructure');
        return;
      }
      if (category === 'automation') {
        setTab('playbooks');
      }
    },
    [navigate, setTab],
  );

  // ── Investigation Checklists (persisted) ──
  const [checklist, setChecklist] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('wardex_checklist') || '[]');
    } catch {
      return [];
    }
  });
  const [checklistType, setChecklistType] = useState(
    () => localStorage.getItem('wardex_checklist_type') || '',
  );
  useEffect(() => {
    localStorage.setItem('wardex_checklist', JSON.stringify(checklist));
    localStorage.setItem('wardex_checklist_type', checklistType);
  }, [checklist, checklistType]);

  useInterval(() => {
    rOverview();
    rQueue();
    rEscActive();
  }, 15000);
  useInterval(
    () => {
      if (tab === 'process-tree') {
        rLive();
        rProcFindings();
      }
    },
    tab === 'process-tree' ? 15000 : null,
  );

  const incArr = Array.isArray(incList) ? incList : incList?.incidents || [];
  const caseArr = Array.isArray(caseList) ? caseList : caseList?.cases || [];
  const queueArr = Array.isArray(queue) ? queue : queue?.alerts || [];
  const rbacArr = Array.isArray(rbacData) ? rbacData : rbacData?.users || [];
  const filteredQueueArr = queueArr.filter((alert) => {
    const q = queueFilterText.trim().toLowerCase();
    if (!q) return true;
    return JSON.stringify(alert || {})
      .toLowerCase()
      .includes(q);
  });

  useEffect(() => {
    localStorage.setItem('wardex_saved_queue_filters', JSON.stringify(savedQueueFilters));
  }, [savedQueueFilters]);

  const startWorkflow = async (workflow, caseId) => {
    if (!workflow?.id) return;
    setStartingWorkflowId(workflow.id);
    try {
      await api.investigationStart({
        workflow_id: workflow.id,
        analyst: 'admin',
        case_id: caseId || undefined,
      });
      toast('Investigation started', 'success');
      setTab('investigations');
      rInv();
    } catch {
      toast('Failed to start', 'error');
    } finally {
      setStartingWorkflowId(null);
    }
  };

  const openInvestigationPlanner = async (context, sourceType) => {
    const nextContext = { ...context, sourceType };
    setInvestigationContext(nextContext);
    setTab('investigations');

    const reasons = buildPlannerReasons(nextContext);
    if (reasons.length === 0) {
      setPlannerSuggestions([]);
      return;
    }

    setPlannerLoading(true);
    try {
      const result = await api.investigationSuggest({ alert_reasons: reasons });
      const items = Array.isArray(result) ? result : result?.suggestions || [];
      setPlannerSuggestions(items);
    } catch {
      setPlannerSuggestions([]);
      toast('Failed to load investigation suggestions', 'error');
    } finally {
      setPlannerLoading(false);
    }
  };

  const pivotPlannerToHunt = (context) => {
    const params = new URLSearchParams({
      intent: 'run-hunt',
      huntQuery: buildPlannerHuntQuery(context),
      huntName: buildPlannerHuntName(context),
    });
    navigate(`/detection?${params.toString()}`);
  };

  const viewInc = async (id) => {
    setSelectedInc(id);
    setIncStoryline(null);
    try {
      const d = await api.incidentById(id);
      setIncDetail(d);
    } catch {
      setIncDetail(null);
    }
    try {
      const s = await api.incidentStoryline(id);
      setIncStoryline(s);
    } catch {
      /* optional */
    }
  };
  const openProcess = (process) => setSelectedProcess(process ? { ...process } : null);

  const updateCaseTitleInline = async (caseItem) => {
    const id = caseItem?.id;
    if (!id) return;
    const nextTitle = String(caseTitleDrafts[id] ?? caseItem.title ?? '').trim();
    if (!nextTitle || nextTitle === String(caseItem.title || '').trim()) return;
    try {
      await api.updateCase(id, { title: nextTitle });
      toast('Case title updated', 'success');
      rCases();
    } catch {
      toast('Failed to update case title', 'error');
    }
  };

  const runAnalystQuery = async () => {
    const text = String(analystPrompt || '').trim();
    if (!text) return;
    setAnalystLoading(true);
    try {
      const normalized = text.toLowerCase();
      const payload = {
        text,
        level: normalized.includes('critical')
          ? 'critical'
          : normalized.includes('high')
            ? 'high'
            : undefined,
        limit: normalized.includes('all') ? 1000 : 200,
      };
      const result = await api.analystQuery(payload);
      setAnalystResult(result);
      toast('Analyst query completed', 'success');
    } catch {
      toast('Analyst query failed', 'error');
      setAnalystResult(null);
    } finally {
      setAnalystLoading(false);
    }
  };

  return (
    <div>
      <div className="tabs" style={{ flexWrap: 'wrap', gap: 0 }}>
        {TAB_GROUPS.map((g) => (
          <div key={g.label} style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
            <button
              className="tab"
              onClick={() => toggleGroup(g.label)}
              style={{
                fontWeight: 700,
                fontSize: 11,
                opacity: 0.6,
                padding: '4px 6px',
                minWidth: 'auto',
              }}
              title={`${collapsedGroups[g.label] ? 'Expand' : 'Collapse'} ${g.label}`}
            >
              {collapsedGroups[g.label] ? '▸' : '▾'} {g.label}
            </button>
            {!collapsedGroups[g.label] &&
              g.tabs.map((t) => (
                <button
                  key={t}
                  className={`tab ${tab === t ? 'active' : ''}`}
                  onClick={() => setTab(t)}
                >
                  {t.replace(/-/g, ' ').replace(/^\w/, (c) => c.toUpperCase())}
                </button>
              ))}
            <span style={{ width: 8 }} />
          </div>
        ))}
      </div>

      {tab === 'overview' &&
        (overview ? (
          <>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Workbench Overview
              </div>
              <div className="card-grid">
                <div className="card metric">
                  <div className="metric-label">Identity Routing</div>
                  <div className="metric-value">
                    {overview.identity?.ready_providers || 0}/
                    {overview.identity?.providers_configured || 0}
                  </div>
                  <div className="metric-sub">
                    Ready providers aligned with {overview.identity?.mapped_groups || 0} mapped
                    group
                    {overview.identity?.mapped_groups === 1 ? '' : 's'}
                  </div>
                </div>
                <div className="card metric">
                  <div className="metric-label">Canary Content</div>
                  <div className="metric-value">
                    {(overview.rollouts?.canary_rules || 0) +
                      (overview.rollouts?.canary_hunts || 0)}
                  </div>
                  <div className="metric-sub">
                    {overview.rollouts?.promotion_ready_rules || 0} promotion-ready rule
                    {(overview.rollouts?.promotion_ready_rules || 0) === 1 ? '' : 's'}
                  </div>
                </div>
                <div className="card metric">
                  <div className="metric-label">Saved Search Library</div>
                  <div className="metric-value">{overview.content?.saved_searches || 0}</div>
                  <div className="metric-sub">
                    {overview.content?.packs || 0} pack bundle
                    {(overview.content?.packs || 0) === 1 ? '' : 's'} and{' '}
                    {overview.content?.hunt_library || 0} hunt
                    {(overview.content?.hunt_library || 0) === 1 ? '' : 's'}
                  </div>
                </div>
                <div className="card metric">
                  <div className="metric-label">Automation Queue</div>
                  <div className="metric-value">{overview.automation?.pending_approvals || 0}</div>
                  <div className="metric-sub">
                    {overview.automation?.active_executions || 0} active execution
                    {(overview.automation?.active_executions || 0) === 1 ? '' : 's'}
                  </div>
                </div>
                <div className="card metric">
                  <div className="metric-label">API Health</div>
                  <div className="metric-value">{formatMs(overview.analytics?.worst_p95_ms)}</div>
                  <div className="metric-sub">
                    {formatPct(1 - (overview.analytics?.api_error_rate || 0))} request success
                    across {overview.analytics?.api_requests || 0} API call
                    {(overview.analytics?.api_requests || 0) === 1 ? '' : 's'}
                  </div>
                </div>
                <div className="card metric">
                  <div className="metric-label">Investigations In Flight</div>
                  <div className="metric-value">
                    {overview.automation?.active_investigations || 0}
                  </div>
                  <div className="metric-sub">
                    {overview.automation?.workflow_templates || 0} workflow template
                    {(overview.automation?.workflow_templates || 0) === 1 ? '' : 's'} available
                  </div>
                </div>
              </div>
            </div>

            <div className="card-grid" style={{ marginTop: 16 }}>
              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Identity Program
                </div>
                <div className="summary-grid">
                  <div className="summary-card">
                    <div className="summary-label">SCIM Status</div>
                    <div className="summary-value">
                      {overview.identity?.scim_status || 'disabled'}
                    </div>
                    <div className="summary-meta">
                      {overview.identity?.automation_targets_aligned || 0} automation target
                      {(overview.identity?.automation_targets_aligned || 0) === 1 ? '' : 's'}{' '}
                      aligned
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Providers With Gaps</div>
                    <div className="summary-value">
                      {overview.identity?.providers_with_gaps || 0}
                    </div>
                    <div className="summary-meta">Review group mappings before broad rollout.</div>
                  </div>
                </div>
              </div>

              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Rollout Control
                </div>
                <div className="summary-grid">
                  <div className="summary-card">
                    <div className="summary-label">Canary Hunts</div>
                    <div className="summary-value">{overview.rollouts?.canary_hunts || 0}</div>
                    <div className="summary-meta">
                      Avg canary {overview.rollouts?.average_canary_percentage || 0}%
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Rollout Targets</div>
                    <div className="summary-value">{overview.rollouts?.rollout_targets || 0}</div>
                    <div className="summary-meta">
                      {overview.rollouts?.active_hunts || 0} active hunt
                      {(overview.rollouts?.active_hunts || 0) === 1 ? '' : 's'} attached to delivery
                      lanes
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Historical Events</div>
                    <div className="summary-value">{overview.rollouts?.historical_events || 0}</div>
                    <div className="summary-meta">
                      {overview.rollouts?.rollback_events || 0} rollback event
                      {(overview.rollouts?.rollback_events || 0) === 1 ? '' : 's'} • latest{' '}
                      {overview.rollouts?.last_rollout_at
                        ? formatRelativeTime(overview.rollouts.last_rollout_at)
                        : 'not recorded'}
                    </div>
                  </div>
                </div>
                {Array.isArray(overview.rollouts?.recent_history) &&
                overview.rollouts.recent_history.length > 0 ? (
                  <div style={{ marginTop: 12 }}>
                    {overview.rollouts.recent_history.map((event) => (
                      <div
                        key={event.id}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          gap: 12,
                          padding: '10px 0',
                          borderBottom: '1px solid var(--border)',
                        }}
                      >
                        <div style={{ flex: 1 }}>
                          <div className="row-primary">
                            {event.action} • {event.version}
                          </div>
                          <div className="row-secondary">
                            {event.agent_id || event.platform || 'shared rollout'} • {event.status}
                          </div>
                        </div>
                        <div className="hint" style={{ textAlign: 'right' }}>
                          {formatRelativeTime(event.recorded_at)}
                          <div>{formatDateTime(event.recorded_at)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>

              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Content Bundles
                </div>
                <div className="summary-grid">
                  <div className="summary-card">
                    <div className="summary-label">Packs With Workflows</div>
                    <div className="summary-value">
                      {overview.content?.packs_with_workflows || 0}
                    </div>
                    <div className="summary-meta">
                      {overview.content?.enabled_packs || 0}/{overview.content?.packs || 0} enabled
                      packs
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Scheduled Hunts</div>
                    <div className="summary-value">{overview.content?.scheduled_hunts || 0}</div>
                    <div className="summary-meta">
                      Latest pack update {overview.content?.latest_pack_update || 'not recorded'}
                    </div>
                  </div>
                </div>
              </div>

              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Automation Program
                </div>
                <div className="summary-grid">
                  <div className="summary-card">
                    <div className="summary-label">Coverage</div>
                    <div className="summary-value">
                      {(overview.automation?.playbooks || 0) +
                        (overview.automation?.dynamic_templates || 0)}
                    </div>
                    <div className="summary-meta">
                      {overview.automation?.playbooks || 0} static playbook
                      {(overview.automation?.playbooks || 0) === 1 ? '' : 's'} •{' '}
                      {overview.automation?.dynamic_templates || 0} dynamic
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Success Rate</div>
                    <div className="summary-value">
                      {formatPct(overview.automation?.success_rate || 0)}
                    </div>
                    <div className="summary-meta">
                      Avg runtime {formatMs(overview.automation?.avg_execution_ms)}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Historical Runs</div>
                    <div className="summary-value">{overview.automation?.historical_runs || 0}</div>
                    <div className="summary-meta">
                      Latest{' '}
                      {overview.automation?.last_execution_at
                        ? formatRelativeTime(overview.automation.last_execution_at)
                        : 'not recorded'}
                    </div>
                  </div>
                </div>
                {Array.isArray(overview.automation?.recent_history) &&
                overview.automation.recent_history.length > 0 ? (
                  <div style={{ marginTop: 12 }}>
                    {overview.automation.recent_history.map((execution) => (
                      <div
                        key={execution.execution_id}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          gap: 12,
                          padding: '10px 0',
                          borderBottom: '1px solid var(--border)',
                        }}
                      >
                        <div style={{ flex: 1 }}>
                          <div className="row-primary">
                            {execution.playbook_id} • {execution.status}
                          </div>
                          <div className="row-secondary">
                            {execution.executed_by} •{' '}
                            {execution.duration_ms
                              ? formatMs(execution.duration_ms)
                              : 'runtime pending'}
                          </div>
                        </div>
                        <div className="hint" style={{ textAlign: 'right' }}>
                          {formatRelativeTime(execution.finished_at || execution.started_at)}
                          <div>{formatDateTime(execution.finished_at || execution.started_at)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>

              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Operational Analytics
                </div>
                <div className="summary-grid">
                  <div className="summary-card">
                    <div className="summary-label">Busiest Endpoint</div>
                    <div className="summary-value" style={{ fontSize: 16 }}>
                      {overview.analytics?.busiest_endpoint || '—'}
                    </div>
                    <div className="summary-meta">
                      {overview.analytics?.unique_endpoints || 0} unique endpoint
                      {(overview.analytics?.unique_endpoints || 0) === 1 ? '' : 's'} tracked
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Latency Snapshots</div>
                    <div className="summary-value">
                      {formatMs(overview.analytics?.last_hunt_latency_ms)}
                    </div>
                    <div className="summary-meta">
                      Response {formatMs(overview.analytics?.last_response_latency_ms)}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-header">
                <span className="card-title">Recommendation Queue</span>
              </div>
              {Array.isArray(overview.recommendations) && overview.recommendations.length > 0 ? (
                overview.recommendations.map((item, index) => (
                  <div
                    key={`${item.category}-${index}`}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'flex-start',
                      gap: 12,
                      padding: '10px 0',
                      borderBottom:
                        index === overview.recommendations.length - 1
                          ? 'none'
                          : '1px solid var(--border)',
                    }}
                  >
                    <div style={{ flex: 1 }}>
                      <div className="row-primary">{item.title}</div>
                      <div className="row-secondary">{item.summary}</div>
                      <div className="hint" style={{ marginTop: 4 }}>
                        {item.action_hint}
                      </div>
                    </div>
                    <div className="btn-group" style={{ alignItems: 'center' }}>
                      <span
                        className={`badge ${item.priority === 'high' ? 'badge-err' : item.priority === 'medium' ? 'badge-warn' : 'badge-info'}`}
                      >
                        {item.priority}
                      </span>
                      <button
                        className="btn btn-sm"
                        onClick={() => openOverviewAction(item.category)}
                      >
                        Open
                      </button>
                    </div>
                  </div>
                ))
              ) : (
                <div className="empty">No program-level recommendations right now.</div>
              )}
            </div>

            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>
                Raw Overview Data
              </div>
              <SummaryGrid data={overview} limit={10} />
              <JsonDetails data={overview} />
            </div>
          </>
        ) : (
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Workbench Overview
            </div>
            <div className="empty">Loading...</div>
          </div>
        ))}

      {tab === 'incidents' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Incidents ({incArr.length})</span>
            <div className="btn-group">
              <button className="btn btn-sm" onClick={rInc}>
                ↻ Refresh
              </button>
              <button
                className="btn btn-sm btn-primary"
                onClick={async () => {
                  try {
                    await api.createIncident({ title: 'New incident', severity: 'medium' });
                    toast('Incident created', 'success');
                    rInc();
                  } catch {
                    toast('Failed', 'error');
                  }
                }}
              >
                + New Incident
              </button>
            </div>
          </div>
          {incArr.length === 0 ? (
            <div className="empty">No incidents</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {incArr.map((inc, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                        {inc.id || i}
                      </td>
                      <td>{inc.title || '—'}</td>
                      <td>
                        <span className={`sev-${(inc.severity || 'low').toLowerCase()}`}>
                          {inc.severity}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`badge ${inc.status === 'closed' ? 'badge-ok' : 'badge-warn'}`}
                        >
                          {inc.status || '—'}
                        </span>
                      </td>
                      <td>{inc.created || inc.timestamp || '—'}</td>
                      <td>
                        {inc.id ? (
                          <button className="btn btn-sm" onClick={() => viewInc(inc.id)}>
                            View
                          </button>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {selectedInc !== null && incDetail && (
            <div className="card" style={{ marginTop: 16, borderLeft: '3px solid var(--primary)' }}>
              <div className="card-header">
                <span className="card-title">
                  Incident Detail — {incDetail.title || incDetail.id || selectedInc}
                </span>
                <button
                  className="btn btn-sm"
                  onClick={() => {
                    setSelectedInc(null);
                    setIncDetail(null);
                    setIncStoryline(null);
                  }}
                >
                  ✕ Close
                </button>
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
                  gap: 12,
                  marginBottom: 16,
                }}
              >
                <div>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>ID</span>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                    {incDetail.id || selectedInc}
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Severity</span>
                  <div>
                    <span className={`sev-${(incDetail.severity || 'low').toLowerCase()}`}>
                      {incDetail.severity || '—'}
                    </span>
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Status</span>
                  <div>
                    <span
                      className={`badge ${incDetail.status === 'closed' ? 'badge-ok' : 'badge-warn'}`}
                    >
                      {incDetail.status || '—'}
                    </span>
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Created</span>
                  <div>{incDetail.created || incDetail.timestamp || '—'}</div>
                </div>
                <div>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Updated</span>
                  <div>{incDetail.updated || incDetail.last_updated || '—'}</div>
                </div>
                <div>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Owner</span>
                  <div>{incDetail.owner || incDetail.assigned_to || '—'}</div>
                </div>
              </div>
              {incDetail.summary && (
                <div
                  style={{
                    marginBottom: 12,
                    padding: '8px 12px',
                    background: 'var(--bg)',
                    borderRadius: 6,
                    fontSize: 13,
                  }}
                >
                  {incDetail.summary}
                </div>
              )}
              {(incDetail.event_ids?.length > 0 || incDetail.alert_ids?.length > 0) && (
                <div style={{ marginBottom: 12 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    Related Events / Alerts
                  </span>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                    {(incDetail.event_ids || incDetail.alert_ids || []).map((eid, i) => (
                      <span key={i} className="badge badge-info" style={{ fontSize: 11 }}>
                        {eid}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {incDetail.agent_ids?.length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Agents</span>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                    {incDetail.agent_ids.map((aid, i) => (
                      <span key={i} className="badge" style={{ fontSize: 11 }}>
                        {aid}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {incStoryline && (
                <div style={{ marginTop: 12 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Storyline</span>
                  <div
                    style={{ marginTop: 6, borderLeft: '2px solid var(--border)', paddingLeft: 12 }}
                  >
                    {(
                      incStoryline.events ||
                      incStoryline.steps ||
                      (Array.isArray(incStoryline) ? incStoryline : [])
                    ).map((ev, i) => (
                      <div key={i} style={{ marginBottom: 8, fontSize: 13 }}>
                        <span style={{ fontWeight: 600, marginRight: 8 }}>
                          {ev.timestamp || ev.time || `Step ${i + 1}`}
                        </span>
                        <span>
                          {ev.description || ev.message || ev.action || JSON.stringify(ev)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={async () => {
                    try {
                      await api.updateIncident(selectedInc, { status: 'closed' });
                      toast('Incident closed', 'success');
                      viewInc(selectedInc);
                      rInc();
                    } catch {
                      toast('Failed', 'error');
                    }
                  }}
                >
                  Close Incident
                </button>
                <button
                  className="btn btn-sm"
                  onClick={() => openInvestigationPlanner(incDetail, 'incident')}
                >
                  Plan Investigation
                </button>
                <button className="btn btn-sm" onClick={() => pivotPlannerToHunt(incDetail)}>
                  Open Hunt
                </button>
                <button
                  className="btn btn-sm"
                  onClick={async () => {
                    try {
                      const r = await api.incidentReport(selectedInc);
                      downloadData(
                        typeof r === 'string' ? r : r,
                        `incident-${selectedInc}-report.txt`,
                        'text/plain',
                      );
                    } catch {
                      toast('Failed to generate report', 'error');
                    }
                  }}
                >
                  Export Report
                </button>
              </div>

              {/* ── Investigation Checklist ────────── */}
              <div style={{ marginTop: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <span style={{ fontSize: 12, fontWeight: 600 }}>Investigation Checklist</span>
                  <select
                    className="input"
                    style={{ fontSize: 11, padding: '2px 6px' }}
                    value={checklistType}
                    onChange={(e) => {
                      setChecklistType(e.target.value);
                      const tpl = CHECKLIST_TEMPLATES[e.target.value];
                      if (tpl) setChecklist(tpl.map((t) => ({ text: t, done: false })));
                    }}
                  >
                    <option value="">Select template…</option>
                    {Object.keys(CHECKLIST_TEMPLATES).map((k) => (
                      <option key={k} value={k}>
                        {k.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())}
                      </option>
                    ))}
                  </select>
                </div>
                {checklist.length > 0 && (
                  <div>
                    <div
                      style={{
                        height: 4,
                        background: 'var(--border)',
                        borderRadius: 2,
                        marginBottom: 8,
                      }}
                    >
                      <div
                        style={{
                          height: 4,
                          background: 'var(--primary)',
                          borderRadius: 2,
                          width: `${(checklist.filter((c) => c.done).length / checklist.length) * 100}%`,
                          transition: 'width .3s',
                        }}
                      />
                    </div>
                    {checklist.map((item, i) => (
                      <label
                        key={i}
                        style={{
                          display: 'flex',
                          gap: 8,
                          alignItems: 'flex-start',
                          padding: '4px 0',
                          cursor: 'pointer',
                          fontSize: 13,
                          textDecoration: item.done ? 'line-through' : 'none',
                          opacity: item.done ? 0.6 : 1,
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={item.done}
                          onChange={() =>
                            setChecklist((prev) =>
                              prev.map((c, j) => (j === i ? { ...c, done: !c.done } : c)),
                            )
                          }
                        />
                        {item.text}
                      </label>
                    ))}
                  </div>
                )}
              </div>

              {/* ── Comments ────────────────────── */}
              <div style={{ marginTop: 16 }}>
                <span style={{ fontSize: 12, fontWeight: 600 }}>Comments</span>
                {caseComments.length > 0 && (
                  <div style={{ marginTop: 8, maxHeight: 200, overflowY: 'auto' }}>
                    {caseComments.map((c, i) => (
                      <div
                        key={i}
                        style={{
                          padding: '6px 10px',
                          background: 'var(--bg)',
                          borderRadius: 6,
                          marginBottom: 6,
                          fontSize: 12,
                        }}
                      >
                        <div style={{ fontWeight: 500, marginBottom: 2 }}>
                          {c.author || 'analyst'}{' '}
                          <span style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>
                            {c.timestamp || ''}
                          </span>
                        </div>
                        <div>{c.content}</div>
                      </div>
                    ))}
                  </div>
                )}
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <textarea
                    className="input"
                    rows={2}
                    value={commentText}
                    onChange={(e) => setCommentText(e.target.value)}
                    placeholder="Add a comment…"
                    style={{ flex: 1, resize: 'vertical', minHeight: 40 }}
                  />
                  <button
                    className="btn btn-sm btn-primary"
                    disabled={!commentText.trim()}
                    onClick={async () => {
                      const text = commentText.trim();
                      if (!text) return;
                      try {
                        await api.caseComment(selectedInc, { comment: text });
                        setCaseComments((prev) => [
                          ...prev,
                          { author: 'analyst', content: text, timestamp: new Date().toISOString() },
                        ]);
                        setCommentText('');
                        toast('Comment added', 'success');
                      } catch {
                        setCaseComments((prev) => [
                          ...prev,
                          { author: 'analyst', content: text, timestamp: new Date().toISOString() },
                        ]);
                        setCommentText('');
                      }
                    }}
                  >
                    Post
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'cases' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Cases ({caseArr.length})</span>
            <div className="btn-group">
              <select
                className="form-select"
                value={bulkCaseStatus}
                onChange={(event) => setBulkCaseStatus(event.target.value)}
              >
                {['new', 'triaging', 'investigating', 'escalated', 'resolved', 'closed'].map(
                  (status) => (
                    <option key={status} value={status}>
                      {status}
                    </option>
                  ),
                )}
              </select>
              <button
                className="btn btn-sm"
                disabled={selectedCaseIds.size === 0}
                onClick={async () => {
                  const ids = [...selectedCaseIds];
                  await Promise.allSettled(
                    ids.map((id) => api.updateCase(id, { status: bulkCaseStatus })),
                  );
                  toast(`Updated ${ids.length} case(s)`, 'success');
                  setSelectedCaseIds(new Set());
                  rCases();
                }}
              >
                Bulk Apply
              </button>
              <button
                className="btn btn-sm btn-primary"
                onClick={async () => {
                  try {
                    await api.createCase({ title: 'New investigation' });
                    toast('Case created', 'success');
                    rCases();
                  } catch {
                    toast('Failed', 'error');
                  }
                }}
              >
                + New Case
              </button>
            </div>
          </div>
          {caseStats && (
            <div style={{ marginBottom: 12 }}>
              <SummaryGrid data={caseStats} limit={8} />
            </div>
          )}
          {caseArr.length === 0 ? (
            <div className="empty">No cases</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>
                      <input
                        type="checkbox"
                        checked={caseArr.length > 0 && selectedCaseIds.size === caseArr.length}
                        onChange={(event) => {
                          if (event.target.checked) {
                            setSelectedCaseIds(new Set(caseArr.map((c) => c.id).filter(Boolean)));
                          } else {
                            setSelectedCaseIds(new Set());
                          }
                        }}
                      />
                    </th>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Status</th>
                    <th>Owner</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {caseArr.map((c, i) => (
                    <tr key={i}>
                      <td>
                        <input
                          type="checkbox"
                          checked={selectedCaseIds.has(c.id)}
                          onChange={(event) => {
                            setSelectedCaseIds((current) => {
                              const next = new Set(current);
                              if (event.target.checked) next.add(c.id);
                              else next.delete(c.id);
                              return next;
                            });
                          }}
                        />
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{c.id || i}</td>
                      <td>
                        <input
                          className="form-input"
                          value={caseTitleDrafts[c.id] ?? c.title ?? ''}
                          onChange={(event) =>
                            setCaseTitleDrafts((current) => ({
                              ...current,
                              [c.id]: event.target.value,
                            }))
                          }
                          onBlur={() => updateCaseTitleInline(c)}
                          onKeyDown={(event) => {
                            if (event.key === 'Enter') {
                              event.preventDefault();
                              updateCaseTitleInline(c);
                            }
                          }}
                        />
                      </td>
                      <td>
                        <span
                          className={`badge ${c.status === 'closed' ? 'badge-ok' : 'badge-warn'}`}
                        >
                          {c.status || '—'}
                        </span>
                      </td>
                      <td>{c.owner || c.assigned_to || '—'}</td>
                      <td>{c.created || c.timestamp || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'analyst' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Ask the Analyst</span>
            <span className="badge badge-info">Experimental</span>
          </div>
          <div className="hint" style={{ marginBottom: 10 }}>
            Natural-language prompt to build an event search quickly for triage and hunt pivots.
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="analyst-prompt">
              Prompt
            </label>
            <textarea
              id="analyst-prompt"
              className="form-textarea"
              rows={3}
              value={analystPrompt}
              onChange={(event) => setAnalystPrompt(event.target.value)}
              placeholder="Show me lateral movement on db-01 this week"
            />
          </div>
          <div className="btn-group" style={{ marginTop: 10 }}>
            <button
              className="btn btn-sm btn-primary"
              onClick={runAnalystQuery}
              disabled={analystLoading}
            >
              {analystLoading ? 'Running…' : 'Run Query'}
            </button>
            <button className="btn btn-sm" onClick={() => setAnalystResult(null)}>
              Clear
            </button>
          </div>
          <div style={{ marginTop: 14 }}>
            {analystResult ? (
              <JsonDetails data={analystResult} label="Analyst query result" />
            ) : (
              <div className="empty">No analyst query run yet.</div>
            )}
          </div>
        </div>
      )}

      {tab === 'queue' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">SOC Queue ({filteredQueueArr.length} alerts)</span>
            <div className="btn-group">
              <span
                className={`badge ${(wsStats?.connected_subscribers || 0) > 0 ? 'badge-ok' : 'badge-warn'}`}
              >
                {(wsStats?.connected_subscribers || 0) > 0
                  ? `Live (${wsStats.connected_subscribers})`
                  : 'Live idle'}
              </span>
              <button className="btn btn-sm" onClick={rQueue}>
                ↻ Refresh
              </button>
            </div>
          </div>
          {qStats && (
            <div style={{ marginBottom: 12 }}>
              <SummaryGrid data={qStats} limit={8} />
              <JsonDetails data={qStats} />
            </div>
          )}
          <div className="triage-toolbar" style={{ marginBottom: 10 }}>
            <div className="triage-toolbar-group">
              <input
                className="form-input triage-search"
                value={queueFilterText}
                placeholder="Filter alerts…"
                onChange={(event) => setQueueFilterText(event.target.value)}
              />
              <button
                className="btn btn-sm"
                onClick={() => {
                  const name = `Filter ${savedQueueFilters.length + 1}`;
                  const query = queueFilterText.trim();
                  if (!query) return;
                  setSavedQueueFilters((current) => {
                    const next = [
                      ...current.filter((item) => item.query !== query),
                      { name, query },
                    ];
                    return next.slice(-10);
                  });
                }}
              >
                Save Filter
              </button>
            </div>
            <div className="triage-toolbar-group">
              {savedQueueFilters.slice(-4).map((item) => (
                <button
                  key={`${item.name}-${item.query}`}
                  className="btn btn-sm"
                  onClick={() => setQueueFilterText(item.query)}
                >
                  {item.name}
                </button>
              ))}
            </div>
          </div>
          {filteredQueueArr.length === 0 ? (
            <div className="empty">Queue empty</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Summary</th>
                    <th>Assigned</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredQueueArr.map((a, i) => (
                    <tr key={i}>
                      <td>{a.id || i}</td>
                      <td>
                        <span className={`sev-${(a.severity || 'low').toLowerCase()}`}>
                          {a.severity}
                        </span>
                      </td>
                      <td>{a.summary || a.message || '—'}</td>
                      <td>{a.assigned_to || '—'}</td>
                      <td>
                        <button
                          className="btn btn-sm"
                          onClick={async () => {
                            if (!a.id) {
                              toast('No alert ID', 'error');
                              return;
                            }
                            try {
                              await api.queueAck({ alert_id: a.id });
                              toast('Acknowledged', 'success');
                              rQueue();
                            } catch {
                              toast('Failed', 'error');
                            }
                          }}
                        >
                          Ack
                        </button>
                        <button
                          className="btn btn-sm"
                          onClick={() => openInvestigationPlanner(a, 'queue-alert')}
                        >
                          Plan
                        </button>
                        <button className="btn btn-sm" onClick={() => pivotPlannerToHunt(a)}>
                          Hunt
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'response' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Pending Responses
              </div>
              {(() => {
                const items =
                  pending?.actions || pending?.pending || (Array.isArray(pending) ? pending : []);
                return items.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Action</th>
                          <th>Target</th>
                          <th>Severity</th>
                          <th>Requested</th>
                        </tr>
                      </thead>
                      <tbody>
                        {items.map((a, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 600 }}>{a.action || a.type || '—'}</td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                              {a.target || a.host || '—'}
                            </td>
                            <td>
                              <span className={`sev-${(a.severity || 'low').toLowerCase()}`}>
                                {a.severity || '—'}
                              </span>
                            </td>
                            <td>{a.requested || a.timestamp || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty">{pending ? 'No pending responses' : 'Loading...'}</div>
                );
              })()}
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Response Stats
              </div>
              {respStats ? (
                <>
                  <SummaryGrid data={respStats} limit={8} />
                  <JsonDetails data={respStats} />
                </>
              ) : (
                <div className="empty">Loading...</div>
              )}
            </div>
          </div>
          {respReq && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>
                Response Requests
              </div>
              {(() => {
                const reqs = respReq?.requests || (Array.isArray(respReq) ? respReq : []);
                return reqs.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Type</th>
                          <th>Target</th>
                          <th>Status</th>
                          <th>Progress</th>
                          <th>Requested</th>
                        </tr>
                      </thead>
                      <tbody>
                        {reqs.map((r, i) => {
                          const steps = r.steps || [];
                          const completedSteps = steps.filter(
                            (s) => s.status === 'completed' || s.status === 'done',
                          ).length;
                          const failedSteps = steps.filter(
                            (s) => s.status === 'failed' || s.status === 'error',
                          ).length;
                          const totalSteps = steps.length || r.total_steps || 0;
                          const pct =
                            totalSteps > 0
                              ? Math.round((completedSteps / totalSteps) * 100)
                              : r.status === 'completed'
                                ? 100
                                : 0;
                          const statusClass =
                            r.status === 'completed'
                              ? 'badge-ok'
                              : failedSteps > 0
                                ? 'badge-err'
                                : r.status === 'running'
                                  ? 'badge-info'
                                  : 'badge-warn';
                          return (
                            <tr key={i}>
                              <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                                {r.id || i}
                              </td>
                              <td>{r.type || r.action || '—'}</td>
                              <td>{r.target || r.host || '—'}</td>
                              <td>
                                <span className={`badge ${statusClass}`}>{r.status || '—'}</span>
                              </td>
                              <td style={{ minWidth: 140 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                  <div
                                    style={{
                                      flex: 1,
                                      height: 6,
                                      background: 'var(--border)',
                                      borderRadius: 3,
                                      overflow: 'hidden',
                                    }}
                                  >
                                    <div
                                      style={{
                                        width: `${pct}%`,
                                        height: '100%',
                                        background:
                                          failedSteps > 0
                                            ? 'var(--danger, #e74c3c)'
                                            : 'var(--primary)',
                                        borderRadius: 3,
                                        transition: 'width 0.3s ease',
                                      }}
                                    />
                                  </div>
                                  <span
                                    style={{
                                      fontSize: 11,
                                      color: 'var(--muted)',
                                      whiteSpace: 'nowrap',
                                    }}
                                  >
                                    {totalSteps > 0 ? `${completedSteps}/${totalSteps}` : `${pct}%`}
                                  </span>
                                </div>
                                {r.eta && (
                                  <div
                                    style={{ fontSize: 10, color: 'var(--muted)', marginTop: 2 }}
                                  >
                                    ETA: {r.eta}
                                  </div>
                                )}
                              </td>
                              <td>{r.requested_at || r.timestamp || '—'}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    {/* Per-step execution detail for in-progress/failed requests */}
                    {reqs
                      .filter(
                        (r) =>
                          r.steps?.length > 0 && (r.status === 'running' || r.status === 'failed'),
                      )
                      .map((r, ri) => (
                        <div
                          key={ri}
                          style={{
                            marginTop: 12,
                            padding: 12,
                            background: 'var(--bg)',
                            borderRadius: 6,
                            border: '1px solid var(--border)',
                          }}
                        >
                          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8 }}>
                            Playbook Steps — {r.type || r.action} → {r.target || r.host}
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                            {r.steps.map((step, si) => (
                              <div
                                key={si}
                                style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: 8,
                                  fontSize: 12,
                                  padding: '4px 0',
                                }}
                              >
                                <span style={{ width: 18, textAlign: 'center' }}>
                                  {step.status === 'completed' || step.status === 'done'
                                    ? '✓'
                                    : step.status === 'failed' || step.status === 'error'
                                      ? '✗'
                                      : step.status === 'running'
                                        ? '⟳'
                                        : '○'}
                                </span>
                                <span
                                  style={{
                                    flex: 1,
                                    fontWeight: step.status === 'running' ? 600 : 400,
                                  }}
                                >
                                  {step.name || step.label || `Step ${si + 1}`}
                                </span>
                                {step.duration && (
                                  <span style={{ fontSize: 11, color: 'var(--muted)' }}>
                                    {step.duration}
                                  </span>
                                )}
                                {(step.status === 'failed' || step.status === 'error') &&
                                  step.error && (
                                    <span style={{ fontSize: 11, color: 'var(--danger, #e74c3c)' }}>
                                      {step.error}
                                    </span>
                                  )}
                                {step.rollback && (
                                  <span className="badge badge-warn" style={{ fontSize: 10 }}>
                                    rolled back
                                  </span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                  </div>
                ) : (
                  <div className="empty">No response requests</div>
                );
              })()}
            </div>
          )}
          {respAudit && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>
                Response Audit Trail
              </div>
              {(() => {
                const entries =
                  respAudit?.entries ||
                  respAudit?.audit ||
                  (Array.isArray(respAudit) ? respAudit : []);
                return entries.length > 0 ? (
                  <div style={{ borderLeft: '2px solid var(--border)', paddingLeft: 12 }}>
                    {entries.map((e, i) => (
                      <div key={i} style={{ marginBottom: 8, fontSize: 13 }}>
                        <span style={{ fontWeight: 600, marginRight: 8 }}>
                          {e.timestamp || e.time || '—'}
                        </span>
                        <span style={{ marginRight: 8, color: 'var(--primary)' }}>
                          {e.user || e.actor || '—'}
                        </span>
                        <span>{e.action || e.message || e.description || JSON.stringify(e)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty">No audit entries</div>
                );
              })()}
            </div>
          )}
        </>
      )}

      {tab === 'escalation' && (
        <div>
          {/* Active Escalations */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Active Escalations</span>
              <button className="btn btn-sm" onClick={rEscActive}>
                ↻ Refresh
              </button>
            </div>
            {(() => {
              const esc = escActive?.escalations || (Array.isArray(escActive) ? escActive : []);
              return esc.length === 0 ? (
                <div className="empty">No active escalations</div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Incident</th>
                        <th>Severity</th>
                        <th>Policy</th>
                        <th>Started</th>
                        <th>Level</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {esc.map((e, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                            {e.id || i}
                          </td>
                          <td>{e.incident_id || e.alert_id || '—'}</td>
                          <td>
                            <span className={`sev-${(e.severity || 'low').toLowerCase()}`}>
                              {e.severity || '—'}
                            </span>
                          </td>
                          <td>{e.policy || e.policy_name || '—'}</td>
                          <td>{e.started || e.timestamp || '—'}</td>
                          <td>
                            <span className="badge badge-warn">
                              Level {e.level || e.current_level || 1}
                            </span>
                          </td>
                          <td>
                            <button
                              className="btn btn-sm btn-primary"
                              onClick={async () => {
                                try {
                                  await api.escalationAck({ escalation_id: e.id });
                                  toast('Escalation acknowledged', 'success');
                                  rEscActive();
                                } catch {
                                  toast('Failed', 'error');
                                }
                              }}
                            >
                              Acknowledge
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })()}
          </div>
          {/* Escalation Policies */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Escalation Policies</span>
              <div className="btn-group">
                <button className="btn btn-sm" onClick={rEsc}>
                  ↻ Refresh
                </button>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={() => setShowEscForm(!showEscForm)}
                >
                  {showEscForm ? 'Cancel' : '+ New Policy'}
                </button>
              </div>
            </div>
            {showEscForm && (
              <div
                style={{
                  display: 'flex',
                  gap: 8,
                  flexWrap: 'wrap',
                  marginBottom: 16,
                  padding: 12,
                  background: 'var(--bg)',
                  borderRadius: 6,
                }}
              >
                <input
                  className="form-input"
                  style={{ width: 200 }}
                  placeholder="Policy name"
                  value={escForm.name}
                  onChange={(e) => setEscForm((f) => ({ ...f, name: e.target.value }))}
                />
                <select
                  className="form-input"
                  style={{ width: 120 }}
                  value={escForm.severity}
                  onChange={(e) => setEscForm((f) => ({ ...f, severity: e.target.value }))}
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <select
                  className="form-input"
                  style={{ width: 120 }}
                  value={escForm.channel}
                  onChange={(e) => setEscForm((f) => ({ ...f, channel: e.target.value }))}
                >
                  <option value="email">Email</option>
                  <option value="slack">Slack</option>
                  <option value="pagerduty">PagerDuty</option>
                  <option value="webhook">Webhook</option>
                </select>
                <input
                  className="form-input"
                  style={{ width: 250 }}
                  placeholder="Targets (comma-separated)"
                  value={escForm.targets}
                  onChange={(e) => setEscForm((f) => ({ ...f, targets: e.target.value }))}
                />
                <input
                  className="form-input"
                  style={{ width: 120 }}
                  type="number"
                  placeholder="Timeout (min)"
                  value={escForm.timeout_minutes}
                  onChange={(e) =>
                    setEscForm((f) => ({ ...f, timeout_minutes: parseInt(e.target.value) || 30 }))
                  }
                />
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    if (!escForm.name) {
                      toast('Name required', 'error');
                      return;
                    }
                    try {
                      await api.createEscalationPolicy({
                        ...escForm,
                        targets: escForm.targets
                          .split(',')
                          .map((t) => t.trim())
                          .filter(Boolean),
                      });
                      toast('Policy created', 'success');
                      setShowEscForm(false);
                      setEscForm({
                        name: '',
                        severity: 'critical',
                        channel: 'email',
                        targets: '',
                        timeout_minutes: 30,
                      });
                      rEsc();
                    } catch {
                      toast('Failed', 'error');
                    }
                  }}
                >
                  Create
                </button>
              </div>
            )}
            {(() => {
              const pols = escPolicies?.policies || (Array.isArray(escPolicies) ? escPolicies : []);
              return pols.length === 0 ? (
                <div className="empty">No escalation policies configured</div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Severity</th>
                        <th>Channel</th>
                        <th>Targets</th>
                        <th>Timeout</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pols.map((p, i) => (
                        <tr key={i}>
                          <td style={{ fontWeight: 600 }}>{p.name || '—'}</td>
                          <td>
                            <span className={`sev-${(p.severity || 'low').toLowerCase()}`}>
                              {p.severity || '—'}
                            </span>
                          </td>
                          <td>{p.channel || '—'}</td>
                          <td style={{ fontSize: 12 }}>
                            {Array.isArray(p.targets) ? p.targets.join(', ') : p.targets || '—'}
                          </td>
                          <td>{p.timeout_minutes || p.timeout || '—'} min</td>
                          <td>
                            <button
                              className="btn btn-sm"
                              onClick={async () => {
                                try {
                                  await api.escalationStart({
                                    policy_id: p.id || p.name,
                                    incident_id: 'manual-test',
                                  });
                                  toast('Escalation triggered', 'success');
                                  rEscActive();
                                } catch {
                                  toast('Failed', 'error');
                                }
                              }}
                            >
                              Test
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {tab === 'process-tree' && (
        <div>
          {/* Security findings banner */}
          {procFindings?.findings?.length > 0 && (
            <div
              className="card"
              style={{ marginBottom: 16, borderLeft: '3px solid var(--danger)' }}
            >
              <div className="card-header">
                <span className="card-title">Process Security Findings ({procFindings.total})</span>
                <div className="btn-group">
                  <button
                    className="btn btn-sm"
                    onClick={() => downloadData(procFindings, 'soc-process-findings.json')}
                  >
                    Export
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() => {
                      rLive();
                      rProcFindings();
                    }}
                  >
                    ↻ Refresh
                  </button>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
                {Object.entries(procFindings.risk_summary || {}).map(
                  ([k, v]) =>
                    v > 0 && (
                      <span key={k} className={`sev-${k}`} style={{ fontWeight: 600 }}>
                        {v} {k}
                      </span>
                    ),
                )}
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
                    {procFindings.findings.map((f, i) => (
                      <tr
                        key={i}
                        className="interactive-row"
                        style={{
                          background:
                            f.risk_level === 'critical'
                              ? 'rgba(239,68,68,.06)'
                              : f.risk_level === 'high'
                                ? 'rgba(249,115,22,.06)'
                                : undefined,
                        }}
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
                          <button className="btn btn-sm" onClick={() => openProcess(f)}>
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
          <div className="card-grid">
            {/* Live processes */}
            <div className="card">
              <div className="card-header">
                <span className="card-title">Live Processes ({liveProcs?.count ?? '—'})</span>
                <div className="btn-group">
                  <button className="btn btn-sm" onClick={rLive}>
                    ↻ Refresh
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() => downloadData(liveProcs, 'soc-live-processes.json')}
                  >
                    Export
                  </button>
                </div>
              </div>
              {liveProcs?.processes?.length > 0 ? (
                <div className="table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
                  <table>
                    <thead
                      style={{
                        position: 'sticky',
                        top: 0,
                        background: 'var(--card-bg)',
                        zIndex: 1,
                      }}
                    >
                      <tr>
                        <th>PID</th>
                        <th>Name</th>
                        <th>User</th>
                        <th>CPU %</th>
                        <th>Mem %</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...liveProcs.processes]
                        .sort((a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0))
                        .slice(0, 100)
                        .map((p) => (
                          <tr key={p.pid} className="interactive-row">
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                              {p.pid}
                            </td>
                            <td style={{ fontWeight: p.cpu_percent > 50 ? 700 : 400 }}>{p.name}</td>
                            <td>{p.user}</td>
                            <td style={{ color: p.cpu_percent > 50 ? 'var(--danger)' : undefined }}>
                              {p.cpu_percent?.toFixed(1)}
                            </td>
                            <td
                              style={{ color: p.mem_percent > 30 ? 'var(--warning)' : undefined }}
                            >
                              {p.mem_percent?.toFixed(1)}
                            </td>
                            <td>
                              <button className="btn btn-sm" onClick={() => openProcess(p)}>
                                Investigate
                              </button>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">{liveProcs?.message || 'No live process data'}</div>
              )}
            </div>
            {/* Deep chains */}
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Deep Process Chains
              </div>
              {deepCh?.chains?.length > 0 || (Array.isArray(deepCh) && deepCh.length > 0) ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Chain</th>
                        <th>Depth</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(deepCh?.chains || deepCh || []).map((c, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                            {Array.isArray(c.chain) ? c.chain.join(' → ') : JSON.stringify(c)}
                          </td>
                          <td>{c.depth || c.chain?.length || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">No deep process chains detected</div>
              )}
            </div>
          </div>
          {/* Static process tree - collapsed by default */}
          {procs && (
            <details style={{ marginTop: 16 }}>
              <summary style={{ cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)' }}>
                Static Process Tree (raw)
              </summary>
              <div className="card" style={{ marginTop: 8 }}>
                <JsonDetails data={procs} label="Process tree details" />
              </div>
            </details>
          )}
        </div>
      )}

      {tab === 'entity' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Entity / UEBA Lookup</span>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <input
              className="form-input"
              style={{ width: 300 }}
              placeholder="Entity ID"
              value={entityInput}
              onChange={(e) => setEntityInput(e.target.value)}
            />
            <button
              className="btn btn-primary"
              onClick={async () => {
                if (!entityInput) return;
                try {
                  const r = await api.uebaEntity(entityInput);
                  setEntityResult(r);
                } catch {
                  try {
                    const r = await api.entityById(entityInput);
                    setEntityResult(r);
                  } catch {
                    toast('Entity not found', 'error');
                  }
                }
              }}
            >
              Lookup
            </button>
          </div>
          {entityResult && (
            <>
              <SummaryGrid data={entityResult} limit={12} />
              <JsonDetails data={entityResult} />
            </>
          )}
        </div>
      )}

      {tab === 'rbac' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">RBAC Users</span>
            <button className="btn btn-sm" onClick={rRbac}>
              ↻ Refresh
            </button>
          </div>
          {rbacArr.length === 0 ? (
            <div className="empty">No RBAC users</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rbacArr.map((u, i) => (
                    <tr key={i}>
                      <td>{u.username || u.name || '—'}</td>
                      <td>
                        <span className="badge badge-info">{u.role || '—'}</span>
                      </td>
                      <td>{u.created || '—'}</td>
                      <td>
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={async () => {
                            try {
                              await api.deleteRbacUser(u.username || u.name);
                              toast('User removed', 'success');
                              rRbac();
                            } catch {
                              toast('Failed', 'error');
                            }
                          }}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'investigations' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Investigation Workflows</span>
            <button className="btn btn-sm" onClick={rInv}>
              ↻ Refresh
            </button>
          </div>
          {investigationContext && (
            <div className="card" style={{ marginBottom: 16, background: 'var(--bg)' }}>
              <div className="card-header">
                <div>
                  <div className="card-title">Planner Context</div>
                  <div className="hint">
                    {investigationContext.sourceType || 'signal'} •{' '}
                    {investigationContext.title ||
                      investigationContext.summary ||
                      investigationContext.message ||
                      investigationContext.id ||
                      'Untitled signal'}
                  </div>
                </div>
                <div className="btn-group">
                  <button
                    className="btn btn-sm"
                    onClick={() => pivotPlannerToHunt(investigationContext)}
                  >
                    Open Hunt
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() => {
                      setInvestigationContext(null);
                      setPlannerSuggestions([]);
                    }}
                  >
                    Clear
                  </button>
                </div>
              </div>
              <div className="summary-grid">
                <div className="summary-card">
                  <div className="summary-label">Severity</div>
                  <div className="summary-value">{investigationContext.severity || '—'}</div>
                  <div className="summary-meta">
                    {investigationContext.rule_id ||
                      investigationContext.id ||
                      'No explicit rule or incident ID'}
                  </div>
                </div>
                <div className="summary-card">
                  <div className="summary-label">Suggested Workflows</div>
                  <div className="summary-value">
                    {plannerLoading ? '…' : plannerSuggestions.length}
                  </div>
                  <div className="summary-meta">
                    Matched from incident or alert wording using backend workflow triggers.
                  </div>
                </div>
              </div>
              <div style={{ marginTop: 12 }}>
                {plannerLoading ? (
                  <div className="hint">Evaluating workflow matches for this context…</div>
                ) : plannerSuggestions.length === 0 ? (
                  <div className="hint">
                    No workflow suggestion matched. Use the hunt pivot to build a rule-specific
                    search instead.
                  </div>
                ) : (
                  plannerSuggestions.map((workflow) => (
                    <div
                      key={workflow.id}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        gap: 12,
                        padding: '10px 0',
                        borderBottom: '1px solid var(--border)',
                      }}
                    >
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: 600 }}>{workflow.name}</div>
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                          {workflow.description}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                          {(workflow.steps || []).length} steps •{' '}
                          {(workflow.mitre_techniques || []).join(', ') || 'No ATT&CK mapping'}
                        </div>
                      </div>
                      <div className="btn-group" style={{ alignItems: 'center' }}>
                        <span
                          className={`badge ${(workflow.severity || '').toLowerCase() === 'critical' || (workflow.severity || '').toLowerCase() === 'high' ? 'badge-err' : 'badge-info'}`}
                        >
                          {workflow.severity || 'medium'}
                        </span>
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={() => startWorkflow(workflow, investigationContext.case_id)}
                          disabled={startingWorkflowId === workflow.id}
                        >
                          {startingWorkflowId === workflow.id ? 'Starting…' : 'Start'}
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
          {workflows && Array.isArray(workflows) && workflows.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Severity</th>
                    <th>MITRE</th>
                    <th>Est. Time</th>
                    <th>Steps</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {workflows.map((wf, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{wf.id}</td>
                      <td style={{ fontWeight: 600 }}>{wf.name}</td>
                      <td>
                        <span className={`sev-${(wf.severity || 'medium').toLowerCase()}`}>
                          {wf.severity}
                        </span>
                      </td>
                      <td style={{ fontSize: 11 }}>{(wf.mitre_techniques || []).join(', ')}</td>
                      <td>{wf.estimated_minutes}m</td>
                      <td>{(wf.steps || []).length}</td>
                      <td>
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={() => startWorkflow(wf, investigationContext?.case_id)}
                          disabled={startingWorkflowId === wf.id}
                        >
                          {startingWorkflowId === wf.id ? 'Starting…' : 'Start'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty">No workflows available</div>
          )}
          {activeInvestigations &&
            Array.isArray(activeInvestigations) &&
            activeInvestigations.length > 0 && (
              <div style={{ marginTop: 20 }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
                  Active Investigations
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Workflow</th>
                        <th>Analyst</th>
                        <th>Started</th>
                        <th>Progress</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeInvestigations.map((inv, i) => (
                        <tr key={i}>
                          <td>{inv.workflow_id}</td>
                          <td>{inv.analyst}</td>
                          <td style={{ fontSize: 11 }}>{inv.started_at}</td>
                          <td>{(inv.completed_steps || []).length} steps done</td>
                          <td>
                            <span
                              className={`badge ${inv.status === 'in-progress' ? 'badge-warn' : 'badge-ok'}`}
                            >
                              {inv.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
        </div>
      )}

      {tab === 'efficacy' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Detection Efficacy</span>
            <button className="btn btn-sm" onClick={rEfficacy}>
              ↻ Refresh
            </button>
          </div>
          {efficacyData ? (
            <>
              <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap' }}>
                {Object.entries(efficacyData)
                  .filter(([, v]) => typeof v !== 'object')
                  .map(([k, v]) => (
                    <div
                      key={k}
                      style={{
                        padding: '6px 12px',
                        background: 'var(--bg)',
                        borderRadius: 6,
                        textAlign: 'center',
                      }}
                    >
                      <div
                        style={{
                          fontSize: 10,
                          color: 'var(--text-secondary)',
                          textTransform: 'uppercase',
                        }}
                      >
                        {k.replace(/_/g, ' ')}
                      </div>
                      <div style={{ fontSize: 18, fontWeight: 700 }}>
                        {typeof v === 'number' ? v.toFixed(2) : String(v)}
                      </div>
                    </div>
                  ))}
              </div>
              <JsonDetails data={efficacyData} />
            </>
          ) : (
            <div className="empty">No efficacy data yet — triage alerts to populate</div>
          )}
        </div>
      )}

      {tab === 'timeline' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Host Timeline
          </div>
          {(() => {
            const events =
              tlHost?.events || tlHost?.timeline || (Array.isArray(tlHost) ? tlHost : []);
            if (events.length === 0 && !tlHost) return <div className="empty">Loading...</div>;
            if (events.length === 0) return <div className="empty">No timeline events</div>;
            return (
              <div style={{ borderLeft: '2px solid var(--primary)', paddingLeft: 16 }}>
                {events.map((ev, i) => (
                  <div key={i} style={{ marginBottom: 12, position: 'relative' }}>
                    <div
                      style={{
                        position: 'absolute',
                        left: -22,
                        top: 4,
                        width: 10,
                        height: 10,
                        borderRadius: '50%',
                        background: 'var(--primary)',
                      }}
                    />
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>
                      {ev.timestamp || ev.time || '—'}
                      {ev.host && <span style={{ marginLeft: 8, fontWeight: 600 }}>{ev.host}</span>}
                    </div>
                    <div style={{ fontSize: 13 }}>
                      {ev.severity && (
                        <span
                          className={`sev-${ev.severity.toLowerCase()}`}
                          style={{ marginRight: 8 }}
                        >
                          {ev.severity}
                        </span>
                      )}
                      {ev.event || ev.message || ev.description || ev.action || JSON.stringify(ev)}
                    </div>
                  </div>
                ))}
              </div>
            );
          })()}
        </div>
      )}

      {tab === 'investigation-timeline' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Investigation Timeline
          </div>
          <InvestigationTimeline />
        </div>
      )}

      {tab === 'playbooks' && <PlaybookEditor />}

      {tab === 'campaigns' && <CampaignGraph />}

      <ProcessDrawer
        pid={selectedProcess?.pid}
        snapshot={selectedProcess}
        onClose={() => setSelectedProcess(null)}
        onUpdated={() => {
          rLive();
          rProcFindings();
        }}
      />
    </div>
  );
}

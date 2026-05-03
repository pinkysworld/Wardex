import { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useApiGroup, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import ProcessDrawer from './ProcessDrawer.jsx';
import WorkflowGuidance from './WorkflowGuidance.jsx';
import { JsonDetails, SideDrawer, SummaryGrid } from './operator.jsx';
import InvestigationTimeline from './InvestigationTimeline.jsx';
import { downloadData, formatDateTime, formatRelativeTime } from './operatorUtils.js';
import { buildLongRetentionHistoryPath } from './settings/helpers.js';
import { buildHref } from './workflowPivots.js';

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

const retentionHistoryQueryFromRollout = (rollouts) => {
  const recentEvent = Array.isArray(rollouts?.recent_history) ? rollouts.recent_history[0] : null;
  const query = {
    since: recentEvent?.recorded_at || rollouts?.last_rollout_at || '',
    limit: 25,
  };

  // Content-rule rollout history stores rule ids in agent_id; only seed device filters for
  // rollout events that actually target a deployable agent surface.
  if (recentEvent?.agent_id && recentEvent?.platform !== 'content-rule') {
    query.device_id = recentEvent.agent_id;
  }

  return query;
};

const splitMultilineList = (value) =>
  String(value || '')
    .split('\n')
    .map((entry) => entry.trim())
    .filter(Boolean);

const investigationStatusBadgeClass = (status) => {
  switch (status) {
    case 'handoff-ready':
      return 'badge-warn';
    case 'completed':
      return 'badge-ok';
    default:
      return 'badge-info';
  }
};

const investigationStatusLabel = (status) => {
  switch (status) {
    case 'handoff-ready':
      return 'Handoff Ready';
    case 'in-progress':
      return 'In Progress';
    case 'completed':
      return 'Completed';
    default:
      return status || 'Unknown';
  }
};

const caseStatusBadgeClass = (status) => {
  switch (String(status || '').toLowerCase()) {
    case 'resolved':
    case 'closed':
      return 'badge-ok';
    case 'escalated':
      return 'badge-err';
    default:
      return 'badge-warn';
  }
};

const casePriorityBadgeClass = (priority) => {
  switch (String(priority || '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'badge-err';
    case 'medium':
      return 'badge-warn';
    default:
      return 'badge-info';
  }
};

const caseContainmentLabel = (status) => {
  switch (String(status || '').toLowerCase()) {
    case 'resolved':
    case 'closed':
      return 'Contained';
    case 'escalated':
      return 'Escalated';
    case 'investigating':
      return 'Investigating';
    case 'triaging':
      return 'Triaging';
    default:
      return 'Open';
  }
};

const INCIDENT_DRAWER_PANELS = [
  { id: 'summary', label: 'Summary' },
  { id: 'storyline', label: 'Storyline' },
  { id: 'actions', label: 'Actions' },
];

const CASE_DRAWER_PANELS = [
  { id: 'summary', label: 'Summary' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'actions', label: 'Actions' },
];

const normalizePanelId = (value, panels, fallback) =>
  panels.some((panel) => panel.id === value) ? value : fallback;

const mergeSearchState = (searchParams, updates = {}) => {
  const next = Object.fromEntries(searchParams.entries());
  Object.entries(updates).forEach(([key, value]) => {
    if (value == null) {
      delete next[key];
      return;
    }

    const normalized = String(value).trim();
    if (!normalized) delete next[key];
    else next[key] = normalized;
  });
  return next;
};

const formatResponseTarget = (entry) => {
  if (!entry) return '—';

  const target = entry.target;
  const targetTags = Array.isArray(target?.asset_tags) ? target.asset_tags.filter(Boolean) : [];
  const parts = [
    typeof target === 'string' ? target : '',
    entry.target_hostname,
    target?.hostname,
    entry.target_agent_uid,
    target?.agent_uid,
    entry.host,
    entry.hostname,
    entry.agent_id,
    entry.endpoint_id,
    entry.entity_id,
    ...targetTags,
  ]
    .map((value) => String(value || '').trim())
    .filter(Boolean);

  if (parts.length > 0) return parts.join(' · ');
  if (typeof target === 'number') return String(target);
  if (target && typeof target === 'object') return JSON.stringify(target);
  return String(entry.id || entry.alert_id || '—');
};

function resolveInvestigationPivot(endpoint, context, label) {
  const normalized = String(endpoint || '').trim();
  if (!normalized) return null;

  if (normalized.startsWith('/api/ueba/risky')) {
    return {
      label: label || 'Open UEBA',
      to: buildHref('/ueba', {
        params: {
          entity:
            context?.entity_id || context?.user || context?.username || context?.principal || '',
        },
      }),
    };
  }

  if (
    normalized.startsWith('/api/lateral/analyze') ||
    normalized.startsWith('/api/killchain/reconstruct')
  ) {
    return {
      label: label || 'Open Attack Graph',
      to: buildHref('/attack-graph', {
        params: { node: context?.host || context?.agent_id || context?.entity_id || '' },
      }),
    };
  }

  if (normalized.startsWith('/api/beacon/analyze')) {
    return {
      label: label || 'Open NDR',
      to: buildHref('/ndr', { params: { tab: 'beaconing' } }),
    };
  }

  if (
    normalized.startsWith('/api/processes/analysis') ||
    normalized.startsWith('/api/processes/live')
  ) {
    return { label: label || 'Open Process Tree', to: '/soc#process-tree' };
  }

  if (normalized.startsWith('/api/response/request')) {
    return { label: label || 'Open Response', to: '/soc#response' };
  }

  if (normalized.startsWith('/api/container/alerts')) {
    return {
      label: label || 'Open Infrastructure',
      to: buildHref('/infrastructure', {
        params: { tab: 'observability', q: context?.host || context?.agent_id || '' },
      }),
    };
  }

  if (normalized.startsWith('/api/evidence/plan')) {
    return {
      label: label || 'Open Evidence',
      to: buildHref('/reports', {
        params: {
          tab: 'evidence',
          case: context?.case_id || context?.caseId || undefined,
          incident: context?.incident_id || context?.incidentId || undefined,
          investigation:
            context?.investigation_id ||
            context?.investigationId ||
            context?.workflow_id ||
            undefined,
          source: context?.source || context?.workflow_source || 'investigation',
        },
      }),
    };
  }

  if (normalized.startsWith('/api/events') || normalized.startsWith('/api/alerts')) {
    return {
      label: label || 'Launch Hunt',
      to: buildHref('/detection', {
        params: {
          intent: 'run-hunt',
          huntQuery: buildPlannerHuntQuery(context),
          huntName: buildPlannerHuntName(context),
        },
      }),
    };
  }

  return null;
}

function collectStepPivots(step, context) {
  const pivots = [];
  const pushPivot = (pivot, key, description) => {
    if (!pivot || !pivot.to || pivots.some((entry) => entry.to === pivot.to)) return;
    pivots.push({
      key,
      label: pivot.label,
      to: pivot.to,
      description,
    });
  };

  pushPivot(
    resolveInvestigationPivot(step?.api_pivot, context, 'Open Primary Pivot'),
    `${step?.order || 'step'}-primary`,
    step?.description,
  );

  (step?.auto_queries || []).forEach((query, index) => {
    pushPivot(
      resolveInvestigationPivot(query.endpoint, context, query.name),
      `${step?.order || 'step'}-query-${index}`,
      query.description,
    );
  });

  return pivots;
}

const formatPct = (value) => `${Math.round((Number(value) || 0) * 100)}%`;

const formatMs = (value) => {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? `${Math.round(numeric)} ms` : '—';
};

// ── Campaign Correlation Graph (SVG) ───────────────────────────
function CampaignGraph({ campaignData }) {
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
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const focusedCaseId = searchParams.get('case') || '';
  const focusedInvestigationParam = searchParams.get('investigation') || '';
  const responseTarget = searchParams.get('target') || '';
  const responseSource = searchParams.get('source') || '';
  const focusedIncidentParam = searchParams.get('incident') || '';
  const drawerMode = searchParams.get('drawer') || '';
  const queueFilterParam = searchParams.get('queueFilter') || '';
  const incidentDrawerPanel = normalizePanelId(
    searchParams.get('incidentPanel'),
    INCIDENT_DRAWER_PANELS,
    'summary',
  );
  const caseDrawerPanel = normalizePanelId(
    searchParams.get('casePanel'),
    CASE_DRAWER_PANELS,
    'summary',
  );

  const navigateSoc = useCallback(
    (updates = {}, { hash = location.hash.replace('#', '') || undefined, replace = false } = {}) =>
      navigate(
        buildHref('/soc', {
          params: mergeSearchState(searchParams, updates),
          hash,
        }),
        { replace },
      ),
    [location.hash, navigate, searchParams],
  );

  // Persist active tab in URL hash
  const [tab, setTabRaw] = useState(() => {
    const h = location.hash.replace('#', '');
    return TAB_GROUPS.some((g) => g.tabs.includes(h)) ? h : 'overview';
  });
  const setTab = useCallback(
    (t) => {
      setTabRaw(t);
      navigateSoc({}, { hash: t });
    },
    [navigateSoc],
  );
  useEffect(() => {
    const h = location.hash.replace('#', '');
    if (TAB_GROUPS.some((g) => g.tabs.includes(h))) {
      setTabRaw(h);
    }
  }, [location.hash]);
  const [collapsedGroups, setCollapsedGroups] = useState({});
  const toggleGroup = useCallback(
    (label) => setCollapsedGroups((p) => ({ ...p, [label]: !p[label] })),
    [],
  );

  const { data: socTriageData, reload: reloadSocTriage } = useApiGroup({
    overview: api.workbenchOverview,
    incList: api.incidents,
    caseList: api.cases,
    caseStats: api.casesStats,
    queue: api.queueAlerts,
    qStats: api.queueStats,
    wsStats: api.wsStats,
  });
  const { overview, incList, caseList, caseStats, queue, qStats, wsStats } = socTriageData;
  const rInc = reloadSocTriage;
  const rCases = reloadSocTriage;
  const rQueue = reloadSocTriage;
  const { data: responseData, reload: reloadResponseData } = useApiGroup({
    pending: api.responsePending,
    respReq: api.responseRequests,
    respAudit: api.responseAudit,
    respStats: api.responseStats,
  });
  const { pending, respReq, respAudit, respStats } = responseData;
  const { data: processTreeData, reload: reloadProcessTreeData } = useApiGroup({
    procs: api.processTree,
    deepCh: api.deepChains,
    liveProcs: api.processesLive,
    procFindings: api.processesAnalysis,
  });
  const { procs, deepCh, liveProcs, procFindings } = processTreeData;
  const { data: socAdminData, reload: reloadSocAdmin } = useApiGroup({
    rbacData: api.rbacUsers,
    campaignData: api.campaigns,
  });
  const { rbacData, campaignData } = socAdminData;
  const rRbac = reloadSocAdmin;
  const { data: escalationData, reload: reloadEscalationData } = useApiGroup({
    escPolicies: api.escalationPolicies,
    escActive: api.escalationActive,
  });
  const { escPolicies, escActive } = escalationData;
  const rEsc = reloadEscalationData;
  const rEscActive = reloadEscalationData;
  const { data: investigationData, reload: reloadInvestigations } = useApiGroup({
    workflows: api.investigationWorkflows,
    activeInvestigations: api.investigationActive,
  });
  const { workflows, activeInvestigations } = investigationData;
  const rInv = reloadInvestigations;
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
  const [selectedInvestigationId, setSelectedInvestigationId] = useState('');
  const [stepNoteDrafts, setStepNoteDrafts] = useState({});
  const [findingDraft, setFindingDraft] = useState('');
  const [savingProgressKey, setSavingProgressKey] = useState('');
  const [handoffDraft, setHandoffDraft] = useState({
    toAnalyst: '',
    summary: '',
    nextActions: '',
    questions: '',
  });
  const [savingHandoff, setSavingHandoff] = useState(false);
  const [caseTitleDrafts, setCaseTitleDrafts] = useState({});
  const [analystPrompt, setAnalystPrompt] = useState('show me high severity alerts from this week');
  const [analystResult, setAnalystResult] = useState(null);
  const [analystLoading, setAnalystLoading] = useState(false);
  const [queueFilterText, setQueueFilterText] = useState(queueFilterParam);
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
  const [ticketSyncDraft, setTicketSyncDraft] = useState({
    caseId: null,
    provider: 'jira',
    queueOrProject: '',
    summary: null,
  });
  const [ticketSyncLoading, setTicketSyncLoading] = useState(false);
  const [ticketSyncResult, setTicketSyncResult] = useState(null);
  const [caseWorkspaceComment, setCaseWorkspaceComment] = useState('');
  const [caseWorkspaceCommentSaving, setCaseWorkspaceCommentSaving] = useState(false);
  const [drawerIncidentDetail, setDrawerIncidentDetail] = useState(null);
  const [drawerIncidentStoryline, setDrawerIncidentStoryline] = useState(null);
  const incidentDrawerRequestRef = useRef(0);

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
    reloadSocTriage();
    rEscActive();
  }, 15000);
  useInterval(
    () => {
      if (tab === 'response') {
        reloadResponseData();
      }
    },
    tab === 'response' ? 15000 : null,
  );
  useInterval(
    () => {
      if (tab === 'process-tree') {
        reloadProcessTreeData();
      }
    },
    tab === 'process-tree' ? 15000 : null,
  );

  const incArr = Array.isArray(incList) ? incList : incList?.incidents || [];
  const caseArr = Array.isArray(caseList) ? caseList : caseList?.cases || [];
  const queueArr = Array.isArray(queue) ? queue : queue?.queue || queue?.alerts || [];
  const rbacArr = Array.isArray(rbacData) ? rbacData : rbacData?.users || [];
  const activeInvestigationArr = useMemo(() => {
    if (Array.isArray(activeInvestigations)) return activeInvestigations;
    return Array.isArray(activeInvestigations?.items) ? activeInvestigations.items : [];
  }, [activeInvestigations]);
  const filteredQueueArr = queueArr.filter((alert) => {
    const q = queueFilterText.trim().toLowerCase();
    if (!q) return true;
    return JSON.stringify(alert || {})
      .toLowerCase()
      .includes(q);
  });
  const casesById = Object.fromEntries(caseArr.map((caseItem) => [String(caseItem.id), caseItem]));
  const selectedCaseIdList = [...selectedCaseIds];
  const focusedCase = focusedCaseId ? casesById[String(focusedCaseId)] || null : null;
  const preferredTicketCase =
    (selectedCaseIdList.length === 1 && casesById[String(selectedCaseIdList[0])]) ||
    focusedCase ||
    caseArr[0] ||
    null;
  const activeTicketCaseId =
    ticketSyncDraft.caseId ?? (preferredTicketCase ? String(preferredTicketCase.id) : '');
  const activeTicketCase = activeTicketCaseId
    ? casesById[String(activeTicketCaseId)] || preferredTicketCase
    : preferredTicketCase;
  const activeWorkspaceCase =
    focusedCase ||
    (selectedCaseIdList.length === 1 ? casesById[String(selectedCaseIdList[0])] || null : null) ||
    caseArr[0] ||
    null;
  const defaultTicketSummary = activeTicketCase
    ? `Case #${activeTicketCase.id}: ${activeTicketCase.title || 'Investigation'}`
    : 'SOC investigation sync';
  const activeTicketSummary = ticketSyncDraft.summary ?? defaultTicketSummary;
  const assistantCaseHref = activeTicketCaseId
    ? `/assistant?case=${activeTicketCaseId}`
    : '/assistant';
  const focusedInvestigation = focusedInvestigationParam
    ? activeInvestigationArr.find((entry) => entry.id === focusedInvestigationParam) || null
    : null;
  const selectedInvestigation =
    activeInvestigationArr.find((entry) => entry.id === selectedInvestigationId) ||
    activeInvestigationArr[0] ||
    null;
  const selectedInvestigationIdentity = selectedInvestigation?.id || '';
  const selectedInvestigationHandoff = selectedInvestigation?.handoff || null;
  const selectedInvestigationCase = selectedInvestigation?.case_id
    ? casesById[String(selectedInvestigation.case_id)] || null
    : null;
  const activeWorkspaceInvestigation = activeWorkspaceCase
    ? activeInvestigationArr.find(
        (entry) => String(entry.case_id || '') === String(activeWorkspaceCase.id),
      ) || null
    : null;
  const activeCaseIncidentIds = Array.isArray(activeWorkspaceCase?.incident_ids)
    ? activeWorkspaceCase.incident_ids
    : [];
  const activeCaseEventIds = Array.isArray(activeWorkspaceCase?.event_ids)
    ? activeWorkspaceCase.event_ids
    : [];
  const activeCaseEvidence = Array.isArray(activeWorkspaceCase?.evidence)
    ? activeWorkspaceCase.evidence
    : [];
  const activeCaseComments = Array.isArray(activeWorkspaceCase?.comments)
    ? activeWorkspaceCase.comments
    : [];
  const activeCaseTags = Array.isArray(activeWorkspaceCase?.tags) ? activeWorkspaceCase.tags : [];
  const activeCaseMitre = Array.isArray(activeWorkspaceCase?.mitre_techniques)
    ? activeWorkspaceCase.mitre_techniques
    : [];
  const queueSeed = investigationContext || filteredQueueArr[0] || incArr[0] || null;
  const investigationDetailContext =
    selectedInvestigationCase ||
    investigationContext ||
    (selectedInvestigation
      ? {
          title: selectedInvestigation.workflow_name,
          summary: selectedInvestigation.workflow_description,
          id: selectedInvestigation.workflow_id,
          severity: selectedInvestigation.workflow_severity,
          case_id: selectedInvestigation.case_id,
        }
      : queueSeed || null);
  const queueSeedLabel =
    queueSeed?.title ||
    queueSeed?.summary ||
    queueSeed?.message ||
    queueSeed?.id ||
    'active signal';
  const queueSeedEntity =
    queueSeed?.entity_id || queueSeed?.user || queueSeed?.username || queueSeed?.principal || '';
  const queueSeedHost = queueSeed?.host || queueSeed?.agent_id || queueSeed?.endpoint_id || '';
  const investigationResponseTarget =
    investigationDetailContext?.host ||
    investigationDetailContext?.agent_id ||
    investigationDetailContext?.endpoint_id ||
    investigationDetailContext?.entity_id ||
    queueSeedHost ||
    queueSeedEntity;
  const timelineHostTarget =
    investigationDetailContext?.host ||
    investigationDetailContext?.agent_id ||
    investigationDetailContext?.endpoint_id ||
    queueSeedHost ||
    '';
  const { data: socInsightData, reload: reloadSocInsights } = useApiGroup(
    {
      tlHost: () => api.timelineHost(timelineHostTarget),
      efficacyData: api.efficacySummary,
    },
    [timelineHostTarget],
  );
  const { tlHost, efficacyData } = socInsightData;
  const rEfficacy = reloadSocInsights;
  const rTimeline = reloadSocInsights;
  const hasResponseContext = Boolean(
    focusedCaseId || focusedInvestigationParam || responseTarget || responseSource,
  );
  const caseDrawerOpen = drawerMode === 'case-workspace' && Boolean(focusedCaseId);
  const incidentDrawerOpen = drawerMode === 'incident-detail' && Boolean(focusedIncidentParam);
  const drawerIncidentEvents =
    drawerIncidentStoryline?.events ||
    drawerIncidentStoryline?.steps ||
    (Array.isArray(drawerIncidentStoryline) ? drawerIncidentStoryline : []);
  const drawerIncidentCaseId =
    drawerIncidentDetail?.case_id || drawerIncidentDetail?.linked_case_id || focusedCaseId || '';
  const workflowItems = [
    {
      id: 'threat-detection',
      title: 'Pivot To Threat Detection',
      description: `Turn ${queueSeedLabel} into a hunt or tuning workflow without rebuilding the query.`,
      to: buildHref('/detection', {
        params: {
          intent: 'run-hunt',
          huntQuery: buildPlannerHuntQuery(queueSeed),
          huntName: buildPlannerHuntName(queueSeed),
        },
      }),
      minRole: 'analyst',
      tone: 'primary',
      badge: 'Detect',
    },
    queueSeedEntity
      ? {
          id: 'ueba',
          title: 'Inspect UEBA Risk',
          description: `Open entity-risk analytics for ${queueSeedEntity} before escalating further.`,
          to: buildHref('/ueba', { params: { entity: queueSeedEntity } }),
          minRole: 'analyst',
          badge: 'Entity',
        }
      : null,
    {
      id: 'infrastructure',
      title: 'Review Asset Context',
      description:
        'Check infrastructure exposure, drift, and observability evidence around the active case or alert.',
      to: buildHref('/infrastructure', {
        params: { tab: 'assets', q: queueSeedHost || queueSeedEntity },
      }),
      minRole: 'analyst',
      badge: 'Asset',
    },
    {
      id: 'process-tree',
      title: 'Open Process Tree',
      description: queueSeedHost
        ? `Inspect live processes, deep chains, and raw process evidence for ${queueSeedHost}.`
        : 'Inspect live processes, deep chains, and raw process evidence for the active scope.',
      to: buildHref('/soc', {
        params: {
          case: focusedCaseId || undefined,
          incident: focusedIncidentParam || undefined,
          investigation: focusedInvestigationParam || undefined,
        },
        hash: 'process-tree',
      }),
      actionLabel: 'Open Process Tree',
      minRole: 'analyst',
      badge: 'Process',
    },
    {
      id: 'attack-graph',
      title: 'Open Campaign Graph',
      description:
        'Validate whether the current investigation belongs to a broader propagation path.',
      to: '/attack-graph',
      minRole: 'analyst',
      badge: 'Graph',
    },
    {
      id: 'reports',
      title: 'Export Delivery Snapshot',
      description:
        'Package response posture, case progress, and approvals into report delivery workflows.',
      to: buildHref('/reports', {
        params: {
          tab: 'delivery',
          case: focusedCaseId || undefined,
          incident: focusedIncidentParam || undefined,
          investigation: focusedInvestigationParam || undefined,
          source: responseSource || 'soc-workbench',
          target: responseTarget || investigationResponseTarget || undefined,
        },
      }),
      minRole: 'viewer',
      badge: 'Report',
    },
  ].filter(Boolean);

  const openCaseFocus = useCallback(
    (caseId) => {
      if (!caseId) return;
      navigateSoc(
        {
          case: caseId,
          drawer: undefined,
          casePanel: undefined,
          incident: undefined,
          incidentPanel: undefined,
        },
        { hash: 'cases' },
      );
    },
    [navigateSoc],
  );

  const openCaseDrawer = useCallback(
    (caseId, { panel = 'summary', hash = 'cases' } = {}) => {
      if (!caseId) return;
      navigateSoc(
        {
          case: caseId,
          drawer: 'case-workspace',
          casePanel: panel,
          incident: undefined,
          incidentPanel: undefined,
        },
        { hash },
      );
    },
    [navigateSoc],
  );

  const openInvestigationFocus = useCallback(
    (investigationId, caseId) => {
      if (!investigationId) return;
      navigateSoc(
        {
          investigation: investigationId,
          case: caseId || undefined,
          drawer: undefined,
          casePanel: undefined,
          incident: undefined,
          incidentPanel: undefined,
        },
        { hash: 'investigations' },
      );
    },
    [navigateSoc],
  );

  const openResponseFocus = useCallback(
    ({ caseId, investigationId, target, source } = {}) => {
      navigateSoc(
        {
          case: caseId || undefined,
          investigation: investigationId || undefined,
          target: target || undefined,
          source: source || undefined,
          drawer: undefined,
          casePanel: undefined,
          incident: undefined,
          incidentPanel: undefined,
        },
        { hash: 'response' },
      );
    },
    [navigateSoc],
  );

  const openIncidentDrawer = useCallback(
    (incidentId, { caseId, panel = 'summary', hash = 'incidents' } = {}) => {
      if (!incidentId) return;
      navigateSoc(
        {
          case: caseId || focusedCaseId || undefined,
          incident: incidentId,
          drawer: 'incident-detail',
          casePanel: undefined,
          incidentPanel: panel,
        },
        { hash },
      );
    },
    [focusedCaseId, navigateSoc],
  );

  const closeCaseDrawer = useCallback(() => {
    navigateSoc(
      {
        drawer: undefined,
        casePanel: undefined,
      },
      { replace: true },
    );
  }, [navigateSoc]);

  const closeIncidentDrawer = useCallback(() => {
    navigateSoc(
      {
        drawer: undefined,
        casePanel: undefined,
        incident: undefined,
        incidentPanel: undefined,
      },
      { replace: true },
    );
  }, [navigateSoc]);

  useEffect(() => {
    if (activeInvestigationArr.length === 0) {
      if (selectedInvestigationId) setSelectedInvestigationId('');
      return;
    }
    if (
      focusedInvestigationParam &&
      activeInvestigationArr.some((entry) => entry.id === focusedInvestigationParam)
    ) {
      if (selectedInvestigationId !== focusedInvestigationParam) {
        setSelectedInvestigationId(focusedInvestigationParam);
      }
      return;
    }
    if (!activeInvestigationArr.some((entry) => entry.id === selectedInvestigationId)) {
      setSelectedInvestigationId(activeInvestigationArr[0].id);
    }
  }, [activeInvestigationArr, focusedInvestigationParam, selectedInvestigationId]);

  useEffect(() => {
    if (!selectedInvestigationIdentity) {
      setFindingDraft('');
      setHandoffDraft({ toAnalyst: '', summary: '', nextActions: '', questions: '' });
      return;
    }

    setFindingDraft('');
    setHandoffDraft({
      toAnalyst:
        selectedInvestigationHandoff?.to_analyst || selectedInvestigationCase?.assignee || '',
      summary: selectedInvestigationHandoff?.summary || '',
      nextActions: Array.isArray(selectedInvestigationHandoff?.next_actions)
        ? selectedInvestigationHandoff.next_actions.join('\n')
        : '',
      questions: Array.isArray(selectedInvestigationHandoff?.questions)
        ? selectedInvestigationHandoff.questions.join('\n')
        : '',
    });
  }, [
    selectedInvestigationIdentity,
    selectedInvestigationHandoff,
    selectedInvestigationCase?.assignee,
  ]);

  useEffect(() => {
    localStorage.setItem('wardex_saved_queue_filters', JSON.stringify(savedQueueFilters));
  }, [savedQueueFilters]);

  useEffect(() => {
    if (queueFilterText === queueFilterParam) return;
    setQueueFilterText(queueFilterParam);
  }, [queueFilterParam, queueFilterText]);

  useEffect(() => {
    setCaseWorkspaceComment('');
  }, [activeWorkspaceCase?.id]);

  const fetchDrawerIncidentDetail = useCallback(async (incidentId) => {
    if (!incidentId) {
      setDrawerIncidentDetail(null);
      setDrawerIncidentStoryline(null);
      return;
    }

    const requestId = ++incidentDrawerRequestRef.current;
    setDrawerIncidentDetail((current) =>
      String(current?.id || '') === String(incidentId) ? current : null,
    );
    setDrawerIncidentStoryline(null);

    try {
      const detail = await api.incidentById(incidentId);
      if (incidentDrawerRequestRef.current === requestId) setDrawerIncidentDetail(detail);
    } catch {
      if (incidentDrawerRequestRef.current === requestId) setDrawerIncidentDetail(null);
    }

    try {
      const storyline = await api.incidentStoryline(incidentId);
      if (incidentDrawerRequestRef.current === requestId) setDrawerIncidentStoryline(storyline);
    } catch {
      if (incidentDrawerRequestRef.current === requestId) setDrawerIncidentStoryline(null);
    }
  }, []);

  useEffect(() => {
    if (drawerMode !== 'incident-detail' || !focusedIncidentParam) {
      incidentDrawerRequestRef.current += 1;
      setDrawerIncidentDetail(null);
      setDrawerIncidentStoryline(null);
      return;
    }

    fetchDrawerIncidentDetail(focusedIncidentParam);
  }, [drawerMode, fetchDrawerIncidentDetail, focusedIncidentParam]);

  const updateQueueFilter = useCallback(
    (value, { replace = true } = {}) => {
      setQueueFilterText(value);
      navigateSoc(
        {
          queueFilter: value || undefined,
        },
        {
          hash: 'queue',
          replace,
        },
      );
    },
    [navigateSoc],
  );

  const startWorkflow = async (workflow, caseId) => {
    if (!workflow?.id) return;
    setStartingWorkflowId(workflow.id);
    try {
      const snapshot = await api.investigationStart({
        workflow_id: workflow.id,
        analyst: 'admin',
        case_id: caseId || undefined,
      });
      if (snapshot?.id) {
        setSelectedInvestigationId(snapshot.id);
        openInvestigationFocus(snapshot.id, snapshot.case_id || caseId);
      }
      toast('Investigation started', 'success');
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

  const saveInvestigationProgress = async (
    investigationId,
    payload,
    successMessage,
    progressKey,
  ) => {
    if (!investigationId) return;
    setSavingProgressKey(progressKey || investigationId);
    try {
      const snapshot = await api.investigationProgress({
        investigation_id: investigationId,
        ...payload,
      });
      if (snapshot?.id) setSelectedInvestigationId(snapshot.id);
      if (payload.finding) setFindingDraft('');
      rInv();
      toast(successMessage, 'success');
    } catch {
      toast('Failed to update investigation progress', 'error');
    } finally {
      setSavingProgressKey('');
    }
  };

  const submitInvestigationHandoff = async () => {
    if (!selectedInvestigation) return;
    if (!handoffDraft.toAnalyst.trim() || !handoffDraft.summary.trim()) {
      toast('Handoff target and summary are required', 'warning');
      return;
    }

    setSavingHandoff(true);
    try {
      const snapshot = await api.investigationHandoff({
        investigation_id: selectedInvestigation.id,
        to_analyst: handoffDraft.toAnalyst.trim(),
        summary: handoffDraft.summary.trim(),
        next_actions: splitMultilineList(handoffDraft.nextActions),
        questions: splitMultilineList(handoffDraft.questions),
        case_id: selectedInvestigation.case_id || undefined,
      });
      if (snapshot?.id) setSelectedInvestigationId(snapshot.id);
      rInv();
      rCases();
      toast('Investigation handed off', 'success');
    } catch {
      toast('Failed to hand off investigation', 'error');
    } finally {
      setSavingHandoff(false);
    }
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

  const syncSelectedCaseToTicket = async () => {
    if (!activeTicketCaseId) {
      toast('Select a case before syncing to ticketing', 'warning');
      return;
    }

    const summary = String(activeTicketSummary || '').trim() || defaultTicketSummary;
    setTicketSyncLoading(true);
    try {
      const result = await api.ticketsSync({
        provider: ticketSyncDraft.provider || 'jira',
        object_kind: 'case',
        object_id: String(activeTicketCaseId),
        queue_or_project: ticketSyncDraft.queueOrProject.trim() || undefined,
        summary,
      });
      setTicketSyncResult(result);
      setTicketSyncDraft((current) => ({ ...current, summary }));
      toast('Ticket sync submitted', 'success');
    } catch {
      setTicketSyncResult(null);
      toast('Ticket sync failed', 'error');
    } finally {
      setTicketSyncLoading(false);
    }
  };

  const addCaseWorkspaceComment = async () => {
    if (!activeWorkspaceCase?.id) return;
    const text = String(caseWorkspaceComment || '').trim();
    if (!text) {
      toast('Write a case note before posting it', 'warning');
      return;
    }

    setCaseWorkspaceCommentSaving(true);
    try {
      await api.caseComment(activeWorkspaceCase.id, { comment: text });
      setCaseWorkspaceComment('');
      toast('Case note added', 'success');
      rCases();
    } catch {
      toast('Failed to add case note', 'error');
    } finally {
      setCaseWorkspaceCommentSaving(false);
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

      <WorkflowGuidance
        title="SOC Pivots"
        description="Move from queue and case context into hunts, entity analytics, asset evidence, campaign mapping, and delivery reporting."
        items={workflowItems}
      />

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
                    <button
                      className="btn btn-sm"
                      style={{ marginTop: 10 }}
                      onClick={() =>
                        navigate(
                          buildLongRetentionHistoryPath(
                            retentionHistoryQueryFromRollout(overview.rollouts),
                          ),
                        )
                      }
                    >
                      Open retained events
                    </button>
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
                          <div className="btn-group">
                            <button className="btn btn-sm" onClick={() => viewInc(inc.id)}>
                              View
                            </button>
                            <button
                              className="btn btn-sm"
                              onClick={() =>
                                openIncidentDrawer(inc.id, {
                                  panel: 'summary',
                                  hash: 'incidents',
                                })
                              }
                            >
                              Open Drawer
                            </button>
                          </div>
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
                <div className="btn-group">
                  <button
                    className="btn btn-sm"
                    onClick={() =>
                      openIncidentDrawer(selectedInc, {
                        panel: 'summary',
                        hash: 'incidents',
                      })
                    }
                  >
                    Open Shareable Drawer
                  </button>
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
        <>
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
                <button className="btn btn-sm" onClick={() => navigate(assistantCaseHref)}>
                  Ask Assistant
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
                      <th>Workspace</th>
                    </tr>
                  </thead>
                  <tbody>
                    {caseArr.map((c, i) => (
                      <tr
                        key={i}
                        style={
                          String(c.id) === focusedCaseId
                            ? { background: 'rgba(59,130,246,.08)' }
                            : undefined
                        }
                      >
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
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                          {c.id || i}
                        </td>
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
                          <span className={`badge ${caseStatusBadgeClass(c.status)}`}>
                            {c.status || '—'}
                          </span>
                        </td>
                        <td>{c.assignee || c.owner || c.assigned_to || '—'}</td>
                        <td>{c.created_at || c.created || c.timestamp || '—'}</td>
                        <td>
                          <div className="btn-group">
                            <button className="btn btn-sm" onClick={() => openCaseFocus(c.id)}>
                              {String(c.id) === focusedCaseId ? 'Focused' : 'Open Workspace'}
                            </button>
                            <button
                              className="btn btn-sm"
                              onClick={() =>
                                openCaseDrawer(c.id, {
                                  panel: 'summary',
                                  hash: 'cases',
                                })
                              }
                            >
                              Open Drawer
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <span className="card-title">Focused Case Workspace</span>
                <div className="hint" style={{ marginTop: 6 }}>
                  Keep narrative, ownership, evidence, pivots, and notes together so analysts can
                  stay in one workflow instead of bouncing across tabs.
                </div>
              </div>
              <div className="btn-group">
                {activeWorkspaceCase && String(activeWorkspaceCase.id) !== focusedCaseId ? (
                  <button
                    className="btn btn-sm"
                    onClick={() => openCaseFocus(activeWorkspaceCase.id)}
                  >
                    Create Deep Link
                  </button>
                ) : null}
                <button
                  className="btn btn-sm"
                  disabled={!activeWorkspaceCase}
                  onClick={() =>
                    activeWorkspaceCase
                      ? openCaseDrawer(activeWorkspaceCase.id, {
                          panel: 'summary',
                          hash: 'cases',
                        })
                      : null
                  }
                >
                  Open Shareable Drawer
                </button>
                <button
                  className="btn btn-sm"
                  disabled={!activeWorkspaceCase}
                  onClick={() =>
                    activeWorkspaceInvestigation
                      ? openInvestigationFocus(
                          activeWorkspaceInvestigation.id,
                          activeWorkspaceCase?.id,
                        )
                      : setTab('investigations')
                  }
                >
                  {activeWorkspaceInvestigation ? 'Open Investigation' : 'Open Investigations'}
                </button>
                <button
                  className="btn btn-sm"
                  disabled={!activeWorkspaceCase}
                  onClick={() =>
                    navigate(
                      activeWorkspaceCase
                        ? `/assistant?case=${encodeURIComponent(activeWorkspaceCase.id)}`
                        : '/assistant',
                    )
                  }
                >
                  Ask Assistant
                </button>
                <button
                  className="btn btn-sm btn-primary"
                  disabled={!activeWorkspaceCase}
                  onClick={() =>
                    openResponseFocus({
                      caseId: activeWorkspaceCase?.id,
                      target: activeWorkspaceCase ? `case:${activeWorkspaceCase.id}` : undefined,
                      source: 'case',
                    })
                  }
                >
                  Open Response Workspace
                </button>
              </div>
            </div>
            {!activeWorkspaceCase ? (
              <div className="empty">
                Focus a case from the table or use a `?case=` deep link to open a case workspace.
              </div>
            ) : (
              <>
                <SummaryGrid
                  data={{
                    case_id: activeWorkspaceCase.id,
                    status: activeWorkspaceCase.status || 'new',
                    priority: activeWorkspaceCase.priority || 'medium',
                    containment: caseContainmentLabel(activeWorkspaceCase.status),
                    owner: activeWorkspaceCase.assignee || 'Unassigned',
                    updated_at: activeWorkspaceCase.updated_at || activeWorkspaceCase.created_at,
                    incidents: activeCaseIncidentIds.length,
                    events: activeCaseEventIds.length,
                    evidence: activeCaseEvidence.length,
                    comments: activeCaseComments.length,
                    linked_workflow: activeWorkspaceInvestigation?.workflow_name || 'Not started',
                  }}
                  limit={10}
                />

                <div
                  style={{
                    display: 'grid',
                    gap: 14,
                    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                    marginTop: 16,
                  }}
                >
                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Narrative
                    </div>
                    <div style={{ lineHeight: 1.5 }}>
                      {activeWorkspaceCase.description?.trim() ||
                        'No case narrative has been written yet. Use this workspace to track the analyst story, scope, and containment state.'}
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                      <span className={`badge ${caseStatusBadgeClass(activeWorkspaceCase.status)}`}>
                        {activeWorkspaceCase.status || 'new'}
                      </span>
                      <span
                        className={`badge ${casePriorityBadgeClass(activeWorkspaceCase.priority)}`}
                      >
                        {activeWorkspaceCase.priority || 'medium'}
                      </span>
                      {activeWorkspaceCase.assignee ? (
                        <span className="badge badge-info">
                          Owner {activeWorkspaceCase.assignee}
                        </span>
                      ) : null}
                    </div>
                  </div>

                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Linked Context
                    </div>
                    <div className="hint" style={{ marginBottom: 8 }}>
                      Follow the same case across incidents, events, ATT&CK mapping, and analyst
                      tags.
                    </div>
                    {activeCaseIncidentIds.length === 0 &&
                    activeCaseEventIds.length === 0 &&
                    activeCaseMitre.length === 0 &&
                    activeCaseTags.length === 0 ? (
                      <div className="empty">No linked evidence or context yet.</div>
                    ) : (
                      <>
                        {activeCaseIncidentIds.length > 0 ? (
                          <div style={{ marginBottom: 10 }}>
                            <div className="row-secondary" style={{ marginBottom: 6 }}>
                              Linked incidents
                            </div>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                              {activeCaseIncidentIds.map((incidentId) => (
                                <button
                                  key={`case-incident-${incidentId}`}
                                  className="btn btn-sm"
                                  onClick={() =>
                                    openIncidentDrawer(incidentId, {
                                      caseId: activeWorkspaceCase.id,
                                      panel: 'summary',
                                      hash: 'cases',
                                    })
                                  }
                                >
                                  {`Incident #${incidentId}`}
                                </button>
                              ))}
                            </div>
                          </div>
                        ) : null}
                        {activeCaseEventIds.length > 0 ? (
                          <div style={{ marginBottom: 10 }}>
                            <div className="row-secondary" style={{ marginBottom: 6 }}>
                              Linked events
                            </div>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                              {activeCaseEventIds.map((eventId) => (
                                <span key={`case-event-${eventId}`} className="badge badge-info">
                                  Event #{eventId}
                                </span>
                              ))}
                            </div>
                          </div>
                        ) : null}
                        {activeCaseMitre.length > 0 ? (
                          <div style={{ marginBottom: 10 }}>
                            <div className="row-secondary" style={{ marginBottom: 6 }}>
                              ATT&CK coverage
                            </div>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                              {activeCaseMitre.map((technique) => (
                                <span key={`case-mitre-${technique}`} className="badge badge-info">
                                  {technique}
                                </span>
                              ))}
                            </div>
                          </div>
                        ) : null}
                        {activeCaseTags.length > 0 ? (
                          <div>
                            <div className="row-secondary" style={{ marginBottom: 6 }}>
                              Analyst tags
                            </div>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                              {activeCaseTags.map((tag) => (
                                <span key={`case-tag-${tag}`} className="badge badge-info">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          </div>
                        ) : null}
                      </>
                    )}
                  </div>
                </div>

                <div className="card-title" style={{ marginTop: 18, marginBottom: 12 }}>
                  Recommended pivots
                </div>
                <div className="btn-group" style={{ flexWrap: 'wrap' }}>
                  <button className="btn btn-sm" onClick={() => setTab('investigations')}>
                    Investigation timeline
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() =>
                      navigate(
                        buildHref('/reports', {
                          params: {
                            tab: 'evidence',
                            case: activeWorkspaceCase?.id || focusedCaseId || undefined,
                            incident: focusedIncidentParam || undefined,
                            investigation:
                              activeWorkspaceInvestigation?.id ||
                              focusedInvestigationParam ||
                              undefined,
                            source: responseSource || 'case-workspace',
                            target: responseTarget || undefined,
                          },
                        }),
                      )
                    }
                  >
                    Evidence report
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() =>
                      navigate(buildHref('/infrastructure', { params: { tab: 'assets' } }))
                    }
                  >
                    Asset context
                  </button>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() =>
                      openResponseFocus({
                        caseId: activeWorkspaceCase.id,
                        target: `case:${activeWorkspaceCase.id}`,
                        source: 'case',
                      })
                    }
                  >
                    Response approvals
                  </button>
                </div>

                <div
                  style={{
                    display: 'grid',
                    gap: 14,
                    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                    marginTop: 16,
                  }}
                >
                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Evidence
                    </div>
                    {activeCaseEvidence.length === 0 ? (
                      <div className="empty">No evidence linked yet.</div>
                    ) : (
                      <div style={{ display: 'grid', gap: 10 }}>
                        {activeCaseEvidence.map((item, index) => (
                          <div
                            key={`${item.reference_id || item.kind || 'evidence'}-${index}`}
                            style={{
                              border: '1px solid var(--border)',
                              borderRadius: 10,
                              padding: 12,
                              background: 'var(--bg)',
                            }}
                          >
                            <div className="row-primary">
                              {item.description || item.reference_id || 'Linked evidence'}
                            </div>
                            <div className="row-secondary">
                              {item.kind || 'unknown'} · {item.reference_id || 'no reference'}
                            </div>
                            <div className="row-secondary" style={{ marginTop: 6 }}>
                              Added {item.added_at ? formatDateTime(item.added_at) : 'recently'}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Case Notes
                    </div>
                    {activeCaseComments.length === 0 ? (
                      <div className="empty">No case notes yet.</div>
                    ) : (
                      <div style={{ display: 'grid', gap: 10 }}>
                        {activeCaseComments.map((comment, index) => (
                          <div
                            key={`${comment.timestamp || 'comment'}-${index}`}
                            style={{
                              border: '1px solid var(--border)',
                              borderRadius: 10,
                              padding: 12,
                              background: 'var(--bg)',
                            }}
                          >
                            <div className="row-primary">{comment.author || 'analyst'}</div>
                            <div className="row-secondary">
                              {comment.timestamp ? formatDateTime(comment.timestamp) : 'recently'}
                            </div>
                            <div style={{ marginTop: 8 }}>
                              {comment.text || comment.content || 'No comment body'}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    <div style={{ marginTop: 12 }}>
                      <label className="form-label" htmlFor="case-workspace-comment">
                        Add case note
                      </label>
                      <textarea
                        id="case-workspace-comment"
                        className="form-input"
                        rows={3}
                        value={caseWorkspaceComment}
                        onChange={(event) => setCaseWorkspaceComment(event.target.value)}
                        placeholder="Capture analyst context, next steps, or containment updates."
                      />
                      <div className="btn-group" style={{ marginTop: 10 }}>
                        <button
                          className="btn btn-sm btn-primary"
                          disabled={caseWorkspaceCommentSaving || !caseWorkspaceComment.trim()}
                          onClick={addCaseWorkspaceComment}
                        >
                          {caseWorkspaceCommentSaving ? 'Posting…' : 'Post Case Note'}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                <JsonDetails data={activeWorkspaceCase} label="Focused case payload" />
              </>
            )}
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <span className="card-title">Ticket Sync</span>
                <div className="hint" style={{ marginTop: 6 }}>
                  Sync the selected or focused case into Jira, ServiceNow, Linear, or another
                  downstream queue without leaving the workbench.
                </div>
              </div>
              <div className="btn-group">
                <button className="btn btn-sm" onClick={() => setTicketSyncResult(null)}>
                  Clear Result
                </button>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={syncSelectedCaseToTicket}
                  disabled={ticketSyncLoading || !activeTicketCaseId}
                >
                  {ticketSyncLoading ? 'Syncing…' : 'Sync Case'}
                </button>
              </div>
            </div>
            <div
              style={{
                display: 'grid',
                gap: 12,
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              }}
            >
              <div>
                <label className="form-label" htmlFor="ticket-sync-case">
                  Target case
                </label>
                <select
                  id="ticket-sync-case"
                  className="form-select"
                  value={activeTicketCaseId}
                  onChange={(event) =>
                    setTicketSyncDraft((current) => ({ ...current, caseId: event.target.value }))
                  }
                >
                  <option value="">Select a case</option>
                  {caseArr.map((caseItem) => (
                    <option key={caseItem.id} value={String(caseItem.id)}>
                      {`#${caseItem.id} ${caseItem.title || 'Untitled case'}`}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="form-label" htmlFor="ticket-sync-provider">
                  Ticketing provider
                </label>
                <select
                  id="ticket-sync-provider"
                  className="form-select"
                  value={ticketSyncDraft.provider}
                  onChange={(event) =>
                    setTicketSyncDraft((current) => ({ ...current, provider: event.target.value }))
                  }
                >
                  {['jira', 'servicenow', 'linear', 'pagerduty', 'custom'].map((provider) => (
                    <option key={provider} value={provider}>
                      {provider}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="form-label" htmlFor="ticket-sync-queue">
                  Project or queue
                </label>
                <input
                  id="ticket-sync-queue"
                  className="form-input"
                  value={ticketSyncDraft.queueOrProject}
                  onChange={(event) =>
                    setTicketSyncDraft((current) => ({
                      ...current,
                      queueOrProject: event.target.value,
                    }))
                  }
                  placeholder="SECOPS"
                />
              </div>
            </div>
            <div style={{ marginTop: 12 }}>
              <label className="form-label" htmlFor="ticket-sync-summary">
                Sync summary
              </label>
              <input
                id="ticket-sync-summary"
                className="form-input"
                value={activeTicketSummary}
                onChange={(event) =>
                  setTicketSyncDraft((current) => ({ ...current, summary: event.target.value }))
                }
                placeholder="Summarize the case for the downstream queue"
              />
            </div>
            <div className="hint" style={{ marginTop: 10 }}>
              Use the assistant route for case-aware summaries and citations before syncing this
              case.
            </div>
            {ticketSyncResult ? (
              <div style={{ marginTop: 14 }}>
                <JsonDetails data={ticketSyncResult} label="Last ticket sync" />
              </div>
            ) : null}
          </div>
        </>
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
                onChange={(event) => updateQueueFilter(event.target.value)}
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
              <button
                className="btn btn-sm"
                disabled={!queueFilterText.trim()}
                onClick={() => updateQueueFilter('')}
              >
                Clear Filter
              </button>
            </div>
            <div className="triage-toolbar-group">
              {savedQueueFilters.slice(-4).map((item) => (
                <button
                  key={`${item.name}-${item.query}`}
                  className="btn btn-sm"
                  onClick={() => updateQueueFilter(item.query, { replace: false })}
                >
                  {item.name}
                </button>
              ))}
            </div>
          </div>
          {queueFilterText.trim() ? (
            <div className="hint" style={{ marginBottom: 10 }}>
              This queue filter is mirrored into the URL so the current triage slice can be shared
              or reopened directly.
            </div>
          ) : null}
          {filteredQueueArr.length === 0 ? (
            <div className="empty">
              {queueArr.length > 0 && queueFilterText.trim()
                ? 'Filters excluded every queued alert. Clear or adjust the URL-backed filter to continue.'
                : 'Queue empty'}
            </div>
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
                        <button
                          className="btn btn-sm"
                          onClick={() =>
                            openResponseFocus({
                              target: a.host || a.agent_id || a.endpoint_id || a.entity_id || a.id,
                              source: 'queue',
                            })
                          }
                        >
                          Respond
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
          <div className="detail-callout" style={{ marginBottom: 16 }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                gap: 12,
                flexWrap: 'wrap',
              }}
            >
              <div style={{ flex: 1, minWidth: 240 }}>
                <strong>
                  {hasResponseContext ? 'Workflow handoff context' : 'Response Operations'}
                </strong>
                <div style={{ marginTop: 6 }}>
                  {hasResponseContext
                    ? `${responseSource ? `${responseSource.charAt(0).toUpperCase()}${responseSource.slice(1)} workflow` : 'Selected workflow'}${focusedCase ? ` is linked to case ${focusedCase.id} (${focusedCase.title}).` : ''}${focusedInvestigation ? ` Investigation ${focusedInvestigation.workflow_name || focusedInvestigation.id} is still active.` : ''}${responseTarget ? ` Suggested response target: ${responseTarget}.` : ''}`
                    : 'Monitor queued approvals, in-flight playbooks, and audit history from one shared response queue.'}
                </div>
              </div>
              <button className="btn btn-sm" onClick={reloadResponseData}>
                ↻ Refresh
              </button>
            </div>
            {hasResponseContext && (
              <div className="btn-group" style={{ marginTop: 10, flexWrap: 'wrap' }}>
                {focusedCase && (
                  <button className="btn btn-sm" onClick={() => openCaseFocus(focusedCase.id)}>
                    Open Case
                  </button>
                )}
                {focusedInvestigation && (
                  <button
                    className="btn btn-sm"
                    onClick={() =>
                      openInvestigationFocus(focusedInvestigation.id, focusedInvestigation.case_id)
                    }
                  >
                    Open Investigation
                  </button>
                )}
              </div>
            )}
          </div>
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
                              {formatResponseTarget(a)}
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
                              <td>{formatResponseTarget(r)}</td>
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
                            Playbook Steps — {r.type || r.action} → {formatResponseTarget(r)}
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
                  respAudit?.audit_log ||
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
                          {e.user || e.actor || e.target || '—'}
                        </span>
                        <span>
                          {e.action || e.message || e.description || 'Audit event'}
                          {e.outcome ? ` (${e.outcome})` : ''}
                        </span>
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
                  <button className="btn btn-sm" onClick={() => reloadProcessTreeData()}>
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
                  <button className="btn btn-sm" onClick={reloadProcessTreeData}>
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
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Investigation Planner</span>
              <button className="btn btn-sm" onClick={rInv}>
                ↻ Refresh
              </button>
            </div>
            {investigationContext ? (
              <div className="card" style={{ marginTop: 16, background: 'var(--bg)' }}>
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
                  <div className="summary-card">
                    <div className="summary-label">Linked Case</div>
                    <div className="summary-value">
                      {investigationContext.case_id || selectedInvestigationCase?.id || 'Unlinked'}
                    </div>
                    <div className="summary-meta">
                      {selectedInvestigationCase?.title ||
                        'Start a workflow and hand it into a case when needed.'}
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
                          <div
                            style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}
                          >
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
            ) : (
              <div className="hint" style={{ marginTop: 16 }}>
                Open the planner from an incident or queue alert to seed workflow suggestions and
                hunt pivots from the current signal.
              </div>
            )}
          </div>

          <div className="triage-layout">
            <section className="triage-list">
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="card-header">
                  <span className="card-title">Active Investigations</span>
                  <span className="badge badge-info">{activeInvestigationArr.length}</span>
                </div>
                {activeInvestigationArr.length === 0 ? (
                  <div className="empty">
                    No active investigations yet. Start a workflow from the planner or the library
                    below.
                  </div>
                ) : (
                  <div style={{ display: 'grid', gap: 12 }}>
                    {activeInvestigationArr.map((investigation) => (
                      <button
                        key={investigation.id}
                        className="card"
                        style={{
                          textAlign: 'left',
                          padding: 16,
                          borderColor:
                            selectedInvestigation?.id === investigation.id
                              ? 'var(--accent)'
                              : 'var(--border)',
                          background:
                            selectedInvestigation?.id === investigation.id
                              ? 'var(--bg)'
                              : 'var(--bg-card)',
                        }}
                        onClick={() =>
                          openInvestigationFocus(investigation.id, investigation.case_id)
                        }
                      >
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            gap: 12,
                            alignItems: 'flex-start',
                          }}
                        >
                          <div>
                            <div className="row-primary">
                              {investigation.workflow_name || investigation.workflow_id}
                            </div>
                            <div className="row-secondary">
                              {investigation.analyst} •{' '}
                              {investigation.case_id
                                ? `Case ${investigation.case_id}`
                                : 'No linked case'}
                            </div>
                          </div>
                          <span
                            className={`badge ${investigationStatusBadgeClass(investigation.status)}`}
                          >
                            {investigationStatusLabel(investigation.status)}
                          </span>
                        </div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                          <span className="badge badge-info">
                            {investigation.completion_percent || 0}% complete
                          </span>
                          <span className="badge badge-info">
                            {(investigation.completed_steps || []).length}/
                            {investigation.total_steps || 0} steps
                          </span>
                          {investigation.next_step?.title ? (
                            <span className="badge badge-info">
                              Next: {investigation.next_step.title}
                            </span>
                          ) : null}
                        </div>
                        <div className="row-secondary" style={{ marginTop: 10 }}>
                          Updated{' '}
                          {formatRelativeTime(investigation.updated_at || investigation.started_at)}
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div className="card">
                <div className="card-header">
                  <span className="card-title">Workflow Library</span>
                  <span className="badge badge-info">
                    {Array.isArray(workflows) ? workflows.length : 0}
                  </span>
                </div>
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
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                              {wf.id}
                            </td>
                            <td>
                              <div className="row-primary">{wf.name}</div>
                              <div className="row-secondary">{wf.description}</div>
                            </td>
                            <td>
                              <span className={`sev-${(wf.severity || 'medium').toLowerCase()}`}>
                                {wf.severity}
                              </span>
                            </td>
                            <td style={{ fontSize: 11 }}>
                              {(wf.mitre_techniques || []).join(', ')}
                            </td>
                            <td>{wf.estimated_minutes}m</td>
                            <td>{(wf.steps || []).length}</td>
                            <td>
                              <button
                                className="btn btn-sm btn-primary"
                                onClick={() =>
                                  startWorkflow(
                                    wf,
                                    investigationContext?.case_id || selectedInvestigation?.case_id,
                                  )
                                }
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
              </div>
            </section>

            <aside className="triage-detail">
              <div className="card">
                {!selectedInvestigation ? (
                  <div className="empty">
                    Select an active investigation to track step progress, notes, pivots, and
                    handoff details.
                  </div>
                ) : (
                  <>
                    <div className="detail-hero">
                      <div>
                        <div className="detail-hero-title">
                          {selectedInvestigation.workflow_name || selectedInvestigation.workflow_id}
                        </div>
                        <div className="detail-hero-copy">
                          {selectedInvestigation.workflow_description}
                        </div>
                      </div>
                      <span
                        className={`badge ${investigationStatusBadgeClass(selectedInvestigation.status)}`}
                      >
                        {investigationStatusLabel(selectedInvestigation.status)}
                      </span>
                    </div>

                    <div style={{ marginTop: 16 }}>
                      <SummaryGrid
                        data={{
                          analyst: selectedInvestigation.analyst,
                          case: selectedInvestigation.case_id || 'Unlinked',
                          progress: `${selectedInvestigation.completion_percent || 0}%`,
                          steps_completed: `${(selectedInvestigation.completed_steps || []).length}/${selectedInvestigation.total_steps || 0}`,
                          started_at: formatDateTime(selectedInvestigation.started_at),
                          updated_at: formatDateTime(
                            selectedInvestigation.updated_at || selectedInvestigation.started_at,
                          ),
                        }}
                        limit={6}
                      />
                    </div>

                    <div className="btn-group" style={{ marginTop: 16, flexWrap: 'wrap' }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => pivotPlannerToHunt(investigationDetailContext)}
                      >
                        Open Hunt
                      </button>
                      {selectedInvestigationCase ? (
                        <button
                          className="btn btn-sm"
                          onClick={() => openCaseFocus(selectedInvestigationCase.id)}
                        >
                          Open Case
                        </button>
                      ) : null}
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={() =>
                          openResponseFocus({
                            caseId: selectedInvestigationCase?.id || selectedInvestigation?.case_id,
                            investigationId: selectedInvestigation.id,
                            target: investigationResponseTarget,
                            source: 'investigation',
                          })
                        }
                      >
                        Open Response
                      </button>
                    </div>

                    {selectedInvestigation.handoff && (
                      <div className="detail-callout" style={{ marginTop: 16 }}>
                        <strong>Latest handoff</strong>
                        <div style={{ marginTop: 6 }}>
                          {selectedInvestigation.handoff.from_analyst} handed this workflow to{' '}
                          {selectedInvestigation.handoff.to_analyst}{' '}
                          {formatRelativeTime(selectedInvestigation.handoff.updated_at)}.
                        </div>
                        <div style={{ marginTop: 6 }}>{selectedInvestigation.handoff.summary}</div>
                      </div>
                    )}

                    <div className="card" style={{ marginTop: 16 }}>
                      <div className="card-header">
                        <span className="card-title">Findings and Completion Criteria</span>
                        {selectedInvestigation.next_step?.title ? (
                          <span className="badge badge-info">
                            Next: {selectedInvestigation.next_step.title}
                          </span>
                        ) : null}
                      </div>
                      {(selectedInvestigation.findings || []).length > 0 ? (
                        <div
                          style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}
                        >
                          {selectedInvestigation.findings.map((finding, index) => (
                            <span key={`${finding}-${index}`} className="badge badge-info">
                              {finding}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <div className="hint" style={{ marginBottom: 12 }}>
                          No findings recorded yet. Capture decisive takeaways as the workflow
                          moves.
                        </div>
                      )}
                      <div className="form-group">
                        <label className="form-label" htmlFor="investigation-finding-input">
                          Add finding
                        </label>
                        <input
                          id="investigation-finding-input"
                          className="form-input"
                          value={findingDraft}
                          placeholder="Containment complete on two hosts; VPN IP blocked"
                          onChange={(event) => setFindingDraft(event.target.value)}
                        />
                      </div>
                      <div className="btn-group">
                        <button
                          className="btn btn-sm"
                          disabled={
                            savingProgressKey === `${selectedInvestigation.id}:finding` ||
                            !findingDraft.trim()
                          }
                          onClick={() =>
                            saveInvestigationProgress(
                              selectedInvestigation.id,
                              { finding: findingDraft.trim() },
                              'Finding recorded',
                              `${selectedInvestigation.id}:finding`,
                            )
                          }
                        >
                          {savingProgressKey === `${selectedInvestigation.id}:finding`
                            ? 'Saving…'
                            : 'Record Finding'}
                        </button>
                      </div>
                      {(selectedInvestigation.completion_criteria || []).length > 0 && (
                        <div style={{ marginTop: 16 }}>
                          <div className="card-title" style={{ marginBottom: 8 }}>
                            Completion Criteria
                          </div>
                          <ul style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6 }}>
                            {selectedInvestigation.completion_criteria.map((criterion) => (
                              <li key={criterion}>{criterion}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>

                    <div className="card" style={{ marginTop: 16 }}>
                      <div className="card-title" style={{ marginBottom: 12 }}>
                        Step Progress
                      </div>
                      <div style={{ display: 'grid', gap: 12 }}>
                        {(selectedInvestigation.steps || []).map((step) => {
                          const stepKey = `${selectedInvestigation.id}:${step.order}`;
                          const noteValue =
                            stepNoteDrafts[stepKey] ??
                            selectedInvestigation.notes?.[step.order] ??
                            selectedInvestigation.notes?.[String(step.order)] ??
                            '';
                          const isCompleted = (
                            selectedInvestigation.completed_steps || []
                          ).includes(step.order);
                          const stepPivots = collectStepPivots(step, investigationDetailContext);

                          return (
                            <div
                              key={step.order}
                              style={{
                                border: '1px solid var(--border)',
                                borderRadius: 12,
                                padding: 14,
                                display: 'grid',
                                gap: 10,
                              }}
                            >
                              <div
                                style={{
                                  display: 'flex',
                                  justifyContent: 'space-between',
                                  gap: 12,
                                  alignItems: 'flex-start',
                                }}
                              >
                                <div>
                                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                    <span
                                      className={`badge ${isCompleted ? 'badge-ok' : 'badge-info'}`}
                                    >
                                      {isCompleted ? 'Done' : `Step ${step.order}`}
                                    </span>
                                    <strong>{step.title}</strong>
                                  </div>
                                  <div className="row-secondary" style={{ marginTop: 6 }}>
                                    {step.description}
                                  </div>
                                </div>
                                <button
                                  className={`btn btn-sm ${!isCompleted ? 'btn-primary' : ''}`}
                                  disabled={savingProgressKey === stepKey}
                                  onClick={() =>
                                    saveInvestigationProgress(
                                      selectedInvestigation.id,
                                      {
                                        step: step.order,
                                        completed: !isCompleted,
                                        note: noteValue,
                                      },
                                      isCompleted ? 'Step reopened' : 'Step marked complete',
                                      stepKey,
                                    )
                                  }
                                >
                                  {savingProgressKey === stepKey
                                    ? 'Saving…'
                                    : isCompleted
                                      ? 'Reopen'
                                      : 'Mark Complete'}
                                </button>
                              </div>

                              {(step.recommended_actions || []).length > 0 && (
                                <div>
                                  <div className="row-primary">Recommended actions</div>
                                  <ul
                                    style={{
                                      margin: '6px 0 0',
                                      paddingLeft: 18,
                                      display: 'grid',
                                      gap: 4,
                                    }}
                                  >
                                    {(step.recommended_actions || []).map((action) => (
                                      <li key={action}>{action}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}

                              {(step.evidence_to_collect || []).length > 0 && (
                                <div>
                                  <div className="row-primary">Evidence to collect</div>
                                  <div
                                    style={{
                                      display: 'flex',
                                      gap: 8,
                                      flexWrap: 'wrap',
                                      marginTop: 6,
                                    }}
                                  >
                                    {(step.evidence_to_collect || []).map((item) => (
                                      <span key={item} className="badge badge-info">
                                        {item}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {stepPivots.length > 0 && (
                                <div>
                                  <div className="row-primary">Auto-query pivots</div>
                                  <div
                                    className="btn-group"
                                    style={{ marginTop: 8, flexWrap: 'wrap' }}
                                  >
                                    {stepPivots.map((pivot) => (
                                      <button
                                        key={pivot.key}
                                        className="btn btn-sm"
                                        onClick={() => navigate(pivot.to)}
                                        title={pivot.description || pivot.label}
                                      >
                                        {pivot.label}
                                      </button>
                                    ))}
                                  </div>
                                </div>
                              )}

                              <div className="form-group" style={{ marginBottom: 0 }}>
                                <label
                                  className="form-label"
                                  htmlFor={`investigation-step-note-${step.order}`}
                                >
                                  Analyst note
                                </label>
                                <textarea
                                  id={`investigation-step-note-${step.order}`}
                                  className="form-input"
                                  rows={3}
                                  value={noteValue}
                                  onChange={(event) =>
                                    setStepNoteDrafts((current) => ({
                                      ...current,
                                      [stepKey]: event.target.value,
                                    }))
                                  }
                                  placeholder="Capture what was confirmed, blocked, or still needs review."
                                />
                              </div>
                              <div className="btn-group">
                                <button
                                  className="btn btn-sm"
                                  disabled={savingProgressKey === `${stepKey}:note`}
                                  onClick={() =>
                                    saveInvestigationProgress(
                                      selectedInvestigation.id,
                                      { step: step.order, note: noteValue },
                                      'Step note saved',
                                      `${stepKey}:note`,
                                    )
                                  }
                                >
                                  {savingProgressKey === `${stepKey}:note`
                                    ? 'Saving…'
                                    : 'Save Note'}
                                </button>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    <div className="card" style={{ marginTop: 16 }}>
                      <div className="card-title" style={{ marginBottom: 12 }}>
                        Case Handoff
                      </div>
                      {selectedInvestigationCase ? (
                        <div className="detail-callout" style={{ marginBottom: 16 }}>
                          <strong>Linked case {selectedInvestigationCase.id}</strong>
                          <div style={{ marginTop: 6 }}>
                            {selectedInvestigationCase.title}
                            {selectedInvestigationCase.assignee
                              ? ` • currently assigned to ${selectedInvestigationCase.assignee}`
                              : ' • currently unassigned'}
                          </div>
                        </div>
                      ) : (
                        <div className="detail-callout" style={{ marginBottom: 16 }}>
                          <strong>No linked case</strong>
                          <div style={{ marginTop: 6 }}>
                            Handoff still records against the investigation, but no case owner will
                            be synchronized until the workflow is attached to a case.
                          </div>
                        </div>
                      )}
                      <div className="form-group">
                        <label className="form-label" htmlFor="investigation-handoff-target">
                          Handoff target
                        </label>
                        <input
                          id="investigation-handoff-target"
                          className="form-input"
                          value={handoffDraft.toAnalyst}
                          onChange={(event) =>
                            setHandoffDraft((current) => ({
                              ...current,
                              toAnalyst: event.target.value,
                            }))
                          }
                          placeholder="analyst-2"
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label" htmlFor="investigation-handoff-summary">
                          Summary
                        </label>
                        <textarea
                          id="investigation-handoff-summary"
                          className="form-input"
                          rows={4}
                          value={handoffDraft.summary}
                          onChange={(event) =>
                            setHandoffDraft((current) => ({
                              ...current,
                              summary: event.target.value,
                            }))
                          }
                          placeholder="What is confirmed, what is contained, and what still blocks closure?"
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label" htmlFor="investigation-handoff-actions">
                          Next actions
                        </label>
                        <textarea
                          id="investigation-handoff-actions"
                          className="form-input"
                          rows={3}
                          value={handoffDraft.nextActions}
                          onChange={(event) =>
                            setHandoffDraft((current) => ({
                              ...current,
                              nextActions: event.target.value,
                            }))
                          }
                          placeholder="One action per line"
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label" htmlFor="investigation-handoff-questions">
                          Open questions
                        </label>
                        <textarea
                          id="investigation-handoff-questions"
                          className="form-input"
                          rows={3}
                          value={handoffDraft.questions}
                          onChange={(event) =>
                            setHandoffDraft((current) => ({
                              ...current,
                              questions: event.target.value,
                            }))
                          }
                          placeholder="One question per line"
                        />
                      </div>
                      <div className="btn-group">
                        <button
                          className="btn btn-sm btn-primary"
                          disabled={savingHandoff}
                          onClick={submitInvestigationHandoff}
                        >
                          {savingHandoff ? 'Handing Off…' : 'Hand Off Investigation'}
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </aside>
          </div>
        </>
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
          <div className="card-header">
            <span className="card-title">Host Timeline</span>
            <button className="btn btn-sm" onClick={rTimeline}>
              ↻ Refresh
            </button>
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

      {tab === 'campaigns' && <CampaignGraph campaignData={campaignData} />}

      <SideDrawer
        open={caseDrawerOpen}
        title={
          activeWorkspaceCase
            ? `Case Workspace — #${activeWorkspaceCase.id} ${activeWorkspaceCase.title || 'Untitled case'}`
            : `Case Workspace — ${focusedCaseId}`
        }
        subtitle="Shareable case context with evidence, pivots, and analyst notes."
        onClose={closeCaseDrawer}
        actions={
          <div className="btn-group" style={{ flexWrap: 'wrap' }}>
            {CASE_DRAWER_PANELS.map((panel) => (
              <button
                key={panel.id}
                className={`btn btn-sm ${caseDrawerPanel === panel.id ? 'btn-primary' : ''}`}
                onClick={() =>
                  openCaseDrawer(focusedCaseId, {
                    panel: panel.id,
                    hash: location.hash.replace('#', '') || 'cases',
                  })
                }
              >
                {panel.label}
              </button>
            ))}
          </div>
        }
      >
        {!focusedCaseId ? (
          <div className="empty">No case is selected for this drawer.</div>
        ) : !activeWorkspaceCase ? (
          <div className="empty">Loading case context…</div>
        ) : (
          <>
            {caseDrawerPanel === 'summary' && (
              <>
                <SummaryGrid
                  data={{
                    case_id: activeWorkspaceCase.id,
                    status: activeWorkspaceCase.status || 'new',
                    priority: activeWorkspaceCase.priority || 'medium',
                    containment: caseContainmentLabel(activeWorkspaceCase.status),
                    owner:
                      activeWorkspaceCase.assignee ||
                      activeWorkspaceCase.owner ||
                      activeWorkspaceCase.assigned_to ||
                      'Unassigned',
                    updated_at:
                      activeWorkspaceCase.updated_at || activeWorkspaceCase.created_at || '—',
                    incidents: activeCaseIncidentIds.length,
                    events: activeCaseEventIds.length,
                    evidence: activeCaseEvidence.length,
                    comments: activeCaseComments.length,
                    linked_workflow: activeWorkspaceInvestigation?.workflow_name || 'Not started',
                  }}
                  limit={10}
                />

                <div
                  style={{
                    marginTop: 14,
                    padding: '12px 14px',
                    background: 'var(--bg)',
                    border: '1px solid var(--border)',
                    borderRadius: 10,
                    lineHeight: 1.5,
                  }}
                >
                  {activeWorkspaceCase.description?.trim() ||
                    'No case narrative has been written yet. Use this shareable drawer to keep the analyst story and pivots together.'}
                </div>

                <div
                  style={{
                    display: 'grid',
                    gap: 14,
                    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                    marginTop: 14,
                  }}
                >
                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 8 }}>
                      Linked incidents
                    </div>
                    {activeCaseIncidentIds.length === 0 ? (
                      <div className="empty">No linked incidents yet.</div>
                    ) : (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {activeCaseIncidentIds.map((incidentId) => (
                          <button
                            key={`case-drawer-incident-${incidentId}`}
                            className="btn btn-sm"
                            onClick={() =>
                              openIncidentDrawer(incidentId, {
                                caseId: activeWorkspaceCase.id,
                                panel: 'summary',
                                hash: 'cases',
                              })
                            }
                          >
                            {`Incident #${incidentId}`}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>

                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 8 }}>
                      ATT&CK & Tags
                    </div>
                    {activeCaseMitre.length === 0 && activeCaseTags.length === 0 ? (
                      <div className="empty">No ATT&CK coverage or analyst tags yet.</div>
                    ) : (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {activeCaseMitre.map((technique) => (
                          <span key={`case-drawer-mitre-${technique}`} className="badge badge-info">
                            {technique}
                          </span>
                        ))}
                        {activeCaseTags.map((tag) => (
                          <span key={`case-drawer-tag-${tag}`} className="badge badge-info">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                    <div className="hint" style={{ marginTop: 10 }}>
                      Keep this drawer open while pivoting so the case context stays reusable.
                    </div>
                  </div>
                </div>

                <JsonDetails data={activeWorkspaceCase} label="Case payload" />
              </>
            )}

            {caseDrawerPanel === 'evidence' && (
              <>
                <div
                  style={{
                    display: 'grid',
                    gap: 14,
                    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                  }}
                >
                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Evidence
                    </div>
                    {activeCaseEvidence.length === 0 ? (
                      <div className="empty">No evidence linked yet.</div>
                    ) : (
                      <div style={{ display: 'grid', gap: 10 }}>
                        {activeCaseEvidence.map((item, index) => (
                          <div
                            key={`${item.reference_id || item.kind || 'drawer-evidence'}-${index}`}
                            style={{
                              border: '1px solid var(--border)',
                              borderRadius: 10,
                              padding: 12,
                              background: 'var(--bg)',
                            }}
                          >
                            <div className="row-primary">
                              {item.description || item.reference_id || 'Linked evidence'}
                            </div>
                            <div className="row-secondary">
                              {item.kind || 'unknown'} · {item.reference_id || 'no reference'}
                            </div>
                            <div className="row-secondary" style={{ marginTop: 6 }}>
                              Added {item.added_at ? formatDateTime(item.added_at) : 'recently'}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Case Notes
                    </div>
                    {activeCaseComments.length === 0 ? (
                      <div className="empty">No case notes yet.</div>
                    ) : (
                      <div style={{ display: 'grid', gap: 10 }}>
                        {activeCaseComments.map((comment, index) => (
                          <div
                            key={`${comment.timestamp || 'drawer-comment'}-${index}`}
                            style={{
                              border: '1px solid var(--border)',
                              borderRadius: 10,
                              padding: 12,
                              background: 'var(--bg)',
                            }}
                          >
                            <div className="row-primary">{comment.author || 'analyst'}</div>
                            <div className="row-secondary">
                              {comment.timestamp ? formatDateTime(comment.timestamp) : 'recently'}
                            </div>
                            <div style={{ marginTop: 8 }}>
                              {comment.text || comment.content || 'No comment body'}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    <div style={{ marginTop: 12 }}>
                      <label className="form-label" htmlFor="case-drawer-comment">
                        Add case note (drawer)
                      </label>
                      <textarea
                        id="case-drawer-comment"
                        className="form-input"
                        rows={3}
                        value={caseWorkspaceComment}
                        onChange={(event) => setCaseWorkspaceComment(event.target.value)}
                        placeholder="Capture analyst context, next steps, or containment updates."
                      />
                      <div className="btn-group" style={{ marginTop: 10 }}>
                        <button
                          className="btn btn-sm btn-primary"
                          disabled={caseWorkspaceCommentSaving || !caseWorkspaceComment.trim()}
                          onClick={addCaseWorkspaceComment}
                        >
                          {caseWorkspaceCommentSaving ? 'Posting…' : 'Post Case Note'}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </>
            )}

            {caseDrawerPanel === 'actions' && (
              <>
                <div className="hint" style={{ marginBottom: 12 }}>
                  Use this case drawer to hand off the current investigation without losing the
                  focused case context.
                </div>
                <div className="btn-group" style={{ flexWrap: 'wrap' }}>
                  {activeWorkspaceInvestigation ? (
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        openInvestigationFocus(
                          activeWorkspaceInvestigation.id,
                          activeWorkspaceCase.id,
                        )
                      }
                    >
                      Open Investigation
                    </button>
                  ) : null}
                  <button
                    className="btn btn-sm"
                    onClick={() =>
                      navigate(`/assistant?case=${encodeURIComponent(activeWorkspaceCase.id)}`)
                    }
                  >
                    Ask Assistant
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() =>
                      navigate(
                        buildHref('/reports', {
                          params: {
                            tab: 'evidence',
                            case: activeWorkspaceCase?.id || focusedCaseId || undefined,
                            incident: focusedIncidentParam || undefined,
                            investigation:
                              activeWorkspaceInvestigation?.id ||
                              focusedInvestigationParam ||
                              undefined,
                            source: responseSource || 'case-drawer',
                            target: responseTarget || undefined,
                          },
                        }),
                      )
                    }
                  >
                    Evidence Report
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() =>
                      navigate(buildHref('/infrastructure', { params: { tab: 'assets' } }))
                    }
                  >
                    Asset Context
                  </button>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() =>
                      openResponseFocus({
                        caseId: activeWorkspaceCase.id,
                        target: `case:${activeWorkspaceCase.id}`,
                        source: 'case',
                      })
                    }
                  >
                    Open Response Workspace
                  </button>
                </div>

                <div style={{ marginTop: 14 }}>
                  <SummaryGrid
                    data={{
                      linked_incidents: activeCaseIncidentIds.length,
                      evidence_items: activeCaseEvidence.length,
                      notes: activeCaseComments.length,
                      linked_workflow: activeWorkspaceInvestigation?.workflow_name || 'Not started',
                    }}
                    limit={4}
                  />
                </div>
              </>
            )}
          </>
        )}
      </SideDrawer>

      <SideDrawer
        open={incidentDrawerOpen}
        title={
          drawerIncidentDetail
            ? `Incident Workspace — ${drawerIncidentDetail.title || drawerIncidentDetail.id || focusedIncidentParam}`
            : `Incident Workspace — ${focusedIncidentParam}`
        }
        subtitle="Shareable incident context with storyline, pivots, and response handoff."
        onClose={closeIncidentDrawer}
        actions={
          <div className="btn-group" style={{ flexWrap: 'wrap' }}>
            {INCIDENT_DRAWER_PANELS.map((panel) => (
              <button
                key={panel.id}
                className={`btn btn-sm ${incidentDrawerPanel === panel.id ? 'btn-primary' : ''}`}
                onClick={() =>
                  openIncidentDrawer(focusedIncidentParam, {
                    caseId: drawerIncidentCaseId || undefined,
                    panel: panel.id,
                    hash: location.hash.replace('#', '') || 'incidents',
                  })
                }
              >
                {panel.label}
              </button>
            ))}
          </div>
        }
      >
        {!focusedIncidentParam ? (
          <div className="empty">No incident is selected for this drawer.</div>
        ) : !drawerIncidentDetail ? (
          <div className="empty">Loading incident context…</div>
        ) : (
          <>
            {incidentDrawerPanel === 'summary' && (
              <>
                <SummaryGrid
                  data={{
                    incident_id: drawerIncidentDetail.id || focusedIncidentParam,
                    severity: drawerIncidentDetail.severity || 'unknown',
                    status: drawerIncidentDetail.status || 'open',
                    created: drawerIncidentDetail.created || drawerIncidentDetail.timestamp || '—',
                    updated:
                      drawerIncidentDetail.updated || drawerIncidentDetail.last_updated || '—',
                    owner: drawerIncidentDetail.owner || drawerIncidentDetail.assigned_to || '—',
                    linked_case: drawerIncidentCaseId || 'Not linked',
                    alerts: (drawerIncidentDetail.alert_ids || []).length,
                    events: (drawerIncidentDetail.event_ids || []).length,
                    agents: (drawerIncidentDetail.agent_ids || []).length,
                  }}
                  limit={9}
                />

                {drawerIncidentDetail.summary ? (
                  <div
                    style={{
                      marginTop: 14,
                      padding: '12px 14px',
                      background: 'var(--bg)',
                      border: '1px solid var(--border)',
                      borderRadius: 10,
                      lineHeight: 1.5,
                    }}
                  >
                    {drawerIncidentDetail.summary}
                  </div>
                ) : null}

                <div
                  style={{
                    display: 'grid',
                    gap: 14,
                    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                    marginTop: 14,
                  }}
                >
                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 8 }}>
                      Related Alerts & Events
                    </div>
                    {(drawerIncidentDetail.event_ids || []).length === 0 &&
                    (drawerIncidentDetail.alert_ids || []).length === 0 ? (
                      <div className="empty">No linked alerts or events were provided.</div>
                    ) : (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {[
                          ...(drawerIncidentDetail.event_ids || []),
                          ...(drawerIncidentDetail.alert_ids || []),
                        ].map((entry, index) => (
                          <span key={`${entry}-${index}`} className="badge badge-info">
                            {entry}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 12,
                      padding: 14,
                      background: 'var(--bg-card)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 8 }}>
                      Agent Scope
                    </div>
                    {(drawerIncidentDetail.agent_ids || []).length === 0 ? (
                      <div className="empty">No agent scope is attached to this incident.</div>
                    ) : (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {drawerIncidentDetail.agent_ids.map((agentId, index) => (
                          <span key={`${agentId}-${index}`} className="badge badge-info">
                            {agentId}
                          </span>
                        ))}
                      </div>
                    )}
                    <div className="hint" style={{ marginTop: 10 }}>
                      Keep this drawer open while pivoting so the incident context remains shareable
                      and easy to resume.
                    </div>
                  </div>
                </div>

                <JsonDetails data={drawerIncidentDetail} label="Incident payload" />
              </>
            )}

            {incidentDrawerPanel === 'storyline' && (
              <>
                {drawerIncidentEvents.length === 0 ? (
                  <div className="empty">
                    No storyline events are available for this incident yet.
                  </div>
                ) : (
                  <div style={{ display: 'grid', gap: 10 }}>
                    {drawerIncidentEvents.map((event, index) => (
                      <div
                        key={`${event.timestamp || event.time || 'event'}-${index}`}
                        style={{
                          border: '1px solid var(--border)',
                          borderRadius: 12,
                          padding: 14,
                          background: 'var(--bg-card)',
                        }}
                      >
                        <div className="row-primary">
                          {event.description ||
                            event.message ||
                            event.action ||
                            `Step ${index + 1}`}
                        </div>
                        <div className="row-secondary" style={{ marginTop: 4 }}>
                          {event.timestamp || event.time || `Step ${index + 1}`}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {drawerIncidentStoryline ? (
                  <JsonDetails data={drawerIncidentStoryline} label="Incident storyline payload" />
                ) : null}
              </>
            )}

            {incidentDrawerPanel === 'actions' && (
              <>
                <div className="hint" style={{ marginBottom: 12 }}>
                  Use this incident drawer as the bridge between the active case, investigation
                  workflow, and response approvals.
                </div>
                <div className="btn-group" style={{ flexWrap: 'wrap' }}>
                  {drawerIncidentCaseId ? (
                    <button
                      className="btn btn-sm"
                      onClick={() => openCaseFocus(drawerIncidentCaseId)}
                    >
                      Open Linked Case
                    </button>
                  ) : null}
                  <button
                    className="btn btn-sm"
                    onClick={() => openInvestigationPlanner(drawerIncidentDetail, 'incident')}
                  >
                    Plan Investigation
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() => pivotPlannerToHunt(drawerIncidentDetail)}
                  >
                    Open Hunt
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() =>
                      openResponseFocus({
                        caseId: drawerIncidentCaseId || undefined,
                        target:
                          drawerIncidentDetail.agent_ids?.[0] ||
                          drawerIncidentDetail.id ||
                          focusedIncidentParam,
                        source: 'incident',
                      })
                    }
                  >
                    Open Response Workspace
                  </button>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={async () => {
                      try {
                        await api.updateIncident(focusedIncidentParam, { status: 'closed' });
                        toast('Incident closed', 'success');
                        await fetchDrawerIncidentDetail(focusedIncidentParam);
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
                    onClick={async () => {
                      try {
                        const report = await api.incidentReport(focusedIncidentParam);
                        downloadData(
                          typeof report === 'string' ? report : report,
                          `incident-${focusedIncidentParam}-report.txt`,
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

                <div style={{ marginTop: 14 }}>
                  <SummaryGrid
                    data={{
                      linked_case: drawerIncidentCaseId || '—',
                      response_target:
                        drawerIncidentDetail.agent_ids?.[0] ||
                        drawerIncidentDetail.id ||
                        focusedIncidentParam,
                      storyline_events: drawerIncidentEvents.length,
                    }}
                    limit={3}
                  />
                </div>
              </>
            )}
          </>
        )}
      </SideDrawer>

      <ProcessDrawer
        pid={selectedProcess?.pid}
        snapshot={selectedProcess}
        onClose={() => setSelectedProcess(null)}
        onUpdated={() => {
          reloadProcessTreeData();
        }}
        onSelectProcess={(process) => setSelectedProcess(process ? { ...process } : null)}
      />
    </div>
  );
}

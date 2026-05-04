import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useApi, useApiGroup, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid, SideDrawer, WorkspaceEmptyState } from './operator.jsx';
import { formatDateTime, formatRelativeTime } from './operatorUtils.js';
import { buildLongRetentionHistoryPath } from './settings/helpers.js';
import { useConfirm } from './useConfirm.jsx';
import ThreatIntelOperations from './ThreatIntelOperations.jsx';
import WorkflowGuidance from './WorkflowGuidance.jsx';
import { buildHref } from './workflowPivots.js';

const SAVED_VIEWS = [
  {
    id: 'noisy',
    label: 'Noisy',
    match: (rule, ctx) =>
      (rule.last_test_match_count || 0) >= 5 || ctx.suppressionCount[rule.id] > 0,
  },
  {
    id: 'recent',
    label: 'Recently Tuned',
    match: (rule) => !!rule.last_test_at || !!rule.last_promotion_at,
  },
  {
    id: 'review',
    label: 'Needs Review',
    match: (rule) => !rule.last_test_at || ['draft', 'test'].includes(rule.lifecycle),
  },
  {
    id: 'disabled',
    label: 'Disabled',
    match: (rule) => rule.enabled === false || rule.lifecycle === 'deprecated',
  },
  {
    id: 'suppressed',
    label: 'Suppressed',
    match: (rule, ctx) => ctx.suppressionCount[rule.id] > 0,
  },
];

const WORKSPACE_PANELS = [
  {
    id: 'overview',
    label: 'Overview',
    description: 'Reopen the detection workspace with the full program summary in view.',
  },
  {
    id: 'efficacy',
    label: 'Efficacy',
    description: 'Start with analyst outcome quality before tuning or promotion decisions.',
  },
  {
    id: 'coverage',
    label: 'ATT&CK Gaps',
    description: 'Open straight into technique coverage blind spots and tactic-level gaps.',
  },
  {
    id: 'noise',
    label: 'Suppression Noise',
    description: 'Resume live suppression, false-positive, and replay-noise review.',
  },
  {
    id: 'rollout',
    label: 'Pack Rollout',
    description: 'Focus on content-pack readiness, routing, and stale bundle follow-up.',
  },
];

const RULE_DETAIL_PANELS = [
  {
    id: 'summary',
    label: 'Summary',
    description: 'Open the selected rule with lifecycle, routing, and ATT&CK context first.',
  },
  {
    id: 'efficacy',
    label: 'Rule Efficacy',
    description: 'Reopen rule-level precision, tactic gaps, and false-positive evidence.',
  },
  {
    id: 'promotion',
    label: 'Promotion',
    description: 'Resume checklist, validation replay, and rollout gating work.',
  },
  {
    id: 'hunts',
    label: 'Hunts & Investigations',
    description: 'Return to related saved hunts, bundles, and investigation pivots.',
  },
];

const normalizePanelId = (value, panels, fallback) =>
  panels.some((panel) => panel.id === value) ? value : fallback;

const lifecycleTone = (lifecycle) => {
  if (lifecycle === 'active') return 'badge-ok';
  if (lifecycle === 'canary' || lifecycle === 'test') return 'badge-warn';
  if (lifecycle === 'deprecated' || lifecycle === 'rolled_back') return 'badge-err';
  return 'badge-info';
};

const severityTone = (value) => {
  if (value === 'critical' || value === 'high') return 'badge-err';
  if (value === 'medium' || value === 'elevated') return 'badge-warn';
  return 'badge-info';
};

const normalizeText = (value) => String(value || '').toLowerCase();

const tokenize = (value) =>
  normalizeText(value)
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length > 2);

const formatRatio = (value) => `${Math.round((Number(value) || 0) * 100)}%`;

const formatMetricNumber = (value, digits = 1) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0.0';
  return numeric.toFixed(digits);
};

const formatDeltaRatio = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0%';
  const pct = Math.round(numeric * 100);
  return `${pct > 0 ? '+' : ''}${pct}%`;
};

const replayDeltaTone = (value, lowerIsBetter = false) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || Math.abs(numeric) < 0.001) return 'badge-info';
  const improves = lowerIsBetter ? numeric < 0 : numeric > 0;
  return improves ? 'badge-ok' : 'badge-err';
};

const canaryActionTone = (action) => {
  switch (String(action || '').toLowerCase()) {
    case 'promoted':
      return 'badge-ok';
    case 'rolled_back':
      return 'badge-err';
    default:
      return 'badge-info';
  }
};

const canaryActionLabel = (action) => {
  switch (String(action || '').toLowerCase()) {
    case 'promoted':
      return 'Promoted';
    case 'rolled_back':
      return 'Rolled Back';
    default:
      return 'No Change';
  }
};

const formatHumanLabel = (value, fallback = 'Unknown') => {
  const normalized = String(value || '').trim();
  if (!normalized) return fallback;
  return normalized
    .split(/[_-]+/)
    .filter(Boolean)
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
    .join(' ');
};

const formatLifecycleLabel = (lifecycle) => formatHumanLabel(lifecycle, 'Unknown');

const formatRolloutActionLabel = (action) => {
  const normalized = normalizeText(action);
  if (normalized === 'content-promote') return 'Rule Promotion';
  if (normalized === 'content-rollback') return 'Rule Rollback';
  return formatHumanLabel(action, 'Lifecycle Update');
};

function ReplayDeltaSection({ title, hint, rows }) {
  if (!Array.isArray(rows) || rows.length === 0) return null;

  return (
    <div className="card" style={{ background: 'var(--bg)' }}>
      <div className="card-title" style={{ marginBottom: 8 }}>
        {title}
      </div>
      <div className="hint" style={{ marginBottom: 12 }}>
        {hint}
      </div>
      {rows.slice(0, 4).map((row) => (
        <div
          key={row.id || row.label}
          style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}
        >
          <div className="row-primary">{row.label || row.id}</div>
          <div className="row-secondary">
            {row.sample_count || 0} samples • {row.passed_samples || 0} passed •{' '}
            {row.failed_samples || 0} failed
          </div>
          <div className="chip-row" style={{ marginTop: 8 }}>
            <span className={`badge ${replayDeltaTone(row.delta?.precision)}`}>
              Precision {formatDeltaRatio(row.delta?.precision)}
            </span>
            <span className={`badge ${replayDeltaTone(row.delta?.recall)}`}>
              Recall {formatDeltaRatio(row.delta?.recall)}
            </span>
            <span className={`badge ${replayDeltaTone(row.delta?.false_positive_rate, true)}`}>
              FPR {formatDeltaRatio(row.delta?.false_positive_rate)}
            </span>
          </div>
          {Array.isArray(row.failed_examples) && row.failed_examples.length > 0 && (
            <div className="hint" style={{ marginTop: 8 }}>
              Watch: {row.failed_examples.join(' • ')}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

const formatTrendLabel = (trend) => {
  const normalized = normalizeText(trend);
  if (normalized === 'improving') return 'Improving';
  if (normalized === 'degrading') return 'Degrading';
  if (normalized === 'stable') return 'Stable';
  if (normalized === 'insufficientdata') return 'Limited data';
  return trend || 'Unknown';
};

const formatVerdictLabel = (verdict) => {
  const normalized = normalizeText(verdict).replace(/_/g, ' ');
  if (!normalized) return 'No feedback';
  return normalized.replace(/\b\w/g, (letter) => letter.toUpperCase());
};

const formatVerdictSummary = (byVerdict) => {
  if (!byVerdict || typeof byVerdict !== 'object') return 'No analyst verdicts recorded yet.';
  const entries = Object.entries(byVerdict)
    .filter(([, count]) => Number(count) > 0)
    .sort((left, right) => Number(right[1]) - Number(left[1]))
    .slice(0, 3)
    .map(([verdict, count]) => `${count} ${formatVerdictLabel(verdict)}`);
  return entries.join(' • ') || 'No analyst verdicts recorded yet.';
};

const trendTone = (trend) => {
  const normalized = normalizeText(trend);
  if (normalized === 'improving') return 'badge-ok';
  if (normalized === 'degrading') return 'badge-err';
  if (normalized === 'stable') return 'badge-info';
  return 'badge-warn';
};

const priorityRank = (priority) => {
  const normalized = normalizeText(priority);
  if (normalized === 'critical') return 0;
  if (normalized === 'high') return 1;
  if (normalized === 'medium') return 2;
  return 3;
};

const priorityTone = (priority) => {
  const normalized = normalizeText(priority);
  if (normalized === 'critical') return 'badge-err';
  if (normalized === 'high') return 'badge-warn';
  if (normalized === 'medium') return 'badge-info';
  return 'badge-ok';
};

const ageInDays = (timestamp) => {
  if (!timestamp) return null;
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return null;
  return Math.max(0, Math.floor((Date.now() - parsed.getTime()) / (24 * 60 * 60 * 1000)));
};

const reviewIntervalDays = (rule) => {
  const lifecycle = normalizeText(rule?.lifecycle);
  if (rule?.enabled === false || lifecycle === 'deprecated') return null;
  if (lifecycle === 'draft' || lifecycle === 'test') return 7;
  if (lifecycle === 'canary') return 14;
  if (lifecycle === 'active') return 30;
  return 21;
};

const reviewAnchorAt = (rule) => {
  const candidates = [rule?.last_promotion_at, rule?.last_test_at, rule?.updated_at, rule?.created_at]
    .map((value) => {
      const parsed = value ? new Date(value) : null;
      return parsed && !Number.isNaN(parsed.getTime()) ? parsed : null;
    })
    .filter(Boolean)
    .sort((left, right) => right.getTime() - left.getTime());
  return candidates[0] || null;
};

const nextReviewAt = (rule) => {
  const intervalDays = reviewIntervalDays(rule);
  const anchor = reviewAnchorAt(rule);
  if (intervalDays == null || !anchor) return null;
  return new Date(anchor.getTime() + intervalDays * 24 * 60 * 60 * 1000).toISOString();
};

const daysUntil = (timestamp) => {
  if (!timestamp) return null;
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return null;
  return Math.ceil((parsed.getTime() - Date.now()) / (24 * 60 * 60 * 1000));
};

const ruleReplayState = (rule, suppressionCount) => {
  const hits = Number(rule?.last_test_match_count) || 0;
  const suppressions = suppressionCount[rule?.id] || 0;
  const ageDays = ageInDays(rule?.last_test_at);
  if (!rule?.last_test_at) {
    return {
      label: 'Replay missing',
      tone: 'badge-warn',
      detail: 'Run replay validation before the next ownership review.',
    };
  }
  if (ageDays != null && ageDays >= 14) {
    return {
      label: 'Replay stale',
      tone: 'badge-warn',
      detail: `Replay evidence is ${ageDays} day${ageDays === 1 ? '' : 's'} old.`,
    };
  }
  if (hits >= 5 || suppressions > 0) {
    return {
      label: 'Noisy replay',
      tone: 'badge-err',
      detail: `${hits} replay hit${hits === 1 ? '' : 's'} and ${suppressions} live suppression${suppressions === 1 ? '' : 's'} need review.`,
    };
  }
  return {
    label: 'Replay ready',
    tone: 'badge-ok',
    detail: `${hits} replay hit${hits === 1 ? '' : 's'} from the latest validation run.`,
  };
};

const rulePromotionBlockers = (rule, suppressionCount) => {
  const blockers = [];
  const owner = String(rule?.owner || '').trim().toLowerCase();
  if (!owner || owner === 'system') blockers.push('Assign a named detection owner.');
  if (!rule?.last_test_at) blockers.push('Run replay validation.');
  const replayAgeDays = ageInDays(rule?.last_test_at);
  if (replayAgeDays != null && replayAgeDays >= 14) blockers.push('Refresh stale replay evidence.');
  if ((Number(rule?.last_test_match_count) || 0) >= 5)
    blockers.push('Reduce replay hit volume before promotion.');
  if ((suppressionCount[rule?.id] || 0) > 0) blockers.push('Review live suppressions and scope.');
  if (!Array.isArray(rule?.pack_ids) || rule.pack_ids.length === 0)
    blockers.push('Attach the rule to a content pack.');
  return blockers;
};

const reviewStatusMeta = (rule, suppressionCount) => {
  const dueAt = nextReviewAt(rule);
  const dueInDays = daysUntil(dueAt);
  const blockers = rulePromotionBlockers(rule, suppressionCount);
  const replay = ruleReplayState(rule, suppressionCount);
  if (rule?.enabled === false || normalizeText(rule?.lifecycle) === 'deprecated') {
    return {
      label: 'Inactive',
      tone: 'badge-info',
      rank: 3,
      queue: 'disabled',
      dueAt,
      dueInDays,
      blockers,
      replay,
    };
  }
  if (dueInDays != null && dueInDays < 0) {
    return {
      label: 'Overdue',
      tone: 'badge-err',
      rank: 0,
      queue: 'review',
      dueAt,
      dueInDays,
      blockers,
      replay,
    };
  }
  if (dueInDays != null && dueInDays <= 7) {
    return {
      label: 'Due this week',
      tone: 'badge-warn',
      rank: 1,
      queue: 'recent',
      dueAt,
      dueInDays,
      blockers,
      replay,
    };
  }
  return {
    label: 'Scheduled',
    tone: 'badge-ok',
    rank: 2,
    queue: replay.label === 'Noisy replay' ? 'noisy' : 'recent',
    dueAt,
    dueInDays,
    blockers,
    replay,
  };
};

const summarizePackRollout = (pack, linkedHuntCount, ageDays) => {
  const savedSearchCount = Array.isArray(pack?.saved_searches) ? pack.saved_searches.length : 0;
  const workflowCount = Array.isArray(pack?.recommended_workflows)
    ? pack.recommended_workflows.length
    : 0;

  if (pack?.enabled === false) {
    return {
      label: 'Disabled',
      tone: 'badge-warn',
      rank: 5,
      detail: 'Bundle is disabled and will not take part in promotion or analyst routing.',
    };
  }
  if (!String(pack?.target_group || '').trim()) {
    return {
      label: 'Needs target',
      tone: 'badge-warn',
      rank: 1,
      detail: 'Assign a target group before broad rollout or automation use.',
    };
  }
  if (savedSearchCount === 0 && workflowCount === 0) {
    return {
      label: 'Needs pivots',
      tone: 'badge-warn',
      rank: 2,
      detail: 'Add saved searches or workflow routes so analysts can pivot from the pack.',
    };
  }
  if (linkedHuntCount === 0) {
    return {
      label: 'Needs hunt',
      tone: 'badge-info',
      rank: 3,
      detail: 'No saved hunt currently inherits this bundle context.',
    };
  }
  if (ageDays != null && ageDays >= 21) {
    return {
      label: 'Review stale',
      tone: 'badge-info',
      rank: 4,
      detail: `Bundle has not been updated in ${ageDays} days.`,
    };
  }
  return {
    label: 'Ready',
    tone: 'badge-ok',
    rank: 0,
    detail: 'Target routing, pivots, and saved-hunt linkage are already in place.',
  };
};

const toIsoOrUndefined = (value) => {
  if (!value) return undefined;
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) return undefined;
  return timestamp.toISOString();
};

const scoreFpPatternMatch = (rule, pattern) => {
  if (!rule || !pattern) return 0;

  const haystack = normalizeText(`${rule.id || ''} ${rule.title || ''} ${rule.description || ''}`);
  const normalizedPattern = normalizeText(pattern);
  if (!haystack || !normalizedPattern) return 0;
  if (haystack.includes(normalizedPattern)) return 5;

  const tokens = [...new Set(tokenize(normalizedPattern))];
  if (tokens.length === 0) return 0;

  const matchedTokens = tokens.filter((token) => haystack.includes(token));
  if (matchedTokens.length === 0) return 0;

  const ratio = matchedTokens.length / tokens.length;
  if (matchedTokens.length >= Math.min(2, tokens.length) || ratio >= 0.75) {
    return 1 + ratio * 3;
  }

  return 0;
};

const casePriorityForSeverity = (severity) => {
  const normalized = normalizeText(severity);
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high' || normalized === 'severe') return 'high';
  if (normalized === 'low' || normalized === 'info') return normalized;
  return 'medium';
};

const linkedCaseIdFromHuntResult = (result) =>
  result?.escalated_case_id ||
  result?.case_id ||
  result?.run?.case_id ||
  result?.latest_run?.case_id ||
  null;

const huntResultContextTarget = (result, selectedRule) => {
  const sources = [
    result?.matches,
    result?.results,
    result?.rows,
    result?.items,
    result?.alerts,
    result?.events,
  ].find((entry) => Array.isArray(entry) && entry.length > 0);

  const first = Array.isArray(sources) ? sources[0] : null;
  return (
    first?.hostname ||
    first?.host ||
    first?.agent_id ||
    first?.endpoint_id ||
    first?.entity_id ||
    first?.user ||
    selectedRule?.id ||
    ''
  );
};

const buildDefaultHuntQuery = (rule, explicitQuery = '') => {
  if (explicitQuery) return explicitQuery;

  const terms = [
    rule?.severity_mapping ? `severity:${String(rule.severity_mapping).toLowerCase()}` : '',
    rule?.title || '',
    rule?.id || '',
  ].filter(Boolean);

  return terms.join(' ').trim() || 'severity:high';
};

const buildHuntQuickStarts = (rule) => {
  const base = buildDefaultHuntQuery(rule);
  return [
    {
      id: 'seed',
      label: 'Rule seed',
      description: 'Start with the rule severity and identifiers before widening the scope.',
      query: base,
    },
    {
      id: 'devices',
      label: 'Device rollup',
      description: 'Group by device to see which endpoints need containment or validation first.',
      query: `${base} | count by device_id`,
    },
    {
      id: 'sources',
      label: 'Source hotspots',
      description: 'Surface the loudest source IPs before you tune or suppress the rule.',
      query: `${base} | top 5 src_ip`,
    },
  ];
};

const buildInvestigationReasons = (rule) => {
  if (!rule) return [];

  return [
    rule.title,
    rule.description,
    rule.severity_mapping,
    ...(Array.isArray(rule.attack)
      ? rule.attack.flatMap((attack) => [attack.technique_id, attack.technique_name, attack.tactic])
      : []),
  ].filter(Boolean);
};

const summarizeHuntResult = (result) => {
  if (!result) return { mode: 'empty', count: 0, label: 'No hunt run yet' };
  if (Array.isArray(result))
    return {
      mode: 'matches',
      count: result.length,
      label: `${result.length} matching event${result.length === 1 ? '' : 's'}`,
    };
  if (Array.isArray(result?.rows))
    return {
      mode: 'aggregate',
      count: result.rows.length,
      label: `${result.rows.length} aggregate row${result.rows.length === 1 ? '' : 's'}`,
    };
  if (Array.isArray(result?.buckets))
    return {
      mode: 'aggregate',
      count: result.buckets.length,
      label: `${result.buckets.length} bucket${result.buckets.length === 1 ? '' : 's'}`,
    };
  if (typeof result?.count === 'number')
    return {
      mode: 'aggregate',
      count: result.count,
      label: `${result.count} result${result.count === 1 ? '' : 's'}`,
    };
  if (typeof result?.run?.match_count === 'number')
    return {
      mode: 'saved-hunt',
      count: result.run.match_count,
      label: `${result.run.match_count} saved-hunt match${result.run.match_count === 1 ? '' : 'es'}`,
    };
  return { mode: 'raw', count: 0, label: 'Raw hunt response available' };
};

const bundleListToText = (values) =>
  (Array.isArray(values) ? values : []).filter((value) => String(value || '').trim()).join('\n');

const textToBundleList = (value) => [
  ...new Set(
    String(value || '')
      .split(/\n|,/)
      .map((entry) => entry.trim())
      .filter(Boolean),
  ),
];

const derivePackRuleIds = (pack, rules, selectedRuleId) => {
  if (Array.isArray(pack?.rule_ids) && pack.rule_ids.length > 0) {
    return [...new Set(pack.rule_ids.filter(Boolean))];
  }
  if (pack?.id) {
    const linkedRuleIds = (Array.isArray(rules) ? rules : [])
      .filter((candidate) => (candidate.pack_ids || []).includes(pack.id))
      .map((candidate) => candidate.id)
      .filter(Boolean);
    if (linkedRuleIds.length > 0) return [...new Set(linkedRuleIds)];
  }
  return selectedRuleId ? [selectedRuleId] : [];
};

const buildPackDraft = ({ pack = null, rule = null, rules = [], suggestions = [] } = {}) => ({
  id: pack?.id || '',
  name: pack?.name || `Bundle ${rule?.title || rule?.id || 'Signals'}`,
  description: pack?.description || rule?.description || '',
  enabled: pack?.enabled ?? true,
  savedSearchesText: bundleListToText(pack?.saved_searches),
  recommendedWorkflowsText:
    bundleListToText(pack?.recommended_workflows) ||
    suggestions
      .slice(0, 3)
      .map((workflow) => workflow?.id)
      .filter(Boolean)
      .join('\n'),
  targetGroup: pack?.target_group || '',
  rolloutNotes: pack?.rollout_notes || '',
  ruleIds: derivePackRuleIds(pack, rules, rule?.id),
});

const buildPromotionChecklist = ({ rule, liveSuppressions, packCount, targetGroup }) => {
  const validationReady = Boolean(rule?.last_test_at);
  const matchCount = Number(rule?.last_test_match_count) || 0;
  const noiseReady = matchCount < 5 || liveSuppressions > 0;
  const routingReady = Boolean(String(targetGroup || '').trim());
  const bundleReady = packCount > 0;

  return [
    {
      id: 'validation',
      label: 'Replay validation',
      done: validationReady,
      detail: validationReady
        ? `${matchCount} visible match${matchCount === 1 ? '' : 'es'} from the most recent replay.`
        : 'Run a rule test before moving this rule into canary or active rollout.',
    },
    {
      id: 'noise',
      label: 'Noise plan',
      done: noiseReady,
      detail: noiseReady
        ? liveSuppressions > 0
          ? `${liveSuppressions} scoped suppression${liveSuppressions === 1 ? '' : 's'} already exist for noisy cases.`
          : 'Replay hit volume is low enough to promote without new suppressions.'
        : 'High replay volume needs either scoped suppressions or a lower weight before promotion.',
    },
    {
      id: 'routing',
      label: 'Automation routing',
      done: routingReady,
      detail: routingReady
        ? `Automation is routed to ${targetGroup}.`
        : 'Assign an identity-mapped target group before broad automation rollout.',
    },
    {
      id: 'bundle',
      label: 'Analyst pivots',
      done: bundleReady,
      detail: bundleReady
        ? `${packCount} content pack bundle${packCount === 1 ? '' : 's'} provide saved-search and workflow pivots.`
        : 'Attach a content pack or saved hunt so analysts can pivot from the signal quickly.',
    },
  ];
};

export default function ThreatDetection() {
  const toast = useToast();
  const [confirm, confirmUI] = useConfirm();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: profile } = useApi(api.detectionProfile);
  const { data: summary } = useApi(api.detectionSummary);
  const { data: replayCorpus } = useApi(api.detectionReplayCorpus);
  const { data: efficacySummary } = useApi(api.efficacySummary);
  const { data: fpStats } = useApi(api.fpFeedbackStats);
  const { data: workbenchOverview, reload: reloadWorkbenchOverview } = useApi(
    api.workbenchOverview,
  );
  const {
    data: detectionContentData,
    loading: detectionContentLoading,
    reload: reloadDetectionContent,
  } = useApiGroup({
    weights: api.detectionWeights,
    contentRulesData: api.contentRules,
    packsData: api.contentPacks,
    huntsData: api.hunts,
    suppressionsData: api.suppressions,
  });
  const { data: mitreCoverage } = useApi(api.mitreCoverageAlt);
  const { data: coverageGaps } = useApi(api.coverageGaps);
  const { data: malwareStats } = useApi(api.malwareStats);
  const { data: malwareRecent } = useApi(api.malwareRecent);
  const { data: feedStats } = useApi(api.feedStats);
  const { data: feeds } = useApi(api.feeds);
  const { data: quarantineStats } = useApi(api.quarantineStats);
  const { data: quarantineItems } = useApi(api.quarantineList);
  const { data: hostInventory } = useApi(api.hostInventory);
  const { data: fleetInventory } = useApi(api.fleetInventory);
  const { weights, contentRulesData, packsData, huntsData, suppressionsData } =
    detectionContentData;
  const reloadWeights = reloadDetectionContent;
  const reloadRules = reloadDetectionContent;
  const reloadPacks = reloadDetectionContent;
  const reloadHunts = reloadDetectionContent;
  const reloadSuppressions = reloadDetectionContent;
  const [testResult, setTestResult] = useState(null);
  const [drawerMode, setDrawerMode] = useState(null);
  const [weightInput, setWeightInput] = useState('0.50');
  const [huntDraft, setHuntDraft] = useState({
    id: '',
    name: '',
    query: '',
    hypothesis: '',
    expectedOutcome: 'explore',
    severity: 'medium',
    level: '',
    limit: '250',
    threshold: '1',
    suppressionWindowSecs: '0',
    scheduleIntervalSecs: '',
    scheduleCron: '',
    timeFrom: '',
    timeTo: '',
    lifecycle: 'draft',
    canaryPercentage: '100',
    packId: '',
    targetGroup: '',
    recommendedWorkflows: [],
  });
  const [packDraft, setPackDraft] = useState({
    id: '',
    name: '',
    description: '',
    enabled: true,
    savedSearchesText: '',
    recommendedWorkflowsText: '',
    targetGroup: '',
    rolloutNotes: '',
    ruleIds: [],
  });
  const [huntResult, setHuntResult] = useState(null);
  const [canaryPromotionResults, setCanaryPromotionResults] = useState([]);
  const [replayMode, setReplayMode] = useState('retained_events');
  const [replayPackName, setReplayPackName] = useState('retained-last-alerts');
  const [replayThreshold, setReplayThreshold] = useState('2');
  const [replayLimit, setReplayLimit] = useState('100');
  const [replayPackText, setReplayPackText] = useState('');
  const [replayPackResult, setReplayPackResult] = useState(null);
  const [replayRunning, setReplayRunning] = useState(false);
  const [runningCanaryPromotion, setRunningCanaryPromotion] = useState(false);
  const [huntRunning, setHuntRunning] = useState(false);
  const [huntSaving, setHuntSaving] = useState(false);
  const [packSaving, setPackSaving] = useState(false);
  const [runningSavedHuntId, setRunningSavedHuntId] = useState(null);
  const [escalatingRunId, setEscalatingRunId] = useState(null);
  const [promotingHuntResult, setPromotingHuntResult] = useState(false);
  const [drawerSessionId, setDrawerSessionId] = useState(0);
  const [drawerBaseline, setDrawerBaseline] = useState(null);
  const [investigationSuggestions, setInvestigationSuggestions] = useState([]);
  const [suggestingInvestigations, setSuggestingInvestigations] = useState(false);
  const [startingInvestigationId, setStartingInvestigationId] = useState(null);
  const [suppressionForm, setSuppressionForm] = useState({
    name: '',
    justification: 'Operator suppression',
    severity: '',
    text: '',
  });

  const allRules = useMemo(
    () => (Array.isArray(contentRulesData?.rules) ? contentRulesData.rules : []),
    [contentRulesData],
  );
  const packs = useMemo(
    () => (Array.isArray(packsData?.packs) ? packsData.packs : []),
    [packsData],
  );
  const hunts = useMemo(
    () => (Array.isArray(huntsData?.hunts) ? huntsData.hunts : []),
    [huntsData],
  );
  const suppressions = useMemo(
    () => (Array.isArray(suppressionsData?.suppressions) ? suppressionsData.suppressions : []),
    [suppressionsData],
  );
  const suppressionCount = suppressions.reduce((acc, suppression) => {
    if (suppression.rule_id) acc[suppression.rule_id] = (acc[suppression.rule_id] || 0) + 1;
    return acc;
  }, {});

  const queue = searchParams.get('queue') || 'noisy';
  const query = searchParams.get('q') || '';
  const ownerFilter = searchParams.get('owner') || 'all';
  const selectedRuleId = searchParams.get('rule');
  const workspacePanel = normalizePanelId(searchParams.get('panel'), WORKSPACE_PANELS, 'overview');
  const rulePanel = normalizePanelId(searchParams.get('rulePanel'), RULE_DETAIL_PANELS, 'summary');
  const tuneOpen = searchParams.get('tune') === '1';
  const activeDrawerMode = drawerMode || (tuneOpen ? 'tune' : null);
  const intent = searchParams.get('intent') || '';
  const huntIntent = intent === 'run-hunt';
  const huntQueryParam = searchParams.get('huntQuery') || '';
  const huntNameParam = searchParams.get('huntName') || '';

  const updateSearchState = (updates = {}, options = {}) => {
    const next = new URLSearchParams(searchParams);
    Object.entries(updates).forEach(([key, value]) => {
      if (value == null || String(value).trim() === '') next.delete(key);
      else next.set(key, String(value));
    });
    setSearchParams(next, { replace: options.replace ?? true });
  };

  const filteredRules = allRules.filter((rule) => {
    const savedView = SAVED_VIEWS.find((item) => item.id === queue);
    const queueMatch = savedView ? savedView.match(rule, { suppressionCount }) : true;
    const q = query.trim().toLowerCase();
    const searchMatch =
      !q ||
      String(rule.title || '')
        .toLowerCase()
        .includes(q) ||
      String(rule.id || '')
        .toLowerCase()
        .includes(q) ||
      String(rule.description || '')
        .toLowerCase()
        .includes(q);
    const ownerMatch = ownerFilter === 'all' || String(rule.owner || 'system') === ownerFilter;
    return queueMatch && searchMatch && ownerMatch;
  });

  const selectedRule =
    filteredRules.find((rule) => rule.id === selectedRuleId) ||
    allRules.find((rule) => rule.id === selectedRuleId) ||
    filteredRules[0] ||
    allRules[0] ||
    null;
  const { data: selectedRuleEfficacy } = useApi(
    () => api.efficacyRule(selectedRule.id),
    [selectedRule?.id],
    { skip: !selectedRule?.id },
  );
  const selectedPacks = useMemo(
    () => packs.filter((pack) => (selectedRule?.pack_ids || []).includes(pack.id)),
    [packs, selectedRule],
  );
  const selectedRuleLifecycleHistory = useMemo(() => {
    const history = Array.isArray(selectedRule?.lifecycle_history)
      ? selectedRule.lifecycle_history
      : [];
    return [...history].slice(-4).reverse();
  }, [selectedRule]);
  const selectedRuleLinkedHunts = useMemo(() => {
    const packIds = new Set(selectedPacks.map((pack) => pack.id));
    return hunts.filter((hunt) => packIds.has(hunt.pack_id));
  }, [hunts, selectedPacks]);
  const detectionOwnershipCalendar = useMemo(() => {
    const rows = allRules
      .map((rule) => {
        const review = reviewStatusMeta(rule, suppressionCount);
        return {
          id: rule.id,
          title: rule.title || rule.id,
          owner: rule.owner || 'system',
          lifecycle: formatLifecycleLabel(rule.lifecycle),
          dueAt: review.dueAt,
          dueInDays: review.dueInDays,
          reviewLabel: review.label,
          reviewTone: review.tone,
          reviewRank: review.rank,
          reviewQueue: review.queue,
          blockers: review.blockers,
          replay: review.replay,
          nextAction:
            review.blockers.length > 0
              ? 'Clear replay and ownership blockers before promoting new case or ticket workflows.'
              : 'Keep the next owner review scheduled and use hunts to promote new findings into cases quickly.',
        };
      })
      .sort((left, right) => {
        if (left.reviewRank !== right.reviewRank) return left.reviewRank - right.reviewRank;
        const leftDue = left.dueAt ? new Date(left.dueAt).getTime() : Number.MAX_SAFE_INTEGER;
        const rightDue = right.dueAt ? new Date(right.dueAt).getTime() : Number.MAX_SAFE_INTEGER;
        if (leftDue !== rightDue) return leftDue - rightDue;
        return left.title.localeCompare(right.title);
      });

    const summary = {
      overdue: rows.filter((row) => row.reviewLabel === 'Overdue').length,
      dueThisWeek: rows.filter((row) => row.reviewLabel === 'Due this week').length,
      replayBlockers: rows.filter((row) => row.blockers.length > 0).length,
      noisyOwners: new Set(
        rows
          .filter((row) => row.replay.label === 'Noisy replay')
          .map((row) => row.owner)
          .filter(Boolean),
      ).size,
    };

    return { rows, summary };
  }, [allRules, suppressionCount]);
  const selectedRuleCalendarEntry = useMemo(
    () => detectionOwnershipCalendar.rows.find((row) => row.id === selectedRule?.id) || null,
    [detectionOwnershipCalendar, selectedRule],
  );
  const selectedRuleReviewHistory = selectedRule?.review_history || {};
  const selectedRuleLatestReplay = selectedRuleReviewHistory?.latest_replay || null;
  const selectedRuleAnalystFeedback = selectedRuleReviewHistory?.analyst_feedback || null;
  const currentWeight = Number(
    weights?.weights?.[selectedRule?.id] ?? weights?.[selectedRule?.id] ?? 0.5,
  );
  const activeDrawerSnapshot =
    activeDrawerMode === 'tune'
      ? JSON.stringify({ weightInput })
      : activeDrawerMode === 'suppress'
        ? JSON.stringify(suppressionForm)
        : activeDrawerMode === 'pack'
          ? JSON.stringify(packDraft)
          : activeDrawerMode === 'hunt'
            ? JSON.stringify(huntDraft)
            : null;
  const isDrawerDirty =
    Boolean(activeDrawerMode) &&
    drawerBaseline?.mode === activeDrawerMode &&
    drawerBaseline?.sessionId === drawerSessionId &&
    drawerBaseline?.value !== activeDrawerSnapshot;

  useEffect(() => {
    if (!activeDrawerMode) {
      if (drawerBaseline !== null) setDrawerBaseline(null);
      return;
    }
    if (
      !drawerBaseline ||
      drawerBaseline.mode !== activeDrawerMode ||
      drawerBaseline.sessionId !== drawerSessionId
    ) {
      setDrawerBaseline({
        mode: activeDrawerMode,
        sessionId: drawerSessionId,
        value: activeDrawerSnapshot,
      });
    }
  }, [activeDrawerMode, activeDrawerSnapshot, drawerBaseline, drawerSessionId]);

  useEffect(() => {
    if (!isDrawerDirty) return undefined;
    const handleBeforeUnload = (event) => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isDrawerDirty]);

  useEffect(() => {
    if (!selectedRule || selectedRule.id === selectedRuleId) return;
    const next = new URLSearchParams(searchParams);
    next.set('rule', selectedRule.id);
    setSearchParams(next, { replace: true });
  }, [selectedRule, selectedRuleId, searchParams, setSearchParams]);

  useEffect(() => {
    if (huntIntent && activeDrawerMode !== 'hunt') {
      setDrawerSessionId((value) => value + 1);
      setDrawerMode('hunt');
    }
  }, [huntIntent, activeDrawerMode]);

  useEffect(() => {
    if (!selectedRule) return;
    const initialWeight = weights?.weights?.[selectedRule.id] ?? weights?.[selectedRule.id] ?? 0.5;
    setWeightInput(Number(initialWeight).toFixed(2));
    setSuppressionForm((form) => ({
      ...form,
      name: `Suppress ${selectedRule.title || selectedRule.id}`,
      severity: selectedRule.severity_mapping || '',
    }));
  }, [selectedRule, weights]);

  useEffect(() => {
    const reasons = buildInvestigationReasons(selectedRule);
    if (!selectedRule || reasons.length === 0) {
      setInvestigationSuggestions([]);
      return undefined;
    }

    let cancelled = false;
    setSuggestingInvestigations(true);
    api
      .investigationSuggest({ alert_reasons: reasons })
      .then((result) => {
        if (cancelled) return;
        const items = Array.isArray(result) ? result : result?.suggestions || [];
        setInvestigationSuggestions(items);
      })
      .catch(() => {
        if (!cancelled) setInvestigationSuggestions([]);
      })
      .finally(() => {
        if (!cancelled) setSuggestingInvestigations(false);
      });

    return () => {
      cancelled = true;
    };
  }, [selectedRule]);

  useEffect(() => {
    if (!selectedRule) return;
    if (drawerMode === 'hunt' && !huntIntent && !huntQueryParam && !huntNameParam) return;

    const primaryPack = packs.find((pack) => (selectedRule.pack_ids || []).includes(pack.id));

    setHuntDraft((draft) => ({
      ...draft,
      id: '',
      name: huntNameParam || `Hunt ${selectedRule.title || selectedRule.id}`,
      query: buildDefaultHuntQuery(selectedRule, huntQueryParam),
      severity: String(selectedRule.severity_mapping || draft.severity || 'medium').toLowerCase(),
      level: String(selectedRule.severity_mapping || draft.level || '').toLowerCase(),
      lifecycle: String(selectedRule.lifecycle || 'draft').toLowerCase(),
      canaryPercentage: selectedRule.lifecycle === 'canary' ? '10' : '100',
      packId: primaryPack?.id || '',
      targetGroup: primaryPack?.target_group || '',
      recommendedWorkflows: Array.isArray(primaryPack?.recommended_workflows)
        ? primaryPack.recommended_workflows
        : [],
    }));
  }, [selectedRule, packs, drawerMode, huntIntent, huntQueryParam, huntNameParam]);

  useEffect(() => {
    if (!selectedRule || drawerMode === 'pack') return;
    setPackDraft(
      buildPackDraft({
        pack: selectedPacks[0] || null,
        rule: selectedRule,
        rules: allRules,
        suggestions: investigationSuggestions,
      }),
    );
  }, [selectedRule, selectedPacks, allRules, investigationSuggestions, drawerMode]);

  const openPackEditor = (pack = null) => {
    setPackDraft(
      buildPackDraft({
        pack,
        rule: selectedRule,
        rules: allRules,
        suggestions: investigationSuggestions,
      }),
    );
    setDrawerSessionId((value) => value + 1);
    setDrawerMode('pack');
  };

  const openDrawer = (mode, options = {}) => {
    const { withHuntIntent = mode === 'hunt' } = options;
    const next = new URLSearchParams(searchParams);
    if (selectedRule) next.set('rule', selectedRule.id);
    next.delete('tune');
    next.delete('intent');
    next.delete('huntQuery');
    next.delete('huntName');
    if (mode === 'tune') next.set('tune', '1');
    if (withHuntIntent) next.set('intent', 'run-hunt');
    setSearchParams(next, { replace: true });
    setDrawerSessionId((value) => value + 1);
    setDrawerMode(mode);
  };

  const finalizeDrawerClose = () => {
    const next = new URLSearchParams(searchParams);
    next.delete('tune');
    next.delete('intent');
    next.delete('huntQuery');
    next.delete('huntName');
    setSearchParams(next, { replace: true });
    setDrawerMode(null);
    setDrawerBaseline(null);
  };

  const closeDrawer = async () => {
    if (isDrawerDirty && activeDrawerMode) {
      const labels = {
        tune: 'tuning changes',
        suppress: 'suppression draft changes',
        pack: 'content pack bundle edits',
        hunt: 'hunt draft changes',
      };
      const shouldDiscard = await confirm({
        title: 'Discard unsaved changes?',
        message: `You have unsaved ${labels[activeDrawerMode] || 'changes'}. Close this drawer and lose them?`,
        confirmLabel: 'Discard changes',
        cancelLabel: 'Keep editing',
        tone: 'warning',
      });
      if (!shouldDiscard) return;
    }
    finalizeDrawerClose();
  };

  const renderDrawerDraftNotice = (mode, message) => {
    if (activeDrawerMode !== mode || !isDrawerDirty) return null;
    return (
      <div className="detail-callout" style={{ marginBottom: 16 }}>
        <strong>Unsaved changes</strong>
        <div style={{ marginTop: 6 }}>{message}</div>
      </div>
    );
  };

  const saveWeight = async () => {
    if (!selectedRule) return;
    const parsed = Number(weightInput);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      toast('Enter a valid weight greater than zero.', 'error');
      return;
    }
    try {
      await api.setDetectionWeights({ rule_id: selectedRule.id, weight: parsed });
      toast('Detection weight updated.', 'success');
      reloadWeights();
      finalizeDrawerClose();
    } catch {
      toast('Unable to save detection weight.', 'error');
    }
  };

  const testRule = async () => {
    if (!selectedRule) return;
    try {
      const result = await api.contentRuleTest(selectedRule.id);
      setTestResult(result?.result || result);
      toast('Rule test completed.', 'success');
      reloadRules();
    } catch {
      toast('Rule test failed.', 'error');
    }
  };

  const runCanaryPromotion = async () => {
    setRunningCanaryPromotion(true);
    try {
      const result = await api.efficacyCanaryPromote();
      const results = Array.isArray(result) ? result : [];
      const changedCount = results.filter((entry) =>
        ['promoted', 'rolled_back'].includes(String(entry?.action || '').toLowerCase()),
      ).length;
      setCanaryPromotionResults(results);
      toast(
        changedCount > 0
          ? `Canary automation updated ${changedCount} rule${changedCount === 1 ? '' : 's'}.`
          : 'Canary automation completed with no lifecycle changes.',
        changedCount > 0 ? 'success' : 'info',
      );
      await Promise.all([reloadRules(), reloadWorkbenchOverview()]);
    } catch {
      toast('Canary automation failed.', 'error');
    } finally {
      setRunningCanaryPromotion(false);
    }
  };

  const promoteRule = async (target) => {
    if (!selectedRule) return;
    try {
      await api.contentRulePromote(selectedRule.id, {
        target_status: target,
        reason: `Promoted from workspace to ${target}`,
      });
      toast(`Rule moved to ${target}.`, 'success');
      await Promise.all([reloadRules(), reloadWorkbenchOverview()]);
    } catch {
      toast('Rule promotion failed.', 'error');
    }
  };

  const rollbackRule = async () => {
    if (!selectedRule) return;
    try {
      await api.contentRuleRollback(selectedRule.id);
      toast('Rule rolled back.', 'success');
      await Promise.all([reloadRules(), reloadWorkbenchOverview()]);
    } catch {
      toast('Rule rollback failed.', 'error');
    }
  };

  const disableRule = async () => {
    if (!selectedRule) return;
    try {
      await api.createContentRule({
        ...selectedRule,
        id: selectedRule.id,
        builtin: selectedRule.builtin,
        enabled: false,
        query: selectedRule.query,
      });
      toast('Rule disabled.', 'success');
      reloadRules();
    } catch {
      toast('Rule disable failed.', 'error');
    }
  };

  const createSuppression = async () => {
    if (!selectedRule) return;
    try {
      await api.createSuppression({
        name: suppressionForm.name,
        rule_id: selectedRule.id,
        severity: suppressionForm.severity || undefined,
        text: suppressionForm.text || undefined,
        justification: suppressionForm.justification,
      });
      toast('Suppression saved.', 'success');
      reloadSuppressions();
      finalizeDrawerClose();
    } catch {
      toast('Failed to save suppression.', 'error');
    }
  };

  const savePackDraft = async () => {
    if (!selectedRule) return;
    const name = String(packDraft.name || '').trim();
    if (!name) {
      toast('Enter a content pack name before saving.', 'error');
      return;
    }

    const ruleIds = [...new Set((packDraft.ruleIds || []).filter(Boolean))];
    if (ruleIds.length === 0) ruleIds.push(selectedRule.id);

    setPackSaving(true);
    try {
      await api.createContentPack({
        id: packDraft.id || undefined,
        name,
        description: String(packDraft.description || '').trim(),
        enabled: packDraft.enabled !== false,
        rule_ids: ruleIds,
        saved_searches: textToBundleList(packDraft.savedSearchesText),
        recommended_workflows: textToBundleList(packDraft.recommendedWorkflowsText),
        target_group: String(packDraft.targetGroup || '').trim() || undefined,
        rollout_notes: String(packDraft.rolloutNotes || '').trim() || undefined,
      });
      toast(
        packDraft.id ? 'Content pack bundle updated.' : 'Content pack bundle created.',
        'success',
      );
      reloadPacks();
      reloadRules();
      finalizeDrawerClose();
    } catch (error) {
      toast(
        error?.status === 403
          ? 'Session is not assigned to the selected target group.'
          : 'Failed to save content pack bundle.',
        'error',
      );
    } finally {
      setPackSaving(false);
    }
  };

  const runReplayValidation = async () => {
    const threshold = Number(replayThreshold);
    if (!Number.isFinite(threshold) || threshold <= 0) {
      toast('Enter a replay threshold greater than zero.', 'error');
      return;
    }

    let body;
    if (replayMode === 'retained_events') {
      const limit = Number.parseInt(replayLimit, 10);
      if (!Number.isFinite(limit) || limit <= 0) {
        toast('Enter a retained-event limit greater than zero.', 'error');
        return;
      }
      body = {
        source: 'retained_events',
        name: replayPackName || 'Retained-event replay corpus',
        threshold,
        limit,
      };
    } else {
      try {
        const parsed = JSON.parse(replayPackText || '{}');
        body = Array.isArray(parsed)
          ? { samples: parsed }
          : { ...parsed, samples: parsed.samples || [] };
      } catch {
        toast('Paste a valid JSON replay pack before running validation.', 'error');
        return;
      }
      body = {
        ...body,
        source: 'custom',
        name: replayPackName || body.name || 'Custom replay corpus',
        threshold,
      };
    }

    setReplayRunning(true);
    try {
      const result = await api.evaluateDetectionReplayCorpus(body);
      setReplayPackResult(result);
      toast('Replay validation complete.', 'success');
    } catch {
      toast('Unable to run replay validation.', 'error');
    } finally {
      setReplayRunning(false);
    }
  };

  const runLiveHunt = async (overrideQuery) => {
    const queryText = String(overrideQuery ?? huntDraft.query).trim();
    if (!queryText) {
      toast('Enter a hunt query before running it.', 'error');
      return;
    }

    setHuntRunning(true);
    try {
      const result = await api.hunt(queryText);
      setHuntResult(result);
      toast('Hunt completed.', 'success');
      if (activeDrawerMode !== 'hunt') openDrawer('hunt');
    } catch {
      toast('Hunt failed.', 'error');
    } finally {
      setHuntRunning(false);
    }
  };

  const saveHuntDraft = async () => {
    const queryText = String(huntDraft.query || '').trim();
    if (!queryText) {
      toast('Enter a hunt query before saving.', 'error');
      return;
    }

    const selectedPack = packs.find((pack) => pack.id === huntDraft.packId) || selectedPacks[0];
    const recommendedWorkflows = [
      ...new Set([
        ...(huntDraft.recommendedWorkflows || []).filter(Boolean),
        ...(selectedPack?.recommended_workflows || []).filter(Boolean),
        ...investigationSuggestions
          .slice(0, 3)
          .map((workflow) => workflow?.id)
          .filter(Boolean),
      ]),
    ];

    setHuntSaving(true);
    try {
      await api.createHunt({
        id: huntDraft.id || undefined,
        name: huntDraft.name || `Hunt ${selectedRule?.title || selectedRule?.id || 'Signals'}`,
        hypothesis: huntDraft.hypothesis || undefined,
        expected_outcome: huntDraft.expectedOutcome || 'explore',
        severity: huntDraft.severity || selectedRule?.severity_mapping || 'medium',
        threshold: Number(huntDraft.threshold) || 1,
        suppression_window_secs: Number(huntDraft.suppressionWindowSecs) || 0,
        schedule_interval_secs: huntDraft.scheduleIntervalSecs
          ? Number(huntDraft.scheduleIntervalSecs)
          : undefined,
        schedule_cron: huntDraft.scheduleCron || undefined,
        lifecycle: huntDraft.lifecycle || 'draft',
        canary_percentage:
          huntDraft.lifecycle === 'canary' ? Number(huntDraft.canaryPercentage) || 10 : 100,
        pack_id: huntDraft.packId || selectedPack?.id || undefined,
        target_group: huntDraft.targetGroup || selectedPack?.target_group || undefined,
        recommended_workflows: recommendedWorkflows,
        query: {
          text: queryText,
          level: huntDraft.level || undefined,
          limit: Number(huntDraft.limit) || 250,
        },
      });
      toast('Hunt saved.', 'success');
      reloadHunts();
      setDrawerBaseline((current) =>
        activeDrawerMode === 'hunt'
          ? {
              mode: 'hunt',
              sessionId: drawerSessionId,
              value: activeDrawerSnapshot,
            }
          : current,
      );
    } catch (error) {
      toast(
        error?.status === 403
          ? 'Session is not assigned to the selected target group.'
          : 'Failed to save hunt.',
        'error',
      );
    } finally {
      setHuntSaving(false);
    }
  };

  const runSavedHuntNow = async (huntId) => {
    if (!huntId) return;
    setRunningSavedHuntId(huntId);
    try {
      const result = await api.runHunt(huntId, {
        time_from: toIsoOrUndefined(huntDraft.timeFrom),
        time_to: toIsoOrUndefined(huntDraft.timeTo),
      });
      setHuntResult(result);
      openDrawer('hunt');
      toast('Saved hunt executed.', 'success');
      reloadHunts();
    } catch (error) {
      toast(
        error?.status === 403
          ? 'Session is not assigned to that hunt target group.'
          : 'Failed to run saved hunt.',
        'error',
      );
    } finally {
      setRunningSavedHuntId(null);
    }
  };

  const escalateHuntRun = async (huntId, runId) => {
    if (!huntId || !runId) return;
    setEscalatingRunId(runId);
    try {
      const result = await api.escalateHunt(huntId, { run_id: runId });
      toast(`Escalated to case #${result?.case_id || 'new'}.`, 'success');
      setHuntResult((current) => ({
        ...(current || {}),
        escalated_case_id: result?.case_id,
      }));
      reloadHunts();
    } catch {
      toast('Failed to escalate hunt result to case.', 'error');
    } finally {
      setEscalatingRunId(null);
    }
  };

  const startInvestigationFromWorkflow = async (workflow) => {
    if (!workflow?.id) return;
    setStartingInvestigationId(workflow.id);
    try {
      await api.investigationStart({ workflow_id: workflow.id, analyst: 'admin' });
      toast('Investigation started.', 'success');
      navigate('/soc#investigations');
    } catch {
      toast('Failed to start investigation.', 'error');
    } finally {
      setStartingInvestigationId(null);
    }
  };

  const loadSavedHuntIntoDraft = (hunt) => {
    if (!hunt) return;
    const queryText =
      typeof hunt.query === 'string' ? hunt.query : hunt.query?.text || hunt.query?.query || '';

    setHuntDraft({
      id: hunt.id || '',
      name: hunt.name || `Hunt ${selectedRule?.title || selectedRule?.id || 'Signals'}`,
      query: queryText,
      hypothesis: String(hunt.hypothesis || ''),
      expectedOutcome: String(hunt.expected_outcome || 'explore'),
      severity: String(hunt.severity || selectedRule?.severity_mapping || 'medium').toLowerCase(),
      level: String(hunt.query?.level || '').toLowerCase(),
      limit: String(hunt.query?.limit || 250),
      threshold: String(hunt.threshold || 1),
      suppressionWindowSecs: String(hunt.suppression_window_secs || 0),
      scheduleIntervalSecs: hunt.schedule_interval_secs ? String(hunt.schedule_interval_secs) : '',
      scheduleCron: hunt.schedule_cron || '',
      timeFrom: '',
      timeTo: '',
      lifecycle: String(hunt.lifecycle || 'draft').toLowerCase(),
      canaryPercentage: String(hunt.canary_percentage || 100),
      packId: hunt.pack_id || '',
      targetGroup: hunt.target_group || '',
      recommendedWorkflows: Array.isArray(hunt.recommended_workflows)
        ? hunt.recommended_workflows
        : [],
    });
    openDrawer('hunt', { withHuntIntent: false });
  };

  const packNames = selectedPacks.map((pack) => pack.name || pack.id);
  const packSavedSearches = [
    ...new Set(
      selectedPacks.flatMap((pack) =>
        Array.isArray(pack.saved_searches) ? pack.saved_searches : [],
      ),
    ),
  ];
  const packWorkflowIds = [
    ...new Set(
      selectedPacks.flatMap((pack) =>
        Array.isArray(pack.recommended_workflows) ? pack.recommended_workflows : [],
      ),
    ),
  ];
  const relatedHunts = hunts.filter((hunt) => {
    const text = `${hunt.name || ''} ${JSON.stringify(hunt.query || {})}`.toLowerCase();
    const packMatch =
      selectedRule && hunt.pack_id && (selectedRule.pack_ids || []).includes(hunt.pack_id);
    return (
      selectedRule &&
      (text.includes(String(selectedRule.id).toLowerCase()) ||
        text.includes(String(selectedRule.title || '').toLowerCase()) ||
        packMatch)
    );
  });
  const huntSummary = summarizeHuntResult(huntResult);
  const linkedHuntCaseId = linkedCaseIdFromHuntResult(huntResult);

  const openHuntCase = () => {
    if (!linkedHuntCaseId) return;
    navigate(
      buildHref('/soc', {
        params: { case: linkedHuntCaseId, source: 'hunt' },
        hash: 'cases',
      }),
    );
  };

  const openHuntResponse = () => {
    if (!huntResult) return;
    navigate(
      buildHref('/soc', {
        params: {
          case: linkedHuntCaseId || undefined,
          target: huntResultContextTarget(huntResult, selectedRule),
          source: 'hunt',
        },
        hash: 'response',
      }),
    );
  };

  const promoteCurrentHuntToCase = async () => {
    if (!huntResult) {
      toast('Run a hunt before promoting it to a case.', 'warning');
      return;
    }
    if (linkedHuntCaseId) {
      openHuntCase();
      return;
    }

    setPromotingHuntResult(true);
    try {
      const caseTitle =
        huntDraft.name || `Hunt ${selectedRule?.title || selectedRule?.id || 'Signals'}`;
      const caseDescription = [
        selectedRule?.title ? `Rule: ${selectedRule.title}` : null,
        huntDraft.query ? `Query: ${huntDraft.query}` : null,
        huntSummary.count ? `Matches returned: ${huntSummary.count}.` : null,
        huntSummary.label || null,
      ]
        .filter(Boolean)
        .join('\n');
      const tags = [
        'hunt',
        selectedRule?.id,
        ...(Array.isArray(selectedRule?.attack)
          ? selectedRule.attack.map((mapping) => mapping?.technique_id).filter(Boolean)
          : []),
        ...(huntDraft.recommendedWorkflows || []).filter(Boolean),
      ].filter(Boolean);

      const result = await api.createCase({
        title: caseTitle,
        description: caseDescription,
        priority: casePriorityForSeverity(huntDraft.severity || selectedRule?.severity_mapping),
        tags: [...new Set(tags)],
      });
      setHuntResult((current) => ({
        ...(current || {}),
        escalated_case_id: result?.id,
      }));
      toast(`Promoted hunt result to case #${result?.id || 'new'}.`, 'success');
      if (result?.id) {
        navigate(
          buildHref('/soc', {
            params: { case: result.id, source: 'hunt' },
            hash: 'cases',
          }),
        );
      }
    } catch {
      toast('Failed to promote hunt result to case.', 'error');
    } finally {
      setPromotingHuntResult(false);
    }
  };
  const fpEntries = (
    Array.isArray(fpStats) ? fpStats : Array.isArray(fpStats?.items) ? fpStats.items : []
  )
    .filter((entry) => entry && typeof entry === 'object' && entry.pattern)
    .map((entry) => ({
      pattern: entry.pattern,
      total_marked: Number(entry.total_marked) || 0,
      false_positives: Number(entry.false_positives) || 0,
      fp_ratio: Number(entry.fp_ratio ?? entry.ratio) || 0,
      suppression_weight: Number(entry.suppression_weight) || 1,
    }))
    .sort(
      (left, right) => right.fp_ratio - left.fp_ratio || right.total_marked - left.total_marked,
    );
  const ruleFpSignals = selectedRule
    ? fpEntries
        .map((entry) => ({
          ...entry,
          matchScore: scoreFpPatternMatch(selectedRule, entry.pattern),
        }))
        .filter((entry) => entry.matchScore > 0)
        .sort(
          (left, right) =>
            right.matchScore - left.matchScore ||
            right.fp_ratio - left.fp_ratio ||
            right.total_marked - left.total_marked,
        )
    : [];
  const suppressionAdvisor = ruleFpSignals[0] || null;
  const fpPreview = (ruleFpSignals.length > 0 ? ruleFpSignals : fpEntries).slice(0, 3);
  const huntQuickStarts = buildHuntQuickStarts(selectedRule);
  const severityEfficacyRows = useMemo(
    () =>
      Object.entries(efficacySummary?.by_severity || {})
        .map(([severity, metrics]) => ({ severity, metrics }))
        .sort((left, right) =>
          severityTone(right.severity).localeCompare(severityTone(left.severity)),
        ),
    [efficacySummary],
  );
  const efficacyWorstRules = useMemo(
    () => (Array.isArray(efficacySummary?.worst_rules) ? efficacySummary.worst_rules : []),
    [efficacySummary],
  );
  const efficacyBestRules = useMemo(
    () => (Array.isArray(efficacySummary?.best_rules) ? efficacySummary.best_rules : []),
    [efficacySummary],
  );
  const coverageGapItems = useMemo(() => {
    const items = Array.isArray(coverageGaps?.gaps)
      ? coverageGaps.gaps
      : Array.isArray(coverageGaps)
        ? coverageGaps
        : [];
    return [...items].sort(
      (left, right) =>
        priorityRank(left?.priority) - priorityRank(right?.priority) ||
        String(left?.technique_id || '').localeCompare(String(right?.technique_id || '')),
    );
  }, [coverageGaps]);
  const tacticGapRows = useMemo(() => {
    const items = Array.isArray(coverageGaps?.by_tactic) ? coverageGaps.by_tactic : [];
    return [...items].sort(
      (left, right) =>
        Number(left?.pct ?? 100) - Number(right?.pct ?? 100) ||
        Number(right?.uncovered ?? 0) - Number(left?.uncovered ?? 0),
    );
  }, [coverageGaps]);
  const urgentCoverageGapCount = coverageGapItems.filter(
    (gap) => priorityRank(gap?.priority) <= 1,
  ).length;
  const weakestTactic = tacticGapRows[0] || null;
  const selectedRuleTechniqueIds = new Set(
    (Array.isArray(selectedRule?.attack) ? selectedRule.attack : [])
      .map((attack) => String(attack?.technique_id || '').trim())
      .filter(Boolean),
  );
  const selectedRuleTactics = new Set(
    (Array.isArray(selectedRule?.attack) ? selectedRule.attack : [])
      .map((attack) => normalizeText(attack?.tactic))
      .filter(Boolean),
  );
  const selectedRuleCoverageGaps = coverageGapItems.filter(
    (gap) =>
      selectedRuleTechniqueIds.has(String(gap?.technique_id || '').trim()) ||
      selectedRuleTactics.has(normalizeText(gap?.tactic)),
  );
  const activeSuppressions = useMemo(
    () => suppressions.filter((item) => item.active !== false),
    [suppressions],
  );
  const expiringSuppressions = useMemo(
    () =>
      activeSuppressions.filter((item) => {
        if (!item.expires_at) return false;
        const expiresAt = new Date(item.expires_at);
        if (Number.isNaN(expiresAt.getTime())) return false;
        const delta = expiresAt.getTime() - Date.now();
        return delta >= 0 && delta <= 7 * 24 * 60 * 60 * 1000;
      }),
    [activeSuppressions],
  );
  const noiseWatchlist = useMemo(
    () =>
      allRules
        .map((rule) => {
          const hits = Number(rule.last_test_match_count) || 0;
          const liveSuppressions = suppressionCount[rule.id] || 0;
          const fpSignal =
            fpEntries
              .map((entry) => ({
                ...entry,
                matchScore: scoreFpPatternMatch(rule, entry.pattern),
              }))
              .filter((entry) => entry.matchScore > 0)
              .sort(
                (left, right) =>
                  right.matchScore - left.matchScore ||
                  right.fp_ratio - left.fp_ratio ||
                  right.total_marked - left.total_marked,
              )[0] || null;
          const riskScore =
            (hits >= 5 ? 4 : hits > 0 ? 2 : 0) +
            (liveSuppressions === 0 ? 2 : 0) +
            ((fpSignal?.fp_ratio || 0) >= 0.5 ? 2 : 0) +
            ((fpSignal?.fp_ratio || 0) >= 0.7 ? 1 : 0);
          return {
            rule,
            hits,
            liveSuppressions,
            fpSignal,
            riskScore,
            unresolvedNoise: hits >= 5 && liveSuppressions === 0,
          };
        })
        .filter(
          (item) =>
            item.hits > 0 || item.liveSuppressions > 0 || item.fpSignal || item.unresolvedNoise,
        )
        .sort(
          (left, right) =>
            right.riskScore - left.riskScore ||
            right.hits - left.hits ||
            (right.fpSignal?.fp_ratio || 0) - (left.fpSignal?.fp_ratio || 0),
        ),
    [allRules, suppressionCount, fpEntries],
  );
  const unresolvedNoiseCount = noiseWatchlist.filter((item) => item.unresolvedNoise).length;
  const packRolloutRows = useMemo(
    () =>
      packs
        .map((pack) => {
          const ruleIds = Array.isArray(pack.rule_ids) ? pack.rule_ids : [];
          const linkedRules = allRules.filter(
            (rule) => ruleIds.includes(rule.id) || (rule.pack_ids || []).includes(pack.id),
          );
          const linkedHunts = hunts.filter((hunt) => hunt.pack_id === pack.id);
          const ageDays = ageInDays(pack.updated_at);
          const rollout = summarizePackRollout(pack, linkedHunts.length, ageDays);
          return {
            ...pack,
            linkedRules,
            linkedHunts,
            ageDays,
            rollout,
            averageHits: linkedRules.length
              ? linkedRules.reduce(
                  (acc, rule) => acc + (Number(rule.last_test_match_count) || 0),
                  0,
                ) / linkedRules.length
              : 0,
          };
        })
        .sort(
          (left, right) =>
            left.rollout.rank - right.rollout.rank ||
            right.linkedRules.length - left.linkedRules.length ||
            String(left.name || left.id).localeCompare(String(right.name || right.id)),
        ),
    [packs, allRules, hunts],
  );
  const readyPackCount = packRolloutRows.filter((pack) => pack.rollout.label === 'Ready').length;
  const targetlessPackCount = packRolloutRows.filter(
    (pack) => pack.rollout.label === 'Needs target',
  ).length;
  const stalePackCount = packRolloutRows.filter(
    (pack) => pack.rollout.label === 'Review stale',
  ).length;
  const rolloutOverview = workbenchOverview?.rollouts || null;
  const lifecycleDistributionRows = useMemo(() => {
    const ruleCounts = new Map();
    const huntCounts = new Map();
    allRules.forEach((rule) => {
      const key = normalizeText(rule.lifecycle || 'draft') || 'draft';
      ruleCounts.set(key, (ruleCounts.get(key) || 0) + 1);
    });
    hunts.forEach((hunt) => {
      const key = normalizeText(hunt.lifecycle || 'draft') || 'draft';
      huntCounts.set(key, (huntCounts.get(key) || 0) + 1);
    });
    return ['draft', 'test', 'canary', 'active', 'rolled_back', 'deprecated']
      .map((lifecycle) => {
        const rules = ruleCounts.get(lifecycle) || 0;
        const huntsForLifecycle = huntCounts.get(lifecycle) || 0;
        return {
          id: lifecycle,
          label: formatLifecycleLabel(lifecycle),
          tone: lifecycleTone(lifecycle),
          total: rules + huntsForLifecycle,
          rules,
          hunts: huntsForLifecycle,
        };
      })
      .filter((row) => row.total > 0);
  }, [allRules, hunts]);
  const targetGroupDistributionRows = useMemo(() => {
    const groups = new Map();
    const ensureGroup = (value) => {
      const key = String(value || '').trim() || 'unassigned';
      if (!groups.has(key)) {
        groups.set(key, { group: key, packs: 0, hunts: 0, canaryHunts: 0, linkedRules: 0 });
      }
      return groups.get(key);
    };
    packs.forEach((pack) => {
      const entry = ensureGroup(pack.target_group);
      entry.packs += 1;
      entry.linkedRules += Array.isArray(pack.rule_ids) ? pack.rule_ids.length : 0;
    });
    hunts.forEach((hunt) => {
      const entry = ensureGroup(hunt.target_group);
      entry.hunts += 1;
      if (normalizeText(hunt.lifecycle) === 'canary') entry.canaryHunts += 1;
    });
    return Array.from(groups.values()).sort(
      (left, right) =>
        right.packs + right.hunts - (left.packs + left.hunts) ||
        String(left.group).localeCompare(String(right.group)),
    );
  }, [packs, hunts]);
  const contentRolloutHistory = useMemo(() => {
    const history = Array.isArray(rolloutOverview?.recent_history)
      ? rolloutOverview.recent_history
      : [];
    return history.filter(
      (event) =>
        normalizeText(event.platform) === 'content-rule' ||
        normalizeText(event.action).startsWith('content-'),
    );
  }, [rolloutOverview]);
  const selectedRuleRolloutHistory = useMemo(
    () => contentRolloutHistory.filter((event) => event.agent_id === selectedRule?.id),
    [contentRolloutHistory, selectedRule],
  );
  const routedDeliveryLaneCount = targetGroupDistributionRows.filter(
    (entry) => entry.group !== 'unassigned',
  ).length;
  const replayPlatformDeltas = Array.isArray(replayCorpus?.platform_deltas)
    ? replayCorpus.platform_deltas
    : [];
  const replaySignalTypeDeltas = Array.isArray(replayCorpus?.signal_type_deltas)
    ? replayCorpus.signal_type_deltas
    : [];
  const latestReplayPlatformDeltas = Array.isArray(replayPackResult?.platform_deltas)
    ? replayPackResult.platform_deltas
    : [];
  const latestReplaySignalTypeDeltas = Array.isArray(replayPackResult?.signal_type_deltas)
    ? replayPackResult.signal_type_deltas
    : [];
  const activeWorkspacePanel = WORKSPACE_PANELS.find((panel) => panel.id === workspacePanel);
  const activeRulePanel = RULE_DETAIL_PANELS.find((panel) => panel.id === rulePanel);
  const panelCardStyle = (panelId) => ({
    marginBottom: 16,
    border:
      workspacePanel === panelId
        ? '1px solid color-mix(in srgb, var(--accent) 45%, transparent)'
        : undefined,
    boxShadow:
      workspacePanel === panelId
        ? '0 0 0 1px color-mix(in srgb, var(--accent) 18%, transparent)'
        : undefined,
  });

  const queueCounts = SAVED_VIEWS.reduce((acc, item) => {
    acc[item.id] = allRules.filter((rule) => item.match(rule, { suppressionCount })).length;
    return acc;
  }, {});
  const owners = ['all', ...new Set(allRules.map((rule) => rule.owner || 'system'))];
  const promotionChecklist = buildPromotionChecklist({
    rule: selectedRule,
    liveSuppressions: selectedRule ? suppressionCount[selectedRule.id] || 0 : 0,
    packCount: selectedPacks.length,
    targetGroup: selectedPacks[0]?.target_group || huntDraft.targetGroup,
  });
  const focusRule = (ruleId, panelId = rulePanel) => {
    if (!ruleId) return;
    updateSearchState({
      rule: ruleId,
      rulePanel: panelId ? normalizePanelId(panelId, RULE_DETAIL_PANELS, 'summary') : undefined,
    });
  };
  const focusWorkspacePanel = (panelId, nextRulePanel = null) => {
    updateSearchState({
      panel: normalizePanelId(panelId, WORKSPACE_PANELS, 'overview'),
      rulePanel: nextRulePanel
        ? normalizePanelId(nextRulePanel, RULE_DETAIL_PANELS, 'summary')
        : undefined,
      rule: selectedRule?.id || selectedRuleId || undefined,
    });
  };
  const focusRulePanel = (panelId, ruleId = selectedRule?.id || selectedRuleId) => {
    updateSearchState({
      rule: ruleId || undefined,
      rulePanel: normalizePanelId(panelId, RULE_DETAIL_PANELS, 'summary'),
    });
  };
  const workflowItems = [
    {
      id: 'soc-investigations',
      title: 'Move Into Investigations',
      description: `${investigationSuggestions.length} suggested workflow${investigationSuggestions.length === 1 ? '' : 's'} and ${relatedHunts.length} related hunt${relatedHunts.length === 1 ? '' : 's'} are ready for analyst execution.`,
      to: '/soc#investigations',
      minRole: 'analyst',
      tone: 'primary',
      badge: 'Investigate',
    },
    {
      id: 'attack-graph',
      title: 'Validate Attack Path Impact',
      description: `Check whether ${selectedRule?.title || 'this rule family'} is surfacing part of a broader campaign path.`,
      to: '/attack-graph',
      minRole: 'analyst',
      badge: 'Graph',
    },
    {
      id: 'infrastructure',
      title: 'Cross-Check Affected Assets',
      description: `Review drift, malware, and exposure evidence tied to ${selectedRule?.title || 'the active detection context'}.`,
      to: buildHref('/infrastructure', {
        params: { tab: 'integrity', q: selectedRule?.id || selectedRule?.title || '' },
      }),
      minRole: 'analyst',
      badge: 'Asset',
    },
    {
      id: 'reports',
      title: 'Package Validation Evidence',
      description: `${selectedPacks.length} content pack${selectedPacks.length === 1 ? '' : 's'} and current rollout notes can move straight into evidence exports.`,
      to: buildHref('/reports', {
        params: {
          tab: 'evidence',
          source: 'detection',
          target: selectedRule?.id || selectedRule?.title || undefined,
        },
      }),
      minRole: 'viewer',
      badge: 'Report',
    },
  ];

  const prefillSuppressionFromSignal = (entry) => {
    if (!selectedRule) return;
    setSuppressionForm({
      name: `Suppress ${selectedRule.title || selectedRule.id} • ${entry.pattern}`,
      justification: `Suggested from analyst false-positive feedback: ${entry.false_positives}/${entry.total_marked} alerts were marked false positive for pattern "${entry.pattern}".`,
      severity: selectedRule.severity_mapping || '',
      text: entry.pattern,
    });
    openDrawer('suppress');
    toast('Suppression draft created from false-positive feedback.', 'success');
  };

  const applySuggestedWeight = (entry) => {
    if (!selectedRule) return;
    if ((entry.suppression_weight || 1) >= 0.999) {
      toast(
        'This pattern needs more feedback volume before it can suggest a weight change.',
        'error',
      );
      return;
    }

    const suggested = Math.max(0.05, Math.min(5, currentWeight * entry.suppression_weight));
    setWeightInput(suggested.toFixed(2));
    openDrawer('tune');
    toast(
      `Loaded suggested weight ${suggested.toFixed(2)} from false-positive feedback.`,
      'success',
    );
  };

  if (detectionContentLoading && !contentRulesData && selectedRuleId) {
    return (
      <div className="loading" style={{ padding: 40 }}>
        Loading detection content…
      </div>
    );
  }

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <div>
            <div className="card-title">Detection Engineering Workspace</div>
            <div className="hint">
              Triage noisy rules, validate changes, and move detections through lifecycle gates
              without inline edits.
            </div>
          </div>
          <div className="btn-group">
            {['aggressive', 'balanced', 'quiet'].map((option) => (
              <button
                key={option}
                className={`btn btn-sm ${profile?.profile === option ? 'btn-primary' : ''}`}
                onClick={() =>
                  api
                    .setDetectionProfile({ profile: option })
                    .then(() => toast(`Profile set to ${option}.`, 'success'))
                    .catch(() => toast('Unable to update profile.', 'error'))
                }
              >
                {option}
              </button>
            ))}
          </div>
        </div>
        <div className="summary-grid">
          <div className="summary-card">
            <div className="summary-label">Active Profile</div>
            <div className="summary-value">{profile?.profile || '—'}</div>
            <div className="summary-meta">
              Threshold multiplier {profile?.threshold_multiplier ?? '—'}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Rules In Workspace</div>
            <div className="summary-value">{allRules.length}</div>
            <div className="summary-meta">{filteredRules.length} currently in the active queue</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Coverage</div>
            <div className="summary-value">
              {mitreCoverage?.coverage_pct != null ? `${mitreCoverage.coverage_pct}%` : '—'}
            </div>
            <div className="summary-meta">
              {mitreCoverage?.covered_techniques ?? '—'} techniques covered
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Pending Suppressions</div>
            <div className="summary-value">
              {suppressions.filter((item) => item.active !== false).length}
            </div>
            <div className="summary-meta">Live exceptions currently shaping rule outcomes</div>
          </div>
        </div>
        <div style={{ marginTop: 16 }}>
          <div className="row-primary" style={{ marginBottom: 8 }}>
            Workspace focus
          </div>
          <div className="chip-row" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {WORKSPACE_PANELS.map((panel) => (
              <button
                key={panel.id}
                className={`filter-chip-button ${workspacePanel === panel.id ? 'active' : ''}`}
                onClick={() => focusWorkspacePanel(panel.id)}
              >
                {panel.label}
              </button>
            ))}
          </div>
        </div>
        <div className="detail-callout" style={{ marginTop: 16 }}>
          <strong>URL-backed drilldown focus</strong>
          <div style={{ marginTop: 6 }}>
            {activeWorkspacePanel?.description}{' '}
            {selectedRule
              ? `Selected rule detail is pinned to ${activeRulePanel?.label?.toLowerCase() || 'summary'} for ${selectedRule.title || selectedRule.id}.`
              : 'Select a rule to pin a rule-level panel into the route too.'}
          </div>
        </div>
        {summary && <JsonDetails data={summary} label="Detection summary details" />}
      </div>

      <div className="card" style={panelCardStyle('efficacy')}>
        <div className="card-header">
          <div>
            <div className="card-title">Replay Corpus Gate</div>
            <div className="hint">
              Built-in benign admin, developer tooling, identity abuse, ransomware, beaconing, and
              lateral movement fixtures keep promotion decisions tied to repeatable outcomes.
              Retained-event or customer validation packs can use the same gate through{' '}
              <code>POST /api/detection/replay-corpus</code>.
            </div>
          </div>
          <span className={`badge ${replayCorpus?.status === 'ready' ? 'badge-ok' : 'badge-warn'}`}>
            {String(replayCorpus?.status || 'pending').replace(/_/g, ' ')}
          </span>
        </div>
        <div className="summary-grid" style={{ marginTop: 12 }}>
          <div className="summary-card">
            <div className="summary-label">Precision</div>
            <div className="summary-value">{formatRatio(replayCorpus?.summary?.precision)}</div>
            <div className="summary-meta">
              Target {formatRatio(replayCorpus?.acceptance_targets?.precision_min ?? 0.7)}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Recall</div>
            <div className="summary-value">{formatRatio(replayCorpus?.summary?.recall)}</div>
            <div className="summary-meta">
              Target {formatRatio(replayCorpus?.acceptance_targets?.recall_min ?? 0.7)}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">False Positive Rate</div>
            <div className="summary-value">
              {formatRatio(replayCorpus?.summary?.false_positive_rate)}
            </div>
            <div className="summary-meta">
              Max {formatRatio(replayCorpus?.acceptance_targets?.false_positive_rate_max ?? 0.35)}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Samples</div>
            <div className="summary-value">{replayCorpus?.summary?.total_samples ?? 0}</div>
            <div className="summary-meta">Deterministic corpus categories</div>
          </div>
        </div>
        <div className="card-grid" style={{ marginTop: 16 }}>
          {(replayCorpus?.categories || []).slice(0, 6).map((category) => (
            <div key={category.id} className="card" style={{ background: 'var(--bg)' }}>
              <div className="row-primary">{category.label}</div>
              <div className="hint" style={{ marginTop: 4 }}>
                Expected {category.expected}, predicted {category.predicted}.
              </div>
              <div className="chip-row" style={{ marginTop: 8 }}>
                <span className={`badge ${category.passed ? 'badge-ok' : 'badge-err'}`}>
                  {category.passed ? 'Passed' : 'Review'}
                </span>
                <span className="scope-chip">Score {formatMetricNumber(category.score)}</span>
                <span className="scope-chip">Confidence {formatRatio(category.confidence)}</span>
              </div>
              <div className="hint" style={{ marginTop: 8 }}>
                {category.platform_label || category.platform || 'Unknown platform'} •{' '}
                {category.signal_type_label || category.signal_type || 'Unknown signal family'}
              </div>
            </div>
          ))}
        </div>
        <div className="card-grid" style={{ marginTop: 16 }}>
          <ReplayDeltaSection
            title="Platform deltas"
            hint="Spot where replay performance diverges by operating system or platform slice."
            rows={replayPlatformDeltas}
          />
          <ReplayDeltaSection
            title="Signal-type deltas"
            hint="Track whether credential, beaconing, admin, or impact-style signals drift faster than the overall gate."
            rows={replaySignalTypeDeltas}
          />
        </div>
        <div className="detail-callout" style={{ marginTop: 16 }}>
          <strong>Replay validation runner</strong>
          <div className="hint" style={{ marginTop: 6 }}>
            Run the same promotion gate against recent retained telemetry or paste a customer JSON
            pack with labeled samples.
          </div>
          <div className="summary-grid" style={{ marginTop: 12 }}>
            <div className="form-group">
              <label className="form-label" htmlFor="replay-mode">
                Source
              </label>
              <select
                id="replay-mode"
                className="form-select"
                value={replayMode}
                onChange={(event) => setReplayMode(event.target.value)}
              >
                <option value="retained_events">Retained events</option>
                <option value="custom">Custom JSON pack</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="replay-pack-name">
                Pack Name
              </label>
              <input
                id="replay-pack-name"
                className="form-input"
                value={replayPackName}
                onChange={(event) => setReplayPackName(event.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="replay-threshold">
                Threshold
              </label>
              <input
                id="replay-threshold"
                className="form-input"
                value={replayThreshold}
                onChange={(event) => setReplayThreshold(event.target.value)}
              />
            </div>
            {replayMode === 'retained_events' && (
              <div className="form-group">
                <label className="form-label" htmlFor="replay-limit">
                  Retained Limit
                </label>
                <input
                  id="replay-limit"
                  className="form-input"
                  value={replayLimit}
                  onChange={(event) => setReplayLimit(event.target.value)}
                />
              </div>
            )}
          </div>
          {replayMode === 'custom' && (
            <div className="form-group" style={{ marginTop: 12 }}>
              <label className="form-label" htmlFor="replay-pack-json">
                Custom Pack JSON
              </label>
              <textarea
                id="replay-pack-json"
                className="form-textarea"
                rows="6"
                value={replayPackText}
                onChange={(event) => setReplayPackText(event.target.value)}
                placeholder='{"samples":[{"id":"sample-1","expected":"benign","sample":{...}}]}'
              />
            </div>
          )}
          <div className="chip-row" style={{ marginTop: 12 }}>
            <button
              className="btn btn-sm btn-primary"
              onClick={runReplayValidation}
              disabled={replayRunning}
            >
              {replayRunning ? 'Running…' : 'Run Replay Validation'}
            </button>
            {replayMode === 'retained_events' && (
              <button
                className="btn btn-sm"
                onClick={() =>
                  navigate(
                    buildLongRetentionHistoryPath({
                      limit: Math.max(1, Number.parseInt(replayLimit, 10) || 25),
                    }),
                  )
                }
              >
                Open retained events
              </button>
            )}
            {replayPackResult?.summary && (
              <span className="scope-chip">
                Last run: {replayPackResult.summary.total_samples || 0} samples • precision{' '}
                {formatRatio(replayPackResult.summary.precision)} • recall{' '}
                {formatRatio(replayPackResult.summary.recall)}
              </span>
            )}
          </div>
          {replayPackResult && (
            <JsonDetails data={replayPackResult} label="Latest replay validation details" />
          )}
        </div>
        {replayPackResult && (
          <div className="card-grid" style={{ marginTop: 16 }}>
            <ReplayDeltaSection
              title="Latest validation platform deltas"
              hint="Use the last retained-event or custom replay run to see which platform slices need attention before promotion."
              rows={latestReplayPlatformDeltas}
            />
            <ReplayDeltaSection
              title="Latest validation signal-type deltas"
              hint="Compare the newest replay run by signal family so promotion decisions stay tied to the weakest slice."
              rows={latestReplaySignalTypeDeltas}
            />
          </div>
        )}
        {replayCorpus && <JsonDetails data={replayCorpus} label="Replay corpus details" />}
      </div>

      <div className="card" style={panelCardStyle('efficacy')}>
        <div className="card-title" style={{ marginBottom: 10 }}>
          Detection Efficacy Drilldown
        </div>
        <div className="hint" style={{ marginBottom: 12 }}>
          Review analyst-triaged true positives, false positives, and mean triage time before you
          promote or suppress content.
        </div>
        <div className="summary-grid">
          <div className="summary-card">
            <div className="summary-label">Overall Precision</div>
            <div className="summary-value">{formatRatio(efficacySummary?.overall_precision)}</div>
            <div className="summary-meta">True-positive share across resolved rule outcomes.</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">True Positive Rate</div>
            <div className="summary-value">{formatRatio(efficacySummary?.overall_tp_rate)}</div>
            <div className="summary-meta">
              Across {efficacySummary?.total_alerts_triaged ?? 0} triaged alerts.
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">False Positive Rate</div>
            <div className="summary-value">{formatRatio(efficacySummary?.overall_fp_rate)}</div>
            <div className="summary-meta">Use this to prioritize tuning and suppression work.</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Mean Triage</div>
            <div className="summary-value">
              {formatMetricNumber(efficacySummary?.mean_triage_secs)}s
            </div>
            <div className="summary-meta">
              {efficacySummary?.rules_tracked ?? 0} rules currently have outcome history.
            </div>
          </div>
        </div>
        <div className="card-grid" style={{ marginTop: 16 }}>
          <div className="card" style={{ background: 'var(--bg)' }}>
            <div className="card-title" style={{ marginBottom: 10 }}>
              Severity Breakdown
            </div>
            {severityEfficacyRows.length === 0 ? (
              <div className="hint">No severity-level triage metrics have been recorded yet.</div>
            ) : (
              severityEfficacyRows.map(({ severity, metrics }) => (
                <div
                  key={severity}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '10px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div className="row-primary">{severity}</div>
                    <div className="row-secondary">
                      {metrics.total || 0} triaged alert{metrics.total === 1 ? '' : 's'} • mean
                      triage {formatMetricNumber(metrics.mean_triage_secs)}s
                    </div>
                  </div>
                  <div className="btn-group" style={{ alignItems: 'center' }}>
                    <span className={`badge ${severityTone(severity)}`}>
                      {formatRatio(metrics.tp_rate)} TP
                    </span>
                    <span className="badge badge-info">{formatRatio(metrics.fp_rate)} FP</span>
                  </div>
                </div>
              ))
            )}
          </div>
          <div className="card" style={{ background: 'var(--bg)' }}>
            <div className="card-title" style={{ marginBottom: 10 }}>
              Rules Needing Attention
            </div>
            {efficacyWorstRules.length === 0 ? (
              <div className="hint">No rule-level efficacy ranking is available yet.</div>
            ) : (
              efficacyWorstRules.slice(0, 4).map((rule) => (
                <div
                  key={rule.rule_id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '10px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div className="row-primary">{rule.rule_name || rule.rule_id}</div>
                    <div className="row-secondary">
                      Precision {formatRatio(rule.precision)} • {rule.false_positives || 0} false
                      positive
                      {rule.false_positives === 1 ? '' : 's'} •{' '}
                      {formatMetricNumber(rule.mean_triage_secs)}s mean triage
                    </div>
                  </div>
                  <div className="btn-group" style={{ alignItems: 'center' }}>
                    <span className={`badge ${trendTone(rule.trend)}`}>
                      {formatTrendLabel(rule.trend)}
                    </span>
                    <button
                      className="btn btn-sm"
                      onClick={() => focusRule(rule.rule_id, 'efficacy')}
                    >
                      Focus Rule
                    </button>
                  </div>
                </div>
              ))
            )}
            <div className="card-title" style={{ marginTop: 16, marginBottom: 10 }}>
              High Precision Rules
            </div>
            {efficacyBestRules.length === 0 ? (
              <div className="hint">
                The high-confidence rule list will appear once outcomes are tracked.
              </div>
            ) : (
              efficacyBestRules.slice(0, 3).map((rule) => (
                <div
                  key={rule.rule_id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '10px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div className="row-primary">{rule.rule_name || rule.rule_id}</div>
                    <div className="row-secondary">
                      Precision {formatRatio(rule.precision)} • {rule.true_positives || 0} true
                      positive
                      {rule.true_positives === 1 ? '' : 's'}
                    </div>
                  </div>
                  <span className={`badge ${trendTone(rule.trend)}`}>
                    {formatTrendLabel(rule.trend)}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
        <div className="btn-group" style={{ marginTop: 16 }}>
          <button
            className={`btn btn-sm ${workspacePanel === 'efficacy' ? 'btn-primary' : ''}`}
            onClick={() => focusWorkspacePanel('efficacy', 'efficacy')}
          >
            Focus Drilldown
          </button>
        </div>
      </div>

      <WorkflowGuidance
        title="Detection Pivots"
        description="Carry the active rule, hunt, and pack context into analyst investigations, asset review, and export workflows."
        items={workflowItems}
      />

      <div className="card" style={panelCardStyle('coverage')}>
        <div className="card-title" style={{ marginBottom: 10 }}>
          ATT&CK Coverage Heatmap (Rules + Hunts)
        </div>
        <div className="hint" style={{ marginBottom: 12 }}>
          Highlights technique blind spots where neither rule coverage nor hunt coverage is present.
        </div>
        <div className="summary-grid">
          <div className="summary-card">
            <div className="summary-label">Covered Techniques</div>
            <div className="summary-value">{mitreCoverage?.covered_techniques ?? '—'}</div>
            <div className="summary-meta">
              {mitreCoverage?.coverage_pct ?? '—'}% total ATT&CK coverage
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Gap Techniques</div>
            <div className="summary-value">
              {Array.isArray(coverageGaps?.gaps)
                ? coverageGaps.gaps.length
                : Array.isArray(coverageGaps)
                  ? coverageGaps.length
                  : '—'}
            </div>
            <div className="summary-meta">Techniques without matched rule/hunt content</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Critical + High Gaps</div>
            <div className="summary-value">{urgentCoverageGapCount}</div>
            <div className="summary-meta">Prioritize these before broad content promotion.</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Weakest Tactic</div>
            <div className="summary-value">{weakestTactic?.tactic || '—'}</div>
            <div className="summary-meta">
              {weakestTactic
                ? `${weakestTactic.uncovered} uncovered technique${weakestTactic.uncovered === 1 ? '' : 's'} • ${Math.round(Number(weakestTactic.pct) || 0)}% coverage`
                : 'No tactic-level gap summary available.'}
            </div>
          </div>
        </div>
        <div className="card-grid" style={{ marginTop: 16 }}>
          <div className="card" style={{ background: 'var(--bg)' }}>
            <div className="card-title" style={{ marginBottom: 10 }}>
              Priority Gaps
            </div>
            {coverageGapItems.length === 0 ? (
              <div className="hint">No ATT&CK gaps are currently reported.</div>
            ) : (
              coverageGapItems.slice(0, 6).map((gap) => (
                <div
                  key={`${gap?.technique_id || gap?.technique || 'gap'}-${gap?.tactic || 'tactic'}`}
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
                      {gap?.technique_id || gap?.technique || 'Unknown technique'} •{' '}
                      {gap?.technique_name || gap?.name || 'Unmapped'}
                    </div>
                    <div className="row-secondary">
                      {gap?.tactic || 'unknown tactic'} •{' '}
                      {gap?.recommendation || 'No recommendation available.'}
                    </div>
                    <div className="hint" style={{ marginTop: 4 }}>
                      {(Array.isArray(gap?.suggested_sources) ? gap.suggested_sources : []).join(
                        ' • ',
                      ) || 'No suggested sources'}
                    </div>
                  </div>
                  <span className={`badge ${priorityTone(gap?.priority)}`}>
                    {gap?.priority || 'Low'}
                  </span>
                </div>
              ))
            )}
          </div>
          <div className="card" style={{ background: 'var(--bg)' }}>
            <div className="card-title" style={{ marginBottom: 10 }}>
              Tactic Coverage + Recommendations
            </div>
            {tacticGapRows.length === 0 ? (
              <div className="hint">No tactic-level gap data has been recorded yet.</div>
            ) : (
              tacticGapRows.slice(0, 5).map((row) => (
                <div
                  key={row.tactic}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '10px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div className="row-primary">{row.tactic}</div>
                    <div className="row-secondary">
                      {row.covered}/{row.total} covered • {row.uncovered} gap
                      {row.uncovered === 1 ? '' : 's'}
                    </div>
                  </div>
                  <span
                    className={`badge ${Number(row.pct) < 50 ? 'badge-err' : Number(row.pct) < 75 ? 'badge-warn' : 'badge-ok'}`}
                  >
                    {Math.round(Number(row.pct) || 0)}%
                  </span>
                </div>
              ))
            )}
            <div className="card-title" style={{ marginTop: 16, marginBottom: 10 }}>
              Top Recommendations
            </div>
            {Array.isArray(coverageGaps?.top_recommendations) &&
            coverageGaps.top_recommendations.length > 0 ? (
              coverageGaps.top_recommendations.slice(0, 4).map((recommendation) => (
                <div
                  key={recommendation}
                  style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}
                >
                  <div className="row-secondary">{recommendation}</div>
                </div>
              ))
            ) : (
              <div className="hint">No prioritized coverage recommendations are available.</div>
            )}
          </div>
        </div>
        <div className="btn-group" style={{ marginTop: 16 }}>
          <button
            className={`btn btn-sm ${workspacePanel === 'coverage' ? 'btn-primary' : ''}`}
            onClick={() => focusWorkspacePanel('coverage', 'efficacy')}
          >
            Focus Drilldown
          </button>
        </div>
      </div>

      <div className="card-grid" style={{ marginBottom: 16 }}>
        <div className="card" style={panelCardStyle('noise')}>
          <div className="card-title" style={{ marginBottom: 10 }}>
            Suppression Noise Signals
          </div>
          <div className="hint" style={{ marginBottom: 12 }}>
            Use live suppression scope, replay hits, and false-positive labels to decide where to
            tune next.
          </div>
          <div className="summary-grid">
            <div className="summary-card">
              <div className="summary-label">Active Suppressions</div>
              <div className="summary-value">{activeSuppressions.length}</div>
              <div className="summary-meta">Currently shaping live alert visibility.</div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Noisy Without Scope</div>
              <div className="summary-value">{unresolvedNoiseCount}</div>
              <div className="summary-meta">
                High-hit rules that still lack a scoped suppression.
              </div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Expiring This Week</div>
              <div className="summary-value">{expiringSuppressions.length}</div>
              <div className="summary-meta">Review before the exception window closes.</div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Rule FP Signals</div>
              <div className="summary-value">{ruleFpSignals.length}</div>
              <div className="summary-meta">
                Pattern-level analyst noise already overlaps the selected rule.
              </div>
            </div>
          </div>
          <div style={{ marginTop: 12 }}>
            {noiseWatchlist.length === 0 ? (
              <div className="hint">
                No replay noise or false-positive signals are available yet.
              </div>
            ) : (
              noiseWatchlist.slice(0, 5).map((item) => (
                <div
                  key={item.rule.id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '10px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div className="row-primary">{item.rule.title || item.rule.id}</div>
                    <div className="row-secondary">
                      {item.hits} replay hit{item.hits === 1 ? '' : 's'} • {item.liveSuppressions}{' '}
                      live suppression
                      {item.liveSuppressions === 1 ? '' : 's'}
                      {item.fpSignal
                        ? ` • ${formatRatio(item.fpSignal.fp_ratio)} FP pattern ${item.fpSignal.pattern}`
                        : ''}
                    </div>
                  </div>
                  <div className="btn-group" style={{ alignItems: 'center' }}>
                    <span
                      className={`badge ${item.unresolvedNoise ? 'badge-err' : item.liveSuppressions > 0 ? 'badge-ok' : 'badge-warn'}`}
                    >
                      {item.unresolvedNoise
                        ? 'Needs scope'
                        : item.liveSuppressions > 0
                          ? 'Scoped'
                          : 'Review'}
                    </span>
                    <button
                      className="btn btn-sm"
                      onClick={() => focusRule(item.rule.id, 'efficacy')}
                    >
                      Focus Rule
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
          <div className="btn-group" style={{ marginTop: 16 }}>
            <button
              className={`btn btn-sm ${workspacePanel === 'noise' ? 'btn-primary' : ''}`}
              onClick={() => focusWorkspacePanel('noise', 'efficacy')}
            >
              Focus Drilldown
            </button>
          </div>
        </div>

        <div className="card" style={panelCardStyle('rollout')}>
          <div className="card-title" style={{ marginBottom: 10 }}>
            Content Pack Rollout Signals
          </div>
          <div className="hint" style={{ marginBottom: 12 }}>
            Track which bundles are ready for analyst use, still missing routing, or need a
            stale-content review.
          </div>
          <div className="summary-grid">
            <div className="summary-card">
              <div className="summary-label">Ready Bundles</div>
              <div className="summary-value">{readyPackCount}</div>
              <div className="summary-meta">
                Target routing, pivots, and hunt linkage are in place.
              </div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Missing Target Group</div>
              <div className="summary-value">{targetlessPackCount}</div>
              <div className="summary-meta">These bundles still need analyst routing.</div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Stale Bundles</div>
              <div className="summary-value">{stalePackCount}</div>
              <div className="summary-meta">Bundles older than 21 days without an update.</div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Tracked Packs</div>
              <div className="summary-value">{packRolloutRows.length}</div>
              <div className="summary-meta">
                Includes saved-search and workflow-routed content bundles.
              </div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Delivery Lanes</div>
              <div className="summary-value">{routedDeliveryLaneCount}</div>
              <div className="summary-meta">
                {contentRolloutHistory.length} recent lifecycle event
                {contentRolloutHistory.length === 1 ? '' : 's'} across assigned analyst groups.
              </div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Historical Events</div>
              <div className="summary-value">{rolloutOverview?.historical_events || 0}</div>
              <div className="summary-meta">
                {rolloutOverview?.rollback_events || 0} rollback event
                {(rolloutOverview?.rollback_events || 0) === 1 ? '' : 's'} • latest{' '}
                {rolloutOverview?.last_rollout_at
                  ? formatRelativeTime(rolloutOverview.last_rollout_at)
                  : 'not recorded'}
              </div>
            </div>
          </div>
          <div style={{ marginTop: 12 }}>
            {packRolloutRows.length === 0 ? (
              <div className="hint">No content pack bundles are defined yet.</div>
            ) : (
              packRolloutRows.slice(0, 5).map((pack) => (
                <div
                  key={pack.id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '10px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div className="row-primary">{pack.name || pack.id}</div>
                    <div className="row-secondary">
                      {pack.linkedRules.length} rule{pack.linkedRules.length === 1 ? '' : 's'} •{' '}
                      {pack.linkedHunts.length} hunt
                      {pack.linkedHunts.length === 1 ? '' : 's'} • target{' '}
                      {pack.target_group || 'unassigned'}
                    </div>
                    <div className="hint" style={{ marginTop: 4 }}>
                      {pack.rollout.detail}
                      {pack.ageDays != null ? ` • updated ${pack.ageDays}d ago` : ''}
                      {pack.rollout_notes ? ` • ${pack.rollout_notes}` : ''}
                    </div>
                  </div>
                  <div className="btn-group" style={{ alignItems: 'center' }}>
                    <span className={`badge ${pack.rollout.tone}`}>{pack.rollout.label}</span>
                    <button className="btn btn-sm" onClick={() => openPackEditor(pack)}>
                      Open Bundle
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 10 }}>
              Lifecycle Distribution
            </div>
            {lifecycleDistributionRows.length === 0 ? (
              <div className="hint">No lifecycle-tracked rules or hunts are available yet.</div>
            ) : (
              lifecycleDistributionRows.map((row) => (
                <div
                  key={row.id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '10px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div className="row-primary">{row.label}</div>
                    <div className="row-secondary">
                      {row.rules} rule{row.rules === 1 ? '' : 's'} • {row.hunts} hunt
                      {row.hunts === 1 ? '' : 's'}
                    </div>
                  </div>
                  <span className={`badge ${row.tone}`}>{row.total}</span>
                </div>
              ))
            )}
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 10 }}>
              Target Group Distribution
            </div>
            {targetGroupDistributionRows.length === 0 ? (
              <div className="hint">
                Assign a target group to packs or hunts to track delivery lanes.
              </div>
            ) : (
              targetGroupDistributionRows.slice(0, 6).map((entry) => (
                <div
                  key={entry.group}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '10px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div className="row-primary">{entry.group}</div>
                    <div className="row-secondary">
                      {entry.packs} pack{entry.packs === 1 ? '' : 's'} • {entry.hunts} hunt
                      {entry.hunts === 1 ? '' : 's'} • {entry.linkedRules} linked rule
                      {entry.linkedRules === 1 ? '' : 's'}
                    </div>
                    {entry.canaryHunts > 0 && (
                      <div className="hint" style={{ marginTop: 4 }}>
                        {entry.canaryHunts} canary hunt{entry.canaryHunts === 1 ? '' : 's'} still
                        staged in this lane.
                      </div>
                    )}
                  </div>
                  <span
                    className={`badge ${entry.group === 'unassigned' ? 'badge-warn' : 'badge-info'}`}
                  >
                    {entry.group === 'unassigned' ? 'Needs routing' : 'Routed'}
                  </span>
                </div>
              ))
            )}
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 10 }}>
              Recent Rollout Activity
            </div>
            {contentRolloutHistory.length === 0 ? (
              <div className="hint">
                Recent content lifecycle activity will appear here once promotions or rollbacks are
                recorded.
              </div>
            ) : (
              contentRolloutHistory.map((event) => (
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
                      {formatRolloutActionLabel(event.action)} • {event.version}
                    </div>
                    <div className="row-secondary">
                      {formatLifecycleLabel(event.rollout_group)} lane •{' '}
                      {formatHumanLabel(event.status)}
                    </div>
                    <div className="hint" style={{ marginTop: 4 }}>
                      {event.notes || 'No operator notes recorded.'}
                    </div>
                  </div>
                  <div className="hint" style={{ textAlign: 'right' }}>
                    {formatRelativeTime(event.recorded_at)}
                    <div>{formatDateTime(event.recorded_at)}</div>
                  </div>
                </div>
              ))
            )}
          </div>
          <div className="btn-group" style={{ marginTop: 16 }}>
            <button
              className={`btn btn-sm ${workspacePanel === 'rollout' ? 'btn-primary' : ''}`}
              onClick={() => focusWorkspacePanel('rollout', 'hunts')}
            >
              Focus Drilldown
            </button>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title" style={{ marginBottom: 10 }}>
          Detection Domains
        </div>
        <div className="summary-grid">
          <div className="summary-card">
            <div className="summary-label">Malware Scanning</div>
            <div className="summary-value">
              {malwareStats?.detections ?? malwareRecent?.length ?? 0}
            </div>
            <div className="summary-meta">Recent detections and signature activity</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Feed Ingestion</div>
            <div className="summary-value">
              {feedStats?.active_feeds ?? feeds?.feeds?.length ?? 0}
            </div>
            <div className="summary-meta">Connected intel and rules feeds</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Quarantine Store</div>
            <div className="summary-value">
              {quarantineStats?.active ?? quarantineItems?.items?.length ?? 0}
            </div>
            <div className="summary-meta">Tracked quarantined artifacts</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Asset Inventory</div>
            <div className="summary-value">
              {fleetInventory?.items?.length ?? hostInventory?.software?.length ?? 0}
            </div>
            <div className="summary-meta">Visible endpoint and host assets</div>
          </div>
        </div>
      </div>

      <ThreatIntelOperations />

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title" style={{ marginBottom: 10 }}>
          Detection Ownership And Review Calendar
        </div>
        <div className="summary-grid">
          <div className="summary-card">
            <div className="summary-label">Overdue Reviews</div>
            <div className="summary-value">{detectionOwnershipCalendar.summary.overdue}</div>
            <div className="summary-meta">Rules that have slipped past their next owner review.</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Due This Week</div>
            <div className="summary-value">{detectionOwnershipCalendar.summary.dueThisWeek}</div>
            <div className="summary-meta">Upcoming reviews that should stay inside the current shift plan.</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Replay Blockers</div>
            <div className="summary-value">{detectionOwnershipCalendar.summary.replayBlockers}</div>
            <div className="summary-meta">Rules needing replay, suppression, or ownership cleanup before promotion.</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Noisy Owners</div>
            <div className="summary-value">{detectionOwnershipCalendar.summary.noisyOwners}</div>
            <div className="summary-meta">Owners currently carrying replay noise or suppression cleanup.</div>
          </div>
        </div>
        <div style={{ marginTop: 12 }}>
          {detectionOwnershipCalendar.rows.length === 0 ? (
            <div className="empty">No rules are available for ownership review yet.</div>
          ) : (
            detectionOwnershipCalendar.rows.slice(0, 5).map((row) => (
              <div
                key={row.id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  gap: 12,
                  padding: '10px 0',
                  borderBottom: '1px solid var(--border)',
                }}
              >
                <div style={{ flex: 1 }}>
                  <div className="row-primary">{row.title}</div>
                  <div className="row-secondary">
                    {row.owner} • {row.lifecycle}
                  </div>
                  <div className="hint" style={{ marginTop: 4 }}>
                    {row.dueAt
                      ? `Next review ${formatRelativeTime(row.dueAt)} • ${row.replay.detail}`
                      : `Review date unavailable • ${row.replay.detail}`}
                  </div>
                  <div className="hint" style={{ marginTop: 4 }}>
                    {row.blockers.length > 0
                      ? `${row.blockers.length} promotion blocker${row.blockers.length === 1 ? '' : 's'} • ${row.nextAction}`
                      : row.nextAction}
                  </div>
                </div>
                <div style={{ minWidth: 240, textAlign: 'right' }}>
                  <div className="chip-row" style={{ justifyContent: 'flex-end', marginBottom: 8 }}>
                    <span className={`badge ${row.reviewTone}`}>{row.reviewLabel}</span>
                    <span className={`badge ${row.replay.tone}`}>{row.replay.label}</span>
                  </div>
                  <div className="btn-group" style={{ justifyContent: 'flex-end' }}>
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        updateSearchState({
                          panel: 'overview',
                          queue: row.reviewQueue,
                          rule: row.id,
                          rulePanel: 'promotion',
                        })
                      }
                    >
                      Review Rule
                    </button>
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        updateSearchState({
                          panel: 'overview',
                          queue: row.reviewQueue,
                          rule: row.id,
                          rulePanel: 'hunts',
                        })
                      }
                    >
                      Open Hunt
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="triage-layout">
        <section className="triage-list">
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Rule Queues
            </div>
            <div className="chip-row" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {SAVED_VIEWS.map((item) => (
                <button
                  key={item.id}
                  className={`filter-chip-button ${queue === item.id ? 'active' : ''}`}
                  onClick={() => {
                    const next = new URLSearchParams(searchParams);
                    next.set('queue', item.id);
                    next.delete('rule');
                    setSearchParams(next, { replace: true });
                  }}
                >
                  {item.label} ({queueCounts[item.id] || 0})
                </button>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="triage-toolbar">
              <div className="triage-toolbar-group">
                <input
                  className="form-input triage-search"
                  value={query}
                  onChange={(event) => {
                    const next = new URLSearchParams(searchParams);
                    if (event.target.value) next.set('q', event.target.value);
                    else next.delete('q');
                    setSearchParams(next, { replace: true });
                  }}
                  placeholder="Search rules, IDs, or descriptions"
                  aria-label="Search rules"
                />
                <select
                  className="form-select"
                  value={ownerFilter}
                  onChange={(event) => {
                    const next = new URLSearchParams(searchParams);
                    if (event.target.value === 'all') next.delete('owner');
                    else next.set('owner', event.target.value);
                    setSearchParams(next, { replace: true });
                  }}
                  aria-label="Filter by owner"
                >
                  {owners.map((owner) => (
                    <option key={owner} value={owner}>
                      {owner === 'all' ? 'All owners' : owner}
                    </option>
                  ))}
                </select>
              </div>
              <div className="triage-toolbar-group">
                <button className="btn btn-sm" onClick={reloadRules}>
                  Refresh
                </button>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={testRule}
                  disabled={!selectedRule}
                >
                  Test Selected
                </button>
              </div>
            </div>

            <div className="sticky-bulk-bar">
              <span className="hint">
                Queue focuses noisy, recently changed, and suppressed detections first.
              </span>
            </div>

            <div className="split-list-table">
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Owner</th>
                    <th>ATT&CK</th>
                    <th>Noise</th>
                    <th>Lifecycle</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.length === 0 ? (
                    <tr>
                      <td colSpan="5">
                        <WorkspaceEmptyState description="No rules match this queue and filter scope." />
                      </td>
                    </tr>
                  ) : (
                    filteredRules.map((rule) => (
                      <tr
                        key={rule.id}
                        className={selectedRule?.id === rule.id ? 'row-active' : ''}
                        onClick={() => {
                          const next = new URLSearchParams(searchParams);
                          next.set('rule', rule.id);
                          setSearchParams(next, { replace: true });
                        }}
                        onMouseEnter={() => {
                          const next = new URLSearchParams(searchParams);
                          next.set('rule', rule.id);
                          setSearchParams(next, { replace: true });
                        }}
                        style={{ cursor: 'pointer' }}
                      >
                        <td>
                          <div className="row-primary">{rule.title || rule.id}</div>
                          <div className="row-secondary">
                            {rule.description || 'No rule narrative available.'}
                          </div>
                        </td>
                        <td>{rule.owner || 'system'}</td>
                        <td>{Array.isArray(rule.attack) ? rule.attack.length : 0} mappings</td>
                        <td>
                          <span
                            className={`badge ${severityTone((rule.last_test_match_count || 0) >= 5 ? 'high' : 'low')}`}
                          >
                            {rule.last_test_match_count || 0} hits
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${lifecycleTone(rule.lifecycle)}`}>
                            {rule.lifecycle || 'draft'}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <aside className="triage-detail">
          <div className="card">
            {!selectedRule ? (
              <WorkspaceEmptyState description="Select a rule to inspect lifecycle, validation, and related suppressions." />
            ) : (
              <>
                <div className="detail-hero">
                  <div>
                    <div className="detail-hero-title">{selectedRule.title || selectedRule.id}</div>
                    <div className="detail-hero-copy">
                      {selectedRule.description ||
                        'This rule needs a clearer analyst-facing summary before rollout.'}
                    </div>
                  </div>
                  <span className={`badge ${lifecycleTone(selectedRule.lifecycle)}`}>
                    {selectedRule.lifecycle || 'draft'}
                  </span>
                </div>

                <div
                  className="chip-row"
                  style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}
                >
                  <span
                    className={`badge ${selectedRule.enabled === false ? 'badge-err' : 'badge-ok'}`}
                  >
                    {selectedRule.enabled === false ? 'Disabled' : 'Enabled'}
                  </span>
                  <span className="badge badge-info">{selectedRule.kind || 'sigma'}</span>
                  <span className="badge badge-info">Owner: {selectedRule.owner || 'system'}</span>
                  <span className={`badge ${severityTone(selectedRule.severity_mapping || 'low')}`}>
                    {selectedRule.severity_mapping || 'severity inherited'}
                  </span>
                </div>

                <div className="btn-group" style={{ marginTop: 16 }}>
                  <button className="btn btn-sm btn-primary" onClick={testRule}>
                    Test
                  </button>
                  <button className="btn btn-sm" onClick={() => openDrawer('tune')}>
                    Tune
                  </button>
                  <button className="btn btn-sm" onClick={() => openDrawer('hunt')}>
                    Hunt
                  </button>
                  <button className="btn btn-sm" onClick={() => openDrawer('suppress')}>
                    Suppress
                  </button>
                  <button className="btn btn-sm" onClick={() => promoteRule('canary')}>
                    Promote
                  </button>
                  <button className="btn btn-sm" onClick={rollbackRule}>
                    Rollback
                  </button>
                  <button className="btn btn-sm btn-danger" onClick={disableRule}>
                    Disable
                  </button>
                </div>

                <div className="summary-grid" style={{ marginTop: 16 }}>
                  <div className="summary-card">
                    <div className="summary-label">Last Test</div>
                    <div className="summary-value">
                      {selectedRule.last_test_at
                        ? formatRelativeTime(selectedRule.last_test_at)
                        : 'Never'}
                    </div>
                    <div className="summary-meta">
                      {selectedRule.last_test_at
                        ? formatDateTime(selectedRule.last_test_at)
                        : 'Run a validation replay before promotion.'}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Next Review</div>
                    <div className="summary-value">
                      {selectedRuleCalendarEntry?.dueAt
                        ? formatRelativeTime(selectedRuleCalendarEntry.dueAt)
                        : 'Unscheduled'}
                    </div>
                    <div className="summary-meta">
                      {selectedRuleCalendarEntry?.dueAt
                        ? `${selectedRuleCalendarEntry.reviewLabel} • ${formatDateTime(selectedRuleCalendarEntry.dueAt)}`
                        : 'Record validation or promotion evidence to schedule the next review.'}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Promotion Blockers</div>
                    <div className="summary-value">
                      {selectedRuleCalendarEntry?.blockers.length || 0}
                    </div>
                    <div className="summary-meta">
                      {selectedRuleCalendarEntry?.blockers?.[0] ||
                        'No immediate replay or ownership blockers are open.'}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Validation Hits</div>
                    <div className="summary-value">{selectedRule.last_test_match_count || 0}</div>
                    <div className="summary-meta">
                      Replay hit count from the most recent rule test.
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Suppressions</div>
                    <div className="summary-value">{suppressionCount[selectedRule.id] || 0}</div>
                    <div className="summary-meta">
                      Active exceptions tied directly to this rule.
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">FP Advisor</div>
                    <div className="summary-value">
                      {suppressionAdvisor ? formatRatio(suppressionAdvisor.fp_ratio) : '—'}
                    </div>
                    <div className="summary-meta">
                      {suppressionAdvisor
                        ? `${suppressionAdvisor.false_positives}/${suppressionAdvisor.total_marked} labels matched “${suppressionAdvisor.pattern}”`
                        : 'No rule-specific false-positive pattern matched yet.'}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Replay Delta</div>
                    <div className="summary-value">
                      {selectedRuleLatestReplay
                        ? `+${selectedRuleLatestReplay.new_match_count || 0} / -${selectedRuleLatestReplay.cleared_match_count || 0}`
                        : 'Untracked'}
                    </div>
                    <div className="summary-meta">
                      {selectedRuleLatestReplay
                        ? `${selectedRuleLatestReplay.match_count || 0} matches • ${selectedRuleLatestReplay.suppressed_count || 0} suppressed`
                        : 'Run repeat validations to track new and cleared replay evidence.'}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Latest Analyst Verdict</div>
                    <div className="summary-value">
                      {formatVerdictLabel(selectedRuleAnalystFeedback?.latest_verdict)}
                    </div>
                    <div className="summary-meta">
                      {selectedRuleAnalystFeedback?.latest_at
                        ? `${selectedRuleAnalystFeedback.latest_analyst || 'Analyst'} • ${formatRelativeTime(selectedRuleAnalystFeedback.latest_at)}`
                        : 'No analyst review history is attached to this rule yet.'}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Content Packs</div>
                    <div className="summary-value">{packNames.length}</div>
                    <div className="summary-meta">
                      {selectedPacks[0]
                        ? `${selectedPacks[0].target_group || 'Unassigned'} • ${packWorkflowIds.length} workflow route${packWorkflowIds.length === 1 ? '' : 's'}`
                        : 'No pack membership recorded.'}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Automation Target</div>
                    <div className="summary-value">
                      {selectedPacks[0]?.target_group || huntDraft.targetGroup || 'Unassigned'}
                    </div>
                    <div className="summary-meta">
                      {selectedPacks[0]?.rollout_notes ||
                        'Assign an IdP-mapped group before broad automation rollout.'}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Pack Searches</div>
                    <div className="summary-value">{packSavedSearches.length}</div>
                    <div className="summary-meta">
                      {packSavedSearches.slice(0, 2).join(' • ') ||
                        'No saved-search bundle attached to this rule yet.'}
                    </div>
                  </div>
                </div>

                <div className="detail-callout" style={{ marginTop: 16 }}>
                  <strong>Route-backed rule panel</strong>
                  <div style={{ marginTop: 6 }}>{activeRulePanel?.description}</div>
                </div>

                <div
                  className="chip-row"
                  style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 16 }}
                >
                  {RULE_DETAIL_PANELS.map((panel) => (
                    <button
                      key={panel.id}
                      className={`filter-chip-button ${rulePanel === panel.id ? 'active' : ''}`}
                      onClick={() => focusRulePanel(panel.id)}
                    >
                      {panel.label}
                    </button>
                  ))}
                </div>

                {rulePanel === 'summary' && (
                  <div
                    className="card"
                    style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Rule Summary Workspace
                    </div>
                    <div className="summary-grid">
                      <div className="summary-card">
                        <div className="summary-label">Pinned Drilldown</div>
                        <div className="summary-value">
                          {activeWorkspacePanel?.label || 'Overview'}
                        </div>
                        <div className="summary-meta">
                          {activeWorkspacePanel?.description ||
                            'Use the workspace focus chips above to reopen this rule in a specific drilldown.'}
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Mapped Techniques</div>
                        <div className="summary-value">
                          {Array.isArray(selectedRule.attack) ? selectedRule.attack.length : 0}
                        </div>
                        <div className="summary-meta">
                          {selectedRuleCoverageGaps.length > 0
                            ? `${selectedRuleCoverageGaps.length} adjacent ATT&CK gap${selectedRuleCoverageGaps.length === 1 ? '' : 's'} still open.`
                            : 'No uncovered tactic-adjacent ATT&CK gaps overlap this rule right now.'}
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Handoff Queue</div>
                        <div className="summary-value">{queue}</div>
                        <div className="summary-meta">
                          {ownerFilter === 'all'
                            ? 'Visible across every owner in the current detection queue.'
                            : `Filtered to ${ownerFilter} ownership for shared triage review.`}
                        </div>
                      </div>
                    </div>

                    <div className="card" style={{ marginTop: 16, padding: 16 }}>
                      <div className="card-title" style={{ marginBottom: 10 }}>
                        Analyst Review History
                      </div>
                      <div className="summary-grid">
                        <div className="summary-card">
                          <div className="summary-label">Latest Replay Delta</div>
                          <div className="summary-value">
                            {selectedRuleLatestReplay
                              ? `+${selectedRuleLatestReplay.new_match_count || 0} / -${selectedRuleLatestReplay.cleared_match_count || 0}`
                              : 'No replays'}
                          </div>
                          <div className="summary-meta">
                            {selectedRuleLatestReplay?.tested_at
                              ? `${formatDateTime(selectedRuleLatestReplay.tested_at)} • ${selectedRuleLatestReplay.summary}`
                              : 'Replay history appears here after the rule is tested more than once.'}
                          </div>
                        </div>
                        <div className="summary-card">
                          <div className="summary-label">Analyst Verdict Mix</div>
                          <div className="summary-value">
                            {selectedRuleAnalystFeedback?.total || 0}
                          </div>
                          <div className="summary-meta">
                            {formatVerdictSummary(selectedRuleAnalystFeedback?.by_verdict)}
                          </div>
                        </div>
                      </div>
                      <div className="grid-2" style={{ marginTop: 12 }}>
                        <div className="card" style={{ padding: 12 }}>
                          <div className="section-title" style={{ marginBottom: 8 }}>
                            Recent Replays
                          </div>
                          {Array.isArray(selectedRuleReviewHistory?.recent_replays) &&
                          selectedRuleReviewHistory.recent_replays.length > 0 ? (
                            selectedRuleReviewHistory.recent_replays.map((replay, index) => (
                              <div
                                key={`${selectedRule?.id || 'rule'}-replay-${index}`}
                                className="list-row"
                              >
                                <div>
                                  <div className="row-primary">
                                    {formatDateTime(replay.tested_at)}
                                  </div>
                                  <div className="row-secondary">
                                    {`${replay.match_count || 0} matches • ${replay.suppressed_count || 0} suppressed • +${replay.new_match_count || 0} / -${replay.cleared_match_count || 0}`}
                                  </div>
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="empty">Recent replay deltas will appear here.</div>
                          )}
                        </div>
                        <div className="card" style={{ padding: 12 }}>
                          <div className="section-title" style={{ marginBottom: 8 }}>
                            Recent Analyst Feedback
                          </div>
                          {Array.isArray(selectedRuleAnalystFeedback?.recent) &&
                          selectedRuleAnalystFeedback.recent.length > 0 ? (
                            selectedRuleAnalystFeedback.recent.map((entry) => (
                              <div key={entry.id} className="list-row">
                                <div>
                                  <div className="row-primary">
                                    {formatVerdictLabel(entry.verdict)}
                                  </div>
                                  <div className="row-secondary">
                                    {`${entry.analyst || 'Analyst'} • ${formatDateTime(entry.created_at)}`}
                                  </div>
                                  {entry.notes ? (
                                    <div className="hint" style={{ marginTop: 4 }}>
                                      {entry.notes}
                                    </div>
                                  ) : null}
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="empty">
                              Analyst review notes will appear here once feedback is recorded.
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {rulePanel === 'efficacy' && (
                  <div
                    className="card"
                    style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Rule Efficacy
                    </div>
                    <div className="hint" style={{ marginBottom: 10 }}>
                      Analyst outcome quality for the currently selected rule.
                    </div>
                    {selectedRuleEfficacy ? (
                      <>
                        <div className="summary-grid">
                          <div className="summary-card">
                            <div className="summary-label">Precision</div>
                            <div className="summary-value">
                              {formatRatio(selectedRuleEfficacy.precision)}
                            </div>
                            <div className="summary-meta">
                              {selectedRuleEfficacy.true_positives || 0} TP •{' '}
                              {selectedRuleEfficacy.false_positives || 0} FP
                            </div>
                          </div>
                          <div className="summary-card">
                            <div className="summary-label">True Positive Rate</div>
                            <div className="summary-value">
                              {formatRatio(selectedRuleEfficacy.tp_rate)}
                            </div>
                            <div className="summary-meta">
                              {selectedRuleEfficacy.total_alerts || 0} tracked alert outcome
                              {selectedRuleEfficacy.total_alerts === 1 ? '' : 's'}
                            </div>
                          </div>
                          <div className="summary-card">
                            <div className="summary-label">False Positive Rate</div>
                            <div className="summary-value">
                              {formatRatio(selectedRuleEfficacy.fp_rate)}
                            </div>
                            <div className="summary-meta">
                              {selectedRuleEfficacy.pending || 0} pending •{' '}
                              {selectedRuleEfficacy.inconclusive || 0} inconclusive
                            </div>
                          </div>
                          <div className="summary-card">
                            <div className="summary-label">Trend</div>
                            <div className="summary-value">
                              {formatTrendLabel(selectedRuleEfficacy.trend)}
                            </div>
                            <div className="summary-meta">
                              Mean triage{' '}
                              {formatMetricNumber(selectedRuleEfficacy.mean_triage_secs)}s
                            </div>
                          </div>
                        </div>
                      </>
                    ) : (
                      <div className="hint">
                        No triage outcomes are recorded for this rule yet. Once analysts label
                        alerts, precision and trend will appear here.
                      </div>
                    )}

                    <div className="card-title" style={{ marginTop: 16, marginBottom: 10 }}>
                      Mapped tactic gaps
                    </div>
                    {Array.isArray(selectedRule.attack) && selectedRule.attack.length > 0 ? (
                      selectedRuleCoverageGaps.length === 0 ? (
                        <div className="hint">
                          No uncovered ATT&CK gaps currently overlap this rule&apos;s mapped
                          tactics.
                        </div>
                      ) : (
                        selectedRuleCoverageGaps.slice(0, 4).map((gap) => (
                          <div
                            key={`${gap.technique_id}-${gap.tactic}`}
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
                                {gap.technique_id} • {gap.technique_name}
                              </div>
                              <div className="row-secondary">
                                {gap.tactic} • {gap.recommendation}
                              </div>
                            </div>
                            <span className={`badge ${priorityTone(gap.priority)}`}>
                              {gap.priority}
                            </span>
                          </div>
                        ))
                      )
                    ) : (
                      <div className="hint">
                        Attach ATT&CK mappings to this rule to surface tactic-adjacent gaps here.
                      </div>
                    )}
                  </div>
                )}

                {rulePanel === 'summary' && (
                  <div className="detail-callout" style={{ marginTop: 16 }}>
                    <strong>MITRE impact</strong>
                    <div style={{ marginTop: 6 }}>
                      {Array.isArray(selectedRule.attack) && selectedRule.attack.length > 0
                        ? selectedRule.attack
                            .map(
                              (attack) =>
                                `${attack.technique_name || attack.technique_id} (${attack.tactic || 'mapped tactic'})`,
                            )
                            .join(' • ')
                        : 'No ATT&CK mapping is attached yet. Add one before broad promotion so analysts understand coverage intent.'}
                    </div>
                  </div>
                )}

                {rulePanel === 'promotion' && (
                  <div
                    className="card"
                    style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Promotion checklist
                    </div>
                    <div className="hint" style={{ marginBottom: 10 }}>
                      Use this preflight before you move the rule into canary or active rollout.
                    </div>
                    {promotionChecklist.map((item) => (
                      <div
                        key={item.id}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'flex-start',
                          gap: 12,
                          padding: '10px 0',
                          borderBottom: '1px solid var(--border)',
                        }}
                      >
                        <div style={{ flex: 1 }}>
                          <div className="row-primary">{item.label}</div>
                          <div className="row-secondary">{item.detail}</div>
                        </div>
                        <span className={`badge ${item.done ? 'badge-ok' : 'badge-warn'}`}>
                          {item.done ? 'Ready' : 'Needs work'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {rulePanel === 'promotion' && (
                  <div
                    className="card"
                    style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Validation and Context
                    </div>
                    {testResult ? (
                      <div className="summary-grid">
                        <div className="summary-card">
                          <div className="summary-label">Tested At</div>
                          <div className="summary-value">
                            {formatRelativeTime(testResult.tested_at)}
                          </div>
                          <div className="summary-meta">{formatDateTime(testResult.tested_at)}</div>
                        </div>
                        <div className="summary-card">
                          <div className="summary-label">Visible Matches</div>
                          <div className="summary-value">{testResult.match_count}</div>
                          <div className="summary-meta">{testResult.summary}</div>
                        </div>
                        <div className="summary-card">
                          <div className="summary-label">Suppressed Matches</div>
                          <div className="summary-value">{testResult.suppressed_count}</div>
                          <div className="summary-meta">
                            Hidden by active suppressions or exceptions.
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="hint">
                        Run a rule test to preview impact before tuning or promotion.
                      </div>
                    )}
                  </div>
                )}

                {rulePanel === 'promotion' && (
                  <div
                    className="card"
                    style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Canary Rollout Automation
                    </div>
                    <div className="hint" style={{ marginBottom: 12 }}>
                      Run the stored efficacy gate to promote healthy canary rules and roll back
                      degrading ones without leaving the detection workspace.
                    </div>
                    <div className="btn-group" style={{ marginBottom: 12 }}>
                      <button
                        className="btn btn-sm"
                        onClick={runCanaryPromotion}
                        disabled={runningCanaryPromotion}
                      >
                        {runningCanaryPromotion ? 'Running…' : 'Run Canary Auto-Promotion'}
                      </button>
                    </div>
                    {canaryPromotionResults.length === 0 ? (
                      <div className="hint">
                        No canary automation results captured in this session yet.
                      </div>
                    ) : (
                      canaryPromotionResults.slice(0, 6).map((result) => (
                        <div
                          key={`${result.rule_id || result.rule_name}-${result.action}`}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'flex-start',
                            gap: 12,
                            padding: '10px 0',
                            borderBottom: '1px solid var(--border)',
                          }}
                        >
                          <div style={{ flex: 1 }}>
                            <div className="row-primary">
                              {result.rule_name || result.rule_id || 'Unnamed rule'}
                            </div>
                            <div className="row-secondary">
                              {result.reason || 'No reason recorded.'}
                            </div>
                          </div>
                          <span className={`badge ${canaryActionTone(result.action)}`}>
                            {canaryActionLabel(result.action)}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {rulePanel === 'promotion' && (
                  <div
                    className="card"
                    style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Lifecycle Evidence
                    </div>
                    <div className="summary-grid" style={{ marginBottom: 12 }}>
                      <div className="summary-card">
                        <div className="summary-label">Current Lifecycle</div>
                        <div className="summary-value">
                          {formatLifecycleLabel(selectedRule.lifecycle)}
                        </div>
                        <div className="summary-meta">Version {selectedRule.version || 1}</div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Last Promotion</div>
                        <div className="summary-value">
                          {selectedRule.last_promotion_at
                            ? formatRelativeTime(selectedRule.last_promotion_at)
                            : 'Not recorded'}
                        </div>
                        <div className="summary-meta">
                          {selectedRule.last_promotion_at
                            ? formatDateTime(selectedRule.last_promotion_at)
                            : 'Promotion evidence appears after the first lifecycle change.'}
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Routed Bundles</div>
                        <div className="summary-value">{selectedPacks.length}</div>
                        <div className="summary-meta">
                          {selectedRuleLinkedHunts.length} linked hunt
                          {selectedRuleLinkedHunts.length === 1 ? '' : 's'} share this delivery
                          lane.
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Analytics Events</div>
                        <div className="summary-value">{selectedRuleRolloutHistory.length}</div>
                        <div className="summary-meta">
                          Recorded content rollout events tied to this rule id.
                        </div>
                      </div>
                    </div>
                    {selectedRuleLifecycleHistory.length === 0 ? (
                      <div className="hint">
                        Lifecycle transitions will appear here once the rule moves through promotion
                        or rollback.
                      </div>
                    ) : (
                      selectedRuleLifecycleHistory.map((change, index) => (
                        <div
                          key={`${change.changed_at}-${index}`}
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
                              {formatLifecycleLabel(change.from)} {'->'}{' '}
                              {formatLifecycleLabel(change.to)}
                            </div>
                            <div className="row-secondary">
                              {change.reason || 'No operator reason recorded.'} •{' '}
                              {change.changed_by || 'system'}
                            </div>
                          </div>
                          <div className="hint" style={{ textAlign: 'right' }}>
                            {formatRelativeTime(change.changed_at)}
                            <div>{formatDateTime(change.changed_at)}</div>
                          </div>
                        </div>
                      ))
                    )}
                    {selectedRuleRolloutHistory.length > 0 && (
                      <div style={{ marginTop: 12 }}>
                        <div className="card-title" style={{ marginBottom: 8 }}>
                          Recorded rollout analytics
                        </div>
                        {selectedRuleRolloutHistory.map((event) => (
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
                                {formatRolloutActionLabel(event.action)}
                              </div>
                              <div className="row-secondary">
                                {formatLifecycleLabel(event.rollout_group)} lane •{' '}
                                {formatHumanLabel(event.status)}
                              </div>
                              <div className="hint" style={{ marginTop: 4 }}>
                                {event.notes || 'No operator notes recorded.'}
                              </div>
                            </div>
                            <div className="hint" style={{ textAlign: 'right' }}>
                              {formatRelativeTime(event.recorded_at)}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {rulePanel === 'efficacy' && (
                  <div
                    className="card"
                    style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      False-Positive Signals
                    </div>
                    <div className="hint" style={{ marginBottom: 10 }}>
                      {ruleFpSignals.length > 0
                        ? 'These patterns overlap the selected rule and can be turned into scoped suppressions or safer weighting changes.'
                        : 'No direct false-positive pattern matched this rule yet. Showing the strongest global analyst feedback patterns instead.'}
                    </div>
                    {fpPreview.length === 0 ? (
                      <div className="hint">
                        False-positive feedback will appear here once analysts label alert outcomes.
                      </div>
                    ) : (
                      fpPreview.map((entry) => (
                        <div
                          key={entry.pattern}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'flex-start',
                            gap: 12,
                            padding: '10px 0',
                            borderBottom: '1px solid var(--border)',
                          }}
                        >
                          <div style={{ flex: 1 }}>
                            <div className="row-primary">{entry.pattern}</div>
                            <div className="row-secondary">
                              {entry.false_positives}/{entry.total_marked} analyst labels marked
                              false positive
                              {entry.suppression_weight < 1
                                ? ` • suggested weight ${entry.suppression_weight.toFixed(2)}`
                                : ' • weighting stays unchanged until more samples accumulate'}
                            </div>
                          </div>
                          <div className="btn-group" style={{ alignItems: 'center' }}>
                            <span
                              className={`badge ${entry.fp_ratio >= 0.7 ? 'badge-err' : entry.fp_ratio >= 0.4 ? 'badge-warn' : 'badge-info'}`}
                            >
                              {formatRatio(entry.fp_ratio)} FP
                            </span>
                            <button
                              className="btn btn-sm"
                              onClick={() => prefillSuppressionFromSignal(entry)}
                            >
                              Prefill suppression
                            </button>
                            <button
                              className="btn btn-sm"
                              onClick={() => applySuggestedWeight(entry)}
                              disabled={entry.suppression_weight >= 0.999}
                            >
                              Use weight
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {rulePanel === 'hunts' && (
                  <div
                    className="card"
                    style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Hunts and Investigations
                    </div>
                    <div className="summary-grid">
                      <div className="summary-card">
                        <div className="summary-label">Saved Hunts</div>
                        <div className="summary-value">{relatedHunts.length}</div>
                        <div className="summary-meta">
                          {relatedHunts[0]?.name || 'No hunt references found for this rule.'}
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Suggested Workflows</div>
                        <div className="summary-value">{investigationSuggestions.length}</div>
                        <div className="summary-meta">
                          {investigationSuggestions[0]?.name ||
                            'No workflow suggestion matched this rule context.'}
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Promotion State</div>
                        <div className="summary-value">
                          {selectedRule.last_promotion_at
                            ? formatRelativeTime(selectedRule.last_promotion_at)
                            : 'Pending'}
                        </div>
                        <div className="summary-meta">
                          {selectedRule.last_promotion_at
                            ? formatDateTime(selectedRule.last_promotion_at)
                            : 'No promotion event recorded yet.'}
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Pack Workflows</div>
                        <div className="summary-value">{packWorkflowIds.length}</div>
                        <div className="summary-meta">
                          {packWorkflowIds[0] || 'No workflow routes packaged yet.'}
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Target Group</div>
                        <div className="summary-value">
                          {selectedPacks[0]?.target_group || huntDraft.targetGroup || 'Unassigned'}
                        </div>
                        <div className="summary-meta">
                          {packSavedSearches.length} search template
                          {packSavedSearches.length === 1 ? '' : 's'} bundled for this rule family
                        </div>
                      </div>
                    </div>

                    <div style={{ marginTop: 12 }}>
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          gap: 12,
                          marginBottom: 8,
                        }}
                      >
                        <div className="row-primary">Pack automation bundles</div>
                        <button
                          className="btn btn-sm"
                          onClick={() => openPackEditor(selectedPacks[0] || null)}
                          disabled={!selectedRule}
                        >
                          {selectedPacks.length === 0 ? 'Create Bundle' : 'Edit Primary Bundle'}
                        </button>
                      </div>
                      {selectedPacks.length === 0 ? (
                        <div className="hint">
                          This rule is not attached to a content pack bundle yet. Create one to
                          manage saved searches, workflow routes, and target-group rollout notes
                          from this workspace.
                        </div>
                      ) : (
                        selectedPacks.slice(0, 2).map((pack) => (
                          <div
                            key={pack.id}
                            style={{
                              padding: '10px 0',
                              borderBottom: '1px solid var(--border)',
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
                              <div style={{ flex: 1 }}>
                                <div className="row-primary">{pack.name}</div>
                                <div className="row-secondary">
                                  {(Array.isArray(pack.saved_searches) ? pack.saved_searches : [])
                                    .slice(0, 3)
                                    .join(' • ') || 'No saved-search bundle attached.'}
                                </div>
                                <div className="hint" style={{ marginTop: 4 }}>
                                  {(Array.isArray(pack.recommended_workflows)
                                    ? pack.recommended_workflows
                                    : []
                                  ).join(', ') || 'No workflow routes'}{' '}
                                  • Target {pack.target_group || 'unassigned'}
                                </div>
                                {pack.rollout_notes && (
                                  <div className="hint" style={{ marginTop: 4 }}>
                                    {pack.rollout_notes}
                                  </div>
                                )}
                              </div>
                              <button className="btn btn-sm" onClick={() => openPackEditor(pack)}>
                                Edit
                              </button>
                            </div>
                          </div>
                        ))
                      )}
                    </div>

                    <div style={{ marginTop: 16 }}>
                      <div className="row-primary" style={{ marginBottom: 8 }}>
                        Rule-aligned saved hunts
                      </div>
                      {relatedHunts.length === 0 ? (
                        <div className="hint">
                          No saved hunt references were found. Open the hunt drawer to save one from
                          this rule context.
                        </div>
                      ) : (
                        relatedHunts.slice(0, 3).map((hunt) => (
                          <div
                            key={hunt.id || hunt.name}
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              gap: 12,
                              padding: '10px 0',
                              borderBottom: '1px solid var(--border)',
                            }}
                          >
                            <div style={{ flex: 1 }}>
                              <div className="row-primary">{hunt.name || hunt.id}</div>
                              <div className="row-secondary">
                                {hunt.query?.text || JSON.stringify(hunt.query || {})}
                              </div>
                              <div className="hint" style={{ marginTop: 4 }}>
                                {(hunt.lifecycle || 'draft').replace(/_/g, ' ')} •{' '}
                                {hunt.canary_percentage || 100}% rollout •{' '}
                                {hunt.target_group || 'unassigned target'}
                                {hunt.pack_id ? ` • ${hunt.pack_id}` : ''}
                              </div>
                              <div className="hint" style={{ marginTop: 4 }}>
                                {(hunt.expected_outcome || 'explore').toUpperCase()} •{' '}
                                {hunt.hypothesis || 'No explicit hypothesis documented.'}
                              </div>
                              <div className="hint" style={{ marginTop: 4 }}>
                                {hunt.latest_run?.started_at
                                  ? `Last run ${formatRelativeTime(hunt.latest_run.started_at)} • ${hunt.latest_run.match_count || 0} matches`
                                  : 'No saved-hunt run recorded yet.'}
                              </div>
                              <div className="hint" style={{ marginTop: 4 }}>
                                Yield {(Number(hunt.latest_run?.yield_rate || 0) * 100).toFixed(0)}%
                                {hunt.latest_run?.suppressed_count != null
                                  ? ` • ${hunt.latest_run.suppressed_count} suppressed`
                                  : ''}
                                {hunt.latest_run?.case_id
                                  ? ` • linked case #${hunt.latest_run.case_id}`
                                  : ''}
                              </div>
                            </div>
                            <div className="btn-group" style={{ alignItems: 'center' }}>
                              <button
                                className="btn btn-sm"
                                onClick={() => loadSavedHuntIntoDraft(hunt)}
                              >
                                Open
                              </button>
                              <button
                                className="btn btn-sm btn-primary"
                                onClick={() => runSavedHuntNow(hunt.id)}
                                disabled={runningSavedHuntId === hunt.id}
                              >
                                {runningSavedHuntId === hunt.id ? 'Running…' : 'Run'}
                              </button>
                              <button
                                className="btn btn-sm"
                                onClick={() => escalateHuntRun(hunt.id, hunt.latest_run?.id)}
                                disabled={
                                  !hunt.latest_run?.id || escalatingRunId === hunt.latest_run?.id
                                }
                              >
                                {escalatingRunId === hunt.latest_run?.id
                                  ? 'Escalating…'
                                  : 'Escalate to Case'}
                              </button>
                            </div>
                          </div>
                        ))
                      )}
                    </div>

                    <div style={{ marginTop: 16 }}>
                      <div className="row-primary" style={{ marginBottom: 8 }}>
                        Suggested investigations
                      </div>
                      {suggestingInvestigations ? (
                        <div className="hint">
                          Scoring workflow suggestions from the selected rule context…
                        </div>
                      ) : investigationSuggestions.length === 0 ? (
                        <div className="hint">
                          No builtin workflow matched the current rule metadata. You can still pivot
                          into hunts from this drawer.
                        </div>
                      ) : (
                        investigationSuggestions.slice(0, 3).map((workflow) => (
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
                              <div className="row-primary">{workflow.name}</div>
                              <div className="row-secondary">{workflow.description}</div>
                              <div className="hint" style={{ marginTop: 4 }}>
                                {(workflow.mitre_techniques || []).join(', ') ||
                                  'No ATT&CK mapping'}{' '}
                                • {(workflow.steps || []).length} steps •{' '}
                                {workflow.estimated_minutes || '—'}m
                              </div>
                            </div>
                            <div className="btn-group" style={{ alignItems: 'center' }}>
                              <span
                                className={`badge ${severityTone(String(workflow.severity || 'medium').toLowerCase())}`}
                              >
                                {workflow.severity || 'medium'}
                              </span>
                              <button
                                className="btn btn-sm btn-primary"
                                onClick={() => startInvestigationFromWorkflow(workflow)}
                                disabled={startingInvestigationId === workflow.id}
                              >
                                {startingInvestigationId === workflow.id ? 'Starting…' : 'Start'}
                              </button>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}

                <JsonDetails data={selectedRule} label="Rule metadata and raw query" />
                {testResult && <JsonDetails data={testResult} label="Rule test result JSON" />}
              </>
            )}
          </div>
        </aside>
      </div>

      <SideDrawer
        open={activeDrawerMode === 'tune'}
        title={selectedRule ? `Tune ${selectedRule.title || selectedRule.id}` : 'Tune rule'}
        subtitle="Move weighting changes into a side panel so validation and save actions are harder to trigger accidentally."
        onClose={closeDrawer}
        actions={
          <button className="btn btn-sm btn-primary" onClick={saveWeight}>
            Save Weight
          </button>
        }
      >
        {renderDrawerDraftNotice(
          'tune',
          'Save the new weight or discard this tuning draft before leaving the drawer.',
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="rule-weight">
            Detection Weight
          </label>
          <input
            id="rule-weight"
            className="form-input"
            type="number"
            min="0.05"
            max="5"
            step="0.05"
            value={weightInput}
            onChange={(event) => setWeightInput(event.target.value)}
          />
          <div className="hint">
            Preview the likely blast radius using the latest test match count before committing.
          </div>
        </div>
        <SummaryGrid
          data={{
            current_profile: profile?.profile,
            last_test_match_count: selectedRule?.last_test_match_count || 0,
            live_suppressions: suppressionCount[selectedRule?.id] || 0,
            current_weight: Number.isFinite(currentWeight) ? currentWeight.toFixed(2) : '0.50',
            suggested_weight: suppressionAdvisor
              ? Math.max(
                  0.05,
                  Math.min(5, currentWeight * suppressionAdvisor.suppression_weight),
                ).toFixed(2)
              : '—',
            recommendation:
              (selectedRule?.last_test_match_count || 0) >= 5
                ? 'Reduce noise before promotion'
                : 'Ready for canary validation',
          }}
          limit={4}
        />
      </SideDrawer>

      <SideDrawer
        open={drawerMode === 'suppress'}
        title={selectedRule ? `Suppress ${selectedRule.title || selectedRule.id}` : 'Suppress rule'}
        subtitle="Capture intent and scope explicitly so exceptions remain understandable later."
        onClose={closeDrawer}
        actions={
          <button className="btn btn-sm btn-primary" onClick={createSuppression}>
            Save Suppression
          </button>
        }
      >
        {renderDrawerDraftNotice(
          'suppress',
          'This suppression draft has changed. Save it or discard it before closing the drawer.',
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="suppression-name">
            Name
          </label>
          <input
            id="suppression-name"
            className="form-input"
            value={suppressionForm.name}
            onChange={(event) =>
              setSuppressionForm((form) => ({ ...form, name: event.target.value }))
            }
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="suppression-justification">
            Justification
          </label>
          <textarea
            id="suppression-justification"
            className="form-textarea"
            value={suppressionForm.justification}
            onChange={(event) =>
              setSuppressionForm((form) => ({ ...form, justification: event.target.value }))
            }
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="suppression-text">
            Match Text Filter
          </label>
          <input
            id="suppression-text"
            className="form-input"
            value={suppressionForm.text}
            onChange={(event) =>
              setSuppressionForm((form) => ({ ...form, text: event.target.value }))
            }
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="suppression-severity">
            Severity
          </label>
          <input
            id="suppression-severity"
            className="form-input"
            value={suppressionForm.severity}
            onChange={(event) =>
              setSuppressionForm((form) => ({ ...form, severity: event.target.value }))
            }
          />
        </div>
      </SideDrawer>

      <SideDrawer
        open={drawerMode === 'pack'}
        title={
          packDraft.id
            ? `Edit ${packDraft.name || 'Content Pack Bundle'}`
            : 'Create Content Pack Bundle'
        }
        subtitle="Manage saved-search bundles, workflow routes, and target-group rollout notes without leaving the detection workspace."
        onClose={closeDrawer}
        actions={
          <button className="btn btn-sm btn-primary" onClick={savePackDraft} disabled={packSaving}>
            {packSaving ? 'Saving…' : 'Save Bundle'}
          </button>
        }
      >
        {renderDrawerDraftNotice(
          'pack',
          'Bundle routing, saved searches, or rollout notes changed and have not been saved yet.',
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="pack-name">
            Pack Name
          </label>
          <input
            id="pack-name"
            className="form-input"
            value={packDraft.name}
            onChange={(event) => setPackDraft((draft) => ({ ...draft, name: event.target.value }))}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="pack-description">
            Description
          </label>
          <textarea
            id="pack-description"
            className="form-textarea"
            rows="3"
            value={packDraft.description}
            onChange={(event) =>
              setPackDraft((draft) => ({ ...draft, description: event.target.value }))
            }
          />
        </div>
        <div className="summary-grid" style={{ marginBottom: 16 }}>
          <div className="form-group">
            <label className="form-label" htmlFor="pack-target-group">
              Target Group
            </label>
            <input
              id="pack-target-group"
              className="form-input"
              value={packDraft.targetGroup}
              onChange={(event) =>
                setPackDraft((draft) => ({ ...draft, targetGroup: event.target.value }))
              }
              placeholder="soc-analysts"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="pack-enabled">
              Bundle State
            </label>
            <label
              htmlFor="pack-enabled"
              style={{ display: 'flex', alignItems: 'center', gap: 8, minHeight: 38 }}
            >
              <input
                id="pack-enabled"
                type="checkbox"
                checked={packDraft.enabled}
                onChange={(event) =>
                  setPackDraft((draft) => ({ ...draft, enabled: event.target.checked }))
                }
              />
              <span>{packDraft.enabled ? 'Enabled for packaging' : 'Disabled bundle'}</span>
            </label>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="pack-searches">
            Saved Searches
          </label>
          <textarea
            id="pack-searches"
            className="form-textarea"
            rows="5"
            value={packDraft.savedSearchesText}
            onChange={(event) =>
              setPackDraft((draft) => ({ ...draft, savedSearchesText: event.target.value }))
            }
            placeholder={'failed logins by user\ngeo anomalies by src_ip'}
          />
          <div className="hint">
            Use one saved-search template per line or separate values with commas.
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="pack-workflows">
            Workflow Routes
          </label>
          <textarea
            id="pack-workflows"
            className="form-textarea"
            rows="4"
            value={packDraft.recommendedWorkflowsText}
            onChange={(event) =>
              setPackDraft((draft) => ({
                ...draft,
                recommendedWorkflowsText: event.target.value,
              }))
            }
            placeholder={'credential-storm\nidentity-abuse'}
          />
          <div className="hint">
            These workflow ids are attached to new hunts and rule context for this bundle.
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="pack-rollout-notes">
            Rollout Notes
          </label>
          <textarea
            id="pack-rollout-notes"
            className="form-textarea"
            rows="4"
            value={packDraft.rolloutNotes}
            onChange={(event) =>
              setPackDraft((draft) => ({ ...draft, rolloutNotes: event.target.value }))
            }
            placeholder="Map identity content to analysts before broad rollout."
          />
        </div>
        <div className="detail-callout" style={{ marginBottom: 16 }}>
          <strong>Bundle coverage</strong>
          <div style={{ marginTop: 6 }}>
            {packDraft.ruleIds.length} rule{packDraft.ruleIds.length === 1 ? '' : 's'} attached •{' '}
            {textToBundleList(packDraft.savedSearchesText).length} saved search
            {textToBundleList(packDraft.savedSearchesText).length === 1 ? '' : 'es'} •{' '}
            {textToBundleList(packDraft.recommendedWorkflowsText).length} workflow route
            {textToBundleList(packDraft.recommendedWorkflowsText).length === 1 ? '' : 's'}
          </div>
        </div>
      </SideDrawer>

      <SideDrawer
        open={drawerMode === 'hunt'}
        title={selectedRule ? `Hunt ${selectedRule.title || selectedRule.id}` : 'Threat Hunt'}
        subtitle="Run an ad-hoc hunt, save it for reuse, and pivot into an investigation workflow from the same rule context."
        onClose={closeDrawer}
        actions={
          <div className="btn-group">
            <button className="btn btn-sm" onClick={saveHuntDraft} disabled={huntSaving}>
              {huntSaving ? 'Saving…' : 'Save Hunt'}
            </button>
            <button
              className="btn btn-sm btn-primary"
              onClick={() => runLiveHunt()}
              disabled={huntRunning}
            >
              {huntRunning ? 'Running…' : 'Run Hunt'}
            </button>
          </div>
        }
      >
        {renderDrawerDraftNotice(
          'hunt',
          'This hunt draft has changed. Save it for reuse or discard it explicitly before leaving.',
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="hunt-name">
            Hunt Name
          </label>
          <input
            id="hunt-name"
            className="form-input"
            value={huntDraft.name}
            onChange={(event) => setHuntDraft((draft) => ({ ...draft, name: event.target.value }))}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="hunt-query">
            Query
          </label>
          <textarea
            id="hunt-query"
            className="form-textarea"
            rows="5"
            value={huntDraft.query}
            onChange={(event) => setHuntDraft((draft) => ({ ...draft, query: event.target.value }))}
          />
          <div className="hint">
            Use the live hunt DSL for pivots like `severity:high`, `process_name:mimikatz | count by
            device_id`, or `src_ip:10.* | top 5 dst_ip`.
          </div>
        </div>
        <div className="detail-callout" style={{ marginBottom: 16 }}>
          <strong>Query starters</strong>
          <div style={{ marginTop: 6 }}>
            Start with the current rule context, then switch into host or source pivots before you
            save the hunt.
          </div>
          <div style={{ marginTop: 10, display: 'grid', gap: 10 }}>
            {huntQuickStarts.map((starter) => (
              <div
                key={starter.id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  gap: 12,
                  padding: '10px 0',
                  borderBottom: '1px solid var(--border)',
                }}
              >
                <div style={{ flex: 1 }}>
                  <div className="row-primary">{starter.label}</div>
                  <div
                    style={{
                      marginTop: 4,
                      fontFamily: 'var(--font-mono)',
                      fontSize: 12,
                      color: 'var(--text)',
                    }}
                  >
                    {starter.query}
                  </div>
                  <div className="hint" style={{ marginTop: 4 }}>
                    {starter.description}
                  </div>
                </div>
                <div className="btn-group" style={{ alignItems: 'center' }}>
                  <button
                    className="btn btn-sm"
                    onClick={() => setHuntDraft((draft) => ({ ...draft, query: starter.query }))}
                  >
                    Use
                  </button>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => {
                      setHuntDraft((draft) => ({ ...draft, query: starter.query }));
                      runLiveHunt(starter.query);
                    }}
                    disabled={huntRunning}
                  >
                    {huntRunning ? 'Running…' : 'Run'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="summary-grid" style={{ marginBottom: 16 }}>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-hypothesis">
              Hypothesis
            </label>
            <input
              id="hunt-hypothesis"
              className="form-input"
              value={huntDraft.hypothesis}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, hypothesis: event.target.value }))
              }
              placeholder="What are we trying to validate?"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-expected-outcome">
              Expected Outcome
            </label>
            <select
              id="hunt-expected-outcome"
              className="form-select"
              value={huntDraft.expectedOutcome}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, expectedOutcome: event.target.value }))
              }
            >
              {['confirm', 'refute', 'explore'].map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-severity">
              Severity
            </label>
            <select
              id="hunt-severity"
              className="form-select"
              value={huntDraft.severity}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, severity: event.target.value }))
              }
            >
              {['critical', 'high', 'medium', 'low'].map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-level">
              Search Level
            </label>
            <input
              id="hunt-level"
              className="form-input"
              value={huntDraft.level}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, level: event.target.value }))
              }
              placeholder="critical / high / medium"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-limit">
              Limit
            </label>
            <input
              id="hunt-limit"
              className="form-input"
              type="number"
              min="1"
              step="1"
              value={huntDraft.limit}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, limit: event.target.value }))
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-threshold">
              Threshold
            </label>
            <input
              id="hunt-threshold"
              className="form-input"
              type="number"
              min="1"
              step="1"
              value={huntDraft.threshold}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, threshold: event.target.value }))
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-window">
              Suppression Window Secs
            </label>
            <input
              id="hunt-window"
              className="form-input"
              type="number"
              min="0"
              step="60"
              value={huntDraft.suppressionWindowSecs}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, suppressionWindowSecs: event.target.value }))
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-schedule">
              Schedule Interval Secs
            </label>
            <input
              id="hunt-schedule"
              className="form-input"
              type="number"
              min="0"
              step="60"
              value={huntDraft.scheduleIntervalSecs}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, scheduleIntervalSecs: event.target.value }))
              }
              placeholder="Optional"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-schedule-cron">
              Schedule (Cron)
            </label>
            <input
              id="hunt-schedule-cron"
              className="form-input"
              value={huntDraft.scheduleCron}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, scheduleCron: event.target.value }))
              }
              placeholder="0 8 * * *"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-time-from">
              Retro Window From
            </label>
            <input
              id="hunt-time-from"
              className="form-input"
              type="datetime-local"
              value={huntDraft.timeFrom}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, timeFrom: event.target.value }))
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-time-to">
              Retro Window To
            </label>
            <input
              id="hunt-time-to"
              className="form-input"
              type="datetime-local"
              value={huntDraft.timeTo}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, timeTo: event.target.value }))
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-lifecycle">
              Promotion Lifecycle
            </label>
            <select
              id="hunt-lifecycle"
              className="form-select"
              value={huntDraft.lifecycle}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, lifecycle: event.target.value }))
              }
            >
              {['draft', 'test', 'canary', 'active'].map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-canary">
              Canary Percentage
            </label>
            <input
              id="hunt-canary"
              className="form-input"
              type="number"
              min="1"
              max="100"
              step="1"
              value={huntDraft.canaryPercentage}
              disabled={huntDraft.lifecycle !== 'canary'}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, canaryPercentage: event.target.value }))
              }
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-pack">
              Content Pack
            </label>
            <select
              id="hunt-pack"
              className="form-select"
              value={huntDraft.packId}
              onChange={(event) => {
                const nextPackId = event.target.value;
                const nextPack = packs.find((pack) => pack.id === nextPackId);
                setHuntDraft((draft) => ({
                  ...draft,
                  packId: nextPackId,
                  targetGroup: nextPack?.target_group || draft.targetGroup,
                  recommendedWorkflows: Array.isArray(nextPack?.recommended_workflows)
                    ? nextPack.recommended_workflows
                    : draft.recommendedWorkflows,
                }));
              }}
            >
              <option value="">No pack</option>
              {packs.map((pack) => (
                <option key={pack.id} value={pack.id}>
                  {pack.name}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-target-group">
              Target Group
            </label>
            <input
              id="hunt-target-group"
              className="form-input"
              value={huntDraft.targetGroup}
              onChange={(event) =>
                setHuntDraft((draft) => ({ ...draft, targetGroup: event.target.value }))
              }
              placeholder="soc-analysts"
            />
          </div>
        </div>

        <div className="detail-callout" style={{ marginBottom: 16 }}>
          <strong>Investigation pivots</strong>
          <div style={{ marginTop: 6 }}>
            {investigationSuggestions.length === 0
              ? 'No workflow suggestion is ready for this rule yet. Start with a hunt and pivot from the resulting matches.'
              : investigationSuggestions
                  .slice(0, 2)
                  .map((workflow) => workflow.name)
                  .join(' • ')}
          </div>
        </div>

        <div className="detail-callout" style={{ marginBottom: 16 }}>
          <strong>Content bundle</strong>
          <div style={{ marginTop: 6 }}>
            {selectedPacks[0]
              ? `${selectedPacks[0].name} • ${(selectedPacks[0].recommended_workflows || []).join(', ') || 'no workflow routes'} • ${selectedPacks[0].target_group || 'unassigned target'}`
              : 'This hunt is not attached to a content pack yet. Choose a pack to inherit saved-search and workflow routing.'}
          </div>
        </div>

        <div className="card" style={{ padding: 16, background: 'var(--bg)' }}>
          <div className="card-title" style={{ marginBottom: 10 }}>
            Latest Hunt Result
          </div>
          <div className="summary-grid">
            <div className="summary-card">
              <div className="summary-label">Result Mode</div>
              <div className="summary-value">{huntSummary.mode}</div>
              <div className="summary-meta">{huntSummary.label}</div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Count</div>
              <div className="summary-value">{huntSummary.count}</div>
              <div className="summary-meta">
                Matches, rows, or buckets returned by the most recent run.
              </div>
            </div>
          </div>
          <div className="btn-group" style={{ marginTop: 12, flexWrap: 'wrap' }}>
            <button
              className="btn btn-sm btn-primary"
              disabled={!huntResult || promotingHuntResult}
              onClick={promoteCurrentHuntToCase}
            >
              {!huntResult
                ? 'Promote to Case'
                : linkedHuntCaseId
                  ? 'Open Linked Case'
                  : promotingHuntResult
                    ? 'Promoting…'
                    : 'Promote to Case'}
            </button>
            {linkedHuntCaseId && (
              <button className="btn btn-sm" onClick={openHuntCase}>
                Open Case
              </button>
            )}
            <button className="btn btn-sm" disabled={!huntResult} onClick={openHuntResponse}>
              Open Response
            </button>
          </div>
          {!huntResult ? (
            <div className="hint" style={{ marginTop: 10 }}>
              No hunt has been run from this drawer yet.
            </div>
          ) : (
            <div style={{ marginTop: 10 }}>
              <JsonDetails data={huntResult} label="Hunt response" />
            </div>
          )}
        </div>
      </SideDrawer>

      {confirmUI}
    </div>
  );
}

import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid, SideDrawer } from './operator.jsx';
import { formatDateTime, formatRelativeTime } from './operatorUtils.js';
import { useConfirm } from './useConfirm.jsx';

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
  const { data: weights, reload: reloadWeights } = useApi(api.detectionWeights);
  const { data: fpStats } = useApi(api.fpFeedbackStats);
  const { data: contentRulesData, reload: reloadRules } = useApi(api.contentRules);
  const { data: packsData, reload: reloadPacks } = useApi(api.contentPacks);
  const { data: huntsData, reload: reloadHunts } = useApi(api.hunts);
  const { data: suppressionsData, reload: reloadSuppressions } = useApi(api.suppressions);
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
  const [huntRunning, setHuntRunning] = useState(false);
  const [huntSaving, setHuntSaving] = useState(false);
  const [packSaving, setPackSaving] = useState(false);
  const [runningSavedHuntId, setRunningSavedHuntId] = useState(null);
  const [escalatingRunId, setEscalatingRunId] = useState(null);
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
  const tuneOpen = searchParams.get('tune') === '1';
  const activeDrawerMode = drawerMode || (tuneOpen ? 'tune' : null);
  const intent = searchParams.get('intent') || '';
  const huntIntent = intent === 'run-hunt';
  const huntQueryParam = searchParams.get('huntQuery') || '';
  const huntNameParam = searchParams.get('huntName') || '';

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
  const selectedPacks = useMemo(
    () => packs.filter((pack) => (selectedRule?.pack_ids || []).includes(pack.id)),
    [packs, selectedRule],
  );
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

  const promoteRule = async (target) => {
    if (!selectedRule) return;
    try {
      await api.contentRulePromote(selectedRule.id, {
        target_status: target,
        reason: `Promoted from workspace to ${target}`,
      });
      toast(`Rule moved to ${target}.`, 'success');
      reloadRules();
    } catch {
      toast('Rule promotion failed.', 'error');
    }
  };

  const rollbackRule = async () => {
    if (!selectedRule) return;
    try {
      await api.contentRuleRollback(selectedRule.id);
      toast('Rule rolled back.', 'success');
      reloadRules();
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
        {summary && <JsonDetails data={summary} label="Detection summary details" />}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
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
        </div>
        <div style={{ marginTop: 10, display: 'grid', gap: 8 }}>
          {(Array.isArray(coverageGaps?.gaps)
            ? coverageGaps.gaps
            : Array.isArray(coverageGaps)
              ? coverageGaps
              : []
          )
            .slice(0, 8)
            .map((gap, index) => (
              <div
                key={`${gap?.technique_id || gap?.technique || 'gap'}-${index}`}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  borderBottom: '1px solid var(--border)',
                  padding: '8px 0',
                }}
              >
                <div className="row-primary">
                  {gap?.technique_id || gap?.technique || 'Unknown technique'}
                </div>
                <div className="row-secondary">
                  {gap?.technique_name || gap?.name || 'Unmapped'}
                </div>
              </div>
            ))}
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
                        <div className="empty" style={{ padding: 24 }}>
                          No rules match this queue and filter scope.
                        </div>
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
              <div className="empty">
                Select a rule to inspect lifecycle, validation, and related suppressions.
              </div>
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
                            {entry.false_positives}/{entry.total_marked} analyst labels marked false
                            positive
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
                        This rule is not attached to a content pack bundle yet. Create one to manage
                        saved searches, workflow routes, and target-group rollout notes from this
                        workspace.
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
                              {(workflow.mitre_techniques || []).join(', ') || 'No ATT&CK mapping'}{' '}
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

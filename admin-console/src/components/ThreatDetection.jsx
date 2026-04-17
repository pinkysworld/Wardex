import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid, SideDrawer, formatDateTime, formatRelativeTime } from './operator.jsx';

const SAVED_VIEWS = [
  { id: 'noisy', label: 'Noisy', match: (rule, ctx) => (rule.last_test_match_count || 0) >= 5 || ctx.suppressionCount[rule.id] > 0 },
  { id: 'recent', label: 'Recently Tuned', match: (rule) => !!rule.last_test_at || !!rule.last_promotion_at },
  { id: 'review', label: 'Needs Review', match: (rule) => !rule.last_test_at || ['draft', 'test'].includes(rule.lifecycle) },
  { id: 'disabled', label: 'Disabled', match: (rule) => rule.enabled === false || rule.lifecycle === 'deprecated' },
  { id: 'suppressed', label: 'Suppressed', match: (rule, ctx) => ctx.suppressionCount[rule.id] > 0 },
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

const tokenize = (value) => normalizeText(value)
  .split(/[^a-z0-9]+/)
  .filter((token) => token.length > 2);

const formatRatio = (value) => `${Math.round((Number(value) || 0) * 100)}%`;

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
  if (Array.isArray(result)) return { mode: 'matches', count: result.length, label: `${result.length} matching event${result.length === 1 ? '' : 's'}` };
  if (Array.isArray(result?.rows)) return { mode: 'aggregate', count: result.rows.length, label: `${result.rows.length} aggregate row${result.rows.length === 1 ? '' : 's'}` };
  if (Array.isArray(result?.buckets)) return { mode: 'aggregate', count: result.buckets.length, label: `${result.buckets.length} bucket${result.buckets.length === 1 ? '' : 's'}` };
  if (typeof result?.count === 'number') return { mode: 'aggregate', count: result.count, label: `${result.count} result${result.count === 1 ? '' : 's'}` };
  if (typeof result?.run?.match_count === 'number') return { mode: 'saved-hunt', count: result.run.match_count, label: `${result.run.match_count} saved-hunt match${result.run.match_count === 1 ? '' : 'es'}` };
  return { mode: 'raw', count: 0, label: 'Raw hunt response available' };
};

export default function ThreatDetection() {
  const toast = useToast();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: profile } = useApi(api.detectionProfile);
  const { data: summary } = useApi(api.detectionSummary);
  const { data: weights, reload: reloadWeights } = useApi(api.detectionWeights);
  const { data: fpStats } = useApi(api.fpFeedbackStats);
  const { data: contentRulesData, reload: reloadRules } = useApi(api.contentRules);
  const { data: packsData } = useApi(api.contentPacks);
  const { data: huntsData, reload: reloadHunts } = useApi(api.hunts);
  const { data: suppressionsData, reload: reloadSuppressions } = useApi(api.suppressions);
  const { data: mitreCoverage } = useApi(api.mitreCoverageAlt);
  const [testResult, setTestResult] = useState(null);
  const [drawerMode, setDrawerMode] = useState(null);
  const [weightInput, setWeightInput] = useState('0.50');
  const [huntDraft, setHuntDraft] = useState({
    name: '',
    query: '',
    severity: 'medium',
    level: '',
    limit: '250',
    threshold: '1',
    suppressionWindowSecs: '0',
    scheduleIntervalSecs: '',
  });
  const [huntResult, setHuntResult] = useState(null);
  const [huntRunning, setHuntRunning] = useState(false);
  const [huntSaving, setHuntSaving] = useState(false);
  const [runningSavedHuntId, setRunningSavedHuntId] = useState(null);
  const [investigationSuggestions, setInvestigationSuggestions] = useState([]);
  const [suggestingInvestigations, setSuggestingInvestigations] = useState(false);
  const [startingInvestigationId, setStartingInvestigationId] = useState(null);
  const [suppressionForm, setSuppressionForm] = useState({
    name: '',
    justification: 'Operator suppression',
    severity: '',
    text: '',
  });

  const allRules = Array.isArray(contentRulesData?.rules) ? contentRulesData.rules : [];
  const packs = Array.isArray(packsData?.packs) ? packsData.packs : [];
  const hunts = Array.isArray(huntsData?.hunts) ? huntsData.hunts : [];
  const suppressions = Array.isArray(suppressionsData?.suppressions) ? suppressionsData.suppressions : [];
  const suppressionCount = suppressions.reduce((acc, suppression) => {
    if (suppression.rule_id) acc[suppression.rule_id] = (acc[suppression.rule_id] || 0) + 1;
    return acc;
  }, {});

  const queue = searchParams.get('queue') || 'noisy';
  const query = searchParams.get('q') || '';
  const ownerFilter = searchParams.get('owner') || 'all';
  const selectedRuleId = searchParams.get('rule');
  const tuneOpen = searchParams.get('tune') === '1';
  const intent = searchParams.get('intent') || '';
  const huntIntent = intent === 'run-hunt';
  const huntQueryParam = searchParams.get('huntQuery') || '';
  const huntNameParam = searchParams.get('huntName') || '';

  const filteredRules = allRules.filter((rule) => {
    const savedView = SAVED_VIEWS.find((item) => item.id === queue);
    const queueMatch = savedView ? savedView.match(rule, { suppressionCount }) : true;
    const q = query.trim().toLowerCase();
    const searchMatch = !q
      || String(rule.title || '').toLowerCase().includes(q)
      || String(rule.id || '').toLowerCase().includes(q)
      || String(rule.description || '').toLowerCase().includes(q);
    const ownerMatch = ownerFilter === 'all' || String(rule.owner || 'system') === ownerFilter;
    return queueMatch && searchMatch && ownerMatch;
  });

  const selectedRule = filteredRules.find((rule) => rule.id === selectedRuleId)
    || allRules.find((rule) => rule.id === selectedRuleId)
    || filteredRules[0]
    || allRules[0]
    || null;
  const currentWeight = Number(weights?.weights?.[selectedRule?.id] ?? weights?.[selectedRule?.id] ?? 0.5);

  useEffect(() => {
    if (!selectedRule || selectedRule.id === selectedRuleId) return;
    const next = new URLSearchParams(searchParams);
    next.set('rule', selectedRule.id);
    setSearchParams(next, { replace: true });
  }, [selectedRule, selectedRuleId, searchParams, setSearchParams]);

  useEffect(() => {
    if (huntIntent && drawerMode !== 'hunt') {
      setDrawerMode('hunt');
    }
  }, [huntIntent, drawerMode]);

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
    api.investigationSuggest({ alert_reasons: reasons })
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

    setHuntDraft((draft) => ({
      ...draft,
      name: huntNameParam || `Hunt ${selectedRule.title || selectedRule.id}`,
      query: buildDefaultHuntQuery(selectedRule, huntQueryParam),
      severity: String(selectedRule.severity_mapping || draft.severity || 'medium').toLowerCase(),
      level: String(selectedRule.severity_mapping || draft.level || '').toLowerCase(),
    }));
  }, [selectedRule, drawerMode, huntIntent, huntQueryParam, huntNameParam]);

  const openDrawer = (mode) => {
    const next = new URLSearchParams(searchParams);
    if (selectedRule) next.set('rule', selectedRule.id);
    next.delete('tune');
    next.delete('intent');
    next.delete('huntQuery');
    next.delete('huntName');
    if (mode === 'tune') next.set('tune', '1');
    if (mode === 'hunt') next.set('intent', 'run-hunt');
    setSearchParams(next, { replace: true });
    setDrawerMode(mode);
  };

  const closeDrawer = () => {
    const next = new URLSearchParams(searchParams);
    next.delete('tune');
    next.delete('intent');
    next.delete('huntQuery');
    next.delete('huntName');
    setSearchParams(next, { replace: true });
    setDrawerMode(null);
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
      closeDrawer();
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
      await api.contentRulePromote(selectedRule.id, { target_status: target, reason: `Promoted from workspace to ${target}` });
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
      closeDrawer();
    } catch {
      toast('Failed to save suppression.', 'error');
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
      if (drawerMode !== 'hunt') openDrawer('hunt');
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

    setHuntSaving(true);
    try {
      await api.createHunt({
        name: huntDraft.name || `Hunt ${selectedRule?.title || selectedRule?.id || 'Signals'}`,
        severity: huntDraft.severity || selectedRule?.severity_mapping || 'medium',
        threshold: Number(huntDraft.threshold) || 1,
        suppression_window_secs: Number(huntDraft.suppressionWindowSecs) || 0,
        schedule_interval_secs: huntDraft.scheduleIntervalSecs ? Number(huntDraft.scheduleIntervalSecs) : undefined,
        query: {
          text: queryText,
          level: huntDraft.level || undefined,
          limit: Number(huntDraft.limit) || 250,
        },
      });
      toast('Hunt saved.', 'success');
      reloadHunts();
    } catch {
      toast('Failed to save hunt.', 'error');
    } finally {
      setHuntSaving(false);
    }
  };

  const runSavedHuntNow = async (huntId) => {
    if (!huntId) return;
    setRunningSavedHuntId(huntId);
    try {
      const result = await api.runHunt(huntId);
      setHuntResult(result);
      openDrawer('hunt');
      toast('Saved hunt executed.', 'success');
      reloadHunts();
    } catch {
      toast('Failed to run saved hunt.', 'error');
    } finally {
      setRunningSavedHuntId(null);
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
    const queryText = typeof hunt.query === 'string'
      ? hunt.query
      : hunt.query?.text || hunt.query?.query || '';

    setHuntDraft({
      name: hunt.name || `Hunt ${selectedRule?.title || selectedRule?.id || 'Signals'}`,
      query: queryText,
      severity: String(hunt.severity || selectedRule?.severity_mapping || 'medium').toLowerCase(),
      level: String(hunt.query?.level || '').toLowerCase(),
      limit: String(hunt.query?.limit || 250),
      threshold: String(hunt.threshold || 1),
      suppressionWindowSecs: String(hunt.suppression_window_secs || 0),
      scheduleIntervalSecs: hunt.schedule_interval_secs ? String(hunt.schedule_interval_secs) : '',
    });
    openDrawer('hunt');
  };

  const packNames = (selectedRule?.pack_ids || []).map((packId) => packs.find((pack) => pack.id === packId)?.name || packId);
  const relatedHunts = hunts.filter((hunt) => {
    const text = `${hunt.name || ''} ${JSON.stringify(hunt.query || {})}`.toLowerCase();
    return selectedRule && (text.includes(String(selectedRule.id).toLowerCase()) || text.includes(String(selectedRule.title || '').toLowerCase()));
  });
  const huntSummary = summarizeHuntResult(huntResult);
  const fpEntries = (Array.isArray(fpStats) ? fpStats : Array.isArray(fpStats?.items) ? fpStats.items : [])
    .filter((entry) => entry && typeof entry === 'object' && entry.pattern)
    .map((entry) => ({
      pattern: entry.pattern,
      total_marked: Number(entry.total_marked) || 0,
      false_positives: Number(entry.false_positives) || 0,
      fp_ratio: Number(entry.fp_ratio ?? entry.ratio) || 0,
      suppression_weight: Number(entry.suppression_weight) || 1,
    }))
    .sort((left, right) => right.fp_ratio - left.fp_ratio || right.total_marked - left.total_marked);
  const ruleFpSignals = selectedRule
    ? fpEntries
      .map((entry) => ({
        ...entry,
        matchScore: scoreFpPatternMatch(selectedRule, entry.pattern),
      }))
      .filter((entry) => entry.matchScore > 0)
      .sort((left, right) => right.matchScore - left.matchScore || right.fp_ratio - left.fp_ratio || right.total_marked - left.total_marked)
    : [];
  const suppressionAdvisor = ruleFpSignals[0] || null;
  const fpPreview = (ruleFpSignals.length > 0 ? ruleFpSignals : fpEntries).slice(0, 3);

  const queueCounts = SAVED_VIEWS.reduce((acc, item) => {
    acc[item.id] = allRules.filter((rule) => item.match(rule, { suppressionCount })).length;
    return acc;
  }, {});
  const owners = ['all', ...new Set(allRules.map((rule) => rule.owner || 'system'))];

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
      toast('This pattern needs more feedback volume before it can suggest a weight change.', 'error');
      return;
    }

    const suggested = Math.max(0.05, Math.min(5, currentWeight * entry.suppression_weight));
    setWeightInput(suggested.toFixed(2));
    openDrawer('tune');
    toast(`Loaded suggested weight ${suggested.toFixed(2)} from false-positive feedback.`, 'success');
  };

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <div>
            <div className="card-title">Detection Engineering Workspace</div>
            <div className="hint">Triage noisy rules, validate changes, and move detections through lifecycle gates without inline edits.</div>
          </div>
          <div className="btn-group">
            {['aggressive', 'balanced', 'quiet'].map((option) => (
              <button
                key={option}
                className={`btn btn-sm ${profile?.profile === option ? 'btn-primary' : ''}`}
                onClick={() => api.setDetectionProfile({ profile: option }).then(() => toast(`Profile set to ${option}.`, 'success')).catch(() => toast('Unable to update profile.', 'error'))}
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
            <div className="summary-meta">Threshold multiplier {profile?.threshold_multiplier ?? '—'}</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Rules In Workspace</div>
            <div className="summary-value">{allRules.length}</div>
            <div className="summary-meta">{filteredRules.length} currently in the active queue</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Coverage</div>
            <div className="summary-value">{mitreCoverage?.coverage_pct != null ? `${mitreCoverage.coverage_pct}%` : '—'}</div>
            <div className="summary-meta">{mitreCoverage?.covered_techniques ?? '—'} techniques covered</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Pending Suppressions</div>
            <div className="summary-value">{suppressions.filter((item) => item.active !== false).length}</div>
            <div className="summary-meta">Live exceptions currently shaping rule outcomes</div>
          </div>
        </div>
        {summary && <JsonDetails data={summary} label="Detection summary details" />}
      </div>

      <div className="triage-layout">
        <section className="triage-list">
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Rule Queues</div>
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
                  {owners.map((owner) => <option key={owner} value={owner}>{owner === 'all' ? 'All owners' : owner}</option>)}
                </select>
              </div>
              <div className="triage-toolbar-group">
                <button className="btn btn-sm" onClick={reloadRules}>Refresh</button>
                <button className="btn btn-sm btn-primary" onClick={testRule} disabled={!selectedRule}>Test Selected</button>
              </div>
            </div>

            <div className="sticky-bulk-bar">
              <span className="hint">Queue focuses noisy, recently changed, and suppressed detections first.</span>
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
                    <tr><td colSpan="5"><div className="empty" style={{ padding: 24 }}>No rules match this queue and filter scope.</div></td></tr>
                  ) : filteredRules.map((rule) => (
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
                        <div className="row-secondary">{rule.description || 'No rule narrative available.'}</div>
                      </td>
                      <td>{rule.owner || 'system'}</td>
                      <td>{Array.isArray(rule.attack) ? rule.attack.length : 0} mappings</td>
                      <td>
                        <span className={`badge ${severityTone((rule.last_test_match_count || 0) >= 5 ? 'high' : 'low')}`}>
                          {(rule.last_test_match_count || 0)} hits
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${lifecycleTone(rule.lifecycle)}`}>{rule.lifecycle || 'draft'}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <aside className="triage-detail">
          <div className="card">
            {!selectedRule ? <div className="empty">Select a rule to inspect lifecycle, validation, and related suppressions.</div> : (
              <>
                <div className="detail-hero">
                  <div>
                    <div className="detail-hero-title">{selectedRule.title || selectedRule.id}</div>
                    <div className="detail-hero-copy">{selectedRule.description || 'This rule needs a clearer analyst-facing summary before rollout.'}</div>
                  </div>
                  <span className={`badge ${lifecycleTone(selectedRule.lifecycle)}`}>{selectedRule.lifecycle || 'draft'}</span>
                </div>

                <div className="chip-row" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                  <span className={`badge ${selectedRule.enabled === false ? 'badge-err' : 'badge-ok'}`}>{selectedRule.enabled === false ? 'Disabled' : 'Enabled'}</span>
                  <span className="badge badge-info">{selectedRule.kind || 'sigma'}</span>
                  <span className="badge badge-info">Owner: {selectedRule.owner || 'system'}</span>
                  <span className={`badge ${severityTone(selectedRule.severity_mapping || 'low')}`}>{selectedRule.severity_mapping || 'severity inherited'}</span>
                </div>

                <div className="btn-group" style={{ marginTop: 16 }}>
                  <button className="btn btn-sm btn-primary" onClick={testRule}>Test</button>
                  <button className="btn btn-sm" onClick={() => openDrawer('tune')}>Tune</button>
                  <button className="btn btn-sm" onClick={() => openDrawer('hunt')}>Hunt</button>
                  <button className="btn btn-sm" onClick={() => openDrawer('suppress')}>Suppress</button>
                  <button className="btn btn-sm" onClick={() => promoteRule('canary')}>Promote</button>
                  <button className="btn btn-sm" onClick={rollbackRule}>Rollback</button>
                  <button className="btn btn-sm btn-danger" onClick={disableRule}>Disable</button>
                </div>

                <div className="summary-grid" style={{ marginTop: 16 }}>
                  <div className="summary-card">
                    <div className="summary-label">Last Test</div>
                    <div className="summary-value">{selectedRule.last_test_at ? formatRelativeTime(selectedRule.last_test_at) : 'Never'}</div>
                    <div className="summary-meta">{selectedRule.last_test_at ? formatDateTime(selectedRule.last_test_at) : 'Run a validation replay before promotion.'}</div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Validation Hits</div>
                    <div className="summary-value">{selectedRule.last_test_match_count || 0}</div>
                    <div className="summary-meta">Replay hit count from the most recent rule test.</div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Suppressions</div>
                    <div className="summary-value">{suppressionCount[selectedRule.id] || 0}</div>
                    <div className="summary-meta">Active exceptions tied directly to this rule.</div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">FP Advisor</div>
                    <div className="summary-value">{suppressionAdvisor ? formatRatio(suppressionAdvisor.fp_ratio) : '—'}</div>
                    <div className="summary-meta">
                      {suppressionAdvisor
                        ? `${suppressionAdvisor.false_positives}/${suppressionAdvisor.total_marked} labels matched “${suppressionAdvisor.pattern}”`
                        : 'No rule-specific false-positive pattern matched yet.'}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Content Packs</div>
                    <div className="summary-value">{packNames.length}</div>
                    <div className="summary-meta">{packNames.slice(0, 2).join(' • ') || 'No pack membership recorded.'}</div>
                  </div>
                </div>

                <div className="detail-callout" style={{ marginTop: 16 }}>
                  <strong>MITRE impact</strong>
                  <div style={{ marginTop: 6 }}>
                    {Array.isArray(selectedRule.attack) && selectedRule.attack.length > 0
                      ? selectedRule.attack.map((attack) => `${attack.technique_name || attack.technique_id} (${attack.tactic || 'mapped tactic'})`).join(' • ')
                      : 'No ATT&CK mapping is attached yet. Add one before broad promotion so analysts understand coverage intent.'}
                  </div>
                </div>

                <div className="card" style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}>
                  <div className="card-title" style={{ marginBottom: 10 }}>Validation and Context</div>
                  {testResult ? (
                    <div className="summary-grid">
                      <div className="summary-card">
                        <div className="summary-label">Tested At</div>
                        <div className="summary-value">{formatRelativeTime(testResult.tested_at)}</div>
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
                        <div className="summary-meta">Hidden by active suppressions or exceptions.</div>
                      </div>
                    </div>
                  ) : (
                    <div className="hint">Run a rule test to preview impact before tuning or promotion.</div>
                  )}
                </div>

                <div className="card" style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}>
                  <div className="card-title" style={{ marginBottom: 10 }}>False-Positive Signals</div>
                  <div className="hint" style={{ marginBottom: 10 }}>
                    {ruleFpSignals.length > 0
                      ? 'These patterns overlap the selected rule and can be turned into scoped suppressions or safer weighting changes.'
                      : 'No direct false-positive pattern matched this rule yet. Showing the strongest global analyst feedback patterns instead.'}
                  </div>
                  {fpPreview.length === 0 ? (
                    <div className="hint">False-positive feedback will appear here once analysts label alert outcomes.</div>
                  ) : fpPreview.map((entry) => (
                    <div key={entry.pattern} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                      <div style={{ flex: 1 }}>
                        <div className="row-primary">{entry.pattern}</div>
                        <div className="row-secondary">
                          {entry.false_positives}/{entry.total_marked} analyst labels marked false positive
                          {entry.suppression_weight < 1
                            ? ` • suggested weight ${entry.suppression_weight.toFixed(2)}`
                            : ' • weighting stays unchanged until more samples accumulate'}
                        </div>
                      </div>
                      <div className="btn-group" style={{ alignItems: 'center' }}>
                        <span className={`badge ${entry.fp_ratio >= 0.7 ? 'badge-err' : entry.fp_ratio >= 0.4 ? 'badge-warn' : 'badge-info'}`}>{formatRatio(entry.fp_ratio)} FP</span>
                        <button className="btn btn-sm" onClick={() => prefillSuppressionFromSignal(entry)}>Prefill suppression</button>
                        <button className="btn btn-sm" onClick={() => applySuggestedWeight(entry)} disabled={entry.suppression_weight >= 0.999}>Use weight</button>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="card" style={{ marginTop: 16, padding: 16, background: 'var(--bg)' }}>
                  <div className="card-title" style={{ marginBottom: 10 }}>Hunts and Investigations</div>
                  <div className="summary-grid">
                    <div className="summary-card">
                      <div className="summary-label">Saved Hunts</div>
                      <div className="summary-value">{relatedHunts.length}</div>
                      <div className="summary-meta">{relatedHunts[0]?.name || 'No hunt references found for this rule.'}</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-label">Suggested Workflows</div>
                      <div className="summary-value">{investigationSuggestions.length}</div>
                      <div className="summary-meta">{investigationSuggestions[0]?.name || 'No workflow suggestion matched this rule context.'}</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-label">Promotion State</div>
                      <div className="summary-value">{selectedRule.last_promotion_at ? formatRelativeTime(selectedRule.last_promotion_at) : 'Pending'}</div>
                      <div className="summary-meta">{selectedRule.last_promotion_at ? formatDateTime(selectedRule.last_promotion_at) : 'No promotion event recorded yet.'}</div>
                    </div>
                  </div>

                  <div style={{ marginTop: 12 }}>
                    <div className="row-primary" style={{ marginBottom: 8 }}>Rule-aligned saved hunts</div>
                    {relatedHunts.length === 0 ? (
                      <div className="hint">No saved hunt references were found. Open the hunt drawer to save one from this rule context.</div>
                    ) : relatedHunts.slice(0, 3).map((hunt) => (
                      <div key={hunt.id || hunt.name} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                        <div style={{ flex: 1 }}>
                          <div className="row-primary">{hunt.name || hunt.id}</div>
                          <div className="row-secondary">{hunt.query?.text || JSON.stringify(hunt.query || {})}</div>
                          <div className="hint" style={{ marginTop: 4 }}>
                            {hunt.latest_run?.started_at
                              ? `Last run ${formatRelativeTime(hunt.latest_run.started_at)} • ${hunt.latest_run.match_count || 0} matches`
                              : 'No saved-hunt run recorded yet.'}
                          </div>
                        </div>
                        <div className="btn-group" style={{ alignItems: 'center' }}>
                          <button className="btn btn-sm" onClick={() => loadSavedHuntIntoDraft(hunt)}>Open</button>
                          <button className="btn btn-sm btn-primary" onClick={() => runSavedHuntNow(hunt.id)} disabled={runningSavedHuntId === hunt.id}>
                            {runningSavedHuntId === hunt.id ? 'Running…' : 'Run'}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div style={{ marginTop: 16 }}>
                    <div className="row-primary" style={{ marginBottom: 8 }}>Suggested investigations</div>
                    {suggestingInvestigations ? (
                      <div className="hint">Scoring workflow suggestions from the selected rule context…</div>
                    ) : investigationSuggestions.length === 0 ? (
                      <div className="hint">No builtin workflow matched the current rule metadata. You can still pivot into hunts from this drawer.</div>
                    ) : investigationSuggestions.slice(0, 3).map((workflow) => (
                      <div key={workflow.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                        <div style={{ flex: 1 }}>
                          <div className="row-primary">{workflow.name}</div>
                          <div className="row-secondary">{workflow.description}</div>
                          <div className="hint" style={{ marginTop: 4 }}>
                            {(workflow.mitre_techniques || []).join(', ') || 'No ATT&CK mapping'} • {(workflow.steps || []).length} steps • {workflow.estimated_minutes || '—'}m
                          </div>
                        </div>
                        <div className="btn-group" style={{ alignItems: 'center' }}>
                          <span className={`badge ${severityTone(String(workflow.severity || 'medium').toLowerCase())}`}>{workflow.severity || 'medium'}</span>
                          <button className="btn btn-sm btn-primary" onClick={() => startInvestigationFromWorkflow(workflow)} disabled={startingInvestigationId === workflow.id}>
                            {startingInvestigationId === workflow.id ? 'Starting…' : 'Start'}
                          </button>
                        </div>
                      </div>
                    ))}
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
        open={drawerMode === 'tune' || tuneOpen}
        title={selectedRule ? `Tune ${selectedRule.title || selectedRule.id}` : 'Tune rule'}
        subtitle="Move weighting changes into a side panel so validation and save actions are harder to trigger accidentally."
        onClose={closeDrawer}
        actions={<button className="btn btn-sm btn-primary" onClick={saveWeight}>Save Weight</button>}
      >
        <div className="form-group">
          <label className="form-label" htmlFor="rule-weight">Detection Weight</label>
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
          <div className="hint">Preview the likely blast radius using the latest test match count before committing.</div>
        </div>
        <SummaryGrid data={{
          current_profile: profile?.profile,
          last_test_match_count: selectedRule?.last_test_match_count || 0,
          live_suppressions: suppressionCount[selectedRule?.id] || 0,
          current_weight: Number.isFinite(currentWeight) ? currentWeight.toFixed(2) : '0.50',
          suggested_weight: suppressionAdvisor ? Math.max(0.05, Math.min(5, currentWeight * suppressionAdvisor.suppression_weight)).toFixed(2) : '—',
          recommendation: (selectedRule?.last_test_match_count || 0) >= 5 ? 'Reduce noise before promotion' : 'Ready for canary validation',
        }} limit={4} />
      </SideDrawer>

      <SideDrawer
        open={drawerMode === 'suppress'}
        title={selectedRule ? `Suppress ${selectedRule.title || selectedRule.id}` : 'Suppress rule'}
        subtitle="Capture intent and scope explicitly so exceptions remain understandable later."
        onClose={closeDrawer}
        actions={<button className="btn btn-sm btn-primary" onClick={createSuppression}>Save Suppression</button>}
      >
        <div className="form-group">
          <label className="form-label" htmlFor="suppression-name">Name</label>
          <input id="suppression-name" className="form-input" value={suppressionForm.name} onChange={(event) => setSuppressionForm((form) => ({ ...form, name: event.target.value }))} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="suppression-justification">Justification</label>
          <textarea id="suppression-justification" className="form-textarea" value={suppressionForm.justification} onChange={(event) => setSuppressionForm((form) => ({ ...form, justification: event.target.value }))} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="suppression-text">Match Text Filter</label>
          <input id="suppression-text" className="form-input" value={suppressionForm.text} onChange={(event) => setSuppressionForm((form) => ({ ...form, text: event.target.value }))} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="suppression-severity">Severity</label>
          <input id="suppression-severity" className="form-input" value={suppressionForm.severity} onChange={(event) => setSuppressionForm((form) => ({ ...form, severity: event.target.value }))} />
        </div>
      </SideDrawer>

      <SideDrawer
        open={drawerMode === 'hunt'}
        title={selectedRule ? `Hunt ${selectedRule.title || selectedRule.id}` : 'Threat Hunt'}
        subtitle="Run an ad-hoc hunt, save it for reuse, and pivot into an investigation workflow from the same rule context."
        onClose={closeDrawer}
        actions={(
          <div className="btn-group">
            <button className="btn btn-sm" onClick={saveHuntDraft} disabled={huntSaving}>
              {huntSaving ? 'Saving…' : 'Save Hunt'}
            </button>
            <button className="btn btn-sm btn-primary" onClick={() => runLiveHunt()} disabled={huntRunning}>
              {huntRunning ? 'Running…' : 'Run Hunt'}
            </button>
          </div>
        )}
      >
        <div className="form-group">
          <label className="form-label" htmlFor="hunt-name">Hunt Name</label>
          <input id="hunt-name" className="form-input" value={huntDraft.name} onChange={(event) => setHuntDraft((draft) => ({ ...draft, name: event.target.value }))} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="hunt-query">Query</label>
          <textarea
            id="hunt-query"
            className="form-textarea"
            rows="5"
            value={huntDraft.query}
            onChange={(event) => setHuntDraft((draft) => ({ ...draft, query: event.target.value }))}
          />
          <div className="hint">Use the live hunt DSL for pivots like `severity:high`, `process_name:mimikatz | count by device_id`, or `src_ip:10.* | top 5 dst_ip`.</div>
        </div>
        <div className="summary-grid" style={{ marginBottom: 16 }}>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-severity">Severity</label>
            <select id="hunt-severity" className="form-select" value={huntDraft.severity} onChange={(event) => setHuntDraft((draft) => ({ ...draft, severity: event.target.value }))}>
              {['critical', 'high', 'medium', 'low'].map((option) => <option key={option} value={option}>{option}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-level">Search Level</label>
            <input id="hunt-level" className="form-input" value={huntDraft.level} onChange={(event) => setHuntDraft((draft) => ({ ...draft, level: event.target.value }))} placeholder="critical / high / medium" />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-limit">Limit</label>
            <input id="hunt-limit" className="form-input" type="number" min="1" step="1" value={huntDraft.limit} onChange={(event) => setHuntDraft((draft) => ({ ...draft, limit: event.target.value }))} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-threshold">Threshold</label>
            <input id="hunt-threshold" className="form-input" type="number" min="1" step="1" value={huntDraft.threshold} onChange={(event) => setHuntDraft((draft) => ({ ...draft, threshold: event.target.value }))} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-window">Suppression Window Secs</label>
            <input id="hunt-window" className="form-input" type="number" min="0" step="60" value={huntDraft.suppressionWindowSecs} onChange={(event) => setHuntDraft((draft) => ({ ...draft, suppressionWindowSecs: event.target.value }))} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="hunt-schedule">Schedule Interval Secs</label>
            <input id="hunt-schedule" className="form-input" type="number" min="0" step="60" value={huntDraft.scheduleIntervalSecs} onChange={(event) => setHuntDraft((draft) => ({ ...draft, scheduleIntervalSecs: event.target.value }))} placeholder="Optional" />
          </div>
        </div>

        <div className="detail-callout" style={{ marginBottom: 16 }}>
          <strong>Investigation pivots</strong>
          <div style={{ marginTop: 6 }}>
            {investigationSuggestions.length === 0
              ? 'No workflow suggestion is ready for this rule yet. Start with a hunt and pivot from the resulting matches.'
              : investigationSuggestions.slice(0, 2).map((workflow) => workflow.name).join(' • ')}
          </div>
        </div>

        <div className="card" style={{ padding: 16, background: 'var(--bg)' }}>
          <div className="card-title" style={{ marginBottom: 10 }}>Latest Hunt Result</div>
          <div className="summary-grid">
            <div className="summary-card">
              <div className="summary-label">Result Mode</div>
              <div className="summary-value">{huntSummary.mode}</div>
              <div className="summary-meta">{huntSummary.label}</div>
            </div>
            <div className="summary-card">
              <div className="summary-label">Count</div>
              <div className="summary-value">{huntSummary.count}</div>
              <div className="summary-meta">Matches, rows, or buckets returned by the most recent run.</div>
            </div>
          </div>
          {!huntResult ? (
            <div className="hint" style={{ marginTop: 10 }}>No hunt has been run from this drawer yet.</div>
          ) : (
            <div style={{ marginTop: 10 }}>
              <JsonDetails data={huntResult} label="Hunt response" />
            </div>
          )}
        </div>
      </SideDrawer>
    </div>
  );
}

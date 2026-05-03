import { useEffect, useMemo, useState } from 'react';
import { useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SideDrawer, SummaryGrid } from './operator.jsx';
import { downloadData } from './operatorUtils.js';
import AlertNarrative from './AlertNarrative.jsx';

/* ── MITRE + investigation helpers ──────────────────────────── */

const CATEGORY_TO_MITRE = {
  brute_force: { tactic: 'Credential Access', technique: 'T1110', name: 'Brute Force' },
  credential_access: {
    tactic: 'Credential Access',
    technique: 'T1555',
    name: 'Credentials from Password Stores',
  },
  lateral_movement: { tactic: 'Lateral Movement', technique: 'T1021', name: 'Remote Services' },
  privilege_escalation: {
    tactic: 'Privilege Escalation',
    technique: 'T1548',
    name: 'Abuse Elevation Control',
  },
  exfiltration: {
    tactic: 'Exfiltration',
    technique: 'T1041',
    name: 'Exfiltration Over C2 Channel',
  },
  malware: { tactic: 'Execution', technique: 'T1204', name: 'User Execution' },
  ransomware: { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted for Impact' },
  reconnaissance: { tactic: 'Reconnaissance', technique: 'T1595', name: 'Active Scanning' },
  command_and_control: {
    tactic: 'Command and Control',
    technique: 'T1071',
    name: 'Application Layer Protocol',
  },
  persistence: { tactic: 'Persistence', technique: 'T1053', name: 'Scheduled Task/Job' },
};

function inferMitre(alert) {
  const cat = (alert.category || alert.type || '').toLowerCase().replace(/[\s-]/g, '_');
  return CATEGORY_TO_MITRE[cat] || null;
}

function buildExplanation(alert, mitre, reasons) {
  const score = alert.score ?? alert.severity_score ?? null;
  const lines = [];
  if (score !== null && score >= 8) {
    lines.push('This is a critical-severity alert that warrants immediate investigation.');
  } else if (score !== null && score >= 5) {
    lines.push('This is a medium-severity alert. Validate the activity and escalate if confirmed.');
  } else {
    lines.push(
      'This is a lower-severity alert. Review context to determine if further action is needed.',
    );
  }
  if (mitre) {
    lines.push(`Mapped to MITRE ATT&CK ${mitre.tactic} / ${mitre.technique} (${mitre.name}).`);
  }
  if (alert.ml_triage) {
    const label = alert.ml_triage.label || alert.ml_triage.prediction;
    const conf = alert.ml_triage.confidence;
    if (label)
      lines.push(
        `ML triage classified this as "${label}"${conf ? ` with ${(conf * 100).toFixed(0)}% confidence` : ''}.`,
      );
  }
  if (reasons.length > 0) {
    lines.push(`Detection triggered by: ${reasons.join('; ')}.`);
  }
  return lines;
}

function suggestNextSteps(alert, mitre) {
  const steps = ['Verify the source host and user account are legitimate.'];
  if (mitre?.tactic === 'Credential Access') {
    steps.push('Check for concurrent login anomalies across the fleet.');
    steps.push('Reset credentials for the affected account.');
  }
  if (mitre?.tactic === 'Lateral Movement') {
    steps.push('Isolate the source and destination hosts.');
    steps.push('Review SMB/RDP/SSH session logs for the time window.');
  }
  if (mitre?.tactic === 'Impact' || (alert.category || '').toLowerCase().includes('ransom')) {
    steps.push('Quarantine affected endpoints immediately.');
    steps.push('Check for shadow-copy deletion or encryption activity.');
  }
  steps.push('Correlate with adjacent telemetry in the timeline view.');
  steps.push('If benign, mark as false-positive to improve future scoring.');
  return steps;
}

const HASH_VALUE_PATTERN = /\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{32})\b/g;

function extractAlertHashes(alert, reasons) {
  if (!alert) return [];

  const directCandidates = [
    alert.sha256,
    alert.md5,
    alert.hash,
    alert.file_hash,
    alert.artifact_hash,
    alert.indicator_hash,
  ];
  const textCandidates = [alert.message, alert.description, ...reasons]
    .filter(Boolean)
    .flatMap((value) => String(value).match(HASH_VALUE_PATTERN) || []);

  return [...new Set([...directCandidates, ...textCandidates])]
    .map((value) => String(value || '').trim().toLowerCase())
    .filter((value) => /^[a-f0-9]{32}$|^[a-f0-9]{64}$/.test(value));
}

function normalizeAlertProcessCandidate(source, alert) {
  if (!source && !alert) return null;

  const process = source?.process || source?.process_detail || source?.process_snapshot || source || {};
  const pidCandidate = [
    source?.pid,
    source?.process_pid,
    process?.pid,
    alert?.pid,
    alert?.process_pid,
    alert?.process?.pid,
    alert?.process_detail?.pid,
    alert?.process_snapshot?.pid,
    alert?.sample?.pid,
  ]
    .map((value) => Number(value))
    .find((value) => Number.isFinite(value) && value > 0);

  if (!pidCandidate) return null;

  const name =
    source?.name ||
    process?.name ||
    source?.process_name ||
    alert?.process_name ||
    source?.display_name ||
    process?.display_name ||
    source?.exe_path ||
    process?.exe_path ||
    source?.cmd_line ||
    process?.cmd_line ||
    `PID ${pidCandidate}`;

  return {
    pid: pidCandidate,
    ppid: Number(source?.ppid ?? process?.ppid ?? alert?.ppid ?? process?.parent_pid) || null,
    name,
    display_name:
      source?.display_name ||
      process?.display_name ||
      String(name).split('/').pop() ||
      `PID ${pidCandidate}`,
    user: source?.user || process?.user || alert?.user || null,
    group: source?.group || process?.group || alert?.group || null,
    hostname: source?.hostname || process?.hostname || alert?.hostname || null,
    platform: source?.platform || process?.platform || alert?.platform || null,
    cmd_line: source?.cmd_line || process?.cmd_line || alert?.cmd_line || null,
    exe_path: source?.exe_path || process?.exe_path || alert?.exe_path || null,
    cwd: source?.cwd || process?.cwd || alert?.cwd || null,
    start_time: source?.start_time || process?.start_time || null,
    reason: source?.reason || alert?.reasons?.[0] || alert?.message || alert?.description || null,
  };
}

function extractAlertProcessCandidate(alert) {
  return normalizeAlertProcessCandidate(alert, alert);
}

function extractAlertProcessCandidates(alert) {
  if (!alert) return [];

  const items = [extractAlertProcessCandidate(alert)];
  if (Array.isArray(alert.process_candidates)) {
    items.push(
      ...alert.process_candidates.map((candidate) => normalizeAlertProcessCandidate(candidate, alert)),
    );
  }

  const seen = new Set();
  return items.filter((candidate) => {
    if (!candidate || seen.has(candidate.pid)) return false;
    seen.add(candidate.pid);
    return true;
  });
}

/* ── AlertDrawer component ──────────────────────────────────── */

export default function AlertDrawer({
  alert,
  onClose,
  onUpdated,
  onSelectProcess,
  onPrevious,
  onNext,
  canPrevious = false,
  canNext = false,
  positionLabel = null,
}) {
  const toast = useToast();
  const [explainOpen, setExplainOpen] = useState(false);
  const [explainData, setExplainData] = useState(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [artifactContext, setArtifactContext] = useState({
    hashMatch: null,
    recentDetections: [],
    sightings: [],
  });
  const [artifactContextLoading, setArtifactContextLoading] = useState(false);

  const summary = useMemo(() => {
    if (!alert) return null;
    return {
      severity: alert.severity,
      score: alert.score,
      source: alert.source,
      category: alert.category || alert.type,
      hostname: alert.hostname,
      origin: alert.alert_origin,
      agent_id: alert.origin_agent_id || alert.agent_id,
      timestamp: alert.timestamp || alert.time,
    };
  }, [alert]);
  const reasons = useMemo(() => {
    if (!alert) return [];
    return Array.isArray(alert.reasons)
      ? alert.reasons
      : alert.reasons
        ? [alert.reasons]
        : [];
  }, [alert]);
  const alertHashes = useMemo(() => extractAlertHashes(alert, reasons), [alert, reasons]);
  const processCandidates = useMemo(() => extractAlertProcessCandidates(alert), [alert]);
  const processNames = useMemo(
    () => (Array.isArray(alert?.process_names) ? alert.process_names.filter(Boolean) : []),
    [alert],
  );
  const processResolution = useMemo(() => {
    const value = alert?.process_resolution;
    if (typeof value !== 'string' || value.length === 0) return null;
    const labels = {
      unique: { label: '1 live match', tone: 'success' },
      multiple: { label: `${processCandidates.length} candidates`, tone: 'warning' },
      remote_host: { label: 'Remote host — switch agent', tone: 'info' },
      unresolved: { label: 'No live match', tone: 'muted' },
      none: { label: 'No process names', tone: 'muted' },
    };
    return { code: value, ...(labels[value] || { label: value, tone: 'muted' }) };
  }, [alert, processCandidates]);

  useEffect(() => {
    let cancelled = false;
    if (!alert) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setExplainData(null);
      setExplainLoading(false);
      return undefined;
    }
    setExplainLoading(true);
    api
      .detectionExplain({
        event_id: alert.id || alert.alert_id,
        alert_id: alert.alert_id || alert.id,
      })
      .then((data) => {
        if (!cancelled) setExplainData(data);
      })
      .catch(() => {
        if (!cancelled) setExplainData(null);
      })
      .finally(() => {
        if (!cancelled) setExplainLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [alert]);

  useEffect(() => {
    let cancelled = false;

    if (!alert || alertHashes.length === 0) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setArtifactContext({ hashMatch: null, recentDetections: [], sightings: [] });
      setArtifactContextLoading(false);
      return undefined;
    }

    setArtifactContextLoading(true);
    Promise.allSettled([
      api.scanHash({ hash: alertHashes[0] }),
      api.malwareRecent(),
      api.threatIntelSightings(25),
    ])
      .then(([hashMatchResult, recentDetectionsResult, sightingsResult]) => {
        if (cancelled) return;

        const recentDetections = Array.isArray(recentDetectionsResult.value)
          ? recentDetectionsResult.value.filter((item) =>
              alertHashes.includes(String(item.sha256 || '').toLowerCase()),
            )
          : [];
        const sightingsItems = Array.isArray(sightingsResult.value?.items)
          ? sightingsResult.value.items
          : [];
        const sightings = sightingsItems.filter((item) =>
          alertHashes.includes(String(item.value || '').toLowerCase()),
        );

        setArtifactContext({
          hashMatch: hashMatchResult.status === 'fulfilled' ? hashMatchResult.value : null,
          recentDetections,
          sightings,
        });
      })
      .catch(() => {
        if (!cancelled) {
          setArtifactContext({ hashMatch: null, recentDetections: [], sightings: [] });
        }
      })
      .finally(() => {
        if (!cancelled) setArtifactContextLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [alert, alertHashes]);

  if (!alert) return null;

  const mitre = inferMitre(alert);
  const fallbackExplanation = buildExplanation(alert, mitre, reasons);
  const fallbackNextSteps = suggestNextSteps(alert, mitre);

  const explanation = explainData?.why_fired?.length
    ? [...(explainData.summary || []), ...explainData.why_fired]
    : fallbackExplanation;
  const whySafeOrNoisy = explainData?.why_safe_or_noisy || [];
  const nextSteps = explainData?.next_steps?.length ? explainData.next_steps : fallbackNextSteps;
  const analystFeedback = Array.isArray(explainData?.feedback) ? explainData.feedback : [];
  const entityScores = Array.isArray(explainData?.entity_scores) ? explainData.entity_scores : [];
  const processLinkState = processCandidates.length
    ? 'Process-linked'
    : processNames.length
      ? 'Process-attributed'
      : 'PID-free';

  const submitFeedback = async (verdict) => {
    try {
      await api.recordDetectionFeedback({
        event_id: alert.id || alert.alert_id,
        alert_id: String(alert.alert_id || alert.id || ''),
        analyst: 'console_analyst',
        verdict,
        reason_pattern:
          reasons.length > 0 ? reasons.join(', ') : alert.category || alert.type || 'unknown',
        notes:
          verdict === 'false_positive'
            ? 'Submitted from alert drawer as benign or noisy.'
            : 'Submitted from alert drawer as analyst-confirmed malicious activity.',
        evidence: (explainData?.evidence || []).slice(0, 8),
      });
      const refreshed = await api.detectionExplain({
        event_id: alert.id || alert.alert_id,
        alert_id: alert.alert_id || alert.id,
      });
      setExplainData(refreshed);
      toast('Analyst feedback saved', 'success');
      onUpdated?.();
    } catch {
      toast('Analyst feedback failed', 'error');
    }
  };

  const markFalsePositive = async () => {
    const pattern =
      reasons.length > 0 ? reasons.join(', ') : alert.category || alert.type || 'unknown';
    try {
      await api.fpFeedback({
        alert_id: alert.id || alert.alert_id,
        pattern,
        is_false_positive: true,
      });
      await api.recordDetectionFeedback({
        event_id: alert.id || alert.alert_id,
        alert_id: String(alert.alert_id || alert.id || ''),
        analyst: 'console_analyst',
        verdict: 'false_positive',
        reason_pattern: pattern,
        notes: 'Marked as false positive from the alert drawer.',
        evidence: (explainData?.evidence || []).slice(0, 8),
      });
      toast('Marked as false positive', 'success');
      onUpdated?.();
    } catch {
      toast('False-positive feedback failed', 'error');
    }
  };

  const createIncidentFromAlert = async () => {
    try {
      await api.createIncident({
        title: `${alert.category || alert.type || 'Alert'} on ${alert.hostname || 'host'}`,
        severity: alert.severity || 'medium',
        event_ids: [alert.id || alert.alert_id].filter(Boolean),
        summary: alert.message || alert.description || 'Created from live alert stream',
      });
      toast('Incident created', 'success');
      onUpdated?.();
    } catch {
      toast('Incident creation failed', 'error');
    }
  };

  return (
    <SideDrawer
      open={!!alert}
      onClose={onClose}
      title={alert.message || alert.description || alert.category || 'Alert detail'}
      subtitle={`${processLinkState} alert context · ${(alert.severity || 'unknown').toUpperCase()}`}
      actions={
        <>
          {(onPrevious || onNext || positionLabel) && (
            <div className="drawer-nav">
              {positionLabel && <span className="scope-chip">{positionLabel}</span>}
              {onPrevious && (
                <button className="btn btn-sm" onClick={onPrevious} disabled={!canPrevious}>
                  Previous
                </button>
              )}
              {onNext && (
                <button className="btn btn-sm" onClick={onNext} disabled={!canNext}>
                  Next
                </button>
              )}
            </div>
          )}
          <button
            className="btn btn-sm"
            onClick={() =>
              downloadData(alert, `alert-${alert.id || alert.alert_id || 'detail'}.json`)
            }
          >
            Export
          </button>
          <button className="btn btn-sm" onClick={markFalsePositive}>
            Mark FP
          </button>
          <button className="btn btn-sm" onClick={() => submitFeedback('true_positive')}>
            Confirm TP
          </button>
          <button className="btn btn-sm btn-primary" onClick={createIncidentFromAlert}>
            Create Incident
          </button>
        </>
      }
    >
      <SummaryGrid data={summary} limit={8} />

      {(processCandidates.length > 0 || processNames.length > 0) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div
            className="card-title"
            style={{
              marginBottom: 8,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              flexWrap: 'wrap',
            }}
          >
            <span>Process Pivot</span>
            {processResolution && (
              <span
                data-testid="alert-process-resolution"
                data-resolution={processResolution.code}
                className={`badge badge-${processResolution.tone}`}
                style={{ fontSize: 11, fontWeight: 500 }}
              >
                {processResolution.label}
              </span>
            )}
          </div>
          {processNames.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div className="metric-label" style={{ marginBottom: 6 }}>
                Extracted Process Names
              </div>
              <div className="chip-row">
                {processNames.map((name) => (
                  <span key={name} className="scope-chip">
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}
          {processCandidates.length > 0 ? (
            <div style={{ display: 'grid', gap: 12 }}>
              {processCandidates.map((candidate) => (
                <div key={candidate.pid} className="drawer-copy-grid">
                  <div>
                    <div className="metric-label">Process</div>
                    <div className="row-primary">
                      {candidate.display_name} (PID {candidate.pid})
                    </div>
                    <div className="row-secondary">
                      {candidate.hostname || 'Local host'}
                      {candidate.user ? ` · ${candidate.user}` : ''}
                    </div>
                  </div>
                  <div>
                    <div className="metric-label">Command</div>
                    <div
                      style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}
                    >
                      {candidate.cmd_line || candidate.exe_path || candidate.name}
                    </div>
                  </div>
                  {onSelectProcess && (
                    <div className="btn-group" style={{ marginTop: 4 }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => onSelectProcess(candidate)}
                      >
                        {processCandidates.length === 1
                          ? 'Investigate Process'
                          : `Inspect ${candidate.display_name}`}
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="hint">
              {alert.process_resolution === 'remote_host'
                ? 'Wardex extracted process names, but this alert originated on a different host so no local PID was resolved.'
                : 'Wardex extracted process names for this alert, but no live process matched them at collection time.'}
            </div>
          )}
        </div>
      )}

      <AlertNarrative narrative={alert.narrative} />

      {/* ── Explain Alert ───────────────────────────── */}
      <div className="card" style={{ marginTop: 16 }}>
        <button
          onClick={() => setExplainOpen((v) => !v)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--primary)',
            cursor: 'pointer',
            fontWeight: 600,
            fontSize: 14,
            padding: 0,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          {explainOpen ? '▾' : '▸'} Explain this Alert
        </button>
        {explainOpen && (
          <div style={{ marginTop: 12 }}>
            {explainLoading && (
              <div style={{ marginBottom: 10, fontSize: 13, color: 'var(--text-secondary)' }}>
                Loading server-backed explainability…
              </div>
            )}
            {mitre && (
              <div style={{ marginBottom: 10 }}>
                <span className="badge badge-info" style={{ marginRight: 6 }}>
                  {mitre.technique}
                </span>
                <span style={{ fontSize: 13 }}>
                  {mitre.tactic} — {mitre.name}
                </span>
              </div>
            )}
            <ul
              style={{
                margin: '0 0 12px',
                paddingLeft: 18,
                fontSize: 13,
                lineHeight: 1.7,
                color: 'var(--text)',
              }}
            >
              {explanation.map((line, i) => (
                <li key={i}>{line}</li>
              ))}
            </ul>
            {whySafeOrNoisy.length > 0 && (
              <>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                  Why this may be safe or noisy
                </div>
                <ul
                  style={{
                    margin: '0 0 12px',
                    paddingLeft: 18,
                    fontSize: 13,
                    lineHeight: 1.7,
                    color: 'var(--text-secondary)',
                  }}
                >
                  {whySafeOrNoisy.map((line, i) => (
                    <li key={`noise-${i}`}>{line}</li>
                  ))}
                </ul>
              </>
            )}
            {entityScores.length > 0 && (
              <div style={{ margin: '12px 0' }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
                  Entity risk scoring
                </div>
                <div style={{ display: 'grid', gap: 10 }}>
                  {entityScores.slice(0, 4).map((entity) => {
                    const components = Array.isArray(entity.score_components)
                      ? entity.score_components
                      : [];
                    const sequenceSignals = Array.isArray(entity.sequence_signals)
                      ? entity.sequence_signals
                      : [];
                    const graphContext = Array.isArray(entity.graph_context)
                      ? entity.graph_context
                      : [];
                    const pivots = Array.isArray(entity.recommended_pivots)
                      ? entity.recommended_pivots
                      : [];
                    return (
                      <div
                        key={`${entity.entity_kind}-${entity.entity_id}`}
                        className="card"
                        style={{ margin: 0, padding: 12, background: 'var(--surface-muted)' }}
                      >
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            gap: 12,
                            alignItems: 'flex-start',
                            marginBottom: 6,
                          }}
                        >
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 700 }}>
                              {entity.entity_kind?.replace(/_/g, ' ') || 'entity'} ·{' '}
                              {entity.entity_id || 'unknown'}
                            </div>
                            {entity.peer_group && (
                              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                                Peer group: {entity.peer_group}
                              </div>
                            )}
                          </div>
                          <span className="badge badge-info">
                            {Number(entity.score ?? 0).toFixed(1)} / 10
                          </span>
                        </div>
                        {components.length > 0 && (
                          <div className="chip-row" style={{ marginBottom: 6 }}>
                            {components.slice(0, 4).map((component) => (
                              <span key={component.name} className="scope-chip">
                                {String(component.name || 'component').replace(/_/g, ' ')}:{' '}
                                {Number(component.score ?? 0).toFixed(1)}
                              </span>
                            ))}
                          </div>
                        )}
                        {[...sequenceSignals.slice(0, 2), ...graphContext.slice(0, 2)].length >
                          0 && (
                          <ul
                            style={{
                              margin: '6px 0',
                              paddingLeft: 18,
                              fontSize: 12,
                              lineHeight: 1.6,
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {[...sequenceSignals.slice(0, 2), ...graphContext.slice(0, 2)].map(
                              (line, i) => (
                                <li key={`${entity.entity_kind}-context-${i}`}>{line}</li>
                              ),
                            )}
                          </ul>
                        )}
                        {pivots.length > 0 && (
                          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                            Next pivot: {pivots[0]}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
              Recommended next steps
            </div>
            <ol
              style={{
                margin: 0,
                paddingLeft: 18,
                fontSize: 13,
                lineHeight: 1.7,
                color: 'var(--text-secondary)',
              }}
            >
              {nextSteps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
            {analystFeedback.length > 0 && (
              <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-secondary)' }}>
                Latest analyst feedback: {analystFeedback[0].analyst} marked this as{' '}
                {String(analystFeedback[0].verdict || '').replace(/_/g, ' ')}.
              </div>
            )}
          </div>
        )}
      </div>

      {(alert.message || alert.description) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            Narrative
          </div>
          <div style={{ lineHeight: 1.6, fontSize: 14 }}>{alert.message || alert.description}</div>
        </div>
      )}
      {reasons.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            Detection Reasons
          </div>
          <div className="chip-row">
            {reasons.map((reason) => (
              <span key={reason} className="badge badge-info">
                {reason}
              </span>
            ))}
          </div>
        </div>
      )}
      {alertHashes.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            Malware &amp; Threat Intel
          </div>
          <div className="chip-row" style={{ marginBottom: 12 }}>
            {alertHashes.slice(0, 2).map((hash) => (
              <span key={hash} className="scope-chip">
                {hash}
              </span>
            ))}
          </div>
          {artifactContextLoading ? (
            <div className="hint">Loading hash reputation and recent sightings.</div>
          ) : (
            <div style={{ display: 'grid', gap: 12 }}>
              <div className="card" style={{ margin: 0, padding: 12, background: 'var(--surface-muted)' }}>
                <div className="metric-label">Hash Reputation</div>
                {artifactContext.hashMatch ? (
                  <>
                    <div className="row-primary" style={{ marginTop: 6 }}>
                      {artifactContext.hashMatch.rule_name}
                    </div>
                    <div className="row-secondary">{artifactContext.hashMatch.detail}</div>
                    <div style={{ marginTop: 8 }}>
                      <span
                        className={`badge ${artifactContext.hashMatch.severity === 'high' || artifactContext.hashMatch.severity === 'critical' ? 'badge-err' : 'badge-info'}`}
                      >
                        {artifactContext.hashMatch.severity || 'unknown'}
                      </span>
                    </div>
                  </>
                ) : (
                  <div className="hint">No direct malware hash match was returned for this artifact.</div>
                )}
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: 12,
                }}
              >
                <div className="card" style={{ margin: 0, padding: 12, background: 'var(--surface-muted)' }}>
                  <div className="metric-label">Recent Hash Detections</div>
                  {artifactContext.recentDetections.length > 0 ? (
                    artifactContext.recentDetections.slice(0, 2).map((detection) => (
                      <div key={`${detection.sha256}-${detection.detected_at}`} style={{ marginTop: 8 }}>
                        <div className="row-primary">{detection.name || detection.family || detection.sha256}</div>
                        <div className="row-secondary">
                          {detection.family || 'unknown family'} · {detection.source || 'unknown source'}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="hint">No matching detections were found in the recent malware history.</div>
                  )}
                </div>
                <div className="card" style={{ margin: 0, padding: 12, background: 'var(--surface-muted)' }}>
                  <div className="metric-label">Recent Threat Intel Sightings</div>
                  {artifactContext.sightings.length > 0 ? (
                    artifactContext.sightings.slice(0, 2).map((sighting, index) => (
                      <div key={`${sighting.timestamp || 'sighting'}-${index}`} style={{ marginTop: 8 }}>
                        <div className="row-primary">{sighting.context || sighting.value}</div>
                        <div className="row-secondary">
                          {sighting.source || 'unknown source'} · {sighting.severity || 'unknown'}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="hint">No recent threat-intel sighting matches were found for this artifact.</div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
      <JsonDetails data={alert} label="Full alert context" />
    </SideDrawer>
  );
}

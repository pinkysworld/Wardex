import { useMemo, useState } from 'react';
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

/* ── AlertDrawer component ──────────────────────────────────── */

export default function AlertDrawer({
  alert,
  onClose,
  onUpdated,
  onPrevious,
  onNext,
  canPrevious = false,
  canNext = false,
  positionLabel = null,
}) {
  const toast = useToast();
  const [explainOpen, setExplainOpen] = useState(false);

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

  if (!alert) return null;

  const reasons = Array.isArray(alert.reasons)
    ? alert.reasons
    : alert.reasons
      ? [alert.reasons]
      : [];

  const mitre = inferMitre(alert);
  const explanation = buildExplanation(alert, mitre, reasons);
  const nextSteps = suggestNextSteps(alert, mitre);

  const markFalsePositive = async () => {
    const pattern =
      reasons.length > 0 ? reasons.join(', ') : alert.category || alert.type || 'unknown';
    try {
      await api.fpFeedback({
        alert_id: alert.id || alert.alert_id,
        pattern,
        is_false_positive: true,
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
      subtitle={`PID-free alert context · ${(alert.severity || 'unknown').toUpperCase()}`}
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
          <button className="btn btn-sm btn-primary" onClick={createIncidentFromAlert}>
            Create Incident
          </button>
        </>
      }
    >
      <SummaryGrid data={summary} limit={8} />

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
      <JsonDetails data={alert} label="Full alert context" />
    </SideDrawer>
  );
}

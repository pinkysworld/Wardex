import { useMemo } from 'react';
import { useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SideDrawer, SummaryGrid, downloadData } from './operator.jsx';

export default function AlertDrawer({ alert, onClose, onUpdated }) {
  const toast = useToast();

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

  const markFalsePositive = async () => {
    const pattern = reasons.length > 0 ? reasons.join(', ') : alert.category || alert.type || 'unknown';
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
          <button className="btn btn-sm" onClick={() => downloadData(alert, `alert-${alert.id || alert.alert_id || 'detail'}.json`)}>Export</button>
          <button className="btn btn-sm" onClick={markFalsePositive}>Mark FP</button>
          <button className="btn btn-sm btn-primary" onClick={createIncidentFromAlert}>Create Incident</button>
        </>
      }
    >
      <SummaryGrid data={summary} limit={8} />
      {(alert.message || alert.description) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>Narrative</div>
          <div style={{ lineHeight: 1.6, fontSize: 14 }}>{alert.message || alert.description}</div>
        </div>
      )}
      {reasons.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>Detection Reasons</div>
          <div className="chip-row">
            {reasons.map((reason) => (
              <span key={reason} className="badge badge-info">{reason}</span>
            ))}
          </div>
        </div>
      )}
      <JsonDetails data={alert} label="Full alert context" />
    </SideDrawer>
  );
}

import { useMemo } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SideDrawer, SummaryGrid, downloadData } from './operator.jsx';

function requestSeverity(detail) {
  const risk = (detail?.risk_level || '').toLowerCase();
  if (risk === 'critical') return 'critical';
  if (risk === 'severe') return 'high';
  if (risk === 'elevated') return 'medium';
  return 'low';
}

function buildSnapshotDetail(pid, snapshot) {
  if (!snapshot) return null;
  const name = snapshot.name || snapshot.display_name || `PID ${pid}`;
  const displayName = snapshot.display_name || String(name).split('/').pop() || `PID ${pid}`;
  const riskLevel = snapshot.risk_level || 'nominal';
  const finding = snapshot.reason ? {
    pid,
    name,
    user: snapshot.user || 'unknown',
    risk_level: riskLevel,
    reason: snapshot.reason,
    cpu_percent: snapshot.cpu_percent ?? 0,
    mem_percent: snapshot.mem_percent ?? 0,
  } : null;
  const findings = Array.isArray(snapshot.findings)
    ? snapshot.findings
    : finding
      ? [finding]
      : [];
  const recommendations = snapshot.analysis?.recommendations?.length
    ? snapshot.analysis.recommendations
    : [
        'This process exited before Wardex could collect a full live inspection.',
        'The fields below come from the last visible snapshot in the process table.',
      ];
  return {
    pid,
    ppid: snapshot.ppid ?? null,
    name,
    display_name: displayName,
    user: snapshot.user || 'unknown',
    group: snapshot.group || '—',
    cpu_percent: snapshot.cpu_percent ?? 0,
    mem_percent: snapshot.mem_percent ?? 0,
    hostname: snapshot.hostname || 'Local host',
    platform: snapshot.platform || 'macos',
    cmd_line: snapshot.cmd_line || name,
    exe_path: snapshot.exe_path || (String(name).includes('/') ? name : null),
    cwd: snapshot.cwd || null,
    start_time: snapshot.start_time || null,
    elapsed: snapshot.elapsed || null,
    risk_level: riskLevel,
    findings,
    network_activity: snapshot.network_activity || [],
    code_signature: snapshot.code_signature || null,
    analysis: {
      self_process: Boolean(snapshot.analysis?.self_process),
      listener_count: snapshot.analysis?.listener_count ?? 0,
      recommendations,
      exited_before_inspection: true,
    },
  };
}

export default function ProcessDrawer({ pid, snapshot, onClose, onUpdated }) {
  const toast = useToast();
  const { data: detail, loading, error, reload } = useApi(
    () => api.processDetail(pid),
    [pid],
    { skip: !pid }
  );
  const processGone = error?.status === 404;
  const snapshotDetail = useMemo(() => buildSnapshotDetail(pid, snapshot), [pid, snapshot]);
  const activeDetail = detail || (processGone ? snapshotDetail : null);

  const summary = useMemo(() => {
    if (!activeDetail) return null;
    return {
      pid: activeDetail.pid,
      ppid: activeDetail.ppid,
      user: activeDetail.user,
      group: activeDetail.group,
      cpu_percent: activeDetail.cpu_percent,
      mem_percent: activeDetail.mem_percent,
      hostname: activeDetail.hostname,
      platform: activeDetail.platform,
      start_time: activeDetail.start_time,
      elapsed: activeDetail.elapsed,
      risk_level: activeDetail.risk_level,
    };
  }, [activeDetail]);

  if (!pid) return null;

  const queueAction = async (body, label) => {
    try {
      const result = await api.responseRequest(body);
      const status = result?.request?.status || result?.status || 'submitted';
      toast(`${label} request ${String(status).toLowerCase()}`, 'success');
      onUpdated?.();
    } catch {
      toast(`${label} request failed`, 'error');
    }
  };

  const queueKill = async () => {
    if (!detail) return;
    if (!window.confirm(`Queue kill request for PID ${detail.pid} (${detail.display_name || detail.name})?`)) return;
    await queueAction({
      action: 'kill_process',
      pid: detail.pid,
      process_name: detail.display_name || detail.name,
      hostname: detail.hostname,
      severity: requestSeverity(detail),
      reason: `Operator-requested kill for ${(detail.display_name || detail.name)} via admin console`,
    }, 'Kill');
  };

  const queueIsolate = async () => {
    if (!detail) return;
    if (!window.confirm(`Queue host isolation for ${detail.hostname}?`)) return;
    await queueAction({
      action: 'isolate',
      hostname: detail.hostname,
      severity: requestSeverity(detail),
      reason: `Operator-requested host isolation while investigating PID ${detail.pid}`,
    }, 'Isolation');
  };

  return (
    <SideDrawer
      open={!!pid}
      onClose={onClose}
      title={activeDetail?.display_name || activeDetail?.name || `PID ${pid}`}
      subtitle={activeDetail ? `${activeDetail.platform} · ${activeDetail.hostname}` : `PID ${pid}`}
      actions={
        <>
          <button className="btn btn-sm" onClick={reload}>Refresh</button>
          {activeDetail && <button className="btn btn-sm" onClick={() => downloadData(activeDetail, `process-${activeDetail.pid}.json`)}>Export</button>}
          <button className="btn btn-sm" disabled={!detail || detail?.analysis?.self_process} onClick={queueKill}>Queue Kill</button>
          <button className="btn btn-sm btn-primary" disabled={!detail} onClick={queueIsolate}>Queue Isolate</button>
        </>
      }
    >
      {loading && <div className="loading"><div className="spinner" /></div>}
      {processGone && (
        <div className="error-box">
          This process exited before Wardex could complete a live inspection. Showing the last known snapshot from the process table.
        </div>
      )}
      {error && !processGone && <div className="error-box">Failed to load process detail.</div>}
      {activeDetail && (
        <>
          <SummaryGrid data={summary} limit={10} />

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 8 }}>Execution Context</div>
            <div className="drawer-copy-grid">
              <div>
                <div className="metric-label">Executable</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>{activeDetail.exe_path || 'Unavailable'}</div>
              </div>
              <div>
                <div className="metric-label">Working Directory</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>{activeDetail.cwd || 'Unavailable'}</div>
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <div className="metric-label">Command Line</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>{activeDetail.cmd_line || 'Unavailable'}</div>
              </div>
            </div>
          </div>

          {activeDetail.findings?.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Behavioural Findings</div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Risk</th><th>Reason</th><th>CPU</th><th>Memory</th></tr></thead>
                  <tbody>
                    {activeDetail.findings.map((finding, index) => (
                      <tr key={`${finding.pid}-${index}`}>
                        <td><span className={`sev-${finding.risk_level}`}>{finding.risk_level}</span></td>
                        <td>{finding.reason}</td>
                        <td>{finding.cpu_percent?.toFixed?.(1) ?? finding.cpu_percent}</td>
                        <td>{finding.mem_percent?.toFixed?.(1) ?? finding.mem_percent}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeDetail.analysis?.recommendations?.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Analyst Guidance</div>
              <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
                {activeDetail.analysis.recommendations.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </div>
          )}

          {activeDetail.network_activity?.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Network Activity</div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Protocol</th><th>Endpoint</th><th>State</th></tr></thead>
                  <tbody>
                    {activeDetail.network_activity.map((entry, index) => (
                      <tr key={`${entry.endpoint}-${index}`}>
                        <td>{entry.protocol}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{entry.endpoint}</td>
                        <td>{entry.state || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeDetail.code_signature && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Code Signature</div>
              <SummaryGrid data={activeDetail.code_signature} limit={6} />
            </div>
          )}

          <JsonDetails data={activeDetail} label="Deep inspection fields" />
        </>
      )}
    </SideDrawer>
  );
}

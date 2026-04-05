import { useState } from 'react';
import { useApi, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';

function Metric({ label, value, sub, accent }) {
  return (
    <div className={`card metric${accent ? ' metric-accent' : ''}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value ?? '—'}</div>
      {sub && <div className="metric-sub">{sub}</div>}
    </div>
  );
}

function SectionTitle({ children }) {
  return <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '.5px', margin: '20px 0 10px' }}>{children}</h3>;
}

export default function Dashboard() {
  const toast = useToast();
  const { data: st, loading: l1, reload: r1 } = useApi(api.status);
  const { data: fleet, reload: r2 } = useApi(api.fleetDashboard);
  const { data: alertData, reload: r3 } = useApi(api.alerts);
  const { data: telem, reload: r4 } = useApi(api.telemetryCurrent);
  const { data: hp, reload: r5 } = useApi(api.health);
  const { data: detSum, reload: r6 } = useApi(api.detectionSummary);
  const { data: tiStatus, reload: r7 } = useApi(api.threatIntelStatus);
  const { data: qStats, reload: r8 } = useApi(api.queueStats);
  const { data: respStats, reload: r9 } = useApi(api.responseStats);
  const { data: profile } = useApi(api.detectionProfile);
  const { data: procAnalysis, reload: rPA } = useApi(api.processesAnalysis);
  const { data: hostInf } = useApi(api.hostInfo);
  const [refreshing, setRefreshing] = useState(false);

  const reloadAll = async () => {
    setRefreshing(true);
    await Promise.allSettled([r1(), r2(), r3(), r4(), r5(), r6(), r7(), r8(), r9(), rPA()]);
    setRefreshing(false);
  };

  useInterval(reloadAll, 30000);

  if (l1) return <div className="loading"><div className="spinner" /> Loading dashboard…</div>;

  const alertList = Array.isArray(alertData) ? alertData : alertData?.alerts || [];
  const critical = alertList.filter(a => (a.severity || '').toLowerCase() === 'critical').length;
  const elevated = alertList.filter(a => ['elevated', 'severe', 'high'].includes((a.severity || '').toLowerCase())).length;

  return (
    <div>
      <div className="section-header">
        <h2>Security Overview</h2>
        <div className="btn-group">
          {hostInf && <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{hostInf.hostname} · {hostInf.platform} {hostInf.os_version} · {hostInf.arch}</span>}
          <button className="btn btn-sm" onClick={reloadAll} disabled={refreshing}>
            {refreshing ? 'Refreshing…' : '↻ Refresh'}
          </button>
        </div>
      </div>

      {/* ── System Health ── */}
      <SectionTitle>System Health</SectionTitle>
      <div className="card-grid">
        <Metric label="System Status" value={hp?.status === 'ok' ? '✓ Healthy' : hp?.status || '—'} sub={`Uptime: ${st?.uptime || '—'}`} accent />
        <Metric label="Active Agents" value={fleet?.total_agents ?? fleet?.agents ?? '—'} sub={fleet?.online ? `${fleet.online} online` : undefined} />
        <Metric label="Events/sec" value={telem?.events_per_sec ?? telem?.rate ?? '—'} sub={telem?.total_events ? `Total: ${telem.total_events}` : undefined} />
        <Metric label="Queue Pending" value={qStats?.pending ?? qStats?.total ?? '—'} sub={qStats?.assigned ? `${qStats.assigned} assigned` : undefined} />
      </div>

      {/* ── Threat Overview ── */}
      <SectionTitle>Threat Overview</SectionTitle>
      <div className="card-grid">
        <Metric label="Total Alerts" value={alertList.length} sub={`${critical} critical · ${elevated} elevated`} />
        <Metric label="Detection Profile" value={profile?.profile || '—'} sub={profile?.description} />
        <Metric label="Threat Intel IoCs" value={tiStatus?.total_iocs ?? tiStatus?.ioc_count ?? '—'} sub={tiStatus?.active_feeds ? `${tiStatus.active_feeds} feeds` : undefined} />
        <Metric label="Response Actions" value={respStats?.total ?? '—'} sub={respStats?.pending ? `${respStats.pending} pending` : undefined} />
      </div>

      {/* ── Process Security ── */}
      {procAnalysis && (
        <>
          <SectionTitle>Process Security</SectionTitle>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">
                Process Analysis — {procAnalysis.process_count || 0} running
              </span>
              <span className={`badge ${procAnalysis.status === 'clean' ? 'badge-ok' : procAnalysis.status === 'critical' ? 'badge-err' : 'badge-warn'}`}>
                {procAnalysis.status === 'clean' ? '✓ Clean' : `⚠ ${procAnalysis.total || 0} finding(s)`}
              </span>
            </div>
            {procAnalysis.findings?.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>PID</th><th>Process</th><th>User</th><th>Risk</th><th>Reason</th><th>CPU%</th><th>Mem%</th></tr></thead>
                  <tbody>
                    {procAnalysis.findings.map((f, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{f.pid}</td>
                        <td><strong>{f.name}</strong></td>
                        <td>{f.user}</td>
                        <td><span className={`sev-${f.risk_level}`}>{f.risk_level}</span></td>
                        <td style={{ fontSize: 12 }}>{f.reason}</td>
                        <td>{f.cpu_percent?.toFixed(1)}</td>
                        <td>{f.mem_percent?.toFixed(1)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty" style={{ padding: 12 }}>No suspicious processes detected</div>
            )}
          </div>
        </>
      )}

      {/* ── Detection Summary ── */}
      {detSum && (
        <>
          <SectionTitle>Detection Engine</SectionTitle>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header"><span className="card-title">Detection Summary</span></div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10, padding: '12px 0' }}>
              {Object.entries(detSum).filter(([k]) => typeof detSum[k] !== 'object').map(([k, v]) => (
                <div key={k} style={{ textAlign: 'center' }}>
                  <div className="metric-label">{k.replace(/_/g, ' ')}</div>
                  <div style={{ fontSize: 18, fontWeight: 600 }}>{typeof v === 'boolean' ? (v ? '✓' : '✗') : v}</div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* ── Recent Alerts ── */}
      <SectionTitle>Recent Alerts</SectionTitle>
      <div className="card">
        <div className="card-header">
          <span className="card-title">Latest ({Math.min(alertList.length, 25)} of {alertList.length})</span>
          <button className="btn btn-sm btn-danger" onClick={async () => {
            try { await api.alertsClear(); toast('Alerts cleared', 'success'); r3(); } catch { toast('Failed to clear alerts', 'error'); }
          }}>Clear All</button>
        </div>
        {alertList.length === 0 ? (
          <div className="empty">No alerts — system is quiet</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Message</th></tr></thead>
              <tbody>
                {alertList.slice(0, 25).map((a, i) => (
                  <tr key={i}>
                    <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{a.timestamp || a.time || '—'}</td>
                    <td><span className={`sev-${(a.severity || 'low').toLowerCase()}`}>{a.severity || '—'}</span></td>
                    <td>{a.category || a.type || '—'}</td>
                    <td style={{ fontSize: 13 }}>{a.message || a.description || JSON.stringify(a).slice(0, 120)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

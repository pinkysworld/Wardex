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
  const [refreshing, setRefreshing] = useState(false);

  const reloadAll = async () => {
    setRefreshing(true);
    await Promise.allSettled([r1(), r2(), r3(), r4(), r5(), r6(), r7(), r8(), r9()]);
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
        <button className="btn btn-sm" onClick={reloadAll} disabled={refreshing}>
          {refreshing ? 'Refreshing…' : '↻ Refresh'}
        </button>
      </div>

      {/* KPI Row */}
      <div className="card-grid">
        <Metric label="System Health" value={hp?.status === 'ok' ? '✓ Healthy' : hp?.status || '—'} sub={`Uptime: ${st?.uptime || '—'}`} accent />
        <Metric label="Total Alerts" value={alertList.length} sub={`${critical} critical · ${elevated} elevated`} />
        <Metric label="Active Agents" value={fleet?.total_agents ?? fleet?.agents ?? '—'} sub={fleet?.online ? `${fleet.online} online` : undefined} />
        <Metric label="Events/sec" value={telem?.events_per_sec ?? telem?.rate ?? '—'} sub={telem?.total_events ? `Total: ${telem.total_events}` : undefined} />
      </div>

      <div className="card-grid">
        <Metric label="Detection Profile" value={profile?.profile || '—'} sub={profile?.description} />
        <Metric label="Threat Intel IoCs" value={tiStatus?.total_iocs ?? tiStatus?.ioc_count ?? '—'} sub={tiStatus?.active_feeds ? `${tiStatus.active_feeds} feeds` : undefined} />
        <Metric label="Queue Pending" value={qStats?.pending ?? qStats?.total ?? '—'} sub={qStats?.assigned ? `${qStats.assigned} assigned` : undefined} />
        <Metric label="Response Actions" value={respStats?.total ?? '—'} sub={respStats?.pending ? `${respStats.pending} pending` : undefined} />
      </div>

      {/* Detection Summary */}
      {detSum && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header"><span className="card-title">Detection Summary</span></div>
          <div className="json-block">{JSON.stringify(detSum, null, 2)}</div>
        </div>
      )}

      {/* Recent Alerts */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Recent Alerts ({alertList.length})</span>
          <button className="btn btn-sm btn-danger" onClick={async () => {
            try { await api.alertsClear(); toast('Alerts cleared', 'success'); r3(); } catch { toast('Failed to clear alerts', 'error'); }
          }}>Clear All</button>
        </div>
        {alertList.length === 0 ? (
          <div className="empty">No alerts</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Message</th></tr></thead>
              <tbody>
                {alertList.slice(0, 50).map((a, i) => (
                  <tr key={i}>
                    <td style={{ whiteSpace: 'nowrap' }}>{a.timestamp || a.time || '—'}</td>
                    <td><span className={`sev-${(a.severity || 'low').toLowerCase()}`}>{a.severity || '—'}</span></td>
                    <td>{a.category || a.type || '—'}</td>
                    <td>{a.message || a.description || JSON.stringify(a).slice(0, 120)}</td>
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

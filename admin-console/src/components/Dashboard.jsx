import { useState, useMemo } from 'react';
import { useApi, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import AlertDrawer from './AlertDrawer.jsx';
import ProcessDrawer from './ProcessDrawer.jsx';
import DashboardWidget, { useWidgetLayout } from './DashboardWidget.jsx';

function Metric({ label, value, sub, accent, onClick }) {
  return (
    <div className={`card metric${accent ? ' metric-accent' : ''}`}
      style={onClick ? { cursor: 'pointer' } : undefined} onClick={onClick}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value ?? '—'}</div>
      {sub && <div className="metric-sub">{sub}</div>}
    </div>
  );
}

const SEV_COLORS = { critical: '#ef4444', severe: '#f97316', elevated: '#eab308', high: '#f97316', medium: '#3b82f6', low: '#6b7280' };

function alertSeverity(alert) {
  return (alert?.severity || alert?.level || alert?.risk_level || 'unknown').toLowerCase();
}

function alertCategory(alert) {
  return alert?.category || alert?.type || alert?.alert_origin || alert?.action || 'Signal';
}

function alertNarrative(alert) {
  if (!alert) return 'Open alert details';
  if (alert.message) return alert.message;
  if (alert.description) return alert.description;
  if (alert.summary) return alert.summary;
  if (Array.isArray(alert.reasons) && alert.reasons.length > 0) return alert.reasons.join(', ');
  if (alert.reason) return alert.reason;
  if (alert.action && alert.score != null) return `${alert.action} · score ${Number(alert.score).toFixed(2)}`;
  if (alert.action) return alert.action;
  if (alert.alert_origin) return `Origin: ${alert.alert_origin}`;
  return 'Open alert details';
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
  const { data: telemHistory } = useApi(api.telemetryHistory);
  // Phase 44: additional dashboard data
  const { data: mwStats, reload: rMW } = useApi(api.malwareStats);
  const { data: gaps, reload: rGap } = useApi(api.coverageGaps);
  const { data: qrStats, reload: rQR } = useApi(api.quarantineStats);
  const { data: lcStats, reload: rLC } = useApi(api.lifecycleStats);
  const { data: fdStats, reload: rFD } = useApi(api.feedStats);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedAlert, setExpandedAlert] = useState(null);
  const [sevFilter, setSevFilter] = useState('all');
  const [selectedProcess, setSelectedProcess] = useState(null);
  const { data: dnsSummary, reload: rDNS } = useApi(api.dnsThreatSummary);

  const defaultWidgets = ['system-health', 'telemetry', 'threat-overview', 'charts', 'process-security', 'detection-engine', 'malware-ti', 'dns-threats', 'lifecycle', 'recent-alerts'];
  const { order, hidden, moveWidget, removeWidget, restoreWidget, resetLayout } = useWidgetLayout(defaultWidgets, 'dashboard');

  const reloadAll = async () => {
    setRefreshing(true);
    await Promise.allSettled([r1(), r2(), r3(), r4(), r5(), r6(), r7(), r8(), r9(), rPA(), rMW(), rGap(), rQR(), rLC(), rFD(), rDNS()]);
    setRefreshing(false);
  };

  useInterval(reloadAll, 30000);

  const alertList = Array.isArray(alertData) ? alertData : alertData?.alerts || [];
  const critical = alertList.filter(a => alertSeverity(a) === 'critical').length;
  const elevated = alertList.filter(a => ['elevated', 'severe', 'high'].includes(alertSeverity(a))).length;

  // Severity breakdown for pie chart
  const sevBreakdown = useMemo(() => {
    const counts = {};
    alertList.forEach(a => {
      const s = alertSeverity(a);
      counts[s] = (counts[s] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [alertList]);

  // Alert timeline data (last 24 hours bucketed into ~12 intervals)
  const alertTimeline = useMemo(() => {
    if (!alertList.length) return [];
    const now = Date.now();
    const buckets = 12;
    const interval = 2 * 60 * 60 * 1000; // 2 hours
    const data = [];
    for (let i = buckets - 1; i >= 0; i--) {
      const start = now - (i + 1) * interval;
      const end = now - i * interval;
      const count = alertList.filter(a => {
        const t = new Date(a.timestamp || a.time || 0).getTime();
        return t >= start && t < end;
      }).length;
      const label = new Date(end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      data.push({ time: label, alerts: count });
    }
    return data;
  }, [alertList]);

  // Telemetry history for area chart
  const telemChart = useMemo(() => {
    if (!telemHistory) return [];
    const arr = Array.isArray(telemHistory) ? telemHistory : telemHistory?.samples || telemHistory?.history || [];
    return arr.slice(-30).map((s, i) => ({
      t: i,
      cpu: s.cpu_load_pct ?? s.cpu,
      mem: s.memory_load_pct ?? s.memory,
      net: s.network_kbps ?? s.network,
    }));
  }, [telemHistory]);

  // Filtered alerts
  const filteredAlerts = sevFilter === 'all' ? alertList : alertList.filter(a =>
    alertSeverity(a) === sevFilter
  );
  const selectedAlert = expandedAlert == null
    ? null
    : filteredAlerts.find((a, i) => (a.id || a.alert_id || `alert-${i}`) === expandedAlert);
  const openProcess = (process) => setSelectedProcess(process ? { ...process } : null);

  if (l1) return <div className="loading"><div className="spinner" /> Loading dashboard…</div>;

  return (
    <div>
      <div className="section-header">
        <h2>Security Overview</h2>
        <div className="btn-group">
          {hostInf && <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{hostInf.hostname} · {hostInf.platform} {hostInf.os_version} · {hostInf.arch}</span>}
          <button className="btn btn-sm" onClick={reloadAll} disabled={refreshing}>
            {refreshing ? 'Refreshing…' : '↻ Refresh'}
          </button>
          <button className="btn btn-sm" onClick={resetLayout} title="Reset widget layout">⊞ Reset Layout</button>
        </div>
      </div>

      {order.map(wid => {
        if (wid === 'system-health') return (
      <DashboardWidget key={wid} id={wid} title="System Health" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
      <div className="card-grid">
        <Metric label="System Status" value={hp?.status === 'ok' ? '✓ Healthy' : hp?.status || '—'} sub={`Uptime: ${st?.uptime || '—'}`} accent />
        <Metric label="Active Agents" value={fleet?.total_agents ?? fleet?.agents ?? '—'} sub={fleet?.online ? `${fleet.online} online` : undefined} />
        <Metric label="Events/sec" value={telem?.events_per_sec ?? telem?.rate ?? '—'} sub={telem?.total_events ? `Total: ${telem.total_events}` : undefined} />
        <Metric label="Queue Pending" value={qStats?.pending ?? qStats?.total ?? '—'} sub={qStats?.assigned ? `${qStats.assigned} assigned` : undefined} />
      </div>
      </DashboardWidget>
        );
        if (wid === 'telemetry' && telemChart.length > 0) return (
      <DashboardWidget key={wid} id={wid} title="System Telemetry" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
          <div className="card" style={{ padding: '12px 8px', marginBottom: 16 }}>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={telemChart}>
                <XAxis dataKey="t" tick={false} />
                <YAxis width={35} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }} />
                <Area type="monotone" dataKey="cpu" name="CPU %" stroke="#3b82f6" fill="#3b82f680" strokeWidth={2} />
                <Area type="monotone" dataKey="mem" name="Memory %" stroke="#8b5cf6" fill="#8b5cf680" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
      </DashboardWidget>
        );
        if (wid === 'threat-overview') return (
      <DashboardWidget key={wid} id={wid} title="Threat Overview" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
      <div className="card-grid">
        <Metric label="Total Alerts" value={alertList.length} sub={`${critical} critical · ${elevated} elevated`} />
        <Metric label="Detection Profile" value={profile?.profile || '—'} sub={profile?.description} />
        <Metric label="Threat Intel IoCs" value={tiStatus?.total_iocs ?? tiStatus?.ioc_count ?? '—'} sub={tiStatus?.active_feeds ? `${tiStatus.active_feeds} feeds` : undefined} />
        <Metric label="Response Actions" value={respStats?.total ?? '—'} sub={respStats?.pending ? `${respStats.pending} pending` : undefined} />
      </div>
      </DashboardWidget>
        );
        if (wid === 'charts' && (alertTimeline.length > 0 || sevBreakdown.length > 0)) return (
      <DashboardWidget key={wid} id={wid} title="Alert Charts" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
        <div className="card-grid" style={{ marginTop: 12, marginBottom: 16 }}>
          {alertTimeline.length > 0 && (
            <div className="card" style={{ padding: '12px 8px', gridColumn: sevBreakdown.length > 0 ? 'span 2' : 'span 3' }}>
              <div className="card-title" style={{ marginBottom: 8, paddingLeft: 8 }}>Alert Timeline (24h)</div>
              <ResponsiveContainer width="100%" height={140}>
                <BarChart data={alertTimeline}>
                  <XAxis dataKey="time" tick={{ fontSize: 10 }} interval={1} />
                  <YAxis width={25} tick={{ fontSize: 10 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }} />
                  <Bar dataKey="alerts" fill="#3b82f6" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
          {sevBreakdown.length > 0 && (
            <div className="card" style={{ padding: '12px 8px' }}>
              <div className="card-title" style={{ marginBottom: 8, paddingLeft: 8 }}>By Severity</div>
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie data={sevBreakdown} cx="50%" cy="50%" outerRadius={50} innerRadius={25} paddingAngle={2} dataKey="value" label={({ name, value }) => `${name} (${value})`} style={{ fontSize: 10 }}>
                    {sevBreakdown.map((entry, i) => (
                      <Cell key={i} fill={SEV_COLORS[entry.name] || '#6b7280'} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </DashboardWidget>
        );
        if (wid === 'process-security' && procAnalysis) return (
      <DashboardWidget key={wid} id={wid} title="Process Security" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
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
                  <thead><tr><th>PID</th><th>Process</th><th>User</th><th>Risk</th><th>Reason</th><th>CPU%</th><th>Mem%</th><th>Actions</th></tr></thead>
                  <tbody>
                    {procAnalysis.findings.map((f, i) => (
                      <tr key={i} style={{ cursor: 'pointer' }}
                        onClick={() => openProcess(f)}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{f.pid}</td>
                        <td><strong>{f.name}</strong></td>
                        <td>{f.user}</td>
                        <td><span className={`sev-${f.risk_level}`}>{f.risk_level}</span></td>
                        <td style={{ fontSize: 12 }}>{f.reason}</td>
                        <td>{f.cpu_percent?.toFixed(1)}</td>
                        <td>{f.mem_percent?.toFixed(1)}</td>
                        <td>
                          <button className="btn btn-sm" onClick={(event) => {
                            event.stopPropagation();
                            openProcess(f);
                          }}>
                            Investigate
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty" style={{ padding: 12 }}>No suspicious processes detected</div>
            )}
          </div>
      </DashboardWidget>
        );
        if (wid === 'detection-engine' && detSum) return (
      <DashboardWidget key={wid} id={wid} title="Detection Engine" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
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
      </DashboardWidget>
        );
        if (wid === 'malware-ti') return (
      <DashboardWidget key={wid} id={wid} title="Malware & Threat Intelligence" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
      <div className="card-grid">
        <Metric label="Malware DB" value={mwStats?.database?.total_entries ?? '—'} sub={mwStats?.scanner?.total_scans ? `${mwStats.scanner.total_scans} scans` : undefined} />
        <Metric label="YARA Rules" value={mwStats?.yara_rules ?? '—'} sub={mwStats?.scanner?.malicious_count ? `${mwStats.scanner.malicious_count} detections` : undefined} />
        <Metric label="Quarantined" value={qrStats?.total ?? '—'} sub={qrStats?.pending_review ? `${qrStats.pending_review} pending review` : undefined} accent={qrStats?.total > 0} />
        <Metric label="Feed Sources" value={fdStats?.total_sources ?? '—'} sub={fdStats?.active_sources ? `${fdStats.active_sources} active` : undefined} />
      </div>
      </DashboardWidget>
        );
        if (wid === 'dns-threats') return (
      <DashboardWidget key={wid} id={wid} title="DNS Threat Intelligence" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
      <div className="card-grid">
        <Metric label="Domains Analyzed" value={dnsSummary?.domains_analyzed ?? '—'} sub={dnsSummary?.threats_detected ? `${dnsSummary.threats_detected} threats` : undefined} />
        <Metric label="DGA Suspects" value={dnsSummary?.dga_suspects ?? '—'} accent={dnsSummary?.dga_suspects > 0} />
        <Metric label="Tunnel Suspects" value={dnsSummary?.tunnel_suspects ?? '—'} accent={dnsSummary?.tunnel_suspects > 0} />
        <Metric label="Fast-Flux" value={dnsSummary?.fast_flux_suspects ?? '—'} accent={dnsSummary?.fast_flux_suspects > 0} />
      </div>
      </DashboardWidget>
        );
        if (wid === 'lifecycle' && (lcStats || gaps)) return (
      <DashboardWidget key={wid} id={wid} title="Fleet Lifecycle & Coverage" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
          <div className="card-grid">
            {lcStats && <Metric label="Active Agents" value={lcStats.active ?? '—'} sub={lcStats.stale ? `${lcStats.stale} stale · ${lcStats.offline ?? 0} offline` : undefined} />}
            {lcStats && <Metric label="Archived" value={lcStats.archived ?? 0} sub={lcStats.decommissioned ? `${lcStats.decommissioned} decommissioned` : undefined} />}
            {gaps && <Metric label="ATT&CK Gaps" value={gaps.total_gaps ?? gaps.gaps?.length ?? '—'} sub={gaps.critical_gaps != null ? `${gaps.critical_gaps} critical` : undefined} accent={gaps.total_gaps > 0 || (gaps.gaps?.length > 0)} />}
            {fdStats && <Metric label="IoCs Ingested" value={fdStats.total_iocs_ingested ?? '—'} sub={fdStats.total_hashes_imported ? `${fdStats.total_hashes_imported} hashes` : undefined} />}
          </div>
      </DashboardWidget>
        );
        if (wid === 'recent-alerts') return (
      <DashboardWidget key={wid} id={wid} title="Recent Alerts" index={order.indexOf(wid)} onMove={moveWidget} onRemove={removeWidget}>
      <div className="card">
        <div className="card-header">
          <span className="card-title">Latest ({Math.min(filteredAlerts.length, 25)} of {alertList.length})</span>
          <div className="btn-group">
            {['all', 'critical', 'severe', 'elevated', 'low'].map(s => (
              <button key={s} className={`btn btn-sm ${sevFilter === s ? 'btn-primary' : ''}`} onClick={() => setSevFilter(s)}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
            <button className="btn btn-sm btn-danger" onClick={async () => {
              try { await api.alertsClear(); toast('Alerts cleared', 'success'); r3(); } catch { toast('Failed to clear alerts', 'error'); }
            }}>Clear All</button>
          </div>
        </div>
        {filteredAlerts.length === 0 ? (
          <div className="empty">No alerts{sevFilter !== 'all' ? ` matching "${sevFilter}"` : ''} — system is quiet</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Message</th><th>Actions</th></tr></thead>
              <tbody>
                {filteredAlerts.slice(0, 25).map((a, i) => {
                  const aid = a.id || a.alert_id || `alert-${i}`;
                  return (
                    <tr key={aid} style={{ cursor: 'pointer', background: expandedAlert === aid ? 'rgba(59,130,246,.08)' : undefined }}
                      onClick={() => setExpandedAlert(aid)}>
                      <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{a.timestamp || a.time || '—'}</td>
                      <td><span className={`sev-${alertSeverity(a)}`}>{alertSeverity(a)}</span></td>
                      <td>{alertCategory(a)}</td>
                      <td style={{ fontSize: 13 }}>{alertNarrative(a)}</td>
                      <td>
                        <button className="btn btn-sm" onClick={(event) => {
                          event.stopPropagation();
                          setExpandedAlert(aid);
                        }}>
                          Investigate
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      </DashboardWidget>
        );
        return null;
      })}

      {/* Restore removed widgets */}
      {hidden.size > 0 && (
        <div style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Hidden widgets:</span>
          {[...hidden].map(w => (
            <button key={w} className="btn btn-sm" onClick={() => restoreWidget(w)}>
              + {w.replace(/-/g, ' ')}
            </button>
          ))}
        </div>
      )}

      <AlertDrawer alert={selectedAlert} onClose={() => setExpandedAlert(null)} onUpdated={reloadAll} />
      <ProcessDrawer
        pid={selectedProcess?.pid}
        snapshot={selectedProcess}
        onClose={() => setSelectedProcess(null)}
        onUpdated={reloadAll}
      />
    </div>
  );
}

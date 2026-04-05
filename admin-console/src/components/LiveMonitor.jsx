import { useState } from 'react';
import { useApi, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';

export default function LiveMonitor() {
  const toast = useToast();
  const { data: alertData, loading, reload } = useApi(api.alerts);
  const { data: countData, reload: reloadCount } = useApi(api.alertsCount);
  const { data: grouped, reload: reloadGrouped } = useApi(api.alertsGrouped);
  const { data: hp } = useApi(api.health);
  const { data: procData, reload: reloadProcs } = useApi(api.processesLive);
  const { data: procAnalysis, reload: reloadPA } = useApi(api.processesAnalysis);
  const [selectedId, setSelectedId] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [tab, setTab] = useState('stream');
  const [procSort, setProcSort] = useState('cpu');
  const [procFilter, setProcFilter] = useState('');

  const reloadAll = () => { reload(); reloadCount(); reloadGrouped(); };
  useInterval(reloadAll, 10000);

  const alertList = Array.isArray(alertData) ? alertData : alertData?.alerts || [];

  // Process list with sorting and filtering
  const procList = (() => {
    let list = procData?.processes || [];
    if (procFilter) {
      const f = procFilter.toLowerCase();
      list = list.filter(p => p.name?.toLowerCase().includes(f) || p.user?.toLowerCase().includes(f) || String(p.pid).includes(f));
    }
    if (procSort === 'cpu') list = [...list].sort((a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0));
    else if (procSort === 'mem') list = [...list].sort((a, b) => (b.mem_percent || 0) - (a.mem_percent || 0));
    else if (procSort === 'name') list = [...list].sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    else if (procSort === 'pid') list = [...list].sort((a, b) => a.pid - b.pid);
    return list;
  })();

  return (
    <div>
      <div className="section-header">
        <h2>Live Alert Stream</h2>
        <div className="btn-group">
          <span className={`badge ${hp?.status === 'ok' ? 'badge-ok' : 'badge-err'}`}>
            {hp?.status === 'ok' ? 'System Healthy' : 'Degraded'}
          </span>
          <span className="badge badge-info">
            {countData == null ? '…' : (typeof countData === 'object' ? countData.count : countData)} alerts
          </span>
          <button className="btn btn-sm" onClick={reloadAll}>↻ Refresh</button>
        </div>
      </div>

      <div className="tabs">
        <button className={`tab ${tab === 'stream' ? 'active' : ''}`} onClick={() => setTab('stream')}>Alert Stream</button>
        <button className={`tab ${tab === 'grouped' ? 'active' : ''}`} onClick={() => setTab('grouped')}>Grouped</button>
        <button className={`tab ${tab === 'analysis' ? 'active' : ''}`} onClick={() => setTab('analysis')}>Analysis</button>
        <button className={`tab ${tab === 'processes' ? 'active' : ''}`} onClick={() => setTab('processes')}>Processes</button>
      </div>

      {loading && <div className="loading"><div className="spinner" /></div>}

      {tab === 'stream' && !loading && (
        <div className="card">
          {alertList.length === 0 ? <div className="empty">No alerts — system is quiet</div> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Category</th><th>Message</th><th>Actions</th></tr></thead>
                <tbody>
                  {alertList.map((a, i) => {
                    const aid = a.id || a.alert_id || `${a.timestamp}-${i}`;
                    return (
                    <tr key={aid} style={selectedId === aid ? { background: 'rgba(59,130,246,.08)' } : undefined}>
                      <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{a.timestamp || a.time || '—'}</td>
                      <td><span className={`sev-${(a.severity || 'low').toLowerCase()}`}>{a.severity}</span></td>
                      <td>{a.source || '—'}</td>
                      <td>{a.category || a.type || '—'}</td>
                      <td>{a.message || a.description || '—'}</td>
                      <td>
                        <button className="btn btn-sm" onClick={() => setSelectedId(selectedId === aid ? null : aid)}>
                          {selectedId === aid ? 'Hide' : 'Details'}
                        </button>
                      </td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {selectedId !== null && (() => {
            const sel = alertList.find((a, i) => (a.id || a.alert_id || `${a.timestamp}-${i}`) === selectedId);
            return sel ? (
            <div style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Alert Detail</div>
              <div className="json-block">{JSON.stringify(sel, null, 2)}</div>
            </div>
            ) : null;
          })()}
        </div>
      )}

      {tab === 'grouped' && (
        <div className="card">
          {!grouped || (Array.isArray(grouped) && grouped.length === 0) ? <div className="empty">No grouped data</div> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Group</th><th>Severity</th><th>Count</th><th>Avg Score</th><th>Max Score</th><th>First Seen</th><th>Last Seen</th><th>Reasons</th></tr></thead>
                <tbody>
                  {(Array.isArray(grouped) ? grouped : []).map(g => (
                    <tr key={g.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>#{g.id}</td>
                      <td><span className={`sev-${(g.level || 'low').toLowerCase()}`}>{g.level}</span></td>
                      <td><strong>{g.count}</strong></td>
                      <td>{g.avg_score?.toFixed(2)}</td>
                      <td>{g.max_score?.toFixed(2)}</td>
                      <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{g.first_seen || '—'}</td>
                      <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{g.last_seen || '—'}</td>
                      <td style={{ fontSize: 12 }}>{(g.representative_reasons || []).join(', ') || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'analysis' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Alert Analysis</span>
            <button className="btn btn-sm btn-primary" onClick={async () => {
              try {
                const r = await api.alertsAnalysis({});
                setAnalysisResult(r);
                toast('Analysis complete', 'success');
              } catch { toast('Analysis failed', 'error'); }
            }}>Run Analysis</button>
          </div>
          {analysisResult ? (
            <div>
              {analysisResult.summary && (
                <div style={{ padding: '12px 16px', background: 'var(--bg)', borderRadius: 'var(--radius)', marginBottom: 16, lineHeight: 1.6 }}>
                  {analysisResult.summary}
                </div>
              )}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 16 }}>
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Total Alerts</div>
                  <div style={{ fontSize: 24, fontWeight: 700 }}>{analysisResult.total_alerts}</div>
                </div>
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Pattern</div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>
                    {typeof analysisResult.pattern === 'string' ? analysisResult.pattern : analysisResult.pattern?.Sustained?.severity ? `Sustained ${analysisResult.pattern.Sustained.severity}` : JSON.stringify(analysisResult.pattern)}
                  </div>
                </div>
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Score Trend</div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>
                    {analysisResult.score_trend?.Rising ? `Rising (+${analysisResult.score_trend.Rising.slope})` :
                     analysisResult.score_trend?.Falling ? `Declining (${analysisResult.score_trend.Falling.slope})` :
                     analysisResult.score_trend === 'Volatile' ? 'Volatile' : 'Stable'}
                  </div>
                </div>
                {analysisResult.severity_breakdown && (
                  <div className="card" style={{ padding: 12 }}>
                    <div className="metric-label">Severity</div>
                    <div style={{ fontSize: 13 }}>
                      <span className="sev-critical">{analysisResult.severity_breakdown.critical}</span> critical,{' '}
                      <span className="sev-severe">{analysisResult.severity_breakdown.severe}</span> severe,{' '}
                      <span className="sev-elevated">{analysisResult.severity_breakdown.elevated}</span> elevated
                    </div>
                  </div>
                )}
              </div>
              {analysisResult.dominant_reasons?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>Top Detection Reasons</div>
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Reason</th><th>Count</th></tr></thead>
                      <tbody>
                        {analysisResult.dominant_reasons.map(([reason, count], i) => (
                          <tr key={i}><td>{reason}</td><td>{count}</td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              {analysisResult.isolation_guidance?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>Isolation &amp; Response Guidance</div>
                  {analysisResult.isolation_guidance.map((g, i) => (
                    <div key={i} style={{ padding: '10px 14px', background: 'var(--bg)', borderRadius: 'var(--radius)', marginBottom: 8, borderLeft: '3px solid var(--warning)' }}>
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>{g.reason}</div>
                      <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 6 }}>{g.threat_description}</div>
                      <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
                        {g.steps.map((step, j) => <li key={j}>{step}</li>)}
                      </ul>
                    </div>
                  ))}
                </div>
              )}
              <details>
                <summary style={{ cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)' }}>Raw JSON</summary>
                <div className="json-block" style={{ marginTop: 8 }}>{JSON.stringify(analysisResult, null, 2)}</div>
              </details>
            </div>
          ) : (
            <div className="empty">Click "Run Analysis" to analyze current alert patterns</div>
          )}
        </div>
      )}

      {tab === 'processes' && (
        <div>
          {/* Process summary + controls */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Running Processes</span>
              <div className="btn-group">
                <button className="btn btn-sm" onClick={() => { reloadProcs(); reloadPA(); }}>↻ Refresh</button>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, marginBottom: 12 }}>
              <div className="card" style={{ padding: 10 }}>
                <div className="metric-label">Process Count</div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>{procData?.count ?? '—'}</div>
              </div>
              <div className="card" style={{ padding: 10 }}>
                <div className="metric-label">Total CPU</div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>{procData?.total_cpu_percent != null ? `${procData.total_cpu_percent.toFixed(1)}%` : '—'}</div>
              </div>
              <div className="card" style={{ padding: 10 }}>
                <div className="metric-label">Total Memory</div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>{procData?.total_mem_percent != null ? `${procData.total_mem_percent.toFixed(1)}%` : '—'}</div>
              </div>
              <div className="card" style={{ padding: 10 }}>
                <div className="metric-label">Findings</div>
                <div style={{ fontSize: 22, fontWeight: 700, color: (procAnalysis?.total || 0) > 0 ? 'var(--danger)' : 'var(--success)' }}>
                  {procAnalysis?.total ?? '—'}
                </div>
              </div>
            </div>

            {/* Sort + Filter controls */}
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Sort:</span>
              {['cpu', 'mem', 'name', 'pid'].map(s => (
                <button key={s} className={`btn btn-sm ${procSort === s ? 'btn-primary' : ''}`} onClick={() => setProcSort(s)}>
                  {s === 'cpu' ? 'CPU ↓' : s === 'mem' ? 'Memory ↓' : s === 'name' ? 'Name A-Z' : 'PID'}
                </button>
              ))}
              <input
                type="text"
                placeholder="Filter by name, user, or PID…"
                value={procFilter}
                onChange={e => setProcFilter(e.target.value)}
                style={{ marginLeft: 'auto', padding: '4px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13, minWidth: 200 }}
              />
            </div>
          </div>

          {/* Security findings */}
          {procAnalysis?.findings?.length > 0 && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Security Findings</div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Risk</th><th>PID</th><th>Process</th><th>User</th><th>CPU</th><th>Mem</th><th>Reason</th></tr></thead>
                  <tbody>
                    {procAnalysis.findings.map((f, i) => (
                      <tr key={i} style={{ background: f.risk_level === 'critical' ? 'rgba(239,68,68,.06)' : f.risk_level === 'high' ? 'rgba(249,115,22,.06)' : undefined }}>
                        <td><span className={`sev-${f.risk_level}`}>{f.risk_level}</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{f.pid}</td>
                        <td style={{ fontWeight: 600 }}>{f.name}</td>
                        <td>{f.user}</td>
                        <td>{f.cpu_percent?.toFixed(1)}%</td>
                        <td>{f.mem_percent?.toFixed(1)}%</td>
                        <td style={{ fontSize: 12 }}>{f.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Process table */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>
              All Processes {procFilter && <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>({procList.length} matching)</span>}
            </div>
            {procList.length === 0 ? (
              <div className="empty">{procData?.message || 'No process data available'}</div>
            ) : (
              <div className="table-wrap" style={{ maxHeight: 500, overflowY: 'auto' }}>
                <table>
                  <thead style={{ position: 'sticky', top: 0, background: 'var(--card-bg)', zIndex: 1 }}>
                    <tr>
                      <th style={{ cursor: 'pointer' }} onClick={() => setProcSort('pid')}>PID{procSort === 'pid' ? ' ↓' : ''}</th>
                      <th>PPID</th>
                      <th style={{ cursor: 'pointer' }} onClick={() => setProcSort('name')}>Name{procSort === 'name' ? ' ↓' : ''}</th>
                      <th>User</th>
                      <th>Group</th>
                      <th style={{ cursor: 'pointer' }} onClick={() => setProcSort('cpu')}>CPU %{procSort === 'cpu' ? ' ↓' : ''}</th>
                      <th style={{ cursor: 'pointer' }} onClick={() => setProcSort('mem')}>Mem %{procSort === 'mem' ? ' ↓' : ''}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {procList.slice(0, 200).map(p => (
                      <tr key={p.pid}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{p.pid}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{p.ppid ?? '—'}</td>
                        <td style={{ fontWeight: p.cpu_percent > 50 ? 700 : 400 }}>{p.name}</td>
                        <td>{p.user}</td>
                        <td>{p.group || '—'}</td>
                        <td style={{ color: p.cpu_percent > 50 ? 'var(--danger)' : undefined }}>{p.cpu_percent?.toFixed(1)}</td>
                        <td style={{ color: p.mem_percent > 30 ? 'var(--warning)' : undefined }}>{p.mem_percent?.toFixed(1)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {procList.length > 200 && (
                  <div style={{ padding: 8, textAlign: 'center', fontSize: 12, color: 'var(--text-secondary)' }}>
                    Showing 200 of {procList.length} processes. Use filter to narrow results.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

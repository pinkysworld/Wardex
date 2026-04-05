import { useState } from 'react';
import { useApi, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';

export default function LiveMonitor() {
  const toast = useToast();
  const { data: alertData, loading, reload } = useApi(api.alerts);
  const { data: countData, reload: reloadCount } = useApi(api.alertsCount);
  const { data: grouped, reload: reloadGrouped } = useApi(api.alertsGrouped);
  const { data: hp } = useApi(api.health);
  const [selectedId, setSelectedId] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [tab, setTab] = useState('stream');

  const reloadAll = () => { reload(); reloadCount(); reloadGrouped(); };
  useInterval(reloadAll, 10000);

  const alertList = Array.isArray(alertData) ? alertData : alertData?.alerts || [];

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
          {!grouped ? <div className="empty">No grouped data</div> : (
            <div className="json-block">{JSON.stringify(grouped, null, 2)}</div>
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
            <div className="json-block">{JSON.stringify(analysisResult, null, 2)}</div>
          ) : (
            <div className="empty">Click "Run Analysis" to analyze current alert patterns</div>
          )}
        </div>
      )}
    </div>
  );
}

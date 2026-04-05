import { useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';

export default function ReportsExports() {
  const toast = useToast();
  const [tab, setTab] = useState('reports');
  const { data: rptList, reload: rReports } = useApi(api.reports);
  const { data: execSum } = useApi(api.executiveSummary);
  const { data: research } = useApi(api.researchTracks);
  const { data: auditData } = useApi(api.auditLog);
  const { data: auditVerifyData } = useApi(api.auditVerify);
  const { data: adminAudit } = useApi(api.auditAdmin);
  const { data: retStatus } = useApi(api.retentionStatus);
  const [exportData, setExportData] = useState(null);
  const [analyzeResult, setAnalyzeResult] = useState(null);

  const reportArr = Array.isArray(rptList) ? rptList : rptList?.reports || [];

  const download = (data, name) => {
    const blob = new Blob([typeof data === 'string' ? data : JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <div className="tabs">
        {['reports', 'exports', 'audit', 'retention'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'reports' && (
        <>
          {execSum && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Executive Summary</div>
              <div className="json-block">{JSON.stringify(execSum, null, 2)}</div>
            </div>
          )}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Reports ({reportArr.length})</span>
              <button className="btn btn-sm" onClick={rReports}>↻ Refresh</button>
            </div>
            {reportArr.length === 0 ? <div className="empty">No reports</div> : (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>ID</th><th>Title</th><th>Type</th><th>Created</th><th>Actions</th></tr></thead>
                  <tbody>
                    {reportArr.map((r, i) => (
                      <tr key={i}>
                        <td>{r.id || i}</td>
                        <td>{r.title || r.name || '—'}</td>
                        <td>{r.type || '—'}</td>
                        <td>{r.created || r.timestamp || '—'}</td>
                        <td>
                          <div className="btn-group">
                            <button className="btn btn-sm" onClick={async () => {
                              try { const d = await api.reportById(r.id || i); download(d, `report-${r.id || i}.json`); toast('Downloaded', 'success'); } catch { toast('Failed', 'error'); }
                            }}>⬇ Download</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Run Analysis</span>
              <button className="btn btn-sm btn-primary" onClick={async () => {
                try { const r = await api.analyze({}); setAnalyzeResult(r); toast('Analysis complete', 'success'); } catch { toast('Analysis failed', 'error'); }
              }}>Analyze</button>
            </div>
            {analyzeResult && <div className="json-block">{JSON.stringify(analyzeResult, null, 2)}</div>}
          </div>
        </>
      )}

      {tab === 'exports' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 16 }}>Formal Verification Exports</div>
          <div className="btn-group">
            <button className="btn" onClick={async () => {
              try { const r = await api.exportTla(); setExportData({ type: 'TLA+', data: r }); toast('TLA+ exported', 'success'); } catch { toast('Failed', 'error'); }
            }}>Export TLA+</button>
            <button className="btn" onClick={async () => {
              try { const r = await api.exportAlloy(); setExportData({ type: 'Alloy', data: r }); toast('Alloy exported', 'success'); } catch { toast('Failed', 'error'); }
            }}>Export Alloy</button>
            <button className="btn" onClick={async () => {
              try { const r = await api.exportWitnesses(); setExportData({ type: 'Witnesses', data: r }); toast('Witnesses exported', 'success'); } catch { toast('Failed', 'error'); }
            }}>Export Witnesses</button>
          </div>
          {exportData && (
            <div style={{ marginTop: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span className="card-title">{exportData.type}</span>
                <button className="btn btn-sm" onClick={() => download(exportData.data, `${exportData.type.toLowerCase()}.json`)}>⬇ Download</button>
              </div>
              <div className="json-block">{typeof exportData.data === 'string' ? exportData.data : JSON.stringify(exportData.data, null, 2)}</div>
            </div>
          )}
          {research && (
            <div style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Research Tracks</div>
              <div className="json-block">{JSON.stringify(research, null, 2)}</div>
            </div>
          )}
        </div>
      )}

      {tab === 'audit' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Audit Log</div>
              <div className="json-block">{JSON.stringify(auditData, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Admin Audit</div>
              <div className="json-block">{JSON.stringify(adminAudit, null, 2)}</div>
            </div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Audit Verification</div>
            <div className="json-block">{JSON.stringify(auditVerifyData, null, 2)}</div>
          </div>
        </>
      )}

      {tab === 'retention' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Data Retention</span>
            <button className="btn btn-sm btn-primary" onClick={async () => {
              try { await api.retentionApply({}); toast('Retention policy applied', 'success'); } catch { toast('Failed', 'error'); }
            }}>Apply Policy</button>
          </div>
          <div className="json-block">{JSON.stringify(retStatus, null, 2)}</div>
        </div>
      )}
    </div>
  );
}

import { useState } from 'react';
import { useApi, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';

export default function SOCWorkbench() {
  const toast = useToast();
  const [tab, setTab] = useState('overview');
  const { data: overview, reload: rOverview } = useApi(api.workbenchOverview);
  const { data: incList, reload: rInc } = useApi(api.incidents);
  const { data: caseList, reload: rCases } = useApi(api.cases);
  const { data: caseStats } = useApi(api.casesStats);
  const { data: queue, reload: rQueue } = useApi(api.queueAlerts);
  const { data: qStats } = useApi(api.queueStats);
  const { data: pending } = useApi(api.responsePending);
  const { data: respReq } = useApi(api.responseRequests);
  const { data: respAudit } = useApi(api.responseAudit);
  const { data: respStats } = useApi(api.responseStats);
  const { data: procs } = useApi(api.processTree);
  const { data: deepCh } = useApi(api.deepChains);
  const { data: liveProcs, reload: rLive } = useApi(api.processesLive);
  const { data: procFindings } = useApi(api.processesAnalysis);
  const { data: rbacData, reload: rRbac } = useApi(api.rbacUsers);
  const { data: tlHost } = useApi(api.timelineHost);
  const [selectedInc, setSelectedInc] = useState(null);
  const [incDetail, setIncDetail] = useState(null);
  const [entityInput, setEntityInput] = useState('');
  const [entityResult, setEntityResult] = useState(null);

  useInterval(() => { rOverview(); rQueue(); }, 15000);

  const incArr = Array.isArray(incList) ? incList : incList?.incidents || [];
  const caseArr = Array.isArray(caseList) ? caseList : caseList?.cases || [];
  const queueArr = Array.isArray(queue) ? queue : queue?.alerts || [];
  const rbacArr = Array.isArray(rbacData) ? rbacData : rbacData?.users || [];

  const viewInc = async (id) => {
    setSelectedInc(id);
    try { const d = await api.incidentById(id); setIncDetail(d); } catch { setIncDetail(null); }
  };

  return (
    <div>
      <div className="tabs">
        {['overview', 'incidents', 'cases', 'queue', 'response', 'process-tree', 'entity', 'rbac', 'timeline'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.replace(/-/g, ' ').replace(/^\w/, c => c.toUpperCase())}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Workbench Overview</div>
          <div className="json-block">{JSON.stringify(overview, null, 2)}</div>
        </div>
      )}

      {tab === 'incidents' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Incidents ({incArr.length})</span>
            <div className="btn-group">
              <button className="btn btn-sm" onClick={rInc}>↻ Refresh</button>
              <button className="btn btn-sm btn-primary" onClick={async () => {
                try { await api.createIncident({ title: 'New incident', severity: 'medium' }); toast('Incident created', 'success'); rInc(); } catch { toast('Failed', 'error'); }
              }}>+ New Incident</button>
            </div>
          </div>
          {incArr.length === 0 ? <div className="empty">No incidents</div> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
                <tbody>
                  {incArr.map((inc, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{inc.id || i}</td>
                      <td>{inc.title || '—'}</td>
                      <td><span className={`sev-${(inc.severity || 'low').toLowerCase()}`}>{inc.severity}</span></td>
                      <td><span className={`badge ${inc.status === 'closed' ? 'badge-ok' : 'badge-warn'}`}>{inc.status || '—'}</span></td>
                      <td>{inc.created || inc.timestamp || '—'}</td>
                      <td>{inc.id ? <button className="btn btn-sm" onClick={() => viewInc(inc.id)}>View</button> : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {selectedInc !== null && incDetail && (
            <div style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Incident Detail</div>
              <div className="json-block">{JSON.stringify(incDetail, null, 2)}</div>
            </div>
          )}
        </div>
      )}

      {tab === 'cases' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Cases ({caseArr.length})</span>
            <button className="btn btn-sm btn-primary" onClick={async () => {
              try { await api.createCase({ title: 'New investigation' }); toast('Case created', 'success'); rCases(); } catch { toast('Failed', 'error'); }
            }}>+ New Case</button>
          </div>
          {caseStats && <div className="json-block" style={{ marginBottom: 12 }}>{JSON.stringify(caseStats, null, 2)}</div>}
          {caseArr.length === 0 ? <div className="empty">No cases</div> : (
            <div className="json-block">{JSON.stringify(caseArr, null, 2)}</div>
          )}
        </div>
      )}

      {tab === 'queue' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">SOC Queue ({queueArr.length} alerts)</span>
            <button className="btn btn-sm" onClick={rQueue}>↻ Refresh</button>
          </div>
          {qStats && <div className="json-block" style={{ marginBottom: 12 }}>{JSON.stringify(qStats, null, 2)}</div>}
          {queueArr.length === 0 ? <div className="empty">Queue empty</div> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Severity</th><th>Summary</th><th>Assigned</th><th>Actions</th></tr></thead>
                <tbody>
                  {queueArr.map((a, i) => (
                    <tr key={i}>
                      <td>{a.id || i}</td>
                      <td><span className={`sev-${(a.severity || 'low').toLowerCase()}`}>{a.severity}</span></td>
                      <td>{a.summary || a.message || '—'}</td>
                      <td>{a.assigned_to || '—'}</td>
                      <td>
                        <button className="btn btn-sm" onClick={async () => {
                          if (!a.id) { toast('No alert ID', 'error'); return; }
                          try { await api.queueAck({ alert_id: a.id }); toast('Acknowledged', 'success'); rQueue(); } catch { toast('Failed', 'error'); }
                        }}>Ack</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'response' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Pending Responses</div>
              <div className="json-block">{JSON.stringify(pending, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Response Stats</div>
              <div className="json-block">{JSON.stringify(respStats, null, 2)}</div>
            </div>
          </div>
          {respReq && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Response Requests</div>
              <div className="json-block">{JSON.stringify(respReq, null, 2)}</div>
            </div>
          )}
          {respAudit && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Response Audit Trail</div>
              <div className="json-block">{JSON.stringify(respAudit, null, 2)}</div>
            </div>
          )}
        </>
      )}

      {tab === 'process-tree' && (
        <div>
          {/* Security findings banner */}
          {procFindings?.findings?.length > 0 && (
            <div className="card" style={{ marginBottom: 16, borderLeft: '3px solid var(--danger)' }}>
              <div className="card-title" style={{ marginBottom: 8 }}>⚠ Process Security Findings ({procFindings.total})</div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
                {Object.entries(procFindings.risk_summary || {}).map(([k, v]) => v > 0 && (
                  <span key={k} className={`sev-${k}`} style={{ fontWeight: 600 }}>{v} {k}</span>
                ))}
              </div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Risk</th><th>PID</th><th>Process</th><th>User</th><th>CPU</th><th>Mem</th><th>Reason</th></tr></thead>
                  <tbody>
                    {procFindings.findings.map((f, i) => (
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
          <div className="card-grid">
            {/* Live processes */}
            <div className="card">
              <div className="card-header">
                <span className="card-title">Live Processes ({liveProcs?.count ?? '—'})</span>
                <button className="btn btn-sm" onClick={rLive}>↻ Refresh</button>
              </div>
              {liveProcs?.processes?.length > 0 ? (
                <div className="table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
                  <table>
                    <thead style={{ position: 'sticky', top: 0, background: 'var(--card-bg)', zIndex: 1 }}>
                      <tr><th>PID</th><th>Name</th><th>User</th><th>CPU %</th><th>Mem %</th></tr>
                    </thead>
                    <tbody>
                      {[...(liveProcs.processes)].sort((a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0)).slice(0, 100).map(p => (
                        <tr key={p.pid}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{p.pid}</td>
                          <td style={{ fontWeight: p.cpu_percent > 50 ? 700 : 400 }}>{p.name}</td>
                          <td>{p.user}</td>
                          <td style={{ color: p.cpu_percent > 50 ? 'var(--danger)' : undefined }}>{p.cpu_percent?.toFixed(1)}</td>
                          <td style={{ color: p.mem_percent > 30 ? 'var(--warning)' : undefined }}>{p.mem_percent?.toFixed(1)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : <div className="empty">{liveProcs?.message || 'No live process data'}</div>}
            </div>
            {/* Deep chains */}
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Deep Process Chains</div>
              {deepCh?.chains?.length > 0 || (Array.isArray(deepCh) && deepCh.length > 0) ? (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Chain</th><th>Depth</th></tr></thead>
                    <tbody>
                      {(deepCh?.chains || deepCh || []).map((c, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Array.isArray(c.chain) ? c.chain.join(' → ') : JSON.stringify(c)}</td>
                          <td>{c.depth || c.chain?.length || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : <div className="empty">No deep process chains detected</div>}
            </div>
          </div>
          {/* Static process tree - collapsed by default */}
          {procs && (
            <details style={{ marginTop: 16 }}>
              <summary style={{ cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)' }}>Static Process Tree (raw)</summary>
              <div className="card" style={{ marginTop: 8 }}>
                <div className="json-block">{JSON.stringify(procs, null, 2)}</div>
              </div>
            </details>
          )}
        </div>
      )}

      {tab === 'entity' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Entity / UEBA Lookup</span>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <input className="form-input" style={{ width: 300 }} placeholder="Entity ID" value={entityInput} onChange={e => setEntityInput(e.target.value)} />
            <button className="btn btn-primary" onClick={async () => {
              if (!entityInput) return;
              try {
                const r = await api.uebaEntity(entityInput);
                setEntityResult(r);
              } catch { try { const r = await api.entityById(entityInput); setEntityResult(r); } catch { toast('Entity not found', 'error'); } }
            }}>Lookup</button>
          </div>
          {entityResult && <div className="json-block">{JSON.stringify(entityResult, null, 2)}</div>}
        </div>
      )}

      {tab === 'rbac' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">RBAC Users</span>
            <button className="btn btn-sm" onClick={rRbac}>↻ Refresh</button>
          </div>
          {rbacArr.length === 0 ? <div className="empty">No RBAC users</div> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Actions</th></tr></thead>
                <tbody>
                  {rbacArr.map((u, i) => (
                    <tr key={i}>
                      <td>{u.username || u.name || '—'}</td>
                      <td><span className="badge badge-info">{u.role || '—'}</span></td>
                      <td>{u.created || '—'}</td>
                      <td>
                        <button className="btn btn-sm btn-danger" onClick={async () => {
                          try { await api.deleteRbacUser(u.username || u.name); toast('User removed', 'success'); rRbac(); } catch { toast('Failed', 'error'); }
                        }}>Remove</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'timeline' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Host Timeline</div>
          <div className="json-block">{JSON.stringify(tlHost, null, 2)}</div>
        </div>
      )}
    </div>
  );
}

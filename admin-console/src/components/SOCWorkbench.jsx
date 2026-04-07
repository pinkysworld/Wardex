import { useState } from 'react';
import { useApi, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import ProcessDrawer from './ProcessDrawer.jsx';
import { JsonDetails, SummaryGrid, downloadData } from './operator.jsx';

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
  const { data: procFindings, reload: rProcFindings } = useApi(api.processesAnalysis);
  const { data: rbacData, reload: rRbac } = useApi(api.rbacUsers);
  const { data: tlHost } = useApi(api.timelineHost);
  const { data: escPolicies, reload: rEsc } = useApi(api.escalationPolicies);
  const { data: escActive, reload: rEscActive } = useApi(api.escalationActive);
  const { data: workflows } = useApi(api.investigationWorkflows);
  const { data: activeInvestigations, reload: rInv } = useApi(api.investigationActive);
  const { data: efficacyData, reload: rEfficacy } = useApi(api.efficacySummary);
  const [selectedInc, setSelectedInc] = useState(null);
  const [incDetail, setIncDetail] = useState(null);
  const [incStoryline, setIncStoryline] = useState(null);
  const [entityInput, setEntityInput] = useState('');
  const [entityResult, setEntityResult] = useState(null);
  const [escForm, setEscForm] = useState({ name: '', severity: 'critical', channel: 'email', targets: '', timeout_minutes: 30 });
  const [showEscForm, setShowEscForm] = useState(false);
  const [selectedProcess, setSelectedProcess] = useState(null);

  useInterval(() => { rOverview(); rQueue(); rEscActive(); }, 15000);
  useInterval(() => {
    if (tab === 'process-tree') {
      rLive();
      rProcFindings();
    }
  }, tab === 'process-tree' ? 15000 : null);

  const incArr = Array.isArray(incList) ? incList : incList?.incidents || [];
  const caseArr = Array.isArray(caseList) ? caseList : caseList?.cases || [];
  const queueArr = Array.isArray(queue) ? queue : queue?.alerts || [];
  const rbacArr = Array.isArray(rbacData) ? rbacData : rbacData?.users || [];

  const viewInc = async (id) => {
    setSelectedInc(id);
    setIncStoryline(null);
    try { const d = await api.incidentById(id); setIncDetail(d); } catch { setIncDetail(null); }
    try { const s = await api.incidentStoryline(id); setIncStoryline(s); } catch { /* optional */ }
  };
  const openProcess = (process) => setSelectedProcess(process ? { ...process } : null);

  return (
    <div>
      <div className="tabs">
        {['overview', 'incidents', 'cases', 'queue', 'response', 'escalation', 'investigations', 'efficacy', 'process-tree', 'entity', 'rbac', 'timeline'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.replace(/-/g, ' ').replace(/^\w/, c => c.toUpperCase())}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Workbench Overview</div>
          {overview ? <><SummaryGrid data={overview} limit={10} /><JsonDetails data={overview} /></> : <div className="empty">Loading...</div>}
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
            <div className="card" style={{ marginTop: 16, borderLeft: '3px solid var(--primary)' }}>
              <div className="card-header">
                <span className="card-title">Incident Detail — {incDetail.title || incDetail.id || selectedInc}</span>
                <button className="btn btn-sm" onClick={() => { setSelectedInc(null); setIncDetail(null); setIncStoryline(null); }}>✕ Close</button>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12, marginBottom: 16 }}>
                <div><span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>ID</span><div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{incDetail.id || selectedInc}</div></div>
                <div><span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Severity</span><div><span className={`sev-${(incDetail.severity || 'low').toLowerCase()}`}>{incDetail.severity || '—'}</span></div></div>
                <div><span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Status</span><div><span className={`badge ${incDetail.status === 'closed' ? 'badge-ok' : 'badge-warn'}`}>{incDetail.status || '—'}</span></div></div>
                <div><span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Created</span><div>{incDetail.created || incDetail.timestamp || '—'}</div></div>
                <div><span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Updated</span><div>{incDetail.updated || incDetail.last_updated || '—'}</div></div>
                <div><span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Owner</span><div>{incDetail.owner || incDetail.assigned_to || '—'}</div></div>
              </div>
              {incDetail.summary && <div style={{ marginBottom: 12, padding: '8px 12px', background: 'var(--bg)', borderRadius: 6, fontSize: 13 }}>{incDetail.summary}</div>}
              {(incDetail.event_ids?.length > 0 || incDetail.alert_ids?.length > 0) && (
                <div style={{ marginBottom: 12 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Related Events / Alerts</span>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                    {(incDetail.event_ids || incDetail.alert_ids || []).map((eid, i) => (
                      <span key={i} className="badge badge-info" style={{ fontSize: 11 }}>{eid}</span>
                    ))}
                  </div>
                </div>
              )}
              {(incDetail.agent_ids?.length > 0) && (
                <div style={{ marginBottom: 12 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Agents</span>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                    {incDetail.agent_ids.map((aid, i) => <span key={i} className="badge" style={{ fontSize: 11 }}>{aid}</span>)}
                  </div>
                </div>
              )}
              {incStoryline && (
                <div style={{ marginTop: 12 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Storyline</span>
                  <div style={{ marginTop: 6, borderLeft: '2px solid var(--border)', paddingLeft: 12 }}>
                    {(incStoryline.events || incStoryline.steps || (Array.isArray(incStoryline) ? incStoryline : [])).map((ev, i) => (
                      <div key={i} style={{ marginBottom: 8, fontSize: 13 }}>
                        <span style={{ fontWeight: 600, marginRight: 8 }}>{ev.timestamp || ev.time || `Step ${i + 1}`}</span>
                        <span>{ev.description || ev.message || ev.action || JSON.stringify(ev)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
                <button className="btn btn-sm btn-primary" onClick={async () => {
                  try { await api.updateIncident(selectedInc, { status: 'closed' }); toast('Incident closed', 'success'); viewInc(selectedInc); rInc(); } catch { toast('Failed', 'error'); }
                }}>Close Incident</button>
                <button className="btn btn-sm" onClick={async () => {
                  try { const r = await api.incidentReport(selectedInc); const blob = new Blob([typeof r === 'string' ? r : JSON.stringify(r, null, 2)], { type: 'text/plain' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `incident-${selectedInc}-report.txt`; a.click(); } catch { toast('Failed to generate report', 'error'); }
                }}>Export Report</button>
              </div>
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
          {caseStats && (
            <div style={{ marginBottom: 12 }}>
              <SummaryGrid data={caseStats} limit={8} />
            </div>
          )}
          {caseArr.length === 0 ? <div className="empty">No cases</div> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Owner</th><th>Created</th></tr></thead>
                <tbody>
                  {caseArr.map((c, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{c.id || i}</td>
                      <td>{c.title || '—'}</td>
                      <td><span className={`badge ${c.status === 'closed' ? 'badge-ok' : 'badge-warn'}`}>{c.status || '—'}</span></td>
                      <td>{c.owner || c.assigned_to || '—'}</td>
                      <td>{c.created || c.timestamp || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'queue' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">SOC Queue ({queueArr.length} alerts)</span>
            <button className="btn btn-sm" onClick={rQueue}>↻ Refresh</button>
          </div>
          {qStats && (
            <div style={{ marginBottom: 12 }}>
              <SummaryGrid data={qStats} limit={8} />
              <JsonDetails data={qStats} />
            </div>
          )}
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
              {(() => {
                const items = pending?.actions || pending?.pending || (Array.isArray(pending) ? pending : []);
                return items.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Action</th><th>Target</th><th>Severity</th><th>Requested</th></tr></thead>
                      <tbody>
                        {items.map((a, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 600 }}>{a.action || a.type || '—'}</td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{a.target || a.host || '—'}</td>
                            <td><span className={`sev-${(a.severity || 'low').toLowerCase()}`}>{a.severity || '—'}</span></td>
                            <td>{a.requested || a.timestamp || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : <div className="empty">{pending ? 'No pending responses' : 'Loading...'}</div>;
              })()}
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Response Stats</div>
              {respStats ? (
                <>
                  <SummaryGrid data={respStats} limit={8} />
                  <JsonDetails data={respStats} />
                </>
              ) : <div className="empty">Loading...</div>}
            </div>
          </div>
          {respReq && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Response Requests</div>
              {(() => {
                const reqs = respReq?.requests || (Array.isArray(respReq) ? respReq : []);
                return reqs.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>ID</th><th>Type</th><th>Target</th><th>Status</th><th>Requested</th></tr></thead>
                      <tbody>
                        {reqs.map((r, i) => (
                          <tr key={i}>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{r.id || i}</td>
                            <td>{r.type || r.action || '—'}</td>
                            <td>{r.target || r.host || '—'}</td>
                            <td><span className={`badge ${r.status === 'completed' ? 'badge-ok' : 'badge-warn'}`}>{r.status || '—'}</span></td>
                            <td>{r.requested_at || r.timestamp || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : <div className="empty">No response requests</div>;
              })()}
            </div>
          )}
          {respAudit && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Response Audit Trail</div>
              {(() => {
                const entries = respAudit?.entries || respAudit?.audit || (Array.isArray(respAudit) ? respAudit : []);
                return entries.length > 0 ? (
                  <div style={{ borderLeft: '2px solid var(--border)', paddingLeft: 12 }}>
                    {entries.map((e, i) => (
                      <div key={i} style={{ marginBottom: 8, fontSize: 13 }}>
                        <span style={{ fontWeight: 600, marginRight: 8 }}>{e.timestamp || e.time || '—'}</span>
                        <span style={{ marginRight: 8, color: 'var(--primary)' }}>{e.user || e.actor || '—'}</span>
                        <span>{e.action || e.message || e.description || JSON.stringify(e)}</span>
                      </div>
                    ))}
                  </div>
                ) : <div className="empty">No audit entries</div>;
              })()}
            </div>
          )}
        </>
      )}

      {tab === 'escalation' && (
        <div>
          {/* Active Escalations */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Active Escalations</span>
              <button className="btn btn-sm" onClick={rEscActive}>↻ Refresh</button>
            </div>
            {(() => {
              const esc = escActive?.escalations || (Array.isArray(escActive) ? escActive : []);
              return esc.length === 0 ? <div className="empty">No active escalations</div> : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>ID</th><th>Incident</th><th>Severity</th><th>Policy</th><th>Started</th><th>Level</th><th>Actions</th></tr></thead>
                    <tbody>
                      {esc.map((e, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.id || i}</td>
                          <td>{e.incident_id || e.alert_id || '—'}</td>
                          <td><span className={`sev-${(e.severity || 'low').toLowerCase()}`}>{e.severity || '—'}</span></td>
                          <td>{e.policy || e.policy_name || '—'}</td>
                          <td>{e.started || e.timestamp || '—'}</td>
                          <td><span className="badge badge-warn">Level {e.level || e.current_level || 1}</span></td>
                          <td>
                            <button className="btn btn-sm btn-primary" onClick={async () => {
                              try { await api.escalationAck({ escalation_id: e.id }); toast('Escalation acknowledged', 'success'); rEscActive(); } catch { toast('Failed', 'error'); }
                            }}>Acknowledge</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })()}
          </div>
          {/* Escalation Policies */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Escalation Policies</span>
              <div className="btn-group">
                <button className="btn btn-sm" onClick={rEsc}>↻ Refresh</button>
                <button className="btn btn-sm btn-primary" onClick={() => setShowEscForm(!showEscForm)}>{showEscForm ? 'Cancel' : '+ New Policy'}</button>
              </div>
            </div>
            {showEscForm && (
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16, padding: 12, background: 'var(--bg)', borderRadius: 6 }}>
                <input className="form-input" style={{ width: 200 }} placeholder="Policy name" value={escForm.name} onChange={e => setEscForm(f => ({ ...f, name: e.target.value }))} />
                <select className="form-input" style={{ width: 120 }} value={escForm.severity} onChange={e => setEscForm(f => ({ ...f, severity: e.target.value }))}>
                  <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
                </select>
                <select className="form-input" style={{ width: 120 }} value={escForm.channel} onChange={e => setEscForm(f => ({ ...f, channel: e.target.value }))}>
                  <option value="email">Email</option><option value="slack">Slack</option><option value="pagerduty">PagerDuty</option><option value="webhook">Webhook</option>
                </select>
                <input className="form-input" style={{ width: 250 }} placeholder="Targets (comma-separated)" value={escForm.targets} onChange={e => setEscForm(f => ({ ...f, targets: e.target.value }))} />
                <input className="form-input" style={{ width: 120 }} type="number" placeholder="Timeout (min)" value={escForm.timeout_minutes} onChange={e => setEscForm(f => ({ ...f, timeout_minutes: parseInt(e.target.value) || 30 }))} />
                <button className="btn btn-primary" onClick={async () => {
                  if (!escForm.name) { toast('Name required', 'error'); return; }
                  try {
                    await api.createEscalationPolicy({ ...escForm, targets: escForm.targets.split(',').map(t => t.trim()).filter(Boolean) });
                    toast('Policy created', 'success');
                    setShowEscForm(false); setEscForm({ name: '', severity: 'critical', channel: 'email', targets: '', timeout_minutes: 30 });
                    rEsc();
                  } catch { toast('Failed', 'error'); }
                }}>Create</button>
              </div>
            )}
            {(() => {
              const pols = escPolicies?.policies || (Array.isArray(escPolicies) ? escPolicies : []);
              return pols.length === 0 ? <div className="empty">No escalation policies configured</div> : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Name</th><th>Severity</th><th>Channel</th><th>Targets</th><th>Timeout</th><th>Actions</th></tr></thead>
                    <tbody>
                      {pols.map((p, i) => (
                        <tr key={i}>
                          <td style={{ fontWeight: 600 }}>{p.name || '—'}</td>
                          <td><span className={`sev-${(p.severity || 'low').toLowerCase()}`}>{p.severity || '—'}</span></td>
                          <td>{p.channel || '—'}</td>
                          <td style={{ fontSize: 12 }}>{Array.isArray(p.targets) ? p.targets.join(', ') : p.targets || '—'}</td>
                          <td>{p.timeout_minutes || p.timeout || '—'} min</td>
                          <td>
                            <button className="btn btn-sm" onClick={async () => {
                              try { await api.escalationStart({ policy_id: p.id || p.name, incident_id: 'manual-test' }); toast('Escalation triggered', 'success'); rEscActive(); } catch { toast('Failed', 'error'); }
                            }}>Test</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {tab === 'process-tree' && (
        <div>
          {/* Security findings banner */}
          {procFindings?.findings?.length > 0 && (
            <div className="card" style={{ marginBottom: 16, borderLeft: '3px solid var(--danger)' }}>
              <div className="card-header">
                <span className="card-title">Process Security Findings ({procFindings.total})</span>
                <div className="btn-group">
                  <button className="btn btn-sm" onClick={() => downloadData(procFindings, 'soc-process-findings.json')}>Export</button>
                  <button className="btn btn-sm" onClick={() => { rLive(); rProcFindings(); }}>↻ Refresh</button>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
                {Object.entries(procFindings.risk_summary || {}).map(([k, v]) => v > 0 && (
                  <span key={k} className={`sev-${k}`} style={{ fontWeight: 600 }}>{v} {k}</span>
                ))}
              </div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Risk</th><th>PID</th><th>Process</th><th>User</th><th>CPU</th><th>Mem</th><th>Reason</th><th>Actions</th></tr></thead>
                  <tbody>
                    {procFindings.findings.map((f, i) => (
                      <tr key={i} className="interactive-row" style={{ background: f.risk_level === 'critical' ? 'rgba(239,68,68,.06)' : f.risk_level === 'high' ? 'rgba(249,115,22,.06)' : undefined }}>
                        <td><span className={`sev-${f.risk_level}`}>{f.risk_level}</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{f.pid}</td>
                        <td style={{ fontWeight: 600 }}>{f.name}</td>
                        <td>{f.user}</td>
                        <td>{f.cpu_percent?.toFixed(1)}%</td>
                        <td>{f.mem_percent?.toFixed(1)}%</td>
                        <td style={{ fontSize: 12 }}>{f.reason}</td>
                        <td><button className="btn btn-sm" onClick={() => openProcess(f)}>Investigate</button></td>
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
                <div className="btn-group">
                  <button className="btn btn-sm" onClick={rLive}>↻ Refresh</button>
                  <button className="btn btn-sm" onClick={() => downloadData(liveProcs, 'soc-live-processes.json')}>Export</button>
                </div>
              </div>
              {liveProcs?.processes?.length > 0 ? (
                <div className="table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
                  <table>
                    <thead style={{ position: 'sticky', top: 0, background: 'var(--card-bg)', zIndex: 1 }}>
                      <tr><th>PID</th><th>Name</th><th>User</th><th>CPU %</th><th>Mem %</th><th>Actions</th></tr>
                    </thead>
                    <tbody>
                      {[...(liveProcs.processes)].sort((a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0)).slice(0, 100).map(p => (
                        <tr key={p.pid} className="interactive-row">
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{p.pid}</td>
                          <td style={{ fontWeight: p.cpu_percent > 50 ? 700 : 400 }}>{p.name}</td>
                          <td>{p.user}</td>
                          <td style={{ color: p.cpu_percent > 50 ? 'var(--danger)' : undefined }}>{p.cpu_percent?.toFixed(1)}</td>
                          <td style={{ color: p.mem_percent > 30 ? 'var(--warning)' : undefined }}>{p.mem_percent?.toFixed(1)}</td>
                          <td><button className="btn btn-sm" onClick={() => openProcess(p)}>Investigate</button></td>
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
                <JsonDetails data={procs} label="Process tree details" />
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
          {entityResult && (
            <>
              <SummaryGrid data={entityResult} limit={12} />
              <JsonDetails data={entityResult} />
            </>
          )}
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

      {tab === 'investigations' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Investigation Workflows</span>
            <button className="btn btn-sm" onClick={rInv}>↻ Refresh</button>
          </div>
          {workflows && Array.isArray(workflows) && workflows.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>MITRE</th><th>Est. Time</th><th>Steps</th><th>Actions</th></tr></thead>
                <tbody>
                  {workflows.map((wf, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{wf.id}</td>
                      <td style={{ fontWeight: 600 }}>{wf.name}</td>
                      <td><span className={`sev-${(wf.severity || 'medium').toLowerCase()}`}>{wf.severity}</span></td>
                      <td style={{ fontSize: 11 }}>{(wf.mitre_techniques || []).join(', ')}</td>
                      <td>{wf.estimated_minutes}m</td>
                      <td>{(wf.steps || []).length}</td>
                      <td>
                        <button className="btn btn-sm btn-primary" onClick={async () => {
                          try {
                            await api.investigationStart({ workflow_id: wf.id, analyst: 'admin' });
                            toast('Investigation started', 'success');
                            rInv();
                          } catch { toast('Failed to start', 'error'); }
                        }}>Start</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div className="empty">No workflows available</div>}
          {activeInvestigations && Array.isArray(activeInvestigations) && activeInvestigations.length > 0 && (
            <div style={{ marginTop: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>Active Investigations</div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Workflow</th><th>Analyst</th><th>Started</th><th>Progress</th><th>Status</th></tr></thead>
                  <tbody>
                    {activeInvestigations.map((inv, i) => (
                      <tr key={i}>
                        <td>{inv.workflow_id}</td>
                        <td>{inv.analyst}</td>
                        <td style={{ fontSize: 11 }}>{inv.started_at}</td>
                        <td>{(inv.completed_steps || []).length} steps done</td>
                        <td><span className={`badge ${inv.status === 'in-progress' ? 'badge-warn' : 'badge-ok'}`}>{inv.status}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'efficacy' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Detection Efficacy</span>
            <button className="btn btn-sm" onClick={rEfficacy}>↻ Refresh</button>
          </div>
          {efficacyData ? (
            <>
              <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap' }}>
                {Object.entries(efficacyData).filter(([, v]) => typeof v !== 'object').map(([k, v]) => (
                  <div key={k} style={{ padding: '6px 12px', background: 'var(--bg)', borderRadius: 6, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>{k.replace(/_/g, ' ')}</div>
                    <div style={{ fontSize: 18, fontWeight: 700 }}>{typeof v === 'number' ? v.toFixed(2) : String(v)}</div>
                  </div>
                ))}
              </div>
              <JsonDetails data={efficacyData} />
            </>
          ) : <div className="empty">No efficacy data yet — triage alerts to populate</div>}
        </div>
      )}

      {tab === 'timeline' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Host Timeline</div>
          {(() => {
            const events = tlHost?.events || tlHost?.timeline || (Array.isArray(tlHost) ? tlHost : []);
            if (events.length === 0 && !tlHost) return <div className="empty">Loading...</div>;
            if (events.length === 0) return <div className="empty">No timeline events</div>;
            return (
              <div style={{ borderLeft: '2px solid var(--primary)', paddingLeft: 16 }}>
                {events.map((ev, i) => (
                  <div key={i} style={{ marginBottom: 12, position: 'relative' }}>
                    <div style={{ position: 'absolute', left: -22, top: 4, width: 10, height: 10, borderRadius: '50%', background: 'var(--primary)' }} />
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>
                      {ev.timestamp || ev.time || '—'}
                      {ev.host && <span style={{ marginLeft: 8, fontWeight: 600 }}>{ev.host}</span>}
                    </div>
                    <div style={{ fontSize: 13 }}>
                      {ev.severity && <span className={`sev-${ev.severity.toLowerCase()}`} style={{ marginRight: 8 }}>{ev.severity}</span>}
                      {ev.event || ev.message || ev.description || ev.action || JSON.stringify(ev)}
                    </div>
                  </div>
                ))}
              </div>
            );
          })()}
        </div>
      )}
      <ProcessDrawer
        pid={selectedProcess?.pid}
        snapshot={selectedProcess}
        onClose={() => setSelectedProcess(null)}
        onUpdated={() => { rLive(); rProcFindings(); }}
      />
    </div>
  );
}

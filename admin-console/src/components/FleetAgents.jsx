import { useState } from 'react';
import { useApi, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';

export default function FleetAgents() {
  const toast = useToast();
  const [tab, setTab] = useState('fleet');
  const { data: fleetSt, reload: rFleet } = useApi(api.fleetStatus);
  const { data: dash, reload: rDash } = useApi(api.fleetDashboard);
  const { data: agentList, reload: rAgents } = useApi(api.agents);
  const { data: swarm } = useApi(api.swarmPosture);
  const { data: swarmIntelData } = useApi(api.swarmIntel);
  const { data: plat } = useApi(api.platform);
  const { data: evts, reload: rEvents } = useApi(api.events);
  const { data: evtSum } = useApi(api.eventsSummary);
  const { data: policyHist } = useApi(api.policyHistory);
  const { data: releases } = useApi(api.updatesReleases);
  const { data: rollout } = useApi(api.rolloutConfig);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [agentDetail, setAgentDetail] = useState(null);

  useInterval(() => { rFleet(); rAgents(); }, 15000);

  const agentArr = Array.isArray(agentList) ? agentList : agentList?.agents || [];
  const eventArr = Array.isArray(evts) ? evts : evts?.events || [];

  const viewAgent = async (id) => {
    setSelectedAgent(id);
    try {
      const d = await api.agentDetails(id);
      setAgentDetail(d);
    } catch { setAgentDetail(null); }
  };

  return (
    <div>
      <div className="tabs">
        {['fleet', 'agents', 'events', 'updates', 'swarm'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'fleet' && (
        <>
          <div className="card-grid">
            <div className="card metric"><div className="metric-label">Total Agents</div><div className="metric-value">{dash?.total_agents ?? dash?.agents ?? '—'}</div></div>
            <div className="card metric"><div className="metric-label">Online</div><div className="metric-value">{dash?.online ?? '—'}</div></div>
            <div className="card metric"><div className="metric-label">Platform</div><div className="metric-value">{plat?.os ?? plat?.platform ?? '—'}</div></div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Fleet Status</div>
            <div className="json-block">{JSON.stringify(fleetSt, null, 2)}</div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Fleet Dashboard</div>
            <div className="json-block">{JSON.stringify(dash, null, 2)}</div>
          </div>
        </>
      )}

      {tab === 'agents' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Registered Agents ({agentArr.length})</span>
            <button className="btn btn-sm" onClick={rAgents}>↻ Refresh</button>
          </div>
          {agentArr.length === 0 ? <div className="empty">No agents registered</div> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Hostname</th><th>OS</th><th>Version</th><th>Status</th><th>Last Seen</th><th>Actions</th></tr></thead>
                <tbody>
                  {agentArr.map((a, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{a.id || a.agent_id || '—'}</td>
                      <td>{a.hostname || '—'}</td>
                      <td>{a.os || a.platform || '—'}</td>
                      <td>{a.version || '—'}</td>
                      <td><span className={`dot ${a.status === 'online' ? 'dot-green' : a.status === 'offline' ? 'dot-red' : 'dot-yellow'}`} />{a.status || '—'}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>{a.last_seen || a.last_heartbeat || '—'}</td>
                      <td>
                        <button className="btn btn-sm" onClick={() => viewAgent(a.id || a.agent_id)}>Details</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {selectedAgent && agentDetail && (
            <div style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Agent: {selectedAgent}</div>
              <div className="json-block">{JSON.stringify(agentDetail, null, 2)}</div>
              <div className="btn-group" style={{ marginTop: 8 }}>
                <button className="btn btn-sm btn-danger" onClick={async () => {
                  try { await api.deleteAgent(selectedAgent); toast('Agent removed', 'success'); rAgents(); setSelectedAgent(null); } catch { toast('Failed', 'error'); }
                }}>Remove Agent</button>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'events' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Events ({eventArr.length})</span>
            <div className="btn-group">
              <button className="btn btn-sm" onClick={rEvents}>↻ Refresh</button>
              <button className="btn btn-sm" onClick={async () => {
                try {
                  const data = await api.eventsExport();
                  const blob = new Blob([typeof data === 'string' ? data : JSON.stringify(data)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a'); a.href = url; a.download = 'events.json'; a.click();
                  URL.revokeObjectURL(url);
                  toast('Events exported', 'success');
                } catch { toast('Export failed', 'error'); }
              }}>⬇ Export</button>
            </div>
          </div>
          {evtSum && <div className="json-block" style={{ marginBottom: 16 }}>{JSON.stringify(evtSum, null, 2)}</div>}
          {eventArr.length === 0 ? <div className="empty">No events</div> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Details</th></tr></thead>
                <tbody>
                  {eventArr.slice(0, 100).map((e, i) => (
                    <tr key={i}>
                      <td style={{ whiteSpace: 'nowrap', fontSize: 12, fontFamily: 'var(--font-mono)' }}>{e.timestamp || e.time || '—'}</td>
                      <td>{e.event_type || e.type || '—'}</td>
                      <td>{e.source || '—'}</td>
                      <td>{e.message || e.description || JSON.stringify(e).slice(0, 100)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'updates' && (
        <>
          {releases && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Available Releases</div>
              <div className="json-block">{JSON.stringify(releases, null, 2)}</div>
            </div>
          )}
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Rollout Config</div>
              <div className="json-block">{JSON.stringify(rollout, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Policy History</div>
              <div className="json-block">{JSON.stringify(policyHist, null, 2)}</div>
            </div>
          </div>
        </>
      )}

      {tab === 'swarm' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Swarm Posture</div>
            <div className="json-block">{JSON.stringify(swarm, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Swarm Intel</div>
            <div className="json-block">{JSON.stringify(swarmIntelData, null, 2)}</div>
          </div>
        </>
      )}
    </div>
  );
}

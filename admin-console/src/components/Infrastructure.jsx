import { useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid } from './operator.jsx';

export default function Infrastructure() {
  const toast = useToast();
  const [tab, setTab] = useState('monitor');
  const { data: monSt } = useApi(api.monitorStatus);
  const { data: corrData } = useApi(api.correlation);
  const { data: drift } = useApi(api.driftStatus);
  const { data: fp } = useApi(api.fingerprintStatus);
  const { data: causal } = useApi(api.causalGraph);
  const { data: threads } = useApi(api.threadsStatus);
  const { data: energy } = useApi(api.energyStatus);
  const { data: tenants } = useApi(api.tenantsCount);
  const { data: patchData } = useApi(api.patches);
  const { data: mesh } = useApi(api.meshHealth);
  const { data: tls } = useApi(api.tlsStatus);
  const { data: slo } = useApi(api.sloStatus);
  const { data: deps } = useApi(api.systemDeps);
  const { data: hostApps, reload: rApps } = useApi(api.hostApps);
  const { data: hostInv } = useApi(api.hostInventory);
  const { data: vulnSummary, reload: rVuln } = useApi(api.vulnerabilitySummary);
  const { data: ndrData, reload: rNdr } = useApi(api.ndrReport);
  const { data: containerSt, reload: rContainer } = useApi(api.containerStats);
  const { data: containerAlerts } = useApi(api.containerAlerts);
  const { data: certSummary, reload: rCerts } = useApi(api.certsSummary);
  const { data: certAlerts } = useApi(api.certsAlerts);
  const { data: driftBaselines } = useApi(api.configDriftBaselines);
  const { data: assetSummary, reload: rAssets } = useApi(api.assetsSummary);
  const [assetSearch, setAssetSearch] = useState('');
  const [assetResults, setAssetResults] = useState(null);

  return (
    <div>
      <div className="tabs">
        {['monitor', 'correlation', 'drift', 'energy', 'mesh', 'system', 'inventory', 'vulnerabilities', 'ndr', 'containers', 'certificates', 'assets'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'monitor' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Monitor Status</div>
            {monSt ? <><SummaryGrid data={monSt} limit={12} /><JsonDetails data={monSt} /></> : <div className="empty">Loading...</div>}
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Fingerprint</div>
            {fp ? <><SummaryGrid data={fp} limit={10} /><JsonDetails data={fp} /></> : <div className="empty">Loading...</div>}
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Causal Graph</div>
            {causal ? <><SummaryGrid data={causal} limit={10} /><JsonDetails data={causal} /></> : <div className="empty">Loading...</div>}
          </div>
        </div>
      )}

      {tab === 'correlation' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Correlation Engine</div>
          {corrData ? (
            <>
              <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap' }}>
                {Object.entries(corrData).filter(([, v]) => typeof v !== 'object').map(([k, v]) => (
                  <div key={k} style={{ padding: '6px 12px', background: 'var(--bg)', borderRadius: 6, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>{k.replace(/_/g, ' ')}</div>
                    <div style={{ fontSize: 18, fontWeight: 700 }}>{String(v)}</div>
                  </div>
                ))}
              </div>
              {(() => {
                const rules = corrData.rules || corrData.correlations || (Array.isArray(corrData) ? corrData : []);
                return rules.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Rule</th><th>Window</th><th>Matches</th><th>Status</th></tr></thead>
                      <tbody>
                        {(Array.isArray(rules) ? rules : []).map((r, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 600 }}>{r.name || r.rule || '—'}</td>
                            <td>{r.window || r.time_window || '—'}</td>
                            <td>{r.matches ?? r.hits ?? '—'}</td>
                            <td><span className={`badge ${r.active !== false ? 'badge-ok' : 'badge-warn'}`}>{r.active !== false ? 'Active' : 'Disabled'}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null;
              })()}
            </>
          ) : <div className="empty">Loading...</div>}
        </div>
      )}

      {tab === 'drift' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Configuration Drift</span>
            <button className="btn btn-sm btn-primary" onClick={async () => {
              try { await api.driftReset(); toast('Drift baseline reset', 'success'); } catch { toast('Failed', 'error'); }
            }}>Reset Baseline</button>
          </div>
          {drift ? (
            <>
              <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap' }}>
                {Object.entries(drift).filter(([, v]) => typeof v !== 'object' || v === null).map(([k, v]) => (
                  <div key={k} style={{ padding: '6px 12px', background: 'var(--bg)', borderRadius: 6, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>{k.replace(/_/g, ' ')}</div>
                    <div style={{ fontSize: 16, fontWeight: 700 }}>{typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v ?? '—')}</div>
                  </div>
                ))}
              </div>
              {(() => {
                const changes = drift.changes || drift.drifts || (Array.isArray(drift) ? drift : []);
                return Array.isArray(changes) && changes.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>File / Path</th><th>Type</th><th>Detected</th></tr></thead>
                      <tbody>
                        {changes.map((c, i) => (
                          <tr key={i}>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{c.path || c.file || '—'}</td>
                            <td><span className={`badge ${c.type === 'added' ? 'badge-ok' : c.type === 'removed' ? 'badge-danger' : 'badge-warn'}`}>{c.type || '—'}</span></td>
                            <td>{c.detected || c.timestamp || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : <div className="empty" style={{ marginTop: 8 }}>No drift detected</div>;
              })()}
            </>
          ) : <div className="empty">Loading...</div>}
        </div>
      )}

      {tab === 'energy' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Energy Status</div>
            {energy ? <><SummaryGrid data={energy} limit={12} /><JsonDetails data={energy} /></> : <div className="empty">Loading...</div>}
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Tenants</div>
            {tenants ? <><SummaryGrid data={tenants} limit={10} /><JsonDetails data={tenants} /></> : <div className="empty">Loading...</div>}
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Patches</div>
            {(() => {
              const ptch = patchData?.patches || (Array.isArray(patchData) ? patchData : []);
              if (!patchData) return <div className="empty">Loading...</div>;
              return ptch.length > 0 ? (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Patch</th><th>Version</th><th>Status</th><th>Date</th></tr></thead>
                    <tbody>
                      {ptch.map((p, i) => (
                        <tr key={i}>
                          <td>{p.name || p.id || '—'}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{p.version || '—'}</td>
                          <td><span className={`badge ${p.status === 'applied' ? 'badge-ok' : 'badge-warn'}`}>{p.status || '—'}</span></td>
                          <td>{p.date || p.applied_at || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', gap: 8 }}>
                {Object.entries(patchData).map(([k, v]) => (
                  <div key={k} style={{ padding: '6px 10px', background: 'var(--bg)', borderRadius: 6 }}>
                    <div style={{ fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>{k.replace(/_/g, ' ')}</div>
                    <div style={{ fontSize: 15, fontWeight: 700 }}>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</div>
                  </div>
                ))}
              </div>;
            })()}
            <JsonDetails data={patchData} />
          </div>
        </div>
      )}

      {tab === 'mesh' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Service Mesh</span>
              <button className="btn btn-sm btn-primary" onClick={async () => {
                try { await api.meshHeal(); toast('Mesh heal initiated', 'success'); } catch { toast('Failed', 'error'); }
              }}>Heal</button>
            </div>
            {mesh ? <><SummaryGrid data={mesh} limit={10} /><JsonDetails data={mesh} /></> : <div className="empty">Loading...</div>}
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>TLS Status</div>
            {tls ? <><SummaryGrid data={tls} limit={10} /><JsonDetails data={tls} /></> : <div className="empty">Loading...</div>}
          </div>
        </div>
      )}

      {tab === 'system' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Threads</div>
            {threads ? (
              <>
                <SummaryGrid data={threads} exclude={['subsystems']} limit={12} />
                <JsonDetails data={threads?.subsystems} label="Subsystems" />
              </>
            ) : <div className="empty">Loading...</div>}
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>SLO Status</div>
            {slo ? <><SummaryGrid data={slo} limit={12} /><JsonDetails data={slo} /></> : <div className="empty">Loading...</div>}
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Dependencies</div>
            {deps ? (
              <>
                {(() => {
                  const depArr = deps.dependencies || deps.deps || (Array.isArray(deps) ? deps : []);
                  const connectors = deps?.connectors?.items || [];
                  return depArr.length > 0 ? (
                    <>
                      <div className="table-wrap">
                        <table>
                          <thead><tr><th>Name</th><th>Version</th><th>Status</th></tr></thead>
                          <tbody>
                            {(Array.isArray(depArr) ? depArr : []).map((d, i) => (
                              <tr key={i}>
                                <td style={{ fontWeight: 600 }}>{d.name || '—'}</td>
                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{d.version || '—'}</td>
                                <td><span className={`badge ${d.healthy !== false ? 'badge-ok' : 'badge-err'}`}>{d.healthy !== false ? 'OK' : 'Unhealthy'}</span></td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <JsonDetails data={deps} />
                    </>
                  ) : (
                    <>
                      <SummaryGrid data={deps} exclude={['connectors', 'deployments', 'dependencies', 'deps']} limit={10} />
                      {connectors.length > 0 && (
                        <div style={{ marginTop: 16 }}>
                          <div className="card-title" style={{ marginBottom: 8 }}>Connectors</div>
                          <div className="table-wrap">
                            <table>
                              <thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Auth</th></tr></thead>
                              <tbody>
                                {connectors.slice(0, 12).map((item, index) => (
                                  <tr key={item.id || index}>
                                    <td>{item.name || item.id || '—'}</td>
                                    <td>{item.kind || '—'}</td>
                                    <td>{item.status || '—'}</td>
                                    <td>{item.auth_mode || '—'}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                      {deps?.deployments && (
                        <div style={{ marginTop: 16 }}>
                          <div className="card-title" style={{ marginBottom: 8 }}>Deployments</div>
                          <SummaryGrid data={deps.deployments} limit={8} />
                        </div>
                      )}
                      <JsonDetails data={deps} />
                    </>
                  );
                })()}
              </>
            ) : <div className="empty">Loading...</div>}
          </div>
        </div>
      )}

      {tab === 'inventory' && (
        <div>
          {/* System inventory summary */}
          {hostInv && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>System Inventory</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                {hostInv.hardware && (
                  <div className="card" style={{ padding: 12 }}>
                    <div className="metric-label">Hardware</div>
                    <div style={{ fontSize: 14, fontWeight: 600 }}>{hostInv.hardware.model || 'Unknown'}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{hostInv.hardware.cpu || '—'}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>RAM: {hostInv.hardware.memory || '—'}</div>
                  </div>
                )}
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Software Packages</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>{hostInv.software?.length ?? '—'}</div>
                </div>
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Services</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>{hostInv.services?.length ?? '—'}</div>
                </div>
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Network Ports</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>{hostInv.ports?.length ?? '—'}</div>
                </div>
                <div className="card" style={{ padding: 12 }}>
                  <div className="metric-label">Users</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>{hostInv.users?.length ?? '—'}</div>
                </div>
              </div>
            </div>
          )}

          {/* Installed apps */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Installed Applications ({hostApps?.count ?? '—'})</span>
              <button className="btn btn-sm" onClick={rApps}>↻ Refresh</button>
            </div>
            {hostApps?.apps?.length > 0 ? (
              <div className="table-wrap" style={{ maxHeight: 500, overflowY: 'auto' }}>
                <table>
                  <thead style={{ position: 'sticky', top: 0, background: 'var(--card-bg)', zIndex: 1 }}>
                    <tr><th>Application</th><th>Version</th><th>Bundle ID</th><th>Size (MB)</th><th>Last Modified</th></tr>
                  </thead>
                  <tbody>
                    {hostApps.apps.map((app, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 600 }}>{app.name}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{app.version || '—'}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>{app.bundle_id || '—'}</td>
                        <td>{app.size_mb != null ? app.size_mb.toFixed(0) : '—'}</td>
                        <td style={{ whiteSpace: 'nowrap', fontSize: 12 }}>{app.last_modified || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <div className="empty">{hostApps?.message || 'No app data available (macOS only)'}</div>}
          </div>

          {/* Services list */}
          {hostInv?.services?.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Services</div>
              <div className="table-wrap" style={{ maxHeight: 300, overflowY: 'auto' }}>
                <table>
                  <thead style={{ position: 'sticky', top: 0, background: 'var(--card-bg)', zIndex: 1 }}>
                    <tr><th>Service</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {hostInv.services.map((s, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{typeof s === 'string' ? s : s.name || s.label || s.id || 'service'}</td>
                        <td>{typeof s === 'object' ? s.status || '—' : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Listening ports */}
          {hostInv?.ports?.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Listening Ports</div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Port</th><th>Protocol</th><th>Process</th></tr></thead>
                  <tbody>
                    {hostInv.ports.map((p, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{typeof p === 'string' ? p : p.port || p.address || p.endpoint || '—'}</td>
                        <td>{typeof p === 'object' ? p.protocol || '—' : '—'}</td>
                        <td>{typeof p === 'object' ? p.process || '—' : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'vulnerabilities' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Vulnerability Scanner</span>
            <button className="btn btn-sm" onClick={rVuln}>↻ Refresh</button>
          </div>
          {vulnSummary ? <><SummaryGrid data={vulnSummary} limit={12} /><JsonDetails data={vulnSummary} /></> : <div className="empty">Loading...</div>}
        </div>
      )}

      {tab === 'ndr' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Network Detection & Response</span>
            <button className="btn btn-sm" onClick={rNdr}>↻ Refresh</button>
          </div>
          {ndrData ? <><SummaryGrid data={ndrData} limit={12} /><JsonDetails data={ndrData} /></> : <div className="empty">No network data yet. Ingest netflow via POST /api/ndr/netflow</div>}
        </div>
      )}

      {tab === 'containers' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Container Security</span>
            <button className="btn btn-sm" onClick={rContainer}>↻ Refresh</button>
          </div>
          {containerSt ? <SummaryGrid data={containerSt} limit={6} /> : <div className="empty">Loading...</div>}
          {containerAlerts && Array.isArray(containerAlerts) && containerAlerts.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>Recent Alerts</div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Time</th><th>Kind</th><th>Container</th><th>Severity</th><th>Message</th></tr></thead>
                  <tbody>
                    {containerAlerts.slice(0, 50).map((a, i) => (
                      <tr key={i}>
                        <td style={{ fontSize: 11 }}>{a.timestamp || '—'}</td>
                        <td>{a.kind || '—'}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{a.container_id || '—'}</td>
                        <td><span className={`sev-${(a.severity || 'low').toLowerCase()}`}>{a.severity || '—'}</span></td>
                        <td>{a.message || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'certificates' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">TLS Certificate Monitor</span>
            <button className="btn btn-sm" onClick={rCerts}>↻ Refresh</button>
          </div>
          {certSummary ? <SummaryGrid data={certSummary} limit={10} /> : <div className="empty">Loading...</div>}
          {certAlerts && Array.isArray(certAlerts) && certAlerts.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>Certificate Alerts</div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Domain</th><th>Issue</th><th>Days Left</th><th>Severity</th></tr></thead>
                  <tbody>
                    {certAlerts.map((a, i) => (
                      <tr key={i}>
                        <td>{a.domain || a.subject || '—'}</td>
                        <td>{a.kind || a.issue || '—'}</td>
                        <td>{a.days_remaining ?? '—'}</td>
                        <td><span className={`sev-${(a.severity || 'medium').toLowerCase()}`}>{a.severity || '—'}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'assets' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Unified Asset Inventory</span>
            <button className="btn btn-sm" onClick={rAssets}>↻ Refresh</button>
          </div>
          {assetSummary ? <SummaryGrid data={assetSummary} limit={12} /> : <div className="empty">Loading...</div>}
          <div style={{ display: 'flex', gap: 8, marginTop: 16, marginBottom: 12 }}>
            <input type="text" placeholder="Search assets..." value={assetSearch} onChange={e => setAssetSearch(e.target.value)} className="auth-input" style={{ flex: 1 }} />
            <button className="btn btn-sm btn-primary" onClick={async () => {
              if (!assetSearch.trim()) return;
              try { const r = await api.assetsSearch(assetSearch); setAssetResults(r); } catch { toast('Search failed', 'error'); }
            }}>Search</button>
          </div>
          {assetResults && Array.isArray(assetResults) && (
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Provider</th><th>Risk</th><th>Last Seen</th></tr></thead>
                <tbody>
                  {assetResults.map((a, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{a.id || '—'}</td>
                      <td>{a.name || a.hostname || '—'}</td>
                      <td>{a.asset_type || '—'}</td>
                      <td>{a.provider || '—'}</td>
                      <td>{a.risk_score != null ? a.risk_score.toFixed(2) : '—'}</td>
                      <td>{a.last_seen || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {assetSummary && <JsonDetails data={assetSummary} />}
        </div>
      )}
    </div>
  );
}

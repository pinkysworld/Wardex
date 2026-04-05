import { useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';

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

  return (
    <div>
      <div className="tabs">
        {['monitor', 'correlation', 'drift', 'energy', 'mesh', 'system', 'inventory'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'monitor' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Monitor Status</div>
            <div className="json-block">{JSON.stringify(monSt, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Fingerprint</div>
            <div className="json-block">{JSON.stringify(fp, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Causal Graph</div>
            <div className="json-block">{JSON.stringify(causal, null, 2)}</div>
          </div>
        </div>
      )}

      {tab === 'correlation' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Correlation Engine</div>
          <div className="json-block">{JSON.stringify(corrData, null, 2)}</div>
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
          <div className="json-block">{JSON.stringify(drift, null, 2)}</div>
        </div>
      )}

      {tab === 'energy' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Energy Status</div>
            <div className="json-block">{JSON.stringify(energy, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Tenants</div>
            <div className="json-block">{JSON.stringify(tenants, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Patches</div>
            <div className="json-block">{JSON.stringify(patchData, null, 2)}</div>
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
            <div className="json-block">{JSON.stringify(mesh, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>TLS Status</div>
            <div className="json-block">{JSON.stringify(tls, null, 2)}</div>
          </div>
        </div>
      )}

      {tab === 'system' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Threads</div>
            <div className="json-block">{JSON.stringify(threads, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>SLO Status</div>
            <div className="json-block">{JSON.stringify(slo, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Dependencies</div>
            <div className="json-block">{JSON.stringify(deps, null, 2)}</div>
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
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{typeof s === 'string' ? s : s.name || JSON.stringify(s)}</td>
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
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{typeof p === 'string' ? p : p.port || JSON.stringify(p)}</td>
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
    </div>
  );
}

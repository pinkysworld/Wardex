import { useState, useEffect } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';

export default function Settings() {
  const toast = useToast();
  const [tab, setTab] = useState('config');
  const { data: config, reload: rConfig } = useApi(api.configCurrent);
  const { data: monOpts } = useApi(api.monitoringOptions);
  const { data: monPaths } = useApi(api.monitoringPaths);
  const { data: flags } = useApi(api.featureFlags);
  const { data: siemSt } = useApi(api.siemStatus);
  const { data: siemCfg, reload: rSiem } = useApi(api.siemConfig);
  const { data: taxiiSt } = useApi(api.taxiiStatus);
  const { data: taxiiCfg, reload: rTaxii } = useApi(api.taxiiConfig);
  const { data: enrichConn } = useApi(api.enrichmentConnectors);
  const { data: idp } = useApi(api.idpProviders);
  const { data: scim } = useApi(api.scimConfig);
  const { data: sbomData } = useApi(api.sbom);
  const { data: dbVer } = useApi(api.adminDbVersion);
  const { data: dlqData } = useApi(api.dlqStats);
  const { data: dbSizes, reload: rSizes } = useApi(api.adminDbSizes);
  const { data: storageStats, reload: rStats } = useApi(api.storageStats);
  const [configEditing, setConfigEditing] = useState(false);
  const [configText, setConfigText] = useState('');
  const [purgeDays, setPurgeDays] = useState(30);
  const [compacting, setCompacting] = useState(false);
  const [purging, setPurging] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [cleaning, setCleaning] = useState(false);

  const startEdit = () => {
    setConfigText(typeof config === 'string' ? config : JSON.stringify(config, null, 2));
    setConfigEditing(true);
  };

  const formatBytes = (bytes) => {
    if (bytes == null) return '—';
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  };

  return (
    <div>
      <div className="tabs">
        {['config', 'integrations', 'flags', 'admin'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'config' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Configuration</span>
              <div className="btn-group">
                <button className="btn btn-sm" onClick={rConfig}>↻ Reload</button>
                <button className="btn btn-sm" onClick={async () => {
                  try { await api.configReload(); toast('Config reloaded from disk', 'success'); rConfig(); } catch { toast('Reload failed', 'error'); }
                }}>Reload from Disk</button>
                {!configEditing && <button className="btn btn-sm btn-primary" onClick={startEdit}>Edit</button>}
              </div>
            </div>
            {configEditing ? (
              <div>
                <textarea className="form-textarea" style={{ height: 300 }} value={configText} onChange={e => setConfigText(e.target.value)} />
                <div className="btn-group" style={{ marginTop: 8 }}>
                  <button className="btn btn-primary" onClick={async () => {
                    try {
                      let body;
                      try { body = JSON.parse(configText); } catch { toast('Invalid JSON', 'error'); return; }
                      await api.configSave(body);
                      toast('Config saved', 'success');
                      setConfigEditing(false);
                      rConfig();
                    } catch { toast('Save failed', 'error'); }
                  }}>Save</button>
                  <button className="btn" onClick={() => setConfigEditing(false)}>Cancel</button>
                </div>
              </div>
            ) : (
              <div className="json-block">{typeof config === 'string' ? config : JSON.stringify(config, null, 2)}</div>
            )}
          </div>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Monitoring Options</div>
              <div className="json-block">{JSON.stringify(monOpts, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Monitored Paths</div>
              <div className="json-block">{JSON.stringify(monPaths, null, 2)}</div>
            </div>
          </div>
        </>
      )}

      {tab === 'integrations' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-header">
                <span className="card-title">SIEM Integration</span>
                <span className={`badge ${siemSt?.connected ? 'badge-ok' : 'badge-warn'}`}>{siemSt?.connected ? 'Connected' : 'Not connected'}</span>
              </div>
              <div className="json-block">{JSON.stringify(siemCfg, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-header">
                <span className="card-title">TAXII Feed</span>
                <div className="btn-group">
                  <span className={`badge ${taxiiSt?.connected ? 'badge-ok' : 'badge-warn'}`}>{taxiiSt?.connected ? 'Active' : 'Inactive'}</span>
                  <button className="btn btn-sm" onClick={async () => {
                    try { await api.taxiiPull(); toast('TAXII pull initiated', 'success'); } catch { toast('Pull failed', 'error'); }
                  }}>Pull Now</button>
                </div>
              </div>
              <div className="json-block">{JSON.stringify(taxiiCfg, null, 2)}</div>
            </div>
          </div>
          <div className="card-grid" style={{ marginTop: 16 }}>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Enrichment Connectors</div>
              <div className="json-block">{JSON.stringify(enrichConn, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>IdP Providers</div>
              <div className="json-block">{JSON.stringify(idp, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>SCIM Config</div>
              <div className="json-block">{JSON.stringify(scim, null, 2)}</div>
            </div>
          </div>
        </>
      )}

      {tab === 'flags' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Feature Flags</div>
          {flags && typeof flags === 'object' ? (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Flag</th><th>Status</th></tr></thead>
                <tbody>
                  {Object.entries(flags).map(([k, v]) => (
                    <tr key={k}>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{k}</td>
                      <td><span className={`badge ${v ? 'badge-ok' : 'badge-warn'}`}>{v ? 'Enabled' : 'Disabled'}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="json-block">{JSON.stringify(flags, null, 2)}</div>
          )}
        </div>
      )}

      {tab === 'admin' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>DB Version</div>
              <div className="json-block">{JSON.stringify(dbVer, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Dead Letter Queue</div>
              <div className="json-block">{JSON.stringify(dlqData, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>SBOM</div>
              <div className="json-block">{JSON.stringify(sbomData, null, 2)}</div>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Database Storage</div>
            {dbSizes && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 16 }}>
                <div className="stat-box">
                  <div className="stat-label">Main DB</div>
                  <div className="stat-value">{formatBytes(dbSizes.db_bytes)}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">WAL File</div>
                  <div className="stat-value">{formatBytes(dbSizes.wal_bytes)}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">SHM File</div>
                  <div className="stat-value">{formatBytes(dbSizes.shm_bytes)}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Total</div>
                  <div className="stat-value">{formatBytes(dbSizes.total_bytes)}</div>
                </div>
              </div>
            )}
            {storageStats && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 12, marginBottom: 16 }}>
                <div className="stat-box"><div className="stat-label">Alerts</div><div className="stat-value">{storageStats.total_alerts ?? '—'}</div></div>
                <div className="stat-box"><div className="stat-label">Cases</div><div className="stat-value">{storageStats.total_cases ?? '—'}</div></div>
                <div className="stat-box"><div className="stat-label">Audit</div><div className="stat-value">{storageStats.total_audit_entries ?? '—'}</div></div>
                <div className="stat-box"><div className="stat-label">Agents</div><div className="stat-value">{storageStats.total_agents ?? '—'}</div></div>
              </div>
            )}
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Database Maintenance</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <button className="btn" disabled={compacting} onClick={async () => {
                  setCompacting(true);
                  try {
                    const r = await api.adminDbCompact();
                    toast(`Compacted: ${formatBytes(r.bytes_reclaimed)} reclaimed`, 'success');
                    rSizes();
                  } catch { toast('Compact failed', 'error'); }
                  setCompacting(false);
                }}>{compacting ? 'Compacting...' : 'Compact Database'}</button>
                <span style={{ fontSize: '0.85rem', opacity: 0.7 }}>VACUUM + WAL checkpoint — reclaims unused space</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <label style={{ fontSize: '0.85rem' }}>Purge data older than</label>
                <input type="number" min="1" max="3650" value={purgeDays} onChange={e => setPurgeDays(Number(e.target.value))}
                  style={{ width: 70, padding: '4px 8px' }} />
                <span style={{ fontSize: '0.85rem' }}>days</span>
                <button className="btn" disabled={purging} onClick={async () => {
                  if (isNaN(purgeDays) || purgeDays < 1) { toast('Invalid value — enter 1-3650 days', 'error'); return; }
                  if (!confirm(`Purge all records older than ${purgeDays} days?`)) return;
                  setPurging(true);
                  try {
                    const r = await api.adminDbPurge({ retention_days: purgeDays });
                    toast(`Purged: ${r.alerts_purged} alerts, ${r.audit_purged} audit, ${r.metrics_purged} metrics`, 'success');
                    rSizes(); rStats();
                  } catch { toast('Purge failed', 'error'); }
                  setPurging(false);
                }}>{purging ? 'Purging...' : 'Purge Old Data'}</button>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <button className="btn" disabled={cleaning} onClick={async () => {
                  setCleaning(true);
                  try {
                    const r = await api.adminCleanupLegacy();
                    if (r.count > 0) toast(`Cleaned ${r.count} legacy files`, 'success');
                    else toast('No legacy files found', 'info');
                  } catch { toast('Cleanup failed', 'error'); }
                  setCleaning(false);
                }}>{cleaning ? 'Cleaning...' : 'Clean Legacy Files'}</button>
                <span style={{ fontSize: '0.85rem', opacity: 0.7 }}>Remove old .json/.jsonl flat files from var/</span>
              </div>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Admin Actions</div>
            <div className="btn-group">
              <button className="btn" onClick={async () => {
                try { await api.adminBackup(); toast('Backup created', 'success'); } catch { toast('Backup failed', 'error'); }
              }}>Create Backup</button>
              <button className="btn btn-danger" style={{ marginLeft: 8 }} onClick={async () => {
                const answer = prompt('Type RESET_ALL_DATA to confirm deleting all database records:');
                if (answer !== 'RESET_ALL_DATA') { toast('Reset cancelled', 'info'); return; }
                setResetting(true);
                try {
                  const r = await api.adminDbReset({ confirm: 'RESET_ALL_DATA' });
                  toast(`Database reset: ${r.records_purged} records purged`, 'warning');
                  rSizes(); rStats();
                } catch { toast('Reset failed', 'error'); }
                setResetting(false);
              }}>{resetting ? 'Resetting...' : 'Reset Database'}</button>
              <button className="btn btn-danger" onClick={async () => {
                if (!confirm('Shutdown the Wardex server?')) return;
                try { await api.shutdown(); toast('Shutdown initiated', 'warning'); } catch { toast('Shutdown failed', 'error'); }
              }}>Shutdown Server</button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

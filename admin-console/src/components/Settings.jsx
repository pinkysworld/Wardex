import { useState } from 'react';
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
  const [configEditing, setConfigEditing] = useState(false);
  const [configText, setConfigText] = useState('');

  const startEdit = () => {
    setConfigText(typeof config === 'string' ? config : JSON.stringify(config, null, 2));
    setConfigEditing(true);
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
                      try { body = JSON.parse(configText); } catch { body = configText; }
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
            <div className="card-title" style={{ marginBottom: 12 }}>Admin Actions</div>
            <div className="btn-group">
              <button className="btn" onClick={async () => {
                try { await api.adminBackup(); toast('Backup created', 'success'); } catch { toast('Backup failed', 'error'); }
              }}>Create Backup</button>
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

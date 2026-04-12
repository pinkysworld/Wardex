import { useState, useEffect, useMemo } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid } from './operator.jsx';

function ToggleSwitch({ label, checked, onChange, description }) {
  return (
    <div
      role="switch"
      aria-checked={checked}
      tabIndex={0}
      onClick={() => onChange(!checked)}
      onKeyDown={e => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); onChange(!checked); } }}
      style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', padding: '6px 0' }}
    >
      <div
        style={{ width: 40, height: 22, borderRadius: 11, background: checked ? 'var(--primary)' : 'var(--border)', position: 'relative', transition: 'background .2s', flexShrink: 0 }}>
        <div style={{ width: 18, height: 18, borderRadius: 9, background: '#fff', position: 'absolute', top: 2, left: checked ? 20 : 2, transition: 'left .2s', boxShadow: '0 1px 3px rgba(0,0,0,.2)' }} />
      </div>
      <div>
        <div style={{ fontSize: 13, fontWeight: 500 }}>{label}</div>
        {description && <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{description}</div>}
      </div>
    </div>
  );
}

function NumberInput({ label, value, onChange, min, max, step, unit, description }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 4 }}>{label}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input type="number" value={value ?? ''} onChange={e => onChange(Number(e.target.value))}
          min={min} max={max} step={step || 1}
          style={{ width: 90, padding: '4px 8px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
        {unit && <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{unit}</span>}
      </div>
      {description && <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>{description}</div>}
    </div>
  );
}

function TextInput({ label, value, onChange, placeholder, description }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 4 }}>{label}</div>
      <input type="text" value={value ?? ''} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        style={{ width: '100%', maxWidth: 400, padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
      {description && <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>{description}</div>}
    </div>
  );
}

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
  const [structuredConfig, setStructuredConfig] = useState(null);
  const [editMode, setEditMode] = useState('form'); // 'form' or 'json'
  const [savedSnapshot, setSavedSnapshot] = useState(null);
  const [showDiff, setShowDiff] = useState(false);
  const [purgeDays, setPurgeDays] = useState(30);
  const [compacting, setCompacting] = useState(false);
  const [purging, setPurging] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [cleaning, setCleaning] = useState(false);

  // ── Team (RBAC) ──
  const { data: teamUsers, reload: rTeam } = useApi(api.rbacUsers);
  const [newUser, setNewUser] = useState({ username: '', role: 'analyst' });
  const [creatingUser, setCreatingUser] = useState(false);

  // Parse config into structured form when loaded
  useEffect(() => {
    if (config && !configEditing) {
      const parsed = typeof config === 'string' ? (() => { try { return JSON.parse(config); } catch { return null; } })() : config;
      if (parsed) {
        setStructuredConfig(JSON.parse(JSON.stringify(parsed)));
        setSavedSnapshot(JSON.stringify(parsed, null, 2));
      }
    }
  }, [config, configEditing]);

  const startEdit = () => {
    const parsed = typeof config === 'string' ? (() => { try { return JSON.parse(config); } catch { return null; } })() : config;
    if (parsed) {
      setStructuredConfig(JSON.parse(JSON.stringify(parsed)));
      setSavedSnapshot(JSON.stringify(parsed, null, 2));
    }
    setConfigText(typeof config === 'string' ? config : JSON.stringify(config, null, 2));
    setConfigEditing(true);
  };

  const updateField = (path, value) => {
    setStructuredConfig(prev => {
      const next = JSON.parse(JSON.stringify(prev));
      const keys = path.split('.');
      let obj = next;
      for (let i = 0; i < keys.length - 1; i++) {
        if (obj[keys[i]] === undefined) obj[keys[i]] = {};
        obj = obj[keys[i]];
      }
      obj[keys[keys.length - 1]] = value;
      return next;
    });
  };

  const saveConfig = async () => {
    try {
      const body = editMode === 'json' ? JSON.parse(configText) : structuredConfig;
      await api.configSave(body);
      toast('Config saved', 'success');
      setConfigEditing(false);
      setSavedSnapshot(JSON.stringify(body, null, 2));
      rConfig();
    } catch (e) {
      toast(editMode === 'json' && e instanceof SyntaxError ? 'Invalid JSON' : 'Save failed', 'error');
    }
  };

  // Config diff computation
  const configDiff = useMemo(() => {
    if (!savedSnapshot || !structuredConfig) return null;
    const current = JSON.stringify(structuredConfig, null, 2);
    if (current === savedSnapshot) return null;
    const oldLines = savedSnapshot.split('\n');
    const newLines = current.split('\n');
    const changes = [];
    const maxLen = Math.max(oldLines.length, newLines.length);
    for (let i = 0; i < maxLen; i++) {
      if (oldLines[i] !== newLines[i]) {
        if (oldLines[i]) changes.push({ type: 'remove', line: i + 1, text: oldLines[i] });
        if (newLines[i]) changes.push({ type: 'add', line: i + 1, text: newLines[i] });
      }
    }
    return changes.length > 0 ? changes : null;
  }, [savedSnapshot, structuredConfig]);

  const formatBytes = (bytes) => {
    if (bytes == null) return '—';
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  };

  const configScalars = useMemo(() => {
    if (!structuredConfig || typeof structuredConfig !== 'object') return null;
    return Object.fromEntries(
      Object.entries(structuredConfig).filter(([, value]) => value == null || typeof value !== 'object' || Array.isArray(value))
    );
  }, [structuredConfig]);

  const configSections = useMemo(() => {
    if (!structuredConfig || typeof structuredConfig !== 'object') return [];
    return Object.entries(structuredConfig).filter(([, value]) => value && typeof value === 'object' && !Array.isArray(value));
  }, [structuredConfig]);

  const normalizedMonitoringPaths = useMemo(() => {
    if (Array.isArray(monPaths)) return monPaths;
    if (Array.isArray(monPaths?.paths)) return monPaths.paths;
    if (Array.isArray(monPaths?.items)) return monPaths.items;
    return [];
  }, [monPaths]);

  const connectorRows = useMemo(() => {
    if (Array.isArray(enrichConn)) return enrichConn;
    if (Array.isArray(enrichConn?.items)) return enrichConn.items;
    if (Array.isArray(enrichConn?.connectors)) return enrichConn.connectors;
    return [];
  }, [enrichConn]);

  const idpRows = useMemo(() => {
    if (Array.isArray(idp)) return idp;
    if (Array.isArray(idp?.providers)) return idp.providers;
    if (Array.isArray(idp?.items)) return idp.items;
    return [];
  }, [idp]);

  const flagEntries = useMemo(() => {
    if (!flags || typeof flags !== 'object' || Array.isArray(flags)) return [];
    return Object.entries(flags);
  }, [flags]);

  // Default config values for reset
  const DEFAULTS = {
    collection_interval_secs: 15,
    alert_threshold: 2.5,
    entropy_threshold_pct: 10,
    network_burst_threshold_kbps: 3500,
    port: 9097,
    log_level: 'info',
  };

  const resetToDefaults = () => {
    if (!confirm('Reset configuration to default values?')) return;
    setStructuredConfig(prev => {
      const next = JSON.parse(JSON.stringify(prev));
      Object.entries(DEFAULTS).forEach(([k, v]) => { if (k in next) next[k] = v; });
      return next;
    });
    toast('Reset to defaults — click Save to apply', 'info');
  };

  return (
    <div>
      <div className="tabs">
        {['config', 'monitoring', 'integrations', 'flags', 'team', 'admin'].map(t => (
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
                {configEditing && (
                  <>
                    <button className={`btn btn-sm ${editMode === 'form' ? 'btn-primary' : ''}`} onClick={() => {
                      setEditMode('form');
                      if (configText) { try { setStructuredConfig(JSON.parse(configText)); } catch { /* ignore parse errors */ } }
                    }}>Form</button>
                    <button className={`btn btn-sm ${editMode === 'json' ? 'btn-primary' : ''}`} onClick={() => {
                      setEditMode('json');
                      setConfigText(JSON.stringify(structuredConfig, null, 2));
                    }}>JSON</button>
                  </>
                )}
              </div>
            </div>
            {configEditing ? (
              editMode === 'json' ? (
                <div>
                  <textarea className="form-textarea" style={{ height: 300 }} value={configText} onChange={e => setConfigText(e.target.value)} />
                  <div className="btn-group" style={{ marginTop: 8 }}>
                    <button className="btn btn-primary" onClick={saveConfig}>Save</button>
                    <button className="btn" onClick={() => setConfigEditing(false)}>Cancel</button>
                  </div>
                </div>
              ) : structuredConfig ? (
                <div>
                  {/* Structured form for common fields */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, padding: '12px 0' }}>
                    <div className="card" style={{ padding: 14 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12, color: 'var(--primary)' }}>General</div>
                      <NumberInput label="Collection Interval" value={structuredConfig.collection_interval_secs} onChange={v => updateField('collection_interval_secs', v)} min={1} max={300} unit="seconds" />
                      <NumberInput label="Port" value={structuredConfig.port} onChange={v => updateField('port', v)} min={1} max={65535} />
                      <TextInput label="Log Level" value={structuredConfig.log_level} onChange={v => updateField('log_level', v)} placeholder="info, debug, warn" />
                    </div>
                    <div className="card" style={{ padding: 14 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12, color: 'var(--primary)' }}>Detection Thresholds</div>
                      <NumberInput label="Alert Threshold" value={structuredConfig.alert_threshold} onChange={v => updateField('alert_threshold', v)} min={0} max={10} step={0.1} description="Score above which an alert fires" />
                      <NumberInput label="Entropy Threshold" value={structuredConfig.entropy_threshold_pct} onChange={v => updateField('entropy_threshold_pct', v)} min={0} max={100} unit="%" />
                      <NumberInput label="Network Burst Threshold" value={structuredConfig.network_burst_threshold_kbps} onChange={v => updateField('network_burst_threshold_kbps', v)} min={0} max={100000} unit="kbps" />
                    </div>
                    {structuredConfig.siem && (
                      <div className="card" style={{ padding: 14 }}>
                        <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12, color: 'var(--primary)' }}>SIEM</div>
                        <ToggleSwitch label="SIEM Enabled" checked={!!structuredConfig.siem?.enabled} onChange={v => updateField('siem.enabled', v)} />
                        <TextInput label="Endpoint" value={structuredConfig.siem?.endpoint} onChange={v => updateField('siem.endpoint', v)} placeholder="https://siem.example.com" />
                        <TextInput label="Format" value={structuredConfig.siem?.format} onChange={v => updateField('siem.format', v)} placeholder="cef, json, leef" />
                      </div>
                    )}
                    {structuredConfig.taxii && (
                      <div className="card" style={{ padding: 14 }}>
                        <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12, color: 'var(--primary)' }}>TAXII</div>
                        <ToggleSwitch label="TAXII Enabled" checked={!!structuredConfig.taxii?.enabled} onChange={v => updateField('taxii.enabled', v)} />
                        <TextInput label="Server URL" value={structuredConfig.taxii?.url} onChange={v => updateField('taxii.url', v)} placeholder="https://taxii.example.com" />
                        <NumberInput label="Poll Interval" value={structuredConfig.taxii?.poll_interval_secs} onChange={v => updateField('taxii.poll_interval_secs', v)} min={60} unit="seconds" />
                      </div>
                    )}
                  </div>
                  {/* All other fields as key-value pairs */}
                  <details style={{ marginTop: 12 }}>
                    <summary style={{ cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)' }}>All configuration fields ({Object.keys(structuredConfig).length})</summary>
                    <div style={{ padding: '12px 0' }}>
                      {Object.entries(structuredConfig).filter(([k]) => !['siem', 'taxii'].includes(k) && typeof structuredConfig[k] !== 'object').map(([k, v]) => (
                        <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, minWidth: 200, color: 'var(--text-secondary)' }}>{k}</span>
                          {typeof v === 'boolean' ? (
                            <ToggleSwitch label="" checked={v} onChange={val => updateField(k, val)} />
                          ) : (
                            <input type={typeof v === 'number' ? 'number' : 'text'} value={v ?? ''} onChange={e => updateField(k, typeof v === 'number' ? Number(e.target.value) : e.target.value)}
                              style={{ flex: 1, maxWidth: 300, padding: '4px 8px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12 }} />
                          )}
                        </div>
                      ))}
                    </div>
                  </details>
                  {/* Config diff */}
                  {configDiff && (
                    <div style={{ marginTop: 12 }}>
                      <button className="btn btn-sm" onClick={() => setShowDiff(!showDiff)} style={{ marginBottom: 8 }}>
                        {showDiff ? 'Hide' : 'Show'} Changes ({configDiff.length})
                      </button>
                      {showDiff && (
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, background: 'var(--bg)', borderRadius: 'var(--radius)', padding: 10, maxHeight: 200, overflowY: 'auto' }}>
                          {configDiff.map((d, i) => (
                            <div key={i} style={{ color: d.type === 'add' ? 'var(--success)' : 'var(--danger)', whiteSpace: 'pre' }}>
                              {d.type === 'add' ? '+' : '-'} {d.text}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  <div className="btn-group" style={{ marginTop: 12 }}>
                    <button className="btn btn-primary" onClick={saveConfig}>Save</button>
                    <button className="btn" onClick={() => setConfigEditing(false)}>Cancel</button>
                    <button className="btn" onClick={resetToDefaults} title="Reset common fields to default values">Reset Defaults</button>
                  </div>
                </div>
              ) : (
                <div className="empty">Loading configuration...</div>
              )
            ) : (
              structuredConfig ? (
                <div style={{ padding: '12px 0' }}>
                  <SummaryGrid data={configScalars} limit={12} emptyMessage="Configuration is organized into sections below" />
                  {configSections.length > 0 && (
                    <div className="card-grid" style={{ marginTop: 16 }}>
                      {configSections.map(([sectionKey, sectionValue]) => (
                        <div key={sectionKey} className="card" style={{ padding: 14 }}>
                          <div className="card-title" style={{ marginBottom: 12 }}>{sectionKey.replace(/_/g, ' ')}</div>
                          <SummaryGrid data={sectionValue} limit={8} />
                        </div>
                      ))}
                    </div>
                  )}
                  <JsonDetails data={structuredConfig} label="Full configuration breakdown" />
                </div>
              ) : (
                <>
                  <div className="empty">Configuration is not yet available in structured form.</div>
                  <JsonDetails data={config} label="Available configuration fields" />
                </>
              )
            )}
          </div>
        </>
      )}

      {tab === 'monitoring' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Monitoring Scope</div>
            {monOpts && typeof monOpts === 'object' ? (
              <>
                <SummaryGrid data={monOpts} limit={12} />
                <JsonDetails data={monOpts} />
              </>
            ) : (
              <>
                <div className="empty">No monitoring scope metadata available.</div>
                <JsonDetails data={monOpts} />
              </>
            )}
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Monitored Paths</div>
            {normalizedMonitoringPaths.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Path</th><th>Type</th></tr></thead>
                  <tbody>
                    {normalizedMonitoringPaths.map((p, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                          {typeof p === 'string' ? p : p.path || p.pattern || p.root || p.name || '—'}
                        </td>
                        <td>{typeof p === 'object' ? p.type || p.kind || 'file' : 'file'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : monPaths && typeof monPaths === 'object' ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 0 }}>
                {Object.entries(monPaths).map(([k, v]) => (
                  <div key={k} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{k}:</span>
                    <span style={{ marginLeft: 8, fontSize: 13 }}>{typeof v === 'boolean' ? (v ? '✓ active' : '✗ inactive') : String(v)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <>
                <SummaryGrid data={monPaths} limit={10} />
                <JsonDetails data={monPaths} />
              </>
            )}
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
              {siemCfg && typeof siemCfg === 'object' ? (
                <>
                  <SummaryGrid data={siemCfg} limit={10} />
                  <JsonDetails data={siemCfg} />
                </>
              ) : (
                <>
                  <div className="empty">No SIEM configuration available.</div>
                  <JsonDetails data={siemCfg} />
                </>
              )}
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
              {taxiiCfg && typeof taxiiCfg === 'object' ? (
                <>
                  <SummaryGrid data={taxiiCfg} limit={10} />
                  <JsonDetails data={taxiiCfg} />
                </>
              ) : (
                <>
                  <div className="empty">No TAXII configuration available.</div>
                  <JsonDetails data={taxiiCfg} />
                </>
              )}
            </div>
          </div>
          <div className="card-grid" style={{ marginTop: 16 }}>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Enrichment Connectors</div>
              {connectorRows.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Name</th><th>Type</th><th>Status</th></tr></thead>
                      <tbody>{connectorRows.map((c, i) => (
                        <tr key={i}><td>{c.name || c.id || '—'}</td><td>{c.type || '—'}</td><td><span className={`badge ${c.enabled ? 'badge-ok' : 'badge-warn'}`}>{c.enabled ? 'Active' : 'Inactive'}</span></td></tr>
                      ))}</tbody>
                    </table>
                  </div>
              ) : (
                <>
                  <SummaryGrid data={enrichConn} limit={10} emptyMessage="No connectors configured" />
                  <JsonDetails data={enrichConn} />
                </>
              )}
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>IdP Providers</div>
              {idpRows.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Name</th><th>Type</th><th>Status</th></tr></thead>
                      <tbody>{idpRows.map((p, i) => (
                        <tr key={i}><td>{p.name || p.id || '—'}</td><td>{p.type || '—'}</td><td>{p.enabled ? '✓' : '✗'}</td></tr>
                      ))}</tbody>
                    </table>
                  </div>
              ) : (
                <>
                  <SummaryGrid data={idp} limit={10} emptyMessage="No identity providers configured" />
                  <JsonDetails data={idp} />
                </>
              )}
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>SCIM Config</div>
              {scim && typeof scim === 'object' && !Array.isArray(scim) ? (
                <>
                  <SummaryGrid data={scim} limit={10} />
                  <JsonDetails data={scim} />
                </>
              ) : (
                <>
                  <div className="empty">No SCIM configuration available.</div>
                  <JsonDetails data={scim} />
                </>
              )}
            </div>
          </div>
        </>
      )}

      {tab === 'flags' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Feature Flags</div>
          {flagEntries.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Flag</th><th>Status</th></tr></thead>
                <tbody>
                  {flagEntries.map(([k, v]) => (
                    <tr key={k}>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{k}</td>
                      <td><span className={`badge ${v ? 'badge-ok' : 'badge-warn'}`}>{v ? 'Enabled' : 'Disabled'}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <>
              <div className="empty">No feature flags available.</div>
              <JsonDetails data={flags} />
            </>
          )}
        </div>
      )}

      {tab === 'team' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Team &amp; RBAC</div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div>
              <div style={{ fontSize: 12, marginBottom: 4 }}>Username</div>
              <input className="input" value={newUser.username} onChange={e => setNewUser(p => ({ ...p, username: e.target.value }))}
                placeholder="username" style={{ width: 180 }} />
            </div>
            <div>
              <div style={{ fontSize: 12, marginBottom: 4 }}>Role</div>
              <select className="input" value={newUser.role} onChange={e => setNewUser(p => ({ ...p, role: e.target.value }))}>
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="viewer">Viewer</option>
                <option value="service-account">Service Account</option>
              </select>
            </div>
            <button className="btn btn-primary" disabled={!newUser.username.trim() || creatingUser}
              onClick={async () => {
                setCreatingUser(true);
                try {
                  const res = await api.rbacCreateUser({ username: newUser.username.trim(), role: newUser.role });
                  toast(`User created${res?.token ? ' — token: ' + res.token : ''}`, 'success');
                  setNewUser({ username: '', role: 'analyst' });
                  rTeam();
                } catch (e) { toast('Failed to create user: ' + (e.message || e), 'error'); }
                setCreatingUser(false);
              }}>{creatingUser ? 'Creating…' : 'Create User'}</button>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead>
              <tbody>
                {(Array.isArray(teamUsers) ? teamUsers : []).map(u => (
                  <tr key={u.username || u.name}>
                    <td>{u.username || u.name}</td>
                    <td><span className={`badge ${u.role === 'admin' ? 'badge-danger' : u.role === 'analyst' ? 'badge-ok' : 'badge-info'}`}>{u.role}</span></td>
                    <td>
                      <button className="btn btn-ghost btn-sm" style={{ color: 'var(--danger)' }}
                        onClick={async () => {
                          if (!confirm(`Delete user "${u.username || u.name}"?`)) return;
                          try { await api.rbacDeleteUser(u.username || u.name); toast('User deleted', 'success'); rTeam(); }
                          catch (e) { toast('Delete failed: ' + (e.message || e), 'error'); }
                        }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {(!teamUsers || (Array.isArray(teamUsers) && teamUsers.length === 0)) && (
            <div className="empty">No team members configured yet.</div>
          )}
        </div>
      )}

      {tab === 'admin' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>DB Version</div>
              <SummaryGrid data={dbVer} limit={6} />
              <JsonDetails data={dbVer} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Dead Letter Queue</div>
              <SummaryGrid data={dlqData} limit={8} />
              <JsonDetails data={dlqData} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>SBOM</div>
              <SummaryGrid data={sbomData} limit={8} />
              <JsonDetails data={sbomData} />
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

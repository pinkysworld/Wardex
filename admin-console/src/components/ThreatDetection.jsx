import { useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid } from './operator.jsx';
import RuleEditor from './RuleEditor.jsx';

export default function ThreatDetection() {
  const toast = useToast();
  const [tab, setTab] = useState('overview');
  const { data: profile, reload: rProfile } = useApi(api.detectionProfile);
  const { data: summary } = useApi(api.detectionSummary);
  const { data: sigma } = useApi(api.sigmaRules);
  const { data: sigmaStats } = useApi(api.sigmaStats);
  const { data: enforcement } = useApi(api.enforcementStatus);
  const { data: tiStatus } = useApi(api.threatIntelStatus);
  const { data: tiStats } = useApi(api.threatIntelStats);
  const { data: deception } = useApi(api.deceptionStatus);
  const { data: sideChannel } = useApi(api.sideChannelStatus);
  const { data: mitre } = useApi(api.mitreCoverage);
  const { data: heatmap } = useApi(api.mitreHeatmap);
  const { data: checks } = useApi(api.checkpoints);
  const { data: weights } = useApi(api.detectionWeights);
  const { data: fpStats, reload: rFP } = useApi(api.fpFeedbackStats);
  const { data: contentRulesData } = useApi(api.contentRules);
  const { data: packsData } = useApi(api.contentPacks);
  const { data: huntList, reload: rHunts } = useApi(api.hunts);
  const { data: suppressList, reload: rSuppress } = useApi(api.suppressions);
  const [huntForm, setHuntForm] = useState({ name: '', severity: 'medium', threshold: 1, text: '' });
  const [suppressForm, setSuppressForm] = useState({ name: '', rule_id: '', hostname: '', severity: '', text: '' });
  const [showHuntForm, setShowHuntForm] = useState(false);
  const [showSuppressForm, setShowSuppressForm] = useState(false);

  const handleProfileChange = async (name) => {
    try {
      await api.setDetectionProfile({ profile: name });
      toast(`Profile set to ${name}`, 'success');
      rProfile();
    } catch { toast('Failed to set profile', 'error'); }
  };

  const heatmapCells = Array.isArray(heatmap) ? heatmap : [];

  return (
    <div>
      <div className="tabs">
        {['overview', 'sigma', 'mitre', 'threat-intel', 'hunts', 'tuning', 'rule-editor'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.replace(/-/g, ' ').replace(/^\w/, c => c.toUpperCase())}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <>
          {/* Tuning Profile */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Detection Tuning Profile</span>
              <div className="btn-group">
                {['aggressive', 'balanced', 'quiet'].map(p => (
                  <button key={p} className={`btn btn-sm ${profile?.profile === p ? 'btn-primary' : ''}`}
                          onClick={() => handleProfileChange(p)}>
                    {p.charAt(0).toUpperCase() + p.slice(1)}
                  </button>
                ))}
              </div>
            </div>
            {profile && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
                <div><span className="metric-label">Active Profile</span><div className="metric-value" style={{ fontSize: 20 }}>{profile.profile}</div></div>
                <div><span className="metric-label">Threshold Multiplier</span><div className="metric-value" style={{ fontSize: 20 }}>{profile.threshold_multiplier}</div></div>
                <div><span className="metric-label">Learn Threshold</span><div className="metric-value" style={{ fontSize: 20 }}>{profile.learn_threshold}</div></div>
              </div>
            )}
          </div>

          {/* Detection Summary */}
          <div className="card-grid">
            <div className="card">
              <div className="card-title">Enforcement</div>
              <div style={{ marginTop: 12 }}>
                <SummaryGrid data={enforcement} limit={8} />
              </div>
            </div>
            <div className="card">
              <div className="card-title">Side Channel</div>
              <div style={{ marginTop: 12 }}>
                <SummaryGrid data={sideChannel} limit={8} />
              </div>
            </div>
            <div className="card">
              <div className="card-title">Deception Engine</div>
              <div style={{ marginTop: 12 }}>
                <SummaryGrid data={deception} limit={8} />
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Quick Actions</div>
            <div className="btn-group">
              <button className="btn" onClick={async () => { try { await api.runDemo(); toast('Demo started', 'success'); } catch { toast('Failed', 'error'); } }}>Run Demo</button>
              <button className="btn" onClick={async () => { try { await api.resetBaseline(); toast('Baseline reset', 'success'); } catch { toast('Failed', 'error'); } }}>Reset Baseline</button>
              <button className="btn" onClick={async () => { try { await api.checkpoint(); toast('Checkpoint created', 'success'); } catch { toast('Failed', 'error'); } }}>Create Checkpoint</button>
              <button className="btn" onClick={async () => { try { await api.alertsSample({}); toast('Sample alert created', 'success'); } catch { toast('Failed', 'error'); } }}>Generate Sample Alert</button>
            </div>
          </div>

          {summary && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Detection Summary</div>
              <SummaryGrid data={summary} limit={12} />
            </div>
          )}
        </>
      )}

      {tab === 'sigma' && (
        <>
          <div className="card-grid">
            <div className="card metric"><div className="metric-label">Total Rules</div><div className="metric-value">{sigmaStats?.total_rules ?? sigmaStats?.total ?? '—'}</div></div>
            <div className="card metric"><div className="metric-label">Active</div><div className="metric-value">{sigmaStats?.active ?? '—'}</div></div>
            <div className="card metric"><div className="metric-label">Categories</div><div className="metric-value">{sigmaStats?.categories ?? '—'}</div></div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Sigma Rules</div>
            {(() => {
              const rules = sigma?.rules || (Array.isArray(sigma) ? sigma : []);
              if (!sigma) return <div className="empty">No rules loaded</div>;
              return rules.length > 0 ? (
                <>
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Title</th><th>Level</th><th>Status</th><th>ID</th></tr></thead>
                      <tbody>
                        {rules.slice(0, 50).map((rule, index) => (
                          <tr key={rule.id || index}>
                            <td>{rule.title || 'Untitled rule'}</td>
                            <td>{rule.level || '—'}</td>
                            <td><span className={`badge ${rule.status === 'enabled' || rule.status === 'active' ? 'badge-ok' : 'badge-warn'}`}>{rule.status || 'unknown'}</span></td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{rule.id || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <JsonDetails data={sigma} />
                </>
              ) : (
                <>
                  <SummaryGrid data={sigma} limit={10} />
                  <JsonDetails data={sigma} />
                </>
              );
            })()}
          </div>
          {contentRulesData && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Content Rules</div>
              {(() => {
                const rules = contentRulesData?.rules || [];
                return rules.length > 0 ? (
                  <>
                    <div className="table-wrap">
                      <table>
                        <thead><tr><th>Title</th><th>Kind</th><th>Owner</th><th>Enabled</th></tr></thead>
                        <tbody>
                          {rules.slice(0, 25).map((rule, index) => (
                            <tr key={rule.id || index}>
                              <td>{rule.title || rule.name || 'Untitled'}</td>
                              <td>{rule.kind || 'native'}</td>
                              <td>{rule.owner || '—'}</td>
                              <td><span className={`badge ${rule.enabled !== false ? 'badge-ok' : 'badge-warn'}`}>{rule.enabled !== false ? 'Yes' : 'No'}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <JsonDetails data={contentRulesData} />
                  </>
                ) : (
                  <>
                    <SummaryGrid data={contentRulesData} limit={10} />
                    <JsonDetails data={contentRulesData} />
                  </>
                );
              })()}
            </div>
          )}
          {packsData && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Content Packs</div>
              {(() => {
                const packs = packsData?.packs || [];
                return packs.length > 0 ? (
                  <>
                    <div className="table-wrap">
                      <table>
                        <thead><tr><th>Pack</th><th>Rules</th><th>Status</th></tr></thead>
                        <tbody>
                          {packs.slice(0, 25).map((pack, index) => (
                            <tr key={pack.id || pack.name || index}>
                              <td>{pack.name || pack.id || 'Untitled pack'}</td>
                              <td>{Array.isArray(pack.rule_ids) ? pack.rule_ids.length : pack.rule_count ?? '—'}</td>
                              <td><span className={`badge ${pack.enabled !== false ? 'badge-ok' : 'badge-warn'}`}>{pack.enabled !== false ? 'Enabled' : 'Disabled'}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <JsonDetails data={packsData} />
                  </>
                ) : (
                  <>
                    <SummaryGrid data={packsData} limit={10} />
                    <JsonDetails data={packsData} />
                  </>
                );
              })()}
            </div>
          )}
          {suppressList && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-header">
                <span className="card-title">Active Suppressions ({suppressList?.count ?? (suppressList?.suppressions || []).length})</span>
                <button className="btn btn-sm" onClick={() => setTab('hunts')}>Manage →</button>
              </div>
              {(() => {
                const sups = suppressList?.suppressions || (Array.isArray(suppressList) ? suppressList : []);
                return sups.length === 0 ? <div className="empty">No active suppressions</div> : (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Name</th><th>Rule</th><th>Host</th><th>Severity</th></tr></thead>
                      <tbody>
                        {sups.slice(0, 10).map((s, i) => (
                          <tr key={i}><td>{s.name || '—'}</td><td style={{ fontSize: 12 }}>{s.rule_id || '—'}</td><td>{s.hostname || '—'}</td><td>{s.severity || '—'}</td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                );
              })()}
            </div>
          )}
        </>
      )}

      {tab === 'mitre' && (
        <>
          {mitre && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-header">
                <span className="card-title">MITRE ATT&CK Coverage</span>
                <span className="badge badge-info">{mitre.covered_techniques ?? '—'} / {mitre.total_techniques ?? '—'} techniques</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 16 }}>
                <div><span className="metric-label">Coverage</span><div className="metric-value" style={{ fontSize: 20 }}>{mitre.coverage_pct ?? '—'}%</div></div>
                <div><span className="metric-label">Gaps</span><div className="metric-value" style={{ fontSize: 20 }}>{mitre.gaps?.length ?? '—'}</div></div>
                <div><span className="metric-label">Tactics</span><div className="metric-value" style={{ fontSize: 20 }}>{mitre.by_tactic ? Object.keys(mitre.by_tactic).length : '—'}</div></div>
              </div>
              {mitre.by_tactic && (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Tactic</th><th>Covered</th><th>Total</th><th>Coverage</th></tr></thead>
                    <tbody>
                      {Object.entries(mitre.by_tactic).map(([tac, info]) => (
                        <tr key={tac}>
                          <td>{tac}</td>
                          <td>{typeof info === 'object' ? info.covered : info}</td>
                          <td>{typeof info === 'object' ? info.total : '—'}</td>
                          <td>{typeof info === 'object' && info.total ? `${Math.round(info.covered / info.total * 100)}%` : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
          {heatmapCells.length > 0 && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Technique Heatmap</div>
              <div className="heatmap-grid">
                {heatmapCells.map((c, i) => (
                  <div key={i} className={`heatmap-cell heat-${Math.min(c.count || c.coverage || 0, 3)}`}
                       title={`${c.technique_id || c.id}: ${c.name || ''}\nSources: ${c.count || c.sources || 0}`}>
                    {c.technique_id || c.id || ''}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {tab === 'threat-intel' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Threat Intel Status</div>
              <SummaryGrid data={tiStatus} limit={10} />
              <JsonDetails data={tiStatus} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Enrichment Stats</div>
              <SummaryGrid data={tiStats} limit={10} />
              <JsonDetails data={tiStats} />
            </div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Actions</div>
            <div className="btn-group">
              <button className="btn" onClick={async () => {
                try { const r = await api.threatIntelPurge({ ttl_days: 90 }); toast(`Purged ${r.purged} expired IoCs`, 'success'); } catch { toast('Purge failed', 'error'); }
              }}>Purge Expired (90d)</button>
            </div>
          </div>
        </>
      )}

      {tab === 'hunts' && (
        <div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Threat Hunts ({(huntList?.hunts || huntList || []).length})</span>
              <button className="btn btn-sm btn-primary" onClick={() => setShowHuntForm(!showHuntForm)}>
                {showHuntForm ? 'Cancel' : '+ New Hunt'}
              </button>
            </div>
            {showHuntForm && (
              <div style={{ padding: '12px 0', borderBottom: '1px solid var(--border)', marginBottom: 12, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Name</label>
                  <input type="text" value={huntForm.name} onChange={e => setHuntForm(p => ({ ...p, name: e.target.value }))}
                    placeholder="Hunt name" style={{ width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
                </div>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Severity</label>
                  <select value={huntForm.severity} onChange={e => setHuntForm(p => ({ ...p, severity: e.target.value }))}
                    style={{ width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }}>
                    <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Threshold</label>
                  <input type="number" value={huntForm.threshold} onChange={e => setHuntForm(p => ({ ...p, threshold: Number(e.target.value) }))}
                    min={1} style={{ width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
                </div>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Search Text</label>
                  <input type="text" value={huntForm.text} onChange={e => setHuntForm(p => ({ ...p, text: e.target.value }))}
                    placeholder="Search pattern" style={{ width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                  <button className="btn btn-primary" onClick={async () => {
                    if (!huntForm.name) { toast('Name required', 'error'); return; }
                    try {
                      await api.createHunt({ name: huntForm.name, severity: huntForm.severity, threshold: huntForm.threshold, text: huntForm.text || undefined });
                      toast('Hunt created', 'success');
                      setShowHuntForm(false);
                      setHuntForm({ name: '', severity: 'medium', threshold: 1, text: '' });
                      rHunts();
                    } catch { toast('Failed to create hunt', 'error'); }
                  }}>Create</button>
                </div>
              </div>
            )}
            {(() => {
              const hunts = huntList?.hunts || (Array.isArray(huntList) ? huntList : []);
              return hunts.length === 0 ? <div className="empty">No hunts defined</div> : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Name</th><th>Severity</th><th>Owner</th><th>Enabled</th><th>Threshold</th><th>Last Run</th><th>Actions</th></tr></thead>
                    <tbody>
                      {hunts.map((h, i) => (
                        <tr key={h.id || i}>
                          <td style={{ fontWeight: 600 }}>{h.name}</td>
                          <td><span className={`sev-${(h.severity || 'medium').toLowerCase()}`}>{h.severity}</span></td>
                          <td>{h.owner || '—'}</td>
                          <td><span className={`badge ${h.enabled ? 'badge-ok' : 'badge-warn'}`}>{h.enabled ? 'Yes' : 'No'}</span></td>
                          <td>{h.threshold}</td>
                          <td style={{ fontSize: 12, fontFamily: 'var(--font-mono)' }}>{h.last_run_at || '—'}</td>
                          <td>
                            <button className="btn btn-sm" onClick={async () => {
                              try { await api.runHunt(h.id); toast('Hunt executed', 'success'); rHunts(); } catch { toast('Run failed', 'error'); }
                            }}>Run</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })()}
          </div>

          {/* Suppression Management */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Suppression Rules ({suppressList?.count ?? (suppressList?.suppressions || []).length})</span>
              <button className="btn btn-sm btn-primary" onClick={() => setShowSuppressForm(!showSuppressForm)}>
                {showSuppressForm ? 'Cancel' : '+ New Suppression'}
              </button>
            </div>
            {showSuppressForm && (
              <div style={{ padding: '12px 0', borderBottom: '1px solid var(--border)', marginBottom: 12, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10 }}>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Name</label>
                  <input type="text" value={suppressForm.name} onChange={e => setSuppressForm(p => ({ ...p, name: e.target.value }))}
                    placeholder="Suppression name" style={{ width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
                </div>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Rule ID (optional)</label>
                  <input type="text" value={suppressForm.rule_id} onChange={e => setSuppressForm(p => ({ ...p, rule_id: e.target.value }))}
                    style={{ width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
                </div>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Hostname (optional)</label>
                  <input type="text" value={suppressForm.hostname} onChange={e => setSuppressForm(p => ({ ...p, hostname: e.target.value }))}
                    style={{ width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
                </div>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Severity (optional)</label>
                  <select value={suppressForm.severity} onChange={e => setSuppressForm(p => ({ ...p, severity: e.target.value }))}
                    style={{ width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }}>
                    <option value="">Any</option><option value="low">Low</option><option value="medium">Medium</option><option value="elevated">Elevated</option><option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Text match</label>
                  <input type="text" value={suppressForm.text} onChange={e => setSuppressForm(p => ({ ...p, text: e.target.value }))}
                    placeholder="Pattern to suppress" style={{ width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                  <button className="btn btn-primary" onClick={async () => {
                    if (!suppressForm.name) { toast('Name required', 'error'); return; }
                    try {
                      const body = { name: suppressForm.name };
                      if (suppressForm.rule_id) body.rule_id = suppressForm.rule_id;
                      if (suppressForm.hostname) body.hostname = suppressForm.hostname;
                      if (suppressForm.severity) body.severity = suppressForm.severity;
                      if (suppressForm.text) body.text = suppressForm.text;
                      await api.createSuppression(body);
                      toast('Suppression created', 'success');
                      setShowSuppressForm(false);
                      setSuppressForm({ name: '', rule_id: '', hostname: '', severity: '', text: '' });
                      rSuppress();
                    } catch { toast('Failed', 'error'); }
                  }}>Create</button>
                </div>
              </div>
            )}
            {(() => {
              const sups = suppressList?.suppressions || (Array.isArray(suppressList) ? suppressList : []);
              return sups.length === 0 ? <div className="empty">No suppressions</div> : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>ID</th><th>Name</th><th>Rule</th><th>Host</th><th>Severity</th><th>Active</th></tr></thead>
                    <tbody>
                      {sups.map((s, i) => (
                        <tr key={s.id || i}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{s.id || i}</td>
                          <td>{s.name || '—'}</td>
                          <td style={{ fontSize: 12 }}>{s.rule_id || '—'}</td>
                          <td>{s.hostname || '—'}</td>
                          <td>{s.severity ? <span className={`sev-${s.severity}`}>{s.severity}</span> : '—'}</td>
                          <td><span className={`badge ${s.active !== false ? 'badge-ok' : 'badge-warn'}`}>{s.active !== false ? 'Active' : 'Inactive'}</span></td>
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

      {tab === 'tuning' && (
        <>
          {weights && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Detection Weights</div>
              <SummaryGrid data={weights} limit={12} />
              <JsonDetails data={weights} />
            </div>
          )}
          {fpStats && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>False Positive Feedback</div>
              {Array.isArray(fpStats) && fpStats.length > 0 ? (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Pattern</th><th>Total</th><th>FPs</th><th>FP Ratio</th><th>Suppression</th></tr></thead>
                    <tbody>
                      {fpStats.map((f, i) => (
                        <tr key={i}>
                          <td>{f.pattern}</td>
                          <td>{f.total_marked}</td>
                          <td>{f.false_positives}</td>
                          <td>{(f.fp_ratio * 100).toFixed(1)}%</td>
                          <td>{f.suppression_weight?.toFixed(2)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <>
                  <SummaryGrid data={fpStats} limit={10} />
                  <JsonDetails data={fpStats} />
                </>
              )}
            </div>
          )}
          {checks && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Checkpoints</div>
              <SummaryGrid data={checks} exclude={['timestamps', 'device_states']} limit={10} />
              <JsonDetails data={checks} />
            </div>
          )}
        </>
      )}

      {tab === 'rule-editor' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Detection Rule Editor</div>
          <RuleEditor onRuleCreated={() => toast('Rule created — detection engine updated', 'success')} />
        </div>
      )}
    </div>
  );
}

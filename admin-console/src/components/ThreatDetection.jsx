import { useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';

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
  const { data: fpStats } = useApi(api.fpFeedbackStats);
  const { data: contentRulesData } = useApi(api.contentRules);
  const { data: packsData } = useApi(api.contentPacks);
  const { data: huntList } = useApi(api.hunts);
  const { data: suppressList } = useApi(api.suppressions);

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
        {['overview', 'sigma', 'mitre', 'threat-intel', 'hunts', 'tuning'].map(t => (
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
              <div className="json-block" style={{ marginTop: 12 }}>{JSON.stringify(enforcement, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title">Side Channel</div>
              <div className="json-block" style={{ marginTop: 12 }}>{JSON.stringify(sideChannel, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title">Deception Engine</div>
              <div className="json-block" style={{ marginTop: 12 }}>{JSON.stringify(deception, null, 2)}</div>
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
              <div className="json-block">{JSON.stringify(summary, null, 2)}</div>
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
            {!sigma ? <div className="empty">No rules loaded</div> : (
              <div className="json-block">{JSON.stringify(sigma, null, 2)}</div>
            )}
          </div>
          {contentRulesData && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Content Rules</div>
              <div className="json-block">{JSON.stringify(contentRulesData, null, 2)}</div>
            </div>
          )}
          {packsData && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Content Packs</div>
              <div className="json-block">{JSON.stringify(packsData, null, 2)}</div>
            </div>
          )}
          {suppressList && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Suppressions</div>
              <div className="json-block">{JSON.stringify(suppressList, null, 2)}</div>
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
              <div className="json-block">{JSON.stringify(tiStatus, null, 2)}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Enrichment Stats</div>
              <div className="json-block">{JSON.stringify(tiStats, null, 2)}</div>
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
        <div className="card">
          <div className="card-header">
            <span className="card-title">Threat Hunts</span>
          </div>
          {!huntList || (Array.isArray(huntList) && huntList.length === 0) ? (
            <div className="empty">No hunts defined</div>
          ) : (
            <div className="json-block">{JSON.stringify(huntList, null, 2)}</div>
          )}
        </div>
      )}

      {tab === 'tuning' && (
        <>
          {weights && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Detection Weights</div>
              <div className="json-block">{JSON.stringify(weights, null, 2)}</div>
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
              ) : <div className="json-block">{JSON.stringify(fpStats, null, 2)}</div>}
            </div>
          )}
          {checks && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Checkpoints</div>
              <div className="json-block">{JSON.stringify(checks, null, 2)}</div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

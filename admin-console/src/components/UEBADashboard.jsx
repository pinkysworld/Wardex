import { useState, useMemo } from 'react';
import { useApi, useInterval } from '../hooks.jsx';
import * as api from '../api.js';

const RISK_THRESHOLDS = { critical: 80, high: 60, medium: 40, low: 20 };
const ANOMALY_TYPES = [
  'ImpossibleTravel',
  'UnusualLoginTime',
  'AnomalousAccess',
  'PrivilegeEscalationChain',
  'DataExfiltrationPattern',
  'LateralMovement',
  'AnomalousProcess',
  'ServiceAnomaly',
  'DataVolumeAnomaly',
  'FirstTimeActivity',
];
const TIME_RANGES = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
];

function riskLevel(score) {
  if (score >= RISK_THRESHOLDS.critical) return { label: 'Critical', cls: 'badge-err' };
  if (score >= RISK_THRESHOLDS.high) return { label: 'High', cls: 'badge-err' };
  if (score >= RISK_THRESHOLDS.medium) return { label: 'Medium', cls: 'badge-warn' };
  if (score >= RISK_THRESHOLDS.low) return { label: 'Low', cls: 'badge-info' };
  return { label: 'Nominal', cls: 'badge-ok' };
}

// ── Risk Score Bar ──────────────────────────────────────────
function RiskBar({ score, max = 100 }) {
  const pct = Math.min((score / max) * 100, 100);
  const color =
    score >= 80
      ? 'var(--err)'
      : score >= 60
        ? '#e67e22'
        : score >= 40
          ? 'var(--warn)'
          : 'var(--ok)';
  return (
    <div
      style={{
        width: '100%',
        height: 8,
        borderRadius: 4,
        background: 'var(--bg)',
        overflow: 'hidden',
      }}
      role="meter"
      aria-valuenow={score}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-label={`Risk score ${score}`}
    >
      <div
        style={{
          width: `${pct}%`,
          height: '100%',
          borderRadius: 4,
          background: color,
          transition: 'width 0.3s ease',
        }}
      />
    </div>
  );
}

// ── Peer Comparison Spark ───────────────────────────────────
function PeerSparkBar({ entityRisk, peerAvg }) {
  const maxVal = Math.max(entityRisk, peerAvg, 1);
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12 }}>
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
          <span>Entity</span>
          <span>{entityRisk.toFixed(1)}</span>
        </div>
        <div style={{ height: 6, borderRadius: 3, background: 'var(--bg)' }}>
          <div
            style={{
              width: `${(entityRisk / maxVal) * 100}%`,
              height: '100%',
              borderRadius: 3,
              background: entityRisk > peerAvg * 1.5 ? 'var(--err)' : 'var(--primary)',
            }}
          />
        </div>
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
          <span>Peer avg</span>
          <span>{peerAvg.toFixed(1)}</span>
        </div>
        <div style={{ height: 6, borderRadius: 3, background: 'var(--bg)' }}>
          <div
            style={{
              width: `${(peerAvg / maxVal) * 100}%`,
              height: '100%',
              borderRadius: 3,
              background: 'var(--text-secondary)',
            }}
          />
        </div>
      </div>
    </div>
  );
}

export default function UEBADashboard() {
  const [timeRange, setTimeRange] = useState(TIME_RANGES[2]);
  const [selectedEntity, setSelectedEntity] = useState(null);
  const [anomalyFilter, setAnomalyFilter] = useState('all');
  const [sortBy, setSortBy] = useState('risk_score');

  const {
    data: riskyEntities,
    loading: loadingRisky,
    reload: reloadRisky,
  } = useApi(() => api.uebaRiskyEntities(10));
  const {
    data: anomalies,
    loading: loadingAnomalies,
    reload: reloadAnomalies,
  } = useApi(() => api.uebaAnomalies(200));
  const { data: peerGroups } = useApi(api.uebaPeerGroups);
  const { data: entityDetail, loading: loadingDetail } = useApi(
    () => (selectedEntity ? api.uebaEntity(selectedEntity) : Promise.resolve(null)),
    [selectedEntity],
    { skip: !selectedEntity },
  );

  useInterval(() => {
    reloadRisky();
    reloadAnomalies();
  }, 30000);

  const entities = useMemo(() => {
    if (!riskyEntities) return [];
    const list = Array.isArray(riskyEntities) ? riskyEntities : riskyEntities.items || [];
    const sorted = [...list];
    if (sortBy === 'risk_score') sorted.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
    else if (sortBy === 'anomaly_count')
      sorted.sort((a, b) => (b.anomaly_count || 0) - (a.anomaly_count || 0));
    else if (sortBy === 'entity_id')
      sorted.sort((a, b) => (a.entity_id || '').localeCompare(b.entity_id || ''));
    return sorted;
  }, [riskyEntities, sortBy]);

  const filteredAnomalies = useMemo(() => {
    if (!anomalies) return [];
    const list = Array.isArray(anomalies) ? anomalies : anomalies.items || [];
    if (anomalyFilter === 'all') return list;
    return list.filter((a) => a.anomaly_type === anomalyFilter);
  }, [anomalies, anomalyFilter]);

  const anomalyStats = useMemo(() => {
    if (!anomalies) return {};
    const list = Array.isArray(anomalies) ? anomalies : anomalies.items || [];
    const counts = {};
    for (const a of list) {
      counts[a.anomaly_type] = (counts[a.anomaly_type] || 0) + 1;
    }
    return counts;
  }, [anomalies]);

  const topRiskCount = entities.filter((e) => (e.risk_score || 0) >= RISK_THRESHOLDS.high).length;

  return (
    <div className="ueba-dashboard" style={{ display: 'grid', gap: 16 }}>
      {/* Summary Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 12,
        }}
      >
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div
            style={{
              fontSize: 28,
              fontWeight: 700,
              color: topRiskCount > 0 ? 'var(--err)' : 'var(--ok)',
            }}
          >
            {topRiskCount}
          </div>
          <div className="hint">High-Risk Entities</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{entities.length}</div>
          <div className="hint">Tracked Entities</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div
            style={{
              fontSize: 28,
              fontWeight: 700,
              color: filteredAnomalies.length > 20 ? 'var(--warn)' : 'var(--text)',
            }}
          >
            {filteredAnomalies.length}
          </div>
          <div className="hint">Anomalies Detected</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {Array.isArray(peerGroups) ? peerGroups.length : 0}
          </div>
          <div className="hint">Peer Groups</div>
        </div>
      </div>

      {/* Time Range & Filters */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ fontSize: 13, fontWeight: 600 }}>Time Range:</span>
        {TIME_RANGES.map((tr) => (
          <button
            key={tr.label}
            className={`btn btn-sm ${tr.label === timeRange.label ? 'btn-primary' : ''}`}
            onClick={() => setTimeRange(tr)}
          >
            {tr.label}
          </button>
        ))}
        <span style={{ marginLeft: 16, fontSize: 13, fontWeight: 600 }}>Sort:</span>
        <select
          className="auth-input"
          style={{ width: 'auto', fontSize: 12, padding: '4px 8px' }}
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          aria-label="Sort entities by"
        >
          <option value="risk_score">Risk Score</option>
          <option value="anomaly_count">Anomaly Count</option>
          <option value="entity_id">Entity ID</option>
        </select>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: selectedEntity ? '1fr 1fr' : '1fr',
          gap: 16,
        }}
      >
        {/* Left: Risky Entities Table */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div
            style={{
              padding: '12px 16px',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div className="card-title">Risky Entities</div>
            <button
              className="btn btn-sm"
              onClick={reloadRisky}
              aria-label="Refresh risky entities"
            >
              Refresh
            </button>
          </div>
          {loadingRisky ? (
            <div className="loading" style={{ padding: 20 }}>
              Loading…
            </div>
          ) : (
            <div style={{ maxHeight: 500, overflowY: 'auto' }}>
              <table className="data-table" style={{ width: '100%' }}>
                <thead>
                  <tr>
                    <th>Entity</th>
                    <th>Kind</th>
                    <th>Risk</th>
                    <th>Anomalies</th>
                    <th>Peer Group</th>
                  </tr>
                </thead>
                <tbody>
                  {entities.length === 0 ? (
                    <tr>
                      <td
                        colSpan={5}
                        style={{ textAlign: 'center', padding: 20, color: 'var(--text-secondary)' }}
                      >
                        No risky entities detected
                      </td>
                    </tr>
                  ) : (
                    entities.map((e, i) => {
                      const rl = riskLevel(e.risk_score || 0);
                      return (
                        <tr
                          key={e.entity_id || i}
                          onClick={() => setSelectedEntity(e.entity_id)}
                          style={{
                            cursor: 'pointer',
                            background:
                              selectedEntity === e.entity_id ? 'var(--bg-hover)' : undefined,
                          }}
                          aria-selected={selectedEntity === e.entity_id}
                        >
                          <td style={{ fontWeight: 600 }}>{e.entity_id || '—'}</td>
                          <td>
                            <span className="badge badge-info">{e.entity_kind || 'User'}</span>
                          </td>
                          <td style={{ minWidth: 120 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <span className={`badge ${rl.cls}`}>
                                {(e.risk_score || 0).toFixed(0)}
                              </span>
                              <RiskBar score={e.risk_score || 0} />
                            </div>
                          </td>
                          <td>{e.anomaly_count || 0}</td>
                          <td>{e.peer_group || '—'}</td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right: Entity Detail */}
        {selectedEntity && (
          <div className="card" style={{ padding: 16 }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: 12,
              }}
            >
              <div className="card-title">Entity: {selectedEntity}</div>
              <button
                className="btn btn-sm"
                onClick={() => setSelectedEntity(null)}
                aria-label="Close entity detail"
              >
                ✕
              </button>
            </div>
            {loadingDetail ? (
              <div className="loading">Loading…</div>
            ) : entityDetail ? (
              <div style={{ display: 'grid', gap: 12 }}>
                <div
                  style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 13 }}
                >
                  <div>
                    <strong>Kind:</strong> {entityDetail.entity_kind}
                  </div>
                  <div>
                    <strong>Risk Score:</strong>{' '}
                    <span className={`badge ${riskLevel(entityDetail.risk_score || 0).cls}`}>
                      {(entityDetail.risk_score || 0).toFixed(1)}
                    </span>
                  </div>
                  <div>
                    <strong>Observations:</strong> {entityDetail.observation_count || 0}
                  </div>
                  <div>
                    <strong>Peer Group:</strong> {entityDetail.peer_group || '—'}
                  </div>
                </div>
                <RiskBar score={entityDetail.risk_score || 0} />
                {entityDetail.peer_avg_risk !== undefined && (
                  <PeerSparkBar
                    entityRisk={entityDetail.risk_score || 0}
                    peerAvg={entityDetail.peer_avg_risk || 0}
                  />
                )}
                {entityDetail.anomalies && entityDetail.anomalies.length > 0 && (
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 6 }}>
                      Recent Anomalies
                    </div>
                    <div style={{ maxHeight: 250, overflowY: 'auto', display: 'grid', gap: 6 }}>
                      {entityDetail.anomalies.slice(0, 20).map((a, i) => {
                        const rl = riskLevel(a.score || 0);
                        return (
                          <div
                            key={i}
                            style={{
                              padding: 8,
                              borderRadius: 8,
                              border: '1px solid var(--border)',
                              fontSize: 12,
                            }}
                          >
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                              <span className={`badge ${rl.cls}`}>{a.anomaly_type}</span>
                              <span style={{ color: 'var(--text-secondary)' }}>
                                {a.score?.toFixed(1)}
                              </span>
                            </div>
                            <div style={{ marginTop: 4, color: 'var(--text-secondary)' }}>
                              {a.description}
                            </div>
                            {a.mitre_technique && (
                              <div style={{ marginTop: 2 }}>
                                <span className="badge badge-info">{a.mitre_technique}</span>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="empty" style={{ padding: 20 }}>
                Entity not found
              </div>
            )}
          </div>
        )}
      </div>

      {/* Anomaly Feed */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            padding: '12px 16px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 8,
          }}
        >
          <div className="card-title">Anomaly Feed</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <button
              className={`btn btn-sm ${anomalyFilter === 'all' ? 'btn-primary' : ''}`}
              onClick={() => setAnomalyFilter('all')}
            >
              All ({(Array.isArray(anomalies) ? anomalies : anomalies?.items || []).length})
            </button>
            {ANOMALY_TYPES.filter((t) => anomalyStats[t]).map((t) => (
              <button
                key={t}
                className={`btn btn-sm ${anomalyFilter === t ? 'btn-primary' : ''}`}
                onClick={() => setAnomalyFilter(t)}
              >
                {t.replace(/([A-Z])/g, ' $1').trim()} ({anomalyStats[t]})
              </button>
            ))}
          </div>
        </div>
        {loadingAnomalies ? (
          <div className="loading" style={{ padding: 20 }}>
            Loading…
          </div>
        ) : (
          <div style={{ maxHeight: 400, overflowY: 'auto' }}>
            <table className="data-table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Entity</th>
                  <th>Score</th>
                  <th>Description</th>
                  <th>MITRE</th>
                </tr>
              </thead>
              <tbody>
                {filteredAnomalies.length === 0 ? (
                  <tr>
                    <td
                      colSpan={5}
                      style={{ textAlign: 'center', padding: 20, color: 'var(--text-secondary)' }}
                    >
                      No anomalies in this period
                    </td>
                  </tr>
                ) : (
                  filteredAnomalies.slice(0, 100).map((a, i) => (
                    <tr
                      key={i}
                      onClick={() => setSelectedEntity(a.entity_id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <span className={`badge ${riskLevel(a.score || 0).cls}`}>
                          {a.anomaly_type?.replace(/([A-Z])/g, ' $1').trim()}
                        </span>
                      </td>
                      <td style={{ fontWeight: 600 }}>{a.entity_id}</td>
                      <td>{(a.score || 0).toFixed(1)}</td>
                      <td
                        style={{
                          maxWidth: 300,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {a.description}
                      </td>
                      <td>
                        {a.mitre_technique ? (
                          <span className="badge badge-info">{a.mitre_technique}</span>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Peer Group Comparison */}
      {Array.isArray(peerGroups) && peerGroups.length > 0 && (
        <div className="card" style={{ padding: 16 }}>
          <div className="card-title" style={{ marginBottom: 12 }}>
            Peer Group Baselines
          </div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: 12,
            }}
          >
            {peerGroups.map((pg, i) => (
              <div
                key={pg.group || i}
                style={{ padding: 12, borderRadius: 8, border: '1px solid var(--border)' }}
              >
                <div style={{ fontWeight: 700, marginBottom: 8 }}>
                  {pg.group} <span className="hint">({pg.entity_count} entities)</span>
                </div>
                <div style={{ fontSize: 12, display: 'grid', gap: 4 }}>
                  <div>
                    Avg Risk: <strong>{(pg.avg_risk || 0).toFixed(1)}</strong>
                  </div>
                  <div>
                    Avg Data Volume:{' '}
                    <strong>{((pg.avg_data_bytes || 0) / 1024).toFixed(1)} KB</strong>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useApiGroup, useInterval } from '../hooks.jsx';
import * as api from '../api.js';
import WorkflowGuidance from './WorkflowGuidance.jsx';
import { buildHref } from './workflowPivots.js';

const RISK_THRESHOLDS = { critical: 80, high: 60, medium: 40, low: 20 };
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

function formatTimestamp(timestampMs) {
  if (!timestampMs) return '—';
  const date = new Date(timestampMs);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toISOString();
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

export default function UEBADashboard() {
  const [searchParams, setSearchParams] = useSearchParams();
  const timeRange =
    TIME_RANGES.find((entry) => entry.label === searchParams.get('range')) || TIME_RANGES[2];
  const selectedEntity = searchParams.get('entity') || '';
  const sortBy = searchParams.get('sort') || 'risk_score';

  const updateParams = (changes) => {
    const next = new URLSearchParams(searchParams);
    Object.entries(changes).forEach(([key, value]) => {
      if (value == null || value === '' || value === 'all') next.delete(key);
      else next.set(key, value);
    });
    setSearchParams(next, { replace: true });
  };

  const {
    data: uebaOverviewData,
    loading: loadingUebaOverview,
    reload: reloadUebaOverview,
  } = useApiGroup({
    riskyEntities: () => api.uebaRiskyEntities(10),
  });
  const { riskyEntities } = uebaOverviewData;
  const loadingRisky = loadingUebaOverview;

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

  const activeEntity = selectedEntity || entities[0]?.entity_id || '';
  const {
    data: entityDetail,
    loading: loadingDetail,
    reload: reloadEntityDetail,
  } = useApi(
    () => (activeEntity ? api.uebaEntity(activeEntity) : Promise.resolve(null)),
    [activeEntity],
    {
      skip: !activeEntity,
    },
  );

  const refreshUebaOverview = () => {
    void reloadUebaOverview();
    if (activeEntity) void reloadEntityDetail();
  };

  useInterval(() => {
    refreshUebaOverview();
  }, 30000);

  const peerGroups = useMemo(() => {
    const groups = new Map();
    for (const entity of entities) {
      if (!entity?.peer_group) continue;
      const current = groups.get(entity.peer_group) || {
        group: entity.peer_group,
        entity_count: 0,
        total_risk: 0,
        total_anomalies: 0,
      };
      current.entity_count += 1;
      current.total_risk += Number(entity.risk_score) || 0;
      current.total_anomalies += Number(entity.anomaly_count) || 0;
      groups.set(entity.peer_group, current);
    }
    return Array.from(groups.values())
      .map((group) => ({
        group: group.group,
        entity_count: group.entity_count,
        avg_risk: group.total_risk / Math.max(group.entity_count, 1),
        total_anomalies: group.total_anomalies,
      }))
      .sort((left, right) => right.avg_risk - left.avg_risk);
  }, [entities]);

  const totalAnomalyCount = useMemo(
    () => entities.reduce((sum, entity) => sum + (Number(entity?.anomaly_count) || 0), 0),
    [entities],
  );

  const topRiskCount = entities.filter((e) => (e.risk_score || 0) >= RISK_THRESHOLDS.high).length;
  const focusEntity = activeEntity;
  const entityPlaybook = useMemo(() => {
    if (!activeEntity) return null;
    const riskScore = Number(entityDetail?.risk_score) || 0;
    const anomalyCount =
      Number(entityDetail?.anomaly_count) ||
      Number(entities.find((entry) => entry.entity_id === activeEntity)?.anomaly_count) ||
      0;
    const observationCount = Number(entityDetail?.observation_count) || 0;
    const entityKind = String(
      entityDetail?.entity_kind ||
        entities.find((entry) => entry.entity_id === activeEntity)?.entity_kind ||
        'entity',
    ).toLowerCase();
    const suggestedOwner =
      entityKind === 'user'
        ? 'Identity or IAM owner'
        : entityKind === 'service'
          ? 'Service owner'
          : 'Endpoint or platform owner';
    const escalationLane =
      riskScore >= RISK_THRESHOLDS.high || anomalyCount >= 3
        ? 'Immediate case escalation'
        : 'Analyst validation';
    const narrative =
      anomalyCount > 0
        ? `${activeEntity} is above the risky-entity threshold with ${anomalyCount} anomaly flags across ${observationCount} observations and should be validated against recent identity, network, and endpoint telemetry.`
        : `${activeEntity} is above the risky-entity threshold and should be validated against recent identity, network, and endpoint telemetry before broad containment.`;
    const nextStep = `Validate the latest authentication, process, and network activity tied to ${activeEntity}.`;
    return {
      narrative,
      primaryPressure:
        anomalyCount > 0 ? `${anomalyCount} anomaly flags` : 'Elevated behavior score',
      observationCount,
      suggestedOwner,
      escalationLane,
      nextStep,
    };
  }, [activeEntity, entities, entityDetail]);
  const workflowItems = useMemo(() => {
    const focalEntity = focusEntity || 'the highest-risk entity';
    const focalKind =
      entityDetail?.entity_kind ||
      entities.find((entry) => entry.entity_id === focusEntity)?.entity_kind ||
      'entity';
    return [
      {
        id: 'soc-investigate',
        title: 'Escalate Into SOC Workbench',
        description: `Move ${focalEntity} into investigation planning and active case workflows.`,
        to: '/soc#investigations',
        minRole: 'analyst',
        tone: 'primary',
        badge: 'Investigate',
      },
      {
        id: 'attack-graph',
        title: 'Validate Attack Paths',
        description: `Check whether ${focalEntity} is connected to lateral movement or campaign edges.`,
        to: buildHref('/attack-graph', { params: { node: focusEntity } }),
        minRole: 'analyst',
        badge: 'Graph',
      },
      {
        id: 'threat-detection',
        title: 'Launch A Focused Hunt',
        description: `Seed a hunt with ${focalKind} risk context and current anomaly pressure.`,
        to: buildHref('/detection', {
          params: {
            intent: 'run-hunt',
            huntQuery: focusEntity ? `${focalKind}:${focusEntity} ueba anomaly` : 'ueba anomaly',
            huntName: focusEntity ? `Hunt ${focusEntity}` : 'Hunt risky entity activity',
          },
        }),
        minRole: 'analyst',
        badge: 'Detect',
      },
      {
        id: 'infrastructure',
        title: 'Cross-Check Asset Health',
        description: `Review exposure, drift, and observability evidence tied to ${focalEntity}.`,
        to: buildHref('/infrastructure', {
          params: { tab: 'assets', q: focusEntity },
        }),
        minRole: 'analyst',
        badge: 'Asset',
      },
      {
        id: 'reports',
        title: 'Capture Privacy And Evidence',
        description: 'Export analyst context into privacy-budget and evidence review workflows.',
        to: buildHref('/reports', {
          params: {
            tab: 'privacy',
            source: 'ueba',
            target: focusEntity || undefined,
          },
        }),
        minRole: 'viewer',
        badge: 'Report',
      },
    ];
  }, [entities, entityDetail, focusEntity]);

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
              color: totalAnomalyCount > 20 ? 'var(--warn)' : 'var(--text)',
            }}
          >
            {totalAnomalyCount}
          </div>
          <div className="hint">Anomalies Detected</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{peerGroups.length}</div>
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
            onClick={() => updateParams({ range: tr.label })}
          >
            {tr.label}
          </button>
        ))}
        <span style={{ marginLeft: 16, fontSize: 13, fontWeight: 600 }}>Sort:</span>
        <select
          className="auth-input"
          style={{ width: 'auto', fontSize: 12, padding: '4px 8px' }}
          value={sortBy}
          onChange={(e) => updateParams({ sort: e.target.value })}
          aria-label="Sort entities by"
        >
          <option value="risk_score">Risk Score</option>
          <option value="anomaly_count">Anomaly Count</option>
          <option value="entity_id">Entity ID</option>
        </select>
      </div>

      <WorkflowGuidance
        title="Entity Pivots"
        description="Carry the selected UEBA context into investigation, hunt, graph, and reporting workflows without rebuilding the query."
        items={workflowItems}
      />

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
              onClick={refreshUebaOverview}
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
                          onClick={() => updateParams({ entity: e.entity_id })}
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
                onClick={() => updateParams({ entity: null })}
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
                    <strong>Anomaly Flags:</strong> {entityDetail.anomaly_count || 0}
                  </div>
                  <div>
                    <strong>Peer Group:</strong> {entityDetail.peer_group || '—'}
                  </div>
                  <div>
                    <strong>Last Seen:</strong> {formatTimestamp(entityDetail.last_seen_ms)}
                  </div>
                </div>
                <RiskBar score={entityDetail.risk_score || 0} />
                {entityPlaybook && (
                  <div
                    className="card"
                    style={{
                      padding: 14,
                      background: 'var(--bg)',
                      border: '1px solid var(--border)',
                    }}
                  >
                    <div className="card-title" style={{ marginBottom: 10 }}>
                      Response Playbook
                    </div>
                    <div className="hint" style={{ marginBottom: 14 }}>
                      {entityPlaybook.narrative}
                    </div>
                    <div className="summary-grid" style={{ marginBottom: 14 }}>
                      <div className="summary-card">
                        <div className="summary-label">Primary pressure</div>
                        <div className="summary-value">{entityPlaybook.primaryPressure}</div>
                        <div className="summary-meta">Current UEBA pressure on this entity.</div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Observations</div>
                        <div className="summary-value">{entityPlaybook.observationCount}</div>
                        <div className="summary-meta">
                          Total observations retained for this entity.
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Suggested owner</div>
                        <div className="summary-value">{entityPlaybook.suggestedOwner}</div>
                        <div className="summary-meta">{entityPlaybook.escalationLane}</div>
                      </div>
                    </div>
                    <div className="detail-callout" style={{ marginBottom: 14 }}>
                      {entityPlaybook.nextStep}
                    </div>
                    <div className="btn-group" style={{ flexWrap: 'wrap' }}>
                      <a className="btn btn-sm btn-primary" href="/soc#investigations">
                        Escalate investigation
                      </a>
                      <a
                        className="btn btn-sm"
                        href={buildHref('/assistant', {
                          params: {
                            source: 'ueba',
                            investigation: selectedEntity,
                          },
                        })}
                      >
                        Ask assistant
                      </a>
                      <a
                        className="btn btn-sm"
                        href={buildHref('/reports', {
                          params: {
                            tab: 'delivery',
                            source: 'ueba',
                            target: selectedEntity,
                          },
                        })}
                      >
                        Package evidence
                      </a>
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

      {/* Peer Group Comparison */}
      {peerGroups.length > 0 && (
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
                    Flagged anomalies: <strong>{pg.total_anomalies || 0}</strong>
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

import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi } from '../hooks.jsx';
import * as api from '../api.js';
import WorkflowGuidance from './WorkflowGuidance.jsx';
import { buildHref } from './workflowPivots.js';
import { formatDateTime, formatRelativeTime } from './operatorUtils.js';

// ── Simple Force-Directed Graph Renderer ─────────────────────
// Renders attack paths as a canvas-based force-directed graph
// without external dependencies (D3-free).

const NODE_RADIUS = 24;
const NODE_COLORS = {
  host: '#3498db',
  user: '#e74c3c',
  process: '#2ecc71',
  service: '#9b59b6',
  ip: '#f39c12',
  unknown: '#95a5a6',
};
const EDGE_TYPES = {
  lateral_movement: { color: '#e74c3c', label: 'Lateral' },
  privilege_escalation: { color: '#e67e22', label: 'Priv Esc' },
  data_access: { color: '#f1c40f', label: 'Data' },
  execution: { color: '#9b59b6', label: 'Exec' },
  default: { color: '#95a5a6', label: '' },
};
const CANVAS_WIDTH = 900;
const CANVAS_HEIGHT = 600;

function forceSimulation(nodes, edges, width, height, iterations = 100) {
  // Initialize positions
  for (const n of nodes) {
    if (n.x === undefined) n.x = width / 2 + (Math.random() - 0.5) * width * 0.6;
    if (n.y === undefined) n.y = height / 2 + (Math.random() - 0.5) * height * 0.6;
    n.vx = 0;
    n.vy = 0;
  }

  const nodeMap = new Map(nodes.map((n, i) => [n.id, i]));

  for (let iter = 0; iter < iterations; iter++) {
    const alpha = 1 - iter / iterations;

    // Repulsion between all nodes
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        let dx = nodes[j].x - nodes[i].x;
        let dy = nodes[j].y - nodes[i].y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        let force = (200 * alpha) / (dist * dist);
        let fx = (dx / dist) * force;
        let fy = (dy / dist) * force;
        nodes[i].vx -= fx;
        nodes[i].vy -= fy;
        nodes[j].vx += fx;
        nodes[j].vy += fy;
      }
    }

    // Attraction along edges
    for (const e of edges) {
      const si = nodeMap.get(e.source);
      const ti = nodeMap.get(e.target);
      if (si === undefined || ti === undefined) continue;
      let dx = nodes[ti].x - nodes[si].x;
      let dy = nodes[ti].y - nodes[si].y;
      let dist = Math.sqrt(dx * dx + dy * dy) || 1;
      let force = (dist - 120) * 0.005 * alpha;
      let fx = (dx / dist) * force;
      let fy = (dy / dist) * force;
      nodes[si].vx += fx;
      nodes[si].vy += fy;
      nodes[ti].vx -= fx;
      nodes[ti].vy -= fy;
    }

    // Center gravity
    for (const n of nodes) {
      n.vx += (width / 2 - n.x) * 0.001 * alpha;
      n.vy += (height / 2 - n.y) * 0.001 * alpha;
    }

    // Apply velocities with damping
    for (const n of nodes) {
      n.vx *= 0.6;
      n.vy *= 0.6;
      n.x += n.vx;
      n.y += n.vy;
      // Keep in bounds
      n.x = Math.max(NODE_RADIUS + 10, Math.min(width - NODE_RADIUS - 10, n.x));
      n.y = Math.max(NODE_RADIUS + 10, Math.min(height - NODE_RADIUS - 10, n.y));
    }
  }

  return nodes;
}

function drawGraph(ctx, nodes, edges, width, height, hoveredNode, isDark) {
  ctx.clearRect(0, 0, width, height);

  // Draw edges
  for (const e of edges) {
    const src = nodes.find((n) => n.id === e.source);
    const tgt = nodes.find((n) => n.id === e.target);
    if (!src || !tgt) continue;
    const edgeType = EDGE_TYPES[e.type] || EDGE_TYPES.default;
    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.strokeStyle = edgeType.color;
    ctx.lineWidth = e.weight ? Math.min(e.weight, 4) : 1.5;
    ctx.globalAlpha = hoveredNode
      ? hoveredNode === e.source || hoveredNode === e.target
        ? 1
        : 0.15
      : 0.6;
    ctx.stroke();

    // Arrow head
    const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
    const arrowLen = 10;
    const mx = tgt.x - Math.cos(angle) * (NODE_RADIUS + 4);
    const my = tgt.y - Math.sin(angle) * (NODE_RADIUS + 4);
    ctx.beginPath();
    ctx.moveTo(mx, my);
    ctx.lineTo(mx - arrowLen * Math.cos(angle - 0.4), my - arrowLen * Math.sin(angle - 0.4));
    ctx.lineTo(mx - arrowLen * Math.cos(angle + 0.4), my - arrowLen * Math.sin(angle + 0.4));
    ctx.closePath();
    ctx.fillStyle = edgeType.color;
    ctx.fill();
    ctx.globalAlpha = 1;

    // Edge label
    if (edgeType.label) {
      const lx = (src.x + tgt.x) / 2;
      const ly = (src.y + tgt.y) / 2;
      ctx.font = '10px system-ui';
      ctx.fillStyle = isDark ? '#aaa' : '#666';
      ctx.textAlign = 'center';
      ctx.fillText(edgeType.label, lx, ly - 6);
    }
  }

  // Draw nodes
  for (const n of nodes) {
    const isHovered = hoveredNode === n.id;
    const color = NODE_COLORS[n.type] || NODE_COLORS.unknown;
    ctx.globalAlpha = hoveredNode && !isHovered ? 0.3 : 1;

    // Circle
    ctx.beginPath();
    ctx.arc(n.x, n.y, isHovered ? NODE_RADIUS + 4 : NODE_RADIUS, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    if (n.compromised) {
      ctx.strokeStyle = '#e74c3c';
      ctx.lineWidth = 3;
      ctx.stroke();
    }

    // Risk ring
    if (n.risk_score > 0) {
      const ringAlpha = Math.min(n.risk_score / 100, 1);
      ctx.beginPath();
      ctx.arc(n.x, n.y, NODE_RADIUS + 8, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * ringAlpha);
      ctx.strokeStyle = `rgba(231, 76, 60, ${ringAlpha})`;
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Label
    ctx.font = `${isHovered ? 'bold ' : ''}11px system-ui`;
    ctx.fillStyle = isDark ? '#eee' : '#222';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const label = n.label || n.id;
    ctx.fillText(
      label.length > 12 ? label.substring(0, 11) + '…' : label,
      n.x,
      n.y + NODE_RADIUS + 14,
    );
    ctx.globalAlpha = 1;
  }
}

function formatChainWindow(startMs, endMs) {
  const start = Number(startMs || 0);
  const end = Number(endMs || 0);
  if (!start || !end || end <= start) return 'Single-stage burst';
  const durationSeconds = Math.round((end - start) / 1000);
  if (durationSeconds < 60) return `${durationSeconds}s window`;
  if (durationSeconds < 3600) return `${Math.round(durationSeconds / 60)}m window`;
  const durationHours = durationSeconds / 3600;
  return `${durationHours >= 10 ? Math.round(durationHours) : durationHours.toFixed(1)}h window`;
}

function formatChainTimestamp(timestampMs) {
  const timestamp = Number(timestampMs || 0);
  if (!timestamp) return '—';
  return formatDateTime(new Date(timestamp).toISOString());
}

export default function AttackGraph() {
  const canvasRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [searchParams, setSearchParams] = useSearchParams();

  const { data: lateralData } = useApi(api.campaigns);
  const { data: coverageGaps } = useApi(api.coverageGaps);
  const campaignSummary = lateralData?.summary || {};
  const sequenceSummaries = Array.isArray(lateralData?.sequence_summaries)
    ? lateralData.sequence_summaries
    : [];
  const temporalChains = Array.isArray(lateralData?.temporal_chains)
    ? lateralData.temporal_chains
    : [];
  const selectedChainId = searchParams.get('chain') || temporalChains[0]?.chain_id || '';
  const selectedChain = useMemo(
    () => temporalChains.find((chain) => chain.chain_id === selectedChainId) || temporalChains[0] || null,
    [selectedChainId, temporalChains],
  );

  const { nodes, edges } = useMemo(() => {
    if (!lateralData) return { nodes: [], edges: [] };
    const data = lateralData.graph || lateralData;
    const n = (data.nodes || []).slice(0, 200);
    const e = (data.edges || []).slice(0, 500);
    return { nodes: n, edges: e };
  }, [lateralData]);

  const layoutNodes = useMemo(() => {
    if (nodes.length === 0) return [];
    return forceSimulation([...nodes.map((n) => ({ ...n }))], edges, CANVAS_WIDTH, CANVAS_HEIGHT);
  }, [nodes, edges]);
  const selectedNodeId = searchParams.get('node') || '';
  const selectedNode = useMemo(
    () =>
      layoutNodes.find((node) => node.id === selectedNodeId) ||
      nodes.find((node) => node.id === selectedNodeId) ||
      null,
    [layoutNodes, nodes, selectedNodeId],
  );

  const updateParams = useCallback(
    (changes) => {
      const next = new URLSearchParams(searchParams);
      Object.entries(changes).forEach(([key, value]) => {
        if (value == null || value === '') next.delete(key);
        else next.set(key, value);
      });
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  const render = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || layoutNodes.length === 0) return;
    const ctx = canvas.getContext('2d');
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    drawGraph(ctx, layoutNodes, edges, canvas.width, canvas.height, hoveredNode, isDark);
  }, [layoutNodes, edges, hoveredNode]);

  useEffect(() => {
    render();
  }, [render]);

  const handleMouseMove = useCallback(
    (e) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const found = layoutNodes.find(
        (n) => Math.sqrt((n.x - mx) ** 2 + (n.y - my) ** 2) < NODE_RADIUS + 4,
      );
      setHoveredNode(found ? found.id : null);
      canvas.style.cursor = found ? 'pointer' : 'default';
    },
    [layoutNodes],
  );

  const handleClick = useCallback(
    (e) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const found = layoutNodes.find(
        (n) => Math.sqrt((n.x - mx) ** 2 + (n.y - my) ** 2) < NODE_RADIUS + 4,
      );
      updateParams({ node: found?.id || null });
    },
    [layoutNodes, updateParams],
  );

  const selectedEdges = useMemo(() => {
    if (!selectedNode) return [];
    return edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id);
  }, [selectedNode, edges]);
  const workflowItems = useMemo(() => {
    const focalNode = selectedNode?.id || nodes[0]?.id || '';
    const focalType = selectedNode?.type || 'node';
    return [
      {
        id: 'soc-campaigns',
        title: 'Open Campaign Investigation',
        description: `${selectedEdges.length || edges.length} graph edge${selectedEdges.length === 1 ? '' : 's'} can be reviewed in campaign and investigation workflows.`,
        to: '/soc#campaigns',
        minRole: 'analyst',
        tone: 'primary',
        badge: 'Investigate',
      },
      {
        id: 'hunt-graph-node',
        title: 'Seed A Detection Hunt',
        description: `Turn ${focalNode || 'the selected graph path'} into a hunt query and response-ready workflow.`,
        to: buildHref('/detection', {
          params: {
            intent: 'run-hunt',
            huntQuery: focalNode
              ? `${focalType}:${focalNode} attack graph path`
              : 'attack graph campaign',
            huntName: focalNode ? `Hunt ${focalNode}` : 'Hunt attack graph signals',
          },
        }),
        minRole: 'analyst',
        badge: 'Detect',
      },
      {
        id: 'ueba-entity',
        title: 'Inspect UEBA Risk',
        description: `Carry ${focalNode || 'the selected identity'} into entity-risk scoring and anomaly review.`,
        to: buildHref('/ueba', { params: { entity: focalNode } }),
        minRole: 'analyst',
        badge: 'Entity',
      },
      {
        id: 'infrastructure',
        title: 'Cross-Check Asset Evidence',
        description: `Open infrastructure drift, exposure, or observability context for ${focalNode || 'the selected node'}.`,
        to: buildHref('/infrastructure', { params: { tab: 'assets', q: focalNode } }),
        minRole: 'analyst',
        badge: 'Asset',
      },
      {
        id: 'ndr',
        title: 'Validate Network Side',
        description:
          'Use NDR to confirm whether graph relationships align with current network anomalies.',
        to: buildHref('/ndr', { params: { tab: 'overview' } }),
        minRole: 'analyst',
        badge: 'Network',
      },
      {
        id: 'reports',
        title: 'Export Evidence Bundle',
        description: 'Package graph context into evidence and executive reporting workflows.',
        to: buildHref('/reports', {
          params: {
            tab: 'evidence',
            source: 'attack-graph',
            target: focalNode || undefined,
          },
        }),
        minRole: 'viewer',
        badge: 'Report',
      },
    ];
  }, [edges.length, nodes, selectedEdges.length, selectedNode]);

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 16 }}>Attack Path Graph</div>
          <div className="hint">
            {nodes.length} nodes, {edges.length} edges — lateral movement, privilege escalation, and
            data access paths
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {Object.entries(NODE_COLORS)
            .filter(([k]) => k !== 'unknown')
            .map(([type, color]) => (
              <span
                key={type}
                style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}
              >
                <span
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: '50%',
                    background: color,
                    display: 'inline-block',
                  }}
                />
                {type}
              </span>
            ))}
        </div>
      </div>

      <WorkflowGuidance
        title="Attack Graph Pivots"
        description="Move from graph context into hunts, campaigns, entity analytics, network validation, and evidence workflows without losing the selected node."
        items={workflowItems}
      />

      <div
        className="card"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 12,
        }}
      >
        <div>
          <div className="card-title">Campaign Intelligence</div>
          <div className="hint">
            Stored-event clustering turns repeated sequence and graph signals into campaign-ready
            pivots.
          </div>
        </div>
        <div>
          <div className="metric-value">{campaignSummary.campaign_count ?? 0}</div>
          <div className="metric-label">Active campaigns</div>
        </div>
        <div>
          <div className="metric-value">{campaignSummary.total_alerts ?? 0}</div>
          <div className="metric-label">Alerts analyzed</div>
        </div>
        <div>
          <div className="metric-value">
            {Math.round((campaignSummary.fleet_coverage || 0) * 100)}%
          </div>
          <div className="metric-label">Fleet coverage</div>
        </div>
        <div>
          <div className="metric-value">
            {campaignSummary.temporal_chain_count ?? temporalChains.length}
          </div>
          <div className="metric-label">Local temporal chains</div>
        </div>
        {sequenceSummaries[0] && (
          <div style={{ gridColumn: '1 / -1' }}>
            <div style={{ fontWeight: 700, marginBottom: 6 }}>{sequenceSummaries[0].name}</div>
            <div className="chip-row" style={{ marginBottom: 8 }}>
              <span className="badge badge-info">{sequenceSummaries[0].severity}</span>
              <span className="scope-chip">{sequenceSummaries[0].host_count} hosts</span>
              <span className="scope-chip">{sequenceSummaries[0].alert_count} alerts</span>
              {(sequenceSummaries[0].shared_techniques || []).slice(0, 2).map((technique) => (
                <span key={technique} className="scope-chip">
                  {technique}
                </span>
              ))}
            </div>
            {(sequenceSummaries[0].sequence_signals || []).slice(0, 3).map((signal) => (
              <div key={signal} className="hint">
                {signal}
              </div>
            ))}
          </div>
        )}
        {temporalChains[0] && (
          <div style={{ gridColumn: '1 / -1' }}>
            <div style={{ fontWeight: 700, marginBottom: 6 }}>
              {temporalChains[0].host} temporal chain
            </div>
            <div className="chip-row" style={{ marginBottom: 8 }}>
              <span className="badge badge-warn">{temporalChains[0].severity}</span>
              <span className="scope-chip">{temporalChains[0].alert_count} alerts</span>
              {(temporalChains[0].shared_techniques || []).slice(0, 2).map((technique) => (
                <span key={technique} className="scope-chip">
                  {technique}
                </span>
              ))}
            </div>
            {(temporalChains[0].shared_reasons || []).slice(0, 2).map((reason) => (
              <div key={reason} className="hint">
                {reason}
              </div>
            ))}
          </div>
        )}
        {temporalChains.length > 0 && (
          <div style={{ gridColumn: '1 / -1' }}>
            <div style={{ fontWeight: 700, marginBottom: 6 }}>Temporal chain queue</div>
            <div className="hint" style={{ marginBottom: 10 }}>
              Select a local host burst to inspect timing, shared techniques, and impacted alerts.
            </div>
            <div style={{ display: 'grid', gap: 8 }}>
              {temporalChains.slice(0, 5).map((chain) => {
                const isSelected = selectedChain?.chain_id === chain.chain_id;
                return (
                  <button
                    key={chain.chain_id}
                    type="button"
                    className="card"
                    aria-pressed={isSelected}
                    onClick={() => updateParams({ chain: chain.chain_id })}
                    style={{
                      textAlign: 'left',
                      display: 'grid',
                      gap: 6,
                      borderColor: isSelected ? 'var(--accent)' : 'var(--border)',
                      boxShadow: isSelected ? '0 0 0 1px rgba(59, 130, 246, 0.18)' : 'none',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                      <strong>Focus {chain.host} burst</strong>
                      <span className={`badge ${String(chain.severity || '').toLowerCase() === 'critical' ? 'badge-err' : 'badge-warn'}`}>
                        {chain.severity}
                      </span>
                    </div>
                    <div className="hint">
                      {chain.alert_count} alerts · {formatChainWindow(chain.first_seen_ms, chain.last_seen_ms)}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {selectedChain && (
        <div className="card" style={{ display: 'grid', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'flex-start' }}>
            <div>
              <div className="card-title">Temporal Chain Drilldown</div>
              <div className="hint">
                {selectedChain.host} burst from {formatChainTimestamp(selectedChain.first_seen_ms)} to{' '}
                {formatChainTimestamp(selectedChain.last_seen_ms)}.
              </div>
            </div>
            <div className="chip-row">
              <span className={`badge ${String(selectedChain.severity || '').toLowerCase() === 'critical' ? 'badge-err' : 'badge-warn'}`}>
                {selectedChain.severity}
              </span>
              <span className="scope-chip">{selectedChain.alert_count} alerts</span>
              <span className="scope-chip">{formatChainWindow(selectedChain.first_seen_ms, selectedChain.last_seen_ms)}</span>
            </div>
          </div>

          <div className="card-grid">
            <div className="card">
              <div className="metric-label">Average score</div>
              <div className="metric-value">{Number(selectedChain.avg_score || 0).toFixed(2)}</div>
              <div className="metric-sub">Max {Number(selectedChain.max_score || 0).toFixed(2)}</div>
            </div>
            <div className="card">
              <div className="metric-label">First seen</div>
              <div className="metric-value">{formatRelativeTime(new Date(selectedChain.first_seen_ms).toISOString())}</div>
              <div className="metric-sub">{formatChainTimestamp(selectedChain.first_seen_ms)}</div>
            </div>
            <div className="card">
              <div className="metric-label">Last seen</div>
              <div className="metric-value">{formatRelativeTime(new Date(selectedChain.last_seen_ms).toISOString())}</div>
              <div className="metric-sub">{formatChainTimestamp(selectedChain.last_seen_ms)}</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 8 }}>Shared techniques</div>
              <div className="chip-row">
                {(selectedChain.shared_techniques || []).length > 0 ? (
                  selectedChain.shared_techniques.map((technique) => (
                    <span key={technique} className="scope-chip">
                      {technique}
                    </span>
                  ))
                ) : (
                  <span className="hint">No shared MITRE technique markers were inferred for this burst.</span>
                )}
              </div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 8 }}>Signal overlap</div>
              <div style={{ display: 'grid', gap: 6 }}>
                {(selectedChain.shared_reasons || []).length > 0 ? (
                  selectedChain.shared_reasons.map((reason) => (
                    <div key={reason} className="hint">
                      {reason}
                    </div>
                  ))
                ) : (
                  <span className="hint">No repeated reason strings were shared across the local burst.</span>
                )}
              </div>
            </div>
          </div>

          <div>
            <div className="card-title" style={{ marginBottom: 8 }}>Impacted alerts</div>
            <div className="chip-row">
              {(selectedChain.alert_ids || []).map((alertId) => (
                <span key={alertId} className="scope-chip">
                  {alertId}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: selectedNode ? '1fr 300px' : '1fr',
          gap: 16,
        }}
      >
        <div className="card" style={{ padding: 0, overflow: 'hidden', position: 'relative' }}>
          {nodes.length === 0 ? (
            <div className="empty" style={{ padding: 60, textAlign: 'center' }}>
              <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>
                No Attack Path Data
              </div>
              <div className="hint">
                Campaign and lateral movement data will populate this graph
              </div>
            </div>
          ) : (
            <canvas
              ref={canvasRef}
              width={CANVAS_WIDTH}
              height={CANVAS_HEIGHT}
              onMouseMove={handleMouseMove}
              onClick={handleClick}
              style={{ width: '100%', height: CANVAS_HEIGHT, display: 'block' }}
              aria-label={`Attack path graph with ${nodes.length} nodes and ${edges.length} edges`}
              role="img"
            />
          )}
        </div>

        {selectedNode && (
          <div className="card" style={{ padding: 16 }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: 12,
              }}
            >
              <div className="card-title">Node Detail</div>
              <button
                className="btn btn-sm"
                onClick={() => updateParams({ node: null })}
                aria-label="Close node detail"
              >
                ✕
              </button>
            </div>
            <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
              <div>
                <strong>ID:</strong> {selectedNode.id}
              </div>
              <div>
                <strong>Type:</strong>{' '}
                <span className="badge badge-info">{selectedNode.type || 'unknown'}</span>
              </div>
              <div>
                <strong>Label:</strong> {selectedNode.label || selectedNode.id}
              </div>
              {selectedNode.risk_score !== undefined && (
                <div>
                  <strong>Risk:</strong>{' '}
                  <span
                    className={`badge ${selectedNode.risk_score >= 60 ? 'badge-err' : 'badge-warn'}`}
                  >
                    {selectedNode.risk_score.toFixed(1)}
                  </span>
                </div>
              )}
              {selectedNode.compromised && (
                <div>
                  <span className="badge badge-err">Compromised</span>
                </div>
              )}
              {selectedEdges.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <strong>Connections ({selectedEdges.length}):</strong>
                  <div style={{ display: 'grid', gap: 4, marginTop: 6 }}>
                    {selectedEdges.map((e, i) => (
                      <div
                        key={i}
                        style={{
                          padding: 6,
                          borderRadius: 6,
                          border: '1px solid var(--border)',
                          fontSize: 12,
                        }}
                      >
                        <span
                          style={{
                            color: (EDGE_TYPES[e.type] || EDGE_TYPES.default).color,
                            fontWeight: 600,
                          }}
                        >
                          {e.type?.replace('_', ' ') || 'link'}
                        </span>
                        {' → '}
                        {e.source === selectedNode.id ? e.target : e.source}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="card" style={{ padding: 16 }}>
        <div className="card-title" style={{ marginBottom: 8 }}>
          ATT&CK Gap Heatmap
        </div>
        <div className="hint" style={{ marginBottom: 10 }}>
          Techniques with no active hunt/rule coverage are highlighted for engineering backlogs.
        </div>
        <div style={{ display: 'grid', gap: 6 }}>
          {(Array.isArray(coverageGaps?.gaps)
            ? coverageGaps.gaps
            : Array.isArray(coverageGaps)
              ? coverageGaps
              : []
          )
            .slice(0, 10)
            .map((gap, index) => (
              <div
                key={`${gap?.technique_id || gap?.technique || 'gap'}-${index}`}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  gap: 12,
                  borderBottom: '1px solid var(--border)',
                  padding: '8px 0',
                }}
              >
                <span className="row-primary">
                  {gap?.technique_id || gap?.technique || 'Unknown'}
                </span>
                <span className="row-secondary">
                  {gap?.technique_name || gap?.name || 'Unmapped'}
                </span>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}

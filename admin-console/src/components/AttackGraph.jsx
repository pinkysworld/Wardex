import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { useApi } from '../hooks.jsx';
import * as api from '../api.js';

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

export default function AttackGraph() {
  const canvasRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  const { data: lateralData } = useApi(api.campaigns);

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
      setSelectedNode(found || null);
    },
    [layoutNodes],
  );

  const selectedEdges = useMemo(() => {
    if (!selectedNode) return [];
    return edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id);
  }, [selectedNode, edges]);

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
                onClick={() => setSelectedNode(null)}
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
    </div>
  );
}

import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useInterval } from '../hooks.jsx';
import * as api from '../api.js';
import WorkflowGuidance from './WorkflowGuidance.jsx';
import { buildHref } from './workflowPivots.js';

const PROTOCOL_COLORS = {
  TCP: '#3498db',
  UDP: '#2ecc71',
  ICMP: '#e74c3c',
  HTTP: '#9b59b6',
  HTTPS: '#1abc9c',
  DNS: '#f39c12',
  SSH: '#e67e22',
  OTHER: '#95a5a6',
};

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function RiskBadge({ score }) {
  const cls =
    score >= 8 ? 'badge-err' : score >= 5 ? 'badge-warn' : score >= 3 ? 'badge-info' : 'badge-ok';
  return <span className={`badge ${cls}`}>{score.toFixed(1)}</span>;
}

export default function NDRDashboard() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: report, loading, reload } = useApi(api.ndrReport);
  const { data: tlsAnomalies } = useApi(api.ndrTlsAnomalies);
  const { data: dpiAnomalies } = useApi(api.ndrDpiAnomalies);

  const updateParams = (changes) => {
    const next = new URLSearchParams(searchParams);
    Object.entries(changes).forEach(([key, value]) => {
      if (value == null || value === '') next.delete(key);
      else next.set(key, value);
    });
    setSearchParams(next, { replace: true });
  };

  useInterval(reload, 30000);

  const r = report || {};
  const topTalkers = r.top_talkers || [];
  const unusualDests = r.unusual_destinations || [];
  const protoAnomalies = r.protocol_anomalies || [];
  const encStats = r.encrypted_traffic || {};
  const tlsList = Array.isArray(tlsAnomalies)
    ? tlsAnomalies
    : tlsAnomalies?.items || r.tls_anomalies || [];
  const dpiList = Array.isArray(dpiAnomalies)
    ? dpiAnomalies
    : dpiAnomalies?.items || r.dpi_anomalies || [];
  const entropyList = r.entropy_anomalies || [];
  const beaconingList = r.beaconing_anomalies || [];
  const selfSignedList = r.self_signed_certs || [];

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'tls', label: `TLS (${tlsList.length})` },
    { id: 'dpi', label: `DPI (${dpiList.length})` },
    { id: 'entropy', label: `Entropy (${entropyList.length})` },
    { id: 'beaconing', label: `Beaconing (${beaconingList.length})` },
    { id: 'certs', label: `Certs (${selfSignedList.length})` },
  ];
  const activeTab = tabs.some((entry) => entry.id === searchParams.get('tab'))
    ? searchParams.get('tab')
    : 'overview';
  const leadAddress = unusualDests[0]?.dst_addr || topTalkers[0]?.addr || '';
  const workflowItems = useMemo(
    () => [
      {
        id: 'soc-triage',
        title: 'Hand Network Signals To SOC',
        description: `${tlsList.length + beaconingList.length + dpiList.length} network findings can move directly into queue triage and response review.`,
        to: '/soc#queue',
        minRole: 'analyst',
        tone: 'primary',
        badge: 'Triage',
      },
      {
        id: 'infrastructure-review',
        title: 'Review Impacted Assets',
        description: `Pivot ${leadAddress || 'the active network footprint'} into observability and asset health review.`,
        to: buildHref('/infrastructure', {
          params: { tab: 'observability', q: leadAddress },
        }),
        minRole: 'analyst',
        badge: 'Asset',
      },
      {
        id: 'hunt-network-pattern',
        title: 'Launch A Hunt',
        description: `Carry ${activeTab} context into Threat Detection for a saved or ad-hoc network hunt.`,
        to: buildHref('/detection', {
          params: {
            intent: 'run-hunt',
            huntQuery: `${activeTab} network anomaly ${leadAddress}`,
            huntName: `Hunt ${activeTab} network anomalies`,
          },
        }),
        minRole: 'analyst',
        badge: 'Detect',
      },
      {
        id: 'attack-graph',
        title: 'Map Campaign Propagation',
        description: 'Use the attack graph to validate whether network findings are part of a broader campaign chain.',
        to: '/attack-graph',
        minRole: 'analyst',
        badge: 'Graph',
      },
      {
        id: 'reports',
        title: 'Package Delivery Evidence',
        description: 'Open report delivery and evidence workflows for executive or audit-ready exports.',
        to: buildHref('/reports', { params: { tab: 'delivery' } }),
        minRole: 'viewer',
        badge: 'Report',
      },
    ],
    [activeTab, beaconingList.length, dpiList.length, leadAddress, tlsList.length],
  );

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      {/* Summary Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 12,
        }}
      >
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{r.total_flows_analysed || 0}</div>
          <div className="hint">Total Flows</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{formatBytes(r.total_bytes)}</div>
          <div className="hint">Total Traffic</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{r.unique_external_destinations || 0}</div>
          <div className="hint">External Destinations</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {(r.connections_per_second || 0).toFixed(1)}
          </div>
          <div className="hint">Connections/sec</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div
            style={{
              fontSize: 28,
              fontWeight: 700,
              color: encStats.encrypted_ratio > 0.9 ? 'var(--ok)' : 'var(--warn)',
            }}
          >
            {((encStats.encrypted_ratio || 0) * 100).toFixed(0)}%
          </div>
          <div className="hint">Encrypted Traffic</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div
            style={{
              fontSize: 28,
              fontWeight: 700,
              color: tlsList.length > 0 ? 'var(--err)' : 'var(--ok)',
            }}
          >
            {tlsList.length}
          </div>
          <div className="hint">TLS Anomalies</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div
            style={{
              fontSize: 28,
              fontWeight: 700,
              color: beaconingList.length > 0 ? 'var(--err)' : 'var(--ok)',
            }}
          >
            {beaconingList.length}
          </div>
          <div className="hint">Beaconing Signals</div>
        </div>
      </div>

      <WorkflowGuidance
        title="Network Pivots"
        description="Push active network findings into hunts, asset review, investigations, and delivery workflows without rebuilding the context by hand."
        items={workflowItems}
      />

      {/* Tab Bar */}
      <div
        style={{
          display: 'flex',
          gap: 4,
          borderBottom: '2px solid var(--border)',
          paddingBottom: 0,
        }}
      >
        {tabs.map((t) => (
          <button
            key={t.id}
            className={`btn btn-sm ${activeTab === t.id ? 'btn-primary' : ''}`}
            onClick={() => updateParams({ tab: t.id })}
            style={{ borderRadius: '8px 8px 0 0' }}
            aria-selected={activeTab === t.id}
            role="tab"
          >
            {t.label}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <button className="btn btn-sm" onClick={reload} aria-label="Refresh NDR data">
          Refresh
        </button>
      </div>

      {loading ? (
        <div className="loading" style={{ padding: 40 }}>
          Analyzing network flows…
        </div>
      ) : (
        <>
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {/* Top Talkers */}
              <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                  <div className="card-title">Top Talkers</div>
                </div>
                <div style={{ maxHeight: 350, overflowY: 'auto' }}>
                  <table className="data-table" style={{ width: '100%' }}>
                    <thead>
                      <tr>
                        <th>Address</th>
                        <th>Traffic</th>
                        <th>Flows</th>
                        <th>Destinations</th>
                        <th>Protocols</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topTalkers.length === 0 ? (
                        <tr>
                          <td colSpan={5} style={{ textAlign: 'center', padding: 16 }}>
                            No data
                          </td>
                        </tr>
                      ) : (
                        topTalkers.map((t, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                              {t.addr}
                            </td>
                            <td>{formatBytes(t.total_bytes)}</td>
                            <td>{t.flow_count}</td>
                            <td>{t.unique_destinations}</td>
                            <td>
                              {(t.protocols || []).map((p) => (
                                <span
                                  key={p}
                                  className="badge badge-info"
                                  style={{
                                    marginRight: 3,
                                    padding: '1px 5px',
                                    fontSize: 10,
                                    background: PROTOCOL_COLORS[p] || PROTOCOL_COLORS.OTHER,
                                    color: '#fff',
                                  }}
                                >
                                  {p}
                                </span>
                              ))}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Unusual Destinations */}
              <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                  <div className="card-title">Unusual External Destinations</div>
                </div>
                <div style={{ maxHeight: 350, overflowY: 'auto' }}>
                  <table className="data-table" style={{ width: '100%' }}>
                    <thead>
                      <tr>
                        <th>Destination</th>
                        <th>Port</th>
                        <th>Traffic</th>
                        <th>Risk</th>
                        <th>Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {unusualDests.length === 0 ? (
                        <tr>
                          <td colSpan={5} style={{ textAlign: 'center', padding: 16 }}>
                            No anomalies
                          </td>
                        </tr>
                      ) : (
                        unusualDests.map((d, i) => (
                          <tr key={i}>
                            <td style={{ fontFamily: 'var(--font-mono)' }}>{d.dst_addr}</td>
                            <td>{d.dst_port}</td>
                            <td>{formatBytes(d.total_bytes)}</td>
                            <td>
                              <RiskBadge score={d.risk_score || 0} />
                            </td>
                            <td
                              style={{
                                maxWidth: 200,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                            >
                              {d.reason}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Protocol Anomalies */}
              <div
                className="card"
                style={{ padding: 0, overflow: 'hidden', gridColumn: '1 / -1' }}
              >
                <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                  <div className="card-title">Protocol Anomalies</div>
                </div>
                <div style={{ maxHeight: 260, overflowY: 'auto' }}>
                  <table className="data-table" style={{ width: '100%' }}>
                    <thead>
                      <tr>
                        <th>Protocol</th>
                        <th>Port</th>
                        <th>Expected</th>
                        <th>Flows</th>
                        <th>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {protoAnomalies.length === 0 ? (
                        <tr>
                          <td colSpan={5} style={{ textAlign: 'center', padding: 16 }}>
                            No anomalies
                          </td>
                        </tr>
                      ) : (
                        protoAnomalies.map((a, i) => (
                          <tr key={i}>
                            <td>
                              <span className="badge badge-warn">{a.protocol}</span>
                            </td>
                            <td>{a.port}</td>
                            <td>{a.expected_protocol}</td>
                            <td>{a.flow_count}</td>
                            <td>
                              <RiskBadge score={a.risk_score || 0} />
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TLS Fingerprint Tab */}
          {activeTab === 'tls' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                <div className="card-title">JA3/JA4 TLS Fingerprint Anomalies</div>
                <div className="hint" style={{ marginTop: 4 }}>
                  Matches against known C2 framework fingerprints and rare TLS client signatures
                </div>
              </div>
              <div style={{ maxHeight: 500, overflowY: 'auto' }}>
                <table className="data-table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th>JA3 Hash</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>SNI</th>
                      <th>TLS Ver</th>
                      <th>Flows</th>
                      <th>Risk</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tlsList.length === 0 ? (
                      <tr>
                        <td colSpan={8} style={{ textAlign: 'center', padding: 20 }}>
                          No TLS anomalies
                        </td>
                      </tr>
                    ) : (
                      tlsList.map((a, i) => (
                        <tr key={i}>
                          <td
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: 11,
                              maxWidth: 120,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                            }}
                            title={a.ja3_hash}
                          >
                            {a.ja3_hash?.substring(0, 12)}…
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{a.src_addr}</td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>
                            {a.dst_addr}:{a.dst_port}
                          </td>
                          <td>{a.tls_sni || '—'}</td>
                          <td>{a.tls_version || '—'}</td>
                          <td>{a.flow_count}</td>
                          <td>
                            <RiskBadge score={a.risk_score || 0} />
                          </td>
                          <td
                            style={{
                              maxWidth: 200,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {a.reason}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* DPI Tab */}
          {activeTab === 'dpi' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                <div className="card-title">Deep Packet Inspection Mismatches</div>
                <div className="hint" style={{ marginTop: 4 }}>
                  Flows where DPI-detected protocol differs from expected port assignment (e.g. SSH
                  tunneled over port 443)
                </div>
              </div>
              <div style={{ maxHeight: 500, overflowY: 'auto' }}>
                <table className="data-table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Port</th>
                      <th>Expected</th>
                      <th>Detected</th>
                      <th>Flows</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dpiList.length === 0 ? (
                      <tr>
                        <td colSpan={7} style={{ textAlign: 'center', padding: 20 }}>
                          No DPI mismatches
                        </td>
                      </tr>
                    ) : (
                      dpiList.map((a, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{a.src_addr}</td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{a.dst_addr}</td>
                          <td>{a.dst_port}</td>
                          <td>
                            <span className="badge badge-ok">{a.expected_protocol}</span>
                          </td>
                          <td>
                            <span className="badge badge-err">{a.detected_protocol}</span>
                          </td>
                          <td>{a.flow_count}</td>
                          <td>
                            <RiskBadge score={a.risk_score || 0} />
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Entropy Tab */}
          {activeTab === 'entropy' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                <div className="card-title">High-Entropy Encrypted Sessions</div>
                <div className="hint" style={{ marginTop: 4 }}>
                  Sessions with payload entropy &gt;7.5 bits — potential encrypted C2 channels or
                  data exfiltration
                </div>
              </div>
              <div style={{ maxHeight: 500, overflowY: 'auto' }}>
                <table className="data-table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Port</th>
                      <th>Avg Entropy</th>
                      <th>Total Traffic</th>
                      <th>Flows</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entropyList.length === 0 ? (
                      <tr>
                        <td colSpan={7} style={{ textAlign: 'center', padding: 20 }}>
                          No high-entropy sessions
                        </td>
                      </tr>
                    ) : (
                      entropyList.map((a, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{a.src_addr}</td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{a.dst_addr}</td>
                          <td>{a.dst_port}</td>
                          <td>
                            <span
                              className={`badge ${a.avg_entropy > 7.8 ? 'badge-err' : 'badge-warn'}`}
                            >
                              {a.avg_entropy?.toFixed(2)}
                            </span>
                          </td>
                          <td>{formatBytes(a.total_bytes)}</td>
                          <td>{a.flow_count}</td>
                          <td>
                            <RiskBadge score={a.risk_score || 0} />
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'beaconing' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                <div className="card-title">Regular Beaconing Cadence</div>
                <div className="hint" style={{ marginTop: 4 }}>
                  Outbound connections with stable intervals and low jitter that resemble
                  command-and-control check-ins
                </div>
              </div>
              <div style={{ maxHeight: 500, overflowY: 'auto' }}>
                <table className="data-table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Protocol</th>
                      <th>Avg Interval</th>
                      <th>Jitter</th>
                      <th>Flows</th>
                      <th>Traffic</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {beaconingList.length === 0 ? (
                      <tr>
                        <td colSpan={8} style={{ textAlign: 'center', padding: 20 }}>
                          No beaconing-like cadence detected
                        </td>
                      </tr>
                    ) : (
                      beaconingList.map((item, index) => (
                        <tr key={index}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{item.src_addr}</td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>
                            {item.dst_addr}:{item.dst_port}
                          </td>
                          <td>
                            <span className="badge badge-info">{item.protocol}</span>
                          </td>
                          <td>{((item.avg_interval_ms || 0) / 1000).toFixed(0)}s</td>
                          <td>
                            <span
                              className={`badge ${item.jitter_pct <= 5 ? 'badge-err' : item.jitter_pct <= 10 ? 'badge-warn' : 'badge-info'}`}
                            >
                              {item.jitter_pct?.toFixed(1)}%
                            </span>
                          </td>
                          <td>{item.flow_count}</td>
                          <td>{formatBytes(item.total_bytes)}</td>
                          <td>
                            <RiskBadge score={item.risk_score || 0} />
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Certs Tab */}
          {activeTab === 'certs' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                <div className="card-title">Self-Signed Certificate Detections</div>
              </div>
              <div style={{ maxHeight: 500, overflowY: 'auto' }}>
                <table className="data-table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th>Destination</th>
                      <th>Port</th>
                      <th>SNI</th>
                      <th>Issuer</th>
                      <th>Subject</th>
                      <th>Flows</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selfSignedList.length === 0 ? (
                      <tr>
                        <td colSpan={7} style={{ textAlign: 'center', padding: 20 }}>
                          No self-signed certificates
                        </td>
                      </tr>
                    ) : (
                      selfSignedList.map((c, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{c.dst_addr}</td>
                          <td>{c.dst_port}</td>
                          <td>{c.tls_sni || '—'}</td>
                          <td>{c.tls_issuer || '—'}</td>
                          <td>{c.tls_subject || '—'}</td>
                          <td>{c.flow_count}</td>
                          <td>
                            <RiskBadge score={c.risk_score || 0} />
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

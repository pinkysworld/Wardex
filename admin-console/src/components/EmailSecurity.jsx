import { useState } from 'react';
import { useApi, useInterval } from '../hooks.jsx';
import * as api from '../api.js';

function PhishingBadge({ score }) {
  if (score >= 0.7)
    return <span className="badge badge-err">High Risk ({(score * 100).toFixed(0)}%)</span>;
  if (score >= 0.4)
    return <span className="badge badge-warn">Medium ({(score * 100).toFixed(0)}%)</span>;
  if (score >= 0.2)
    return <span className="badge badge-info">Low ({(score * 100).toFixed(0)}%)</span>;
  return <span className="badge badge-ok">Clean ({(score * 100).toFixed(0)}%)</span>;
}

export default function EmailSecurity() {
  const [tab, setTab] = useState('quarantine');
  const [analyzeInput, setAnalyzeInput] = useState('');
  const [analyzeResult, setAnalyzeResult] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);

  const { data: quarantine, loading: loadingQ, reload: reloadQ } = useApi(api.emailQuarantine);
  const { data: stats } = useApi(api.emailStats);
  const { data: policies, loading: loadingPolicies } = useApi(api.emailPolicies);

  useInterval(reloadQ, 30000);

  const qItems = Array.isArray(quarantine) ? quarantine : quarantine?.items || [];
  const st = stats || {};

  const handleAnalyze = async () => {
    setAnalyzing(true);
    try {
      const body = JSON.parse(analyzeInput);
      const result = await api.emailAnalyze(body);
      setAnalyzeResult(result);
    } catch (e) {
      setAnalyzeResult({ error: e.message });
    } finally {
      setAnalyzing(false);
    }
  };

  const handleRelease = async (id) => {
    await api.emailQuarantineRelease(id);
    reloadQ();
  };

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
          <div style={{ fontSize: 28, fontWeight: 700 }}>{st.total_scanned || 0}</div>
          <div className="hint">Emails Scanned</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div
            style={{
              fontSize: 28,
              fontWeight: 700,
              color: qItems.length > 0 ? 'var(--err)' : 'var(--ok)',
            }}
          >
            {qItems.length}
          </div>
          <div className="hint">Quarantined</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--warn)' }}>
            {st.phishing_detected || 0}
          </div>
          <div className="hint">Phishing Blocked</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{st.attachments_flagged || 0}</div>
          <div className="hint">Dangerous Attachments</div>
        </div>
      </div>

      {/* Tab Bar */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '2px solid var(--border)' }}>
        {['quarantine', 'analyze', 'policies'].map((t) => (
          <button
            key={t}
            className={`btn btn-sm ${tab === t ? 'btn-primary' : ''}`}
            onClick={() => setTab(t)}
            style={{ borderRadius: '8px 8px 0 0', textTransform: 'capitalize' }}
            role="tab"
            aria-selected={tab === t}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Quarantine Tab */}
      {tab === 'quarantine' && (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div
            style={{
              padding: '12px 16px',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              justifyContent: 'space-between',
            }}
          >
            <div className="card-title">Email Quarantine</div>
            <button className="btn btn-sm" onClick={reloadQ} aria-label="Refresh quarantine">
              Refresh
            </button>
          </div>
          {loadingQ ? (
            <div className="loading" style={{ padding: 20 }}>
              Loading…
            </div>
          ) : (
            <div style={{ maxHeight: 500, overflowY: 'auto' }}>
              <table className="data-table" style={{ width: '100%' }}>
                <thead>
                  <tr>
                    <th>From</th>
                    <th>Subject</th>
                    <th>Phishing Score</th>
                    <th>Auth</th>
                    <th>Indicators</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {qItems.length === 0 ? (
                    <tr>
                      <td
                        colSpan={6}
                        style={{ textAlign: 'center', padding: 20, color: 'var(--text-secondary)' }}
                      >
                        Quarantine is empty
                      </td>
                    </tr>
                  ) : (
                    qItems.map((item, i) => (
                      <tr key={item.id || i}>
                        <td style={{ fontWeight: 600 }}>{item.from || '—'}</td>
                        <td>{item.subject || '—'}</td>
                        <td>
                          <PhishingBadge score={item.phishing_score || 0} />
                        </td>
                        <td>
                          {item.spf && (
                            <span
                              className={`badge ${item.spf === 'pass' ? 'badge-ok' : 'badge-err'}`}
                              style={{ marginRight: 3 }}
                            >
                              SPF:{item.spf}
                            </span>
                          )}
                          {item.dkim && (
                            <span
                              className={`badge ${item.dkim === 'pass' ? 'badge-ok' : 'badge-err'}`}
                            >
                              DKIM:{item.dkim}
                            </span>
                          )}
                        </td>
                        <td
                          style={{
                            maxWidth: 200,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {(item.indicators || []).join(', ') || '—'}
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: 4 }}>
                            <button
                              className="btn btn-sm"
                              onClick={() => handleRelease(item.id)}
                              aria-label={`Release email from ${item.from}`}
                            >
                              Release
                            </button>
                            <button
                              className="btn btn-sm"
                              onClick={async () => {
                                await api.emailQuarantineDelete(item.id);
                                reloadQ();
                              }}
                              aria-label={`Delete email from ${item.from}`}
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Analyze Tab */}
      {tab === 'analyze' && (
        <div className="card" style={{ padding: 16 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            Analyze Email Headers
          </div>
          <div className="hint" style={{ marginBottom: 12 }}>
            Paste email metadata as JSON to analyze for phishing indicators
          </div>
          <textarea
            className="auth-input"
            style={{ width: '100%', minHeight: 180, fontFamily: 'var(--font-mono)', fontSize: 12 }}
            placeholder='{"from": "sender@example.com", "subject": "Urgent!", "authentication_results": "spf=fail", "attachments": []}'
            value={analyzeInput}
            onChange={(e) => setAnalyzeInput(e.target.value)}
            aria-label="Email JSON input"
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button
              className="btn btn-primary"
              onClick={handleAnalyze}
              disabled={analyzing || !analyzeInput.trim()}
            >
              {analyzing ? 'Analyzing…' : 'Analyze'}
            </button>
            <button
              className="btn"
              onClick={() => {
                setAnalyzeInput('');
                setAnalyzeResult(null);
              }}
            >
              Clear
            </button>
          </div>
          {analyzeResult && !analyzeResult.error && (
            <div
              style={{
                marginTop: 16,
                border: '1px solid var(--border)',
                borderRadius: 12,
                padding: 16,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 12,
                }}
              >
                <div className="card-title">Analysis Result</div>
                <PhishingBadge score={analyzeResult.phishing_score || 0} />
              </div>
              <div
                style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 13 }}
              >
                <div>
                  <strong>SPF:</strong> {analyzeResult.auth_results?.spf || '—'}
                </div>
                <div>
                  <strong>DKIM:</strong> {analyzeResult.auth_results?.dkim || '—'}
                </div>
                <div>
                  <strong>DMARC:</strong> {analyzeResult.auth_results?.dmarc || '—'}
                </div>
                <div>
                  <strong>Sender Mismatch:</strong> {analyzeResult.sender_mismatch ? 'Yes' : 'No'}
                </div>
                <div>
                  <strong>Urgency Score:</strong> {(analyzeResult.urgency_score || 0).toFixed(2)}
                </div>
              </div>
              {analyzeResult.indicators && analyzeResult.indicators.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <strong style={{ fontSize: 13 }}>Indicators:</strong>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                    {analyzeResult.indicators.map((ind, i) => (
                      <span key={i} className="badge badge-warn">
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
          {analyzeResult?.error && (
            <div style={{ marginTop: 12, color: 'var(--err)' }}>Error: {analyzeResult.error}</div>
          )}
        </div>
      )}

      {/* Policies Tab */}
      {tab === 'policies' && (
        <div className="card" style={{ padding: 16 }}>
          <div className="card-title" style={{ marginBottom: 12 }}>
            Email Security Policies
          </div>
          {loadingPolicies ? (
            <div className="loading">Loading…</div>
          ) : policies ? (
            <div style={{ display: 'grid', gap: 12 }}>
              {(Array.isArray(policies) ? policies : [policies]).map((p, i) => (
                <div
                  key={i}
                  style={{ padding: 12, borderRadius: 8, border: '1px solid var(--border)' }}
                >
                  <div style={{ fontWeight: 700, marginBottom: 6 }}>
                    {p.name || `Policy ${i + 1}`}
                  </div>
                  <div
                    style={{
                      fontSize: 13,
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr',
                      gap: 4,
                    }}
                  >
                    <div>
                      Quarantine threshold:{' '}
                      <strong>{(p.quarantine_threshold || 0.5).toFixed(2)}</strong>
                    </div>
                    <div>
                      Block dangerous attachments:{' '}
                      <strong>{p.block_dangerous_attachments !== false ? 'Yes' : 'No'}</strong>
                    </div>
                    <div>
                      Require SPF: <strong>{p.require_spf ? 'Yes' : 'No'}</strong>
                    </div>
                    <div>
                      Require DKIM: <strong>{p.require_dkim ? 'Yes' : 'No'}</strong>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty" style={{ padding: 20 }}>
              No policies configured
            </div>
          )}
        </div>
      )}
    </div>
  );
}

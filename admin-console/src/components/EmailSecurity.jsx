import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useInterval } from '../hooks.jsx';
import * as api from '../api.js';
import { WorkspaceEmptyState } from './operator.jsx';

const EMAIL_TABS = ['quarantine', 'analyze', 'policies'];

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
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState(() => {
    const requestedTab = searchParams.get('tab');
    return EMAIL_TABS.includes(requestedTab) ? requestedTab : 'quarantine';
  });
  const [analyzeInput, setAnalyzeInput] = useState('');
  const [analyzeResult, setAnalyzeResult] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);

  const { data: quarantine, loading: loadingQ, reload: reloadQ } = useApi(api.emailQuarantine);
  const { data: stats } = useApi(api.emailStats);
  const { data: policies, loading: loadingPolicies } = useApi(api.emailPolicies);

  useInterval(reloadQ, 30000);

  const qItems = Array.isArray(quarantine) ? quarantine : quarantine?.items || [];
  const st = stats || {};
  const policyList = Array.isArray(policies) ? policies : policies ? [policies] : [];
  const emailLoading = loadingQ || loadingPolicies;
  const phishingDetected = Number(st.phishing_detected || 0);
  const attachmentsFlagged = Number(st.attachments_flagged || 0);
  const priorityTab = emailLoading
    ? 'quarantine'
    : qItems.length > 0
      ? 'quarantine'
      : policyList.length === 0
        ? 'policies'
        : 'analyze';
  const emailFocusTitle = emailLoading
    ? 'Email posture is loading'
    : qItems.length > 0
      ? 'Quarantine queue needs analyst review'
      : policyList.length === 0
        ? 'Email guardrails need policy coverage'
        : phishingDetected > 0 || attachmentsFlagged > 0
          ? 'Blocked mail campaign needs a quick confidence check'
          : 'Email defenses are steady';
  const emailFocusCopy = emailLoading
    ? 'Hold the first decision on quarantine until the current queue and policy profile finish loading, then use the focus actions to move directly into the right review lane.'
    : qItems.length > 0
      ? `${qItems.length} quarantined message${qItems.length === 1 ? ' is' : 's are'} waiting in the review lane, so the first useful action is triage and release validation before moving into policy detail.`
      : policyList.length === 0
        ? 'Policies are missing from the current view, so operators should confirm quarantine thresholds and authentication requirements before relying on mail protection posture.'
        : phishingDetected > 0 || attachmentsFlagged > 0
          ? 'The queue is clear, but recent blocked mail and flagged attachments still justify a quick header review to confirm the current filters are catching the right patterns.'
          : 'Quarantine is empty and policy coverage is present, so operators can treat this workspace as a quick health check and only drop into analysis when something changes.';
  const emailFocusRows = [
    {
      label: 'Quarantine review',
      detail: emailLoading
        ? 'Loading quarantine posture and release queue.'
        : qItems.length > 0
          ? `${qItems.length} message${qItems.length === 1 ? ' needs' : 's need'} release or delete decisions.`
          : 'No quarantined mail is waiting right now.',
      tab: 'quarantine',
      action: 'Open lane',
    },
    {
      label: 'Blocked phishing',
      detail: emailLoading
        ? 'Loading recent phishing detections.'
        : `${phishingDetected} phishing attempt${phishingDetected === 1 ? '' : 's'} blocked in the latest stats window.`,
      tab: 'analyze',
      action: 'Inspect headers',
    },
    {
      label: 'Attachment risk',
      detail: emailLoading
        ? 'Loading attachment risk signals.'
        : `${attachmentsFlagged} dangerous attachment${attachmentsFlagged === 1 ? '' : 's'} flagged for mail protection review.`,
      tab: 'analyze',
      action: 'Review payload',
    },
    {
      label: 'Policy coverage',
      detail: emailLoading
        ? 'Loading policy coverage and thresholds.'
        : policyList.length > 0
          ? `${policyList.length} active policy ${policyList.length === 1 ? 'profile' : 'profiles'} loaded in this view.`
          : 'No policy profile is loaded yet.',
      tab: 'policies',
      action: 'Review policy',
    },
  ];

  useEffect(() => {
    const requestedTab = searchParams.get('tab');
    if (EMAIL_TABS.includes(requestedTab) && requestedTab !== tab) {
      setTab(requestedTab);
      return;
    }
    if (!requestedTab && tab !== 'quarantine') {
      setTab('quarantine');
    }
  }, [searchParams, tab]);

  const openTab = (nextTab) => {
    const resolvedTab = EMAIL_TABS.includes(nextTab) ? nextTab : 'quarantine';
    setTab(resolvedTab);
    const next = new URLSearchParams(searchParams);
    if (resolvedTab === 'quarantine') next.delete('tab');
    else next.set('tab', resolvedTab);
    setSearchParams(next, { replace: true });
  };
  const displayMetric = (value) => (emailLoading ? '—' : value);

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
      <section className="email-focus-strip" aria-label="Current email focus">
        <div className="email-focus-hero">
          <div className="summary-label">Current email focus</div>
          <h3>{emailFocusTitle}</h3>
          <p>{emailFocusCopy}</p>
          <div className="btn-group email-focus-actions">
            <button className="btn btn-primary" type="button" onClick={() => openTab(priorityTab)}>
              Open Priority Lane
            </button>
            <button className="btn btn-sm" type="button" onClick={() => openTab('quarantine')}>
              Review Quarantine
            </button>
            <button className="btn btn-sm" type="button" onClick={() => openTab('policies')}>
              Review Policies
            </button>
          </div>
        </div>
        <div className="card email-focus-summary-grid summary-grid">
          <div className="summary-card">
            <div className="summary-label">Quarantine</div>
            <div className="summary-value">{displayMetric(qItems.length)}</div>
            <div className="summary-meta">
              {emailLoading ? 'loading queue' : 'messages waiting'}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Blocked phishing</div>
            <div className="summary-value">{displayMetric(phishingDetected)}</div>
            <div className="summary-meta">
              {emailLoading ? 'loading detections' : 'recent detections'}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Attachments</div>
            <div className="summary-value">{displayMetric(attachmentsFlagged)}</div>
            <div className="summary-meta">
              {emailLoading ? 'loading attachment risk' : 'flagged payloads'}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Policies</div>
            <div className="summary-value">{displayMetric(policyList.length)}</div>
            <div className="summary-meta">
              {emailLoading ? 'loading profiles' : 'profiles loaded'}
            </div>
          </div>
        </div>
      </section>

      <div className="email-focus-list">
        {emailFocusRows.map((row) => (
          <button
            key={row.label}
            type="button"
            className="email-focus-row"
            onClick={() => openTab(row.tab)}
          >
            <span className="badge badge-info">{row.label}</span>
            <span className="email-focus-row-copy">
              <strong>{row.label}</strong>
              <span>{row.detail}</span>
            </span>
            <span className="email-focus-row-action">{row.action}</span>
          </button>
        ))}
      </div>

      {/* Summary Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 12,
        }}
      >
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {emailLoading ? '—' : st.total_scanned || 0}
          </div>
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
            {emailLoading ? '—' : qItems.length}
          </div>
          <div className="hint">Quarantined</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--warn)' }}>
            {emailLoading ? '—' : st.phishing_detected || 0}
          </div>
          <div className="hint">Phishing Blocked</div>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {emailLoading ? '—' : st.attachments_flagged || 0}
          </div>
          <div className="hint">Dangerous Attachments</div>
        </div>
      </div>

      {/* Tab Bar */}
      <div
        style={{ display: 'flex', gap: 4, borderBottom: '2px solid var(--border)' }}
        role="tablist"
        aria-label="Email security sections"
      >
        {['quarantine', 'analyze', 'policies'].map((t) => (
          <button
            key={t}
            className={`btn btn-sm ${tab === t ? 'btn-primary' : ''}`}
            onClick={() => openTab(t)}
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
          ) : policyList.length > 0 ? (
            <div style={{ display: 'grid', gap: 12 }}>
              {policyList.map((p, i) => (
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
            <WorkspaceEmptyState
              title="No policies configured"
              description="Email security policies will appear here once configured."
            />
          )}
        </div>
      )}
    </div>
  );
}

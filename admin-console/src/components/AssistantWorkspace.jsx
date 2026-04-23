import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { formatDateTime, formatRelativeTime } from './operatorUtils.js';
import { buildHref } from './workflowPivots.js';

function formatCaseValue(value) {
  return String(value || '—').replaceAll('_', ' ');
}

function statusBadgeClass(mode) {
  if (mode === 'llm') return 'badge-ok';
  if (mode === 'retrieval-only') return 'badge-info';
  return 'badge-warn';
}

function formatScopeSource(value) {
  if (!value) return 'Manual';
  return String(value)
    .replaceAll('-', ' ')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function mergeAssistantParams(searchParams, updates = {}) {
  const next = new URLSearchParams(searchParams);
  Object.entries(updates).forEach(([key, value]) => {
    if (value == null || String(value).trim() === '') next.delete(key);
    else next.set(key, String(value).trim());
  });
  return next;
}

function buildSocLink({
  caseId,
  incidentId,
  investigationId,
  source,
  drawer,
  casePanel,
  incidentPanel,
  hash,
}) {
  return buildHref('/soc', {
    params: {
      case: caseId || undefined,
      incident: incidentId || undefined,
      investigation: investigationId || undefined,
      source: source || undefined,
      drawer: drawer || undefined,
      casePanel: casePanel || undefined,
      incidentPanel: incidentPanel || undefined,
    },
    hash,
  });
}

function buildQuestionPlaceholder({ selectedCase, selectedIncident, selectedInvestigation }) {
  if (selectedInvestigation) {
    return `Summarize ${selectedInvestigation.workflow_name} and cite the strongest evidence.`;
  }
  if (selectedIncident) {
    return `Explain incident #${selectedIncident.id} and recommend next actions.`;
  }
  if (selectedCase) {
    return `Summarize case #${selectedCase.id} and cite the strongest evidence.`;
  }
  return 'Explain the strongest current signals and recommend next steps.';
}

const QUICK_PROMPTS = [
  {
    label: 'Case summary',
    build: (selectedCase, selectedIncident, selectedInvestigation) => {
      if (selectedInvestigation) {
        return `Summarize ${selectedInvestigation.workflow_name} for case #${selectedCase?.id || selectedInvestigation.case_id || 'unknown'} and cite the strongest evidence.`;
      }
      if (selectedIncident) {
        return `Summarize incident #${selectedIncident.id} and explain how it affects case #${selectedCase?.id || 'unknown'}.`;
      }
      if (selectedCase) {
        return `Summarize case #${selectedCase.id} and cite the strongest evidence.`;
      }
      return 'Summarize the strongest evidence in the current investigation queue.';
    },
  },
  {
    label: 'Next steps',
    build: (selectedCase, selectedIncident, selectedInvestigation) => {
      if (selectedInvestigation) {
        return `What should the analyst do next in investigation ${selectedInvestigation.workflow_name}?`;
      }
      if (selectedIncident) {
        return `What are the recommended next steps for incident #${selectedIncident.id}?`;
      }
      if (selectedCase) {
        return `What should the analyst do next on case #${selectedCase.id}?`;
      }
      return 'What are the recommended next investigation steps based on current evidence?';
    },
  },
  {
    label: 'Escalation check',
    build: (selectedCase, selectedIncident, selectedInvestigation) => {
      if (selectedInvestigation) {
        return `Is investigation ${selectedInvestigation.workflow_name} ready for response approval or handoff?`;
      }
      if (selectedIncident) {
        return `Is incident #${selectedIncident.id} ready for escalation or response approval?`;
      }
      if (selectedCase) {
        return `Is case #${selectedCase.id} ready for escalation or ticket sync?`;
      }
      return 'Which findings are ready for escalation and why?';
    },
  },
];

export default function AssistantWorkspace() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeIncidentId = searchParams.get('incident') || '';
  const activeInvestigationId = searchParams.get('investigation') || '';
  const activeSource = searchParams.get('source') || '';
  const [caseId, setCaseId] = useState(searchParams.get('case') || '');
  const [question, setQuestion] = useState('');
  const [conversationId, setConversationId] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState(null);
  const [history, setHistory] = useState([]);
  const { data: statusData } = useApi(api.assistantStatus);
  const { data: caseList } = useApi(api.cases);
  const { data: incidentDetail } = useApi(() => api.incidentById(activeIncidentId), [activeIncidentId], {
    skip: !activeIncidentId,
  });
  const { data: investigationList } = useApi(api.investigationActive);

  const cases = Array.isArray(caseList) ? caseList : caseList?.cases || [];
  const investigations = Array.isArray(investigationList)
    ? investigationList
    : investigationList?.items || [];
  const selectedCase = cases.find((entry) => String(entry.id) === String(caseId)) || null;
  const selectedIncident = incidentDetail || null;
  const selectedInvestigation =
    investigations.find((entry) => String(entry.id) === String(activeInvestigationId)) || null;
  const mode = statusData?.mode || 'retrieval-only';

  useEffect(() => {
    setCaseId(searchParams.get('case') || '');
  }, [searchParams]);

  const updateCaseSelection = (nextCaseId) => {
    setCaseId(nextCaseId);
    setSearchParams(
      mergeAssistantParams(searchParams, {
        case: nextCaseId || undefined,
      }),
      { replace: true },
    );
  };

  const clearConversation = () => {
    setConversationId('');
    setResponse(null);
    setHistory([]);
  };

  const runAssistant = async () => {
    const trimmedQuestion = question.trim();
    if (!trimmedQuestion) {
      toast('Enter a question first', 'error');
      return;
    }

    setLoading(true);
    try {
      const payload = await api.assistantQuery({
        question: trimmedQuestion,
        case_id: caseId ? Number(caseId) : undefined,
        incident_id: activeIncidentId ? Number(activeIncidentId) : undefined,
        investigation_id: activeInvestigationId || undefined,
        source: activeSource || undefined,
        conversation_id: conversationId || undefined,
      });
      setResponse(payload);
      setConversationId(payload?.conversation_id || '');
      setHistory((current) => [
        {
          question: trimmedQuestion,
          answer: payload?.answer || '',
          caseId: caseId || '',
          incidentId: activeIncidentId || '',
          investigationId: activeInvestigationId || '',
          source: activeSource || '',
          conversationId: payload?.conversation_id || '',
          mode: payload?.mode || mode,
          createdAt: new Date().toISOString(),
        },
        ...current,
      ].slice(0, 6));
    } catch (error) {
      const bodyMessage =
        typeof error?.body === 'string' && error.body.includes('error') ? error.body : null;
      toast(bodyMessage || error.message || 'Assistant query failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  const caseContext = response?.case_context || null;
  const citations = Array.isArray(response?.citations) ? response.citations : [];
  const contextEvents = Array.isArray(response?.context_events) ? response.context_events : [];
  const warnings = Array.isArray(response?.warnings) ? response.warnings : [];
  const linkedCaseHref = caseContext?.case?.id
    ? buildSocLink({ caseId: caseContext.case.id, hash: 'cases' })
    : '/soc#cases';
  const activeCaseHref = selectedCase
    ? buildSocLink({
        caseId: selectedCase.id,
        hash: 'cases',
        drawer: 'case-workspace',
        casePanel: 'summary',
      })
    : null;
  const activeIncidentHref = activeIncidentId
    ? buildSocLink({
        caseId: caseId || undefined,
        incidentId: activeIncidentId,
        source: activeSource || undefined,
        hash: 'cases',
        drawer: 'incident-detail',
        incidentPanel: 'summary',
      })
    : null;
  const activeInvestigationHref = activeInvestigationId
    ? buildSocLink({
        caseId: caseId || undefined,
        investigationId: activeInvestigationId,
        source: activeSource || undefined,
        hash: 'investigations',
      })
    : null;

  return (
    <div className="stack">
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Analyst Assistant</div>
            <div className="hint" style={{ marginTop: 6 }}>
              Ask case-aware questions, review citations, and keep investigation context attached to
              the response.
            </div>
          </div>
          <div className="btn-group">
            <span className={`badge ${statusBadgeClass(mode)}`}>{mode}</span>
            <span className="badge badge-info">{statusData?.model || 'retrieval-only'}</span>
          </div>
        </div>
        <div
          style={{
            display: 'grid',
            gap: 16,
            gridTemplateColumns: 'minmax(280px, 1.2fr) minmax(220px, 0.8fr)',
          }}
        >
          <div>
            <label className="form-label" htmlFor="assistant-case-select">
              Case context
            </label>
            <select
              id="assistant-case-select"
              className="form-select"
              value={caseId}
              onChange={(event) => updateCaseSelection(event.target.value)}
            >
              <option value="">No case selected</option>
              {cases.map((entry) => (
                <option key={entry.id} value={String(entry.id)}>
                  {`#${entry.id} ${entry.title || 'Untitled case'}`}
                </option>
              ))}
            </select>
            <div className="hint" style={{ marginTop: 8 }}>
              The assistant keeps case, incident, and investigation scope in the URL so the same
              handoff can be reopened directly.
            </div>
          </div>
          <div>
            <div className="card-subtitle" style={{ marginBottom: 8 }}>
              Quick prompts
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {QUICK_PROMPTS.map((prompt) => (
                <button
                  key={prompt.label}
                  type="button"
                  className="btn btn-sm"
                  onClick={() =>
                    setQuestion(prompt.build(selectedCase, selectedIncident, selectedInvestigation))
                  }
                >
                  {prompt.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">Active investigation scope</span>
          <span className="badge badge-info">{formatScopeSource(activeSource)}</span>
        </div>
        {selectedCase || selectedIncident || selectedInvestigation ? (
          <div style={{ display: 'grid', gap: 12 }}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {selectedCase ? (
                <span className="badge badge-info">{`Case #${selectedCase.id}`}</span>
              ) : null}
              {selectedIncident ? (
                <span className="badge badge-info">{`Incident #${selectedIncident.id}`}</span>
              ) : null}
              {selectedInvestigation ? (
                <span className="badge badge-info">
                  {selectedInvestigation.workflow_name || selectedInvestigation.id}
                </span>
              ) : null}
            </div>
            <div className="hint">
              Keep this scope attached when the assistant is opened from a case drawer, incident
              drawer, or active investigation handoff.
            </div>
            <div className="btn-group" style={{ flexWrap: 'wrap' }}>
              {activeCaseHref ? (
                <Link className="btn btn-sm" to={activeCaseHref}>
                  Open Case Drawer
                </Link>
              ) : null}
              {activeIncidentHref ? (
                <Link className="btn btn-sm" to={activeIncidentHref}>
                  Open Incident Drawer
                </Link>
              ) : null}
              {activeInvestigationHref ? (
                <Link className="btn btn-sm" to={activeInvestigationHref}>
                  Open Investigation
                </Link>
              ) : null}
            </div>
            {selectedInvestigation ? (
              <div className="row-card">
                <div className="row-primary">{selectedInvestigation.workflow_name}</div>
                <div className="row-secondary" style={{ marginTop: 4 }}>
                  {`${formatCaseValue(selectedInvestigation.status)} • ${formatCaseValue(selectedInvestigation.analyst)} • ${selectedInvestigation.case_id ? `case ${selectedInvestigation.case_id}` : 'no linked case'}`}
                </div>
              </div>
            ) : null}
            {selectedIncident ? (
              <div className="row-card">
                <div className="row-primary">{selectedIncident.title || `Incident #${selectedIncident.id}`}</div>
                <div className="row-secondary" style={{ marginTop: 4 }}>
                  {`${formatCaseValue(selectedIncident.status)} • ${formatCaseValue(selectedIncident.severity)} • ${selectedIncident.assignee || selectedIncident.owner || 'unassigned'}`}
                </div>
              </div>
            ) : null}
          </div>
        ) : (
          <div className="empty">Open the assistant from a case, incident, or investigation to preserve investigation state.</div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">Ask a question</span>
          <div className="btn-group">
            <button type="button" className="btn btn-sm" onClick={clearConversation}>
              Clear Conversation
            </button>
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={runAssistant}
              disabled={loading}
            >
              {loading ? 'Running…' : 'Ask Assistant'}
            </button>
          </div>
        </div>
        <label className="form-label" htmlFor="assistant-question">
          Question
        </label>
        <textarea
          id="assistant-question"
          className="form-textarea"
          rows={4}
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          placeholder={buildQuestionPlaceholder({
            selectedCase,
            selectedIncident,
            selectedInvestigation,
          })}
        />
        {warnings.length > 0 && (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
            {warnings.map((warning) => (
              <span key={warning} className="badge badge-warn">
                {warning}
              </span>
            ))}
          </div>
        )}
      </div>

      <div
        style={{
          display: 'grid',
          gap: 16,
          gridTemplateColumns: 'minmax(0, 1.35fr) minmax(300px, 0.95fr)',
        }}
      >
        <div className="card">
          <div className="card-header">
            <span className="card-title">Answer</span>
            {response && (
              <span className="badge badge-info">
                Confidence {Math.round((response.confidence || 0) * 100)}%
              </span>
            )}
          </div>
          {response ? (
            <div style={{ display: 'grid', gap: 12 }}>
              <div
                style={{
                  whiteSpace: 'pre-wrap',
                  fontSize: 14,
                  lineHeight: 1.6,
                  color: 'var(--text)',
                }}
              >
                {response.answer}
              </div>
              <div className="hint">
                {response.model_used || 'retrieval-only'} • {response.response_time_ms || 0} ms •{' '}
                {response.conversation_id || 'no conversation'}
                {activeSource ? ` • source ${activeSource}` : ''}
              </div>
            </div>
          ) : (
            <div className="empty">No assistant response yet.</div>
          )}
        </div>

        <div style={{ display: 'grid', gap: 16 }}>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Context & citations</span>
              <span className="badge badge-info">{citations.length} cited</span>
            </div>
            {citations.length > 0 ? (
              <div style={{ display: 'grid', gap: 10 }}>
                {citations.map((citation) => (
                  <div key={`${citation.source_type}-${citation.source_id}`} className="row-card">
                    <div className="row-primary">{citation.summary}</div>
                    <div className="row-secondary" style={{ marginTop: 4 }}>
                      {`${citation.source_type} ${citation.source_id} • relevance ${Math.round((citation.relevance_score || 0) * 100)}%`}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty">Citations will appear here after a query runs.</div>
            )}
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Case context</span>
              {caseContext?.case?.id ? (
                <Link className="btn btn-sm" to={linkedCaseHref}>
                  Open Case in SOC
                </Link>
              ) : null}
            </div>
            {caseContext?.case ? (
              <div style={{ display: 'grid', gap: 10 }}>
                <div className="row-card">
                  <div className="row-primary">{`#${caseContext.case.id} ${caseContext.case.title}`}</div>
                  <div className="row-secondary" style={{ marginTop: 4 }}>
                    {`${formatCaseValue(caseContext.case.status)} • ${formatCaseValue(caseContext.case.priority)} • ${formatCaseValue(caseContext.case.assignee)}`}
                  </div>
                </div>
                <div className="hint">
                  {`${caseContext.linked_events?.length || 0} linked event(s) • ${caseContext.case.comments?.length || 0} comment(s)`}
                </div>
                {Array.isArray(caseContext.case.tags) && caseContext.case.tags.length > 0 && (
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {caseContext.case.tags.map((tag) => (
                      <span key={tag} className="badge badge-info">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ) : selectedCase ? (
              <div style={{ display: 'grid', gap: 8 }}>
                <div className="row-card">
                  <div className="row-primary">{`#${selectedCase.id} ${selectedCase.title}`}</div>
                  <div className="row-secondary" style={{ marginTop: 4 }}>
                    {`${formatCaseValue(selectedCase.status)} • ${formatCaseValue(selectedCase.assignee)}`}
                  </div>
                </div>
                <div className="hint">Run a query to pull linked evidence and citations for this case.</div>
              </div>
            ) : (
              <div className="empty">Select a case to attach case-aware context.</div>
            )}
          </div>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gap: 16,
          gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
        }}
      >
        <div className="card">
          <div className="card-header">
            <span className="card-title">Context window</span>
            <span className="badge badge-info">{contextEvents.length}</span>
          </div>
          {contextEvents.length > 0 ? (
            <div style={{ display: 'grid', gap: 10 }}>
              {contextEvents.map((event) => (
                <div key={`${event.event_type}-${event.id}-${event.timestamp}`} className="row-card">
                  <div className="row-primary">{event.summary}</div>
                  <div className="row-secondary" style={{ marginTop: 4 }}>
                    {`${event.event_type} ${event.id} • ${event.device || 'unknown host'} • ${formatDateTime(event.timestamp)}`}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty">Assistant context events will appear here.</div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Recent turns</span>
            <span className="badge badge-info">{history.length}</span>
          </div>
          {history.length > 0 ? (
            <div style={{ display: 'grid', gap: 10 }}>
              {history.map((entry, index) => (
                <div key={`${entry.conversationId || 'turn'}-${index}`} className="row-card">
                  <div className="row-primary">{entry.question}</div>
                  <div className="row-secondary" style={{ marginTop: 4 }}>
                    {entry.answer || 'No response'}
                  </div>
                  <div className="hint" style={{ marginTop: 6 }}>
                    {entry.caseId ? `case ${entry.caseId}` : 'no case'}
                    {entry.incidentId ? ` • incident ${entry.incidentId}` : ''}
                    {entry.investigationId ? ` • investigation ${entry.investigationId}` : ''}
                    {entry.source ? ` • ${entry.source}` : ''}
                    {' • '}
                    {entry.mode} • {formatRelativeTime(entry.createdAt || new Date().toISOString())}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty">Assistant history will appear here for this session.</div>
          )}
        </div>
      </div>
    </div>
  );
}

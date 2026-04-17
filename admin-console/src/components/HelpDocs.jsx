import { useSearchParams } from 'react-router-dom';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import {
  JsonDetails,
  RawJsonDetails,
  SummaryGrid,
  formatDateTime,
  formatRelativeTime,
} from './operator.jsx';

const GUIDES = {
  'threat-detection': {
    title: 'Detection Support',
    intro:
      'Use this support view to decide whether a rule needs tuning, suppression, validation replay, or promotion.',
    steps: [
      'Start with the noisy queue and confirm whether the rule is matching true operational pressure or just bulk background traffic.',
      'Run a test before promotion so you compare current matches against the previous baseline instead of tuning blind.',
      'Document the reason for suppressions so future analysts understand whether the exception is safe to keep.',
    ],
  },
  infrastructure: {
    title: 'Infrastructure Support',
    intro:
      'The infrastructure explorer now treats exposure, integrity, and telemetry as one operator flow centered on the selected asset.',
    steps: [
      'Confirm whether the current issue is exposure, integrity drift, or observability loss before escalating.',
      'Use the asset pane to pivot across related findings instead of reopening subsystem-specific tabs.',
      'Only drop into raw subsystem JSON after the operator summary is no longer enough for the current decision.',
    ],
  },
  'reports-exports': {
    title: 'Reporting Support',
    intro:
      'Use templates for repeatable outputs, runs for history and rerun, and delivery for light scheduling.',
    steps: [
      'Preview the report first so audience, scope, and approximate size are visible before you publish or download.',
      'Prefer rerun from history when the scope is the same so the operator trail stays readable.',
      'Use daily and weekly schedules for routine delivery instead of building one-off exports each time.',
    ],
  },
  default: {
    title: 'Operator Support',
    intro:
      'This page turns system docs and API metadata into task-oriented guidance, not just raw reference material.',
    steps: [
      'Choose the current workflow context to surface the most relevant runbook copy.',
      'Use the inbox to see durable operator work that needs follow-up across the console.',
      'Expand the API and schema sections only when you need raw technical detail.',
    ],
  },
};

export default function HelpDocs() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const context = searchParams.get('context') || 'default';
  const guide = GUIDES[context] || GUIDES.default;
  const focusObject =
    searchParams.get('rule') ||
    searchParams.get('asset') ||
    searchParams.get('incident') ||
    searchParams.get('q');
  const { data: epList } = useApi(api.endpoints);
  const { data: research } = useApi(api.researchTracks);
  const { data: openApi } = useApi(api.openapi);
  const { data: hostData } = useApi(api.hostInfo);
  const { data: statusData } = useApi(api.status);
  const { data: inboxData, reload: reloadInbox } = useApi(api.inbox);
  const { data: managerOverview } = useApi(api.managerOverview);

  const epArr = Array.isArray(epList) ? epList : epList?.endpoints || [];
  const inboxItems = Array.isArray(inboxData?.items) ? inboxData.items : [];
  const openApiSummary = openApi
    ? {
        title: openApi?.info?.title,
        version: openApi?.info?.version,
        paths: openApi?.paths ? Object.keys(openApi.paths).length : 0,
        schemas: openApi?.components?.schemas ? Object.keys(openApi.components.schemas).length : 0,
      }
    : null;

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="detail-hero">
          <div>
            <div className="detail-hero-title">{guide.title}</div>
            <div className="detail-hero-copy">{guide.intro}</div>
          </div>
          <span className="badge badge-info">{context}</span>
        </div>
        <div className="summary-grid" style={{ marginTop: 16 }}>
          <div className="summary-card">
            <div className="summary-label">System Version</div>
            <div className="summary-value">{statusData?.version || '—'}</div>
            <div className="summary-meta">{hostData?.hostname || 'Unknown host'}</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Context Scope</div>
            <div className="summary-value">{focusObject || 'Workspace-level'}</div>
            <div className="summary-meta">
              {focusObject
                ? 'Object-aware help is using the selected scope from the URL.'
                : 'Open “Help For View” from another workspace to carry its scope here.'}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Inbox Items</div>
            <div className="summary-value">
              {inboxItems.filter((item) => !item.acknowledged).length}
            </div>
            <div className="summary-meta">
              Durable operator work shared across the app shell and this support center.
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Endpoints</div>
            <div className="summary-value">{epArr.length}</div>
            <div className="summary-meta">
              Live API metadata remains available below for technical support.
            </div>
          </div>
        </div>
      </div>

      <div className="card-grid">
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Suggested Workflow
          </div>
          <div style={{ display: 'grid', gap: 10 }}>
            {guide.steps.map((step, index) => (
              <div key={step} style={{ display: 'flex', gap: 10 }}>
                <span className="badge badge-info">{index + 1}</span>
                <div style={{ fontSize: 13, lineHeight: 1.5 }}>{step}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Operator Inbox
          </div>
          {inboxItems.length === 0 ? (
            <div className="empty">No operator inbox items are active.</div>
          ) : (
            <div style={{ display: 'grid', gap: 10 }}>
              {inboxItems.map((item) => (
                <div
                  key={item.id}
                  style={{
                    border: '1px solid var(--border)',
                    borderRadius: 12,
                    padding: 12,
                    opacity: item.acknowledged ? 0.65 : 1,
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      gap: 10,
                      alignItems: 'flex-start',
                    }}
                  >
                    <div>
                      <div className="row-primary">{item.title}</div>
                      <div className="row-secondary">{item.summary}</div>
                    </div>
                    <span
                      className={`badge ${item.severity === 'high' ? 'badge-err' : 'badge-warn'}`}
                    >
                      {item.severity}
                    </span>
                  </div>
                  <div className="hint" style={{ marginTop: 8 }}>
                    {item.created_at
                      ? `${formatRelativeTime(item.created_at)} • ${formatDateTime(item.created_at)}`
                      : 'Recently created'}
                  </div>
                  {!item.acknowledged && (
                    <button
                      className="btn btn-sm"
                      style={{ marginTop: 10 }}
                      onClick={async () => {
                        try {
                          await api.ackInbox({ id: item.id });
                          toast('Inbox item acknowledged.', 'success');
                          reloadInbox();
                        } catch {
                          toast('Unable to acknowledge inbox item.', 'error');
                        }
                      }}
                    >
                      Acknowledge
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Runbook Links
          </div>
          <div style={{ display: 'grid', gap: 8 }}>
            <button
              className={`filter-chip-button ${context === 'threat-detection' ? 'active' : ''}`}
              onClick={() =>
                setSearchParams(
                  { context: 'threat-detection', rule: searchParams.get('rule') || '' },
                  { replace: true },
                )
              }
            >
              How to tune this rule
            </button>
            <button
              className={`filter-chip-button ${context === 'infrastructure' ? 'active' : ''}`}
              onClick={() =>
                setSearchParams(
                  { context: 'infrastructure', asset: searchParams.get('asset') || '' },
                  { replace: true },
                )
              }
            >
              How to investigate this asset
            </button>
            <button
              className={`filter-chip-button ${context === 'reports-exports' ? 'active' : ''}`}
              onClick={() => setSearchParams({ context: 'reports-exports' }, { replace: true })}
            >
              How to publish this report
            </button>
          </div>
          <div className="detail-callout" style={{ marginTop: 16 }}>
            <strong>What does this mean?</strong>
            <div style={{ marginTop: 6 }}>
              Severity describes urgency, lifecycle describes change readiness, and acknowledged
              inbox items stay visible so the team has a durable record of follow-up work.
            </div>
          </div>
        </div>
      </div>

      <div className="card-grid">
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Manager Context
          </div>
          <SummaryGrid data={managerOverview} limit={10} />
          <JsonDetails data={managerOverview} label="Manager overview payload" />
        </div>

        {research && (
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Research Tracks
            </div>
            <SummaryGrid data={research} limit={10} />
            <JsonDetails data={research} />
          </div>
        )}

        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            API / Schema Reference
          </div>
          <SummaryGrid data={openApiSummary} limit={6} />
          <JsonDetails data={epArr.slice(0, 12)} label="Endpoint preview" />
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <span className="card-title">API Endpoints ({epArr.length})</span>
        </div>
        {epArr.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {epArr.slice(0, 40).map((ep, index) => (
                  <tr key={`${ep.path || ep.url || index}-${index}`}>
                    <td>
                      <span className="badge badge-info">{ep.method || 'GET'}</span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                      {ep.path || ep.url || ep}
                    </td>
                    <td>{ep.description || ep.summary || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <>
            <div className="empty">Endpoint metadata is not available.</div>
            <RawJsonDetails data={epList} label="Endpoint metadata JSON" />
          </>
        )}
      </div>

      {openApi && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            OpenAPI Schema
          </div>
          <SummaryGrid data={openApiSummary} limit={6} />
          <RawJsonDetails data={openApi} label="OpenAPI JSON" />
        </div>
      )}
    </div>
  );
}

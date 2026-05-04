import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, RawJsonDetails, SummaryGrid } from './operator.jsx';
import { formatDateTime, formatRelativeTime } from './operatorUtils.js';

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
      'This page turns system docs, API metadata, and GraphQL capabilities into task-oriented guidance rather than raw reference material.',
    steps: [
      'Choose the current workflow context to surface the most relevant runbook copy and recommended follow-up work.',
      'Use the documentation center for deployment guidance and operator runbooks before dropping into raw troubleshooting payloads.',
      'Use the API and GraphQL explorers only when you need direct contract verification or a precise support payload.',
    ],
  },
};

const DOC_SECTION_OPTIONS = [
  { value: 'all', label: 'All docs' },
  { value: 'runbooks', label: 'Runbooks' },
  { value: 'deployment', label: 'Deployment' },
  { value: 'api', label: 'API & SDK' },
  { value: 'guides', label: 'Guides' },
];

const API_AUTH_FILTERS = [
  { value: 'all', label: 'All endpoints' },
  { value: 'authenticated', label: 'Authenticated' },
  { value: 'public', label: 'Public' },
];

const GRAPHQL_SAMPLES = {
  status: {
    label: 'System status',
    query: `{
  status {
    version
    uptime_secs
    agents_online
    alerts_total
  }
}`,
  },
  alerts: {
    label: 'Recent alerts',
    query: `{
  alerts(limit: 5) {
    id
    level
    summary
  }
}`,
  },
  schema: {
    label: 'Schema introspection',
    query: `{
  __schema {
    queryType { name }
    types { name }
  }
}`,
  },
};

function updateSearchParams(searchParams, setSearchParams, patch) {
  const next = new URLSearchParams(searchParams);
  Object.entries(patch).forEach(([key, value]) => {
    const trimmed = typeof value === 'string' ? value.trim() : value;
    if (trimmed == null || trimmed === '') next.delete(key);
    else next.set(key, String(trimmed));
  });
  setSearchParams(next, { replace: true });
}

function parseMarkdownBlocks(content) {
  const blocks = [];
  const lines = String(content || '').split('\n');
  let paragraph = [];
  let listItems = [];
  let listOrdered = false;
  let codeLines = [];
  let inCodeBlock = false;

  const flushParagraph = () => {
    if (paragraph.length > 0) {
      blocks.push({ type: 'paragraph', text: paragraph.join(' ') });
      paragraph = [];
    }
  };
  const flushList = () => {
    if (listItems.length > 0) {
      blocks.push({ type: 'list', ordered: listOrdered, items: listItems });
      listItems = [];
    }
  };
  const flushCode = () => {
    if (codeLines.length > 0) {
      blocks.push({ type: 'code', text: codeLines.join('\n') });
      codeLines = [];
    }
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('```')) {
      flushParagraph();
      flushList();
      if (inCodeBlock) flushCode();
      inCodeBlock = !inCodeBlock;
      continue;
    }
    if (inCodeBlock) {
      codeLines.push(line);
      continue;
    }
    if (!trimmed) {
      flushParagraph();
      flushList();
      continue;
    }
    const headingMatch = trimmed.match(/^(#{1,3})\s+(.*)$/);
    if (headingMatch) {
      flushParagraph();
      flushList();
      blocks.push({
        type: 'heading',
        level: headingMatch[1].length,
        text: headingMatch[2],
      });
      continue;
    }
    const unorderedMatch = trimmed.match(/^[-*]\s+(.*)$/);
    if (unorderedMatch) {
      flushParagraph();
      if (listItems.length > 0 && listOrdered) flushList();
      listOrdered = false;
      listItems.push(unorderedMatch[1]);
      continue;
    }
    const orderedMatch = trimmed.match(/^\d+\.\s+(.*)$/);
    if (orderedMatch) {
      flushParagraph();
      if (listItems.length > 0 && !listOrdered) flushList();
      listOrdered = true;
      listItems.push(orderedMatch[1]);
      continue;
    }
    flushList();
    paragraph.push(trimmed);
  }

  flushParagraph();
  flushList();
  flushCode();
  return blocks;
}

function MarkdownArticle({ content }) {
  const blocks = useMemo(() => parseMarkdownBlocks(content), [content]);
  if (!content) return <div className="empty">Select a document to load its content.</div>;
  return (
    <article style={{ display: 'grid', gap: 12 }}>
      {blocks.map((block, index) => {
        if (block.type === 'heading') {
          const Tag = block.level === 1 ? 'h2' : block.level === 2 ? 'h3' : 'h4';
          return (
            <Tag key={`heading-${index}`} style={{ margin: 0 }}>
              {block.text}
            </Tag>
          );
        }
        if (block.type === 'list') {
          const Tag = block.ordered ? 'ol' : 'ul';
          return (
            <Tag
              key={`list-${index}`}
              style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6 }}
            >
              {block.items.map((item) => (
                <li key={item} style={{ lineHeight: 1.5 }}>
                  {item}
                </li>
              ))}
            </Tag>
          );
        }
        if (block.type === 'code') {
          return (
            <pre
              key={`code-${index}`}
              className="json-block"
              style={{ margin: 0, whiteSpace: 'pre-wrap' }}
            >
              {block.text}
            </pre>
          );
        }
        return (
          <p key={`paragraph-${index}`} style={{ margin: 0, lineHeight: 1.6, fontSize: 14 }}>
            {block.text}
          </p>
        );
      })}
    </article>
  );
}

function FilterField({ label, children }) {
  return (
    <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
      <span style={{ fontWeight: 600 }}>{label}</span>
      {children}
    </label>
  );
}

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
  const docsQuery = searchParams.get('docs_q') || '';
  const docsSection = searchParams.get('docs_section') || 'all';
  const selectedDocPath = searchParams.get('doc') || '';
  const endpointQuery = searchParams.get('api_q') || '';
  const endpointAuthFilter = searchParams.get('api_auth') || 'all';
  const selectedGraphqlSample = searchParams.get('graphql_sample') || 'status';
  const [graphqlQuery, setGraphqlQuery] = useState(
    GRAPHQL_SAMPLES[selectedGraphqlSample]?.query || GRAPHQL_SAMPLES.status.query,
  );
  const [graphqlResponse, setGraphqlResponse] = useState(null);
  const [graphqlRunning, setGraphqlRunning] = useState(false);
  const [firstRunProof, setFirstRunProof] = useState(null);
  const [firstRunProofRunning, setFirstRunProofRunning] = useState(false);
  const [failoverDrillResult, setFailoverDrillResult] = useState(null);
  const [failoverDrillRunning, setFailoverDrillRunning] = useState(false);

  const { data: epList } = useApi(api.endpoints);
  const { data: research } = useApi(api.researchTracks);
  const { data: openApi } = useApi(api.openapi);
  const { data: hostData } = useApi(api.hostInfo);
  const { data: statusData } = useApi(api.status);
  const { data: inboxData, reload: reloadInbox } = useApi(api.inbox);
  const { data: managerOverview } = useApi(api.managerOverview);
  const { data: supportDiagnostics } = useApi(api.supportDiag);
  const { data: readinessEvidence, reload: reloadReadinessEvidence } = useApi(
    api.supportReadinessEvidence,
  );
  const { data: parityData } = useApi(api.supportParity);
  const { data: docsIndexData } = useApi(
    () => api.docsIndex({ q: docsQuery, section: docsSection, limit: 40 }),
    [docsQuery, docsSection],
  );
  const { data: docsContent } = useApi(() => api.docsContent(selectedDocPath), [selectedDocPath], {
    skip: !selectedDocPath,
  });

  const epArr = useMemo(() => (Array.isArray(epList) ? epList : epList?.endpoints || []), [epList]);
  const inboxItems = Array.isArray(inboxData?.items) ? inboxData.items : [];
  const docsEntries = useMemo(
    () => (Array.isArray(docsIndexData?.items) ? docsIndexData.items : []),
    [docsIndexData],
  );
  const parityIssues = Array.isArray(parityData?.issues) ? parityData.issues : [];
  const reportWorkflow = parityData?.report_workflow || null;
  const reportWorkflowSurfaces = [
    ['runtime_routes', 'Runtime routes'],
    ['runtime_openapi', 'Live OpenAPI'],
    ['docs_openapi', 'Docs OpenAPI'],
    ['typescript_sdk', 'TypeScript SDK'],
    ['python_sdk', 'Python SDK'],
  ].map(([key, label]) => {
    const surface = reportWorkflow?.[key] || {};
    const present = Array.isArray(surface.present) ? surface.present : [];
    const missing = Array.isArray(surface.missing) ? surface.missing : [];
    return { key, label, present, missing };
  });
  const reportWorkflowMissingCount = reportWorkflowSurfaces.reduce(
    (count, surface) => count + surface.missing.length,
    0,
  );
  const readiness = readinessEvidence?.evidence || null;
  const readinessLimitations = Array.isArray(readiness?.known_limitations)
    ? readiness.known_limitations
    : [];
  const controlPlane = readiness?.control_plane || null;
  const controlPlaneSummary = controlPlane
    ? {
        topology: controlPlane.topology,
        orchestration_scope: String(
          controlPlane.orchestration_scope || 'standalone_reference',
        ).replace(/_/g, ' '),
        ha_mode: controlPlane.ha_mode,
        cluster_role: controlPlane.cluster
          ? String(controlPlane.cluster.role || 'unknown').replace(/_/g, ' ')
          : 'Local only',
        cluster_leader:
          controlPlane.cluster?.leader_id || (controlPlane.cluster ? 'Pending' : 'Local'),
        cluster_peers: controlPlane.cluster
          ? `${controlPlane.cluster.peers_reachable || 0} / ${controlPlane.cluster.peers_total || 0}`
          : '—',
        recovery_status: controlPlane.recovery_status,
        restore_ready: controlPlane.restore_ready ? 'Ready' : 'Review',
        backup_schedule: controlPlane.backup_schedule_cron,
        observed_backups: controlPlane.observed_backups,
        checkpoint_count: controlPlane.checkpoint_count,
        recent_drills: Array.isArray(controlPlane.failover_drill_history)
          ? controlPlane.failover_drill_history.length
          : 0,
        failover_drill: String(controlPlane.failover_drill?.status || 'not_run').replace(/_/g, ' '),
        last_failover_drill: controlPlane.failover_drill?.last_run_at
          ? formatDateTime(controlPlane.failover_drill.last_run_at)
          : 'Not run',
        latest_backup_at: controlPlane.latest_backup_at
          ? formatDateTime(controlPlane.latest_backup_at)
          : '—',
        latest_checkpoint_at: controlPlane.latest_checkpoint_at
          ? formatDateTime(controlPlane.latest_checkpoint_at)
          : '—',
      }
    : null;
  const controlPlaneChecks = controlPlane
    ? [
        {
          label: 'Durable storage',
          ok: controlPlane.durable_storage,
          detail: controlPlane.durable_storage
            ? controlPlane.event_store_path || 'Persistent event storage enabled.'
            : 'Event persistence is disabled.',
        },
        {
          label: 'Restore artifacts',
          ok: controlPlane.restore_ready,
          detail: `${controlPlane.observed_backups || 0} backups / ${
            controlPlane.checkpoint_count || 0
          } checkpoints`,
        },
        {
          label: 'Failover model',
          ok: String(controlPlane.recovery_status || '').startsWith('ready_'),
          detail: String(
            controlPlane.documented_failover || controlPlane.ha_mode || 'review_recovery_plan',
          ).replace(/_/g, ' '),
        },
        ...(controlPlane.cluster
          ? [
              {
                label: 'Cluster orchestration',
                ok: Boolean(controlPlane.cluster.healthy),
                detail: `${String(controlPlane.cluster.role || 'unknown').replace(/_/g, ' ')} · ${
                  controlPlane.cluster.peers_reachable || 0
                }/${controlPlane.cluster.peers_total || 0} peers reachable${
                  controlPlane.cluster.leader_id
                    ? ` · leader ${controlPlane.cluster.leader_id}`
                    : ''
                }`,
              },
            ]
          : []),
        {
          label: 'Automated drill',
          ok: controlPlane.failover_drill?.status === 'passed',
          detail: controlPlane.failover_drill?.last_run_at
            ? `${String(controlPlane.failover_drill?.status || 'review').replace(/_/g, ' ')}${
                controlPlane.failover_drill?.actor ? ` by ${controlPlane.failover_drill.actor}` : ''
              } at ${formatDateTime(controlPlane.failover_drill.last_run_at)}`
            : controlPlane.failover_drill?.summary ||
              'No automated failover drill has been recorded yet.',
        },
      ]
    : [];
  const failoverDrillHistory = Array.isArray(controlPlane?.failover_drill_history)
    ? controlPlane.failover_drill_history.slice(0, 3)
    : [];
  const openApiSummary = openApi
    ? {
        title: openApi?.info?.title,
        version: openApi?.info?.version,
        paths: openApi?.paths ? Object.keys(openApi.paths).length : 0,
        schemas: openApi?.components?.schemas ? Object.keys(openApi.components.schemas).length : 0,
      }
    : null;

  useEffect(() => {
    setGraphqlQuery(GRAPHQL_SAMPLES[selectedGraphqlSample]?.query || GRAPHQL_SAMPLES.status.query);
  }, [selectedGraphqlSample]);

  useEffect(() => {
    if (selectedDocPath || docsEntries.length === 0) return;
    const next = new URLSearchParams(searchParams);
    next.set('doc', docsEntries[0].path);
    setSearchParams(next, { replace: true });
  }, [docsEntries, searchParams, selectedDocPath, setSearchParams]);

  const filteredEndpoints = useMemo(() => {
    const query = endpointQuery.trim().toLowerCase();
    return epArr.filter((entry) => {
      const matchesAuth =
        endpointAuthFilter === 'all'
          ? true
          : endpointAuthFilter === 'authenticated'
            ? Boolean(entry.auth)
            : !entry.auth;
      if (!matchesAuth) return false;
      if (!query) return true;
      const haystack = `${entry.method || ''} ${entry.path || entry.url || ''} ${
        entry.description || entry.summary || ''
      }`.toLowerCase();
      return haystack.includes(query);
    });
  }, [endpointAuthFilter, endpointQuery, epArr]);

  const selectedEndpoint = useMemo(() => {
    if (filteredEndpoints.length === 0) return null;
    return filteredEndpoints[0];
  }, [filteredEndpoints]);

  const selectedEndpointSpec = selectedEndpoint ? openApi?.paths?.[selectedEndpoint.path] : null;

  const runGraphqlQuery = async () => {
    setGraphqlRunning(true);
    try {
      const result = await api.graphql({ query: graphqlQuery });
      setGraphqlResponse(result);
      toast('GraphQL query completed.', 'success');
    } catch (error) {
      const message = error?.body || error?.message || 'GraphQL query failed';
      setGraphqlResponse({ errors: [{ message }] });
      toast('GraphQL query failed.', 'error');
    } finally {
      setGraphqlRunning(false);
    }
  };

  const runFirstRunProof = async () => {
    setFirstRunProofRunning(true);
    try {
      const result = await api.firstRunProof();
      setFirstRunProof(result);
      toast('First-run proof completed.', 'success');
    } catch (error) {
      const message = error?.body || error?.message || 'First-run proof failed';
      setFirstRunProof({ error: message });
      toast('First-run proof failed.', 'error');
    } finally {
      setFirstRunProofRunning(false);
    }
  };

  const runFailoverDrill = async () => {
    setFailoverDrillRunning(true);
    try {
      const result = await api.failoverDrill();
      setFailoverDrillResult(result);
      await reloadReadinessEvidence();
      if (result?.drill?.status === 'passed') {
        toast('Control-plane failover drill passed.', 'success');
      } else {
        toast('Control-plane failover drill reported recovery gaps.', 'warning');
      }
    } catch (error) {
      const message = error?.body || error?.message || 'Control-plane failover drill failed';
      setFailoverDrillResult({ error: message });
      toast('Control-plane failover drill failed.', 'error');
    } finally {
      setFailoverDrillRunning(false);
    }
  };

  const runProductionDemoLab = async () => {
    setFirstRunProofRunning(true);
    try {
      const result = await api.productionDemoLab();
      setFirstRunProof(result);
      toast('Production demo lab seeded.', 'success');
    } catch (error) {
      const message = error?.body || error?.message || 'Production demo lab failed';
      setFirstRunProof({ error: message });
      toast('Production demo lab failed.', 'error');
    } finally {
      setFirstRunProofRunning(false);
    }
  };

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
            <div className="summary-label">Docs Version</div>
            <div className="summary-value">
              {docsIndexData?.version || statusData?.version || '—'}
            </div>
            <div className="summary-meta">
              Embedded docs and runbooks currently indexed for this build.
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Context Scope</div>
            <div className="summary-value">{focusObject || 'Workspace-level'}</div>
            <div className="summary-meta">
              {focusObject
                ? 'Context-aware help is using the selected scope from the URL.'
                : 'Open “Help For View” from another workspace to carry its scope here.'}
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Parity Issues</div>
            <div className="summary-value">{parityIssues.length}</div>
            <div className="summary-meta">
              OpenAPI, GraphQL, and generated SDK drift is summarized below.
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-label">Readiness</div>
            <div className="summary-value">{readiness?.status || '—'}</div>
            <div className="summary-meta">
              {readinessEvidence?.digest
                ? `Evidence digest ${String(readinessEvidence.digest).slice(0, 12)}`
                : 'Production evidence pack is loading.'}
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <div>
            <span className="card-title">Documentation Center</span>
            <div className="hint" style={{ marginTop: 4 }}>
              Search embedded runbooks, deployment guides, and SDK references for the current
              operator context before dropping into lower-level diagnostics.
            </div>
          </div>
          <span className="badge badge-info">
            {docsIndexData?.version || statusData?.version || '—'}
          </span>
        </div>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(260px, 320px) minmax(0, 1fr)',
            gap: 16,
            alignItems: 'start',
          }}
        >
          <div style={{ display: 'grid', gap: 12 }}>
            <FilterField label="Search docs">
              <input
                aria-label="Search docs"
                value={docsQuery}
                onChange={(event) =>
                  updateSearchParams(searchParams, setSearchParams, {
                    docs_q: event.target.value,
                  })
                }
                placeholder="deployment, sdk, runbook..."
                style={{
                  width: '100%',
                  padding: '8px 10px',
                  borderRadius: 10,
                  border: '1px solid var(--border)',
                  background: 'var(--bg)',
                  color: 'var(--text)',
                }}
              />
            </FilterField>
            <FilterField label="Docs section">
              <select
                aria-label="Docs section"
                value={docsSection}
                onChange={(event) =>
                  updateSearchParams(searchParams, setSearchParams, {
                    docs_section: event.target.value,
                    doc: '',
                  })
                }
                style={{
                  width: '100%',
                  padding: '8px 10px',
                  borderRadius: 10,
                  border: '1px solid var(--border)',
                  background: 'var(--bg)',
                  color: 'var(--text)',
                }}
              >
                {DOC_SECTION_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </FilterField>
            <div className="hint">
              {docsIndexData?.total ?? docsEntries.length} document
              {(docsIndexData?.total ?? docsEntries.length) === 1 ? '' : 's'} indexed for this
              build.
            </div>
            {docsEntries.length === 0 ? (
              <div className="empty">No documents match the current search.</div>
            ) : (
              <div style={{ display: 'grid', gap: 10, maxHeight: 560, overflowY: 'auto' }}>
                {docsEntries.map((entry) => {
                  const active = entry.path === selectedDocPath;
                  return (
                    <button
                      key={entry.path}
                      type="button"
                      onClick={() =>
                        updateSearchParams(searchParams, setSearchParams, { doc: entry.path })
                      }
                      style={{
                        textAlign: 'left',
                        border: active ? '1px solid var(--accent)' : '1px solid var(--border)',
                        borderRadius: 12,
                        padding: 12,
                        background: active
                          ? 'var(--bg-soft, rgba(53, 119, 255, 0.08))'
                          : 'var(--card)',
                        color: 'var(--text)',
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                        <div className="row-primary">{entry.title}</div>
                        <span className="badge badge-info">{entry.kind}</span>
                      </div>
                      <div className="row-secondary" style={{ marginTop: 6 }}>
                        {entry.summary || entry.path}
                      </div>
                      <div className="chip-row" style={{ marginTop: 8 }}>
                        {Array.isArray(entry.tags)
                          ? entry.tags.slice(0, 3).map((tag) => (
                              <span key={`${entry.path}-${tag}`} className="badge badge-info">
                                {tag}
                              </span>
                            ))
                          : null}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          <div className="card" style={{ padding: 14, minHeight: 320 }}>
            <div className="detail-hero" style={{ marginBottom: 16 }}>
              <div>
                <div className="detail-hero-title">{docsContent?.title || 'Select a document'}</div>
                <div className="detail-hero-copy">
                  {docsContent?.summary ||
                    'Choose a guide or runbook from the list to load it here.'}
                </div>
              </div>
              {docsContent?.section && (
                <span className="badge badge-info">{docsContent.section}</span>
              )}
            </div>
            {docsContent?.tags?.length > 0 && (
              <div className="chip-row" style={{ marginBottom: 12 }}>
                {docsContent.tags.map((tag) => (
                  <span key={`${docsContent.path}-${tag}`} className="badge badge-info">
                    {tag}
                  </span>
                ))}
              </div>
            )}
            {docsContent?.headings?.length > 0 && (
              <div className="hint" style={{ marginBottom: 12 }}>
                {docsContent.headings.slice(0, 4).join(' • ')}
              </div>
            )}
            <MarkdownArticle content={docsContent?.content} />
            <JsonDetails data={docsContent} label="Document metadata" />
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
                updateSearchParams(searchParams, setSearchParams, {
                  context: 'threat-detection',
                  rule: searchParams.get('rule') || '',
                  docs_section: 'runbooks',
                  doc: 'runbooks/troubleshooting.md',
                })
              }
            >
              Open troubleshooting runbook
            </button>
            <button
              className={`filter-chip-button ${context === 'infrastructure' ? 'active' : ''}`}
              onClick={() =>
                updateSearchParams(searchParams, setSearchParams, {
                  context: 'infrastructure',
                  asset: searchParams.get('asset') || '',
                  docs_section: 'deployment',
                  doc: 'runbooks/deployment.md',
                })
              }
            >
              Open deployment guidance
            </button>
            <button
              className={`filter-chip-button ${context === 'reports-exports' ? 'active' : ''}`}
              onClick={() =>
                updateSearchParams(searchParams, setSearchParams, {
                  context: 'reports-exports',
                  docs_section: 'api',
                  doc: 'SDK_GUIDE.md',
                })
              }
            >
              Open SDK guide
            </button>
          </div>
          <div className="detail-callout" style={{ marginTop: 16 }}>
            <strong>What changed?</strong>
            <div style={{ marginTop: 6 }}>
              This support center now links embedded runbooks, deployment guidance, API parity, and
              GraphQL verification into one routed operator surface.
            </div>
          </div>
        </div>
      </div>

      <div className="card-grid" style={{ marginTop: 16 }}>
        <div className="card">
          <div className="card-header" style={{ marginBottom: 12 }}>
            <div className="card-title">Production Readiness</div>
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={runFirstRunProof}
              disabled={firstRunProofRunning}
            >
              {firstRunProofRunning ? 'Running...' : 'Run Proof'}
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={runFailoverDrill}
              disabled={failoverDrillRunning}
            >
              {failoverDrillRunning ? 'Running drill...' : 'Run Failover Drill'}
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={runProductionDemoLab}
              disabled={firstRunProofRunning}
            >
              Demo Lab
            </button>
          </div>
          <SummaryGrid
            data={{
              status: readiness?.status,
              runtime: readiness?.version?.runtime,
              enabled_collectors: readiness?.collectors?.enabled,
              audit_chain: readiness?.audit_chain?.status,
              contract_status: readiness?.contracts?.status,
              response_history: readiness?.response_history?.closed_or_reopenable,
              report_artifacts: readiness?.evidence?.reports_with_artifact_metadata,
              observed_backups: readiness?.backup?.observed_backups,
            }}
            limit={8}
          />
          {readinessLimitations.length === 0 ? (
            <div className="empty">No readiness blockers are currently reported.</div>
          ) : (
            <div style={{ display: 'grid', gap: 8, marginTop: 12 }}>
              {readinessLimitations.map((item) => (
                <div key={item} className="stat-box" style={{ fontSize: 12 }}>
                  <span className="badge badge-warn" style={{ marginRight: 8 }}>
                    Review
                  </span>
                  {item}
                </div>
              ))}
            </div>
          )}
          {controlPlaneSummary ? (
            <>
              <div className="card-title" style={{ marginTop: 16, marginBottom: 12 }}>
                Control-plane posture
              </div>
              <SummaryGrid data={controlPlaneSummary} limit={15} />
              {controlPlaneChecks.length > 0 ? (
                <div style={{ display: 'grid', gap: 8, marginTop: 12 }}>
                  {controlPlaneChecks.map((item) => (
                    <div key={item.label} className="stat-box" style={{ fontSize: 12 }}>
                      <span
                        className={`badge ${item.ok ? 'badge-ok' : 'badge-warn'}`}
                        style={{ marginRight: 8 }}
                      >
                        {item.ok ? 'Ready' : 'Review'}
                      </span>
                      <strong>{item.label}</strong>
                      <span style={{ marginLeft: 8 }}>{item.detail}</span>
                    </div>
                  ))}
                </div>
              ) : null}
              {failoverDrillHistory.length > 0 ? (
                <>
                  <div className="card-title" style={{ marginTop: 16, marginBottom: 12 }}>
                    Recent drill history
                  </div>
                  <div style={{ display: 'grid', gap: 8 }}>
                    {failoverDrillHistory.map((drill, index) => (
                      <div
                        key={`${drill.last_run_at || 'not-run'}-${index}`}
                        className="stat-box"
                        style={{ fontSize: 12 }}
                      >
                        <span
                          className={`badge ${
                            drill.status === 'passed' ? 'badge-ok' : 'badge-warn'
                          }`}
                          style={{ marginRight: 8 }}
                        >
                          {String(drill.status || 'review').replace(/_/g, ' ')}
                        </span>
                        <strong>
                          {String(drill.drill_type || 'failover_drill').replace(/_/g, ' ')}
                        </strong>
                        <span style={{ marginLeft: 8 }}>
                          {String(drill.orchestration_scope || 'standalone_reference').replace(
                            /_/g,
                            ' ',
                          )}
                          {drill.actor ? ` · ${drill.actor}` : ''}
                          {drill.last_run_at ? ` · ${formatDateTime(drill.last_run_at)}` : ''}
                        </span>
                      </div>
                    ))}
                  </div>
                </>
              ) : null}
            </>
          ) : null}
          {firstRunProof ? (
            <JsonDetails data={firstRunProof} label="First-run proof result" />
          ) : null}
          {failoverDrillResult ? (
            <JsonDetails data={failoverDrillResult} label="Automated failover drill result" />
          ) : null}
          <JsonDetails data={readinessEvidence} label="Production readiness evidence pack" />
        </div>

        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Support Snapshot
          </div>
          <SummaryGrid data={supportDiagnostics?.bundle?.operations} limit={8} />
          <JsonDetails data={supportDiagnostics} label="Support diagnostics bundle" />
        </div>

        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Contract Parity
          </div>
          <SummaryGrid
            data={{
              runtime_version: parityData?.runtime?.version,
              openapi_version: parityData?.rest?.openapi_version,
              openapi_paths: parityData?.rest?.openapi_path_count,
              endpoint_catalog: parityData?.rest?.endpoint_catalog_count,
              graphql_types: parityData?.graphql?.types,
              graphql_root_fields: Array.isArray(parityData?.graphql?.root_fields)
                ? parityData.graphql.root_fields.length
                : 0,
              python_sdk: parityData?.sdk?.python?.version,
              typescript_sdk: parityData?.sdk?.typescript?.version,
            }}
            limit={8}
          />
          {parityIssues.length === 0 ? (
            <div className="empty">REST, GraphQL, and generated SDK versions are aligned.</div>
          ) : (
            <div style={{ display: 'grid', gap: 8, marginTop: 12 }}>
              {parityIssues.map((issue) => (
                <div key={issue} className="stat-box" style={{ fontSize: 12 }}>
                  <span className="badge badge-warn" style={{ marginRight: 8 }}>
                    Review
                  </span>
                  {issue}
                </div>
              ))}
            </div>
          )}
          {reportWorkflow ? (
            <div style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>
                Report Workflow Coverage
              </div>
              <SummaryGrid
                data={{
                  alignment: reportWorkflow.aligned ? 'Aligned' : 'Review',
                  required_operations: Array.isArray(reportWorkflow.required_operations)
                    ? reportWorkflow.required_operations.length
                    : 0,
                  sdk_endpoints: Array.isArray(reportWorkflow.required_sdk_endpoints)
                    ? reportWorkflow.required_sdk_endpoints.length
                    : 0,
                  missing_checks: reportWorkflowMissingCount,
                }}
                limit={4}
              />
              <div style={{ display: 'grid', gap: 8, marginTop: 12 }}>
                {reportWorkflowSurfaces.map((surface) => (
                  <div key={surface.key} className="stat-box" style={{ fontSize: 12 }}>
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: 8,
                        flexWrap: 'wrap',
                      }}
                    >
                      <strong>{surface.label}</strong>
                      <span
                        className={`badge ${surface.missing.length === 0 ? 'badge-ok' : 'badge-warn'}`}
                      >
                        {surface.missing.length === 0
                          ? `Aligned (${surface.present.length})`
                          : `${surface.missing.length} missing`}
                      </span>
                    </div>
                    <div className="row-secondary" style={{ marginTop: 6 }}>
                      {surface.missing.length === 0
                        ? `${surface.present.length} checks covered for this surface.`
                        : `Missing: ${surface.missing.join(', ')}`}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          <JsonDetails data={parityData} label="Parity payload" />
        </div>
      </div>

      <div className="card-grid" style={{ marginTop: 16 }}>
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            GraphQL Explorer
          </div>
          <div style={{ display: 'grid', gap: 12 }}>
            <FilterField label="GraphQL sample">
              <select
                aria-label="GraphQL sample"
                value={selectedGraphqlSample}
                onChange={(event) =>
                  updateSearchParams(searchParams, setSearchParams, {
                    graphql_sample: event.target.value,
                  })
                }
                style={{
                  width: '100%',
                  padding: '8px 10px',
                  borderRadius: 10,
                  border: '1px solid var(--border)',
                  background: 'var(--bg)',
                  color: 'var(--text)',
                }}
              >
                {Object.entries(GRAPHQL_SAMPLES).map(([key, sample]) => (
                  <option key={key} value={key}>
                    {sample.label}
                  </option>
                ))}
              </select>
            </FilterField>
            <FilterField label="GraphQL query">
              <textarea
                aria-label="GraphQL query"
                value={graphqlQuery}
                onChange={(event) => setGraphqlQuery(event.target.value)}
                rows={12}
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  borderRadius: 12,
                  border: '1px solid var(--border)',
                  background: 'var(--bg)',
                  color: 'var(--text)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 12,
                }}
              />
            </FilterField>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button
                className="btn btn-primary"
                type="button"
                disabled={graphqlRunning}
                onClick={runGraphqlQuery}
              >
                {graphqlRunning ? 'Running…' : 'Run Query'}
              </button>
            </div>
            {graphqlResponse ? (
              <>
                <SummaryGrid
                  data={{
                    data_keys: graphqlResponse.data ? Object.keys(graphqlResponse.data).length : 0,
                    error_count: Array.isArray(graphqlResponse.errors)
                      ? graphqlResponse.errors.length
                      : 0,
                  }}
                  limit={4}
                />
                <RawJsonDetails data={graphqlResponse} label="GraphQL response" />
              </>
            ) : (
              <div className="empty">Run a GraphQL query to inspect the live support surface.</div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            API Contract & Explorer
          </div>
          <div style={{ display: 'grid', gap: 12 }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: 10,
              }}
            >
              <FilterField label="Filter endpoints">
                <input
                  aria-label="Filter endpoints"
                  value={endpointQuery}
                  onChange={(event) =>
                    updateSearchParams(searchParams, setSearchParams, {
                      api_q: event.target.value,
                    })
                  }
                  placeholder="/api/support or graphql"
                  style={{
                    width: '100%',
                    padding: '8px 10px',
                    borderRadius: 10,
                    border: '1px solid var(--border)',
                    background: 'var(--bg)',
                    color: 'var(--text)',
                  }}
                />
              </FilterField>
              <FilterField label="Endpoint auth">
                <select
                  aria-label="Endpoint auth"
                  value={endpointAuthFilter}
                  onChange={(event) =>
                    updateSearchParams(searchParams, setSearchParams, {
                      api_auth: event.target.value,
                    })
                  }
                  style={{
                    width: '100%',
                    padding: '8px 10px',
                    borderRadius: 10,
                    border: '1px solid var(--border)',
                    background: 'var(--bg)',
                    color: 'var(--text)',
                  }}
                >
                  {API_AUTH_FILTERS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </FilterField>
            </div>
            <SummaryGrid
              data={{
                visible_endpoints: filteredEndpoints.length,
                total_endpoints: epArr.length,
                openapi_paths: openApiSummary?.paths,
                schemas: openApiSummary?.schemas,
              }}
              limit={4}
            />
            {selectedEndpoint ? (
              <div className="stat-box">
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                  <span className="badge badge-info">{selectedEndpoint.method || 'GET'}</span>
                  <strong style={{ fontFamily: 'var(--font-mono)' }}>
                    {selectedEndpoint.path}
                  </strong>
                  <span className={`badge ${selectedEndpoint.auth ? 'badge-warn' : 'badge-ok'}`}>
                    {selectedEndpoint.auth ? 'Auth required' : 'Public'}
                  </span>
                </div>
                <div className="row-secondary" style={{ marginTop: 6 }}>
                  {selectedEndpoint.description || 'No summary available.'}
                </div>
                <JsonDetails
                  data={{
                    endpoint: selectedEndpoint,
                    openapi_path: selectedEndpointSpec,
                  }}
                  label="Selected endpoint detail"
                />
              </div>
            ) : (
              <div className="empty">No endpoints match the current filter.</div>
            )}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16, marginBottom: 16 }}>
        <div className="card-header">
          <span className="card-title">API Endpoints ({filteredEndpoints.length})</span>
        </div>
        {filteredEndpoints.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Auth</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {filteredEndpoints.slice(0, 40).map((ep, index) => (
                  <tr key={`${ep.path || ep.url || index}-${index}`}>
                    <td>
                      <span className="badge badge-info">{ep.method || 'GET'}</span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                      {ep.path || ep.url || ep}
                    </td>
                    <td>
                      <span className={`badge ${ep.auth ? 'badge-warn' : 'badge-ok'}`}>
                        {ep.auth ? 'Authenticated' : 'Public'}
                      </span>
                    </td>
                    <td>{ep.description || ep.summary || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty">Endpoint metadata is not available.</div>
        )}
        <RawJsonDetails data={openApi} label="OpenAPI JSON" />
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
      </div>
    </div>
  );
}

import { Link, useSearchParams } from 'react-router-dom';
import { useCallback, useMemo, useState } from 'react';
import { useApiGroup } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid, WorkspaceEmptyState } from './operator.jsx';
import { buildHref } from './workflowPivots.js';
import CommandActionDrawers from './command/CommandActionDrawers.jsx';
import RuleTuningChecklist from './command/RuleTuningChecklist.jsx';
import {
  CONNECTOR_LANES,
  IMPROVEMENT_LANES,
  asArray,
  compactTimestamp,
  connectorStatusFromReadiness,
  formatCount,
  normalizedStatus,
  riskBadge,
  statusBadge,
} from './command/helpers.js';
import { CommandSection, MetricCard, WorkItem } from './command/primitives.jsx';

const VALID_DRAWER_TYPES = ['remediation', 'connectors', 'rules', 'release', 'evidence'];

export default function CommandCenter() {
  const [searchParams, setSearchParams] = useSearchParams();
  const drawerParam = searchParams.get('drawer');
  const [drawerItem, setDrawerItem] = useState(null);
  const drawer = VALID_DRAWER_TYPES.includes(drawerParam)
    ? { type: drawerParam, item: drawerItem }
    : null;
  const { data, loading, errors, reload } = useApiGroup({
    commandSummary: api.commandSummary,
    incidentsData: api.incidents,
    casesData: api.cases,
    queueStats: api.queueStats,
    responseStats: api.responseStats,
    remediationReviews: api.remediationChangeReviews,
    efficacySummary: api.efficacySummary,
    contentRulesData: api.contentRules,
    suppressionsData: api.suppressions,
    updatesData: api.updatesReleases,
    sbomData: api.sbom,
    configData: api.configCurrent,
    assistantStatus: api.assistantStatus,
    rbacUsersData: api.rbacUsers,
    complianceData: api.complianceStatus,
    reportTemplatesData: api.reportTemplates,
  });

  const incidents = useMemo(() => asArray(data.incidentsData, ['incidents', 'items']), [data]);
  const cases = useMemo(() => asArray(data.casesData, ['cases', 'items']), [data]);
  const reviews = useMemo(
    () => asArray(data.remediationReviews, ['reviews', 'items', 'change_reviews']),
    [data],
  );
  const rules = useMemo(() => asArray(data.contentRulesData, ['rules', 'items']), [data]);
  const suppressions = useMemo(
    () => asArray(data.suppressionsData, ['suppressions', 'items']),
    [data],
  );
  const releases = useMemo(() => asArray(data.updatesData, ['releases', 'items']), [data]);
  const users = useMemo(() => asArray(data.rbacUsersData, ['users', 'items']), [data]);
  const reportTemplates = useMemo(
    () => asArray(data.reportTemplatesData, ['templates', 'items']),
    [data],
  );

  const suppressionCount = useMemo(
    () =>
      suppressions.reduce((accumulator, suppression) => {
        const ruleId = suppression.rule_id || suppression.ruleId || suppression.rule;
        if (ruleId) accumulator[ruleId] = (accumulator[ruleId] || 0) + 1;
        return accumulator;
      }, {}),
    [suppressions],
  );

  const noisyRules = useMemo(
    () =>
      rules.filter(
        (rule) =>
          (Number(rule.last_test_match_count || rule.match_count || 0) >= 5 ||
            (suppressionCount[rule.id] || 0) > 0) &&
          rule.enabled !== false,
      ),
    [rules, suppressionCount],
  );

  const staleRules = useMemo(
    () =>
      rules.filter(
        (rule) =>
          !rule.last_test_at &&
          !rule.last_promotion_at &&
          normalizedStatus(rule.lifecycle || 'draft') !== 'active',
      ),
    [rules],
  );

  const pendingReviews = reviews.filter((review) =>
    ['pending_review', 'pending', 'requested'].includes(normalizedStatus(review.approval_status)),
  );
  const approvedReviews = reviews.filter(
    (review) => normalizedStatus(review.approval_status) === 'approved',
  );
  const readyRollbacks = reviews.filter((review) => Boolean(review.rollback_proof));
  const activeIncidents = incidents.filter(
    (incident) => !['closed', 'resolved', 'contained'].includes(normalizedStatus(incident.status)),
  );
  const activeCases = cases.filter(
    (caseEntry) => !['closed', 'resolved'].includes(normalizedStatus(caseEntry.status)),
  );
  const connectorReadiness = useMemo(
    () =>
      asArray(data.commandSummary?.lanes?.connectors?.readiness, ['collectors']).reduce(
        (accumulator, item) => {
          const provider = String(item?.provider || '').trim();
          if (provider) accumulator[provider] = item;
          return accumulator;
        },
        {},
      ),
    [data.commandSummary],
  );
  const connectorRows = CONNECTOR_LANES.map((connector) => ({
    ...connector,
    ...connectorStatusFromReadiness(connector, connectorReadiness[connector.provider]),
  }));
  const connectorIssues = connectorRows.filter(
    (connector) =>
      !['ok', 'ready', 'healthy', 'connected'].includes(normalizedStatus(connector.status)),
  );
  const activeRelease =
    releases[0] || data.updatesData?.current || data.updatesData?.latest || null;
  const complianceStatus =
    data.complianceData?.status ||
    data.complianceData?.overall_status ||
    data.complianceData?.state ||
    'unknown';
  const assistantMode = data.assistantStatus?.mode || 'retrieval-only';
  const assistantGuardrailTone = assistantMode === 'retrieval-only' ? 'badge-info' : 'badge-warn';
  const evidenceBoundaryWarnings = [
    'Require citations for every assistant recommendation.',
    'Label uncertainty before response or executive export.',
    'Keep prompts scoped to incident, case, investigation, or selected evidence.',
  ];
  const failedRequests = Object.keys(errors || {}).length;
  const summaryMetrics = data.commandSummary?.metrics || {};
  const commandMetrics = {
    incidents: summaryMetrics.open_incidents ?? activeIncidents.length,
    cases: summaryMetrics.active_cases ?? activeCases.length,
    pendingReviews: summaryMetrics.pending_remediation_reviews ?? pendingReviews.length,
    connectorIssues: summaryMetrics.connector_issues ?? connectorIssues.length,
    noisyRules: summaryMetrics.noisy_rules ?? noisyRules.length,
    staleRules: summaryMetrics.stale_rules ?? staleRules.length,
    releaseCandidates: summaryMetrics.release_candidates ?? releases.length,
    compliancePacks: summaryMetrics.compliance_packs ?? reportTemplates.length,
  };
  const laneSummaries = data.commandSummary?.lanes || {};

  const renderLaneAnnotation = (laneKey, fallbackAnnotation, fallbackNextStep) => {
    const lane = laneSummaries?.[laneKey] || {};
    return (
      <WorkItem
        key={`annotation-${laneKey}`}
        title={lane.annotation || fallbackAnnotation}
        detail={lane.next_step || fallbackNextStep}
        badge="lane note"
        tone={statusBadge(lane.status || 'info')}
      />
    );
  };

  const openDrawer = useCallback(
    (type, item = null) => {
      if (!VALID_DRAWER_TYPES.includes(type)) return;
      setDrawerItem(item);
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.set('drawer', type);
          return next;
        },
        { replace: false },
      );
    },
    [setSearchParams, setDrawerItem],
  );
  const closeDrawer = useCallback(() => {
    setDrawerItem(null);
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete('drawer');
        return next;
      },
      { replace: false },
    );
  }, [setSearchParams, setDrawerItem]);

  return (
    <div className="workspace command-center-workspace">
      <div className="workspace-header command-hero">
        <div>
          <div className="eyebrow">Product Command Center</div>
          <h2>Operate incidents, connectors, quality, releases, and evidence from one place</h2>
          <p>
            This workspace now connects high-signal command summaries with action drawers, so
            analysts can validate, approve, replay, and export without losing context.
          </p>
          <div className="chip-row">
            {IMPROVEMENT_LANES.map((lane) => (
              <span key={lane} className="badge badge-info">
                {lane}
              </span>
            ))}
          </div>
        </div>
        <div className="actions">
          <button className="btn" type="button" onClick={reload} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh Center'}
          </button>
          <Link className="btn" to="/help?doc=runbooks/command-center.md">
            Runbook
          </Link>
          <Link className="btn btn-primary" to="/soc">
            Open SOC
          </Link>
        </div>
      </div>

      {failedRequests > 0 && (
        <div className="alert-banner warning">
          {failedRequests} supporting API request{failedRequests === 1 ? '' : 's'} failed. The
          command center is still showing available lanes so operators can continue triage.
        </div>
      )}

      <div className="summary-grid command-summary-grid">
        <MetricCard
          label="Open incidents"
          value={formatCount(commandMetrics.incidents)}
          detail={`${formatCount(commandMetrics.cases)} active cases`}
          tone={commandMetrics.incidents > 0 ? 'badge-warn' : 'badge-ok'}
          to="/soc"
        />
        <MetricCard
          label="Pending approvals"
          value={formatCount(commandMetrics.pendingReviews)}
          detail={`${formatCount(readyRollbacks.length)} rollback proofs ready`}
          tone={commandMetrics.pendingReviews > 0 ? 'badge-warn' : 'badge-ok'}
          onClick={() => openDrawer('remediation')}
        />
        <MetricCard
          label="Connector gaps"
          value={formatCount(commandMetrics.connectorIssues)}
          detail="Cloud, SaaS, identity, EDR, and syslog lanes"
          tone={commandMetrics.connectorIssues > 0 ? 'badge-warn' : 'badge-ok'}
          onClick={() => openDrawer('connectors')}
        />
        <MetricCard
          label="Noisy rules"
          value={formatCount(commandMetrics.noisyRules)}
          detail={`${formatCount(commandMetrics.staleRules)} rules need validation`}
          tone={commandMetrics.noisyRules > 0 ? 'badge-warn' : 'badge-ok'}
          onClick={() => openDrawer('rules')}
        />
        <MetricCard
          label="Release candidates"
          value={formatCount(commandMetrics.releaseCandidates)}
          detail={activeRelease?.version || activeRelease?.tag || 'No release metadata loaded'}
          tone={activeRelease ? 'badge-info' : 'badge-warn'}
          onClick={() => openDrawer('release')}
        />
        <MetricCard
          label="Compliance packs"
          value={formatCount(commandMetrics.compliancePacks)}
          detail={`Compliance status: ${complianceStatus}`}
          tone={statusBadge(complianceStatus)}
          onClick={() => openDrawer('evidence')}
        />
      </div>

      <CommandActionDrawers
        drawer={drawer}
        connectorRows={connectorRows}
        reviews={reviews}
        rules={rules}
        releases={releases}
        reportTemplates={reportTemplates}
        suppressionCount={suppressionCount}
        data={data}
        onClose={closeDrawer}
        onReload={reload}
      />

      <div className="grid-2">
        <CommandSection
          eyebrow="Incident Command Center"
          title="Resolve incidents without losing context"
          description="Open cases, current incidents, response pressure, and evidence-export paths stay visible together."
          actions={
            <Link className="btn btn-sm" to="/soc">
              Open investigation workspace
            </Link>
          }
        >
          {renderLaneAnnotation(
            'incidents',
            'Keep the incident lane staffed before you fan out to release or remediation work.',
            'Use the SOC workspace to verify ownership, pressure, and export readiness.',
          )}
          {activeIncidents.length > 0 ? (
            activeIncidents
              .slice(0, 4)
              .map((incident) => (
                <WorkItem
                  key={incident.id || incident.title}
                  title={incident.title || incident.name || `Incident ${incident.id}`}
                  detail={`${incident.status || 'open'} - ${incident.severity || incident.priority || 'unscored'} - ${compactTimestamp(incident.updated_at || incident.created_at)}`}
                  badge={incident.severity || incident.priority || 'open'}
                  tone={riskBadge(incident.severity || incident.priority)}
                  to={buildHref('/soc', { params: { incident: incident.id || undefined } })}
                />
              ))
          ) : (
            <WorkspaceEmptyState
              compact
              title="No active incidents loaded"
              description="Live incident, case, rollback, and report context will appear here as soon as data is available."
            />
          )}
          <SummaryGrid
            data={{ queue: data.queueStats || {}, response: data.responseStats || {} }}
            limit={4}
          />
        </CommandSection>

        <CommandSection
          eyebrow="Connector Onboarding Wizard"
          title="Guide every collector from setup to proof"
          description="Each lane needs saved config, connection validation, sample event preview, and recent data proof."
          actions={
            <button className="btn btn-sm" type="button" onClick={() => openDrawer('connectors')}>
              Validate connectors
            </button>
          }
        >
          {renderLaneAnnotation(
            'connectors',
            'Every shipped connector should expose saved config, validation, and proof-of-life context.',
            'Validate credentials and ingestion proof before downstream workflows depend on the lane.',
          )}
          <div className="table-wrap">
            <table className="data-table compact-table">
              <thead>
                <tr>
                  <th>Connector</th>
                  <th>Lane</th>
                  <th>Status</th>
                  <th>Sample</th>
                </tr>
              </thead>
              <tbody>
                {connectorRows.map((connector) => (
                  <tr key={connector.id}>
                    <td>
                      <button
                        className="btn-link command-inline-action"
                        type="button"
                        onClick={() => openDrawer('connectors', connector)}
                      >
                        {connector.label}
                      </button>
                    </td>
                    <td>{connector.category}</td>
                    <td>
                      <span className={`badge ${statusBadge(connector.status)}`}>
                        {connector.status}
                      </span>
                      <div className="hint">{connector.detail}</div>
                    </td>
                    <td>{connector.sample}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <JsonDetails
            data={data.commandSummary?.lanes?.connectors?.readiness || { collectors: [] }}
            label="Readiness evidence"
          />
        </CommandSection>

        <CommandSection
          eyebrow="Detection Quality Dashboard"
          title="Track noisy, stale, and suppression-heavy detections"
          description="Precision, false positives, tuning debt, and ATT&CK coverage work are visible before promotion."
          actions={
            <button className="btn btn-sm" type="button" onClick={() => openDrawer('rules')}>
              Run replay
            </button>
          }
        >
          {renderLaneAnnotation(
            'rule_tuning',
            'Detection quality stays credible only when replay debt and suppressions remain visible.',
            'Run replay and update promotion evidence before pushing noisy content wider.',
          )}
          <SummaryGrid
            data={{
              total_rules: rules.length,
              noisy_rules: noisyRules.length,
              suppressions: suppressions.length,
              stale_rules: staleRules.length,
            }}
            limit={4}
          />
          {noisyRules.slice(0, 4).map((rule) => (
            <WorkItem
              key={rule.id || rule.name}
              title={rule.name || rule.title || rule.id}
              detail={`${formatCount(rule.last_test_match_count || 0)} replay hits - ${formatCount(suppressionCount[rule.id] || 0)} suppressions`}
              badge={rule.lifecycle || 'review'}
              tone={statusBadge(rule.lifecycle)}
              onClick={() => openDrawer('rules', rule)}
            />
          ))}
          <JsonDetails data={data.efficacySummary} label="Efficacy summary" />
        </CommandSection>

        <CommandSection
          eyebrow="Release and Upgrade Center"
          title="Make upgrades auditable before operators click deploy"
          description="The release lane connects version inventory, SBOM, package readiness, and rollback posture."
          actions={
            <button className="btn btn-sm" type="button" onClick={() => openDrawer('release')}>
              Check readiness
            </button>
          }
        >
          {renderLaneAnnotation(
            'release',
            'Release readiness should stay tied to candidate metadata, SBOM context, and rollback posture.',
            'Review rollout evidence before any deploy handoff leaves the Command Center.',
          )}
          <SummaryGrid
            data={{
              current_version:
                data.configData?.version || data.configData?.app_version || 'unknown',
              latest_release: activeRelease?.version || activeRelease?.tag || 'unknown',
              sbom_components:
                data.sbomData?.components?.length || data.sbomData?.component_count || 0,
              release_count: releases.length,
            }}
            limit={4}
          />
          {releases.slice(0, 3).map((release) => (
            <WorkItem
              key={release.version || release.tag || release.id}
              title={release.version || release.tag || release.name || 'Release candidate'}
              detail={
                release.notes ||
                release.summary ||
                compactTimestamp(release.created_at || release.published_at)
              }
              badge={release.status || 'candidate'}
              tone={statusBadge(release.status)}
              onClick={() => openDrawer('release', release)}
            />
          ))}
        </CommandSection>

        <CommandSection
          eyebrow="Guided Remediation Approval Flow"
          title="Show blast radius before live execution"
          description="Approvals, required approver count, rollback proof, dry-run evidence, and typed-host gates stay together."
          actions={
            <button className="btn btn-sm" type="button" onClick={() => openDrawer('remediation')}>
              Review changes
            </button>
          }
        >
          {renderLaneAnnotation(
            'remediation',
            'Blast radius, approval state, and rollback proof belong together before live execution.',
            'Verify typed-host confirmation and approval quorum before approving rollback execution.',
          )}
          {reviews.length > 0 ? (
            reviews
              .slice(0, 5)
              .map((review) => (
                <WorkItem
                  key={review.id || review.title}
                  title={review.title || review.change_type || 'Remediation review'}
                  detail={`${review.asset_id || 'unscoped'} - ${review.approvals?.length || 0}/${review.required_approvers || 1} approvals - rollback ${review.rollback_proof ? 'ready' : 'pending'}`}
                  badge={review.approval_status || 'pending'}
                  tone={statusBadge(review.approval_status)}
                  onClick={() => openDrawer('remediation', review)}
                />
              ))
          ) : (
            <WorkspaceEmptyState
              compact
              title="No remediation reviews loaded"
              description="Live rollback requests will appear here with blast radius, approval chain, and rollback proof state."
            />
          )}
          <SummaryGrid
            data={{
              pending: pendingReviews.length,
              approved: approvedReviews.length,
              rollback_ready: readyRollbacks.length,
            }}
            limit={3}
          />
        </CommandSection>

        <CommandSection
          eyebrow="AI Analyst Evidence Boundaries"
          title="Keep assistant answers inside cited evidence"
          description="Assistant output declares scope, evidence, confidence, and uncertainty before it becomes action."
          actions={
            <Link className="btn btn-sm" to="/assistant">
              Open assistant
            </Link>
          }
        >
          <SummaryGrid
            data={{
              mode: assistantMode,
              model: data.assistantStatus?.model || 'retrieval-only',
              provider: data.assistantStatus?.provider || 'local',
              active_conversations: data.assistantStatus?.active_conversations || 0,
            }}
            limit={4}
          />
          {evidenceBoundaryWarnings.map((warning) => (
            <WorkItem
              key={warning}
              title={warning}
              badge="guardrail"
              tone={assistantGuardrailTone}
            />
          ))}
        </CommandSection>

        <CommandSection
          eyebrow="Attack Storytelling"
          title="Turn detections into a readable attack narrative"
          description="Incident storylines and graph pivots explain initial access, lateral movement, containment, and impact."
          actions={
            <Link className="btn btn-sm" to="/attack-graph">
              Open attack graph
            </Link>
          }
        >
          {activeIncidents.slice(0, 4).map((incident) => (
            <WorkItem
              key={`story-${incident.id || incident.title}`}
              title={incident.title || incident.name || `Incident ${incident.id}`}
              detail="Open storyline, graph pivot, and report export context."
              badge="storyline"
              tone="badge-info"
              to={buildHref('/soc', {
                params: { incident: incident.id || undefined, incidentPanel: 'storyline' },
              })}
            />
          ))}
          {activeIncidents.length === 0 && (
            <WorkspaceEmptyState
              compact
              title="No attack stories queued"
              description="The next incident with linked evidence will expose storyline and graph pivots here."
            />
          )}
        </CommandSection>

        <CommandSection
          eyebrow="Tenant and Team RBAC Polish"
          title="Preview access risk before role changes"
          description="Role templates, scoped API keys, JIT admin elevation, and access-change audit checks are tracked from this lane."
          actions={
            <Link className="btn btn-sm" to="/settings">
              Open identity settings
            </Link>
          }
        >
          <SummaryGrid
            data={{
              users: users.length,
              admins: users.filter((user) => normalizedStatus(user.role) === 'admin').length,
              analysts: users.filter((user) => normalizedStatus(user.role) === 'analyst').length,
              access_source: data.rbacUsersData?.source || 'local',
            }}
            limit={4}
          />
          {users.slice(0, 4).map((user) => (
            <WorkItem
              key={user.username || user.user_id || user.email}
              title={user.username || user.user_id || user.email || 'User'}
              detail={user.groups?.join(', ') || user.source || 'No group scope loaded'}
              badge={user.role || 'viewer'}
              tone={statusBadge(user.role === 'admin' ? 'warning' : 'ready')}
            />
          ))}
        </CommandSection>

        <CommandSection
          eyebrow="Rule Tuning Workflow"
          title="Move from false-positive feedback to safe promotion"
          description="Noisy rule triage, suppression drafts, replay validation, and promotion checklist live in one flow."
          actions={
            <button className="btn btn-sm" type="button" onClick={() => openDrawer('rules')}>
              Open checklist
            </button>
          }
        >
          {(staleRules.length > 0 ? staleRules : noisyRules).slice(0, 4).map((rule) => (
            <RuleTuningChecklist
              key={`checklist-${rule.id || rule.name}`}
              rule={rule}
              suppressionCount={suppressionCount[rule.id] || 0}
              onReplay={(selectedRule) => openDrawer('rules', selectedRule)}
            />
          ))}
          {staleRules.length === 0 && noisyRules.length === 0 && (
            <WorkspaceEmptyState
              compact
              title="No stale rules detected"
              description="Rules needing replay, suppression, or promotion evidence will appear here."
            />
          )}
        </CommandSection>

        <CommandSection
          eyebrow="Evidence-Ready Compliance Packs"
          title="Prepare auditor-ready exports from operational truth"
          description="Compliance packs combine incidents, release attestations, config state, and report templates."
          actions={
            <button className="btn btn-sm" type="button" onClick={() => openDrawer('evidence')}>
              Create evidence pack
            </button>
          }
        >
          {renderLaneAnnotation(
            'evidence',
            'Evidence exports should reflect operational truth, not detached checklist state.',
            'Generate packs only after compliance posture and release context are current.',
          )}
          <SummaryGrid
            data={{
              compliance_status: complianceStatus,
              templates: reportTemplates.length,
              sbom_available: Boolean(data.sbomData?.components || data.sbomData?.component_count),
              release_metadata: releases.length > 0,
            }}
            limit={4}
          />
          {reportTemplates.slice(0, 4).map((template) => (
            <WorkItem
              key={template.id || template.name}
              title={template.name || template.title || 'Evidence template'}
              detail={
                template.description || template.scope || 'Ready for compliance evidence export.'
              }
              badge={template.framework || template.type || 'pack'}
              tone="badge-info"
              onClick={() => openDrawer('evidence', template)}
            />
          ))}
        </CommandSection>
      </div>
    </div>
  );
}

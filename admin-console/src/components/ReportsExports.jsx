import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useApiGroup, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid } from './operator.jsx';
import { downloadData, formatDateTime, formatRelativeTime } from './operatorUtils.js';
import WorkflowGuidance from './WorkflowGuidance.jsx';
import { buildHref } from './workflowPivots.js';

const TABS = ['templates', 'runs', 'delivery', 'compliance', 'evidence', 'privacy'];

const TAB_LABELS = {
  templates: 'Templates',
  runs: 'Runs',
  delivery: 'Delivery',
  compliance: 'Compliance',
  evidence: 'Evidence',
  privacy: 'Privacy',
};

const ALERT_EXPORT_FORMATS = [
  {
    id: 'json',
    label: 'Native JSON',
    extension: 'json',
    mime: 'application/json',
    description: 'Complete alert records for downstream processing or archival.',
  },
  {
    id: 'cef',
    label: 'CEF',
    extension: 'cef',
    mime: 'text/plain;charset=utf-8',
    description: 'Common Event Format for ArcSight-style SIEM ingestion.',
  },
  {
    id: 'leef',
    label: 'LEEF',
    extension: 'leef',
    mime: 'text/plain;charset=utf-8',
    description: 'QRadar Log Event Extended Format for IBM-aligned pipelines.',
  },
  {
    id: 'syslog',
    label: 'Syslog',
    extension: 'log',
    mime: 'text/plain;charset=utf-8',
    description: 'Plain syslog lines for collectors that expect transport-ready text.',
  },
  {
    id: 'ecs',
    label: 'Elastic ECS',
    extension: 'json',
    mime: 'application/json',
    description: 'Elastic Common Schema JSON records for search and retention workflows.',
  },
  {
    id: 'udm',
    label: 'Google UDM',
    extension: 'json',
    mime: 'application/json',
    description: 'Chronicle UDM export for Google SecOps pipelines.',
  },
  {
    id: 'sentinel',
    label: 'Microsoft Sentinel',
    extension: 'json',
    mime: 'application/json',
    description: 'Sentinel-ready JSON with familiar severity and entity shapes.',
  },
  {
    id: 'qradar',
    label: 'QRadar JSON',
    extension: 'json',
    mime: 'application/json',
    description: 'Normalized QRadar-oriented JSON payload for custom integrations.',
  },
];

const COMMON_HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
const ARTIFACT_SCOPE_FILTERS = ['all', 'current', 'unscoped'];
const TEMPLATE_SCOPE_FILTERS = ['all', 'current', 'unscoped'];

function mergeReportParams(searchParams, updates = {}) {
  const next = new URLSearchParams(searchParams);
  Object.entries(updates).forEach(([key, value]) => {
    if (value == null || String(value).trim() === '') next.delete(key);
    else next.set(key, String(value).trim());
  });
  return next;
}

function formatScopeSource(value) {
  if (!value) return 'Manual';
  return String(value)
    .replaceAll('-', ' ')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function buildSocLink({
  caseId,
  incidentId,
  investigationId,
  source,
  target,
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
      target: target || undefined,
      drawer: drawer || undefined,
      casePanel: casePanel || undefined,
      incidentPanel: incidentPanel || undefined,
    },
    hash,
  });
}

function buildExecutionContextPayload({ caseId, incidentId, investigationId, source }) {
  return {
    case_id: caseId || undefined,
    incident_id: incidentId || undefined,
    investigation_id: investigationId || undefined,
    source: source || undefined,
  };
}

function describeExecutionContext(context = {}) {
  const normalizedContext = context || {};
  const labels = [];
  if (normalizedContext.case_id) labels.push(`Case #${normalizedContext.case_id}`);
  if (normalizedContext.incident_id) labels.push(`Incident #${normalizedContext.incident_id}`);
  if (normalizedContext.investigation_id) {
    labels.push(`Investigation ${normalizedContext.investigation_id}`);
  }
  if (normalizedContext.source) labels.push(formatScopeSource(normalizedContext.source));
  return labels;
}

function executionContextMatches(context = {}, activeContext = {}) {
  if (!activeContext.case_id && !activeContext.incident_id && !activeContext.investigation_id) {
    return false;
  }
  const keys = ['case_id', 'incident_id', 'investigation_id', 'source'];
  return keys.every((key) => {
    if (!activeContext[key]) return true;
    return String(context?.[key] || '') === String(activeContext[key]);
  });
}

function hasExecutionContext(context = {}) {
  return Boolean(
    context?.case_id || context?.incident_id || context?.investigation_id || context?.source,
  );
}

function sanitizeFilename(value) {
  const normalized = String(value || 'export')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || 'export';
}

function formatPercent(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0.0%';
  return `${numeric.toFixed(1)}%`;
}

function findingStatusLabel(status) {
  switch (status) {
    case 'pass':
      return 'Pass';
    case 'fail':
      return 'Fail';
    case 'manual_review':
      return 'Manual Review';
    case 'not_applicable':
      return 'Not Applicable';
    default:
      return 'Unknown';
  }
}

function findingBadgeClass(status) {
  switch (status) {
    case 'pass':
      return 'badge-ok';
    case 'fail':
      return 'badge-err';
    case 'manual_review':
      return 'badge-warn';
    case 'not_applicable':
      return 'badge-info';
    default:
      return 'badge-info';
  }
}

function escapeMarkdownCell(value) {
  return String(value ?? '')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n+/g, ' ')
    .trim();
}

function buildComplianceMarkdown(report) {
  if (!report) return '';
  const frameworkParts = String(report.framework_id || '').split('-');
  const frameworkVersion = frameworkParts[frameworkParts.length - 1] || '';
  const lines = [
    `# Compliance Report: ${report.framework_name}${frameworkVersion ? ` ${frameworkVersion}` : ''}`,
    '',
    `Generated: ${report.generated_at || 'unknown'}`,
    '',
    '## Summary',
    '',
    '| Metric | Value |',
    '|--------|-------|',
    `| Total Controls | ${report.total_controls ?? 0} |`,
    `| Passed | ${report.passed ?? 0} |`,
    `| Failed | ${report.failed ?? 0} |`,
    `| Manual Review | ${report.manual_review ?? 0} |`,
    `| Not Applicable | ${report.not_applicable ?? 0} |`,
    `| Compliance Score | ${formatPercent(report.score_percent)} |`,
    '',
    '## Findings',
    '',
    '| Control | Title | Status | Evidence |',
    '|---------|-------|--------|----------|',
  ];

  const findings = Array.isArray(report.findings) ? report.findings : [];
  findings.forEach((finding) => {
    lines.push(
      `| ${escapeMarkdownCell(finding.control_id)} | ${escapeMarkdownCell(finding.title)} | ${escapeMarkdownCell(findingStatusLabel(finding.status))} | ${escapeMarkdownCell(finding.evidence)} |`,
    );
  });

  const remediations = findings.filter(
    (finding) => finding.status === 'fail' && String(finding.remediation || '').trim(),
  );
  if (remediations.length > 0) {
    lines.push('', '## Remediation Actions', '');
    remediations.forEach((finding) => {
      lines.push(`- ${finding.control_id}: ${finding.remediation}`);
    });
  }

  return lines.join('\n');
}

function buildEvidenceBundle(report, complianceSummary, privacyBudget, attestation, storedReports) {
  return {
    bundle_type: 'compliance_evidence',
    generated_at: new Date().toISOString(),
    framework_id: report?.framework_id ?? null,
    framework_name: report?.framework_name ?? null,
    report,
    report_markdown: buildComplianceMarkdown(report),
    compliance_summary: complianceSummary ?? null,
    privacy_budget: privacyBudget ?? null,
    attestation: attestation ?? null,
    stored_report_count: Array.isArray(storedReports) ? storedReports.length : 0,
  };
}

function buildArtifactRunScope({ caseId, incidentId, investigationId, fallback = 'global' }) {
  if (investigationId) return 'investigation';
  if (incidentId) return 'incident';
  if (caseId) return 'case';
  return fallback;
}

function responseEntryMatchesTarget(entry, target) {
  if (!target) return true;
  const normalizedTarget = String(target).trim().toLowerCase();
  if (!normalizedTarget || normalizedTarget.startsWith('case:')) return true;
  const candidates = [
    entry?.target,
    entry?.target_hostname,
    entry?.target_agent_uid,
    entry?.target?.hostname,
    entry?.target?.agent_uid,
    entry?.target?.ip,
  ]
    .filter(Boolean)
    .map((value) =>
      typeof value === 'string' ? value.toLowerCase() : JSON.stringify(value).toLowerCase(),
    );
  return candidates.some((candidate) => candidate.includes(normalizedTarget));
}

export default function ReportsExports() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = TABS.includes(searchParams.get('tab')) ? searchParams.get('tab') : 'templates';
  const activeCaseId = searchParams.get('case') || '';
  const activeIncidentId = searchParams.get('incident') || '';
  const activeInvestigationId = searchParams.get('investigation') || '';
  const activeSource = searchParams.get('source') || '';
  const activeResponseTarget = searchParams.get('target') || '';
  const hasScopeSelection = Boolean(activeCaseId || activeIncidentId || activeInvestigationId);
  const [templateScopeFilter, setTemplateScopeFilter] = useState('all');
  const [artifactSearch, setArtifactSearch] = useState('');
  const [artifactScopeFilter, setArtifactScopeFilter] = useState('all');
  const [republishingLegacyId, setRepublishingLegacyId] = useState(null);
  const [attachingLegacyId, setAttachingLegacyId] = useState(null);
  const [savingScopedTemplate, setSavingScopedTemplate] = useState(false);
  const [persistingArtifactKey, setPersistingArtifactKey] = useState(null);
  const artifactReportQuery =
    artifactScopeFilter === 'current' && (activeCaseId || activeIncidentId || activeInvestigationId)
      ? {
          caseId: activeCaseId || undefined,
          incidentId: activeIncidentId || undefined,
          investigationId: activeInvestigationId || undefined,
          source: activeSource || undefined,
          scope: 'scoped',
        }
      : artifactScopeFilter === 'unscoped'
        ? { scope: 'unscoped' }
        : {};
  const { data: reportInventoryData, reload: reloadReportInventory } = useApiGroup(
    {
      reportsData: api.reports,
      artifactReportsData: () => api.reports(artifactReportQuery),
    },
    [artifactScopeFilter, activeCaseId, activeIncidentId, activeInvestigationId, activeSource],
  );
  const { reportsData, artifactReportsData } = reportInventoryData;
  const templateQuery =
    templateScopeFilter === 'current' && hasScopeSelection
      ? {
          caseId: activeCaseId || undefined,
          incidentId: activeIncidentId || undefined,
          investigationId: activeInvestigationId || undefined,
          source: activeSource || undefined,
          scope: 'scoped',
        }
      : templateScopeFilter === 'unscoped'
        ? { scope: 'unscoped' }
        : {};
  const { data: templateWorkspaceData, reload: reloadTemplateWorkspace } = useApiGroup(
    {
      execSum: api.executiveSummary,
      templateData: () => api.reportTemplates(templateQuery),
    },
    [templateScopeFilter, activeCaseId, activeIncidentId, activeInvestigationId, activeSource],
  );
  const { execSum, templateData } = templateWorkspaceData;
  const scopedHistoryQuery = hasScopeSelection
    ? {
        caseId: activeCaseId || undefined,
        incidentId: activeIncidentId || undefined,
        investigationId: activeInvestigationId || undefined,
        source: activeSource || undefined,
        scope: 'scoped',
      }
    : {};
  const { data: reportHistoryData, reload: reloadReportHistory } = useApiGroup(
    {
      runData: () => api.reportRuns(scopedHistoryQuery),
      scheduleData: () => api.reportSchedules(scopedHistoryQuery),
    },
    [activeCaseId, activeIncidentId, activeInvestigationId, activeSource],
  );
  const { runData, scheduleData } = reportHistoryData;
  const { data: caseList } = useApi(api.cases);
  const { data: incidentDetail } = useApi(
    () => api.incidentById(activeIncidentId),
    [activeIncidentId],
    {
      skip: !activeIncidentId,
    },
  );
  const { data: investigationList } = useApi(api.investigationActive, [], {
    skip: !activeInvestigationId,
  });
  const {
    data: evidenceContextData,
    loading: evidenceContextLoading,
    errors: evidenceContextErrors,
    reload: reloadEvidenceContext,
  } = useApiGroup({
    complianceSummaryData: api.complianceSummary,
    complianceReportData: api.complianceReport,
    privacyBudgetData: api.privacyBudget,
    attestationData: api.attestationStatus,
  });
  const { complianceSummaryData, complianceReportData, privacyBudgetData, attestationData } =
    evidenceContextData;
  const complianceSummaryLoading = evidenceContextLoading;
  const complianceReportsLoading = evidenceContextLoading;
  const privacyBudgetLoading = evidenceContextLoading;
  const attestationLoading = evidenceContextLoading;
  const complianceSummaryError = evidenceContextErrors.complianceSummaryData;
  const complianceReportsError = evidenceContextErrors.complianceReportData;
  const privacyBudgetError = evidenceContextErrors.privacyBudgetData;
  const attestationError = evidenceContextErrors.attestationData;
  const { data: responseDeliveryData, reload: reloadResponseDelivery } = useApiGroup(
    {
      responsePendingData: api.responsePending,
      responseRequestData: api.responseRequests,
      responseAuditData: api.responseAudit,
      responseStatsData: api.responseStats,
    },
    [activeTab],
    {
      skip: activeTab !== 'delivery',
    },
  );
  const { responsePendingData, responseRequestData, responseAuditData, responseStatsData } =
    responseDeliveryData;
  const templates = Array.isArray(templateData?.templates) ? templateData.templates : [];
  const runs = Array.isArray(runData?.runs) ? runData.runs : [];
  const schedules = Array.isArray(scheduleData?.schedules) ? scheduleData.schedules : [];
  const cases = Array.isArray(caseList) ? caseList : caseList?.cases || [];
  const investigations = Array.isArray(investigationList)
    ? investigationList
    : investigationList?.items || [];
  const storedReports = Array.isArray(reportsData) ? reportsData : reportsData?.reports || [];
  const artifactStoredReports = Array.isArray(artifactReportsData)
    ? artifactReportsData
    : artifactReportsData?.reports || [];
  const complianceReports = Array.isArray(complianceReportData)
    ? complianceReportData
    : complianceReportData?.reports || [];
  const complianceSummaryFrameworks = Array.isArray(complianceSummaryData?.frameworks)
    ? complianceSummaryData.frameworks
    : [];
  const responsePendingItems = Array.isArray(responsePendingData?.pending)
    ? responsePendingData.pending
    : [];
  const responseRequestItems = Array.isArray(responseRequestData?.requests)
    ? responseRequestData.requests
    : Array.isArray(responseRequestData)
      ? responseRequestData
      : [];
  const responseAuditItems = Array.isArray(responseAuditData?.audit_log)
    ? responseAuditData.audit_log
    : Array.isArray(responseAuditData)
      ? responseAuditData
      : [];
  const [selectedTemplateId, setSelectedTemplateId] = useState(null);
  const [selectedComplianceId, setSelectedComplianceId] = useState(null);
  const [scheduleForm, setScheduleForm] = useState({
    name: 'Weekly Executive Status',
    kind: 'executive_status',
    scope: 'global',
    format: 'json',
    cadence: 'weekly',
    target: 'ops@wardex.local',
  });
  const [alertExportFormat, setAlertExportFormat] = useState('json');
  const [exportingAlerts, setExportingAlerts] = useState(false);
  const [auditFilters, setAuditFilters] = useState({ q: '', method: '', status: '', auth: '' });
  const [exportingAudit, setExportingAudit] = useState(false);
  const [piiInput, setPiiInput] = useState('');
  const [piiResult, setPiiResult] = useState(null);
  const [scanningPii, setScanningPii] = useState(false);
  const [forgetEntity, setForgetEntity] = useState('');
  const [forgetConfirm, setForgetConfirm] = useState('');
  const [forgetResult, setForgetResult] = useState(null);
  const [forgetting, setForgetting] = useState(false);
  const selectedCase = cases.find((entry) => String(entry.id) === String(activeCaseId)) || null;
  const selectedIncident = incidentDetail || null;
  const selectedInvestigation =
    investigations.find((entry) => String(entry.id) === String(activeInvestigationId)) || null;
  const hasActiveScope = hasScopeSelection;
  const scopeSummary = {
    case: selectedCase
      ? `#${selectedCase.id} ${selectedCase.title || 'Untitled case'}`
      : activeCaseId
        ? `#${activeCaseId}`
        : 'No case',
    incident: selectedIncident
      ? selectedIncident.title || selectedIncident.summary || `#${activeIncidentId}`
      : activeIncidentId
        ? `#${activeIncidentId}`
        : 'No incident',
    investigation: selectedInvestigation
      ? selectedInvestigation.workflow_name || selectedInvestigation.id
      : activeInvestigationId || 'No investigation',
    source: formatScopeSource(activeSource),
    response_target: activeResponseTarget || 'Not pinned',
  };
  const reportScopeParams = {
    case: activeCaseId || undefined,
    incident: activeIncidentId || undefined,
    investigation: activeInvestigationId || undefined,
    source: activeSource || undefined,
    target: activeResponseTarget || undefined,
  };
  const activeExecutionContext = buildExecutionContextPayload({
    caseId: activeCaseId,
    incidentId: activeIncidentId,
    investigationId: activeInvestigationId,
    source: activeSource,
  });
  const activeArtifactScope = buildArtifactRunScope({
    caseId: activeCaseId,
    incidentId: activeIncidentId,
    investigationId: activeInvestigationId,
  });
  const scopedArtifactRuns = runs.filter((run) => {
    const query = artifactSearch.trim().toLowerCase();
    const matchesQuery =
      !query ||
      [run.id, run.name, run.kind, run.summary, ...describeExecutionContext(run.execution_context)]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query));
    if (!matchesQuery) return false;
    if (artifactScopeFilter === 'current') {
      return executionContextMatches(run.execution_context, activeExecutionContext);
    }
    if (artifactScopeFilter === 'unscoped') {
      return !hasExecutionContext(run.execution_context);
    }
    return true;
  });
  const legacyStoredReports = artifactStoredReports.filter((report) => {
    if (hasExecutionContext(report.execution_context)) return false;
    const query = artifactSearch.trim().toLowerCase();
    if (!query) return true;
    return [report.id, report.report_type || report.type, report.generated_at]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  });
  const scopedBackendReports = artifactStoredReports.filter((report) => {
    if (!hasExecutionContext(report.execution_context)) return false;
    const query = artifactSearch.trim().toLowerCase();
    const matchesQuery =
      !query ||
      [
        report.id,
        report.report_type || report.type,
        report.generated_at,
        ...describeExecutionContext(report.execution_context),
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query));
    if (!matchesQuery) return false;
    return true;
  });
  const filteredResponsePending = responsePendingItems.filter((entry) =>
    responseEntryMatchesTarget(entry, activeResponseTarget),
  );
  const filteredResponseRequests = responseRequestItems.filter((entry) =>
    responseEntryMatchesTarget(entry, activeResponseTarget),
  );
  const filteredResponseAudit = responseAuditItems.filter((entry) =>
    responseEntryMatchesTarget(entry, activeResponseTarget),
  );

  const activeTemplateId = templates.some((template) => template.id === selectedTemplateId)
    ? selectedTemplateId
    : templates[0]?.id || null;
  const selectedTemplate = templates.find((template) => template.id === activeTemplateId) || null;
  const activeComplianceId = complianceReports.some(
    (report) => report.framework_id === selectedComplianceId,
  )
    ? selectedComplianceId
    : complianceReports[0]?.framework_id || null;
  const selectedReport =
    complianceReports.find((report) => report.framework_id === activeComplianceId) || null;
  const activeAlertExport =
    ALERT_EXPORT_FORMATS.find((format) => format.id === alertExportFormat) ||
    ALERT_EXPORT_FORMATS[0];
  const complianceSnapshotTemplate =
    templates.find((template) => template.kind === 'compliance_snapshot') ||
    templates.find((template) => template.id === 'tpl-compliance-snapshot') ||
    null;
  const auditExportTemplate =
    templates.find((template) => template.kind === 'audit_export') ||
    templates.find((template) => template.id === 'tpl-audit-export') ||
    null;
  const attestationChecks = Array.isArray(attestationData?.checks) ? attestationData.checks : [];
  const failingAttestationChecks = attestationChecks.filter((check) => !check?.passed);
  const totalFailedControls = complianceReports.reduce(
    (total, report) => total + Number(report.failed || 0),
    0,
  );
  const totalManualReviewControls = complianceReports.reduce(
    (total, report) => total + Number(report.manual_review || 0),
    0,
  );

  const previewPayload = selectedTemplate
    ? {
        name: selectedTemplate.name,
        kind: selectedTemplate.kind,
        scope: selectedTemplate.scope,
        format: selectedTemplate.format,
        audience: selectedTemplate.audience,
        summary: selectedTemplate.description,
        executive_summary: execSum,
        estimated_size: `${JSON.stringify({ selectedTemplate, execSum }).length} bytes`,
      }
    : null;
  const complianceOverview = {
    overall_score: formatPercent(complianceSummaryData?.overall_score),
    frameworks: complianceReports.length,
    failed_controls: totalFailedControls,
    manual_review: totalManualReviewControls,
    generated_at: complianceSummaryData?.generated_at
      ? formatDateTime(complianceSummaryData.generated_at)
      : 'Not generated yet',
  };
  const evidenceOverview = {
    selected_framework: selectedReport?.framework_name || 'No framework selected',
    alert_formats: ALERT_EXPORT_FORMATS.length,
    attestation_status: attestationData?.passed ? 'Ready' : 'Needs review',
    failed_attestation_checks: failingAttestationChecks.length,
    stored_reports: storedReports.length,
  };
  const privacyOverview = {
    budget_remaining: privacyBudgetData?.budget_remaining ?? 'Unavailable',
    exhausted: privacyBudgetData?.is_exhausted ? 'Yes' : 'No',
    attestation_status: attestationData?.passed ? 'Ready' : 'Blocked',
    outstanding_checks: failingAttestationChecks.length,
  };
  const responseSnapshot = {
    target: activeResponseTarget || 'All response targets',
    pending_approvals: filteredResponsePending.length,
    total_requests: filteredResponseRequests.length,
    ready_to_execute: filteredResponseRequests.filter(
      (request) => String(request.status || '').toLowerCase() === 'approved' && !request.dry_run,
    ).length,
    dry_runs: filteredResponseRequests.filter((request) => Boolean(request.dry_run)).length,
    executed: filteredResponseAudit.filter(
      (entry) => String(entry.outcome || '').toLowerCase() === 'executed',
    ).length,
    denied: filteredResponseAudit.filter(
      (entry) => String(entry.outcome || '').toLowerCase() === 'denied',
    ).length,
    protected_assets:
      activeResponseTarget && !activeResponseTarget.startsWith('case:')
        ? 'Filtered view'
        : (responseStatsData?.protected_assets ?? '—'),
  };
  const workflowItems = [
    {
      id: 'dashboard',
      title: 'Return To Overview',
      description: 'Go back to the security overview with the current reporting backlog in mind.',
      to: '/',
      minRole: 'viewer',
      tone: 'primary',
      badge: 'Overview',
    },
    {
      id: 'threat-detection',
      title: 'Turn Findings Into Detection Work',
      description:
        'Use Threat Detection to convert failed controls, delivery gaps, or evidence findings into hunts and tuning work.',
      to: buildHref('/detection', { params: { queue: 'noisy' } }),
      minRole: 'analyst',
      badge: 'Detect',
    },
    {
      id: 'soc-workbench',
      title: 'Drive Response Follow-Up',
      description: 'Open case and approval workflows to action what the report surfaced.',
      to: buildSocLink({
        caseId: activeCaseId || selectedCase?.id,
        incidentId: activeIncidentId || selectedIncident?.id,
        investigationId: activeInvestigationId || selectedInvestigation?.id,
        source: activeSource || undefined,
        hash: 'response',
      }),
      minRole: 'analyst',
      badge: 'Respond',
    },
    {
      id: 'infrastructure',
      title: 'Review Exposure And Integrity',
      description:
        'Cross-check compliance and evidence findings against exposure, integrity, and observability queues.',
      to: buildHref('/infrastructure', { params: { tab: 'exposure' } }),
      minRole: 'analyst',
      badge: 'Asset',
    },
    {
      id: 'attack-graph',
      title: 'Validate Campaign Context',
      description:
        'Use the attack graph to see whether report findings fit a broader campaign path.',
      to: '/attack-graph',
      minRole: 'analyst',
      badge: 'Graph',
    },
  ];
  const failedFindings = Array.isArray(selectedReport?.findings)
    ? selectedReport.findings.filter((finding) => finding.status === 'fail')
    : [];
  const reviewFindings = Array.isArray(selectedReport?.findings)
    ? selectedReport.findings.filter((finding) => finding.status === 'manual_review')
    : [];

  const switchTab = (tab) =>
    setSearchParams(mergeReportParams(searchParams, { tab }), { replace: true });

  const activeCaseHref = activeCaseId
    ? buildSocLink({
        caseId: activeCaseId,
        incidentId: activeIncidentId || undefined,
        investigationId: activeInvestigationId || undefined,
        source: activeSource || undefined,
        target: activeResponseTarget || undefined,
        drawer: 'case-workspace',
        casePanel: 'summary',
        hash: 'cases',
      })
    : null;
  const activeIncidentHref = activeIncidentId
    ? buildSocLink({
        caseId: activeCaseId || undefined,
        incidentId: activeIncidentId,
        investigationId: activeInvestigationId || undefined,
        source: activeSource || undefined,
        target: activeResponseTarget || undefined,
        drawer: 'incident-detail',
        incidentPanel: 'summary',
        hash: 'cases',
      })
    : null;
  const activeInvestigationHref = activeInvestigationId
    ? buildSocLink({
        caseId: activeCaseId || undefined,
        investigationId: activeInvestigationId,
        source: activeSource || undefined,
        target: activeResponseTarget || undefined,
        hash: 'investigations',
      })
    : null;
  const activeAssistantHref = buildHref('/assistant', {
    params: reportScopeParams,
  });

  const createRun = async (template) => {
    if (!template) return;
    try {
      await api.createReportRun({
        name: template.name,
        kind: template.kind,
        scope: template.scope,
        format: template.format,
        audience: template.audience,
        summary: template.description,
        ...activeExecutionContext,
      });
      toast('Report run created.', 'success');
      reloadReportHistory();
      reloadTemplateWorkspace();
      switchTab('runs');
    } catch {
      toast('Failed to create report run.', 'error');
    }
  };

  const saveScopedTemplate = async (template) => {
    if (!template || !hasActiveScope) return;
    setSavingScopedTemplate(true);
    try {
      const scopedTemplateName = `${template.name} for ${scopeSummary.case}`;
      await api.saveReportTemplate({
        name: scopedTemplateName,
        kind: template.kind,
        scope: template.scope,
        format: template.format,
        status: template.status || 'ready',
        audience: template.audience,
        description: template.description,
        ...activeExecutionContext,
      });
      refreshTemplateWorkspace({ forceCurrentScope: true });
      toast('Scoped template saved for the active investigation context.', 'success');
    } catch {
      toast('Unable to save a scoped template for the current context.', 'error');
    } finally {
      setSavingScopedTemplate(false);
    }
  };

  const createSchedule = async () => {
    try {
      await api.saveReportSchedule({
        ...scheduleForm,
        name: scheduleForm.name,
        next_run_at: new Date(
          Date.now() + (scheduleForm.cadence === 'daily' ? 24 : 7 * 24) * 60 * 60 * 1000,
        ).toISOString(),
        status: 'active',
        ...activeExecutionContext,
      });
      toast('Schedule saved.', 'success');
      reloadReportHistory();
    } catch {
      toast('Unable to save schedule.', 'error');
    }
  };

  const rerun = async (run) => {
    try {
      await api.createReportRun({
        name: run.name,
        kind: run.kind,
        scope: run.scope,
        format: run.format,
        audience: run.audience,
        summary: run.summary,
        ...(run.execution_context || activeExecutionContext),
      });
      toast('Run queued again.', 'success');
      reloadReportHistory();
    } catch {
      toast('Unable to rerun report.', 'error');
    }
  };

  const republishLegacyReport = async (report) => {
    if (!report?.id) return;
    if (!hasActiveScope) {
      toast(
        'Select a case, incident, or investigation scope before republishing a legacy report.',
        'warning',
      );
      return;
    }
    setRepublishingLegacyId(String(report.id));
    try {
      const detail = await api.reportById(report.id);
      const detailReport = detail?.report || null;
      const reportType =
        detail?.report_type || report.report_type || report.type || 'legacy_report';
      const previewOverride = {
        republished_at: new Date().toISOString(),
        republished_from: {
          id: detail?.id || report.id,
          generated_at: detail?.generated_at || report.generated_at || null,
          report_type: reportType,
        },
        execution_context: activeExecutionContext,
        report: detailReport,
      };
      await api.createReportRun({
        name: `Republished ${String(reportType).replaceAll('_', ' ')} #${detail?.id || report.id}`,
        kind: reportType,
        scope: activeInvestigationId
          ? 'investigation'
          : activeIncidentId
            ? 'incident'
            : activeCaseId
              ? 'case'
              : 'legacy',
        format: 'json',
        audience: 'analyst',
        status: 'completed',
        summary: `Republished legacy backend report #${detail?.id || report.id} into the scoped artifact library.`,
        preview_override: previewOverride,
        ...activeExecutionContext,
      });
      reloadReportHistory();
      refreshReportInventory();
      toast('Legacy report republished into the scoped artifact library.', 'success');
    } catch {
      toast('Unable to republish the selected legacy report.', 'error');
    } finally {
      setRepublishingLegacyId(null);
    }
  };

  const attachLegacyReportContext = async (report) => {
    if (!report?.id) return;
    if (!hasActiveScope) {
      toast(
        'Select a case, incident, or investigation scope before attaching a backend report.',
        'warning',
      );
      return;
    }
    setAttachingLegacyId(String(report.id));
    try {
      await api.annotateReportContext(report.id, activeExecutionContext);
      refreshReportInventory();
      toast('Backend report is now attached to the active investigation scope.', 'success');
    } catch {
      toast('Unable to attach the selected backend report to the current scope.', 'error');
    } finally {
      setAttachingLegacyId(null);
    }
  };

  const refreshEvidenceContext = () => reloadEvidenceContext();

  const refreshDeliveryContext = () => reloadResponseDelivery();

  const refreshTemplateWorkspace = ({ forceCurrentScope = false } = {}) => {
    if (forceCurrentScope && hasActiveScope && templateScopeFilter !== 'current') {
      setTemplateScopeFilter('current');
      return;
    }
    reloadTemplateWorkspace();
  };

  const refreshReportInventory = () => {
    if (hasActiveScope && artifactScopeFilter !== 'current') {
      setArtifactScopeFilter('current');
      return;
    }
    reloadReportInventory();
  };

  const persistArtifactRun = async ({
    key,
    name,
    kind,
    format = 'json',
    audience = 'analyst',
    summary,
    payload,
    contentType = 'application/json',
    downloadName,
    scope = activeArtifactScope,
    metadata = {},
  }) => {
    setPersistingArtifactKey(key);
    try {
      await api.createReportRun({
        name,
        kind,
        scope,
        format,
        audience,
        status: 'completed',
        summary,
        preview_override: {
          generated_at: new Date().toISOString(),
          artifact_type: kind,
          download_name: downloadName,
          content_type: contentType,
          payload,
          metadata,
          execution_context: hasActiveScope ? activeExecutionContext : null,
        },
        ...activeExecutionContext,
      });
      reloadReportHistory();
      if (hasActiveScope) setArtifactScopeFilter('current');
      toast('Artifact saved to report run history.', 'success');
    } catch {
      toast('Unable to persist this artifact right now.', 'error');
    } finally {
      setPersistingArtifactKey(null);
    }
  };

  const downloadComplianceJson = (report) => {
    if (!report) return;
    downloadData(report, `${sanitizeFilename(report.framework_id)}-compliance-report.json`);
    toast('Compliance report downloaded.', 'success');
  };

  const downloadComplianceMarkdown = (report) => {
    if (!report) return;
    downloadData(
      buildComplianceMarkdown(report),
      `${sanitizeFilename(report.framework_id)}-compliance-report.md`,
      'text/markdown;charset=utf-8',
    );
    toast('Compliance markdown downloaded.', 'success');
  };

  const downloadEvidenceBundle = (report) => {
    if (!report) return;
    downloadData(
      {
        ...buildEvidenceBundle(
          report,
          complianceSummaryData,
          privacyBudgetData,
          attestationData,
          storedReports,
        ),
        report_scope: hasActiveScope ? activeExecutionContext : null,
      },
      `${sanitizeFilename(report.framework_id)}-evidence-bundle.json`,
    );
    toast('Evidence bundle downloaded.', 'success');
  };

  const saveComplianceJsonArtifact = async (report) => {
    if (!report) return;
    await persistArtifactRun({
      key: `compliance-json-${report.framework_id}`,
      name: `${report.framework_name} Compliance JSON`,
      kind: 'compliance_report',
      format: 'json',
      audience: 'audit',
      summary: `Persisted compliance report artifact for ${report.framework_name}.`,
      payload: report,
      downloadName: `${sanitizeFilename(report.framework_id)}-compliance-report.json`,
      metadata: {
        framework_id: report.framework_id,
        framework_name: report.framework_name,
        score_percent: report.score_percent,
      },
    });
  };

  const saveComplianceMarkdownArtifact = async (report) => {
    if (!report) return;
    const markdown = buildComplianceMarkdown(report);
    await persistArtifactRun({
      key: `compliance-markdown-${report.framework_id}`,
      name: `${report.framework_name} Compliance Markdown`,
      kind: 'compliance_markdown',
      format: 'markdown',
      audience: 'audit',
      summary: `Persisted markdown compliance brief for ${report.framework_name}.`,
      payload: markdown,
      contentType: 'text/markdown;charset=utf-8',
      downloadName: `${sanitizeFilename(report.framework_id)}-compliance-report.md`,
      metadata: {
        framework_id: report.framework_id,
        framework_name: report.framework_name,
      },
    });
  };

  const saveEvidenceBundleArtifact = async (report) => {
    if (!report) return;
    const bundle = {
      ...buildEvidenceBundle(
        report,
        complianceSummaryData,
        privacyBudgetData,
        attestationData,
        storedReports,
      ),
      report_scope: hasActiveScope ? activeExecutionContext : null,
    };
    await persistArtifactRun({
      key: `evidence-bundle-${report.framework_id}`,
      name: `${report.framework_name} Evidence Bundle`,
      kind: 'compliance_evidence_bundle',
      format: 'json',
      audience: 'audit',
      summary: `Persisted evidence bundle for ${report.framework_name}.`,
      payload: bundle,
      downloadName: `${sanitizeFilename(report.framework_id)}-evidence-bundle.json`,
      metadata: {
        framework_id: report.framework_id,
        framework_name: report.framework_name,
        includes_privacy_budget: true,
        includes_attestation: true,
      },
    });
  };

  const exportAlerts = async () => {
    setExportingAlerts(true);
    try {
      const payload = await api.exportAlerts(activeAlertExport.id);
      downloadData(
        payload,
        `alerts-${sanitizeFilename(activeAlertExport.id)}.${activeAlertExport.extension}`,
        activeAlertExport.mime,
      );
      toast(`Alert export downloaded in ${activeAlertExport.label}.`, 'success');
    } catch {
      toast('Unable to export alerts in the selected format.', 'error');
    } finally {
      setExportingAlerts(false);
    }
  };

  const saveAlertExportArtifact = async () => {
    setPersistingArtifactKey('alert-export');
    try {
      const payload = await api.exportAlerts(activeAlertExport.id);
      await api.createReportRun({
        name: `${activeAlertExport.label} Alert Export`,
        kind: 'alert_export',
        scope: activeArtifactScope,
        format: activeAlertExport.extension,
        audience: 'analyst',
        status: 'completed',
        summary: `Persisted backend-native alert export in ${activeAlertExport.label}.`,
        preview_override: {
          generated_at: new Date().toISOString(),
          artifact_type: 'alert_export',
          download_name: `alerts-${sanitizeFilename(activeAlertExport.id)}.${activeAlertExport.extension}`,
          content_type: activeAlertExport.mime,
          payload,
          metadata: {
            export_format: activeAlertExport.id,
            export_label: activeAlertExport.label,
          },
          execution_context: hasActiveScope ? activeExecutionContext : null,
        },
        ...activeExecutionContext,
      });
      reloadReportHistory();
      if (hasActiveScope) setArtifactScopeFilter('current');
      toast(`Alert export saved to run history in ${activeAlertExport.label}.`, 'success');
    } catch {
      toast('Unable to persist the selected alert export.', 'error');
    } finally {
      setPersistingArtifactKey(null);
    }
  };

  const exportAuditLog = async () => {
    setExportingAudit(true);
    try {
      const payload = await api.auditLogExport(auditFilters);
      downloadData(payload, 'audit-log-evidence.csv', 'text/csv;charset=utf-8');
      toast('Audit log evidence exported.', 'success');
    } catch {
      toast('Unable to export audit log evidence.', 'error');
    } finally {
      setExportingAudit(false);
    }
  };

  const saveAuditLogArtifact = async () => {
    setPersistingArtifactKey('audit-export');
    try {
      const payload = await api.auditLogExport(auditFilters);
      await api.createReportRun({
        name: 'Audit Log CSV Artifact',
        kind: 'audit_export',
        scope: activeArtifactScope,
        format: 'csv',
        audience: 'compliance',
        status: 'completed',
        summary: 'Persisted audit-log evidence export with the current filters.',
        preview_override: {
          generated_at: new Date().toISOString(),
          artifact_type: 'audit_export',
          download_name: 'audit-log-evidence.csv',
          content_type: 'text/csv;charset=utf-8',
          payload,
          metadata: {
            filters: auditFilters,
          },
          execution_context: hasActiveScope ? activeExecutionContext : null,
        },
        ...activeExecutionContext,
      });
      reloadReportHistory();
      if (hasActiveScope) setArtifactScopeFilter('current');
      toast('Audit export saved to run history.', 'success');
    } catch {
      toast('Unable to persist the audit export right now.', 'error');
    } finally {
      setPersistingArtifactKey(null);
    }
  };

  const savePrivacySnapshotArtifact = async () => {
    await persistArtifactRun({
      key: 'privacy-snapshot',
      name: 'Privacy and Attestation Snapshot',
      kind: 'privacy_attestation_snapshot',
      format: 'json',
      audience: 'compliance',
      summary: 'Persisted privacy budget and attestation snapshot for downstream review.',
      payload: {
        privacy_budget: privacyBudgetData,
        attestation: attestationData,
        failing_checks: failingAttestationChecks,
      },
      downloadName: 'privacy-attestation-snapshot.json',
      metadata: {
        failing_check_count: failingAttestationChecks.length,
        budget_remaining: privacyBudgetData?.budget_remaining ?? null,
      },
    });
  };

  const downloadResponseSnapshot = () => {
    const payload = {
      generated_at: new Date().toISOString(),
      response_target: activeResponseTarget || null,
      response_source: activeSource || null,
      stats: responseSnapshot,
      pending: filteredResponsePending,
      requests: filteredResponseRequests,
      audit_log: filteredResponseAudit,
    };
    downloadData(payload, 'response-approval-snapshot.json');
    toast('Response snapshot downloaded.', 'success');
  };

  const saveResponseSnapshotArtifact = async () => {
    await persistArtifactRun({
      key: 'response-snapshot',
      name: activeResponseTarget
        ? `Response Snapshot for ${activeResponseTarget}`
        : 'Response Approval Snapshot',
      kind: 'response_approval_snapshot',
      format: 'json',
      audience: 'analyst',
      summary: 'Persisted response approvals, pending actions, and audit evidence.',
      payload: {
        generated_at: new Date().toISOString(),
        response_target: activeResponseTarget || null,
        response_source: activeSource || null,
        stats: responseSnapshot,
        pending: filteredResponsePending,
        requests: filteredResponseRequests,
        audit_log: filteredResponseAudit,
      },
      downloadName: 'response-approval-snapshot.json',
      metadata: {
        response_target: activeResponseTarget || null,
        pending_approvals: filteredResponsePending.length,
        request_count: filteredResponseRequests.length,
      },
    });
  };

  const downloadRunArtifact = (run) => {
    const preview = run?.preview;
    if (preview && typeof preview === 'object' && !Array.isArray(preview)) {
      const payload = Object.prototype.hasOwnProperty.call(preview, 'payload')
        ? preview.payload
        : null;
      const downloadName = preview.download_name;
      const contentType = preview.content_type;
      if (downloadName && payload != null) {
        downloadData(payload, downloadName, contentType || undefined);
        return;
      }
    }
    downloadData(run.preview, `${run.kind}-${run.id}.json`);
  };

  const runPiiScan = async () => {
    if (!piiInput.trim()) {
      toast('Paste a sample before running a PII scan.', 'warning');
      return;
    }
    setScanningPii(true);
    try {
      const result = await api.piiScan(piiInput);
      setPiiResult(result);
      if (result?.has_pii) {
        toast('PII findings detected in the supplied sample.', 'success');
      } else {
        toast('No supported PII patterns were detected.', 'info');
      }
    } catch {
      toast('Unable to complete the PII scan.', 'error');
    } finally {
      setScanningPii(false);
    }
  };

  const runForgetWorkflow = async () => {
    if (!forgetEntity.trim()) {
      toast('Provide an entity id for the erase request.', 'warning');
      return;
    }
    if (forgetConfirm !== 'FORGET') {
      toast('Type FORGET to confirm the erase request.', 'warning');
      return;
    }
    setForgetting(true);
    try {
      const result = await api.gdprForget(forgetEntity.trim());
      setForgetResult(result);
      setForgetEntity('');
      setForgetConfirm('');
      toast('GDPR erase request completed.', 'success');
    } catch {
      toast('Unable to complete the GDPR erase request.', 'error');
    } finally {
      setForgetting(false);
    }
  };

  return (
    <div>
      <div className="tabs" role="tablist" aria-label="Reports & exports sections">
        {TABS.map((tab) => (
          <button
            key={tab}
            className={`tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => switchTab(tab)}
            role="tab"
            aria-selected={activeTab === tab}
          >
            {TAB_LABELS[tab]}
          </button>
        ))}
      </div>

      {hasActiveScope ? (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <div>
              <div className="card-title">Active report scope</div>
              <div className="hint" style={{ marginTop: 6 }}>
                Reporting stayed attached to the current case handoff so analysts can package
                evidence without losing where the request came from.
              </div>
            </div>
            <span className="badge badge-info">{formatScopeSource(activeSource)}</span>
          </div>
          <div style={{ marginTop: 16 }}>
            <SummaryGrid data={scopeSummary} limit={4} />
          </div>
          <div className="btn-group" style={{ marginTop: 16, flexWrap: 'wrap' }}>
            {activeCaseHref ? (
              <a className="btn btn-sm" href={activeCaseHref}>
                Open Case Drawer
              </a>
            ) : null}
            {activeIncidentHref ? (
              <a className="btn btn-sm" href={activeIncidentHref}>
                Open Incident Drawer
              </a>
            ) : null}
            {activeInvestigationHref ? (
              <a className="btn btn-sm" href={activeInvestigationHref}>
                Open Investigation
              </a>
            ) : null}
            <a className="btn btn-sm btn-primary" href={activeAssistantHref}>
              Ask Assistant
            </a>
          </div>
        </div>
      ) : null}

      <WorkflowGuidance
        title="Reporting Pivots"
        description="Use reporting context to jump back into the operational workflows that need tuning, response, or deeper evidence review."
        items={workflowItems}
      />

      {activeTab === 'templates' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Report Center
            </div>
            <div className="hint">
              Choose a reusable template, preview the payload, then create a run that stays visible
              in shared history.
            </div>
            <div className="summary-grid" style={{ marginTop: 16 }}>
              <div className="summary-card">
                <div className="summary-label">Templates</div>
                <div className="summary-value">{templates.length}</div>
                <div className="summary-meta">Reusable report presets for different audiences.</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Run History</div>
                <div className="summary-value">{runs.length}</div>
                <div className="summary-meta">
                  Operators can reopen previews and rerun the same scope.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Scheduled Delivery</div>
                <div className="summary-value">{schedules.length}</div>
                <div className="summary-meta">
                  Daily and weekly presets only in this first version.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Executive Summary</div>
                <div className="summary-value">
                  {execSum?.total_reports ?? storedReports.length}
                </div>
                <div className="summary-meta">
                  Existing reports remain available alongside the new center.
                </div>
              </div>
            </div>
          </div>

          <div className="triage-layout">
            <section className="triage-list">
              <div className="card">
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    alignItems: 'flex-start',
                    marginBottom: 12,
                  }}
                >
                  <div>
                    <div className="card-title">Reusable Templates</div>
                    <div className="hint" style={{ marginTop: 6 }}>
                      Keep the default library visible, or narrow to scoped presets for the active
                      investigation handoff.
                    </div>
                  </div>
                  <div className="btn-group">
                    {TEMPLATE_SCOPE_FILTERS.map((filter) => (
                      <button
                        key={filter}
                        className={`btn btn-sm ${templateScopeFilter === filter ? 'btn-primary' : ''}`}
                        disabled={filter === 'current' && !hasActiveScope}
                        onClick={() => setTemplateScopeFilter(filter)}
                      >
                        {filter === 'all'
                          ? 'All'
                          : filter === 'current'
                            ? 'Current Scope'
                            : 'Unscoped'}
                      </button>
                    ))}
                  </div>
                </div>
                <div style={{ display: 'grid', gap: 12 }}>
                  {templates.length === 0 ? (
                    <div className="empty">
                      {templateScopeFilter === 'current' && hasActiveScope
                        ? 'No scoped templates match the active investigation context yet.'
                        : templateScopeFilter === 'current'
                          ? 'Select a case or investigation scope to filter scoped templates.'
                          : templateScopeFilter === 'unscoped'
                            ? 'No unscoped templates match the current filters.'
                            : 'No report template is available yet.'}
                    </div>
                  ) : (
                    templates.map((template) => (
                      <button
                        key={template.id}
                        className="card"
                        style={{
                          textAlign: 'left',
                          padding: 16,
                          borderColor:
                            activeTemplateId === template.id ? 'var(--accent)' : 'var(--border)',
                          background:
                            activeTemplateId === template.id ? 'var(--bg)' : 'var(--bg-card)',
                        }}
                        onClick={() => setSelectedTemplateId(template.id)}
                      >
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            gap: 12,
                            alignItems: 'flex-start',
                          }}
                        >
                          <div>
                            <div className="row-primary">{template.name}</div>
                            <div className="row-secondary">{template.description}</div>
                          </div>
                          <span className="badge badge-info">{template.audience}</span>
                        </div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                          <span className="badge badge-info">{template.kind}</span>
                          <span className="badge badge-info">{template.scope}</span>
                          <span className="badge badge-info">{template.format}</span>
                          {describeExecutionContext(template.execution_context).map((label) => (
                            <span key={`${template.id}-${label}`} className="badge badge-info">
                              {label}
                            </span>
                          ))}
                        </div>
                      </button>
                    ))
                  )}
                </div>
              </div>
            </section>

            <aside className="triage-detail">
              <div className="card">
                {!selectedTemplate ? (
                  <div className="empty">
                    {templateScopeFilter === 'current' && hasActiveScope
                      ? 'No scoped template is selected because this investigation does not have a saved preset yet.'
                      : 'No report template is available yet.'}
                  </div>
                ) : (
                  <>
                    <div className="detail-hero">
                      <div>
                        <div className="detail-hero-title">{selectedTemplate.name}</div>
                        <div className="detail-hero-copy">{selectedTemplate.description}</div>
                      </div>
                      <span className="badge badge-info">{selectedTemplate.status}</span>
                    </div>

                    <div className="summary-grid" style={{ marginTop: 16 }}>
                      <div className="summary-card">
                        <div className="summary-label">Audience</div>
                        <div className="summary-value">{selectedTemplate.audience}</div>
                        <div className="summary-meta">Who this report is designed for.</div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Scope</div>
                        <div className="summary-value">{selectedTemplate.scope}</div>
                        <div className="summary-meta">
                          Current report scope or dataset grouping.
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Format</div>
                        <div className="summary-value">{selectedTemplate.format}</div>
                        <div className="summary-meta">
                          Initial export format used for preview and download.
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Last Run</div>
                        <div className="summary-value">
                          {selectedTemplate.last_run_at
                            ? formatRelativeTime(selectedTemplate.last_run_at)
                            : 'Never'}
                        </div>
                        <div className="summary-meta">
                          {selectedTemplate.last_run_at
                            ? formatDateTime(selectedTemplate.last_run_at)
                            : 'Run the template to seed history.'}
                        </div>
                      </div>
                    </div>

                    <div className="detail-callout" style={{ marginTop: 16 }}>
                      <strong>Preview-first flow</strong>
                      <div style={{ marginTop: 6 }}>
                        Operators see the expected summary and size before the run lands in history,
                        so exports stop feeling like one-way button clicks.
                      </div>
                    </div>

                    <div className="btn-group" style={{ marginTop: 16 }}>
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={() => createRun(selectedTemplate)}
                      >
                        Create Run
                      </button>
                      <button
                        className="btn btn-sm"
                        onClick={() =>
                          downloadData(previewPayload, `${selectedTemplate.kind}-preview.json`)
                        }
                      >
                        Download Preview
                      </button>
                      <button className="btn btn-sm" onClick={() => switchTab('delivery')}>
                        Schedule Delivery
                      </button>
                      {hasActiveScope ? (
                        <button
                          className="btn btn-sm"
                          disabled={savingScopedTemplate}
                          onClick={() => saveScopedTemplate(selectedTemplate)}
                        >
                          {savingScopedTemplate
                            ? 'Saving Scoped Template...'
                            : 'Save As Scoped Template'}
                        </button>
                      ) : null}
                    </div>

                    {previewPayload && (
                      <div style={{ marginTop: 16 }}>
                        <SummaryGrid data={previewPayload} limit={8} />
                        <JsonDetails data={previewPayload} label="Preview payload" />
                      </div>
                    )}
                  </>
                )}
              </div>
            </aside>
          </div>
        </>
      )}

      {activeTab === 'runs' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Run History</span>
              <button className="btn btn-sm" onClick={reloadReportHistory}>
                Refresh
              </button>
            </div>
            {runs.length === 0 ? (
              <div className="empty">
                {hasActiveScope
                  ? 'No report runs match the active investigation scope yet.'
                  : 'No report runs yet. Create one from the templates tab.'}
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Kind</th>
                      <th>Scope</th>
                      <th>Audience</th>
                      <th>Ran</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((run) => (
                      <tr key={run.id}>
                        <td>
                          <div className="row-primary">{run.name}</div>
                          <div className="row-secondary">{run.summary}</div>
                        </td>
                        <td>{run.kind}</td>
                        <td>
                          {describeExecutionContext(run.execution_context).length > 0 ? (
                            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                              {describeExecutionContext(run.execution_context).map((label) => (
                                <span key={`${run.id}-${label}`} className="badge badge-info">
                                  {label}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="row-secondary">Global</span>
                          )}
                        </td>
                        <td>{run.audience}</td>
                        <td>{run.last_run_at ? formatDateTime(run.last_run_at) : '—'}</td>
                        <td>
                          <span
                            className={`badge ${run.status === 'completed' ? 'badge-ok' : run.status === 'failed' ? 'badge-err' : 'badge-warn'}`}
                          >
                            {run.status}
                          </span>
                        </td>
                        <td>
                          <div className="btn-group">
                            <button className="btn btn-sm" onClick={() => downloadRunArtifact(run)}>
                              Download
                            </button>
                            <button className="btn btn-sm" onClick={() => rerun(run)}>
                              Run Again
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <div className="card-title">Stored Report Artifacts</div>
                <div className="hint" style={{ marginTop: 6 }}>
                  Persisted report-run previews keep execution context, so you can reopen artifacts
                  by case, incident, or investigation handoff.
                </div>
              </div>
              <div className="btn-group">
                {ARTIFACT_SCOPE_FILTERS.map((filter) => (
                  <button
                    key={filter}
                    className={`btn btn-sm ${artifactScopeFilter === filter ? 'btn-primary' : ''}`}
                    disabled={filter === 'current' && !hasActiveScope}
                    onClick={() => setArtifactScopeFilter(filter)}
                  >
                    {filter === 'all' ? 'All' : filter === 'current' ? 'Current Scope' : 'Unscoped'}
                  </button>
                ))}
              </div>
            </div>
            <div className="form-group" style={{ marginTop: 16 }}>
              <label className="form-label" htmlFor="artifact-search">
                Artifact Search
              </label>
              <input
                id="artifact-search"
                className="form-input"
                placeholder="Run id, template name, report type, or scope label"
                value={artifactSearch}
                onChange={(event) => setArtifactSearch(event.target.value)}
              />
            </div>

            <div style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 10 }}>
                Scoped Artifact Library
              </div>
              {scopedArtifactRuns.length === 0 ? (
                <div className="empty">
                  {artifactScopeFilter === 'current' && hasActiveScope
                    ? 'No persisted report-run artifacts match the current investigation scope yet.'
                    : artifactScopeFilter === 'current'
                      ? 'Select a case or investigation scope to filter scoped artifacts.'
                      : 'No persisted report-run artifacts match the current search.'}
                </div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Scope</th>
                        <th>Generated</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scopedArtifactRuns.map((run) => (
                        <tr key={`artifact-${run.id}`}>
                          <td>{run.id}</td>
                          <td>
                            <div className="row-primary">{run.name}</div>
                            <div className="row-secondary">{run.summary}</div>
                          </td>
                          <td>{run.kind}</td>
                          <td>
                            {describeExecutionContext(run.execution_context).length > 0 ? (
                              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                                {describeExecutionContext(run.execution_context).map((label) => (
                                  <span
                                    key={`${run.id}-artifact-${label}`}
                                    className="badge badge-info"
                                  >
                                    {label}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="row-secondary">Global</span>
                            )}
                          </td>
                          <td>{run.last_run_at ? formatDateTime(run.last_run_at) : '—'}</td>
                          <td>
                            <div className="btn-group">
                              <button
                                className="btn btn-sm"
                                onClick={() =>
                                  downloadData(run.preview, `${run.kind}-${run.id}.json`)
                                }
                              >
                                Download
                              </button>
                              <button className="btn btn-sm" onClick={() => rerun(run)}>
                                Run Again
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div style={{ marginTop: 20 }}>
              <div className="card-title" style={{ marginBottom: 10 }}>
                Context-Aware Backend Reports
              </div>
              <div className="hint" style={{ marginBottom: 10 }}>
                Backend reports with attached execution context can now be filtered by the active
                case, incident, or investigation without republishing them into a separate run.
              </div>
              {scopedBackendReports.length === 0 ? (
                <div className="empty">
                  {artifactScopeFilter === 'current' && hasActiveScope
                    ? 'No backend reports are attached to the current investigation scope yet.'
                    : 'No context-aware backend reports match the current search.'}
                </div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Scope</th>
                        <th>Generated</th>
                        <th>Alerts</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scopedBackendReports.map((report) => (
                        <tr key={`scoped-report-${report.id}`}>
                          <td>{report.id}</td>
                          <td>{report.report_type || report.type || 'report'}</td>
                          <td>
                            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                              {describeExecutionContext(report.execution_context).map((label) => (
                                <span key={`${report.id}-${label}`} className="badge badge-info">
                                  {label}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td>{formatDateTime(report.generated_at)}</td>
                          <td>{report.alert_count ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div style={{ marginTop: 20 }}>
              <div className="card-title" style={{ marginBottom: 10 }}>
                Legacy Backend Reports
              </div>
              <div className="hint" style={{ marginBottom: 10 }}>
                These older stored reports do not carry execution context yet, so they stay
                searchable but remain unscoped until they are republished through the report center.
              </div>
              {hasActiveScope ? (
                <div className="hint" style={{ marginBottom: 10 }}>
                  Republish a legacy report to attach the current case handoff and move it into the
                  scoped artifact library.
                </div>
              ) : (
                <div className="hint" style={{ marginBottom: 10 }}>
                  Select a case, incident, or investigation scope above to republish these legacy
                  reports into the scoped artifact library.
                </div>
              )}
              {legacyStoredReports.length === 0 ? (
                <div className="empty">No legacy backend reports match the current search.</div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Generated</th>
                        <th>Alerts</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {legacyStoredReports.map((report) => (
                        <tr key={report.id}>
                          <td>{report.id}</td>
                          <td>{report.report_type || report.type || 'report'}</td>
                          <td>{formatDateTime(report.generated_at)}</td>
                          <td>{report.alert_count ?? '—'}</td>
                          <td>
                            <div className="btn-group">
                              <button
                                className="btn btn-sm"
                                disabled={
                                  !hasActiveScope || String(attachingLegacyId) === String(report.id)
                                }
                                onClick={() => attachLegacyReportContext(report)}
                              >
                                {String(attachingLegacyId) === String(report.id)
                                  ? 'Attaching...'
                                  : 'Attach Current Scope'}
                              </button>
                              <button
                                className="btn btn-sm"
                                disabled={
                                  !hasActiveScope ||
                                  String(republishingLegacyId) === String(report.id)
                                }
                                onClick={() => republishLegacyReport(report)}
                              >
                                {String(republishingLegacyId) === String(report.id)
                                  ? 'Republishing...'
                                  : 'Republish To Scope'}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {activeTab === 'delivery' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Create Delivery Schedule
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="schedule-name">
                Schedule Name
              </label>
              <input
                id="schedule-name"
                className="form-input"
                value={scheduleForm.name}
                onChange={(event) =>
                  setScheduleForm((form) => ({ ...form, name: event.target.value }))
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="schedule-kind">
                Template Kind
              </label>
              <select
                id="schedule-kind"
                className="form-select"
                value={scheduleForm.kind}
                onChange={(event) =>
                  setScheduleForm((form) => ({ ...form, kind: event.target.value }))
                }
              >
                {templates.map((template) => (
                  <option key={template.id} value={template.kind}>
                    {template.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="schedule-cadence">
                Cadence
              </label>
              <select
                id="schedule-cadence"
                className="form-select"
                value={scheduleForm.cadence}
                onChange={(event) =>
                  setScheduleForm((form) => ({ ...form, cadence: event.target.value }))
                }
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="schedule-target">
                Target
              </label>
              <input
                id="schedule-target"
                className="form-input"
                value={scheduleForm.target}
                onChange={(event) =>
                  setScheduleForm((form) => ({ ...form, target: event.target.value }))
                }
              />
            </div>
            <button className="btn btn-sm btn-primary" onClick={createSchedule}>
              Save Schedule
            </button>
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Delivery History
            </div>
            {schedules.length === 0 ? (
              <div className="empty">
                {hasActiveScope
                  ? 'No saved schedules match the active investigation scope yet.'
                  : 'No schedules yet. Create a daily or weekly preset from the left.'}
              </div>
            ) : (
              <div style={{ display: 'grid', gap: 12 }}>
                {schedules.map((schedule) => (
                  <div
                    key={schedule.id}
                    style={{ border: '1px solid var(--border)', borderRadius: 12, padding: 14 }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        gap: 12,
                        alignItems: 'flex-start',
                      }}
                    >
                      <div>
                        <div className="row-primary">{schedule.name}</div>
                        <div className="row-secondary">
                          {schedule.kind} • {schedule.cadence} • {schedule.target}
                        </div>
                        {describeExecutionContext(schedule.execution_context).length > 0 ? (
                          <div
                            style={{
                              display: 'flex',
                              gap: 6,
                              flexWrap: 'wrap',
                              marginTop: 8,
                            }}
                          >
                            {describeExecutionContext(schedule.execution_context).map((label) => (
                              <span key={`${schedule.id}-${label}`} className="badge badge-info">
                                {label}
                              </span>
                            ))}
                          </div>
                        ) : null}
                      </div>
                      <span
                        className={`badge ${schedule.status === 'active' ? 'badge-ok' : 'badge-warn'}`}
                      >
                        {schedule.status}
                      </span>
                    </div>
                    <div className="hint" style={{ marginTop: 10 }}>
                      Next run{' '}
                      {schedule.next_run_at
                        ? `${formatRelativeTime(schedule.next_run_at)} (${formatDateTime(schedule.next_run_at)})`
                        : 'not scheduled'}
                      .
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Response Approval Snapshot
            </div>
            <div className="hint" style={{ marginBottom: 12 }}>
              Package pending approvals, request posture, and response audit context into a
              delivery-ready artifact without leaving the report center.
            </div>
            <div className="btn-group" style={{ marginBottom: 12 }}>
              <button className="btn btn-sm" onClick={refreshDeliveryContext}>
                Refresh Response
              </button>
              <button className="btn btn-sm" onClick={downloadResponseSnapshot}>
                Download Snapshot
              </button>
              <button
                className="btn btn-sm btn-primary"
                disabled={persistingArtifactKey === 'response-snapshot'}
                onClick={saveResponseSnapshotArtifact}
              >
                {persistingArtifactKey === 'response-snapshot'
                  ? 'Saving Response Artifact...'
                  : 'Save Response Artifact'}
              </button>
            </div>
            <SummaryGrid data={responseSnapshot} limit={8} />
            {filteredResponseRequests.length > 0 ? (
              <div className="table-wrap" style={{ marginTop: 16 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Action</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Requester</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredResponseRequests.slice(0, 5).map((request) => (
                      <tr key={request.id}>
                        <td>{request.action_label || request.action || 'Action'}</td>
                        <td>{request.target_hostname || request.target?.hostname || '—'}</td>
                        <td>{request.status || '—'}</td>
                        <td>{request.requested_by || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty" style={{ marginTop: 16 }}>
                No response requests match the current target scope.
              </div>
            )}
            <JsonDetails
              data={{
                target: activeResponseTarget || null,
                pending: filteredResponsePending,
                requests: filteredResponseRequests,
                audit_log: filteredResponseAudit,
              }}
              label="Response snapshot detail"
            />
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Executive Summary Snapshot
            </div>
            <SummaryGrid data={execSum} limit={10} />
            <JsonDetails data={execSum} label="Executive summary detail" />
          </div>
        </div>
      )}

      {activeTab === 'compliance' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Compliance Snapshot</span>
              <div className="btn-group">
                <button className="btn btn-sm" onClick={refreshEvidenceContext}>
                  Refresh
                </button>
                <button
                  className="btn btn-sm btn-primary"
                  disabled={!complianceSnapshotTemplate}
                  onClick={() => createRun(complianceSnapshotTemplate)}
                >
                  Queue Snapshot Run
                </button>
              </div>
            </div>
            <div className="hint" style={{ marginTop: 12 }}>
              Review framework scores, inspect control findings, and export operator-ready evidence
              without leaving the console.
            </div>
            {complianceSummaryError || complianceReportsError ? (
              <div className="empty" style={{ marginTop: 16 }}>
                Unable to load compliance reporting right now.
              </div>
            ) : complianceSummaryLoading || complianceReportsLoading ? (
              <div className="hint" style={{ marginTop: 16 }}>
                Loading compliance coverage and framework findings.
              </div>
            ) : (
              <div style={{ marginTop: 16 }}>
                <SummaryGrid data={complianceOverview} limit={5} />
                {complianceSummaryFrameworks.length > 0 && (
                  <div className="table-wrap" style={{ marginTop: 16 }}>
                    <table>
                      <thead>
                        <tr>
                          <th>Framework</th>
                          <th>Score</th>
                          <th>Passed</th>
                          <th>Failed</th>
                          <th>Total</th>
                        </tr>
                      </thead>
                      <tbody>
                        {complianceSummaryFrameworks.map((framework) => (
                          <tr key={framework.framework}>
                            <td>{framework.framework}</td>
                            <td>{formatPercent(framework.score)}</td>
                            <td>{framework.passed ?? 0}</td>
                            <td>{framework.failed ?? 0}</td>
                            <td>{framework.total ?? 0}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="triage-layout">
            <section className="triage-list">
              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Frameworks
                </div>
                {complianceReports.length === 0 ? (
                  <div className="empty">No framework reports are available yet.</div>
                ) : (
                  <div style={{ display: 'grid', gap: 12 }}>
                    {complianceReports.map((report) => (
                      <button
                        key={report.framework_id}
                        className="card"
                        style={{
                          textAlign: 'left',
                          padding: 16,
                          borderColor:
                            activeComplianceId === report.framework_id
                              ? 'var(--accent)'
                              : 'var(--border)',
                          background:
                            activeComplianceId === report.framework_id
                              ? 'var(--bg)'
                              : 'var(--bg-card)',
                        }}
                        onClick={() => setSelectedComplianceId(report.framework_id)}
                      >
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            gap: 12,
                            alignItems: 'flex-start',
                          }}
                        >
                          <div>
                            <div className="row-primary">{report.framework_name}</div>
                            <div className="row-secondary">
                              {report.total_controls ?? 0} controls evaluated
                            </div>
                          </div>
                          <span
                            className={`badge ${report.failed > 0 ? 'badge-warn' : 'badge-ok'}`}
                          >
                            {formatPercent(report.score_percent)}
                          </span>
                        </div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                          <span className="badge badge-info">Passed {report.passed ?? 0}</span>
                          <span className="badge badge-info">Failed {report.failed ?? 0}</span>
                          <span className="badge badge-info">
                            Review {report.manual_review ?? 0}
                          </span>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </section>

            <aside className="triage-detail">
              <div className="card">
                {!selectedReport ? (
                  <div className="empty">
                    Choose a framework to inspect its evidence and findings.
                  </div>
                ) : (
                  <>
                    <div className="detail-hero">
                      <div>
                        <div className="detail-hero-title">{selectedReport.framework_name}</div>
                        <div className="detail-hero-copy">
                          Generated{' '}
                          {selectedReport.generated_at
                            ? formatDateTime(selectedReport.generated_at)
                            : 'Not available'}
                        </div>
                      </div>
                      <span
                        className={`badge ${selectedReport.failed > 0 ? 'badge-warn' : 'badge-ok'}`}
                      >
                        {formatPercent(selectedReport.score_percent)}
                      </span>
                    </div>

                    <div style={{ marginTop: 16 }}>
                      <SummaryGrid
                        data={{
                          total_controls: selectedReport.total_controls,
                          passed: selectedReport.passed,
                          failed: selectedReport.failed,
                          manual_review: selectedReport.manual_review,
                          not_applicable: selectedReport.not_applicable,
                        }}
                        limit={5}
                      />
                    </div>

                    <div className="detail-callout" style={{ marginTop: 16 }}>
                      <strong>Operator action bias</strong>
                      <div style={{ marginTop: 6 }}>
                        Prioritize failed controls first, then resolve manual review gaps before the
                        next evidence package leaves the team.
                      </div>
                    </div>

                    <div className="btn-group" style={{ marginTop: 16 }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => downloadComplianceJson(selectedReport)}
                      >
                        Download JSON
                      </button>
                      <button
                        className="btn btn-sm"
                        disabled={
                          persistingArtifactKey === `compliance-json-${selectedReport.framework_id}`
                        }
                        onClick={() => saveComplianceJsonArtifact(selectedReport)}
                      >
                        {persistingArtifactKey === `compliance-json-${selectedReport.framework_id}`
                          ? 'Saving JSON Artifact...'
                          : 'Save JSON Artifact'}
                      </button>
                      <button
                        className="btn btn-sm"
                        onClick={() => downloadComplianceMarkdown(selectedReport)}
                      >
                        Download Markdown
                      </button>
                      <button
                        className="btn btn-sm"
                        disabled={
                          persistingArtifactKey ===
                          `compliance-markdown-${selectedReport.framework_id}`
                        }
                        onClick={() => saveComplianceMarkdownArtifact(selectedReport)}
                      >
                        {persistingArtifactKey ===
                        `compliance-markdown-${selectedReport.framework_id}`
                          ? 'Saving Markdown Artifact...'
                          : 'Save Markdown Artifact'}
                      </button>
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={() => downloadEvidenceBundle(selectedReport)}
                      >
                        Download Evidence Bundle
                      </button>
                      <button
                        className="btn btn-sm"
                        disabled={
                          persistingArtifactKey === `evidence-bundle-${selectedReport.framework_id}`
                        }
                        onClick={() => saveEvidenceBundleArtifact(selectedReport)}
                      >
                        {persistingArtifactKey === `evidence-bundle-${selectedReport.framework_id}`
                          ? 'Saving Evidence Artifact...'
                          : 'Save Evidence Artifact'}
                      </button>
                    </div>

                    {failedFindings.length > 0 && (
                      <div className="card" style={{ marginTop: 16 }}>
                        <div className="card-title" style={{ marginBottom: 12 }}>
                          Controls Requiring Remediation
                        </div>
                        <div style={{ display: 'grid', gap: 10 }}>
                          {failedFindings.map((finding) => (
                            <div
                              key={`${finding.control_id}-remediation`}
                              style={{
                                border: '1px solid var(--border)',
                                borderRadius: 12,
                                padding: 14,
                              }}
                            >
                              <div className="row-primary">{finding.control_id}</div>
                              <div className="row-secondary">{finding.title}</div>
                              <div className="hint" style={{ marginTop: 8 }}>
                                {finding.remediation || 'No remediation guidance supplied.'}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {reviewFindings.length > 0 && (
                      <div className="card" style={{ marginTop: 16 }}>
                        <div className="card-title" style={{ marginBottom: 12 }}>
                          Manual Review Queue
                        </div>
                        <div style={{ display: 'grid', gap: 10 }}>
                          {reviewFindings.map((finding) => (
                            <div
                              key={`${finding.control_id}-review`}
                              style={{
                                border: '1px solid var(--border)',
                                borderRadius: 12,
                                padding: 14,
                              }}
                            >
                              <div className="row-primary">{finding.control_id}</div>
                              <div className="row-secondary">{finding.title}</div>
                              <div className="hint" style={{ marginTop: 8 }}>
                                {finding.evidence || 'Awaiting operator-supplied evidence.'}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="card" style={{ marginTop: 16 }}>
                      <div className="card-title" style={{ marginBottom: 12 }}>
                        Control Findings
                      </div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>Control</th>
                              <th>Status</th>
                              <th>Evidence</th>
                              <th>Remediation</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(Array.isArray(selectedReport.findings)
                              ? selectedReport.findings
                              : []
                            ).map((finding) => (
                              <tr key={finding.control_id}>
                                <td>
                                  <div className="row-primary">{finding.control_id}</div>
                                  <div className="row-secondary">{finding.title}</div>
                                </td>
                                <td>
                                  <span className={`badge ${findingBadgeClass(finding.status)}`}>
                                    {findingStatusLabel(finding.status)}
                                  </span>
                                </td>
                                <td>{finding.evidence || 'No evidence captured.'}</td>
                                <td>{finding.remediation || 'No remediation required.'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <JsonDetails data={selectedReport} label="Framework report payload" />
                    </div>
                  </>
                )}
              </div>
            </aside>
          </div>
        </>
      )}

      {activeTab === 'evidence' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Alert Export Formats</span>
              <button className="btn btn-sm" onClick={refreshEvidenceContext}>
                Refresh Context
              </button>
            </div>
            <div className="hint" style={{ marginTop: 12 }}>
              Use backend-native SIEM export formats instead of recreating mappings client-side.
            </div>
            <div style={{ marginTop: 16 }}>
              <SummaryGrid data={evidenceOverview} limit={5} />
            </div>
            <div className="form-group" style={{ marginTop: 16 }}>
              <label className="form-label" htmlFor="alert-export-format">
                Export Format
              </label>
              <select
                id="alert-export-format"
                className="form-select"
                value={alertExportFormat}
                onChange={(event) => setAlertExportFormat(event.target.value)}
              >
                {ALERT_EXPORT_FORMATS.map((format) => (
                  <option key={format.id} value={format.id}>
                    {format.label}
                  </option>
                ))}
              </select>
              <div className="hint" style={{ marginTop: 8 }}>
                {activeAlertExport.description}
              </div>
            </div>
            <div className="btn-group" style={{ marginTop: 16 }}>
              <button
                className="btn btn-sm btn-primary"
                disabled={exportingAlerts}
                onClick={exportAlerts}
              >
                {exportingAlerts ? 'Exporting...' : 'Download Alert Export'}
              </button>
              <button
                className="btn btn-sm"
                disabled={persistingArtifactKey === 'alert-export'}
                onClick={saveAlertExportArtifact}
              >
                {persistingArtifactKey === 'alert-export'
                  ? 'Saving Alert Artifact...'
                  : 'Save Alert Artifact'}
              </button>
              <button
                className="btn btn-sm"
                disabled={!auditExportTemplate}
                onClick={() => createRun(auditExportTemplate)}
              >
                Queue Audit Export Run
              </button>
            </div>
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Audit Log Evidence Export
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="audit-query-filter">
                Search Query
              </label>
              <input
                id="audit-query-filter"
                className="form-input"
                placeholder="Endpoint, IP, auth state, or status code"
                value={auditFilters.q}
                onChange={(event) =>
                  setAuditFilters((filters) => ({ ...filters, q: event.target.value }))
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="audit-method-filter">
                HTTP Method
              </label>
              <select
                id="audit-method-filter"
                className="form-select"
                value={auditFilters.method}
                onChange={(event) =>
                  setAuditFilters((filters) => ({ ...filters, method: event.target.value }))
                }
              >
                <option value="">Any method</option>
                {COMMON_HTTP_METHODS.map((method) => (
                  <option key={method} value={method}>
                    {method}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="audit-status-filter">
                Status Filter
              </label>
              <input
                id="audit-status-filter"
                className="form-input"
                placeholder="401 or 4xx"
                value={auditFilters.status}
                onChange={(event) =>
                  setAuditFilters((filters) => ({ ...filters, status: event.target.value }))
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="audit-auth-filter">
                Auth State
              </label>
              <select
                id="audit-auth-filter"
                className="form-select"
                value={auditFilters.auth}
                onChange={(event) =>
                  setAuditFilters((filters) => ({ ...filters, auth: event.target.value }))
                }
              >
                <option value="">Any auth state</option>
                <option value="authenticated">Authenticated</option>
                <option value="anonymous">Anonymous</option>
              </select>
            </div>
            <button
              className="btn btn-sm btn-primary"
              disabled={exportingAudit}
              onClick={exportAuditLog}
            >
              {exportingAudit ? 'Exporting...' : 'Download Audit CSV'}
            </button>
            <button
              className="btn btn-sm"
              disabled={persistingArtifactKey === 'audit-export'}
              onClick={saveAuditLogArtifact}
              style={{ marginTop: 12 }}
            >
              {persistingArtifactKey === 'audit-export'
                ? 'Saving Audit Artifact...'
                : 'Save Audit Artifact'}
            </button>
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Evidence Bundle Preview
            </div>
            {!selectedReport ? (
              <div className="empty">Select a framework in the compliance tab first.</div>
            ) : (
              <>
                <SummaryGrid
                  data={{
                    framework: selectedReport.framework_name,
                    score: formatPercent(selectedReport.score_percent),
                    failed_controls: selectedReport.failed,
                    privacy_budget: privacyBudgetData?.budget_remaining ?? 'Unavailable',
                    attestation_ready: attestationData?.passed ? 'Yes' : 'No',
                  }}
                  limit={5}
                />
                <div className="hint" style={{ marginTop: 12 }}>
                  The bundle includes the selected framework report, markdown summary, attestation
                  checks, privacy budget, and current report-center inventory counts.
                </div>
                <div className="btn-group" style={{ marginTop: 16 }}>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => downloadEvidenceBundle(selectedReport)}
                  >
                    Download Bundle
                  </button>
                  <button
                    className="btn btn-sm"
                    disabled={
                      persistingArtifactKey === `evidence-bundle-${selectedReport.framework_id}`
                    }
                    onClick={() => saveEvidenceBundleArtifact(selectedReport)}
                  >
                    {persistingArtifactKey === `evidence-bundle-${selectedReport.framework_id}`
                      ? 'Saving Bundle Artifact...'
                      : 'Save Bundle Artifact'}
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() => downloadComplianceMarkdown(selectedReport)}
                  >
                    Download Markdown
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {activeTab === 'privacy' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Privacy Budget and Attestation</span>
              <button className="btn btn-sm" onClick={refreshEvidenceContext}>
                Refresh
              </button>
            </div>
            {privacyBudgetError || attestationError ? (
              <div className="empty" style={{ marginTop: 16 }}>
                Unable to load privacy or attestation state.
              </div>
            ) : privacyBudgetLoading || attestationLoading ? (
              <div className="hint" style={{ marginTop: 16 }}>
                Loading privacy budget and attestation checks.
              </div>
            ) : (
              <>
                <div style={{ marginTop: 16 }}>
                  <SummaryGrid data={privacyOverview} limit={4} />
                </div>
                {failingAttestationChecks.length > 0 && (
                  <div className="table-wrap" style={{ marginTop: 16 }}>
                    <table>
                      <thead>
                        <tr>
                          <th>Check</th>
                          <th>Status</th>
                          <th>Detail</th>
                        </tr>
                      </thead>
                      <tbody>
                        {failingAttestationChecks.map((check) => (
                          <tr key={check.name}>
                            <td>{check.name}</td>
                            <td>
                              <span className="badge badge-warn">Missing</span>
                            </td>
                            <td>{check.detail || 'No detail supplied.'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <JsonDetails
                  data={{ privacy_budget: privacyBudgetData, attestation: attestationData }}
                  label="Privacy and attestation payload"
                />
                <div className="btn-group" style={{ marginTop: 16 }}>
                  <button
                    className="btn btn-sm"
                    disabled={persistingArtifactKey === 'privacy-snapshot'}
                    onClick={savePrivacySnapshotArtifact}
                  >
                    {persistingArtifactKey === 'privacy-snapshot'
                      ? 'Saving Privacy Artifact...'
                      : 'Save Privacy Snapshot'}
                  </button>
                </div>
              </>
            )}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              PII Scan
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="pii-scan-input">
                Sample Content
              </label>
              <textarea
                id="pii-scan-input"
                className="form-input"
                rows={8}
                placeholder="Paste log lines, case notes, or outbound payloads before sharing them."
                value={piiInput}
                onChange={(event) => setPiiInput(event.target.value)}
              />
            </div>
            <div className="btn-group">
              <button
                className="btn btn-sm btn-primary"
                disabled={scanningPii}
                onClick={runPiiScan}
              >
                {scanningPii ? 'Scanning...' : 'Run PII Scan'}
              </button>
              <button
                className="btn btn-sm"
                disabled={!piiResult}
                onClick={() =>
                  downloadData(
                    {
                      scanned_at: new Date().toISOString(),
                      sample_length: piiInput.length,
                      result: piiResult,
                    },
                    'pii-scan-findings.json',
                  )
                }
              >
                Download Findings
              </button>
            </div>
            {piiResult && (
              <div style={{ marginTop: 16 }}>
                <SummaryGrid
                  data={{
                    has_pii: piiResult.has_pii ? 'Yes' : 'No',
                    finding_count: piiResult.finding_count ?? 0,
                    categories: Array.isArray(piiResult.categories)
                      ? piiResult.categories.join(', ')
                      : 'None',
                  }}
                  limit={3}
                />
                <JsonDetails data={piiResult} label="PII scan result" />
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              GDPR Right to Forget
            </div>
            <div className="detail-callout" style={{ marginBottom: 16 }}>
              <strong>Destructive workflow</strong>
              <div style={{ marginTop: 6 }}>
                This action permanently purges records for the supplied entity identifier. Use the
                confirmation phrase before proceeding.
              </div>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="forget-entity-id">
                Entity Id
              </label>
              <input
                id="forget-entity-id"
                className="form-input"
                placeholder="user@example.com or internal subject id"
                value={forgetEntity}
                onChange={(event) => setForgetEntity(event.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="forget-confirm">
                Confirmation Phrase
              </label>
              <input
                id="forget-confirm"
                className="form-input"
                placeholder="Type FORGET"
                value={forgetConfirm}
                onChange={(event) => setForgetConfirm(event.target.value)}
              />
            </div>
            <button
              className="btn btn-sm btn-primary"
              disabled={forgetting}
              onClick={runForgetWorkflow}
            >
              {forgetting ? 'Erasing...' : 'Submit Erase Request'}
            </button>
            {forgetResult && (
              <div style={{ marginTop: 16 }}>
                <SummaryGrid
                  data={{
                    status: forgetResult.status,
                    entity_id: forgetResult.entity_id,
                    records_purged: forgetResult.records_purged,
                    completed_at: forgetResult.timestamp
                      ? formatDateTime(forgetResult.timestamp)
                      : 'Unknown',
                  }}
                  limit={4}
                />
                <div className="btn-group" style={{ marginTop: 12 }}>
                  <button
                    className="btn btn-sm"
                    onClick={() => downloadData(forgetResult, 'gdpr-forget-receipt.json')}
                  >
                    Download Receipt
                  </button>
                </div>
                <JsonDetails data={forgetResult} label="Erase request receipt" />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

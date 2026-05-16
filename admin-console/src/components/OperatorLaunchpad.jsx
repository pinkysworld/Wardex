import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import * as api from '../api.js';
import { useApiGroup, useRole, useToast } from '../hooks.jsx';
import { downloadData, formatDateTime, formatLabel } from './operatorUtils.js';
import {
  evidenceBadge,
  evidenceFreshness,
  evidenceMode,
  evidenceNeedsAttention,
  freshnessDetail,
  isBlockingStatus,
  isReadyStatus,
  signalBadge,
  statusBadge,
} from './operatorTrustUtils.js';

const READINESS_STEPS = [
  {
    key: 'first_agent_online',
    title: 'Collector connected',
    fallback: 'No collector heartbeat yet',
    href: '/fleet',
  },
  {
    key: 'telemetry_flowing',
    title: 'Telemetry flowing',
    fallback: 'Telemetry has not reached the console',
    href: '/monitor',
  },
  {
    key: 'first_alert_visible',
    title: 'First alert visible',
    fallback: 'No alert available for the guided incident path',
    href: '/monitor',
  },
  {
    key: 'intel_source_healthy',
    title: 'Intel source healthy',
    fallback: 'Threat intel source still needs validation',
    href: '/infrastructure',
  },
  {
    key: 'response_approval_dry_run_completed',
    title: 'Response dry-run complete',
    fallback: 'Approval and rollback dry-run is pending',
    href: '/soc?focus=response',
  },
];

const COMMAND_ACCELERATORS = [
  {
    title: 'Connect agent drawer',
    href: '/fleet?fleetTab=updates&updatesPanel=install#connect-agent-drawer',
    shortcut: 'Cmd',
  },
  { title: 'Morning brief', href: '/launchpad#morning-brief', shortcut: 'Cmd' },
  { title: 'Guided incident', href: '/launchpad#guided-incident-path', shortcut: 'Cmd' },
  { title: 'Open SOC queue', href: '/soc#queue', shortcut: 'Cmd' },
  { title: 'Response simulator', href: '/launchpad#response-simulator', shortcut: 'Cmd' },
  { title: 'Fleet drilldown', href: '/launchpad#fleet-health-drilldown', shortcut: 'Cmd' },
  { title: 'Evidence freshness', href: '/launchpad#evidence-freshness', shortcut: 'Cmd' },
  { title: 'Shift handoff', href: '/launchpad#shift-handoff-workspace', shortcut: 'Cmd' },
  {
    title: 'Timeline builder',
    href: '/launchpad#incident-timeline-builder',
    shortcut: 'Cmd',
  },
  {
    title: 'Collector onboarding',
    href: '/launchpad#collector-onboarding-center',
    shortcut: 'Cmd',
  },
  {
    title: 'Fleet risk heatmap',
    href: '/launchpad#fleet-risk-heatmap',
    shortcut: 'Cmd',
  },
  { title: 'Safe assistant', href: '/launchpad#safe-assistant', shortcut: 'Cmd' },
  { title: 'Operator queue', href: '/launchpad#operator-task-queue', shortcut: 'Cmd' },
  { title: 'Release gate', href: '/launchpad#release-gate-automation', shortcut: 'Cmd' },
  { title: 'Demo scenarios', href: '/launchpad#demo-mode', shortcut: 'Cmd' },
];

const COLLECTOR_ONBOARDING_LANES = [
  {
    name: 'Cloud audit lane',
    providers: ['aws_cloudtrail', 'aws', 'azure_activity', 'azure', 'gcp_audit', 'gcp'],
    target: 'CloudTrail, Azure, or GCP audit',
    href: '/settings?tab=integrations#collectors',
  },
  {
    name: 'Identity lane',
    providers: ['okta', 'entra', 'idp', 'identity'],
    target: 'Okta or Entra identity events',
    href: '/settings?tab=integrations#collectors',
  },
  {
    name: 'SaaS lane',
    providers: ['m365', 'workspace', 'github', 'saas'],
    target: 'M365, Workspace, or GitHub audit',
    href: '/settings?tab=integrations#collectors',
  },
  {
    name: 'Endpoint lane',
    providers: ['crowdstrike', 'falcon', 'endpoint'],
    target: 'EDR telemetry and host posture',
    href: '/settings?tab=integrations#collectors',
  },
  {
    name: 'Syslog lane',
    providers: ['syslog', 'generic_syslog', 'network'],
    target: 'Network and appliance syslog',
    href: '/settings?tab=integrations#collectors',
  },
];

const ROLE_HOME_CONFIG = {
  admin: {
    title: 'Admin home',
    summary: 'Release trust, fleet rollout, collector coverage, and access posture.',
    primaryHref: '/launchpad#release-acceptance-report',
    secondaryHref: '/settings?tab=integrations',
    rows: ['Release acceptance', 'Fleet risk', 'Collector onboarding'],
  },
  analyst: {
    title: 'Analyst home',
    summary: 'Queue context, timeline building, evidence freshness, and response simulation.',
    primaryHref: '/launchpad#incident-timeline-builder',
    secondaryHref: '/soc#queue',
    rows: ['Timeline builder', 'Shift handoff', 'Safe assistant'],
  },
  viewer: {
    title: 'Viewer home',
    summary: 'Read-only operational proof, release confidence, and report-ready evidence.',
    primaryHref: '/reports?tab=evidence',
    secondaryHref: '/launchpad#evidence-surface-coverage',
    rows: ['Evidence coverage', 'Release trust', 'Visual gate'],
  },
};

function asArray(value, keys = []) {
  if (Array.isArray(value)) return value;
  for (const key of keys) {
    if (Array.isArray(value?.[key])) return value[key];
  }
  return [];
}

function normalizeProvider(value) {
  return String(value || '')
    .toLowerCase()
    .replaceAll('-', '_')
    .replaceAll(' ', '_');
}

function countValue(value, keys = ['count', 'total', 'open', 'pending']) {
  if (typeof value === 'number') return value;
  for (const key of keys) {
    const numeric = Number(value?.[key]);
    if (Number.isFinite(numeric)) return numeric;
  }
  return 0;
}

function readinessMap(readiness) {
  return asArray(readiness?.checks || readiness, ['items']).reduce((acc, item) => {
    if (item?.key) acc[item.key] = item;
    return acc;
  }, {});
}

function latestRelease(releases) {
  const items = asArray(releases, ['releases', 'items', 'available']);
  return items.find((item) => item.latest || item.recommended) || items[0] || null;
}

function releaseVersion(release) {
  return release?.version || release?.tag || release?.name || 'No update catalog';
}

function integrationRows({ siem, collectors, sso, deps, audit }) {
  const collectorItems = asArray(collectors, ['collectors', 'items']);
  const healthyCollectors = collectorItems.filter((item) => {
    const freshness = String(item?.freshness || item?.status || '').toLowerCase();
    return item?.enabled && !['stale', 'error', 'failed'].includes(freshness);
  }).length;
  const providers = asArray(sso?.providers || sso, ['providers']);
  const dependencyItems = asArray(deps, ['dependencies', 'checks', 'items']);
  const failingDeps = dependencyItems.filter((item) => {
    const status = String(item?.status || item?.state || '').toLowerCase();
    return ['down', 'error', 'failed', 'degraded'].includes(status);
  }).length;

  return [
    {
      name: 'SIEM',
      detail: siem?.enabled ? `${countValue(siem, ['pending'])} pending events` : 'Not enabled',
      ok: Boolean(siem?.enabled) && countValue(siem, ['pending']) === 0,
    },
    {
      name: 'Collectors',
      detail: `${healthyCollectors}/${collectorItems.length || 0} healthy`,
      ok: collectorItems.length > 0 && healthyCollectors === collectorItems.length,
    },
    {
      name: 'SSO / SCIM',
      detail:
        providers.length > 0
          ? `${providers.length} provider${providers.length === 1 ? '' : 's'}`
          : 'Local auth only',
      ok: providers.length > 0 || Boolean(sso?.scim?.enabled),
    },
    {
      name: 'Dependencies',
      detail: dependencyItems.length > 0 ? `${failingDeps} degraded` : 'No dependency payload',
      ok: dependencyItems.length > 0 && failingDeps === 0,
    },
    {
      name: 'Audit chain',
      detail: audit?.ok || audit?.valid || audit?.status === 'ok' ? 'Verified' : 'Review evidence',
      ok: Boolean(audit?.ok || audit?.valid || audit?.status === 'ok'),
    },
  ];
}

function partialErrorRows(errors) {
  return Object.entries(errors || {}).map(([key, error]) => ({
    key,
    message: error?.message || 'Request failed',
  }));
}

function collectorMatchesLane(item, lane) {
  const provider = normalizeProvider(
    item?.provider || item?.id || item?.key || item?.name || item?.label || item?.type,
  );
  return lane.providers.some((candidate) => provider.includes(normalizeProvider(candidate)));
}

function riskBadge(score) {
  if (score >= 70) return { className: 'badge-err', label: 'High risk' };
  if (score >= 30) return { className: 'badge-warn', label: 'Watch' };
  return { className: 'badge-ok', label: 'Contained' };
}

export default function OperatorLaunchpad() {
  const toast = useToast();
  const { role, groups, userId } = useRole();
  const [demoBusy, setDemoBusy] = useState(false);
  const [demoResetBusy, setDemoResetBusy] = useState(false);
  const [evidenceBusy, setEvidenceBusy] = useState(false);
  const [supportBundleBusy, setSupportBundleBusy] = useState(false);
  const [handoffOwner, setHandoffOwner] = useState('');
  const [handoffNote, setHandoffNote] = useState('');
  const { data, loading, errors, reload } = useApiGroup({
    health: api.health,
    status: api.status,
    assistant: api.assistantStatus,
    readiness: api.onboardingReadiness,
    readinessEvidence: api.supportReadinessEvidence,
    dependencies: api.systemDeps,
    sso: api.authSsoConfig,
    siem: api.siemStatus,
    collectors: api.collectorsStatus,
    releases: api.updatesReleases,
    releaseDiff: api.launchpadReleaseDiff,
    releaseDoctor: api.releaseDoctor,
    releaseObservability: api.releaseObservabilityGates,
    releaseProvenance: api.releaseProvenance,
    upgradeRehearsal: api.releaseUpgradeRehearsal,
    cleanReleaseCut: api.cleanReleaseCut,
    containerParity: api.containerReleaseParity,
    releaseVerification: api.releaseVerificationCenter,
    deploymentWizard: api.selfHostedDeploymentWizard,
    dataQuality: api.dataQualityDashboard,
    scaleBaseline: api.performanceScaleBaseline,
    failoverExecution: api.clusterFailoverExecution,
    secretsRotation: api.secretsRotationOperations,
    taskAutomation: api.operatorTaskAutomation,
    validationPacks: api.detectionValidationPacks,
    syntheticConsole: api.syntheticConsoleMonitor,
    incidentReplay: api.incidentTimelineReplay,
    detectionTrust: api.detectionTrustScore,
    fleetDrift: api.fleetDriftCompliance,
    workQueue: api.operatorWorkQueue,
    retentionForecast: api.retentionForecast,
    adversarialValidation: api.adversarialValidation,
    supportBundleDiff: api.supportBundleDiff,
    workflowPreflight: () => api.workflowPreflight({ workflow: 'release' }),
    demoStatus: api.launchpadDemoStatus,
    response: api.responseStats,
    approvalOverview: api.responseApprovalOverview,
    remediationSafety: api.remediationSafety,
    sdkContract: api.sdkContractStatus,
    operationalSnapshots: () => api.operationalSnapshots({ limit: 8 }),
    snapshotPolicy: api.operationalSnapshotPolicy,
    streamReadiness: api.streamReadiness,
    alertHistogram: () => api.alertHistogram({ window: '24h', bucket: '1h' }),
    audit: api.auditVerify,
    privacy: api.privacyBudget,
    attestation: api.attestationStatus,
    alerts: api.alertsCount,
    fleet: api.fleetHealth,
    detectionSummary: api.detectionSummary,
    replayCorpus: api.detectionReplayCorpus,
    fpStats: api.fpFeedbackStats,
    processAnalysis: api.processesAnalysis,
    threadsStatus: api.threadsStatus,
    threadProof: api.threadDetectionProof,
    tenantProof: api.tenantIsolationProof,
  });

  const checks = useMemo(() => readinessMap(data.readiness), [data.readiness]);
  const steps = READINESS_STEPS.map((step) => {
    const check = checks[step.key] || {};
    return {
      ...step,
      label: check.label || step.title,
      detail: check.detail || step.fallback,
      ready: Boolean(check.ready),
    };
  });
  const readyCount = steps.filter((step) => step.ready).length;
  const release = latestRelease(data.releases);
  const currentVersion = data.status?.version || data.health?.version || 'unknown';
  const releaseCatalogVersion = data.releaseDiff?.latest_version || releaseVersion(release);
  const releaseReady =
    (data.releaseDiff?.status || '').toLowerCase() === 'current' ||
    releaseCatalogVersion === currentVersion ||
    (!data.releaseDiff && !release);
  const backendApprovalCount =
    Number(data.approvalOverview?.pending_response_approvals || 0) +
    Number(data.approvalOverview?.pending_playbook_approvals || 0);
  const pendingApprovals = data.approvalOverview
    ? backendApprovalCount
    : countValue(data.response, ['pending_approval', 'pending', 'ready_to_execute']);
  const alertCount = countValue(data.alerts, ['count', 'alerts', 'total']);
  const integrations = integrationRows({
    siem: data.siem,
    collectors: data.collectors,
    sso: data.sso,
    deps: data.dependencies,
    audit: data.audit,
  });
  const collectorItems = asArray(data.collectors, ['collectors', 'items']);
  const replayReady = ['ready', 'passed', 'ok'].includes(
    String(data.replayCorpus?.status || '').toLowerCase(),
  );
  const fpRate = Number(data.fpStats?.false_positive_rate ?? data.fpStats?.overall_fp_rate ?? 0);
  const detectionRules = countValue(data.detectionSummary, [
    'active_rules',
    'rules_total',
    'rule_count',
    'rules_tracked',
  ]);
  const detectionBadge = statusBadge(replayReady && fpRate <= 0.35, !replayReady || fpRate > 0.35);
  const processFindings = asArray(data.processAnalysis, ['findings', 'items']);
  const threadFindingCount = processFindings.filter((finding) => {
    const text =
      `${finding?.kind || ''} ${finding?.reason || ''} ${finding?.detail || ''}`.toLowerCase();
    return (
      finding?.thread_anomaly_score || finding?.thread_anomaly_count || text.includes('thread')
    );
  }).length;
  const threadStatus = data.threadsStatus?.status || data.threadsStatus?.state || 'runtime visible';
  const errorRows = partialErrorRows(errors);
  const demoScenarios = asArray(data.demoStatus?.scenarios).length
    ? asArray(data.demoStatus?.scenarios)
    : ['credential_storm', 'slow_escalation', 'low_battery_attack', 'benign_baseline'];
  const demoSampleAlerts = countValue(data.demoStatus, ['sample_alerts']);

  const generateEvidencePack = async () => {
    if (evidenceBusy) return;
    setEvidenceBusy(true);
    try {
      const pack = await api.launchpadEvidencePack();
      downloadData(pack, 'wardex-evidence-pack.json');
      toast?.('Evidence pack generated', 'success');
      await reload();
    } catch {
      toast?.('Evidence pack could not be generated', 'error');
    } finally {
      setEvidenceBusy(false);
    }
  };

  const generateSupportBundle = async () => {
    if (supportBundleBusy) return;
    setSupportBundleBusy(true);
    try {
      const bundle = await api.supportBundle();
      downloadData(bundle, 'wardex-support-bundle-redacted.json');
      toast?.('Support bundle generated', 'success');
      await reload();
    } catch {
      toast?.('Support bundle could not be generated', 'error');
    } finally {
      setSupportBundleBusy(false);
    }
  };

  const startDemoLab = async () => {
    if (demoBusy) return;
    setDemoBusy(true);
    try {
      await api.productionDemoLab();
      toast?.('Demo lab scenario started', 'success');
      await reload();
    } catch {
      toast?.('Demo lab could not be started', 'error');
    } finally {
      setDemoBusy(false);
    }
  };

  const resetDemoLab = async () => {
    if (demoResetBusy) return;
    setDemoResetBusy(true);
    try {
      await api.launchpadDemoReset();
      toast?.('Demo lab state reset', 'success');
      await reload();
    } catch {
      toast?.('Demo lab reset failed', 'error');
    } finally {
      setDemoResetBusy(false);
    }
  };

  const releaseBadge = statusBadge(releaseReady, !releaseReady);
  const actionBadge = statusBadge(pendingApprovals === 0, pendingApprovals > 0);
  const streamScore = Number(data.streamReadiness?.score ?? data.wsHealth?.readiness?.score ?? 0);
  const streamStatus = data.streamReadiness?.status || data.wsHealth?.status || 'unknown';
  const streamBadge = statusBadge(streamScore >= 80, streamScore > 0 && streamScore < 80);
  const contractDrift = Number(data.sdkContract?.drift_count || 0);
  const releaseDoctorStatus = data.releaseDoctor?.status || (releaseReady ? 'ready' : 'review');
  const releaseDoctorChecks = asArray(data.releaseDoctor?.checks);
  const releaseObservabilityStatus = data.releaseObservability?.status || 'unknown';
  const workflowPreflightStatus = data.workflowPreflight?.status || 'unknown';
  const workQueueCount = Number(data.workQueue?.item_count || 0);
  const detectionTrustAverage = Number(data.detectionTrust?.average_score || 0);
  const retentionPeak = Number(data.retentionForecast?.utilization_pct?.peak || 0);
  const productionSignals = [
    [
      'Provenance',
      data.releaseProvenance?.status,
      freshnessDetail(
        `${countValue(data.releaseProvenance, ['artifact_count'])} artifacts`,
        data.releaseProvenance,
      ),
      data.releaseProvenance,
    ],
    [
      'Upgrade rehearsal',
      data.upgradeRehearsal?.status,
      data.upgradeRehearsal?.target_version || currentVersion,
      data.upgradeRehearsal,
    ],
    [
      'Synthetic console',
      data.syntheticConsole?.status,
      freshnessDetail(
        `${countValue(data.syntheticConsole, ['check_count'])} checks`,
        data.syntheticConsole,
      ),
      data.syntheticConsole,
    ],
    [
      'Timeline replay',
      data.incidentReplay?.status,
      `${countValue(data.incidentReplay, ['incident_count'])} incidents`,
      data.incidentReplay,
    ],
    [
      'Detection trust',
      data.detectionTrust?.status,
      `${detectionTrustAverage || '—'} score`,
      data.detectionTrust,
    ],
    [
      'Fleet drift',
      data.fleetDrift?.status,
      `${countValue(data.fleetDrift, ['version_drift'])} drifted`,
      data.fleetDrift,
    ],
    ['Work queue', data.workQueue?.status, `${workQueueCount} items`, data.workQueue],
    [
      'Retention',
      data.retentionForecast?.status,
      `${retentionPeak || '—'}% peak`,
      data.retentionForecast,
    ],
    [
      'Adversarial',
      data.adversarialValidation?.status,
      `${countValue(data.adversarialValidation, ['scenario_count'])} scenarios`,
      data.adversarialValidation,
    ],
    [
      'Bundle diff',
      data.supportBundleDiff?.status,
      `${countValue(data.supportBundleDiff, ['snapshot_count'])} snapshots`,
      data.supportBundleDiff,
    ],
  ];
  const releaseVerificationSignals = [
    [
      'Clean cut',
      data.cleanReleaseCut?.status,
      freshnessDetail(data.cleanReleaseCut?.target_version || currentVersion, data.cleanReleaseCut),
      data.cleanReleaseCut,
    ],
    [
      'Container parity',
      data.containerParity?.status,
      freshnessDetail(
        `${countValue(data.containerParity, ['fail_count'])} fails`,
        data.containerParity,
      ),
      data.containerParity,
    ],
    [
      'Verification center',
      data.releaseVerification?.status,
      freshnessDetail(
        `${countValue(data.releaseVerification, ['warn_count'])} warnings`,
        data.releaseVerification,
      ),
      data.releaseVerification,
    ],
    [
      'Deployment wizard',
      data.deploymentWizard?.status,
      data.deploymentWizard?.preflight?.storage_ready ? 'storage ready' : 'storage review',
      data.deploymentWizard,
    ],
    [
      'Data quality',
      data.dataQuality?.status,
      freshnessDetail(
        `${countValue(data.dataQuality?.metrics, ['dead_letter_events'])} DLQ`,
        data.dataQuality,
      ),
      data.dataQuality,
    ],
    [
      'Scale baseline',
      data.scaleBaseline?.status,
      freshnessDetail(
        `${countValue(data.scaleBaseline?.metrics, ['request_rate_per_min'])}/min`,
        data.scaleBaseline,
      ),
      data.scaleBaseline,
    ],
    [
      'Failover execution',
      data.failoverExecution?.status,
      freshnessDetail(data.failoverExecution?.mode || 'rehearsal', data.failoverExecution),
      data.failoverExecution,
    ],
    [
      'Secret rotation',
      data.secretsRotation?.status,
      freshnessDetail(
        `${countValue(data.secretsRotation, ['warn_count'])} warnings`,
        data.secretsRotation,
      ),
      data.secretsRotation,
    ],
    [
      'Task automation',
      data.taskAutomation?.status,
      `${countValue(data.taskAutomation, ['automation_count'])} actions`,
      data.taskAutomation,
    ],
    [
      'Validation packs',
      data.validationPacks?.status,
      freshnessDetail(
        `${countValue(data.validationPacks, ['pack_count'])} packs`,
        data.validationPacks,
      ),
      data.validationPacks,
    ],
  ];
  const releaseVerificationRows = asArray(data.releaseVerification?.verification_rows);
  const deploymentPlans = asArray(data.deploymentWizard?.install_plans);
  const dataQualityScore = Number(data.dataQuality?.slo_summary?.score || 0);
  const loadGateRows = asArray(data.scaleBaseline?.load_gate);
  const automationBlueprints = asArray(data.taskAutomation?.action_blueprints);
  const automationPlans = asArray(data.taskAutomation?.automations);
  const executablePacks = countValue(data.validationPacks, ['executable_pack_count']);
  const productionBlockers = productionSignals.filter(([, status]) =>
    ['blocked', 'fail', 'risk', 'attention'].includes(String(status || '').toLowerCase()),
  ).length;
  const releaseVerificationBlockers = releaseVerificationSignals.filter(
    ([, status, , evidenceSource]) =>
      ['blocked', 'fail', 'risk', 'attention'].includes(String(status || '').toLowerCase()) ||
      evidenceNeedsAttention(evidenceSource),
  ).length;
  const releaseFreshEvidenceCount = releaseVerificationSignals.filter(
    ([, , , evidenceSource]) => evidenceFreshness(evidenceSource)?.status === 'fresh',
  ).length;
  const productionBadge = statusBadge(
    productionBlockers === 0 && workQueueCount === 0,
    workQueueCount > 0,
  );
  const verificationBadge = statusBadge(
    releaseVerificationBlockers === 0,
    releaseVerificationBlockers > 0,
  );
  const deploymentConfidenceRows = [
    [
      'API and SDK contract',
      data.sdkContract?.status || data.releaseVerification?.sdk_contract_status || 'unknown',
      `${countValue(data.sdkContract, ['endpoint_count', 'operation_count']) || releaseVerificationRows.length || '—'} checks`,
      data.sdkContract || data.releaseVerification,
    ],
    [
      'Signing and provenance',
      data.releaseProvenance?.status || data.releaseDoctor?.signing_status || 'unknown',
      data.releaseProvenance?.artifact_count
        ? `${data.releaseProvenance.artifact_count} artifacts`
        : 'artifact proof',
      data.releaseProvenance,
    ],
    [
      'Container parity',
      data.containerParity?.status || 'unknown',
      data.containerParity?.image_tag || data.containerParity?.digest || 'image parity',
      data.containerParity,
    ],
    [
      'Backup and failover',
      data.failoverExecution?.status || data.drDrill?.status || 'unknown',
      data.failoverExecution?.last_drill_at
        ? `drilled ${formatDateTime(data.failoverExecution.last_drill_at)}`
        : 'drill evidence',
      data.failoverExecution,
    ],
    [
      'Data quality and scale',
      dataQualityScore >= 90 && loadGateRows.length > 0 ? 'ready' : 'attention',
      `quality ${dataQualityScore || '—'} • ${loadGateRows.length || 0} gates`,
      data.dataQuality || data.scaleBaseline,
    ],
    [
      'Install plan coverage',
      deploymentPlans.length > 0 ? 'ready' : 'attention',
      `${deploymentPlans.length || 0} install plans`,
      data.deploymentWizard,
    ],
  ];
  const deploymentConfidenceBlockers = deploymentConfidenceRows.filter(([, status, , source]) => {
    const normalized = String(status || '').toLowerCase();
    return (
      ['blocked', 'fail', 'risk', 'attention'].includes(normalized) ||
      evidenceNeedsAttention(source)
    );
  }).length;
  const deploymentConfidenceBadge = statusBadge(
    deploymentConfidenceBlockers === 0,
    deploymentConfidenceBlockers > 0,
  );
  const releaseDoctorBadge = statusBadge(
    releaseDoctorStatus === 'ready',
    releaseDoctorStatus === 'review',
  );
  const histogramTotal = countValue(data.alertHistogram, ['total']);
  const indexedSnapshots = asArray(data.operationalSnapshots?.snapshots);
  const inlineSnapshotRows = [
    ['Release diff', data.releaseDiff?.snapshot],
    ['Demo status', data.demoStatus?.snapshot],
    ['Release doctor', data.releaseDoctor?.snapshot],
    ['Observability gates', data.releaseObservability?.snapshot],
    ['Release provenance', data.releaseProvenance?.snapshot],
    ['Upgrade rehearsal', data.upgradeRehearsal?.snapshot],
    ['Clean release cut', data.cleanReleaseCut?.snapshot],
    ['Container parity', data.containerParity?.snapshot],
    ['Verification center', data.releaseVerification?.snapshot],
    ['Deployment wizard', data.deploymentWizard?.snapshot],
    ['Data quality', data.dataQuality?.snapshot],
    ['Scale baseline', data.scaleBaseline?.snapshot],
    ['Failover execution', data.failoverExecution?.snapshot],
    ['Secret rotation', data.secretsRotation?.snapshot],
    ['Task automation', data.taskAutomation?.snapshot],
    ['Validation packs', data.validationPacks?.snapshot],
    ['Synthetic console', data.syntheticConsole?.snapshot],
    ['Timeline replay', data.incidentReplay?.snapshot],
    ['Detection trust', data.detectionTrust?.snapshot],
    ['Fleet drift', data.fleetDrift?.snapshot],
    ['Operator queue', data.workQueue?.snapshot],
    ['Retention forecast', data.retentionForecast?.snapshot],
    ['Adversarial validation', data.adversarialValidation?.snapshot],
    ['Support bundle diff', data.supportBundleDiff?.snapshot],
    ['Workflow preflight', data.workflowPreflight?.snapshot],
    ['Tenant proof', data.tenantProof?.snapshot],
    ['Thread proof', data.threadProof?.snapshot],
    ['Approvals', data.approvalOverview?.snapshot],
    ['Remediation', data.remediationSafety?.snapshot],
    ['Stream', data.streamReadiness?.snapshot],
    ['SDK contract', data.sdkContract?.snapshot],
  ].filter(([, snapshot]) => snapshot?.persisted || snapshot?.digest);
  const snapshotRows = indexedSnapshots.length
    ? indexedSnapshots.map((snapshot) => [
        String(snapshot.kind || 'snapshot').replaceAll('_', ' '),
        snapshot,
      ])
    : inlineSnapshotRows;
  const allEvidenceRows = [
    ...releaseVerificationSignals,
    ...productionSignals,
    ...deploymentConfidenceRows,
  ]
    .map(([name, status, detail, evidenceSource]) => ({ name, status, detail, evidenceSource }))
    .filter((row) => evidenceFreshness(row.evidenceSource));
  const staleEvidenceRows = allEvidenceRows.filter((row) =>
    evidenceNeedsAttention(row.evidenceSource),
  );
  const freshEvidenceRows = allEvidenceRows.filter(
    (row) => evidenceFreshness(row.evidenceSource)?.status === 'fresh',
  );
  const evidenceModeCounts = allEvidenceRows.reduce((acc, row) => {
    const mode = evidenceMode(row.evidenceSource);
    acc[mode] = (acc[mode] || 0) + 1;
    return acc;
  }, {});
  const evidenceModeRows = Object.entries(evidenceModeCounts)
    .map(([mode, count]) => ({ mode, count }))
    .sort((left, right) => right.count - left.count);
  const evidenceFreshnessBadge = statusBadge(
    allEvidenceRows.length > 0 && staleEvidenceRows.length === 0,
    staleEvidenceRows.length > 0,
  );
  const fleetTotal =
    countValue(data.fleet, ['total_agents', 'agent_count', 'agents', 'total']) ||
    countValue(data.fleet?.fleet, ['total_agents', 'agent_count', 'total']);
  const fleetOnline =
    countValue(data.fleet, ['online', 'online_agents']) ||
    countValue(data.fleet?.status_counts?.online) ||
    countValue(data.fleet?.fleet?.status_counts?.online);
  const fleetOffline =
    countValue(data.fleet, ['offline', 'offline_agents']) ||
    countValue(data.fleet?.status_counts?.offline) ||
    countValue(data.fleet?.fleet?.status_counts?.offline);
  const staleHeartbeats =
    countValue(data.fleet, ['stale', 'stale_agents', 'stale_heartbeats']) ||
    countValue(data.fleetDrift, ['stale_heartbeat_count', 'stale_agents']);
  const fleetDriftCount = countValue(data.fleetDrift, [
    'version_drift',
    'drifted_agents',
    'drift_count',
  ]);
  const fleetHealthBadge = statusBadge(
    fleetOnline > 0 && fleetOffline === 0 && fleetDriftCount === 0,
    fleetOffline > 0 || fleetDriftCount > 0 || staleHeartbeats > 0,
  );
  const morningBriefRows = [
    {
      name: 'First-run readiness',
      status: readyCount === steps.length ? 'ready' : 'attention',
      detail: `${readyCount}/${steps.length} checks ready`,
    },
    {
      name: 'Incident queue',
      status: alertCount > 0 ? 'attention' : 'ready',
      detail: `${alertCount} alerts available`,
    },
    {
      name: 'Response approvals',
      status: pendingApprovals === 0 ? 'ready' : 'attention',
      detail: `${pendingApprovals} pending approvals`,
    },
    {
      name: 'Evidence freshness',
      status: staleEvidenceRows.length === 0 ? 'ready' : 'attention',
      detail: `${freshEvidenceRows.length}/${allEvidenceRows.length || 0} fresh proofs`,
    },
    {
      name: 'Release gate',
      status: deploymentConfidenceBlockers === 0 ? 'ready' : 'attention',
      detail: `${deploymentConfidenceBlockers} deployment blockers`,
    },
  ];
  const guidedIncidentSteps = [
    {
      title: 'Connect an agent',
      detail: fleetOnline > 0 ? `${fleetOnline} online sensors` : 'Open the install bundle drawer',
      href: '/fleet?fleetTab=updates&updatesPanel=install#connect-agent-drawer',
      ready: fleetOnline > 0 || steps[0]?.ready,
    },
    {
      title: 'Open the queue',
      detail: alertCount > 0 ? `${alertCount} alerts ready to triage` : 'No alert context yet',
      href: '/soc#queue',
      ready: alertCount > 0,
    },
    {
      title: 'Explain the evidence',
      detail:
        threadFindingCount > 0 ? `${threadFindingCount} thread findings` : 'Process baseline ready',
      href: '/monitor?drawer=alert-evidence',
      ready: alertCount > 0 || threadFindingCount > 0,
    },
    {
      title: 'Simulate response',
      detail:
        pendingApprovals > 0 ? `${pendingApprovals} approvals need review` : 'No approvals blocked',
      href: '/launchpad#response-simulator',
      ready: pendingApprovals === 0 || Boolean(data.remediationSafety?.status),
    },
    {
      title: 'Package handoff',
      detail:
        staleEvidenceRows.length > 0
          ? `${staleEvidenceRows.length} stale proofs`
          : 'Evidence pack ready',
      href: '/reports?tab=evidence',
      ready: staleEvidenceRows.length === 0 && allEvidenceRows.length > 0,
    },
  ];
  const guidedIncidentReadyCount = guidedIncidentSteps.filter((step) => step.ready).length;
  const rollbackStatus =
    data.remediationSafety?.rollback_status ||
    data.remediationSafety?.rollback ||
    data.remediationSafety?.status ||
    'dry_run_only';
  const rollbackReady =
    String(rollbackStatus).toLowerCase().includes('ready') || rollbackStatus === 'dry_run_only';
  const responseSimulatorRows = [
    {
      name: 'Blast radius',
      status: countValue(data.response, ['protected_assets']) > 0 ? 'ready' : 'review',
      detail: `${countValue(data.response, ['protected_assets']) || '—'} protected assets mapped`,
    },
    {
      name: 'Approval queue',
      status: pendingApprovals === 0 ? 'ready' : 'attention',
      detail: `${pendingApprovals} pending approvals`,
    },
    {
      name: 'Rollback posture',
      status: rollbackReady ? 'ready' : 'attention',
      detail: String(rollbackStatus).replaceAll('_', ' '),
    },
    {
      name: 'Dry-run mode',
      status: data.remediationSafety?.status || 'dry_run_only',
      detail: `${countValue(data.response, ['ready_to_execute', 'approved_ready'])} actions ready`,
    },
  ];
  const fleetDrilldownRows = [
    {
      name: 'Online coverage',
      status: fleetOnline > 0 ? 'ready' : 'attention',
      detail: `${fleetOnline}/${fleetTotal || '—'} online`,
    },
    {
      name: 'Offline agents',
      status: fleetOffline === 0 ? 'ready' : 'attention',
      detail: `${fleetOffline} offline`,
    },
    {
      name: 'Stale heartbeat',
      status: staleHeartbeats === 0 ? 'ready' : 'attention',
      detail: `${staleHeartbeats} stale`,
    },
    {
      name: 'Version drift',
      status: fleetDriftCount === 0 ? 'ready' : 'attention',
      detail: `${fleetDriftCount} drifted`,
    },
  ];
  const workQueueItems = asArray(data.workQueue, ['items', 'tasks', 'queue']);
  const generatedTasks = [
    pendingApprovals > 0
      ? {
          title: 'Review response approvals',
          status: 'attention',
          detail: `${pendingApprovals} approvals waiting`,
          href: '/soc#response',
        }
      : null,
    deploymentConfidenceBlockers > 0
      ? {
          title: 'Clear release blockers',
          status: 'attention',
          detail: `${deploymentConfidenceBlockers} deployment blockers`,
          href: '/launchpad#deployment-confidence',
        }
      : null,
    staleEvidenceRows.length > 0
      ? {
          title: 'Refresh stale evidence',
          status: 'attention',
          detail: `${staleEvidenceRows.length} proofs need refresh`,
          href: '/launchpad#evidence-freshness',
        }
      : null,
    fleetOffline > 0 || fleetDriftCount > 0
      ? {
          title: 'Recover fleet coverage',
          status: 'attention',
          detail: `${fleetOffline} offline, ${fleetDriftCount} drifted`,
          href: '/launchpad#fleet-health-drilldown',
        }
      : null,
    workQueueCount > 0
      ? {
          title: 'Work queued automation',
          status: data.workQueue?.status || 'attention',
          detail: `${workQueueCount} production items`,
          href: '/launchpad#operator-task-queue',
        }
      : null,
  ].filter(Boolean);
  const operatorTaskRows = automationPlans.length
    ? automationPlans.slice(0, 5).map((plan, index) => ({
        title: plan.source?.title || `Queued task ${index + 1}`,
        status: plan.source?.status || plan.status || plan.source?.priority || 'attention',
        detail: plan.source?.detail || 'Awaiting operator action',
        href: plan.source?.href || '/launchpad#operator-task-queue',
        owner: plan.owner || null,
        dueAt: plan.due_at || null,
        slaAge: plan.sla_age || null,
        nextEscalationTarget: plan.next_escalation_target || null,
        recommendedAction: plan.recommended_action || null,
        actionBlueprint: plan.action_blueprint || null,
      }))
    : workQueueItems.length
      ? workQueueItems.slice(0, 5).map((item, index) => ({
          title: item.title || item.name || item.kind || `Queued task ${index + 1}`,
          status: item.status || item.priority || 'attention',
          detail:
            item.detail || item.summary || item.owner || item.reason || 'Awaiting operator action',
          href: item.href || item.path || '/launchpad#operator-task-queue',
          owner: item.owner || null,
          dueAt: item.due_at || null,
          slaAge: item.sla_age || null,
          nextEscalationTarget: item.next_escalation_target || null,
          recommendedAction: item.recommended_action || null,
          actionBlueprint: null,
        }))
      : generatedTasks;
  const activeTaskCount = operatorTaskRows.filter((row) => !isReadyStatus(row.status)).length;
  const taskQueueBadge = statusBadge(activeTaskCount === 0, activeTaskCount > 0);
  const releaseGateRows = [
    {
      name: 'Release doctor',
      status: releaseDoctorStatus,
      detail: `${releaseDoctorChecks.length || 0} checks`,
    },
    {
      name: 'Workflow preflight',
      status: workflowPreflightStatus,
      detail: data.workflowPreflight?.next_action || 'release workflow',
    },
    {
      name: 'Validation packs',
      status: data.validationPacks?.status || 'unknown',
      detail: `${executablePacks || 0} executable packs`,
    },
    {
      name: 'SDK contract',
      status: contractDrift === 0 ? 'ready' : 'attention',
      detail: `${contractDrift} drift items`,
    },
    {
      name: 'Deployment gate',
      status: deploymentConfidenceBlockers === 0 ? 'ready' : 'attention',
      detail: `${deploymentConfidenceBlockers} blockers`,
    },
  ];
  const releaseGateBlockers = releaseGateRows.filter((row) => isBlockingStatus(row.status)).length;
  const releaseGateBadge = statusBadge(releaseGateBlockers === 0, releaseGateBlockers > 0);
  const shiftHandoffRows = [
    {
      name: 'Queue summary',
      status: alertCount > 0 ? 'attention' : 'ready',
      detail: `${alertCount} alert contexts, ${activeTaskCount} operator tasks`,
      href: '/soc#queue',
    },
    {
      name: 'Evidence delta',
      status: staleEvidenceRows.length > 0 ? 'attention' : 'ready',
      detail: `${freshEvidenceRows.length}/${allEvidenceRows.length || 0} proofs fresh`,
      href: '/launchpad#evidence-freshness',
    },
    {
      name: 'Release posture',
      status: releaseGateBlockers > 0 ? 'attention' : 'ready',
      detail: `${releaseGateBlockers} ship gate blockers`,
      href: '/launchpad#release-gate-automation',
    },
    {
      name: 'Fleet watch',
      status: fleetOffline > 0 || staleHeartbeats > 0 ? 'attention' : 'ready',
      detail: `${fleetOffline} offline, ${staleHeartbeats} stale heartbeat`,
      href: '/launchpad#fleet-risk-heatmap',
    },
  ];
  const handoffRecipient = handoffOwner.trim() || (userId !== 'anonymous' ? userId : 'next-shift');
  const incidentReplayCount = countValue(data.incidentReplay, [
    'incident_count',
    'timeline_count',
    'count',
  ]);
  const incidentTimelineRows = [
    {
      name: 'Signal capture',
      status: alertCount > 0 ? 'ready' : 'attention',
      detail: `${alertCount} alerts available`,
      href: '/soc#queue',
    },
    {
      name: 'Host and thread proof',
      status: threadFindingCount > 0 ? 'attention' : 'ready',
      detail: `${threadFindingCount} thread findings`,
      href: '/monitor?monitorTab=processes',
    },
    {
      name: 'Timeline replay',
      status: data.incidentReplay?.status || (incidentReplayCount > 0 ? 'ready' : 'attention'),
      detail: `${incidentReplayCount || 0} replayable incidents`,
      href: '/soc?drawer=incident-detail&incidentPanel=timeline#cases',
    },
    {
      name: 'Report handoff',
      status: staleEvidenceRows.length > 0 ? 'attention' : 'ready',
      detail:
        staleEvidenceRows.length > 0 ? `${staleEvidenceRows.length} proofs stale` : 'packet ready',
      href: '/reports?tab=evidence',
    },
  ];
  const collectorOnboardingRows = COLLECTOR_ONBOARDING_LANES.map((lane) => {
    const matches = collectorItems.filter((item) => collectorMatchesLane(item, lane));
    const enabled = matches.filter((item) => item?.enabled !== false).length;
    const review = matches.filter((item) => {
      const status = String(
        item?.freshness || item?.status || item?.validation?.status || '',
      ).toLowerCase();
      return ['stale', 'unknown', 'warning', 'error', 'failed'].includes(status);
    }).length;
    const ready = matches.length > 0 && enabled === matches.length && review === 0;
    return {
      ...lane,
      count: matches.length,
      status: ready ? 'ready' : matches.length > 0 ? 'attention' : 'pending',
      detail:
        matches.length > 0
          ? `${enabled}/${matches.length} enabled, ${review} review`
          : `Add ${lane.target}`,
    };
  });
  const collectorReadyCount = collectorOnboardingRows.filter((row) =>
    isReadyStatus(row.status),
  ).length;
  const collectorOnboardingBadge = statusBadge(
    collectorReadyCount === collectorOnboardingRows.length,
    collectorReadyCount < collectorOnboardingRows.length,
  );
  const releaseAcceptanceRows = [
    ...releaseGateRows,
    {
      name: 'Fresh evidence',
      status: staleEvidenceRows.length === 0 ? 'ready' : 'attention',
      detail: `${freshEvidenceRows.length}/${allEvidenceRows.length || 0} proofs fresh`,
    },
    {
      name: 'Visual smoke',
      status: 'ready',
      detail: 'Launchpad screenshot gate configured',
    },
  ];
  const releaseAcceptanceBlockers = releaseAcceptanceRows.filter((row) =>
    isBlockingStatus(row.status),
  ).length;
  const releaseAcceptanceBadge = statusBadge(
    releaseAcceptanceBlockers === 0,
    releaseAcceptanceBlockers > 0,
  );
  const riskRows = [
    {
      name: 'Offline coverage',
      score: fleetTotal
        ? Math.min(100, Math.round((fleetOffline / fleetTotal) * 100))
        : fleetOffline * 25,
      detail: `${fleetOffline}/${fleetTotal || '—'} offline`,
      href: '/fleet?status=offline',
    },
    {
      name: 'Heartbeat age',
      score: Math.min(100, staleHeartbeats * 20),
      detail: `${staleHeartbeats} stale heartbeat`,
      href: '/fleet?fleetTab=updates&updatesPanel=health',
    },
    {
      name: 'Version drift',
      score: Math.min(100, fleetDriftCount * 20),
      detail: `${fleetDriftCount} drifted agents`,
      href: '/fleet?fleetTab=updates&updatesPanel=versions',
    },
    {
      name: 'Active detections',
      score: Math.min(100, alertCount * 8 + threadFindingCount * 12),
      detail: `${alertCount} alerts, ${threadFindingCount} thread findings`,
      href: '/soc#queue',
    },
  ];
  const maxFleetRisk = Math.max(0, ...riskRows.map((row) => row.score));
  const fleetRiskBadge = riskBadge(maxFleetRisk);
  const responsePlaybookRows = [
    ...responseSimulatorRows,
    {
      name: 'Approval policy',
      status: pendingApprovals > 0 ? 'attention' : 'ready',
      detail: `${pendingApprovals} approvals before execution`,
    },
    {
      name: 'Audit trail',
      status: data.audit?.ok || data.audit?.valid ? 'ready' : 'attention',
      detail: data.audit?.ok || data.audit?.valid ? 'verified chain' : 'verify audit chain',
    },
  ];
  const evidenceCoverageRows = [
    {
      name: 'SOC cases',
      status: alertCount > 0 || threadFindingCount > 0 ? 'ready' : 'attention',
      detail: `${alertCount} alert contexts`,
      href: '/soc#cases',
    },
    {
      name: 'Reports',
      status: allEvidenceRows.length > 0 ? 'ready' : 'attention',
      detail: `${allEvidenceRows.length || 0} proof rows`,
      href: '/reports?tab=evidence',
    },
    {
      name: 'Release gate',
      status: releaseFreshEvidenceCount > 0 ? 'ready' : 'attention',
      detail: `${releaseFreshEvidenceCount}/${releaseVerificationSignals.length} release proofs`,
      href: '/launchpad#release-acceptance-report',
    },
    {
      name: 'Response queue',
      status: data.remediationSafety?.status ? 'ready' : 'attention',
      detail: String(data.remediationSafety?.status || 'dry-run evidence pending'),
      href: '/response-safety',
    },
  ];
  const roleHome = ROLE_HOME_CONFIG[role] || ROLE_HOME_CONFIG.viewer;
  const visualGateRows = [
    {
      name: 'Launchpad viewport',
      status: 'ready',
      detail: '#deployment-confidence and continuity cards',
    },
    {
      name: 'Command palette smoke',
      status: 'ready',
      detail: 'Cmd+K featured actions are asserted',
    },
    {
      name: 'Screenshot artifact',
      status: 'ready',
      detail: 'Playwright validates non-empty screenshot output',
    },
  ];
  const assistantMode = data.assistant?.mode || 'retrieval-only';
  const canonicalJourneys = [
    {
      name: 'Critical alert to response',
      status:
        alertCount > 0 && freshEvidenceRows.length > 0 && pendingApprovals === 0
          ? 'ready'
          : 'attention',
      detail:
        pendingApprovals > 0
          ? `${pendingApprovals} approval(s) waiting`
          : `${alertCount} alert(s), ${freshEvidenceRows.length} fresh proof(s)`,
      href: '/soc#queue',
    },
    {
      name: 'Collector to detection trust',
      status: collectorReadyCount > 0 && staleEvidenceRows.length === 0 ? 'ready' : 'attention',
      detail: `${collectorReadyCount}/${collectorOnboardingRows.length} telemetry lanes ready`,
      href: '/settings?tab=integrations#collectors',
    },
    {
      name: 'Release cut to acceptance',
      status: releaseAcceptanceBlockers === 0 ? 'ready' : 'attention',
      detail: `${releaseAcceptanceBlockers} blocker(s), ${releaseFreshEvidenceCount} release proof(s)`,
      href: '/launchpad#release-acceptance-report',
    },
    {
      name: 'Assistant answer to cited evidence',
      status:
        assistantMode === 'retrieval-only' && freshEvidenceRows.length > 0 ? 'ready' : 'review',
      detail: `${assistantMode} mode, ${freshEvidenceRows.length} usable proof(s)`,
      href: '/assistant?source=launchpad-quality-gate',
    },
  ];
  const canonicalReadyCount = canonicalJourneys.filter((journey) =>
    isReadyStatus(journey.status),
  ).length;
  const assistantBoundaryRows = [
    {
      name: 'Mode boundary',
      status: assistantMode === 'retrieval-only' ? 'ready' : 'attention',
      detail: assistantMode,
      href: '/assistant',
    },
    {
      name: 'Citation requirement',
      status: 'ready',
      detail: 'answers route through cited context',
      href: '/assistant?source=launchpad-safe-boundary',
    },
    {
      name: 'Execution boundary',
      status: 'ready',
      detail: 'assistant cannot execute response actions',
      href: '/response-safety',
    },
  ];
  const urgentPriorityRows =
    operatorTaskRows.length > 0
      ? operatorTaskRows.slice(0, 3)
      : morningBriefRows
          .filter((row) => !isReadyStatus(row.status))
          .slice(0, 3)
          .map((row) => ({
            title: row.name,
            status: row.status,
            detail: row.detail,
            href: '/launchpad#morning-brief',
          }));
  const guidedPriorityRows = [
    ...guidedIncidentSteps.filter((step) => !step.ready),
    ...guidedIncidentSteps.filter((step) => step.ready),
  ]
    .slice(0, 3)
    .map((step) => ({
      title: step.title,
      status: step.ready ? 'ready' : 'attention',
      detail: step.detail,
      href: step.href,
    }));
  const platformGuardrailRows = [
    {
      title: 'Release gate',
      status: releaseGateBlockers === 0 ? 'ready' : 'attention',
      detail: `${releaseGateBlockers} ship gate blockers`,
      href: '/launchpad#release-gate-automation',
    },
    {
      title: 'Evidence freshness',
      status: staleEvidenceRows.length === 0 && allEvidenceRows.length > 0 ? 'ready' : 'attention',
      detail: `${freshEvidenceRows.length}/${allEvidenceRows.length || 0} proofs fresh`,
      href: '/launchpad#evidence-freshness',
    },
    {
      title: 'Fleet coverage',
      status:
        fleetOffline === 0 && staleHeartbeats === 0 && fleetDriftCount === 0
          ? 'ready'
          : 'attention',
      detail: `${fleetOnline}/${fleetTotal || '—'} online, ${staleHeartbeats} stale`,
      href: '/launchpad#fleet-health-drilldown',
    },
  ];
  const guardrailNeedsAttention = platformGuardrailRows.some((row) => !isReadyStatus(row.status));
  const prioritySections = [
    {
      title: 'Needs attention now',
      label: 'Shift priority',
      meta: `${activeTaskCount} active task${activeTaskCount === 1 ? '' : 's'}`,
      badge: taskQueueBadge,
      rows: urgentPriorityRows,
      empty: 'No urgent operator tasks right now.',
    },
    {
      title: 'First incident path',
      label: 'Guided run',
      meta: `${guidedIncidentReadyCount}/${guidedIncidentSteps.length} steps ready`,
      badge: statusBadge(
        guidedIncidentReadyCount === guidedIncidentSteps.length,
        guidedIncidentReadyCount < guidedIncidentSteps.length,
      ),
      rows: guidedPriorityRows,
      empty: 'Incident path is clear.',
    },
    {
      title: 'Ship and evidence guardrails',
      label: 'Trust gate',
      meta: `${releaseGateBlockers} release blocker${releaseGateBlockers === 1 ? '' : 's'}`,
      badge: statusBadge(!guardrailNeedsAttention, guardrailNeedsAttention),
      rows: platformGuardrailRows,
      empty: 'All guardrails are clear.',
    },
  ];

  const exportShiftHandoff = () => {
    downloadData(
      {
        schema: 'wardex.shift_handoff.v1',
        created_at: new Date().toISOString(),
        created_by: userId,
        recipient: handoffRecipient,
        role,
        groups,
        note: handoffNote.trim(),
        summary: shiftHandoffRows,
        tasks: operatorTaskRows,
        evidence: staleEvidenceRows.slice(0, 8),
      },
      'wardex-shift-handoff.json',
    );
    toast?.('Shift handoff exported', 'success');
  };

  const exportTimelineDraft = () => {
    downloadData(
      {
        schema: 'wardex.incident_timeline_draft.v1',
        created_at: new Date().toISOString(),
        rows: incidentTimelineRows,
        alert_count: alertCount,
        thread_finding_count: threadFindingCount,
        fresh_evidence: freshEvidenceRows.length,
      },
      'wardex-incident-timeline-draft.json',
    );
    toast?.('Timeline draft exported', 'success');
  };

  const exportReleaseAcceptance = () => {
    downloadData(
      {
        schema: 'wardex.release_acceptance_report.v1',
        created_at: new Date().toISOString(),
        version: currentVersion,
        blockers: releaseAcceptanceBlockers,
        rows: releaseAcceptanceRows,
        evidence: allEvidenceRows,
      },
      `wardex-release-acceptance-${currentVersion}.json`,
    );
    toast?.('Release acceptance report exported', 'success');
  };

  return (
    <div className="operator-launchpad">
      <section className="card operator-launchpad-hero">
        <div>
          <div className="summary-label">Operator Launchpad</div>
          <h2>Run the first incident with confidence</h2>
          <p>
            Readiness, integration health, release trust, response safety, evidence, and demo paths
            are checked from the live console state.
          </p>
        </div>
        <div className="btn-group">
          <button type="button" className="btn btn-sm" onClick={reload} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={generateEvidencePack}
            disabled={evidenceBusy}
          >
            {evidenceBusy ? 'Generating...' : 'Evidence Pack'}
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={generateSupportBundle}
            disabled={supportBundleBusy}
          >
            {supportBundleBusy ? 'Bundling...' : 'Support Bundle'}
          </button>
        </div>
      </section>

      <section className="summary-grid" aria-label="Operator readiness summary">
        <div className="summary-card">
          <div className="summary-label">First-run path</div>
          <div className="summary-value">
            {readyCount}/{steps.length}
          </div>
          <div className="summary-meta">checks ready</div>
        </div>
        <div className="summary-card">
          <div className="summary-label">Current version</div>
          <div className="summary-value">{currentVersion}</div>
          <div className="summary-meta">doctor: {releaseDoctorStatus}</div>
        </div>
        <div className="summary-card">
          <div className="summary-label">Open alert context</div>
          <div className="summary-value">{alertCount}</div>
          <div className="summary-meta">alerts available</div>
        </div>
        <div className="summary-card">
          <div className="summary-label">Response safety</div>
          <div className="summary-value">{pendingApprovals}</div>
          <div className="summary-meta">pending approvals</div>
        </div>
        <div className="summary-card">
          <div className="summary-label">Detection quality</div>
          <div className="summary-value">{detectionRules || '—'}</div>
          <div className="summary-meta">rules tracked • FP {Math.round(fpRate * 100)}%</div>
        </div>
        <div className="summary-card">
          <div className="summary-label">Stream readiness</div>
          <div className="summary-value">{streamScore || '—'}</div>
          <div className="summary-meta">{streamStatus}</div>
        </div>
        <div className="summary-card">
          <div className="summary-label">Work queue</div>
          <div className="summary-value">{workQueueCount}</div>
          <div className="summary-meta">production items</div>
        </div>
      </section>

      <section className="operator-priority-board" aria-label="Shift priorities">
        {prioritySections.map((section) => (
          <div key={section.title} className="card operator-priority-card">
            <div className="card-header">
              <div>
                <div className="summary-label">{section.label}</div>
                <h3 className="card-title">{section.title}</h3>
                <div className="summary-meta">{section.meta}</div>
              </div>
              <span className={`badge ${section.badge.className}`}>{section.badge.label}</span>
            </div>
            {section.rows.length === 0 ? (
              <div className="empty empty-compact">{section.empty}</div>
            ) : (
              <div className="operator-priority-list">
                {section.rows.map((row) => {
                  const badge = signalBadge(row.status);
                  return (
                    <Link
                      key={`${section.title}-${row.title}-${row.detail}`}
                      className="operator-priority-row"
                      to={row.href || '/launchpad'}
                    >
                      <span className={`badge ${badge.className}`}>{badge.label}</span>
                      <span>
                        <strong>{row.title}</strong>
                        <span>{row.detail}</span>
                      </span>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        ))}
      </section>

      <section className="operator-capability-section" aria-label="Full launchpad capability map">
        <div className="section-header">
          <div>
            <div className="summary-label">Full launchpad</div>
            <h2>Capability map</h2>
          </div>
        </div>

        <div className="operator-launchpad-grid">
          <div className="card operator-lane-card" id="connect-agent-drawer">
            <div className="card-header">
              <div>
                <div className="summary-label">Persistent connect</div>
                <h3 className="card-title">Agent connect drawer</h3>
              </div>
              <Link
                className="btn btn-sm"
                to="/fleet?fleetTab=updates&updatesPanel=install#connect-agent-drawer"
              >
                Open drawer
              </Link>
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Enrollment path</span>
                <strong>Manual or remote</strong>
              </div>
              <div>
                <span>Fleet online</span>
                <strong>
                  {fleetOnline}/{fleetTotal || '—'}
                </strong>
              </div>
              <div>
                <span>Install plans</span>
                <strong>{deploymentPlans.length || '—'}</strong>
              </div>
            </div>
            <div className="summary-meta">
              The Fleet install panel now has a stable command-palette route and hash target.
            </div>
          </div>

          <div className="card operator-lane-card" id="morning-brief">
            <div className="card-header">
              <div>
                <div className="summary-label">Shift handoff</div>
                <h3 className="card-title">Morning brief</h3>
              </div>
              <span className={`badge ${taskQueueBadge.className}`}>{taskQueueBadge.label}</span>
            </div>
            <div className="operator-health-list">
              {morningBriefRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <div key={row.name} className="operator-health-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="card operator-lane-card" id="shift-handoff-workspace">
            <div className="card-header">
              <div>
                <div className="summary-label">Shift continuity</div>
                <h3 className="card-title">Handoff workspace</h3>
              </div>
              <button type="button" className="btn btn-sm" onClick={exportShiftHandoff}>
                Export handoff
              </button>
            </div>
            <div className="operator-handoff-form">
              <label className="form-label" htmlFor="handoff-owner">
                Recipient
              </label>
              <input
                id="handoff-owner"
                className="form-input"
                value={handoffOwner}
                onChange={(event) => setHandoffOwner(event.target.value)}
                placeholder={handoffRecipient}
              />
              <label className="form-label" htmlFor="handoff-note">
                Shift note
              </label>
              <textarea
                id="handoff-note"
                className="form-textarea"
                rows={3}
                value={handoffNote}
                onChange={(event) => setHandoffNote(event.target.value)}
                placeholder="Open items, watchlist, and ownership changes"
              />
            </div>
            <div className="operator-health-list">
              {shiftHandoffRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <Link
                    key={row.name}
                    className="operator-health-row operator-health-link"
                    to={row.href}
                  >
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="card operator-lane-card" id="guided-incident-path">
            <div className="card-header">
              <div>
                <div className="summary-label">Guided incident</div>
                <h3 className="card-title">Triage path</h3>
              </div>
              <span
                className={`badge ${guidedIncidentReadyCount === guidedIncidentSteps.length ? 'badge-ok' : 'badge-warn'}`}
              >
                {guidedIncidentReadyCount}/{guidedIncidentSteps.length}
              </span>
            </div>
            <div className="operator-step-list">
              {guidedIncidentSteps.map((step) => {
                const badge = statusBadge(step.ready);
                return (
                  <Link key={step.title} className="operator-step" to={step.href}>
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>
                      <strong>{step.title}</strong>
                      <span>{step.detail}</span>
                    </span>
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="card operator-lane-card" id="canonical-operator-journeys">
            <div className="card-header">
              <div>
                <div className="summary-label">Golden paths</div>
                <h3 className="card-title">Canonical operator journeys</h3>
              </div>
              <span
                className={`badge ${canonicalReadyCount === canonicalJourneys.length ? 'badge-ok' : 'badge-warn'}`}
              >
                {canonicalReadyCount}/{canonicalJourneys.length}
              </span>
            </div>
            <div className="operator-health-list">
              {canonicalJourneys.map((journey) => {
                const badge = signalBadge(journey.status);
                return (
                  <Link
                    key={journey.name}
                    className="operator-health-row operator-health-link"
                    to={journey.href}
                  >
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{journey.name}</span>
                    <span>{journey.detail}</span>
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="card operator-lane-card" id="incident-timeline-builder">
            <div className="card-header">
              <div>
                <div className="summary-label">Incident reconstruction</div>
                <h3 className="card-title">Timeline builder</h3>
              </div>
              <button type="button" className="btn btn-sm" onClick={exportTimelineDraft}>
                Export draft
              </button>
            </div>
            <div className="operator-health-list">
              {incidentTimelineRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <Link
                    key={row.name}
                    className="operator-health-row operator-health-link"
                    to={row.href}
                  >
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </Link>
                );
              })}
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Replay incidents</span>
                <strong>{incidentReplayCount || '—'}</strong>
              </div>
              <div>
                <span>Fresh evidence</span>
                <strong>{freshEvidenceRows.length}</strong>
              </div>
              <div>
                <span>Handoff target</span>
                <strong>Reports</strong>
              </div>
            </div>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Guided first run</div>
                <h3 className="card-title">Mission path</h3>
              </div>
              <span className={`badge ${readyCount === steps.length ? 'badge-ok' : 'badge-warn'}`}>
                {readyCount}/{steps.length}
              </span>
            </div>
            <div className="operator-step-list">
              {steps.map((step) => {
                const badge = statusBadge(step.ready);
                return (
                  <Link key={step.key} className="operator-step" to={step.href}>
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>
                      <strong>{step.label}</strong>
                      <span>{step.detail}</span>
                    </span>
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Release verification</div>
                <h3 className="card-title">Clean release and deployment</h3>
              </div>
              <span className={`badge ${verificationBadge.className}`}>
                {verificationBadge.label}
              </span>
            </div>
            <div className="operator-health-list">
              {releaseVerificationSignals.map(([name, status, detail, evidenceSource]) => {
                const badge = signalBadge(status);
                const proofBadge = evidenceBadge(evidenceSource);
                return (
                  <div key={name} className="operator-health-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{name}</span>
                    <span>{detail}</span>
                    <span className={`badge ${proofBadge.className}`}>{proofBadge.label}</span>
                  </div>
                );
              })}
            </div>
            <div className="operator-kv-list" style={{ marginTop: 12 }}>
              <div>
                <span>Target</span>
                <strong>{data.cleanReleaseCut?.target_version || '—'}</strong>
              </div>
              <div>
                <span>Container</span>
                <strong>{data.containerParity?.status || 'unknown'}</strong>
              </div>
              <div>
                <span>Validation packs</span>
                <strong>{countValue(data.validationPacks, ['pack_count'])}</strong>
              </div>
            </div>
            <div className="operator-kv-list" style={{ marginTop: 12 }}>
              <div>
                <span>Artifact rows</span>
                <strong>{releaseVerificationRows.length || '—'}</strong>
              </div>
              <div>
                <span>Install plans</span>
                <strong>{deploymentPlans.length || '—'}</strong>
              </div>
              <div>
                <span>Quality score</span>
                <strong>{dataQualityScore || '—'}</strong>
              </div>
              <div>
                <span>Load gates</span>
                <strong>{loadGateRows.length || '—'}</strong>
              </div>
              <div>
                <span>Fresh proof</span>
                <strong>
                  {releaseFreshEvidenceCount}/{releaseVerificationSignals.length}
                </strong>
              </div>
              <div>
                <span>Proof collected</span>
                <strong>
                  {formatDateTime(data.releaseVerification?.evidence_freshness?.collected_at) ||
                    '—'}
                </strong>
              </div>
              <div>
                <span>Dry-run actions</span>
                <strong>{automationBlueprints.length || '—'}</strong>
              </div>
              <div>
                <span>Executable packs</span>
                <strong>{executablePacks || '—'}</strong>
              </div>
            </div>
          </div>

          <div className="card operator-lane-card" id="deployment-confidence">
            <div className="card-header">
              <div>
                <div className="summary-label">Deployment confidence</div>
                <h3 className="card-title">Ship readiness matrix</h3>
              </div>
              <span className={`badge ${deploymentConfidenceBadge.className}`}>
                {deploymentConfidenceBadge.label}
              </span>
            </div>
            <div className="deployment-confidence-matrix">
              {deploymentConfidenceRows.map(([name, status, detail, evidenceSource]) => {
                const badge = signalBadge(status);
                const proofBadge = evidenceBadge(evidenceSource);
                return (
                  <div key={name} className="deployment-confidence-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <strong>{name}</strong>
                    <span>{detail}</span>
                    <span className={`badge ${proofBadge.className}`}>{proofBadge.label}</span>
                  </div>
                );
              })}
            </div>
            <div className="operator-kv-list" style={{ marginTop: 12 }}>
              <div>
                <span>Blockers</span>
                <strong>{deploymentConfidenceBlockers}</strong>
              </div>
              <div>
                <span>Fresh proof</span>
                <strong>
                  {releaseFreshEvidenceCount}/{releaseVerificationSignals.length}
                </strong>
              </div>
              <div>
                <span>Install plans</span>
                <strong>{deploymentPlans.length || '—'}</strong>
              </div>
            </div>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Integration health</div>
                <h3 className="card-title">External systems</h3>
              </div>
              <Link className="btn btn-sm" to="/settings?tab=integrations">
                Open
              </Link>
            </div>
            <div className="operator-health-list">
              {integrations.map((row) => {
                const badge = statusBadge(row.ok);
                return (
                  <div key={row.name} className="operator-health-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="card operator-lane-card" id="collector-onboarding-center">
            <div className="card-header">
              <div>
                <div className="summary-label">Collector onboarding</div>
                <h3 className="card-title">Telemetry lanes</h3>
              </div>
              <span className={`badge ${collectorOnboardingBadge.className}`}>
                {collectorReadyCount}/{collectorOnboardingRows.length}
              </span>
            </div>
            <div className="operator-health-list">
              {collectorOnboardingRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <Link
                    key={row.name}
                    className="operator-health-row operator-health-link"
                    to={row.href}
                  >
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </Link>
                );
              })}
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Configured collectors</span>
                <strong>{collectorItems.length}</strong>
              </div>
              <div>
                <span>Healthy lanes</span>
                <strong>{collectorReadyCount}</strong>
              </div>
            </div>
          </div>

          <div className="card operator-lane-card" id="fleet-health-drilldown">
            <div className="card-header">
              <div>
                <div className="summary-label">Fleet health</div>
                <h3 className="card-title">Agent drilldown</h3>
              </div>
              <span className={`badge ${fleetHealthBadge.className}`}>
                {fleetHealthBadge.label}
              </span>
            </div>
            <div className="operator-health-list">
              {fleetDrilldownRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <div key={row.name} className="operator-health-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </div>
                );
              })}
            </div>
            <div className="btn-group">
              <Link className="btn btn-sm" to="/fleet?status=offline">
                Offline agents
              </Link>
              <Link className="btn btn-sm" to="/fleet?fleetTab=updates&updatesPanel=health">
                Deployment health
              </Link>
            </div>
          </div>

          <div className="card operator-lane-card" id="fleet-risk-heatmap">
            <div className="card-header">
              <div>
                <div className="summary-label">Fleet risk</div>
                <h3 className="card-title">Agent risk heatmap</h3>
              </div>
              <span className={`badge ${fleetRiskBadge.className}`}>{fleetRiskBadge.label}</span>
            </div>
            <div className="operator-risk-list">
              {riskRows.map((row) => {
                const badge = riskBadge(row.score);
                return (
                  <Link key={row.name} className="operator-risk-row" to={row.href}>
                    <span className={`badge ${badge.className}`}>{row.score}</span>
                    <span>
                      <strong>{row.name}</strong>
                      <small>{row.detail}</small>
                    </span>
                    <span className="operator-risk-track" aria-hidden="true">
                      <span style={{ width: `${Math.max(row.score, 4)}%` }} />
                    </span>
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="card operator-lane-card" id="evidence-freshness">
            <div className="card-header">
              <div>
                <div className="summary-label">Evidence freshness</div>
                <h3 className="card-title">Proof freshness rollup</h3>
              </div>
              <span className={`badge ${evidenceFreshnessBadge.className}`}>
                {evidenceFreshnessBadge.label}
              </span>
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Fresh proof</span>
                <strong>
                  {freshEvidenceRows.length}/{allEvidenceRows.length || 0}
                </strong>
              </div>
              <div>
                <span>Stale proof</span>
                <strong>{staleEvidenceRows.length}</strong>
              </div>
              <div>
                <span>Snapshots</span>
                <strong>{snapshotRows.length || '—'}</strong>
              </div>
            </div>
            <div className="operator-kv-list" style={{ marginTop: 12 }}>
              {(evidenceModeRows.length ? evidenceModeRows : [{ mode: 'pending', count: 0 }]).map(
                (row) => (
                  <div key={row.mode}>
                    <span>{row.mode}</span>
                    <strong>{row.count}</strong>
                  </div>
                ),
              )}
            </div>
            <div className="operator-health-list">
              {(staleEvidenceRows.length ? staleEvidenceRows : allEvidenceRows)
                .slice(0, 4)
                .map((row) => {
                  const proofBadge = evidenceBadge(row.evidenceSource);
                  return (
                    <div key={`${row.name}-${row.detail}`} className="operator-health-row">
                      <span className={`badge ${proofBadge.className}`}>{proofBadge.label}</span>
                      <span>{row.name}</span>
                      <span>{row.detail}</span>
                    </div>
                  );
                })}
            </div>
          </div>

          <div className="card operator-lane-card" id="evidence-surface-coverage">
            <div className="card-header">
              <div>
                <div className="summary-label">Evidence everywhere</div>
                <h3 className="card-title">Freshness coverage</h3>
              </div>
              <span className={`badge ${evidenceFreshnessBadge.className}`}>
                {freshEvidenceRows.length}/{allEvidenceRows.length || 0}
              </span>
            </div>
            <div className="operator-health-list">
              {evidenceCoverageRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <Link
                    key={row.name}
                    className="operator-health-row operator-health-link"
                    to={row.href}
                  >
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="card operator-lane-card" id="release-trust">
            <div className="card-header">
              <div>
                <div className="summary-label">Release trust</div>
                <h3 className="card-title">What changed</h3>
              </div>
              <span className={`badge ${releaseBadge.className}`}>{releaseBadge.label}</span>
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Current</span>
                <strong>{currentVersion}</strong>
              </div>
              <div>
                <span>Catalog</span>
                <strong>{releaseCatalogVersion}</strong>
              </div>
              <div>
                <span>Changes</span>
                <strong>
                  {countValue(data.releaseDiff, ['changed_rule_count']) ||
                    asArray(data.releaseDiff?.changed_rules).length}
                </strong>
              </div>
            </div>
            {data.releaseDiff?.operator_summary && (
              <div className="summary-meta">{data.releaseDiff.operator_summary}</div>
            )}
            {release?.published_at && (
              <div className="summary-meta">published {formatDateTime(release.published_at)}</div>
            )}
            <div className="operator-health-list" style={{ marginTop: 12 }}>
              {releaseDoctorChecks.slice(0, 3).map((check) => (
                <div key={check.id || check.detail} className="operator-health-row">
                  <span
                    className={`badge ${check.status === 'pass' ? 'badge-ok' : check.status === 'fail' ? 'badge-err' : 'badge-warn'}`}
                  >
                    {check.status || 'review'}
                  </span>
                  <span>{String(check.id || 'check').replaceAll('_', ' ')}</span>
                  <span>{check.detail || 'No detail'}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Release doctor</div>
                <h3 className="card-title">Acceptance readiness</h3>
              </div>
              <span className={`badge ${releaseDoctorBadge.className}`}>
                {releaseDoctorBadge.label}
              </span>
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Checks</span>
                <strong>{releaseDoctorChecks.length || '—'}</strong>
              </div>
              <div>
                <span>Warnings</span>
                <strong>{Number(data.releaseDoctor?.warn_count || 0)}</strong>
              </div>
              <div>
                <span>Blockers</span>
                <strong>{Number(data.releaseDoctor?.fail_count || 0)}</strong>
              </div>
              <div>
                <span>Observability</span>
                <strong>{releaseObservabilityStatus}</strong>
              </div>
              <div>
                <span>Preflight</span>
                <strong>{workflowPreflightStatus}</strong>
              </div>
              <div>
                <span>Snapshot keep</span>
                <strong>{data.snapshotPolicy?.keep_latest_per_kind || '—'}</strong>
              </div>
            </div>
            <div className="summary-meta">
              {data.releaseDoctor?.next_action ||
                'Run release acceptance after launchpad signals load.'}
            </div>
          </div>

          <div className="card operator-lane-card" id="release-gate-automation">
            <div className="card-header">
              <div>
                <div className="summary-label">Release gate automation</div>
                <h3 className="card-title">Ship gate checklist</h3>
              </div>
              <span className={`badge ${releaseGateBadge.className}`}>
                {releaseGateBadge.label}
              </span>
            </div>
            <div className="operator-health-list">
              {releaseGateRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <div key={row.name} className="operator-health-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </div>
                );
              })}
            </div>
            <div className="btn-group">
              <Link className="btn btn-sm" to="/launchpad#deployment-confidence">
                Deployment matrix
              </Link>
              <Link className="btn btn-sm" to="/reports?tab=evidence">
                Evidence export
              </Link>
            </div>
          </div>

          <div className="card operator-lane-card" id="release-acceptance-report">
            <div className="card-header">
              <div>
                <div className="summary-label">Release acceptance</div>
                <h3 className="card-title">Acceptance report</h3>
              </div>
              <button type="button" className="btn btn-sm" onClick={exportReleaseAcceptance}>
                Export report
              </button>
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Version</span>
                <strong>{currentVersion}</strong>
              </div>
              <div>
                <span>Blockers</span>
                <strong>{releaseAcceptanceBlockers}</strong>
              </div>
              <div>
                <span>Proof rows</span>
                <strong>{allEvidenceRows.length}</strong>
              </div>
            </div>
            <div className="operator-health-list">
              {releaseAcceptanceRows.slice(0, 6).map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <div key={row.name} className="operator-health-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </div>
                );
              })}
            </div>
            <span className={`badge ${releaseAcceptanceBadge.className}`}>
              {releaseAcceptanceBadge.label}
            </span>
          </div>

          <div className="card operator-lane-card" id="operator-task-queue">
            <div className="card-header">
              <div>
                <div className="summary-label">Operator task queue</div>
                <h3 className="card-title">Next actions</h3>
              </div>
              <span className={`badge ${taskQueueBadge.className}`}>
                {activeTaskCount || 'Clear'}
              </span>
            </div>
            {operatorTaskRows.length === 0 ? (
              <div className="empty empty-compact">No generated operator tasks right now.</div>
            ) : (
              <div className="operator-step-list">
                {operatorTaskRows.map((task) => {
                  const badge = signalBadge(task.status);
                  return (
                    <Link
                      key={`${task.title}-${task.detail}`}
                      className="operator-step"
                      to={task.href}
                    >
                      <span className={`badge ${badge.className}`}>{badge.label}</span>
                      <span>
                        <strong>{task.title}</strong>
                        <span>{task.detail}</span>
                        {(task.owner || task.slaAge || task.nextEscalationTarget) && (
                          <span className="hint">
                            {[
                              task.owner ? `Owner: ${task.owner}` : null,
                              task.slaAge ? `SLA: ${formatLabel(task.slaAge)}` : null,
                              task.nextEscalationTarget
                                ? `Escalate: ${task.nextEscalationTarget}`
                                : null,
                            ]
                              .filter(Boolean)
                              .join(' • ')}
                          </span>
                        )}
                        {(task.recommendedAction || task.actionBlueprint?.method) && (
                          <span className="hint">
                            {[
                              task.recommendedAction
                                ? `Next action: ${formatLabel(task.recommendedAction)}`
                                : null,
                              task.actionBlueprint?.method
                                ? `${formatLabel(task.actionBlueprint.method)} blueprint`
                                : null,
                            ]
                              .filter(Boolean)
                              .join(' • ')}
                          </span>
                        )}
                        {task.dueAt && (
                          <span className="hint">Due: {formatDateTime(task.dueAt)}</span>
                        )}
                      </span>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Production assurance</div>
                <h3 className="card-title">Next tranche signals</h3>
              </div>
              <span className={`badge ${productionBadge.className}`}>{productionBadge.label}</span>
            </div>
            <div className="operator-health-list">
              {productionSignals.slice(0, 6).map(([name, status, detail, evidenceSource]) => {
                const badge = signalBadge(status);
                const proofBadge = evidenceBadge(evidenceSource);
                return (
                  <div key={name} className="operator-health-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{name}</span>
                    <span>{detail}</span>
                    {evidenceFreshness(evidenceSource) ? (
                      <span className={`badge ${proofBadge.className}`}>{proofBadge.label}</span>
                    ) : null}
                  </div>
                );
              })}
            </div>
            <div className="operator-kv-list" style={{ marginTop: 12 }}>
              <div>
                <span>Queue</span>
                <strong>{workQueueCount}</strong>
              </div>
              <div>
                <span>Retention peak</span>
                <strong>{retentionPeak || '—'}%</strong>
              </div>
              <div>
                <span>Blockers</span>
                <strong>{productionBlockers}</strong>
              </div>
            </div>
          </div>

          <div className="card operator-lane-card" id="response-playbook-simulator">
            <span id="response-simulator" aria-hidden="true" />
            <div className="card-header">
              <div>
                <div className="summary-label">Response simulator</div>
                <h3 className="card-title">Playbook blast-radius preview</h3>
              </div>
              <span className={`badge ${actionBadge.className}`}>{actionBadge.label}</span>
            </div>
            <div className="operator-health-list">
              {responsePlaybookRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <div key={row.name} className="operator-health-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </div>
                );
              })}
            </div>
            <div className="btn-group">
              <Link className="btn btn-sm" to="/response-safety">
                Open safety lab
              </Link>
              <Link className="btn btn-sm" to="/soc?focus=response">
                Review queue
              </Link>
            </div>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Explainability</div>
                <h3 className="card-title">Alert-to-evidence path</h3>
              </div>
              <Link className="btn btn-sm" to="/monitor">
                Open alerts
              </Link>
            </div>
            <div className="operator-command-grid">
              <Link to="/monitor" className="operator-command-tile">
                Alert drawer
              </Link>
              <Link to="/detection?intent=run-hunt" className="operator-command-tile">
                Run hunt
              </Link>
              <Link to="/reports?tab=evidence" className="operator-command-tile">
                Evidence
              </Link>
            </div>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Detection quality</div>
                <h3 className="card-title">Promotion confidence</h3>
              </div>
              <span className={`badge ${detectionBadge.className}`}>{detectionBadge.label}</span>
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Replay corpus</span>
                <strong>{data.replayCorpus?.status || 'pending'}</strong>
              </div>
              <div>
                <span>FP feedback</span>
                <strong>{Math.round(fpRate * 100)}%</strong>
              </div>
              <div>
                <span>Rules tracked</span>
                <strong>{detectionRules || '—'}</strong>
              </div>
            </div>
            <Link className="btn btn-sm" to="/detection?panel=quality">
              Open quality score
            </Link>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Live stream</div>
                <h3 className="card-title">Promotion guard</h3>
              </div>
              <span className={`badge ${streamBadge.className}`}>{streamBadge.label}</span>
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Readiness</span>
                <strong>{streamScore || '—'}</strong>
              </div>
              <div>
                <span>Histogram</span>
                <strong>{histogramTotal}</strong>
              </div>
              <div>
                <span>Contract drift</span>
                <strong>{contractDrift}</strong>
              </div>
            </div>
            {data.streamReadiness?.next_action && (
              <div className="summary-meta">{data.streamReadiness.next_action}</div>
            )}
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Thread signal depth</div>
                <h3 className="card-title">Process evidence</h3>
              </div>
              <span className={`badge ${threadFindingCount > 0 ? 'badge-warn' : 'badge-ok'}`}>
                {threadFindingCount > 0 ? `${threadFindingCount} review` : 'Baseline'}
              </span>
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Runtime</span>
                <strong>{threadStatus}</strong>
              </div>
              <div>
                <span>Findings</span>
                <strong>{threadFindingCount}</strong>
              </div>
              <div>
                <span>Next pivot</span>
                <strong>{threadFindingCount > 0 ? 'Process drawer' : 'Baseline'}</strong>
              </div>
            </div>
            <Link className="btn btn-sm" to="/monitor?monitorTab=processes">
              Open processes
            </Link>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Command palette</div>
                <h3 className="card-title">Operator accelerators</h3>
              </div>
              <span className="badge badge-info">Cmd+K</span>
            </div>
            <div className="operator-command-grid">
              {COMMAND_ACCELERATORS.map((command) => (
                <Link key={command.title} to={command.href} className="operator-command-tile">
                  <span>{command.title}</span>
                  <small>{command.shortcut}</small>
                </Link>
              ))}
            </div>
          </div>

          <div className="card operator-lane-card" id="role-home-screen">
            <div className="card-header">
              <div>
                <div className="summary-label">Role home</div>
                <h3 className="card-title">{roleHome.title}</h3>
              </div>
              <span className="badge badge-info">{role}</span>
            </div>
            <div className="summary-meta">{roleHome.summary}</div>
            <div className="operator-command-grid">
              {roleHome.rows.map((label) => (
                <Link key={label} to={roleHome.primaryHref} className="operator-command-tile">
                  <span>{label}</span>
                  <small>{groups.length ? groups.slice(0, 2).join(', ') : userId}</small>
                </Link>
              ))}
            </div>
            <div className="btn-group">
              <Link className="btn btn-sm" to={roleHome.primaryHref}>
                Primary view
              </Link>
              <Link className="btn btn-sm" to={roleHome.secondaryHref}>
                Secondary view
              </Link>
            </div>
          </div>

          <div className="card operator-lane-card" id="safe-assistant">
            <div className="card-header">
              <div>
                <div className="summary-label">Operator Assistant</div>
                <h3 className="card-title">Safe assistant boundaries</h3>
              </div>
              <span
                className={`badge ${assistantMode === 'retrieval-only' ? 'badge-info' : 'badge-warn'}`}
              >
                {assistantMode}
              </span>
            </div>
            <div className="operator-health-list">
              {assistantBoundaryRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <Link
                    key={row.name}
                    className="operator-health-row operator-health-link"
                    to={row.href}
                  >
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </Link>
                );
              })}
            </div>
            <Link className="btn btn-sm" to="/assistant?source=launchpad-safe-boundary">
              Open assistant
            </Link>
          </div>

          <div className="card operator-lane-card" id="visual-regression-gate">
            <div className="card-header">
              <div>
                <div className="summary-label">Visual regression</div>
                <h3 className="card-title">Screenshot gate</h3>
              </div>
              <span className="badge badge-ok">Ready</span>
            </div>
            <div className="operator-health-list">
              {visualGateRows.map((row) => {
                const badge = signalBadge(row.status);
                return (
                  <div key={row.name} className="operator-health-row">
                    <span className={`badge ${badge.className}`}>{badge.label}</span>
                    <span>{row.name}</span>
                    <span>{row.detail}</span>
                  </div>
                );
              })}
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Primary route</span>
                <strong>Launchpad</strong>
              </div>
              <div>
                <span>Artifact type</span>
                <strong>Playwright screenshot</strong>
              </div>
            </div>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Operational snapshots</div>
                <h3 className="card-title">Persisted evidence</h3>
              </div>
              <span className={`badge ${snapshotRows.length ? 'badge-ok' : 'badge-info'}`}>
                {snapshotRows.length || 'Live'}
              </span>
            </div>
            {snapshotRows.length === 0 ? (
              <div className="empty empty-compact">
                Snapshots are generated as live signals refresh.
              </div>
            ) : (
              <div className="operator-health-list">
                {snapshotRows.slice(0, 5).map(([name, snapshot]) => {
                  const proofBadge = evidenceBadge(snapshot);
                  return (
                    <div
                      key={`${name}-${snapshot.digest || snapshot.storage_key}`}
                      className="operator-health-row"
                    >
                      <span
                        className={`badge ${snapshot.verified || snapshot.persisted ? 'badge-ok' : 'badge-warn'}`}
                      >
                        {snapshot.verified ? 'Verified' : snapshot.persisted ? 'Saved' : 'Inline'}
                      </span>
                      <span>{name}</span>
                      <span>{String(snapshot.digest || '').slice(0, 12)}</span>
                      {evidenceFreshness(snapshot) ? (
                        <span className={`badge ${proofBadge.className}`}>{proofBadge.label}</span>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            )}
            <div className="summary-meta" style={{ marginTop: 10 }}>
              {data.operationalSnapshots?.count ?? snapshotRows.length} indexed •{' '}
              {data.operationalSnapshots?.verified_count ?? snapshotRows.length} verified
            </div>
          </div>

          <div className="card operator-lane-card" id="demo-mode">
            <div className="card-header">
              <div>
                <div className="summary-label">Demo mode</div>
                <h3 className="card-title">Evaluation scenarios</h3>
              </div>
              <div className="btn-group">
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={resetDemoLab}
                  disabled={demoResetBusy}
                >
                  {demoResetBusy ? 'Resetting...' : 'Reset'}
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={startDemoLab}
                  disabled={demoBusy}
                >
                  {demoBusy ? 'Starting...' : 'Start'}
                </button>
              </div>
            </div>
            <div className="operator-demo-list">
              {demoScenarios.map((scenario) => (
                <span key={scenario}>{String(scenario).replaceAll('_', ' ')}</span>
              ))}
            </div>
            <div className="operator-kv-list">
              <div>
                <span>Scenario count</span>
                <strong>{demoScenarios.length}</strong>
              </div>
              <div>
                <span>Sample alerts</span>
                <strong>{demoSampleAlerts}</strong>
              </div>
              <div>
                <span>Handoff route</span>
                <strong>Reports evidence</strong>
              </div>
            </div>
            <div className="summary-meta">
              {data.demoStatus?.status || 'available'} • {demoSampleAlerts} sample alerts
            </div>
          </div>

          <div className="card operator-lane-card">
            <div className="card-header">
              <div>
                <div className="summary-label">Partial-state resilience</div>
                <h3 className="card-title">Runtime confidence</h3>
              </div>
              <span className={`badge ${errorRows.length === 0 ? 'badge-ok' : 'badge-warn'}`}>
                {errorRows.length === 0 ? 'Clean' : `${errorRows.length} degraded`}
              </span>
            </div>
            {errorRows.length === 0 ? (
              <div className="empty empty-compact">All launchpad signals loaded.</div>
            ) : (
              <div className="operator-health-list">
                {errorRows.map((row) => (
                  <div key={row.key} className="operator-health-row">
                    <span className="badge badge-warn">Partial</span>
                    <span>{row.key}</span>
                    <span>{row.message}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

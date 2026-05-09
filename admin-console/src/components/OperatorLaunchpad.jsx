import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import * as api from '../api.js';
import { useApiGroup, useToast } from '../hooks.jsx';
import { downloadData, formatDateTime } from './operatorUtils.js';

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
  { title: 'Open alert queue', href: '/monitor', shortcut: 'M' },
  { title: 'Detection quality', href: '/detection?panel=quality', shortcut: 'Cmd' },
  { title: 'Thread evidence', href: '/monitor?monitorTab=processes', shortcut: 'Cmd' },
  { title: 'Create incident', href: '/soc?intent=create-incident', shortcut: 'Cmd' },
  { title: 'Generate evidence', href: '/reports?tab=evidence', shortcut: 'Cmd' },
  { title: 'Integration health', href: '/settings?tab=integrations', shortcut: 'Cmd' },
];

function asArray(value, keys = []) {
  if (Array.isArray(value)) return value;
  for (const key of keys) {
    if (Array.isArray(value?.[key])) return value[key];
  }
  return [];
}

function countValue(value, keys = ['count', 'total', 'open', 'pending']) {
  if (typeof value === 'number') return value;
  for (const key of keys) {
    const numeric = Number(value?.[key]);
    if (Number.isFinite(numeric)) return numeric;
  }
  return 0;
}

function statusBadge(ok, pending = false) {
  if (pending) return { className: 'badge-warn', label: 'Needs review' };
  return ok
    ? { className: 'badge-ok', label: 'Ready' }
    : { className: 'badge-warn', label: 'Pending' };
}

function signalBadge(status) {
  const normalized = String(status || 'unknown').toLowerCase();
  if (['ready', 'pass', 'trusted', 'healthy', 'clear'].includes(normalized)) {
    return { className: 'badge-ok', label: normalized };
  }
  if (['blocked', 'fail', 'risk', 'attention'].includes(normalized)) {
    return { className: 'badge-err', label: normalized };
  }
  return { className: 'badge-warn', label: normalized };
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

export default function OperatorLaunchpad() {
  const toast = useToast();
  const [demoBusy, setDemoBusy] = useState(false);
  const [demoResetBusy, setDemoResetBusy] = useState(false);
  const [evidenceBusy, setEvidenceBusy] = useState(false);
  const [supportBundleBusy, setSupportBundleBusy] = useState(false);
  const { data, loading, errors, reload } = useApiGroup({
    health: api.health,
    status: api.status,
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
      `${countValue(data.releaseProvenance, ['artifact_count'])} artifacts`,
    ],
    [
      'Upgrade rehearsal',
      data.upgradeRehearsal?.status,
      data.upgradeRehearsal?.target_version || currentVersion,
    ],
    [
      'Synthetic console',
      data.syntheticConsole?.status,
      `${countValue(data.syntheticConsole, ['check_count'])} checks`,
    ],
    [
      'Timeline replay',
      data.incidentReplay?.status,
      `${countValue(data.incidentReplay, ['incident_count'])} incidents`,
    ],
    ['Detection trust', data.detectionTrust?.status, `${detectionTrustAverage || '—'} score`],
    [
      'Fleet drift',
      data.fleetDrift?.status,
      `${countValue(data.fleetDrift, ['version_drift'])} drifted`,
    ],
    ['Work queue', data.workQueue?.status, `${workQueueCount} items`],
    ['Retention', data.retentionForecast?.status, `${retentionPeak || '—'}% peak`],
    [
      'Adversarial',
      data.adversarialValidation?.status,
      `${countValue(data.adversarialValidation, ['scenario_count'])} scenarios`,
    ],
    [
      'Bundle diff',
      data.supportBundleDiff?.status,
      `${countValue(data.supportBundleDiff, ['snapshot_count'])} snapshots`,
    ],
  ];
  const releaseVerificationSignals = [
    [
      'Clean cut',
      data.cleanReleaseCut?.status,
      data.cleanReleaseCut?.target_version || currentVersion,
    ],
    [
      'Container parity',
      data.containerParity?.status,
      `${countValue(data.containerParity, ['fail_count'])} fails`,
    ],
    [
      'Verification center',
      data.releaseVerification?.status,
      `${countValue(data.releaseVerification, ['warn_count'])} warnings`,
    ],
    [
      'Deployment wizard',
      data.deploymentWizard?.status,
      data.deploymentWizard?.preflight?.storage_ready ? 'storage ready' : 'storage review',
    ],
    [
      'Data quality',
      data.dataQuality?.status,
      `${countValue(data.dataQuality?.metrics, ['dead_letter_events'])} DLQ`,
    ],
    [
      'Scale baseline',
      data.scaleBaseline?.status,
      `${countValue(data.scaleBaseline?.metrics, ['request_rate_per_min'])}/min`,
    ],
    [
      'Failover execution',
      data.failoverExecution?.status,
      data.failoverExecution?.mode || 'rehearsal',
    ],
    [
      'Secret rotation',
      data.secretsRotation?.status,
      `${countValue(data.secretsRotation, ['warn_count'])} warnings`,
    ],
    [
      'Task automation',
      data.taskAutomation?.status,
      `${countValue(data.taskAutomation, ['automation_count'])} actions`,
    ],
    [
      'Validation packs',
      data.validationPacks?.status,
      `${countValue(data.validationPacks, ['pack_count'])} packs`,
    ],
  ];
  const releaseVerificationRows = asArray(data.releaseVerification?.verification_rows);
  const deploymentPlans = asArray(data.deploymentWizard?.install_plans);
  const dataQualityScore = Number(data.dataQuality?.slo_summary?.score || 0);
  const loadGateRows = asArray(data.scaleBaseline?.load_gate);
  const automationBlueprints = asArray(data.taskAutomation?.action_blueprints);
  const executablePacks = countValue(data.validationPacks, ['executable_pack_count']);
  const productionBlockers = productionSignals.filter(([, status]) =>
    ['blocked', 'fail', 'risk', 'attention'].includes(String(status || '').toLowerCase()),
  ).length;
  const releaseVerificationBlockers = releaseVerificationSignals.filter(([, status]) =>
    ['blocked', 'fail', 'risk', 'attention'].includes(String(status || '').toLowerCase()),
  ).length;
  const productionBadge = statusBadge(
    productionBlockers === 0 && workQueueCount === 0,
    workQueueCount > 0,
  );
  const verificationBadge = statusBadge(
    releaseVerificationBlockers === 0,
    releaseVerificationBlockers > 0,
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

      <section className="operator-launchpad-grid">
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
            {releaseVerificationSignals.map(([name, status, detail]) => {
              const badge = signalBadge(status);
              return (
                <div key={name} className="operator-health-row">
                  <span className={`badge ${badge.className}`}>{badge.label}</span>
                  <span>{name}</span>
                  <span>{detail}</span>
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
              <span>Dry-run actions</span>
              <strong>{automationBlueprints.length || '—'}</strong>
            </div>
            <div>
              <span>Executable packs</span>
              <strong>{executablePacks || '—'}</strong>
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

        <div className="card operator-lane-card">
          <div className="card-header">
            <div>
              <div className="summary-label">Production assurance</div>
              <h3 className="card-title">Next tranche signals</h3>
            </div>
            <span className={`badge ${productionBadge.className}`}>{productionBadge.label}</span>
          </div>
          <div className="operator-health-list">
            {productionSignals.slice(0, 6).map(([name, status, detail]) => {
              const badge = signalBadge(status);
              return (
                <div key={name} className="operator-health-row">
                  <span className={`badge ${badge.className}`}>{badge.label}</span>
                  <span>{name}</span>
                  <span>{detail}</span>
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

        <div className="card operator-lane-card">
          <div className="card-header">
            <div>
              <div className="summary-label">Action safety</div>
              <h3 className="card-title">Approvals and dry-runs</h3>
            </div>
            <span className={`badge ${actionBadge.className}`}>{actionBadge.label}</span>
          </div>
          <div className="operator-kv-list">
            <div>
              <span>Pending approval</span>
              <strong>{pendingApprovals}</strong>
            </div>
            <div>
              <span>Ready to execute</span>
              <strong>
                {countValue(data.approvalOverview || data.response, ['ready_to_execute'])}
              </strong>
            </div>
            <div>
              <span>Rollback mode</span>
              <strong>{data.remediationSafety?.status || 'dry_run_only'}</strong>
            </div>
          </div>
          <Link className="btn btn-sm" to="/soc?focus=response">
            Review response queue
          </Link>
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
              {snapshotRows.slice(0, 5).map(([name, snapshot]) => (
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
                </div>
              ))}
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
      </section>
    </div>
  );
}

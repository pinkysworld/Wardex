const HUMANIZED_VALUE_KEYS = new Set([
  'intent',
  'focus',
  'source',
  'drawer',
  'tab',
  'queue',
  'queueFilter',
  'monitorTab',
  'fleetTab',
  'updatesPanel',
  'context',
]);

const HIDDEN_SCOPE_KEYS = new Set([
  'source',
  'context',
  'drawer',
  'casePanel',
  'incidentPanel',
  'intent',
]);

const SCOPE_KEY_PRIORITY = new Map([
  ['case', 0],
  ['incident', 1],
  ['investigation', 2],
  ['rule', 3],
  ['entity', 4],
  ['asset', 5],
  ['status', 6],
  ['tab', 7],
  ['monitorTab', 8],
  ['fleetTab', 9],
  ['updatesPanel', 10],
  ['panel', 11],
  ['view', 12],
  ['range', 13],
  ['sort', 14],
  ['scanPreset', 15],
  ['queue', 16],
  ['queueFilter', 17],
  ['focus', 18],
]);

const COMMAND_ROUTE_CONFIG = {
  'open-launchpad': {
    path: '/launchpad',
  },
  'create-incident': {
    path: '/soc',
    params: { intent: 'create-incident' },
  },
  'open-quarantine': {
    path: '/soc',
    params: { focus: 'quarantine' },
  },
  'run-hunt': {
    path: '/detection',
    params: { intent: 'run-hunt' },
  },
  'detection-quality': {
    path: '/detection',
    params: { panel: 'quality' },
  },
  'start-detection-lab': {
    path: '/detection-lab',
  },
  'thread-evidence': {
    path: '/monitor',
    params: { monitorTab: 'processes' },
  },
  'open-alert-evidence': {
    path: '/monitor',
    params: { drawer: 'alert-evidence' },
  },
  'review-response-safety': {
    path: '/response-safety',
  },
  'validate-connector': {
    path: '/integrations',
    params: { action: 'validate' },
  },
  'operations-health': {
    path: '/operations-health',
  },
  'open-assistant': {
    path: '/assistant',
  },
  'review-offline-agents': {
    path: '/fleet',
    params: { status: 'offline' },
  },
  'connect-first-agent': {
    path: '/fleet',
    params: { fleetTab: 'updates', updatesPanel: 'install' },
    hash: 'connect-agent-drawer',
  },
  'connect-agent-drawer': {
    path: '/fleet',
    params: { fleetTab: 'updates', updatesPanel: 'install' },
    hash: 'connect-agent-drawer',
  },
  'guided-incident': {
    path: '/launchpad',
    hash: 'guided-incident-path',
  },
  'morning-brief': {
    path: '/launchpad',
    hash: 'morning-brief',
  },
  'shift-handoff-workspace': {
    path: '/launchpad',
    hash: 'shift-handoff-workspace',
  },
  'incident-timeline-builder': {
    path: '/launchpad',
    hash: 'incident-timeline-builder',
  },
  'collector-onboarding-center': {
    path: '/launchpad',
    hash: 'collector-onboarding-center',
  },
  'response-simulator': {
    path: '/launchpad',
    hash: 'response-simulator',
  },
  'response-playbook-simulator': {
    path: '/launchpad',
    hash: 'response-playbook-simulator',
  },
  'fleet-health-drilldown': {
    path: '/launchpad',
    hash: 'fleet-health-drilldown',
  },
  'fleet-risk-heatmap': {
    path: '/launchpad',
    hash: 'fleet-risk-heatmap',
  },
  'evidence-freshness': {
    path: '/launchpad',
    hash: 'evidence-freshness',
  },
  'evidence-surface-coverage': {
    path: '/launchpad',
    hash: 'evidence-surface-coverage',
  },
  'operator-task-queue': {
    path: '/launchpad',
    hash: 'operator-task-queue',
  },
  'release-gate': {
    path: '/launchpad',
    hash: 'release-gate-automation',
  },
  'release-acceptance-report': {
    path: '/launchpad',
    hash: 'release-acceptance-report',
  },
  'role-home-screen': {
    path: '/launchpad',
    hash: 'role-home-screen',
  },
  'visual-regression-gate': {
    path: '/launchpad',
    hash: 'visual-regression-gate',
  },
  'safe-assistant': {
    path: '/launchpad',
    hash: 'safe-assistant',
  },
  'open-soc-queue': {
    path: '/soc',
    hash: 'queue',
  },
  'open-process-workbench': {
    path: '/soc',
    hash: 'process-tree',
  },
  'response-readiness': {
    path: '/soc',
    params: { source: 'command-palette' },
    hash: 'response',
  },
  'integration-health': {
    path: '/integrations',
  },
  'release-diff': {
    path: '/launchpad',
    hash: 'release-trust',
  },
  'deployment-confidence': {
    path: '/launchpad',
    hash: 'deployment-confidence',
  },
  'evidence-pack': {
    path: '/reports',
    params: { tab: 'evidence' },
  },
  'malware-scan-presets': {
    path: '/malware',
    params: { scanPreset: 'open-source-av-baseline' },
  },
  'rootkit-sweep': {
    path: '/malware',
    params: { scanPreset: 'rootkit-persistence-sweep' },
  },
  'trojan-loader-hunt': {
    path: '/malware',
    params: { scanPreset: 'trojan-loader-hunt' },
  },
  'demo-lab': {
    path: '/launchpad',
    hash: 'demo-mode',
  },
  'demo-scenarios': {
    path: '/launchpad',
    hash: 'demo-mode',
  },
};

function humanizeToken(value) {
  return String(value)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replaceAll('-', ' ')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function humanizeTokenValue(key, value) {
  if (!HUMANIZED_VALUE_KEYS.has(key)) return String(value);
  return humanizeToken(value);
}

export function buildHref(path, { params, hash } = {}) {
  const search = new URLSearchParams();

  Object.entries(params || {}).forEach(([key, value]) => {
    if (value == null) return;
    const normalized = String(value).trim();
    if (!normalized) return;
    search.set(key, normalized);
  });

  const query = search.toString();
  const normalizedHash = hash ? `#${String(hash).replace(/^#/, '')}` : '';
  return `${path}${query ? `?${query}` : ''}${normalizedHash}`;
}

export function buildCommandHref(action, { params, hash } = {}) {
  const config = COMMAND_ROUTE_CONFIG[action];
  if (!config) return '';

  return buildHref(config.path, {
    params: {
      ...(config.params || {}),
      ...(params || {}),
    },
    hash: hash ?? config.hash,
  });
}

export function buildContextualHelpHref(sectionId, currentSearch = '') {
  const params = new URLSearchParams(currentSearch);
  params.set('context', sectionId);
  const query = params.toString();
  return `/help${query ? `?${query}` : ''}`;
}

export function describeSearchScope(search = '') {
  const params = new URLSearchParams(search);
  const tokens = [];
  let index = 0;

  params.forEach((value, key) => {
    const normalized = String(value || '').trim();
    if (!normalized || HIDDEN_SCOPE_KEYS.has(key)) return;
    tokens.push({
      key,
      label: `${humanizeToken(key)}: ${humanizeTokenValue(key, normalized)}`,
      priority: SCOPE_KEY_PRIORITY.get(key) ?? 99,
      index,
    });
    index += 1;
  });

  return tokens
    .sort((left, right) =>
      left.priority === right.priority ? left.index - right.index : left.priority - right.priority,
    )
    .map((token) => token.label);
}

export const SEARCH_COMMANDS = [
  {
    title: 'Open Operator Launchpad',
    subtitle: 'Review readiness, integrations, release trust, and evidence paths',
    icon: 'OP',
    action: 'open-launchpad',
    path: buildCommandHref('open-launchpad'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Create Incident',
    subtitle: 'Open the SOC workbench with a create flow',
    icon: 'CMD',
    action: 'create-incident',
    path: buildCommandHref('create-incident'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Connect First Agent',
    subtitle: 'Create an enrollment token and copy an OS-specific install command',
    icon: 'AG',
    action: 'connect-first-agent',
    path: buildCommandHref('connect-first-agent'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Connect Agent Drawer',
    subtitle: 'Open the persistent Fleet install bundle and remote enrollment panel',
    icon: 'AG',
    action: 'connect-agent-drawer',
    path: buildCommandHref('connect-agent-drawer'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Guided Incident Path',
    subtitle: 'Walk alert triage through evidence, response simulation, and handoff packaging',
    icon: 'SOC',
    action: 'guided-incident',
    path: buildCommandHref('guided-incident'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Morning Brief',
    subtitle: 'Review shift handoff, readiness gaps, approvals, and release blockers',
    icon: 'BRF',
    action: 'morning-brief',
    path: buildCommandHref('morning-brief'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Shift Handoff Workspace',
    subtitle: 'Export next-shift notes with queue, evidence, release, and fleet watch items',
    icon: 'SHF',
    action: 'shift-handoff-workspace',
    path: buildCommandHref('shift-handoff-workspace'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Incident Timeline Builder',
    subtitle: 'Assemble alert, process, replay, and report context into a timeline draft',
    icon: 'TL',
    action: 'incident-timeline-builder',
    path: buildCommandHref('incident-timeline-builder'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Collector Onboarding Center',
    subtitle: 'Review cloud, identity, SaaS, endpoint, and syslog telemetry lanes',
    icon: 'COL',
    action: 'collector-onboarding-center',
    path: buildCommandHref('collector-onboarding-center'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Open SOC Queue',
    subtitle: 'Review alert queue, why-this-fired evidence, and triage actions',
    icon: 'SOC',
    action: 'open-soc-queue',
    path: buildCommandHref('open-soc-queue'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Open Process Workbench',
    subtitle: 'Jump to live process evidence, security findings, and deep chains',
    icon: 'PS',
    action: 'open-process-workbench',
    path: buildCommandHref('open-process-workbench'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Open Quarantine',
    subtitle: 'Jump to active response and quarantine work',
    icon: 'CMD',
    action: 'open-quarantine',
    path: buildCommandHref('open-quarantine'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Run Hunt',
    subtitle: 'Open threat detection and start a hunt',
    icon: 'CMD',
    action: 'run-hunt',
    path: buildCommandHref('run-hunt'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Detection Quality',
    subtitle: 'Open quality scoring, blockers, and promotion readiness',
    icon: 'DQ',
    action: 'detection-quality',
    path: buildCommandHref('detection-quality'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Start Detection Lab',
    subtitle: 'Replay telemetry, run safe simulations, and validate detection packs',
    icon: 'LAB',
    action: 'start-detection-lab',
    path: buildCommandHref('start-detection-lab'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Thread Evidence',
    subtitle: 'Open process telemetry for thread anomaly review',
    icon: 'THR',
    action: 'thread-evidence',
    path: buildCommandHref('thread-evidence'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Open Alert Evidence',
    subtitle: 'Review source, raw event, why-this-fired, freshness, and evidence export preview',
    icon: 'EV',
    action: 'open-alert-evidence',
    path: buildCommandHref('open-alert-evidence'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Ask Assistant',
    subtitle: 'Open the analyst assistant with case-aware context',
    icon: 'CMD',
    action: 'open-assistant',
    path: buildCommandHref('open-assistant'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Review Offline Agents',
    subtitle: 'Open fleet with the offline status view',
    icon: 'CMD',
    action: 'review-offline-agents',
    path: buildCommandHref('review-offline-agents'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Review Response Safety',
    subtitle: 'Open response dry-run previews, approvals, rollback, and verification',
    icon: 'SAFE',
    action: 'review-response-safety',
    path: buildCommandHref('review-response-safety'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Response Readiness',
    subtitle: 'Open approvals, rollback readiness, execution logs, and verification state',
    icon: 'RR',
    action: 'response-readiness',
    path: buildCommandHref('response-readiness'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Response Simulator',
    subtitle: 'Preview blast radius, approvals, rollback, and verification before execution',
    icon: 'SIM',
    action: 'response-simulator',
    path: buildCommandHref('response-simulator'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Response Playbook Simulator',
    subtitle: 'Review blast radius, approval policy, rollback posture, and audit boundary',
    icon: 'SIM',
    action: 'response-playbook-simulator',
    path: buildCommandHref('response-playbook-simulator'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Integration Health',
    subtitle: 'Open SIEM, SSO, SCIM, and collector readiness',
    icon: 'INT',
    action: 'integration-health',
    path: buildCommandHref('integration-health'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Validate Connector',
    subtitle: 'Open connector health, sample event preview, and setup checklist',
    icon: 'INT',
    action: 'validate-connector',
    path: buildCommandHref('validate-connector'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Operations Health',
    subtitle: 'Open deployment SLOs, ingestion, queue, scan, API, storage, and fleet health',
    icon: 'OPS',
    action: 'operations-health',
    path: buildCommandHref('operations-health'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Release Diff',
    subtitle: 'Review current version, latest catalog, and attestation state',
    icon: 'REL',
    action: 'release-diff',
    path: buildCommandHref('release-diff'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Deployment Confidence',
    subtitle:
      'Review release verification, install plans, evidence freshness, and deployment gates',
    icon: 'DEP',
    action: 'deployment-confidence',
    path: buildCommandHref('deployment-confidence'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Fleet Health Drilldown',
    subtitle: 'Review online coverage, drift, stale heartbeats, and agent connection pivots',
    icon: 'FLT',
    action: 'fleet-health-drilldown',
    path: buildCommandHref('fleet-health-drilldown'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Fleet Risk Heatmap',
    subtitle: 'Compare offline, stale heartbeat, version drift, and active detection risk',
    icon: 'RSK',
    action: 'fleet-risk-heatmap',
    path: buildCommandHref('fleet-risk-heatmap'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Evidence Freshness',
    subtitle: 'Find stale proof, missing snapshots, and freshness gaps before handoff',
    icon: 'EV',
    action: 'evidence-freshness',
    path: buildCommandHref('evidence-freshness'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Evidence Surface Coverage',
    subtitle: 'Check proof freshness across SOC, reports, release gates, and response queues',
    icon: 'EV',
    action: 'evidence-surface-coverage',
    path: buildCommandHref('evidence-surface-coverage'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Operator Task Queue',
    subtitle: 'Open generated shift tasks from approvals, evidence gaps, and release blockers',
    icon: 'TASK',
    action: 'operator-task-queue',
    path: buildCommandHref('operator-task-queue'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Release Gate Automation',
    subtitle: 'Review doctor, preflight, validation packs, contract drift, and release blockers',
    icon: 'REL',
    action: 'release-gate',
    path: buildCommandHref('release-gate'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Release Acceptance Report',
    subtitle: 'Export acceptance proof with release gates, blockers, and evidence rows',
    icon: 'REL',
    action: 'release-acceptance-report',
    path: buildCommandHref('release-acceptance-report'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Role Home Screen',
    subtitle: 'Open the Launchpad card tailored for admin, analyst, or viewer work',
    icon: 'ROLE',
    action: 'role-home-screen',
    path: buildCommandHref('role-home-screen'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Visual Regression Gate',
    subtitle: 'Open the screenshot gate surface used by Playwright visual smoke tests',
    icon: 'VIS',
    action: 'visual-regression-gate',
    path: buildCommandHref('visual-regression-gate'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Safe Assistant',
    subtitle: 'Review retrieval-only, citation, and execution boundaries before asking',
    icon: 'AI',
    action: 'safe-assistant',
    path: buildCommandHref('safe-assistant'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Evidence Pack',
    subtitle: 'Open report evidence and readiness export workflow',
    icon: 'EV',
    action: 'evidence-pack',
    path: buildCommandHref('evidence-pack'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Malware Scan Presets',
    subtitle: 'Wire open-source malware, virus, trojan, and rootkit scan combinations',
    icon: 'AV',
    action: 'malware-scan-presets',
    path: buildCommandHref('malware-scan-presets'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Rootkit Sweep',
    subtitle: 'Open whole-system rootkit and persistence scan presets',
    icon: 'RK',
    action: 'rootkit-sweep',
    path: buildCommandHref('rootkit-sweep'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Trojan Loader Hunt',
    subtitle: 'Open downloader, C2, persistence, and credential-access scan presets',
    icon: 'TR',
    action: 'trojan-loader-hunt',
    path: buildCommandHref('trojan-loader-hunt'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Demo Lab',
    subtitle: 'Open evaluation scenarios and seeded telemetry controls',
    icon: 'DEMO',
    action: 'demo-lab',
    path: buildCommandHref('demo-lab'),
    category: 'Command',
    kind: 'action',
  },
  {
    title: 'Demo Scenarios',
    subtitle: 'Open evaluation mode, scenario reset, and seeded alert controls',
    icon: 'DEMO',
    action: 'demo-scenarios',
    path: buildCommandHref('demo-scenarios'),
    category: 'Command',
    kind: 'action',
  },
];

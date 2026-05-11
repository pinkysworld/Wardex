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
  'context',
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
  'thread-evidence': {
    path: '/monitor',
    params: { monitorTab: 'processes' },
  },
  'open-assistant': {
    path: '/assistant',
  },
  'review-offline-agents': {
    path: '/fleet',
    params: { status: 'offline' },
  },
  'integration-health': {
    path: '/settings',
    params: { tab: 'integrations' },
  },
  'release-diff': {
    path: '/launchpad',
    hash: 'release-trust',
  },
  'evidence-pack': {
    path: '/reports',
    params: { tab: 'evidence' },
  },
  'malware-scan-presets': {
    path: '/infrastructure',
    params: { tab: 'integrity', malwarePanel: 'summary', scanPreset: 'open-source-av-baseline' },
  },
  'rootkit-sweep': {
    path: '/infrastructure',
    params: { tab: 'integrity', malwarePanel: 'actions', scanPreset: 'rootkit-persistence-sweep' },
  },
  'trojan-loader-hunt': {
    path: '/infrastructure',
    params: { tab: 'integrity', malwarePanel: 'provenance', scanPreset: 'trojan-loader-hunt' },
  },
  'demo-lab': {
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

  params.forEach((value, key) => {
    const normalized = String(value || '').trim();
    if (!normalized) return;
    tokens.push(`${humanizeToken(key)}: ${humanizeTokenValue(key, normalized)}`);
  });

  return tokens;
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
    title: 'Thread Evidence',
    subtitle: 'Open process telemetry for thread anomaly review',
    icon: 'THR',
    action: 'thread-evidence',
    path: buildCommandHref('thread-evidence'),
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
    title: 'Integration Health',
    subtitle: 'Open SIEM, SSO, SCIM, and collector readiness',
    icon: 'INT',
    action: 'integration-health',
    path: buildCommandHref('integration-health'),
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
];

import { formatDateTime, formatRelativeTime } from '../operatorUtils.js';

export const CONNECTOR_LANES = [
  {
    id: 'aws',
    label: 'AWS CloudTrail',
    provider: 'aws_cloudtrail',
    category: 'Cloud',
    statusKey: 'awsCollector',
    settingsPath: '/settings?settingsTab=collectors&collector=aws',
  },
  {
    id: 'azure',
    label: 'Azure Activity',
    provider: 'azure_activity',
    category: 'Cloud',
    statusKey: 'azureCollector',
    settingsPath: '/settings?settingsTab=collectors&collector=azure',
  },
  {
    id: 'gcp',
    label: 'GCP Audit Logs',
    provider: 'gcp_audit',
    category: 'Cloud',
    statusKey: 'gcpCollector',
    settingsPath: '/settings?settingsTab=collectors&collector=gcp',
  },
  {
    id: 'okta',
    label: 'Okta System Log',
    provider: 'okta_identity',
    category: 'Identity',
    statusKey: 'oktaCollector',
    settingsPath: '/settings?settingsTab=collectors&collector=okta',
  },
  {
    id: 'entra',
    label: 'Microsoft Entra',
    provider: 'entra_identity',
    category: 'Identity',
    statusKey: 'entraCollector',
    settingsPath: '/settings?settingsTab=collectors&collector=entra',
  },
  {
    id: 'm365',
    label: 'Microsoft 365',
    provider: 'm365_saas',
    category: 'SaaS',
    statusKey: 'm365Collector',
    settingsPath: '/settings?settingsTab=collectors&collector=m365',
  },
  {
    id: 'workspace',
    label: 'Google Workspace',
    provider: 'workspace_saas',
    category: 'SaaS',
    statusKey: 'workspaceCollector',
    settingsPath: '/settings?settingsTab=collectors&collector=workspace',
  },
  {
    id: 'github',
    label: 'GitHub Audit Log',
    provider: 'github_audit',
    category: 'SaaS',
    statusKey: 'githubCollector',
    newLane: true,
    requiredFields: ['organization', 'token_ref'],
    sampleEvent: 'org.audit_log.oauth_access.create',
  },
  {
    id: 'crowdstrike',
    label: 'CrowdStrike Falcon',
    provider: 'crowdstrike_falcon',
    category: 'EDR',
    statusKey: 'crowdstrikeCollector',
    newLane: true,
    requiredFields: ['client_id', 'client_secret_ref', 'cloud'],
    sampleEvent: 'DetectionSummaryEvent',
  },
  {
    id: 'syslog',
    label: 'Generic Syslog',
    provider: 'generic_syslog',
    category: 'Network',
    statusKey: 'syslogCollector',
    newLane: true,
    requiredFields: ['listen_addr', 'parser'],
    sampleEvent: 'cef:0|wardex|syslog|auth_failure',
  },
];

export const IMPROVEMENT_LANES = [
  'Shift Command Board',
  'Incident Command Center',
  'Connector Onboarding Wizard',
  'Detection Quality Dashboard',
  'Release and Upgrade Center',
  'Guided Remediation Approval Flow',
  'AI Analyst Evidence Boundaries',
  'Attack Storytelling',
  'RBAC Polish',
  'Rule Tuning Workflow',
  'Compliance Evidence Packs',
];

export const asArray = (value, keys = []) => {
  if (Array.isArray(value)) return value;
  for (const key of keys) {
    if (Array.isArray(value?.[key])) return value[key];
  }
  return [];
};

export const normalizedStatus = (value) =>
  String(value || '')
    .trim()
    .toLowerCase();

export const statusBadge = (value) => {
  const status = normalizedStatus(value);
  if (['ok', 'ready', 'healthy', 'enabled', 'active', 'passing', 'connected'].includes(status)) {
    return 'badge-ok';
  }
  if (['failed', 'error', 'blocked', 'critical', 'degraded', 'unhealthy'].includes(status)) {
    return 'badge-err';
  }
  if (['pending', 'warning', 'configured', 'partial', 'draft', 'setup_ready'].includes(status)) {
    return 'badge-warn';
  }
  return 'badge-info';
};

export const riskBadge = (value) => {
  const risk = normalizedStatus(value);
  if (risk === 'critical' || risk === 'high') return 'badge-err';
  if (risk === 'medium') return 'badge-warn';
  return 'badge-info';
};

export const formatCount = (value) => {
  const numeric = Number(value || 0);
  if (!Number.isFinite(numeric)) return '0';
  return numeric.toLocaleString();
};

export const compactTimestamp = (value) => {
  if (!value) return 'No timestamp';
  return formatRelativeTime(value) || formatDateTime(value);
};

export const connectorStatus = (connector, data) => {
  const details = data[connector.statusKey] || {};
  const setup = details.setup || details.config || details;
  const validation = details.validation || setup.validation || {};
  const status =
    validation.status ||
    setup.status ||
    details.status ||
    (setup.enabled || details.enabled
      ? 'configured'
      : connector.newLane
        ? 'setup_ready'
        : 'not configured');
  const lastSuccess =
    setup.last_success_at || validation.last_success_at || details.last_success_at || null;
  return {
    status,
    detail:
      validation.message ||
      setup.message ||
      details.detail ||
      (lastSuccess
        ? `Last successful collection ${compactTimestamp(lastSuccess)}.`
        : connector.newLane
          ? 'Guided setup is available with saved config, validation, and sample-event proof.'
          : 'Awaiting validation.'),
    sample:
      setup.sample_event_type ||
      validation.sample_event_type ||
      details.sample_event_type ||
      setup.checkpoint_id ||
      connector.sampleEvent ||
      'Sample preview pending',
  };
};

export const connectorStatusFromReadiness = (connector, readiness = {}) => {
  const lastSuccess = readiness.last_success_at || null;
  const hasError = Boolean(readiness.last_error_at || readiness.error_category);
  const status = hasError
    ? 'warning'
    : readiness.enabled
      ? 'configured'
      : connector.newLane
        ? 'setup_ready'
        : 'not configured';
  return {
    status,
    detail: hasError
      ? `Last collector error ${compactTimestamp(readiness.last_error_at)}${readiness.error_category ? ` (${readiness.error_category})` : ''}.`
      : lastSuccess
        ? `Last successful collection ${compactTimestamp(lastSuccess)}.`
        : connector.newLane
          ? 'Guided setup is available with saved config, validation, and sample-event proof.'
          : 'Awaiting validation.',
    sample:
      readiness.checkpoint_id ||
      readiness.sample_event_type ||
      connector.sampleEvent ||
      'Sample preview pending',
  };
};

export const defaultPlannedConnectorConfig = (connectorId) => {
  switch (connectorId) {
    case 'github':
      return {
        enabled: true,
        organization: 'example-org',
        token_ref: 'vault://wardex/github-audit-token',
        poll_interval_secs: 300,
      };
    case 'crowdstrike':
      return {
        enabled: true,
        cloud: 'us-1',
        client_id: 'crowdstrike-client-id',
        client_secret_ref: 'vault://wardex/crowdstrike-client-secret',
        poll_interval_secs: 300,
      };
    case 'syslog':
      return {
        enabled: true,
        listen_addr: '0.0.0.0:5514',
        parser: 'cef_or_rfc5424',
        sample_window_secs: 300,
      };
    default:
      return { enabled: true };
  }
};

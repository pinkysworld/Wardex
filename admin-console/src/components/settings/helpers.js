// Pure helpers and constants extracted from Settings.jsx.
// No React, no JSX — just data shaping and validation utilities.

export const AUDIT_PAGE_SIZE = 25;
export const AUDIT_METHOD_OPTIONS = ['all', 'GET', 'POST', 'PUT', 'DELETE'];
export const AUDIT_STATUS_OPTIONS = ['all', '2xx', '4xx', '5xx'];
export const AUDIT_AUTH_OPTIONS = ['all', 'authenticated', 'anonymous'];
export const IDENTITY_PROVIDER_OPTIONS = [
  { value: 'oidc', label: 'OIDC' },
  { value: 'saml', label: 'SAML' },
];
export const IDENTITY_ROLE_OPTIONS = [
  { value: 'admin', label: 'Admin' },
  { value: 'analyst', label: 'Analyst' },
  { value: 'viewer', label: 'Viewer' },
];
export const SCIM_MODE_OPTIONS = [
  { value: 'manual', label: 'Manual' },
  { value: 'automatic', label: 'Automatic' },
];
export const SIEM_TYPE_OPTIONS = [
  { value: 'generic', label: 'Generic JSON' },
  { value: 'splunk', label: 'Splunk HEC' },
  { value: 'elastic', label: 'Elastic Bulk' },
  { value: 'elastic-ecs', label: 'Elastic ECS' },
  { value: 'sentinel', label: 'Microsoft Sentinel' },
  { value: 'google', label: 'Google SecOps UDM' },
  { value: 'qradar', label: 'IBM QRadar' },
];

export function parseStructuredConfig(config) {
  if (!config) return null;
  if (typeof config !== 'string') return config;
  try {
    return JSON.parse(config);
  } catch {
    return null;
  }
}

export function normalizeAuditLogResponse(data) {
  if (Array.isArray(data)) {
    return {
      entries: data,
      total: data.length,
      offset: 0,
      limit: data.length,
      count: data.length,
      has_more: false,
    };
  }
  if (!data || typeof data !== 'object') {
    return {
      entries: [],
      total: 0,
      offset: 0,
      limit: AUDIT_PAGE_SIZE,
      count: 0,
      has_more: false,
    };
  }
  const entries = Array.isArray(data.entries) ? data.entries : [];
  const count = typeof data.count === 'number' ? data.count : entries.length;
  const offset = typeof data.offset === 'number' ? data.offset : 0;
  const limit = typeof data.limit === 'number' ? data.limit : AUDIT_PAGE_SIZE;
  const total = typeof data.total === 'number' ? data.total : offset + count;
  const hasMore = typeof data.has_more === 'boolean' ? data.has_more : offset + count < total;
  return {
    entries,
    total,
    offset,
    limit,
    count,
    has_more: hasMore,
  };
}

export function formatAuditTimestamp(value) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export function auditStatusClass(statusCode) {
  if (statusCode >= 500) return 'badge-err';
  if (statusCode >= 400) return 'badge-warn';
  return 'badge-ok';
}

export function auditRangeLabel(page) {
  if (!page.count || !page.total) return 'No audit entries captured yet.';
  return `Showing ${page.offset + 1}-${page.offset + page.count} of ${page.total} entries`;
}

export function normalizeValidation(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { status: 'unknown', issues: [], mapping_count: 0 };
  }
  return {
    status: typeof value.status === 'string' ? value.status : 'unknown',
    issues: Array.isArray(value.issues) ? value.issues : [],
    mapping_count: typeof value.mapping_count === 'number' ? value.mapping_count : 0,
  };
}

export function validationBadgeClass(status) {
  switch (status) {
    case 'ready':
      return 'badge-ok';
    case 'warning':
      return 'badge-warn';
    case 'error':
      return 'badge-err';
    case 'disabled':
      return 'badge-info';
    default:
      return 'badge-info';
  }
}

export function validationStatusLabel(status) {
  switch (status) {
    case 'ready':
      return 'Ready';
    case 'warning':
      return 'Review';
    case 'error':
      return 'Blocked';
    case 'disabled':
      return 'Disabled';
    default:
      return 'Unknown';
  }
}

export function normalizeCollectorTimeline(entry) {
  return Array.isArray(entry?.timeline) ? entry.timeline : [];
}

export function optionalTextValue(value) {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function formatGroupRoleMappings(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return '';
  return Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([group, role]) => `${group}=${role}`)
    .join('\n');
}

export function parseGroupRoleMappings(value) {
  const mappings = {};
  for (const line of value.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const separatorIndex = trimmed.includes('=') ? trimmed.indexOf('=') : trimmed.indexOf(':');
    if (separatorIndex <= 0) {
      return {
        mappings: null,
        error: `Use group=role on each line. Problem: ${trimmed}`,
      };
    }
    const group = trimmed.slice(0, separatorIndex).trim();
    const role = trimmed.slice(separatorIndex + 1).trim();
    if (!group || !role) {
      return {
        mappings: null,
        error: `Use group=role on each line. Problem: ${trimmed}`,
      };
    }
    mappings[group] = role;
  }
  return { mappings, error: null };
}

export function getDefaultSsoCallbackUri() {
  return typeof window === 'undefined'
    ? 'http://localhost:8080/api/auth/sso/callback'
    : `${window.location.origin}/api/auth/sso/callback`;
}

export function createIdpDraft(provider = null) {
  const defaultRedirectUri = getDefaultSsoCallbackUri();
  return {
    id: provider?.id || '',
    kind: String(provider?.kind || 'oidc').toLowerCase(),
    display_name: provider?.display_name || provider?.name || '',
    issuer_url: provider?.issuer_url || '',
    sso_url: provider?.sso_url || '',
    client_id: provider?.client_id || '',
    client_secret: '',
    redirect_uri: provider?.redirect_uri || defaultRedirectUri,
    entity_id: provider?.entity_id || '',
    enabled: provider?.enabled ?? true,
    mappings_text: formatGroupRoleMappings(provider?.group_role_mappings),
  };
}

export function buildSsoLoginPath(providerId, redirect = '/settings') {
  const params = new URLSearchParams();
  if (providerId) params.set('provider_id', providerId);
  params.set('redirect', redirect || '/settings');
  return `/api/auth/sso/login?${params.toString()}`;
}

export function collectorIdentifier(entry) {
  return String(entry?.name || entry?.provider || '').toLowerCase();
}

export function collectorLane(entry) {
  const id = collectorIdentifier(entry);
  if (id.includes('okta') || id.includes('entra')) return 'identity';
  if (
    id.includes('github') ||
    id.includes('m365') ||
    id.includes('microsoft_365') ||
    id.includes('workspace') ||
    id.includes('google_workspace')
  ) {
    return 'saas';
  }
  if (id.includes('aws') || id.includes('azure') || id.includes('gcp')) return 'cloud';
  if (id.includes('crowdstrike') || id.includes('falcon') || id.includes('syslog')) {
    return 'edge';
  }
  return 'other';
}

export function providerLoginKindLabel(kind) {
  return String(kind || 'oidc').toUpperCase();
}

export function createScimDraft(config = null) {
  return {
    enabled: Boolean(config?.enabled),
    base_url: config?.base_url || '',
    bearer_token: config?.bearer_token || '',
    provisioning_mode: String(config?.provisioning_mode || 'manual').toLowerCase(),
    default_role: String(config?.default_role || 'viewer').toLowerCase(),
    mappings_text: formatGroupRoleMappings(config?.group_role_mappings),
  };
}

export function createSiemDraft(config = null) {
  return {
    enabled: Boolean(config?.enabled),
    siem_type: config?.siem_type || 'generic',
    endpoint: config?.endpoint || '',
    auth_token: '',
    index: config?.index || 'wardex',
    source_type: config?.source_type || 'wardex:xdr',
    poll_interval_secs: config?.poll_interval_secs ?? 60,
    pull_enabled: Boolean(config?.pull_enabled),
    pull_query: config?.pull_query || '',
    batch_size: config?.batch_size ?? 50,
    verify_tls: config?.verify_tls ?? true,
  };
}

export function parseListInput(value) {
  return value
    .split('\n')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function createRetentionDraft(status = null) {
  return {
    audit_max_records: status?.audit_max_records ?? 100000,
    alert_max_records: status?.alert_max_records ?? 50000,
    event_max_records: status?.event_max_records ?? 100000,
    audit_max_age_days: Math.round((status?.audit_max_age_secs ?? 0) / 86400),
    remote_syslog_endpoint: status?.remote_syslog_endpoint || '',
  };
}

export function createAwsCollectorDraft(data = null) {
  const config = data?.config ?? data ?? {};
  return {
    enabled: Boolean(config.enabled),
    region: config.region || 'us-east-1',
    access_key_id: config.access_key_id || '',
    secret_access_key: '',
    session_token: '',
    poll_interval_secs: config.poll_interval_secs ?? 60,
    max_results: config.max_results ?? 50,
    event_name_filter: Array.isArray(config.event_name_filter)
      ? config.event_name_filter.join('\n')
      : '',
  };
}

export function createAzureCollectorDraft(data = null) {
  const config = data?.config ?? data ?? {};
  return {
    enabled: Boolean(config.enabled),
    tenant_id: config.tenant_id || '',
    client_id: config.client_id || '',
    client_secret: '',
    subscription_id: config.subscription_id || '',
    poll_interval_secs: config.poll_interval_secs ?? 60,
    categories: Array.isArray(config.categories) ? config.categories.join('\n') : '',
  };
}

export function createGcpCollectorDraft(data = null) {
  const config = data?.config ?? data ?? {};
  return {
    enabled: Boolean(config.enabled),
    project_id: config.project_id || '',
    service_account_email: config.service_account_email || '',
    key_file_path: config.key_file_path || '',
    private_key_pem: '',
    poll_interval_secs: config.poll_interval_secs ?? 60,
    log_filter: config.log_filter || '',
    page_size: config.page_size ?? 100,
  };
}

export function createOktaCollectorDraft(data = null) {
  const config = data?.config ?? data ?? {};
  return {
    enabled: Boolean(config.enabled),
    domain: config.domain || '',
    api_token: '',
    poll_interval_secs: config.poll_interval_secs ?? 30,
    event_type_filter: Array.isArray(config.event_type_filter)
      ? config.event_type_filter.join('\n')
      : '',
  };
}

export function createEntraCollectorDraft(data = null) {
  const config = data?.config ?? data ?? {};
  return {
    enabled: Boolean(config.enabled),
    tenant_id: config.tenant_id || '',
    client_id: config.client_id || '',
    client_secret: '',
    poll_interval_secs: config.poll_interval_secs ?? 30,
  };
}

export function createM365CollectorDraft(data = null) {
  const config = data?.config ?? data ?? {};
  return {
    enabled: Boolean(config.enabled),
    tenant_id: config.tenant_id || '',
    client_id: config.client_id || '',
    client_secret: '',
    poll_interval_secs: config.poll_interval_secs ?? 60,
    content_types: Array.isArray(config.content_types) ? config.content_types.join('\n') : '',
  };
}

export function createWorkspaceCollectorDraft(data = null) {
  const config = data?.config ?? data ?? {};
  return {
    enabled: Boolean(config.enabled),
    customer_id: config.customer_id || 'my_customer',
    delegated_admin_email: config.delegated_admin_email || '',
    service_account_email: config.service_account_email || '',
    credentials_json: '',
    poll_interval_secs: config.poll_interval_secs ?? 60,
    applications: Array.isArray(config.applications) ? config.applications.join('\n') : '',
  };
}

export function createSecretsDraft(data = null) {
  const config = data?.config ?? data ?? {};
  const vault = config.vault ?? {};
  return {
    enabled: Boolean(vault.enabled),
    address: vault.address || 'http://127.0.0.1:8200',
    token: '',
    mount: vault.mount || 'secret',
    namespace: vault.namespace || '',
    cache_ttl_secs: vault.cache_ttl_secs ?? 300,
    env_prefix: config.env_prefix || '',
    secrets_dir: config.secrets_dir || '',
    test_reference: '',
  };
}

export function auditEmptyMessage(filtersActive) {
  return filtersActive
    ? 'No audit entries match the current filters.'
    : 'No audit entries captured yet.';
}

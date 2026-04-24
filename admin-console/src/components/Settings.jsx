import { useState, useEffect, useMemo, useId } from 'react';
import { useApi, useApiGroup, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid } from './operator.jsx';
import { useConfirm } from './useConfirm.jsx';
import { downloadData } from './operatorUtils.js';

const AUDIT_PAGE_SIZE = 25;
const AUDIT_METHOD_OPTIONS = ['all', 'GET', 'POST', 'PUT', 'DELETE'];
const AUDIT_STATUS_OPTIONS = ['all', '2xx', '4xx', '5xx'];
const AUDIT_AUTH_OPTIONS = ['all', 'authenticated', 'anonymous'];
const IDENTITY_PROVIDER_OPTIONS = [
  { value: 'oidc', label: 'OIDC' },
  { value: 'saml', label: 'SAML' },
];
const IDENTITY_ROLE_OPTIONS = [
  { value: 'admin', label: 'Admin' },
  { value: 'analyst', label: 'Analyst' },
  { value: 'viewer', label: 'Viewer' },
];
const SCIM_MODE_OPTIONS = [
  { value: 'manual', label: 'Manual' },
  { value: 'automatic', label: 'Automatic' },
];
const SIEM_TYPE_OPTIONS = [
  { value: 'generic', label: 'Generic JSON' },
  { value: 'splunk', label: 'Splunk HEC' },
  { value: 'elastic', label: 'Elastic Bulk' },
  { value: 'elastic-ecs', label: 'Elastic ECS' },
  { value: 'sentinel', label: 'Microsoft Sentinel' },
  { value: 'google', label: 'Google SecOps UDM' },
  { value: 'qradar', label: 'IBM QRadar' },
];

function parseStructuredConfig(config) {
  if (!config) return null;
  if (typeof config !== 'string') return config;
  try {
    return JSON.parse(config);
  } catch {
    return null;
  }
}

function normalizeAuditLogResponse(data) {
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

function formatAuditTimestamp(value) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function auditStatusClass(statusCode) {
  if (statusCode >= 500) return 'badge-err';
  if (statusCode >= 400) return 'badge-warn';
  return 'badge-ok';
}

function auditRangeLabel(page) {
  if (!page.count || !page.total) return 'No audit entries captured yet.';
  return `Showing ${page.offset + 1}-${page.offset + page.count} of ${page.total} entries`;
}

function normalizeValidation(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { status: 'unknown', issues: [], mapping_count: 0 };
  }
  return {
    status: typeof value.status === 'string' ? value.status : 'unknown',
    issues: Array.isArray(value.issues) ? value.issues : [],
    mapping_count: typeof value.mapping_count === 'number' ? value.mapping_count : 0,
  };
}

function validationBadgeClass(status) {
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

function validationStatusLabel(status) {
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

function normalizeCollectorTimeline(entry) {
  return Array.isArray(entry?.timeline) ? entry.timeline : [];
}

function CollectorTimelineList({ timeline }) {
  if (!Array.isArray(timeline) || timeline.length === 0) return null;
  return (
    <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
      {timeline.slice(0, 5).map((item, index) => (
        <div
          key={`${item.stage || 'checkpoint'}-${index}`}
          style={{
            padding: '8px 10px',
            borderRadius: 10,
            border: '1px solid var(--border)',
            background: 'var(--bg-card)',
          }}
        >
          <div className="chip-row" style={{ marginBottom: 6 }}>
            <span className={`badge ${validationBadgeClass(item.status)}`}>
              {item.stage || 'Checkpoint'}
            </span>
            {item.title && <span className="scope-chip">{item.title}</span>}
          </div>
          {item.detail && <div className="hint">{item.detail}</div>}
        </div>
      ))}
    </div>
  );
}

function CollectorLaneCard({
  title,
  hint,
  rows,
  emptyText,
  primaryHref,
  primaryLabel,
  secondaryHref,
  secondaryLabel,
}) {
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>
        {title}
      </div>
      <div className="hint" style={{ marginBottom: 12 }}>
        {hint}
      </div>
      <div style={{ display: 'grid', gap: 8 }}>
        {rows.length === 0 ? (
          <div className="empty">{emptyText}</div>
        ) : (
          rows.map((entry, index) => (
            <div key={`${collectorIdentifier(entry)}-${index}`} className="stat-box">
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  gap: 12,
                  alignItems: 'flex-start',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>
                    {entry.label || entry.name || entry.provider}
                  </div>
                  <div style={{ fontSize: 12, opacity: 0.75, marginTop: 4 }}>
                    {entry.total_collected || 0} events observed •{' '}
                    {validationStatusLabel(entry.validation?.status)}
                  </div>
                </div>
                <span className={`badge ${validationBadgeClass(entry.validation?.status)}`}>
                  {validationStatusLabel(entry.validation?.status)}
                </span>
              </div>
              <CollectorTimelineList timeline={normalizeCollectorTimeline(entry)} />
            </div>
          ))
        )}
      </div>
      <div className="btn-group" style={{ marginTop: 12, flexWrap: 'wrap' }}>
        <a className="btn btn-sm btn-primary" href={primaryHref}>
          {primaryLabel}
        </a>
        <a className="btn btn-sm" href={secondaryHref}>
          {secondaryLabel}
        </a>
      </div>
    </div>
  );
}

function optionalTextValue(value) {
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

function parseGroupRoleMappings(value) {
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

function formatApiError(error, fallback) {
  if (error?.body) {
    try {
      const parsed = JSON.parse(error.body);
      if (typeof parsed?.error === 'string' && parsed.error) return parsed.error;
    } catch {
      /* ignore invalid error bodies */
    }
  }
  if (typeof error?.message === 'string' && error.message) return error.message;
  return fallback;
}

function createIdpDraft(provider = null) {
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

function getDefaultSsoCallbackUri() {
  return typeof window === 'undefined'
    ? 'http://localhost:8080/api/auth/sso/callback'
    : `${window.location.origin}/api/auth/sso/callback`;
}

function buildSsoLoginPath(providerId, redirect = '/settings') {
  const params = new URLSearchParams();
  if (providerId) params.set('provider_id', providerId);
  params.set('redirect', redirect || '/settings');
  return `/api/auth/sso/login?${params.toString()}`;
}

function collectorIdentifier(entry) {
  return String(entry?.name || entry?.provider || '').toLowerCase();
}

function collectorLane(entry) {
  const id = collectorIdentifier(entry);
  if (id.includes('okta') || id.includes('entra')) return 'identity';
  if (
    id.includes('m365') ||
    id.includes('microsoft_365') ||
    id.includes('workspace') ||
    id.includes('google_workspace')
  ) {
    return 'saas';
  }
  if (id.includes('aws') || id.includes('azure') || id.includes('gcp')) return 'cloud';
  return 'other';
}

function providerLoginKindLabel(kind) {
  return String(kind || 'oidc').toUpperCase();
}

function createScimDraft(config = null) {
  return {
    enabled: Boolean(config?.enabled),
    base_url: config?.base_url || '',
    bearer_token: config?.bearer_token || '',
    provisioning_mode: String(config?.provisioning_mode || 'manual').toLowerCase(),
    default_role: String(config?.default_role || 'viewer').toLowerCase(),
    mappings_text: formatGroupRoleMappings(config?.group_role_mappings),
  };
}

function createSiemDraft(config = null) {
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

function parseListInput(value) {
  return value
    .split('\n')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function createRetentionDraft(status = null) {
  return {
    audit_max_records: status?.audit_max_records ?? 100000,
    alert_max_records: status?.alert_max_records ?? 50000,
    event_max_records: status?.event_max_records ?? 100000,
    audit_max_age_days: Math.round((status?.audit_max_age_secs ?? 0) / 86400),
    remote_syslog_endpoint: status?.remote_syslog_endpoint || '',
  };
}

function createAwsCollectorDraft(data = null) {
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

function createAzureCollectorDraft(data = null) {
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

function createGcpCollectorDraft(data = null) {
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

function createOktaCollectorDraft(data = null) {
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

function createEntraCollectorDraft(data = null) {
  const config = data?.config ?? data ?? {};
  return {
    enabled: Boolean(config.enabled),
    tenant_id: config.tenant_id || '',
    client_id: config.client_id || '',
    client_secret: '',
    poll_interval_secs: config.poll_interval_secs ?? 30,
  };
}

function createM365CollectorDraft(data = null) {
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

function createWorkspaceCollectorDraft(data = null) {
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

function createSecretsDraft(data = null) {
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

function auditEmptyMessage(filtersActive) {
  return filtersActive
    ? 'No audit entries match the current filters.'
    : 'No audit entries captured yet.';
}

function ToggleSwitch({ label, checked, onChange, description }) {
  const toggleId = useId();
  return (
    <label
      htmlFor={toggleId}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        cursor: 'pointer',
        padding: '6px 0',
      }}
    >
      <button
        id={toggleId}
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        onKeyDown={(e) => {
          if (e.key === ' ' || e.key === 'Enter') {
            e.preventDefault();
            onChange(!checked);
          }
        }}
        style={{
          width: 40,
          height: 22,
          borderRadius: 11,
          background: checked ? 'var(--primary)' : 'var(--border)',
          position: 'relative',
          transition: 'background .2s',
          flexShrink: 0,
          border: 'none',
          padding: 0,
        }}
      >
        <span
          style={{
            width: 18,
            height: 18,
            borderRadius: 9,
            background: '#fff',
            position: 'absolute',
            top: 2,
            left: checked ? 20 : 2,
            transition: 'left .2s',
            boxShadow: '0 1px 3px rgba(0,0,0,.2)',
          }}
        />
      </button>
      <span>
        <span style={{ fontSize: 13, fontWeight: 500 }}>{label}</span>
        {description && (
          <span style={{ display: 'block', fontSize: 11, color: 'var(--text-secondary)' }}>
            {description}
          </span>
        )}
      </span>
    </label>
  );
}

function NumberInput({ label, value, onChange, min, max, step, unit, description }) {
  const inputId = useId();
  return (
    <div style={{ marginBottom: 10 }}>
      <label
        htmlFor={inputId}
        style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}
      >
        {label}
      </label>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input
          id={inputId}
          name={label.toLowerCase().replace(/\s+/g, '_')}
          type="number"
          value={value ?? ''}
          onChange={(e) => {
            const n = Number(e.target.value);
            onChange(Math.min(max ?? Infinity, Math.max(min ?? -Infinity, n)));
          }}
          min={min}
          max={max}
          step={step || 1}
          style={{
            width: 90,
            padding: '4px 8px',
            borderRadius: 'var(--radius)',
            border: '1px solid var(--border)',
            background: 'var(--bg)',
            color: 'var(--text)',
            fontSize: 13,
          }}
        />
        {unit && <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{unit}</span>}
      </div>
      {description && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
          {description}
        </div>
      )}
    </div>
  );
}

function TextInput({ label, value, onChange, placeholder, description, type = 'text' }) {
  const inputId = useId();
  return (
    <div style={{ marginBottom: 10 }}>
      <label
        htmlFor={inputId}
        style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}
      >
        {label}
      </label>
      <input
        id={inputId}
        name={label.toLowerCase().replace(/\s+/g, '_')}
        type={type}
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: '100%',
          maxWidth: 400,
          padding: '6px 10px',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--border)',
          background: 'var(--bg)',
          color: 'var(--text)',
          fontSize: 13,
        }}
      />
      {description && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
          {description}
        </div>
      )}
    </div>
  );
}

function SelectInput({ label, value, onChange, options, description }) {
  const inputId = useId();
  return (
    <div style={{ marginBottom: 10 }}>
      <label
        htmlFor={inputId}
        style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}
      >
        {label}
      </label>
      <select
        id={inputId}
        name={label.toLowerCase().replace(/\s+/g, '_')}
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        style={{
          width: '100%',
          maxWidth: 400,
          padding: '6px 10px',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--border)',
          background: 'var(--bg)',
          color: 'var(--text)',
          fontSize: 13,
        }}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {description && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
          {description}
        </div>
      )}
    </div>
  );
}

function TextAreaInput({ label, value, onChange, placeholder, rows = 5, description }) {
  const inputId = useId();
  return (
    <div style={{ marginBottom: 10 }}>
      <label
        htmlFor={inputId}
        style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}
      >
        {label}
      </label>
      <textarea
        id={inputId}
        name={label.toLowerCase().replace(/\s+/g, '_')}
        value={value ?? ''}
        rows={rows}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: '100%',
          padding: '8px 10px',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--border)',
          background: 'var(--bg)',
          color: 'var(--text)',
          fontSize: 13,
          fontFamily: 'var(--font-mono, ui-monospace, monospace)',
        }}
      />
      {description && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
          {description}
        </div>
      )}
    </div>
  );
}

function ValidationIssues({ validation, style }) {
  const normalized = normalizeValidation(validation);
  if (!normalized.issues.length) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, ...style }}>
      {normalized.issues.map((issue, index) => (
        <div key={`${issue.field}-${index}`} className="stat-box" style={{ fontSize: 12 }}>
          <span
            className={`badge ${issue.level === 'error' ? 'badge-err' : 'badge-warn'}`}
            style={{ marginRight: 8 }}
          >
            {issue.level}
          </span>
          <strong>{issue.field}:</strong> {issue.message}
        </div>
      ))}
    </div>
  );
}

export default function Settings() {
  const toast = useToast();
  const [confirm, confirmUI] = useConfirm();
  const [tab, setTab] = useState('config');
  const [auditPage, setAuditPage] = useState(0);
  const [auditQuery, setAuditQuery] = useState('');
  const [auditMethod, setAuditMethod] = useState('all');
  const [auditStatus, setAuditStatus] = useState('all');
  const [auditAuth, setAuditAuth] = useState('all');
  const { data: config, reload: rConfig } = useApi(api.configCurrent);
  const { data: monOpts } = useApi(api.monitoringOptions);
  const { data: monPaths } = useApi(api.monitoringPaths);
  const { data: flags } = useApi(api.featureFlags);
  const { data: integrationsData, reload: rIntegrations } = useApiGroup(
    {
      siemSt: api.siemStatus,
      siemCfg: api.siemConfig,
      taxiiSt: api.taxiiStatus,
      taxiiCfg: api.taxiiConfig,
      enrichConn: api.enrichmentConnectors,
      idp: api.idpProviders,
      scim: api.scimConfig,
      ssoConfigData: api.authSsoConfig,
      collectorsSummary: api.collectorsStatus,
      awsCollectorData: api.collectorsAws,
      azureCollectorData: api.collectorsAzure,
      gcpCollectorData: api.collectorsGcp,
      oktaCollectorData: api.collectorsOkta,
      entraCollectorData: api.collectorsEntra,
      m365CollectorData: api.collectorsM365,
      workspaceCollectorData: api.collectorsWorkspace,
      secretsData: api.secretsStatus,
    },
    [tab],
    {
      skip: tab !== 'integrations',
    },
  );
  const {
    siemSt,
    siemCfg,
    taxiiSt,
    taxiiCfg,
    enrichConn,
    idp,
    scim,
    ssoConfigData,
    collectorsSummary,
    awsCollectorData,
    azureCollectorData,
    gcpCollectorData,
    oktaCollectorData,
    entraCollectorData,
    m365CollectorData,
    workspaceCollectorData,
    secretsData,
  } = integrationsData;
  const { data: sbomData } = useApi(api.sbom);
  const { data: dbVer } = useApi(api.adminDbVersion);
  const { data: dlqData } = useApi(api.dlqStats);
  const { data: dbSizes, reload: rSizes } = useApi(api.adminDbSizes);
  const [historicalDraft, setHistoricalDraft] = useState({
    since: '',
    until: '',
    tenant_id: '',
    device_id: '',
    user_name: '',
    src_ip: '',
    severity_min: '',
    event_class: '',
    limit: 25,
  });
  const [historicalQuery, setHistoricalQuery] = useState({ limit: 25 });
  const {
    data: adminRetentionWorkspaceData,
    loading: historicalEventsLoading,
    reload: reloadAdminRetentionWorkspace,
  } = useApiGroup(
    {
      storageStats: api.storageStats,
      retentionData: api.retentionStatus,
      historicalEventsData: () => api.historicalStorageEvents(historicalQuery),
    },
    [tab, JSON.stringify(historicalQuery)],
    {
      skip: tab !== 'admin',
    },
  );
  const { storageStats, retentionData, historicalEventsData } = adminRetentionWorkspaceData;
  const auditQueryValue = auditQuery.trim();
  const auditMethodValue = auditMethod !== 'all' ? auditMethod : undefined;
  const auditStatusValue = auditStatus !== 'all' ? auditStatus : undefined;
  const auditAuthValue = auditAuth !== 'all' ? auditAuth : undefined;
  const auditFiltersActive = Boolean(
    auditQueryValue || auditMethodValue || auditStatusValue || auditAuthValue,
  );
  const auditOffset = auditPage * AUDIT_PAGE_SIZE;
  const {
    data: auditLogData,
    loading: auditLogLoading,
    error: auditLogError,
    reload: rAuditLog,
  } = useApi(
    () =>
      api.auditLog({
        limit: AUDIT_PAGE_SIZE,
        offset: auditOffset,
        q: auditQueryValue,
        method: auditMethodValue,
        status: auditStatusValue,
        auth: auditAuthValue,
      }),
    [auditOffset, auditQueryValue, auditMethodValue, auditStatusValue, auditAuthValue],
    {
      skip: tab !== 'admin',
    },
  );
  const [configEditing, setConfigEditing] = useState(false);
  const [configText, setConfigText] = useState('');
  const [jsonError, setJsonError] = useState(null);
  const [structuredConfig, setStructuredConfig] = useState(null);
  const [editMode, setEditMode] = useState('form'); // 'form' or 'json'
  const [savedSnapshot, setSavedSnapshot] = useState(null);
  const [showDiff, setShowDiff] = useState(false);
  const [purgeDays, setPurgeDays] = useState(30);
  const [compacting, setCompacting] = useState(false);
  const [purging, setPurging] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [idpDraft, setIdpDraft] = useState(() => createIdpDraft());
  const [idpEditorOpen, setIdpEditorOpen] = useState(false);
  const [idpSaving, setIdpSaving] = useState(false);
  const [idpFormError, setIdpFormError] = useState(null);
  const [scimDraft, setScimDraft] = useState(() => createScimDraft());
  const [scimEditing, setScimEditing] = useState(false);
  const [scimSaving, setScimSaving] = useState(false);
  const [scimFormError, setScimFormError] = useState(null);
  const [retentionDraft, setRetentionDraft] = useState(() => createRetentionDraft());
  const [retentionSaving, setRetentionSaving] = useState(false);
  const [retentionApplying, setRetentionApplying] = useState(false);
  const [lastRetentionApply, setLastRetentionApply] = useState(null);
  const [siemDraft, setSiemDraft] = useState(() => createSiemDraft());
  const [awsCollectorDraft, setAwsCollectorDraft] = useState(() => createAwsCollectorDraft());
  const [azureCollectorDraft, setAzureCollectorDraft] = useState(() => createAzureCollectorDraft());
  const [gcpCollectorDraft, setGcpCollectorDraft] = useState(() => createGcpCollectorDraft());
  const [oktaCollectorDraft, setOktaCollectorDraft] = useState(() => createOktaCollectorDraft());
  const [entraCollectorDraft, setEntraCollectorDraft] = useState(() => createEntraCollectorDraft());
  const [m365CollectorDraft, setM365CollectorDraft] = useState(() => createM365CollectorDraft());
  const [workspaceCollectorDraft, setWorkspaceCollectorDraft] = useState(() =>
    createWorkspaceCollectorDraft(),
  );
  const [secretsDraft, setSecretsDraft] = useState(() => createSecretsDraft());
  const [siemSaving, setSiemSaving] = useState(false);
  const [awsCollectorSaving, setAwsCollectorSaving] = useState(false);
  const [azureCollectorSaving, setAzureCollectorSaving] = useState(false);
  const [gcpCollectorSaving, setGcpCollectorSaving] = useState(false);
  const [oktaCollectorSaving, setOktaCollectorSaving] = useState(false);
  const [entraCollectorSaving, setEntraCollectorSaving] = useState(false);
  const [m365CollectorSaving, setM365CollectorSaving] = useState(false);
  const [workspaceCollectorSaving, setWorkspaceCollectorSaving] = useState(false);
  const [secretsSaving, setSecretsSaving] = useState(false);
  const [siemValidationResult, setSiemValidationResult] = useState(null);
  const [awsCollectorValidationResult, setAwsCollectorValidationResult] = useState(null);
  const [azureCollectorValidationResult, setAzureCollectorValidationResult] = useState(null);
  const [gcpCollectorValidationResult, setGcpCollectorValidationResult] = useState(null);
  const [oktaCollectorValidationResult, setOktaCollectorValidationResult] = useState(null);
  const [entraCollectorValidationResult, setEntraCollectorValidationResult] = useState(null);
  const [m365CollectorValidationResult, setM365CollectorValidationResult] = useState(null);
  const [workspaceCollectorValidationResult, setWorkspaceCollectorValidationResult] =
    useState(null);
  const [secretValidationResult, setSecretValidationResult] = useState(null);

  // ── Team (RBAC) ──
  const { data: teamUsers, reload: rTeam } = useApi(api.rbacUsers);
  const [newUser, setNewUser] = useState({ username: '', role: 'analyst' });
  const [creatingUser, setCreatingUser] = useState(false);

  const parsedConfig = useMemo(() => parseStructuredConfig(config), [config]);
  const parsedConfigText = useMemo(
    () => (parsedConfig ? JSON.stringify(parsedConfig, null, 2) : ''),
    [parsedConfig],
  );
  const visibleConfig = configEditing ? structuredConfig : parsedConfig;

  const startEdit = () => {
    if (parsedConfig) {
      setStructuredConfig(structuredClone(parsedConfig));
      setSavedSnapshot(parsedConfigText);
    }
    setConfigText(parsedConfigText);
    setConfigEditing(true);
  };

  const updateField = (path, value) => {
    setStructuredConfig((prev) => {
      const next = structuredClone(prev);
      const keys = path.split('.');
      let obj = next;
      for (let i = 0; i < keys.length - 1; i++) {
        if (obj[keys[i]] === undefined) obj[keys[i]] = {};
        obj = obj[keys[i]];
      }
      obj[keys[keys.length - 1]] = value;
      return next;
    });
  };

  const saveConfig = async () => {
    try {
      const body = editMode === 'json' ? JSON.parse(configText) : structuredConfig;
      await api.configSave(body);
      await rConfig();
      toast('Config saved', 'success');
      setStructuredConfig(structuredClone(body));
      setSavedSnapshot(JSON.stringify(body, null, 2));
      setConfigEditing(false);
    } catch (e) {
      toast(
        editMode === 'json' && e instanceof SyntaxError ? 'Invalid JSON' : 'Save failed',
        'error',
      );
    }
  };

  // Config diff computation
  const configDiff = useMemo(() => {
    if (!savedSnapshot || !structuredConfig) return null;
    const current = JSON.stringify(structuredConfig, null, 2);
    if (current === savedSnapshot) return null;
    const oldLines = savedSnapshot.split('\n');
    const newLines = current.split('\n');
    const changes = [];
    const maxLen = Math.max(oldLines.length, newLines.length);
    for (let i = 0; i < maxLen; i++) {
      if (oldLines[i] !== newLines[i]) {
        if (oldLines[i]) changes.push({ type: 'remove', line: i + 1, text: oldLines[i] });
        if (newLines[i]) changes.push({ type: 'add', line: i + 1, text: newLines[i] });
      }
    }
    return changes.length > 0 ? changes : null;
  }, [savedSnapshot, structuredConfig]);

  const formatBytes = (bytes) => {
    if (bytes == null) return '—';
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  };

  const configScalars = useMemo(() => {
    if (!visibleConfig || typeof visibleConfig !== 'object') return null;
    return Object.fromEntries(
      Object.entries(visibleConfig).filter(
        ([, value]) => value == null || typeof value !== 'object' || Array.isArray(value),
      ),
    );
  }, [visibleConfig]);

  const configSections = useMemo(() => {
    if (!visibleConfig || typeof visibleConfig !== 'object') return [];
    return Object.entries(visibleConfig).filter(
      ([, value]) => value && typeof value === 'object' && !Array.isArray(value),
    );
  }, [visibleConfig]);

  const normalizedMonitoringPaths = useMemo(() => {
    if (Array.isArray(monPaths)) return monPaths;
    if (Array.isArray(monPaths?.paths)) return monPaths.paths;
    if (Array.isArray(monPaths?.items)) return monPaths.items;
    return [];
  }, [monPaths]);

  const connectorRows = useMemo(() => {
    if (Array.isArray(enrichConn)) return enrichConn;
    if (Array.isArray(enrichConn?.items)) return enrichConn.items;
    if (Array.isArray(enrichConn?.connectors)) return enrichConn.connectors;
    return [];
  }, [enrichConn]);

  const idpRows = useMemo(() => {
    const rows = Array.isArray(idp)
      ? idp
      : Array.isArray(idp?.providers)
        ? idp.providers
        : Array.isArray(idp?.items)
          ? idp.items
          : [];
    return rows.map((entry) => ({
      ...entry,
      validation: normalizeValidation(entry?.validation),
    }));
  }, [idp]);

  const siemConfigData = useMemo(() => {
    const candidate = siemCfg?.config ?? siemCfg;
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
    return candidate;
  }, [siemCfg]);

  const siemStatusData = useMemo(() => {
    if (!siemSt || typeof siemSt !== 'object' || Array.isArray(siemSt)) return null;
    return siemSt;
  }, [siemSt]);

  const scimConfigData = useMemo(() => {
    const candidate = scim?.config ?? scim;
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
    return candidate;
  }, [scim]);

  const siemValidation = useMemo(() => normalizeValidation(siemCfg?.validation), [siemCfg]);
  const scimValidation = useMemo(() => normalizeValidation(scim?.validation), [scim]);
  const ssoConfig = useMemo(
    () => (ssoConfigData && typeof ssoConfigData === 'object' ? ssoConfigData : null),
    [ssoConfigData],
  );
  const readySsoProviders = useMemo(
    () => (Array.isArray(ssoConfig?.providers) ? ssoConfig.providers : []),
    [ssoConfig],
  );
  const retentionConfig = useMemo(
    () => (retentionData && typeof retentionData === 'object' ? retentionData : null),
    [retentionData],
  );
  const historicalEvents = useMemo(
    () => (Array.isArray(historicalEventsData?.events) ? historicalEventsData.events : []),
    [historicalEventsData],
  );
  const collectorRows = useMemo(
    () =>
      Array.isArray(collectorsSummary?.collectors)
        ? collectorsSummary.collectors.map((entry) => ({
            ...entry,
            validation: normalizeValidation(entry?.validation),
          }))
        : [],
    [collectorsSummary],
  );
  const cloudCollectorRows = useMemo(
    () => collectorRows.filter((entry) => collectorLane(entry) === 'cloud'),
    [collectorRows],
  );
  const identityCollectorRows = useMemo(
    () => collectorRows.filter((entry) => collectorLane(entry) === 'identity'),
    [collectorRows],
  );
  const saasCollectorRows = useMemo(
    () => collectorRows.filter((entry) => collectorLane(entry) === 'saas'),
    [collectorRows],
  );
  const awsCollectorValidation = useMemo(
    () => normalizeValidation(awsCollectorData?.validation),
    [awsCollectorData],
  );
  const azureCollectorValidation = useMemo(
    () => normalizeValidation(azureCollectorData?.validation),
    [azureCollectorData],
  );
  const gcpCollectorValidation = useMemo(
    () => normalizeValidation(gcpCollectorData?.validation),
    [gcpCollectorData],
  );
  const oktaCollectorValidation = useMemo(
    () => normalizeValidation(oktaCollectorData?.validation),
    [oktaCollectorData],
  );
  const entraCollectorValidation = useMemo(
    () => normalizeValidation(entraCollectorData?.validation),
    [entraCollectorData],
  );
  const m365CollectorValidation = useMemo(
    () => normalizeValidation(m365CollectorData?.validation),
    [m365CollectorData],
  );
  const workspaceCollectorValidation = useMemo(
    () => normalizeValidation(workspaceCollectorData?.validation),
    [workspaceCollectorData],
  );
  const secretsManagerValidation = useMemo(
    () => normalizeValidation(secretsData?.validation),
    [secretsData],
  );
  const defaultSsoCallbackUri = useMemo(() => getDefaultSsoCallbackUri(), []);
  const enabledIdpCount = useMemo(
    () => idpRows.filter((provider) => provider.enabled).length,
    [idpRows],
  );
  const readyIdpCount = useMemo(
    () =>
      idpRows.filter((provider) => provider.enabled && provider.validation?.status === 'ready')
        .length,
    [idpRows],
  );
  const reviewIdpCount = useMemo(
    () =>
      idpRows.filter((provider) => provider.enabled && provider.validation?.status !== 'ready')
        .length,
    [idpRows],
  );
  const readyCloudCollectorCount = useMemo(
    () =>
      cloudCollectorRows.filter((entry) => entry.enabled && entry.validation?.status === 'ready')
        .length,
    [cloudCollectorRows],
  );
  const readyIdentityCollectorCount = useMemo(
    () =>
      identityCollectorRows.filter((entry) => entry.enabled && entry.validation?.status === 'ready')
        .length,
    [identityCollectorRows],
  );
  const readySaasCollectorCount = useMemo(
    () =>
      saasCollectorRows.filter((entry) => entry.enabled && entry.validation?.status === 'ready')
        .length,
    [saasCollectorRows],
  );
  const reviewCollectorCount = useMemo(
    () => collectorRows.filter((entry) => entry.validation?.status === 'warning').length,
    [collectorRows],
  );

  useEffect(() => {
    if (idpRows.length === 0) setIdpEditorOpen(true);
  }, [idpRows.length]);

  useEffect(() => {
    setSiemDraft(createSiemDraft(siemConfigData));
  }, [siemConfigData]);

  useEffect(() => {
    if (scimEditing) return;
    setScimDraft(createScimDraft(scimConfigData));
    setScimFormError(null);
  }, [scimConfigData, scimEditing]);

  useEffect(() => {
    setRetentionDraft(createRetentionDraft(retentionConfig));
  }, [retentionConfig]);

  useEffect(() => {
    setAwsCollectorDraft(createAwsCollectorDraft(awsCollectorData));
  }, [awsCollectorData]);

  useEffect(() => {
    setAzureCollectorDraft(createAzureCollectorDraft(azureCollectorData));
  }, [azureCollectorData]);

  useEffect(() => {
    setGcpCollectorDraft(createGcpCollectorDraft(gcpCollectorData));
  }, [gcpCollectorData]);

  useEffect(() => {
    setOktaCollectorDraft(createOktaCollectorDraft(oktaCollectorData));
  }, [oktaCollectorData]);

  useEffect(() => {
    setEntraCollectorDraft(createEntraCollectorDraft(entraCollectorData));
  }, [entraCollectorData]);

  useEffect(() => {
    setM365CollectorDraft(createM365CollectorDraft(m365CollectorData));
  }, [m365CollectorData]);

  useEffect(() => {
    setWorkspaceCollectorDraft(createWorkspaceCollectorDraft(workspaceCollectorData));
  }, [workspaceCollectorData]);

  useEffect(() => {
    setSecretsDraft((prev) => ({
      ...createSecretsDraft(secretsData),
      test_reference: prev.test_reference,
    }));
  }, [secretsData]);

  const flagEntries = useMemo(() => {
    if (!flags || typeof flags !== 'object' || Array.isArray(flags)) return [];
    return Object.entries(flags);
  }, [flags]);

  const auditLogPage = useMemo(() => normalizeAuditLogResponse(auditLogData), [auditLogData]);
  const auditControlStyle = {
    width: '100%',
    padding: '6px 10px',
    borderRadius: 'var(--radius)',
    border: '1px solid var(--border)',
    background: 'var(--bg)',
    color: 'var(--text)',
    fontSize: 13,
  };
  const auditLabelStyle = {
    display: 'block',
    fontSize: 12,
    fontWeight: 500,
    marginBottom: 4,
  };

  const clearAuditFilters = () => {
    setAuditQuery('');
    setAuditMethod('all');
    setAuditStatus('all');
    setAuditAuth('all');
    setAuditPage(0);
  };

  const exportAuditLog = async () => {
    try {
      const csv = await api.auditLogExport({
        q: auditQueryValue,
        method: auditMethodValue,
        status: auditStatusValue,
        auth: auditAuthValue,
      });
      downloadData(csv, 'wardex-api-audit.csv', 'text/csv;charset=utf-8');
      toast('Audit log exported', 'success');
    } catch {
      toast('Audit export failed', 'error');
    }
  };

  const openIdpEditor = (provider = null) => {
    setIdpDraft(createIdpDraft(provider));
    setIdpFormError(null);
    setIdpEditorOpen(true);
  };

  const closeIdpEditor = () => {
    setIdpFormError(null);
    setIdpDraft(createIdpDraft());
    setIdpEditorOpen(idpRows.length === 0);
  };

  const launchSsoValidation = (providerId) => {
    window.location.assign(buildSsoLoginPath(providerId, '/settings'));
  };

  const saveIdpProvider = async () => {
    const { mappings, error } = parseGroupRoleMappings(idpDraft.mappings_text);
    if (error) {
      setIdpFormError(error);
      toast(error, 'error');
      return;
    }

    setIdpSaving(true);
    setIdpFormError(null);
    try {
      const result = await api.createIdpProvider({
        id: idpDraft.id || undefined,
        kind: idpDraft.kind,
        display_name: idpDraft.display_name,
        issuer_url: optionalTextValue(idpDraft.issuer_url),
        sso_url: optionalTextValue(idpDraft.sso_url),
        client_id: optionalTextValue(idpDraft.client_id),
        client_secret: optionalTextValue(idpDraft.client_secret),
        redirect_uri: optionalTextValue(idpDraft.redirect_uri),
        entity_id: optionalTextValue(idpDraft.entity_id),
        enabled: idpDraft.enabled,
        group_role_mappings: mappings,
      });
      const validation = normalizeValidation(result?.validation);
      const provider = result?.provider ?? {};
      await rIntegrations();
      setIdpDraft(createIdpDraft(provider));
      setIdpEditorOpen(validation.status === 'warning');
      toast(
        validation.status === 'warning'
          ? 'Identity provider saved with warnings'
          : 'Identity provider saved',
        validation.status === 'warning' ? 'warning' : 'success',
      );
    } catch (error) {
      const message = formatApiError(error, 'Failed to save identity provider');
      setIdpFormError(message);
      toast(message, 'error');
    } finally {
      setIdpSaving(false);
    }
  };

  const openScimEditor = () => {
    setScimDraft(createScimDraft(scimConfigData));
    setScimFormError(null);
    setScimEditing(true);
  };

  const closeScimEditor = () => {
    setScimDraft(createScimDraft(scimConfigData));
    setScimFormError(null);
    setScimEditing(false);
  };

  const saveScimConfig = async () => {
    const { mappings, error } = parseGroupRoleMappings(scimDraft.mappings_text);
    if (error) {
      setScimFormError(error);
      toast(error, 'error');
      return;
    }

    setScimSaving(true);
    setScimFormError(null);
    try {
      const result = await api.setScimConfig({
        enabled: scimDraft.enabled,
        base_url: optionalTextValue(scimDraft.base_url),
        bearer_token: optionalTextValue(scimDraft.bearer_token),
        provisioning_mode: scimDraft.provisioning_mode,
        default_role: scimDraft.default_role,
        group_role_mappings: mappings,
      });
      const validation = normalizeValidation(result?.validation);
      await rIntegrations();
      setScimDraft(createScimDraft(result?.config ?? scimConfigData));
      setScimEditing(validation.status === 'warning');
      toast(
        validation.status === 'warning'
          ? 'SCIM configuration saved with warnings'
          : 'SCIM configuration saved',
        validation.status === 'warning' ? 'warning' : 'success',
      );
    } catch (error) {
      const message = formatApiError(error, 'Failed to save SCIM configuration');
      setScimFormError(message);
      toast(message, 'error');
    } finally {
      setScimSaving(false);
    }
  };

  const saveRetentionSettings = async () => {
    const nextRetention = {
      audit_max_records: Number(retentionDraft.audit_max_records),
      alert_max_records: Number(retentionDraft.alert_max_records),
      event_max_records: Number(retentionDraft.event_max_records),
      audit_max_age_secs: Math.max(0, Number(retentionDraft.audit_max_age_days) || 0) * 86400,
      remote_syslog_endpoint: optionalTextValue(retentionDraft.remote_syslog_endpoint),
    };

    if (
      [
        nextRetention.audit_max_records,
        nextRetention.alert_max_records,
        nextRetention.event_max_records,
      ].some((value) => Number.isNaN(value) || value < 0)
    ) {
      toast('Retention record limits must be zero or positive numbers.', 'error');
      return;
    }

    setRetentionSaving(true);
    try {
      await api.configSave({ retention: nextRetention });
      await Promise.all([rConfig(), refreshAdminRetentionWorkspace()]);
      toast('Retention settings saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save retention settings'), 'error');
    } finally {
      setRetentionSaving(false);
    }
  };

  const applyRetentionNow = async () => {
    const ok = await confirm({
      title: 'Apply retention now?',
      message:
        'This trims in-memory alerts and retained events using the current retention settings. The operation cannot be undone.',
      confirmLabel: 'Apply retention',
      tone: 'warning',
    });
    if (!ok) return;

    setRetentionApplying(true);
    try {
      const result = await api.retentionApply({});
      setLastRetentionApply(result);
      await refreshAdminRetentionWorkspace();
      toast(
        `Retention applied: ${result.trimmed_alerts ?? 0} alerts and ${result.trimmed_events ?? 0} events trimmed`,
        'success',
      );
    } catch (error) {
      toast(formatApiError(error, 'Failed to apply retention settings'), 'error');
    } finally {
      setRetentionApplying(false);
    }
  };

  const runHistoricalSearch = async () => {
    setHistoricalQuery({
      ...historicalDraft,
      limit: Number(historicalDraft.limit) || 25,
    });
  };

  const refreshAdminRetentionWorkspace = () => reloadAdminRetentionWorkspace();

  const buildSiemPayload = () => ({
    enabled: siemDraft.enabled,
    siem_type: siemDraft.siem_type,
    endpoint: siemDraft.endpoint,
    auth_token: optionalTextValue(siemDraft.auth_token),
    index: siemDraft.index,
    source_type: siemDraft.source_type,
    poll_interval_secs: Number(siemDraft.poll_interval_secs),
    pull_enabled: siemDraft.pull_enabled,
    pull_query: siemDraft.pull_query,
    batch_size: Number(siemDraft.batch_size),
    verify_tls: siemDraft.verify_tls,
  });

  const saveSiemConfig = async () => {
    setSiemSaving(true);
    try {
      await api.setSiemConfig(buildSiemPayload());
      setSiemValidationResult(null);
      await rIntegrations();
      toast('SIEM setup saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save SIEM setup'), 'error');
    } finally {
      setSiemSaving(false);
    }
  };

  const validateSiemConfig = async () => {
    try {
      const result = await api.validateSiemConfig(buildSiemPayload());
      setSiemValidationResult(result);
      toast(
        result.success
          ? 'SIEM configuration validated'
          : result.error || 'SIEM validation needs attention',
        result.success ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, 'SIEM validation failed'), 'error');
    }
  };

  const saveAwsCollector = async () => {
    setAwsCollectorSaving(true);
    try {
      await api.saveAwsCollectorConfig({
        enabled: awsCollectorDraft.enabled,
        region: awsCollectorDraft.region,
        access_key_id: awsCollectorDraft.access_key_id,
        secret_access_key: optionalTextValue(awsCollectorDraft.secret_access_key),
        session_token: awsCollectorDraft.session_token,
        poll_interval_secs: Number(awsCollectorDraft.poll_interval_secs),
        max_results: Number(awsCollectorDraft.max_results),
        event_name_filter: parseListInput(awsCollectorDraft.event_name_filter),
      });
      setAwsCollectorValidationResult(null);
      await rIntegrations();
      toast('AWS CloudTrail setup saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save AWS CloudTrail setup'), 'error');
    } finally {
      setAwsCollectorSaving(false);
    }
  };

  const validateAwsCollector = async () => {
    try {
      const result = await api.validateAwsCollector();
      setAwsCollectorValidationResult(result);
      toast(
        result.success
          ? `AWS validation returned ${result.event_count ?? 0} event${result.event_count === 1 ? '' : 's'}`
          : result.error || 'AWS validation needs attention',
        result.success ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, 'AWS validation failed'), 'error');
    }
  };

  const saveAzureCollector = async () => {
    setAzureCollectorSaving(true);
    try {
      await api.saveAzureCollectorConfig({
        enabled: azureCollectorDraft.enabled,
        tenant_id: azureCollectorDraft.tenant_id,
        client_id: azureCollectorDraft.client_id,
        client_secret: optionalTextValue(azureCollectorDraft.client_secret),
        subscription_id: azureCollectorDraft.subscription_id,
        poll_interval_secs: Number(azureCollectorDraft.poll_interval_secs),
        categories: parseListInput(azureCollectorDraft.categories),
      });
      setAzureCollectorValidationResult(null);
      await rIntegrations();
      toast('Azure Activity setup saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save Azure Activity setup'), 'error');
    } finally {
      setAzureCollectorSaving(false);
    }
  };

  const validateAzureCollector = async () => {
    try {
      const result = await api.validateAzureCollector();
      setAzureCollectorValidationResult(result);
      toast(
        result.success
          ? `Azure validation returned ${result.event_count ?? 0} event${result.event_count === 1 ? '' : 's'}`
          : result.error || 'Azure validation needs attention',
        result.success ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, 'Azure validation failed'), 'error');
    }
  };

  const saveGcpCollector = async () => {
    setGcpCollectorSaving(true);
    try {
      await api.saveGcpCollectorConfig({
        enabled: gcpCollectorDraft.enabled,
        project_id: gcpCollectorDraft.project_id,
        service_account_email: gcpCollectorDraft.service_account_email,
        key_file_path: gcpCollectorDraft.key_file_path,
        private_key_pem: optionalTextValue(gcpCollectorDraft.private_key_pem),
        poll_interval_secs: Number(gcpCollectorDraft.poll_interval_secs),
        log_filter: gcpCollectorDraft.log_filter,
        page_size: Number(gcpCollectorDraft.page_size),
      });
      setGcpCollectorValidationResult(null);
      await rIntegrations();
      toast('GCP Audit setup saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save GCP Audit setup'), 'error');
    } finally {
      setGcpCollectorSaving(false);
    }
  };

  const validateGcpCollector = async () => {
    try {
      const result = await api.validateGcpCollector();
      setGcpCollectorValidationResult(result);
      toast(
        result.success
          ? `GCP validation returned ${result.event_count ?? 0} event${result.event_count === 1 ? '' : 's'}`
          : result.error || 'GCP validation needs attention',
        result.success ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, 'GCP validation failed'), 'error');
    }
  };

  const saveOktaCollector = async () => {
    setOktaCollectorSaving(true);
    try {
      await api.saveOktaCollectorConfig({
        enabled: oktaCollectorDraft.enabled,
        domain: oktaCollectorDraft.domain,
        api_token: optionalTextValue(oktaCollectorDraft.api_token),
        poll_interval_secs: Number(oktaCollectorDraft.poll_interval_secs),
        event_type_filter: parseListInput(oktaCollectorDraft.event_type_filter),
      });
      setOktaCollectorValidationResult(null);
      await rIntegrations();
      toast('Okta identity setup saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save Okta identity setup'), 'error');
    } finally {
      setOktaCollectorSaving(false);
    }
  };

  const validateOktaCollector = async () => {
    try {
      const result = await api.validateOktaCollector();
      setOktaCollectorValidationResult(result);
      toast(
        result.success
          ? `Okta validation returned ${result.event_count ?? 0} event${result.event_count === 1 ? '' : 's'}`
          : result.error || 'Okta validation needs attention',
        result.success ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, 'Okta validation failed'), 'error');
    }
  };

  const saveEntraCollector = async () => {
    setEntraCollectorSaving(true);
    try {
      await api.saveEntraCollectorConfig({
        enabled: entraCollectorDraft.enabled,
        tenant_id: entraCollectorDraft.tenant_id,
        client_id: entraCollectorDraft.client_id,
        client_secret: optionalTextValue(entraCollectorDraft.client_secret),
        poll_interval_secs: Number(entraCollectorDraft.poll_interval_secs),
      });
      setEntraCollectorValidationResult(null);
      await rIntegrations();
      toast('Microsoft Entra identity setup saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save Microsoft Entra identity setup'), 'error');
    } finally {
      setEntraCollectorSaving(false);
    }
  };

  const validateEntraCollector = async () => {
    try {
      const result = await api.validateEntraCollector();
      setEntraCollectorValidationResult(result);
      toast(
        result.success
          ? `Entra validation returned ${result.event_count ?? 0} event${result.event_count === 1 ? '' : 's'}`
          : result.error || 'Entra validation needs attention',
        result.success ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, 'Entra validation failed'), 'error');
    }
  };

  const saveM365Collector = async () => {
    setM365CollectorSaving(true);
    try {
      await api.saveM365CollectorConfig({
        enabled: m365CollectorDraft.enabled,
        tenant_id: m365CollectorDraft.tenant_id,
        client_id: m365CollectorDraft.client_id,
        client_secret: optionalTextValue(m365CollectorDraft.client_secret),
        poll_interval_secs: Number(m365CollectorDraft.poll_interval_secs),
        content_types: parseListInput(m365CollectorDraft.content_types),
      });
      setM365CollectorValidationResult(null);
      await rIntegrations();
      toast('Microsoft 365 activity setup saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save Microsoft 365 activity setup'), 'error');
    } finally {
      setM365CollectorSaving(false);
    }
  };

  const validateM365Collector = async () => {
    try {
      const result = await api.validateM365Collector();
      setM365CollectorValidationResult(result);
      toast(
        result.success
          ? `Microsoft 365 validation returned ${result.event_count ?? 0} event${result.event_count === 1 ? '' : 's'}`
          : result.error || 'Microsoft 365 validation needs attention',
        result.success ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, 'Microsoft 365 validation failed'), 'error');
    }
  };

  const saveWorkspaceCollector = async () => {
    setWorkspaceCollectorSaving(true);
    try {
      await api.saveWorkspaceCollectorConfig({
        enabled: workspaceCollectorDraft.enabled,
        customer_id: workspaceCollectorDraft.customer_id,
        delegated_admin_email: workspaceCollectorDraft.delegated_admin_email,
        service_account_email: workspaceCollectorDraft.service_account_email,
        credentials_json: optionalTextValue(workspaceCollectorDraft.credentials_json),
        poll_interval_secs: Number(workspaceCollectorDraft.poll_interval_secs),
        applications: parseListInput(workspaceCollectorDraft.applications),
      });
      setWorkspaceCollectorValidationResult(null);
      await rIntegrations();
      toast('Google Workspace activity setup saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save Google Workspace activity setup'), 'error');
    } finally {
      setWorkspaceCollectorSaving(false);
    }
  };

  const validateWorkspaceCollector = async () => {
    try {
      const result = await api.validateWorkspaceCollector();
      setWorkspaceCollectorValidationResult(result);
      toast(
        result.success
          ? `Google Workspace validation returned ${result.event_count ?? 0} event${result.event_count === 1 ? '' : 's'}`
          : result.error || 'Google Workspace validation needs attention',
        result.success ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, 'Google Workspace validation failed'), 'error');
    }
  };

  const saveSecretsManager = async () => {
    setSecretsSaving(true);
    try {
      await api.saveSecretsConfig({
        vault: {
          enabled: secretsDraft.enabled,
          address: secretsDraft.address,
          token: optionalTextValue(secretsDraft.token),
          mount: secretsDraft.mount,
          namespace: secretsDraft.namespace,
          cache_ttl_secs: Number(secretsDraft.cache_ttl_secs),
        },
        env_prefix: secretsDraft.env_prefix,
        secrets_dir: secretsDraft.secrets_dir,
      });
      await rIntegrations();
      toast('Secrets manager setup saved', 'success');
    } catch (error) {
      toast(formatApiError(error, 'Failed to save secrets manager setup'), 'error');
    } finally {
      setSecretsSaving(false);
    }
  };

  const validateSecretsReference = async () => {
    if (!secretsDraft.test_reference.trim()) {
      toast('Enter a secret reference to validate.', 'error');
      return;
    }

    try {
      const result = await api.validateSecretReference({ reference: secretsDraft.test_reference });
      setSecretValidationResult(result);
      toast(
        result.ok ? 'Secret reference resolved' : result.error || 'Secret validation failed',
        result.ok ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, 'Secret validation failed'), 'error');
    }
  };

  useEffect(() => {
    if (!configEditing || !configDiff) return undefined;
    const handleBeforeUnload = (event) => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [configDiff, configEditing]);

  // Default config values for reset
  const DEFAULTS = {
    collection_interval_secs: 15,
    alert_threshold: 2.5,
    entropy_threshold_pct: 10,
    network_burst_threshold_kbps: 3500,
    port: 9097,
    log_level: 'info',
  };

  const resetToDefaults = async () => {
    const ok = await confirm({
      title: 'Reset configuration to defaults?',
      message:
        'Built-in defaults will overwrite the currently loaded values. You still have to click Save to apply them server-side.',
      confirmLabel: 'Reset',
      tone: 'warning',
    });
    if (!ok) return;
    setStructuredConfig((prev) => {
      const next = structuredClone(prev);
      Object.entries(DEFAULTS).forEach(([k, v]) => {
        if (k in next) next[k] = v;
      });
      return next;
    });
    toast('Reset to defaults — click Save to apply', 'info');
  };

  return (
    <div>
      <div className="tabs">
        {['config', 'monitoring', 'integrations', 'flags', 'team', 'admin'].map((t) => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'config' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Configuration</span>
              <div className="btn-group">
                <button className="btn btn-sm" onClick={rConfig}>
                  ↻ Reload
                </button>
                <button
                  className="btn btn-sm"
                  onClick={async () => {
                    try {
                      await api.configReload();
                      toast('Config reloaded from disk', 'success');
                      rConfig();
                    } catch {
                      toast('Reload failed', 'error');
                    }
                  }}
                >
                  Reload from Disk
                </button>
                {!configEditing && (
                  <button className="btn btn-sm btn-primary" onClick={startEdit}>
                    Edit
                  </button>
                )}
                {configEditing && (
                  <>
                    <button
                      className={`btn btn-sm ${editMode === 'form' ? 'btn-primary' : ''}`}
                      onClick={() => {
                        setEditMode('form');
                        if (configText) {
                          try {
                            setStructuredConfig(JSON.parse(configText));
                          } catch {
                            /* ignore parse errors */
                          }
                        }
                      }}
                    >
                      Form
                    </button>
                    <button
                      className={`btn btn-sm ${editMode === 'json' ? 'btn-primary' : ''}`}
                      onClick={() => {
                        setEditMode('json');
                        setConfigText(JSON.stringify(structuredConfig, null, 2));
                      }}
                    >
                      JSON
                    </button>
                  </>
                )}
              </div>
            </div>
            {configEditing ? (
              editMode === 'json' ? (
                <div>
                  {configDiff && (
                    <div
                      className="error-box"
                      style={{
                        marginBottom: 12,
                        background: 'var(--bg)',
                        color: 'var(--text)',
                        borderColor: 'var(--warning)',
                      }}
                    >
                      Unsaved changes are in progress. Leaving the page or closing the tab will
                      discard them.
                    </div>
                  )}
                  <textarea
                    className="form-textarea"
                    style={{
                      height: 300,
                      borderColor: jsonError ? 'var(--danger, #ef4444)' : undefined,
                    }}
                    value={configText}
                    onChange={(e) => {
                      const v = e.target.value;
                      setConfigText(v);
                      try {
                        JSON.parse(v);
                        setJsonError(null);
                      } catch (err) {
                        setJsonError(err.message);
                      }
                    }}
                  />
                  {jsonError && (
                    <div style={{ fontSize: 11, color: 'var(--danger, #ef4444)', marginTop: 4 }}>
                      ⚠ {jsonError}
                    </div>
                  )}
                  <div className="btn-group" style={{ marginTop: 8 }}>
                    <button className="btn btn-primary" onClick={saveConfig}>
                      Save
                    </button>
                    <button className="btn" onClick={() => setConfigEditing(false)}>
                      Cancel
                    </button>
                  </div>
                </div>
              ) : structuredConfig ? (
                <div>
                  {configDiff && (
                    <div
                      className="error-box"
                      style={{
                        marginBottom: 12,
                        background: 'var(--bg)',
                        color: 'var(--text)',
                        borderColor: 'var(--warning)',
                      }}
                    >
                      Unsaved changes are in progress. Save or cancel before leaving this screen.
                    </div>
                  )}
                  {/* Structured form for common fields */}
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                      gap: 16,
                      padding: '12px 0',
                    }}
                  >
                    <div className="card" style={{ padding: 14 }}>
                      <div
                        style={{
                          fontWeight: 600,
                          fontSize: 13,
                          marginBottom: 12,
                          color: 'var(--primary)',
                        }}
                      >
                        General
                      </div>
                      <NumberInput
                        label="Collection Interval"
                        value={structuredConfig.collection_interval_secs}
                        onChange={(v) => updateField('collection_interval_secs', v)}
                        min={1}
                        max={300}
                        unit="seconds"
                      />
                      <NumberInput
                        label="Port"
                        value={structuredConfig.port}
                        onChange={(v) => updateField('port', v)}
                        min={1}
                        max={65535}
                      />
                      <TextInput
                        label="Log Level"
                        value={structuredConfig.log_level}
                        onChange={(v) => updateField('log_level', v)}
                        placeholder="info, debug, warn"
                      />
                    </div>
                    <div className="card" style={{ padding: 14 }}>
                      <div
                        style={{
                          fontWeight: 600,
                          fontSize: 13,
                          marginBottom: 12,
                          color: 'var(--primary)',
                        }}
                      >
                        Detection Thresholds
                      </div>
                      <NumberInput
                        label="Alert Threshold"
                        value={structuredConfig.alert_threshold}
                        onChange={(v) => updateField('alert_threshold', v)}
                        min={0}
                        max={10}
                        step={0.1}
                        description="Score above which an alert fires"
                      />
                      <NumberInput
                        label="Entropy Threshold"
                        value={structuredConfig.entropy_threshold_pct}
                        onChange={(v) => updateField('entropy_threshold_pct', v)}
                        min={0}
                        max={100}
                        unit="%"
                      />
                      <NumberInput
                        label="Network Burst Threshold"
                        value={structuredConfig.network_burst_threshold_kbps}
                        onChange={(v) => updateField('network_burst_threshold_kbps', v)}
                        min={0}
                        max={100000}
                        unit="kbps"
                      />
                    </div>
                    {structuredConfig.siem && (
                      <div className="card" style={{ padding: 14 }}>
                        <div
                          style={{
                            fontWeight: 600,
                            fontSize: 13,
                            marginBottom: 12,
                            color: 'var(--primary)',
                          }}
                        >
                          SIEM
                        </div>
                        <ToggleSwitch
                          label="SIEM Enabled"
                          checked={!!structuredConfig.siem?.enabled}
                          onChange={(v) => updateField('siem.enabled', v)}
                        />
                        <TextInput
                          label="Endpoint"
                          value={structuredConfig.siem?.endpoint}
                          onChange={(v) => updateField('siem.endpoint', v)}
                          placeholder="https://siem.example.com"
                        />
                        <TextInput
                          label="Format"
                          value={structuredConfig.siem?.format}
                          onChange={(v) => updateField('siem.format', v)}
                          placeholder="cef, json, leef"
                        />
                      </div>
                    )}
                    {structuredConfig.taxii && (
                      <div className="card" style={{ padding: 14 }}>
                        <div
                          style={{
                            fontWeight: 600,
                            fontSize: 13,
                            marginBottom: 12,
                            color: 'var(--primary)',
                          }}
                        >
                          TAXII
                        </div>
                        <ToggleSwitch
                          label="TAXII Enabled"
                          checked={!!structuredConfig.taxii?.enabled}
                          onChange={(v) => updateField('taxii.enabled', v)}
                        />
                        <TextInput
                          label="Server URL"
                          value={structuredConfig.taxii?.url}
                          onChange={(v) => updateField('taxii.url', v)}
                          placeholder="https://taxii.example.com"
                        />
                        <NumberInput
                          label="Poll Interval"
                          value={structuredConfig.taxii?.poll_interval_secs}
                          onChange={(v) => updateField('taxii.poll_interval_secs', v)}
                          min={60}
                          unit="seconds"
                        />
                      </div>
                    )}
                  </div>
                  {/* All other fields as key-value pairs */}
                  <details style={{ marginTop: 12 }}>
                    <summary
                      style={{ cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)' }}
                    >
                      All configuration fields ({Object.keys(structuredConfig).length})
                    </summary>
                    <div style={{ padding: '12px 0' }}>
                      {Object.entries(structuredConfig)
                        .filter(
                          ([k]) =>
                            !['siem', 'taxii'].includes(k) &&
                            typeof structuredConfig[k] !== 'object',
                        )
                        .map(([k, v]) => (
                          <div
                            key={k}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 10,
                              padding: '4px 0',
                              borderBottom: '1px solid var(--border)',
                            }}
                          >
                            <span
                              style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: 12,
                                minWidth: 200,
                                color: 'var(--text-secondary)',
                              }}
                            >
                              {k}
                            </span>
                            {typeof v === 'boolean' ? (
                              <ToggleSwitch
                                label=""
                                checked={v}
                                onChange={(val) => updateField(k, val)}
                              />
                            ) : (
                              <input
                                type={typeof v === 'number' ? 'number' : 'text'}
                                value={v ?? ''}
                                onChange={(e) =>
                                  updateField(
                                    k,
                                    typeof v === 'number' ? Number(e.target.value) : e.target.value,
                                  )
                                }
                                style={{
                                  flex: 1,
                                  maxWidth: 300,
                                  padding: '4px 8px',
                                  borderRadius: 'var(--radius)',
                                  border: '1px solid var(--border)',
                                  background: 'var(--bg)',
                                  color: 'var(--text)',
                                  fontSize: 12,
                                }}
                              />
                            )}
                          </div>
                        ))}
                    </div>
                  </details>
                  {/* Config diff */}
                  {configDiff && (
                    <div style={{ marginTop: 12 }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => setShowDiff(!showDiff)}
                        style={{ marginBottom: 8 }}
                      >
                        {showDiff ? 'Hide' : 'Show'} Changes ({configDiff.length})
                      </button>
                      {showDiff && (
                        <div
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 11,
                            background: 'var(--bg)',
                            borderRadius: 'var(--radius)',
                            padding: 10,
                            maxHeight: 200,
                            overflowY: 'auto',
                          }}
                        >
                          {configDiff.map((d, i) => (
                            <div
                              key={i}
                              style={{
                                color: d.type === 'add' ? 'var(--success)' : 'var(--danger)',
                                whiteSpace: 'pre',
                              }}
                            >
                              {d.type === 'add' ? '+' : '-'} {d.text}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  <div className="btn-group" style={{ marginTop: 12 }}>
                    <button className="btn btn-primary" onClick={saveConfig}>
                      Save
                    </button>
                    <button className="btn" onClick={() => setConfigEditing(false)}>
                      Cancel
                    </button>
                    <button
                      className="btn"
                      onClick={resetToDefaults}
                      title="Reset common fields to default values"
                    >
                      Reset Defaults
                    </button>
                  </div>
                </div>
              ) : (
                <div className="empty">Loading configuration...</div>
              )
            ) : parsedConfig ? (
              <div style={{ padding: '12px 0' }}>
                <SummaryGrid
                  data={configScalars}
                  limit={12}
                  emptyMessage="Configuration is organized into sections below"
                />
                {configSections.length > 0 && (
                  <div className="card-grid" style={{ marginTop: 16 }}>
                    {configSections.map(([sectionKey, sectionValue]) => (
                      <div key={sectionKey} className="card" style={{ padding: 14 }}>
                        <div className="card-title" style={{ marginBottom: 12 }}>
                          {sectionKey.replace(/_/g, ' ')}
                        </div>
                        <SummaryGrid data={sectionValue} limit={8} />
                      </div>
                    ))}
                  </div>
                )}
                <JsonDetails data={parsedConfig} label="Full configuration breakdown" />
              </div>
            ) : (
              <>
                <div className="empty">Configuration is not yet available in structured form.</div>
                <JsonDetails data={config} label="Available configuration fields" />
              </>
            )}
          </div>
        </>
      )}

      {tab === 'monitoring' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Monitoring Scope
            </div>
            {monOpts && typeof monOpts === 'object' ? (
              <>
                <SummaryGrid data={monOpts} limit={12} />
                <JsonDetails data={monOpts} />
              </>
            ) : (
              <>
                <div className="empty">No monitoring scope metadata available.</div>
                <JsonDetails data={monOpts} />
              </>
            )}
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Monitored Paths
            </div>
            {normalizedMonitoringPaths.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Path</th>
                      <th>Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {normalizedMonitoringPaths.map((p, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                          {typeof p === 'string'
                            ? p
                            : p.path || p.pattern || p.root || p.name || '—'}
                        </td>
                        <td>{typeof p === 'object' ? p.type || p.kind || 'file' : 'file'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : monPaths && typeof monPaths === 'object' ? (
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                  gap: 0,
                }}
              >
                {Object.entries(monPaths).map(([k, v]) => (
                  <div
                    key={k}
                    style={{ padding: '6px 0', borderBottom: '1px solid var(--border)' }}
                  >
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{k}:</span>
                    <span style={{ marginLeft: 8, fontSize: 13 }}>
                      {typeof v === 'boolean' ? (v ? '✓ active' : '✗ inactive') : String(v)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <>
                <SummaryGrid data={monPaths} limit={10} />
                <JsonDetails data={monPaths} />
              </>
            )}
          </div>
        </>
      )}

      {tab === 'integrations' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-header">
                <span className="card-title">SIEM Integration</span>
                <div className="btn-group">
                  <span className={`badge ${validationBadgeClass(siemValidation.status)}`}>
                    {validationStatusLabel(siemValidation.status)}
                  </span>
                  <span
                    className={`badge ${
                      !siemStatusData?.enabled
                        ? 'badge-info'
                        : siemStatusData?.last_error
                          ? 'badge-warn'
                          : 'badge-ok'
                    }`}
                  >
                    {!siemStatusData?.enabled
                      ? 'Disabled'
                      : siemStatusData?.last_error
                        ? 'Runtime issue'
                        : 'Active'}
                  </span>
                </div>
              </div>
              {siemConfigData?.has_auth_token && (
                <div style={{ fontSize: 12, opacity: 0.75, marginBottom: 12 }}>
                  A SIEM auth token or secret reference is already stored. Leave the token field
                  blank to keep it.
                </div>
              )}
              <ToggleSwitch
                label="Enable SIEM"
                checked={siemDraft.enabled}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, enabled: value }))}
                description="Enable this when alerts should be pushed to the configured SIEM endpoint."
              />
              <SelectInput
                label="SIEM Type"
                value={siemDraft.siem_type}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, siem_type: value }))}
                options={SIEM_TYPE_OPTIONS}
                description="Choose the payload format expected by your downstream SIEM or data lake."
              />
              <TextInput
                label="SIEM Endpoint"
                value={siemDraft.endpoint}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, endpoint: value }))}
                placeholder="https://siem.example.com/hec"
              />
              <TextInput
                label="Auth Token"
                type="password"
                value={siemDraft.auth_token}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, auth_token: value }))}
                placeholder="Leave blank to keep the current token or reference"
                description="Supports literal values or secret references already resolved by the server."
              />
              <TextInput
                label="Index or Stream"
                value={siemDraft.index}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, index: value }))}
                placeholder="wardex"
              />
              <TextInput
                label="Source Type"
                value={siemDraft.source_type}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, source_type: value }))}
                placeholder="wardex:xdr"
              />
              <NumberInput
                label="Poll Interval"
                value={siemDraft.poll_interval_secs}
                onChange={(value) =>
                  setSiemDraft((prev) => ({ ...prev, poll_interval_secs: value }))
                }
                min={1}
                unit="seconds"
              />
              <NumberInput
                label="Batch Size"
                value={siemDraft.batch_size}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, batch_size: value }))}
                min={1}
                max={1000}
              />
              <ToggleSwitch
                label="Enable Pull Queries"
                checked={siemDraft.pull_enabled}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, pull_enabled: value }))}
                description="Enable saved-search or threat-intel pulls when the connector should also read back from the SIEM."
              />
              <TextAreaInput
                label="Pull Query"
                value={siemDraft.pull_query}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, pull_query: value }))}
                placeholder={'search index=wardex sourcetype=wardex:xdr'}
                description="Optional query used by pull-enabled workflows."
                rows={4}
              />
              <ToggleSwitch
                label="Verify TLS"
                checked={siemDraft.verify_tls}
                onChange={(value) => setSiemDraft((prev) => ({ ...prev, verify_tls: value }))}
                description="Disable only for lab environments with self-signed certificates."
              />
              <ValidationIssues validation={siemValidation} style={{ marginTop: 12 }} />
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={siemSaving}
                  onClick={saveSiemConfig}
                >
                  {siemSaving ? 'Saving…' : 'Save SIEM Setup'}
                </button>
                <button className="btn" type="button" onClick={validateSiemConfig}>
                  Validate SIEM
                </button>
              </div>
              {siemStatusData && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Runtime Status</div>
                  <SummaryGrid data={siemStatusData} limit={6} />
                </div>
              )}
              {siemValidationResult && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Last validation</div>
                  <div style={{ fontSize: 12 }}>
                    {siemValidationResult.success
                      ? 'SIEM configuration is valid and ready to save.'
                      : siemValidationResult.error || 'SIEM validation needs attention.'}
                  </div>
                  <JsonDetails data={siemValidationResult} label="SIEM validation details" />
                </div>
              )}
            </div>
            <div className="card">
              <div className="card-header">
                <span className="card-title">TAXII Feed</span>
                <div className="btn-group">
                  <span className={`badge ${taxiiSt?.connected ? 'badge-ok' : 'badge-warn'}`}>
                    {taxiiSt?.connected ? 'Active' : 'Inactive'}
                  </span>
                  <button
                    className="btn btn-sm"
                    onClick={async () => {
                      try {
                        await api.taxiiPull();
                        toast('TAXII pull initiated', 'success');
                      } catch {
                        toast('Pull failed', 'error');
                      }
                    }}
                  >
                    Pull Now
                  </button>
                </div>
              </div>
              {taxiiCfg && typeof taxiiCfg === 'object' ? (
                <>
                  <SummaryGrid data={taxiiCfg} limit={10} />
                  <JsonDetails data={taxiiCfg} />
                </>
              ) : (
                <>
                  <div className="empty">No TAXII configuration available.</div>
                  <JsonDetails data={taxiiCfg} />
                </>
              )}
            </div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <span className="card-title">Federated Sign-In Readiness</span>
              <span
                className={`badge ${readySsoProviders.length > 0 ? 'badge-ok' : reviewIdpCount > 0 ? 'badge-warn' : 'badge-info'}`}
              >
                {readySsoProviders.length > 0 ? 'Ready' : reviewIdpCount > 0 ? 'Review' : 'Pending'}
              </span>
            </div>
            <div className="summary-grid">
              <div className="summary-card">
                <div className="summary-label">Enabled providers</div>
                <div className="summary-value">{enabledIdpCount}</div>
                <div className="summary-meta">{readyIdpCount} ready for live federated launch.</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Review required</div>
                <div className="summary-value">{reviewIdpCount}</div>
                <div className="summary-meta">
                  Resolve mappings and callback mismatches before sign-in tests.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">SCIM mappings</div>
                <div className="summary-value">
                  {ssoConfig?.scim?.mapping_count ?? scimValidation.mapping_count}
                </div>
                <div className="summary-meta">
                  {ssoConfig?.scim?.enabled
                    ? `SCIM ${ssoConfig?.scim?.status || 'configured'}`
                    : 'SCIM disabled'}
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Callback URI</div>
                <div className="summary-value" style={{ fontSize: 13 }}>
                  {defaultSsoCallbackUri}
                </div>
                <div className="summary-meta">
                  This must match every external IdP redirect configuration.
                </div>
              </div>
            </div>
            <div className="detail-callout" style={{ marginTop: 16 }}>
              Launching an SSO test from here uses the same backend login and callback routes as the
              real console, so operators can validate the external redirect and return path before
              rolling identity changes broadly.
            </div>
            {readySsoProviders.length > 0 ? (
              <div style={{ display: 'grid', gap: 12, marginTop: 16 }}>
                {readySsoProviders.map((provider) => (
                  <div
                    key={provider.id}
                    className="stat-box"
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 12,
                      flexWrap: 'wrap',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600 }}>{provider.display_name}</div>
                      <div style={{ fontSize: 12, opacity: 0.75, marginTop: 4 }}>
                        {providerLoginKindLabel(provider.kind)} provider ready for callback
                        validation.
                      </div>
                    </div>
                    <div className="btn-group" style={{ flexWrap: 'wrap' }}>
                      <button
                        className="btn btn-sm btn-primary"
                        type="button"
                        onClick={() => launchSsoValidation(provider.id)}
                      >
                        Start SSO Test
                      </button>
                      <code style={{ fontSize: 11 }}>
                        {provider.login_path || buildSsoLoginPath(provider.id)}
                      </code>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <ValidationIssues
                validation={{
                  status: reviewIdpCount > 0 ? 'warning' : 'info',
                  issues: [
                    {
                      level: 'warning',
                      field: 'provider_readiness',
                      message:
                        reviewIdpCount > 0
                          ? 'No enabled providers are fully ready for federated launch yet. Resolve the provider warnings below before starting a live SSO test.'
                          : 'Add and enable at least one OIDC or SAML provider before testing federated sign-in.',
                    },
                  ],
                }}
                style={{ marginTop: 16 }}
              />
            )}
          </div>
          <div className="card-grid" style={{ marginTop: 16 }}>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Enrichment Connectors
              </div>
              {connectorRows.length > 0 ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {connectorRows.map((c, i) => (
                        <tr key={i}>
                          <td>{c.name || c.id || '—'}</td>
                          <td>{c.type || '—'}</td>
                          <td>
                            <span className={`badge ${c.enabled ? 'badge-ok' : 'badge-warn'}`}>
                              {c.enabled ? 'Active' : 'Inactive'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <>
                  <SummaryGrid
                    data={enrichConn}
                    limit={10}
                    emptyMessage="No connectors configured"
                  />
                  <JsonDetails data={enrichConn} />
                </>
              )}
            </div>
            <div className="card">
              <div className="card-header">
                <span className="card-title">IdP Providers</span>
                <button className="btn btn-sm" type="button" onClick={() => openIdpEditor()}>
                  New Provider
                </button>
              </div>
              {idpRows.length > 0 ? (
                <>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>Type</th>
                          <th>Status</th>
                          <th>Validation</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {idpRows.map((p, i) => (
                          <tr key={p.id || i}>
                            <td>{p.display_name || p.name || p.id || '—'}</td>
                            <td>{String(p.kind || p.type || '—').toUpperCase()}</td>
                            <td>
                              <span className={`badge ${p.enabled ? 'badge-ok' : 'badge-info'}`}>
                                {p.enabled ? 'Enabled' : 'Disabled'}
                              </span>
                            </td>
                            <td>
                              <span
                                className={`badge ${validationBadgeClass(p.validation?.status)}`}
                              >
                                {validationStatusLabel(p.validation?.status)}
                              </span>
                              <div style={{ fontSize: 12, marginTop: 4, opacity: 0.75 }}>
                                {p.validation?.issues?.length || 0} issue
                                {p.validation?.issues?.length === 1 ? '' : 's'} •{' '}
                                {p.validation?.mapping_count || 0} mapping
                                {(p.validation?.mapping_count || 0) === 1 ? '' : 's'}
                              </div>
                            </td>
                            <td>
                              <div className="btn-group" style={{ flexWrap: 'wrap' }}>
                                <button
                                  className="btn btn-sm"
                                  type="button"
                                  onClick={() => openIdpEditor(p)}
                                >
                                  Edit Provider
                                </button>
                                {p.enabled && p.validation?.status === 'ready' && (
                                  <button
                                    className="btn btn-sm btn-primary"
                                    type="button"
                                    onClick={() => launchSsoValidation(p.id)}
                                  >
                                    Start SSO Test
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {idpRows.some((provider) => provider.validation?.issues?.length > 0) && (
                    <div
                      style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 12 }}
                    >
                      {idpRows
                        .filter((provider) => provider.validation?.issues?.length > 0)
                        .map((provider) => (
                          <div key={`${provider.id}-issues`} className="stat-box">
                            <div style={{ fontWeight: 600, marginBottom: 6 }}>
                              {provider.display_name || provider.id}
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                              {provider.validation.issues.map((issue, index) => (
                                <div key={`${provider.id}-issue-${index}`} style={{ fontSize: 12 }}>
                                  <span
                                    className={`badge ${issue.level === 'error' ? 'badge-err' : 'badge-warn'}`}
                                    style={{ marginRight: 8 }}
                                  >
                                    {issue.level}
                                  </span>
                                  <strong>{issue.field}:</strong> {issue.message}
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                    </div>
                  )}
                  {idpEditorOpen && (
                    <div className="stat-box" style={{ marginTop: 12 }}>
                      <div style={{ fontWeight: 600, marginBottom: 10 }}>
                        {idpDraft.id
                          ? `Edit ${idpDraft.display_name || 'Identity Provider'}`
                          : 'New Identity Provider'}
                      </div>
                      <div style={{ display: 'grid', gap: 10 }}>
                        <SelectInput
                          label="Provider Type"
                          value={idpDraft.kind}
                          onChange={(value) => setIdpDraft((prev) => ({ ...prev, kind: value }))}
                          options={IDENTITY_PROVIDER_OPTIONS}
                        />
                        <ToggleSwitch
                          label="Enabled"
                          checked={idpDraft.enabled}
                          onChange={(value) => setIdpDraft((prev) => ({ ...prev, enabled: value }))}
                          description="Disabled providers stay configured but cannot authenticate users."
                        />
                        <TextInput
                          label="Provider Name"
                          value={idpDraft.display_name}
                          onChange={(value) =>
                            setIdpDraft((prev) => ({ ...prev, display_name: value }))
                          }
                          placeholder="Corporate SSO"
                        />
                        {idpDraft.kind === 'oidc' ? (
                          <>
                            <TextInput
                              label="Issuer URL"
                              value={idpDraft.issuer_url}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, issuer_url: value }))
                              }
                              placeholder="https://issuer.example.com"
                            />
                            <TextInput
                              label="Client ID"
                              value={idpDraft.client_id}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, client_id: value }))
                              }
                              placeholder="wardex-admin"
                            />
                            <TextInput
                              label="Client Secret"
                              type="password"
                              value={idpDraft.client_secret}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, client_secret: value }))
                              }
                              placeholder="Leave blank to keep the current secret"
                              description="Only required when creating a new OIDC provider or rotating the secret."
                            />
                            <TextInput
                              label="Redirect URI"
                              value={idpDraft.redirect_uri}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, redirect_uri: value }))
                              }
                              placeholder="https://console.example.com/api/auth/sso/callback"
                              description="This must match the callback URI registered with your identity provider."
                            />
                          </>
                        ) : (
                          <>
                            <TextInput
                              label="SSO URL"
                              value={idpDraft.sso_url}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, sso_url: value }))
                              }
                              placeholder="https://sso.example.com/login"
                            />
                            <TextInput
                              label="Entity ID"
                              value={idpDraft.entity_id}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, entity_id: value }))
                              }
                              placeholder="urn:example:wardex"
                            />
                          </>
                        )}
                        <TextAreaInput
                          label="Provider Group Mappings"
                          value={idpDraft.mappings_text}
                          onChange={(value) =>
                            setIdpDraft((prev) => ({ ...prev, mappings_text: value }))
                          }
                          placeholder={'Security=admin\nSOC Analysts=analyst'}
                          description="One mapping per line using group=role. Roles must be admin, analyst, or viewer."
                        />
                      </div>
                      {idpFormError && (
                        <div
                          style={{ fontSize: 12, color: 'var(--danger, #b42318)', marginTop: 12 }}
                        >
                          {idpFormError}
                        </div>
                      )}
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                        <button
                          className="btn btn-primary"
                          type="button"
                          disabled={idpSaving}
                          onClick={saveIdpProvider}
                        >
                          {idpSaving ? 'Saving…' : 'Save Provider'}
                        </button>
                        <button className="btn" type="button" onClick={closeIdpEditor}>
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <>
                  <SummaryGrid
                    data={idp}
                    limit={10}
                    emptyMessage="No identity providers configured"
                  />
                  <JsonDetails data={idp} />
                  {idpEditorOpen && (
                    <div className="stat-box" style={{ marginTop: 12 }}>
                      <div style={{ fontWeight: 600, marginBottom: 10 }}>New Identity Provider</div>
                      <div style={{ display: 'grid', gap: 10 }}>
                        <SelectInput
                          label="Provider Type"
                          value={idpDraft.kind}
                          onChange={(value) => setIdpDraft((prev) => ({ ...prev, kind: value }))}
                          options={IDENTITY_PROVIDER_OPTIONS}
                        />
                        <ToggleSwitch
                          label="Enabled"
                          checked={idpDraft.enabled}
                          onChange={(value) => setIdpDraft((prev) => ({ ...prev, enabled: value }))}
                          description="Disabled providers stay configured but cannot authenticate users."
                        />
                        <TextInput
                          label="Provider Name"
                          value={idpDraft.display_name}
                          onChange={(value) =>
                            setIdpDraft((prev) => ({ ...prev, display_name: value }))
                          }
                          placeholder="Corporate SSO"
                        />
                        {idpDraft.kind === 'oidc' ? (
                          <>
                            <TextInput
                              label="Issuer URL"
                              value={idpDraft.issuer_url}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, issuer_url: value }))
                              }
                              placeholder="https://issuer.example.com"
                            />
                            <TextInput
                              label="Client ID"
                              value={idpDraft.client_id}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, client_id: value }))
                              }
                              placeholder="wardex-admin"
                            />
                            <TextInput
                              label="Client Secret"
                              type="password"
                              value={idpDraft.client_secret}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, client_secret: value }))
                              }
                              placeholder="Leave blank to keep the current secret"
                              description="Only required when creating a new OIDC provider or rotating the secret."
                            />
                            <TextInput
                              label="Redirect URI"
                              value={idpDraft.redirect_uri}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, redirect_uri: value }))
                              }
                              placeholder="https://console.example.com/api/auth/sso/callback"
                              description="This must match the callback URI registered with your identity provider."
                            />
                          </>
                        ) : (
                          <>
                            <TextInput
                              label="SSO URL"
                              value={idpDraft.sso_url}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, sso_url: value }))
                              }
                              placeholder="https://sso.example.com/login"
                            />
                            <TextInput
                              label="Entity ID"
                              value={idpDraft.entity_id}
                              onChange={(value) =>
                                setIdpDraft((prev) => ({ ...prev, entity_id: value }))
                              }
                              placeholder="urn:example:wardex"
                            />
                          </>
                        )}
                        <TextAreaInput
                          label="Provider Group Mappings"
                          value={idpDraft.mappings_text}
                          onChange={(value) =>
                            setIdpDraft((prev) => ({ ...prev, mappings_text: value }))
                          }
                          placeholder={'Security=admin\nSOC Analysts=analyst'}
                          description="One mapping per line using group=role. Roles must be admin, analyst, or viewer."
                        />
                      </div>
                      {idpFormError && (
                        <div
                          style={{ fontSize: 12, color: 'var(--danger, #b42318)', marginTop: 12 }}
                        >
                          {idpFormError}
                        </div>
                      )}
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                        <button
                          className="btn btn-primary"
                          type="button"
                          disabled={idpSaving}
                          onClick={saveIdpProvider}
                        >
                          {idpSaving ? 'Saving…' : 'Save Provider'}
                        </button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
            <div className="card">
              <div className="card-header">
                <span className="card-title">SCIM Config</span>
                <div className="btn-group">
                  <span className={`badge ${validationBadgeClass(scimValidation.status)}`}>
                    {validationStatusLabel(scimValidation.status)}
                  </span>
                  {!scimEditing && (
                    <button className="btn btn-sm" type="button" onClick={openScimEditor}>
                      {scimConfigData ? 'Edit SCIM' : 'Configure SCIM'}
                    </button>
                  )}
                </div>
              </div>
              {scimConfigData ? (
                <>
                  <SummaryGrid data={scimConfigData} limit={10} />
                  <div style={{ fontSize: 12, opacity: 0.75, marginTop: 8 }}>
                    {scimValidation.mapping_count} group mapping
                    {scimValidation.mapping_count === 1 ? '' : 's'} configured
                  </div>
                  {scimValidation.issues.length > 0 && (
                    <div
                      style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}
                    >
                      {scimValidation.issues.map((issue, index) => (
                        <div
                          key={`scim-issue-${index}`}
                          className="stat-box"
                          style={{ fontSize: 12 }}
                        >
                          <span
                            className={`badge ${issue.level === 'error' ? 'badge-err' : 'badge-warn'}`}
                            style={{ marginRight: 8 }}
                          >
                            {issue.level}
                          </span>
                          <strong>{issue.field}:</strong> {issue.message}
                        </div>
                      ))}
                    </div>
                  )}
                  <JsonDetails data={scim} />
                </>
              ) : (
                <>
                  <div className="empty">No SCIM configuration available.</div>
                  <JsonDetails data={scim} />
                </>
              )}
              {(scimEditing || !scimConfigData) && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 10 }}>SCIM Provisioning Editor</div>
                  <div style={{ display: 'grid', gap: 10 }}>
                    <ToggleSwitch
                      label="Enable SCIM Provisioning"
                      checked={scimDraft.enabled}
                      onChange={(value) => setScimDraft((prev) => ({ ...prev, enabled: value }))}
                      description="Disable provisioning to retain config without synchronizing users."
                    />
                    <TextInput
                      label="Base URL"
                      value={scimDraft.base_url}
                      onChange={(value) => setScimDraft((prev) => ({ ...prev, base_url: value }))}
                      placeholder="https://scim.example.com"
                    />
                    <TextInput
                      label="Bearer Token"
                      value={scimDraft.bearer_token}
                      onChange={(value) =>
                        setScimDraft((prev) => ({ ...prev, bearer_token: value }))
                      }
                      placeholder="Paste SCIM bearer token"
                    />
                    <SelectInput
                      label="Provisioning Mode"
                      value={scimDraft.provisioning_mode}
                      onChange={(value) =>
                        setScimDraft((prev) => ({ ...prev, provisioning_mode: value }))
                      }
                      options={SCIM_MODE_OPTIONS}
                    />
                    <SelectInput
                      label="Default Role"
                      value={scimDraft.default_role}
                      onChange={(value) =>
                        setScimDraft((prev) => ({ ...prev, default_role: value }))
                      }
                      options={IDENTITY_ROLE_OPTIONS}
                    />
                    <TextAreaInput
                      label="SCIM Group Mappings"
                      value={scimDraft.mappings_text}
                      onChange={(value) =>
                        setScimDraft((prev) => ({ ...prev, mappings_text: value }))
                      }
                      placeholder={'Security=admin\nSOC Analysts=analyst'}
                      description="One mapping per line using group=role. Roles must be admin, analyst, or viewer."
                    />
                  </div>
                  {scimFormError && (
                    <div style={{ fontSize: 12, color: 'var(--danger, #b42318)', marginTop: 12 }}>
                      {scimFormError}
                    </div>
                  )}
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                    <button
                      className="btn btn-primary"
                      type="button"
                      disabled={scimSaving}
                      onClick={saveScimConfig}
                    >
                      {scimSaving ? 'Saving…' : 'Save SCIM'}
                    </button>
                    {scimConfigData && (
                      <button className="btn" type="button" onClick={closeScimEditor}>
                        Cancel
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <span className="card-title">Cloud Collectors &amp; Secrets</span>
              <button className="btn btn-sm" type="button" onClick={() => rIntegrations()}>
                ↻ Refresh
              </button>
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                gap: 12,
              }}
            >
              <div className="stat-box">
                <div className="stat-label">Enabled Collectors</div>
                <div className="stat-value">
                  {collectorRows.filter((entry) => entry.enabled).length}
                </div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Ready Collectors</div>
                <div className="stat-value">
                  {collectorRows.filter((entry) => entry.validation?.status === 'ready').length}
                </div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Review Required</div>
                <div className="stat-value">
                  {collectorRows.filter((entry) => entry.validation?.status === 'warning').length}
                </div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Secrets Manager</div>
                <div className="stat-value">
                  {validationStatusLabel(secretsManagerValidation.status)}
                </div>
              </div>
            </div>
            <JsonDetails
              data={{ collectors: collectorRows, secrets: secretsData }}
              label="Collector and secret diagnostics"
            />
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <span className="card-title">Collector Routing &amp; Health</span>
              <span className={`badge ${reviewCollectorCount > 0 ? 'badge-warn' : 'badge-ok'}`}>
                {reviewCollectorCount > 0 ? 'Review' : 'Ready'}
              </span>
            </div>
            <div className="summary-grid">
              <div className="summary-card">
                <div className="summary-label">Cloud collectors ready</div>
                <div className="summary-value">{readyCloudCollectorCount}</div>
                <div className="summary-meta">
                  AWS, Azure, and GCP lanes ready for validation or polling.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Identity collectors ready</div>
                <div className="summary-value">{readyIdentityCollectorCount}</div>
                <div className="summary-meta">
                  Okta and Entra sign-in telemetry ready for SOC and UEBA handoff.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">SaaS collectors ready</div>
                <div className="summary-value">{readySaasCollectorCount}</div>
                <div className="summary-meta">
                  Microsoft 365 and Google Workspace activity ready for analyst pivots.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Collectors under review</div>
                <div className="summary-value">{reviewCollectorCount}</div>
                <div className="summary-meta">
                  Configured lanes that still need credentials, scoping, or cleanup.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Secrets manager</div>
                <div className="summary-value">
                  {validationStatusLabel(secretsManagerValidation.status)}
                </div>
                <div className="summary-meta">
                  Credential resolution shared by cloud and identity integrations.
                </div>
              </div>
            </div>
            <div className="card-grid" style={{ marginTop: 16 }}>
              <CollectorLaneCard
                title="Identity Telemetry Lane"
                hint="Feed identity collector output into auth-risk, provisioning drift, and account-compromise triage workflows."
                rows={identityCollectorRows}
                emptyText="No identity collectors have been configured yet."
                primaryHref="/soc#queue"
                primaryLabel="Open SOC Queue"
                secondaryHref="/ueba"
                secondaryLabel="Review UEBA"
              />
              <CollectorLaneCard
                title="Cloud Audit Lane"
                hint="Route validated cloud collectors into infrastructure review and attack-path validation before broad automation rollout."
                rows={cloudCollectorRows}
                emptyText="No cloud collectors have been configured yet."
                primaryHref="/infrastructure?tab=observability"
                primaryLabel="Open Infrastructure"
                secondaryHref="/attack-graph"
                secondaryLabel="Review Attack Graph"
              />
              <CollectorLaneCard
                title="SaaS Activity Lane"
                hint="Carry Microsoft 365 and Google Workspace audit activity into identity triage, collaboration-risk review, and scoped reporting workflows."
                rows={saasCollectorRows}
                emptyText="No SaaS collectors have been configured yet."
                primaryHref="/assistant?source=collector-saas"
                primaryLabel="Open Assistant"
                secondaryHref="/reports?source=collector-saas"
                secondaryLabel="Open Reports"
              />
            </div>
          </div>

          <div className="card-grid" style={{ marginTop: 16 }}>
            <div className="card">
              <div className="card-header">
                <span className="card-title">AWS CloudTrail</span>
                <span className={`badge ${validationBadgeClass(awsCollectorValidation.status)}`}>
                  {validationStatusLabel(awsCollectorValidation.status)}
                </span>
              </div>
              {awsCollectorData?.config?.has_secret_access_key && (
                <div style={{ fontSize: 12, opacity: 0.75, marginBottom: 12 }}>
                  A secret or secret reference is already stored. Leave the secret field blank to
                  keep it.
                </div>
              )}
              <ToggleSwitch
                label="Enable AWS collector"
                checked={awsCollectorDraft.enabled}
                onChange={(value) => setAwsCollectorDraft((prev) => ({ ...prev, enabled: value }))}
                description="Use this when CloudTrail should be polled from the browser-configured setup."
              />
              <TextInput
                label="Region"
                value={awsCollectorDraft.region}
                onChange={(value) => setAwsCollectorDraft((prev) => ({ ...prev, region: value }))}
                placeholder="us-east-1"
              />
              <TextInput
                label="Access Key ID"
                value={awsCollectorDraft.access_key_id}
                onChange={(value) =>
                  setAwsCollectorDraft((prev) => ({ ...prev, access_key_id: value }))
                }
                placeholder="AKIA... or ${AWS_ACCESS_KEY_ID}"
              />
              <TextInput
                label="Secret Access Key"
                type="password"
                value={awsCollectorDraft.secret_access_key}
                onChange={(value) =>
                  setAwsCollectorDraft((prev) => ({ ...prev, secret_access_key: value }))
                }
                placeholder="Leave blank to keep the current secret or reference"
                description="Supports literal values or secret references such as ${AWS_SECRET_ACCESS_KEY} or vault://secret/path#key."
              />
              <TextInput
                label="Session Token"
                value={awsCollectorDraft.session_token}
                onChange={(value) =>
                  setAwsCollectorDraft((prev) => ({ ...prev, session_token: value }))
                }
                placeholder="Optional STS token"
              />
              <NumberInput
                label="Poll Interval"
                value={awsCollectorDraft.poll_interval_secs}
                onChange={(value) =>
                  setAwsCollectorDraft((prev) => ({ ...prev, poll_interval_secs: value }))
                }
                min={1}
                unit="seconds"
              />
              <NumberInput
                label="Max Results"
                value={awsCollectorDraft.max_results}
                onChange={(value) =>
                  setAwsCollectorDraft((prev) => ({ ...prev, max_results: value }))
                }
                min={1}
                max={500}
              />
              <TextAreaInput
                label="Event Name Filter"
                value={awsCollectorDraft.event_name_filter}
                onChange={(value) =>
                  setAwsCollectorDraft((prev) => ({ ...prev, event_name_filter: value }))
                }
                placeholder={'ConsoleLogin\nAssumeRole\nCreateAccessKey'}
                description="One event name per line. Leave empty to query the full CloudTrail stream."
                rows={5}
              />
              <ValidationIssues validation={awsCollectorValidation} style={{ marginTop: 12 }} />
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={awsCollectorSaving}
                  onClick={saveAwsCollector}
                >
                  {awsCollectorSaving ? 'Saving…' : 'Save AWS Setup'}
                </button>
                <button className="btn" type="button" onClick={validateAwsCollector}>
                  Validate AWS
                </button>
              </div>
              {awsCollectorValidationResult && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Last validation</div>
                  <div style={{ fontSize: 12 }}>
                    {awsCollectorValidationResult.success
                      ? `Collected ${awsCollectorValidationResult.event_count || 0} event${awsCollectorValidationResult.event_count === 1 ? '' : 's'}.`
                      : awsCollectorValidationResult.error || 'Validation needs attention.'}
                  </div>
                  <JsonDetails data={awsCollectorValidationResult} label="AWS validation details" />
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Azure Activity</span>
                <span className={`badge ${validationBadgeClass(azureCollectorValidation.status)}`}>
                  {validationStatusLabel(azureCollectorValidation.status)}
                </span>
              </div>
              {azureCollectorData?.config?.has_client_secret && (
                <div style={{ fontSize: 12, opacity: 0.75, marginBottom: 12 }}>
                  A client secret or secret reference is already stored. Leave the secret field
                  blank to keep it.
                </div>
              )}
              <ToggleSwitch
                label="Enable Azure collector"
                checked={azureCollectorDraft.enabled}
                onChange={(value) =>
                  setAzureCollectorDraft((prev) => ({ ...prev, enabled: value }))
                }
                description="Use this when Azure Activity Logs should be validated or polled from the saved setup."
              />
              <TextInput
                label="Tenant ID"
                value={azureCollectorDraft.tenant_id}
                onChange={(value) =>
                  setAzureCollectorDraft((prev) => ({ ...prev, tenant_id: value }))
                }
                placeholder="tenant-guid"
              />
              <TextInput
                label="Client ID"
                value={azureCollectorDraft.client_id}
                onChange={(value) =>
                  setAzureCollectorDraft((prev) => ({ ...prev, client_id: value }))
                }
                placeholder="application-guid"
              />
              <TextInput
                label="Client Secret"
                type="password"
                value={azureCollectorDraft.client_secret}
                onChange={(value) =>
                  setAzureCollectorDraft((prev) => ({ ...prev, client_secret: value }))
                }
                placeholder="Leave blank to keep the current secret or reference"
                description="Supports literal values or secret references such as ${AZURE_CLIENT_SECRET}."
              />
              <TextInput
                label="Subscription ID"
                value={azureCollectorDraft.subscription_id}
                onChange={(value) =>
                  setAzureCollectorDraft((prev) => ({ ...prev, subscription_id: value }))
                }
                placeholder="subscription-guid"
              />
              <NumberInput
                label="Poll Interval"
                value={azureCollectorDraft.poll_interval_secs}
                onChange={(value) =>
                  setAzureCollectorDraft((prev) => ({ ...prev, poll_interval_secs: value }))
                }
                min={1}
                unit="seconds"
              />
              <TextAreaInput
                label="Categories"
                value={azureCollectorDraft.categories}
                onChange={(value) =>
                  setAzureCollectorDraft((prev) => ({ ...prev, categories: value }))
                }
                placeholder={'Administrative\nSecurity\nAlert'}
                description="One Azure Activity category per line."
                rows={4}
              />
              <ValidationIssues validation={azureCollectorValidation} style={{ marginTop: 12 }} />
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={azureCollectorSaving}
                  onClick={saveAzureCollector}
                >
                  {azureCollectorSaving ? 'Saving…' : 'Save Azure Setup'}
                </button>
                <button className="btn" type="button" onClick={validateAzureCollector}>
                  Validate Azure
                </button>
              </div>
              {azureCollectorValidationResult && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Last validation</div>
                  <div style={{ fontSize: 12 }}>
                    {azureCollectorValidationResult.success
                      ? `Collected ${azureCollectorValidationResult.event_count || 0} event${azureCollectorValidationResult.event_count === 1 ? '' : 's'}.`
                      : azureCollectorValidationResult.error || 'Validation needs attention.'}
                  </div>
                  <JsonDetails
                    data={azureCollectorValidationResult}
                    label="Azure validation details"
                  />
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">GCP Audit</span>
                <span className={`badge ${validationBadgeClass(gcpCollectorValidation.status)}`}>
                  {validationStatusLabel(gcpCollectorValidation.status)}
                </span>
              </div>
              {(gcpCollectorData?.config?.has_private_key_pem ||
                gcpCollectorData?.config?.key_file_path) && (
                <div style={{ fontSize: 12, opacity: 0.75, marginBottom: 12 }}>
                  A key path or private key is already stored. Leave the private key field blank to
                  keep it.
                </div>
              )}
              <ToggleSwitch
                label="Enable GCP collector"
                checked={gcpCollectorDraft.enabled}
                onChange={(value) => setGcpCollectorDraft((prev) => ({ ...prev, enabled: value }))}
                description="Use this when Cloud Audit Logs should be validated or polled from the saved setup."
              />
              <TextInput
                label="Project ID"
                value={gcpCollectorDraft.project_id}
                onChange={(value) =>
                  setGcpCollectorDraft((prev) => ({ ...prev, project_id: value }))
                }
                placeholder="wardex-prod"
              />
              <TextInput
                label="Service Account Email"
                value={gcpCollectorDraft.service_account_email}
                onChange={(value) =>
                  setGcpCollectorDraft((prev) => ({ ...prev, service_account_email: value }))
                }
                placeholder="collector@project.iam.gserviceaccount.com"
              />
              <TextInput
                label="Key File Path"
                value={gcpCollectorDraft.key_file_path}
                onChange={(value) =>
                  setGcpCollectorDraft((prev) => ({ ...prev, key_file_path: value }))
                }
                placeholder="/secure/path/service-account.json"
                description="Optional when a private key PEM or secret reference is used instead."
              />
              <TextAreaInput
                label="Private Key PEM"
                value={gcpCollectorDraft.private_key_pem}
                onChange={(value) =>
                  setGcpCollectorDraft((prev) => ({ ...prev, private_key_pem: value }))
                }
                placeholder="Leave blank to keep the current PEM or reference"
                description="Supports literal PEM blocks or secret references such as vault://secret/path#private_key."
                rows={4}
              />
              <NumberInput
                label="Poll Interval"
                value={gcpCollectorDraft.poll_interval_secs}
                onChange={(value) =>
                  setGcpCollectorDraft((prev) => ({ ...prev, poll_interval_secs: value }))
                }
                min={1}
                unit="seconds"
              />
              <NumberInput
                label="Page Size"
                value={gcpCollectorDraft.page_size}
                onChange={(value) =>
                  setGcpCollectorDraft((prev) => ({ ...prev, page_size: value }))
                }
                min={1}
                max={1000}
              />
              <TextAreaInput
                label="Log Filter"
                value={gcpCollectorDraft.log_filter}
                onChange={(value) =>
                  setGcpCollectorDraft((prev) => ({ ...prev, log_filter: value }))
                }
                placeholder='logName:"cloudaudit.googleapis.com"'
                description="Cloud Logging filter syntax used during validation and polling."
                rows={4}
              />
              <ValidationIssues validation={gcpCollectorValidation} style={{ marginTop: 12 }} />
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={gcpCollectorSaving}
                  onClick={saveGcpCollector}
                >
                  {gcpCollectorSaving ? 'Saving…' : 'Save GCP Setup'}
                </button>
                <button className="btn" type="button" onClick={validateGcpCollector}>
                  Validate GCP
                </button>
              </div>
              {gcpCollectorValidationResult && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Last validation</div>
                  <div style={{ fontSize: 12 }}>
                    {gcpCollectorValidationResult.success
                      ? `Collected ${gcpCollectorValidationResult.event_count || 0} event${gcpCollectorValidationResult.event_count === 1 ? '' : 's'}.`
                      : gcpCollectorValidationResult.error || 'Validation needs attention.'}
                  </div>
                  <JsonDetails data={gcpCollectorValidationResult} label="GCP validation details" />
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Okta Identity</span>
                <span className={`badge ${validationBadgeClass(oktaCollectorValidation.status)}`}>
                  {validationStatusLabel(oktaCollectorValidation.status)}
                </span>
              </div>
              {oktaCollectorData?.config?.has_api_token && (
                <div style={{ fontSize: 12, opacity: 0.75, marginBottom: 12 }}>
                  An Okta API token or secret reference is already stored. Leave the token field
                  blank to keep it.
                </div>
              )}
              <ToggleSwitch
                label="Enable Okta collector"
                checked={oktaCollectorDraft.enabled}
                onChange={(value) => setOktaCollectorDraft((prev) => ({ ...prev, enabled: value }))}
                description="Use this when Okta system log events should be validated or polled from the saved setup."
              />
              <TextInput
                label="Okta Domain"
                value={oktaCollectorDraft.domain}
                onChange={(value) => setOktaCollectorDraft((prev) => ({ ...prev, domain: value }))}
                placeholder="dev-123456.okta.com"
              />
              <TextInput
                label="API Token"
                type="password"
                value={oktaCollectorDraft.api_token}
                onChange={(value) =>
                  setOktaCollectorDraft((prev) => ({ ...prev, api_token: value }))
                }
                placeholder="Leave blank to keep the current token or reference"
                description="Supports literal values or secret references such as ${OKTA_API_TOKEN}."
              />
              <NumberInput
                label="Poll Interval"
                value={oktaCollectorDraft.poll_interval_secs}
                onChange={(value) =>
                  setOktaCollectorDraft((prev) => ({ ...prev, poll_interval_secs: value }))
                }
                min={1}
                unit="seconds"
              />
              <TextAreaInput
                label="Event Type Filter"
                value={oktaCollectorDraft.event_type_filter}
                onChange={(value) =>
                  setOktaCollectorDraft((prev) => ({ ...prev, event_type_filter: value }))
                }
                placeholder={'user.session.start\nuser.account.lock\nuser.mfa.factor.deactivate'}
                description="One Okta system log event type per line. Leave empty to query the full stream."
                rows={5}
              />
              <ValidationIssues validation={oktaCollectorValidation} style={{ marginTop: 12 }} />
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={oktaCollectorSaving}
                  onClick={saveOktaCollector}
                >
                  {oktaCollectorSaving ? 'Saving…' : 'Save Okta Setup'}
                </button>
                <button className="btn" type="button" onClick={validateOktaCollector}>
                  Validate Okta
                </button>
              </div>
              {oktaCollectorValidationResult && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Last validation</div>
                  <div style={{ fontSize: 12 }}>
                    {oktaCollectorValidationResult.success
                      ? `Collected ${oktaCollectorValidationResult.event_count || 0} event${oktaCollectorValidationResult.event_count === 1 ? '' : 's'}.`
                      : oktaCollectorValidationResult.error || 'Validation needs attention.'}
                  </div>
                  <JsonDetails
                    data={oktaCollectorValidationResult}
                    label="Okta validation details"
                  />
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Microsoft Entra ID</span>
                <span className={`badge ${validationBadgeClass(entraCollectorValidation.status)}`}>
                  {validationStatusLabel(entraCollectorValidation.status)}
                </span>
              </div>
              {entraCollectorData?.config?.has_client_secret && (
                <div style={{ fontSize: 12, opacity: 0.75, marginBottom: 12 }}>
                  A client secret or secret reference is already stored. Leave the secret field
                  blank to keep it.
                </div>
              )}
              <ToggleSwitch
                label="Enable Entra collector"
                checked={entraCollectorDraft.enabled}
                onChange={(value) =>
                  setEntraCollectorDraft((prev) => ({ ...prev, enabled: value }))
                }
                description="Use this when Entra sign-in logs should be validated or polled from the saved setup."
              />
              <TextInput
                label="Tenant ID"
                value={entraCollectorDraft.tenant_id}
                onChange={(value) =>
                  setEntraCollectorDraft((prev) => ({ ...prev, tenant_id: value }))
                }
                placeholder="tenant-guid"
              />
              <TextInput
                label="Client ID"
                value={entraCollectorDraft.client_id}
                onChange={(value) =>
                  setEntraCollectorDraft((prev) => ({ ...prev, client_id: value }))
                }
                placeholder="application-guid"
              />
              <TextInput
                label="Client Secret"
                type="password"
                value={entraCollectorDraft.client_secret}
                onChange={(value) =>
                  setEntraCollectorDraft((prev) => ({ ...prev, client_secret: value }))
                }
                placeholder="Leave blank to keep the current secret or reference"
                description="Supports literal values or secret references such as ${ENTRA_CLIENT_SECRET}."
              />
              <NumberInput
                label="Poll Interval"
                value={entraCollectorDraft.poll_interval_secs}
                onChange={(value) =>
                  setEntraCollectorDraft((prev) => ({ ...prev, poll_interval_secs: value }))
                }
                min={1}
                unit="seconds"
              />
              <ValidationIssues validation={entraCollectorValidation} style={{ marginTop: 12 }} />
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={entraCollectorSaving}
                  onClick={saveEntraCollector}
                >
                  {entraCollectorSaving ? 'Saving…' : 'Save Entra Setup'}
                </button>
                <button className="btn" type="button" onClick={validateEntraCollector}>
                  Validate Entra
                </button>
              </div>
              {entraCollectorValidationResult && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Last validation</div>
                  <div style={{ fontSize: 12 }}>
                    {entraCollectorValidationResult.success
                      ? `Collected ${entraCollectorValidationResult.event_count || 0} event${entraCollectorValidationResult.event_count === 1 ? '' : 's'}.`
                      : entraCollectorValidationResult.error || 'Validation needs attention.'}
                  </div>
                  <JsonDetails
                    data={entraCollectorValidationResult}
                    label="Entra validation details"
                  />
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Microsoft 365 Activity</span>
                <span className={`badge ${validationBadgeClass(m365CollectorValidation.status)}`}>
                  {validationStatusLabel(m365CollectorValidation.status)}
                </span>
              </div>
              {m365CollectorData?.config?.has_client_secret && (
                <div style={{ fontSize: 12, opacity: 0.75, marginBottom: 12 }}>
                  A client secret or secret reference is already stored. Leave the secret field
                  blank to keep it.
                </div>
              )}
              <ToggleSwitch
                label="Enable Microsoft 365 collector"
                checked={m365CollectorDraft.enabled}
                onChange={(value) => setM365CollectorDraft((prev) => ({ ...prev, enabled: value }))}
                description="Use this when unified audit activity should be validated or queued for downstream SaaS workflows."
              />
              <TextInput
                label="Tenant ID"
                value={m365CollectorDraft.tenant_id}
                onChange={(value) =>
                  setM365CollectorDraft((prev) => ({ ...prev, tenant_id: value }))
                }
                placeholder="m365-tenant-guid"
              />
              <TextInput
                label="Client ID"
                value={m365CollectorDraft.client_id}
                onChange={(value) =>
                  setM365CollectorDraft((prev) => ({ ...prev, client_id: value }))
                }
                placeholder="application-guid"
              />
              <TextInput
                label="Client Secret"
                type="password"
                value={m365CollectorDraft.client_secret}
                onChange={(value) =>
                  setM365CollectorDraft((prev) => ({ ...prev, client_secret: value }))
                }
                placeholder="Leave blank to keep the current secret or reference"
                description="Supports literal values or secret references such as ${M365_CLIENT_SECRET}."
              />
              <NumberInput
                label="Poll Interval"
                value={m365CollectorDraft.poll_interval_secs}
                onChange={(value) =>
                  setM365CollectorDraft((prev) => ({ ...prev, poll_interval_secs: value }))
                }
                min={1}
                unit="seconds"
              />
              <TextAreaInput
                label="Content Types"
                value={m365CollectorDraft.content_types}
                onChange={(value) =>
                  setM365CollectorDraft((prev) => ({ ...prev, content_types: value }))
                }
                placeholder={'Audit.AzureActiveDirectory\nAudit.Exchange\nAudit.SharePoint'}
                description="One Microsoft 365 content type per line."
                rows={4}
              />
              <ValidationIssues validation={m365CollectorValidation} style={{ marginTop: 12 }} />
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={m365CollectorSaving}
                  onClick={saveM365Collector}
                >
                  {m365CollectorSaving ? 'Saving…' : 'Save Microsoft 365 Setup'}
                </button>
                <button className="btn" type="button" onClick={validateM365Collector}>
                  Validate Microsoft 365
                </button>
              </div>
              {m365CollectorValidationResult && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Last validation</div>
                  <div style={{ fontSize: 12 }}>
                    {m365CollectorValidationResult.success
                      ? `Collected ${m365CollectorValidationResult.event_count || 0} event${m365CollectorValidationResult.event_count === 1 ? '' : 's'}.`
                      : m365CollectorValidationResult.error || 'Validation needs attention.'}
                  </div>
                  <JsonDetails
                    data={m365CollectorValidationResult}
                    label="Microsoft 365 validation details"
                  />
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Google Workspace Activity</span>
                <span
                  className={`badge ${validationBadgeClass(workspaceCollectorValidation.status)}`}
                >
                  {validationStatusLabel(workspaceCollectorValidation.status)}
                </span>
              </div>
              {workspaceCollectorData?.config?.has_credentials_json && (
                <div style={{ fontSize: 12, opacity: 0.75, marginBottom: 12 }}>
                  A credentials blob or secret reference is already stored. Leave the credentials
                  field blank to keep it.
                </div>
              )}
              <ToggleSwitch
                label="Enable Google Workspace collector"
                checked={workspaceCollectorDraft.enabled}
                onChange={(value) =>
                  setWorkspaceCollectorDraft((prev) => ({ ...prev, enabled: value }))
                }
                description="Use this when Workspace admin, login, or collaboration activity should be validated or routed downstream."
              />
              <TextInput
                label="Customer ID"
                value={workspaceCollectorDraft.customer_id}
                onChange={(value) =>
                  setWorkspaceCollectorDraft((prev) => ({ ...prev, customer_id: value }))
                }
                placeholder="my_customer"
              />
              <TextInput
                label="Delegated Admin Email"
                value={workspaceCollectorDraft.delegated_admin_email}
                onChange={(value) =>
                  setWorkspaceCollectorDraft((prev) => ({ ...prev, delegated_admin_email: value }))
                }
                placeholder="admin@example.com"
              />
              <TextInput
                label="Service Account Email"
                value={workspaceCollectorDraft.service_account_email}
                onChange={(value) =>
                  setWorkspaceCollectorDraft((prev) => ({ ...prev, service_account_email: value }))
                }
                placeholder="collector@workspace.example.iam.gserviceaccount.com"
              />
              <TextAreaInput
                label="Credentials JSON"
                value={workspaceCollectorDraft.credentials_json}
                onChange={(value) =>
                  setWorkspaceCollectorDraft((prev) => ({ ...prev, credentials_json: value }))
                }
                placeholder="Leave blank to keep the current credentials or reference"
                description="Supports literal JSON or secret references such as vault://secret/google#service_account_json."
                rows={4}
              />
              <NumberInput
                label="Poll Interval"
                value={workspaceCollectorDraft.poll_interval_secs}
                onChange={(value) =>
                  setWorkspaceCollectorDraft((prev) => ({ ...prev, poll_interval_secs: value }))
                }
                min={1}
                unit="seconds"
              />
              <TextAreaInput
                label="Applications"
                value={workspaceCollectorDraft.applications}
                onChange={(value) =>
                  setWorkspaceCollectorDraft((prev) => ({ ...prev, applications: value }))
                }
                placeholder={'login\nadmin\ndrive\nmeet'}
                description="One Google Workspace application or audit stream per line."
                rows={4}
              />
              <ValidationIssues
                validation={workspaceCollectorValidation}
                style={{ marginTop: 12 }}
              />
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={workspaceCollectorSaving}
                  onClick={saveWorkspaceCollector}
                >
                  {workspaceCollectorSaving ? 'Saving…' : 'Save Workspace Setup'}
                </button>
                <button className="btn" type="button" onClick={validateWorkspaceCollector}>
                  Validate Workspace
                </button>
              </div>
              {workspaceCollectorValidationResult && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Last validation</div>
                  <div style={{ fontSize: 12 }}>
                    {workspaceCollectorValidationResult.success
                      ? `Collected ${workspaceCollectorValidationResult.event_count || 0} event${workspaceCollectorValidationResult.event_count === 1 ? '' : 's'}.`
                      : workspaceCollectorValidationResult.error || 'Validation needs attention.'}
                  </div>
                  <JsonDetails
                    data={workspaceCollectorValidationResult}
                    label="Workspace validation details"
                  />
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Secrets Manager</span>
                <span className={`badge ${validationBadgeClass(secretsManagerValidation.status)}`}>
                  {validationStatusLabel(secretsManagerValidation.status)}
                </span>
              </div>
              {secretsData?.config?.vault?.has_token && (
                <div style={{ fontSize: 12, opacity: 0.75, marginBottom: 12 }}>
                  A Vault token or secret reference is already stored. Leave the token field blank
                  to keep it.
                </div>
              )}
              <ToggleSwitch
                label="Enable Vault"
                checked={secretsDraft.enabled}
                onChange={(value) => setSecretsDraft((prev) => ({ ...prev, enabled: value }))}
                description="Leave disabled to use only environment variables or local secret files."
              />
              <TextInput
                label="Vault Address"
                value={secretsDraft.address}
                onChange={(value) => setSecretsDraft((prev) => ({ ...prev, address: value }))}
                placeholder="http://127.0.0.1:8200"
              />
              <TextInput
                label="Vault Token"
                type="password"
                value={secretsDraft.token}
                onChange={(value) => setSecretsDraft((prev) => ({ ...prev, token: value }))}
                placeholder="Leave blank to keep the current token or reference"
                description="Supports literal values or secret references when Vault access is delegated through another source."
              />
              <TextInput
                label="Vault Mount"
                value={secretsDraft.mount}
                onChange={(value) => setSecretsDraft((prev) => ({ ...prev, mount: value }))}
                placeholder="secret"
              />
              <TextInput
                label="Vault Namespace"
                value={secretsDraft.namespace}
                onChange={(value) => setSecretsDraft((prev) => ({ ...prev, namespace: value }))}
                placeholder="Optional enterprise namespace"
              />
              <NumberInput
                label="Cache TTL"
                value={secretsDraft.cache_ttl_secs}
                onChange={(value) =>
                  setSecretsDraft((prev) => ({ ...prev, cache_ttl_secs: value }))
                }
                min={0}
                unit="seconds"
              />
              <TextInput
                label="Environment Prefix"
                value={secretsDraft.env_prefix}
                onChange={(value) => setSecretsDraft((prev) => ({ ...prev, env_prefix: value }))}
                placeholder="WARDEX_"
                description="When set, ${API_KEY} resolves against prefixed variables such as WARDEX_API_KEY."
              />
              <TextInput
                label="Secrets Directory"
                value={secretsDraft.secrets_dir}
                onChange={(value) => setSecretsDraft((prev) => ({ ...prev, secrets_dir: value }))}
                placeholder="/run/secrets"
                description="Optional directory boundary for file:// secret references."
              />
              <TextAreaInput
                label="Test Secret Reference"
                value={secretsDraft.test_reference}
                onChange={(value) =>
                  setSecretsDraft((prev) => ({ ...prev, test_reference: value }))
                }
                placeholder={
                  '${API_TOKEN}\nfile:///run/secrets/token\nvault://secret/wardex/api#token'
                }
                description="Enter one reference at a time when validating."
                rows={3}
              />
              {Array.isArray(secretsData?.config?.supported_sources) &&
              secretsData.config.supported_sources.length > 0 ? (
                <div className="chip-row" style={{ marginTop: 4 }}>
                  {secretsData.config.supported_sources.map((source) => (
                    <span key={source} className="badge badge-info">
                      {source}
                    </span>
                  ))}
                </div>
              ) : null}
              <ValidationIssues validation={secretsManagerValidation} style={{ marginTop: 12 }} />
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                <button
                  className="btn btn-primary"
                  type="button"
                  disabled={secretsSaving}
                  onClick={saveSecretsManager}
                >
                  {secretsSaving ? 'Saving…' : 'Save Secrets Setup'}
                </button>
                <button className="btn" type="button" onClick={validateSecretsReference}>
                  Validate Secret Reference
                </button>
              </div>
              {secretsData?.status && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Resolver Status</div>
                  <SummaryGrid data={secretsData.status} limit={6} />
                </div>
              )}
              {secretValidationResult && (
                <div className="stat-box" style={{ marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>Last validation</div>
                  <div style={{ fontSize: 12 }}>
                    {secretValidationResult.ok
                      ? `Resolved ${secretValidationResult.reference_kind} secret with length ${secretValidationResult.resolved_length}.`
                      : secretValidationResult.error || 'Secret validation needs attention.'}
                  </div>
                  <JsonDetails data={secretValidationResult} label="Secret validation details" />
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {tab === 'flags' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Feature Flags
          </div>
          {flagEntries.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Flag</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {flagEntries.map(([k, v]) => (
                    <tr key={k}>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{k}</td>
                      <td>
                        <span className={`badge ${v ? 'badge-ok' : 'badge-warn'}`}>
                          {v ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <>
              <div className="empty">No feature flags available.</div>
              <JsonDetails data={flags} />
            </>
          )}
        </div>
      )}

      {tab === 'team' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Team &amp; RBAC
          </div>
          <div
            style={{
              display: 'flex',
              gap: 8,
              marginBottom: 16,
              flexWrap: 'wrap',
              alignItems: 'flex-end',
            }}
          >
            <div>
              <div style={{ fontSize: 12, marginBottom: 4 }}>Username</div>
              <input
                className="input"
                value={newUser.username}
                onChange={(e) => setNewUser((p) => ({ ...p, username: e.target.value }))}
                placeholder="username"
                style={{ width: 180 }}
              />
            </div>
            <div>
              <div style={{ fontSize: 12, marginBottom: 4 }}>Role</div>
              <select
                className="input"
                value={newUser.role}
                onChange={(e) => setNewUser((p) => ({ ...p, role: e.target.value }))}
              >
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="viewer">Viewer</option>
                <option value="service-account">Service Account</option>
              </select>
            </div>
            <button
              className="btn btn-primary"
              disabled={!newUser.username.trim() || creatingUser}
              onClick={async () => {
                setCreatingUser(true);
                try {
                  const res = await api.rbacCreateUser({
                    username: newUser.username.trim(),
                    role: newUser.role,
                  });
                  toast(`User created${res?.token ? ' — token: ' + res.token : ''}`, 'success');
                  setNewUser({ username: '', role: 'analyst' });
                  rTeam();
                } catch (e) {
                  toast('Failed to create user: ' + (e.message || e), 'error');
                }
                setCreatingUser(false);
              }}
            >
              {creatingUser ? 'Creating…' : 'Create User'}
            </button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {(Array.isArray(teamUsers) ? teamUsers : []).map((u) => (
                  <tr key={u.username || u.name}>
                    <td>{u.username || u.name}</td>
                    <td>
                      <span
                        className={`badge ${u.role === 'admin' ? 'badge-danger' : u.role === 'analyst' ? 'badge-ok' : 'badge-info'}`}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn btn-ghost btn-sm"
                        style={{ color: 'var(--danger)' }}
                        onClick={async () => {
                          const username = u.username || u.name;
                          const ok = await confirm({
                            title: `Delete user "${username}"?`,
                            message:
                              'The account is removed and any active sessions are revoked. This cannot be undone.',
                            confirmLabel: 'Delete user',
                            tone: 'danger',
                          });
                          if (!ok) return;
                          try {
                            await api.rbacDeleteUser(username);
                            toast('User deleted', 'success');
                            rTeam();
                          } catch (e) {
                            toast('Delete failed: ' + (e.message || e), 'error');
                          }
                        }}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {(!teamUsers || (Array.isArray(teamUsers) && teamUsers.length === 0)) && (
            <div className="empty">No team members configured yet.</div>
          )}
        </div>
      )}

      {tab === 'admin' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                DB Version
              </div>
              <SummaryGrid data={dbVer} limit={6} />
              <JsonDetails data={dbVer} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Dead Letter Queue
              </div>
              <SummaryGrid data={dlqData} limit={8} />
              <JsonDetails data={dlqData} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                SBOM
              </div>
              <SummaryGrid data={sbomData} limit={8} />
              <JsonDetails data={sbomData} />
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Database Storage
            </div>
            {dbSizes && (
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                  gap: 12,
                  marginBottom: 16,
                }}
              >
                <div className="stat-box">
                  <div className="stat-label">Main DB</div>
                  <div className="stat-value">{formatBytes(dbSizes.db_bytes)}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">WAL File</div>
                  <div className="stat-value">{formatBytes(dbSizes.wal_bytes)}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">SHM File</div>
                  <div className="stat-value">{formatBytes(dbSizes.shm_bytes)}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Total</div>
                  <div className="stat-value">{formatBytes(dbSizes.total_bytes)}</div>
                </div>
              </div>
            )}
            {storageStats && (
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))',
                  gap: 12,
                  marginBottom: 16,
                }}
              >
                <div className="stat-box">
                  <div className="stat-label">Alerts</div>
                  <div className="stat-value">{storageStats.total_alerts ?? '—'}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Cases</div>
                  <div className="stat-value">{storageStats.total_cases ?? '—'}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Audit</div>
                  <div className="stat-value">{storageStats.total_audit_entries ?? '—'}</div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Agents</div>
                  <div className="stat-value">{storageStats.total_agents ?? '—'}</div>
                </div>
              </div>
            )}
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <span className="card-title">Long-Retention History</span>
              <div className="btn-group">
                <span
                  className={`badge ${historicalEventsData?.enabled || storageStats?.clickhouse_enabled ? 'badge-ok' : 'badge-warn'}`}
                >
                  {historicalEventsData?.enabled || storageStats?.clickhouse_enabled
                    ? 'ClickHouse Ready'
                    : 'Not Configured'}
                </span>
                <button className="btn btn-sm" onClick={refreshAdminRetentionWorkspace}>
                  ↻ Refresh
                </button>
              </div>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                gap: 12,
                marginBottom: 16,
              }}
            >
              <div className="stat-box">
                <div className="stat-label">Retained Events</div>
                <div className="stat-value">{retentionConfig?.current_counts?.events ?? '—'}</div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Buffered Inserts</div>
                <div className="stat-value">{storageStats?.clickhouse_buffer_len ?? '—'}</div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Inserted To ClickHouse</div>
                <div className="stat-value">{storageStats?.clickhouse_total_inserted ?? '—'}</div>
              </div>
              <div className="stat-box">
                <div className="stat-label">Database</div>
                <div className="stat-value">{storageStats?.clickhouse_database || '—'}</div>
              </div>
            </div>

            <div className="card-grid" style={{ marginBottom: 16 }}>
              <div className="card" style={{ padding: 14 }}>
                <div className="card-title" style={{ marginBottom: 10 }}>
                  Retention Controls
                </div>
                <NumberInput
                  label="Audit Records"
                  value={retentionDraft.audit_max_records}
                  onChange={(value) =>
                    setRetentionDraft((prev) => ({ ...prev, audit_max_records: value }))
                  }
                  min={0}
                />
                <NumberInput
                  label="Alert Records"
                  value={retentionDraft.alert_max_records}
                  onChange={(value) =>
                    setRetentionDraft((prev) => ({ ...prev, alert_max_records: value }))
                  }
                  min={0}
                />
                <NumberInput
                  label="Event Records"
                  value={retentionDraft.event_max_records}
                  onChange={(value) =>
                    setRetentionDraft((prev) => ({ ...prev, event_max_records: value }))
                  }
                  min={0}
                />
                <NumberInput
                  label="Audit Max Age"
                  value={retentionDraft.audit_max_age_days}
                  onChange={(value) =>
                    setRetentionDraft((prev) => ({ ...prev, audit_max_age_days: value }))
                  }
                  min={0}
                  unit="days"
                />
                <TextInput
                  label="Remote Syslog Endpoint"
                  value={retentionDraft.remote_syslog_endpoint}
                  onChange={(value) =>
                    setRetentionDraft((prev) => ({ ...prev, remote_syslog_endpoint: value }))
                  }
                  placeholder="udp://syslog.example.com:514"
                />
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                  <button
                    className="btn btn-primary"
                    disabled={retentionSaving}
                    onClick={saveRetentionSettings}
                  >
                    {retentionSaving ? 'Saving…' : 'Save Retention Settings'}
                  </button>
                  <button className="btn" disabled={retentionApplying} onClick={applyRetentionNow}>
                    {retentionApplying ? 'Applying…' : 'Apply Retention Now'}
                  </button>
                </div>
                {lastRetentionApply && (
                  <div className="stat-box" style={{ marginTop: 12 }}>
                    <div style={{ fontWeight: 600, marginBottom: 6 }}>Last apply</div>
                    <div style={{ fontSize: 12 }}>
                      Trimmed {lastRetentionApply.trimmed_alerts ?? 0} alerts and{' '}
                      {lastRetentionApply.trimmed_events ?? 0} events.
                    </div>
                  </div>
                )}
              </div>

              <div className="card" style={{ padding: 14 }}>
                <div className="card-title" style={{ marginBottom: 10 }}>
                  Historical Search
                </div>
                <div style={{ display: 'grid', gap: 10 }}>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                      gap: 10,
                    }}
                  >
                    <TextInput
                      label="Since"
                      value={historicalDraft.since}
                      onChange={(value) =>
                        setHistoricalDraft((prev) => ({ ...prev, since: value }))
                      }
                      placeholder="2026-04-01T00:00:00Z"
                    />
                    <TextInput
                      label="Until"
                      value={historicalDraft.until}
                      onChange={(value) =>
                        setHistoricalDraft((prev) => ({ ...prev, until: value }))
                      }
                      placeholder="2026-04-21T23:59:59Z"
                    />
                    <TextInput
                      label="Tenant"
                      value={historicalDraft.tenant_id}
                      onChange={(value) =>
                        setHistoricalDraft((prev) => ({ ...prev, tenant_id: value }))
                      }
                      placeholder="default"
                    />
                    <TextInput
                      label="Device"
                      value={historicalDraft.device_id}
                      onChange={(value) =>
                        setHistoricalDraft((prev) => ({ ...prev, device_id: value }))
                      }
                      placeholder="agent-01"
                    />
                    <TextInput
                      label="User"
                      value={historicalDraft.user_name}
                      onChange={(value) =>
                        setHistoricalDraft((prev) => ({ ...prev, user_name: value }))
                      }
                      placeholder="analyst@example.com"
                    />
                    <TextInput
                      label="Source IP"
                      value={historicalDraft.src_ip}
                      onChange={(value) =>
                        setHistoricalDraft((prev) => ({ ...prev, src_ip: value }))
                      }
                      placeholder="203.0.113.10"
                    />
                    <NumberInput
                      label="Severity Min"
                      value={historicalDraft.severity_min}
                      onChange={(value) =>
                        setHistoricalDraft((prev) => ({ ...prev, severity_min: value }))
                      }
                      min={0}
                      max={10}
                    />
                    <NumberInput
                      label="Event Class"
                      value={historicalDraft.event_class}
                      onChange={(value) =>
                        setHistoricalDraft((prev) => ({ ...prev, event_class: value }))
                      }
                      min={0}
                    />
                    <NumberInput
                      label="Limit"
                      value={historicalDraft.limit}
                      onChange={(value) =>
                        setHistoricalDraft((prev) => ({ ...prev, limit: value }))
                      }
                      min={1}
                      max={200}
                    />
                  </div>

                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button className="btn btn-primary" onClick={runHistoricalSearch}>
                      Search Retained Events
                    </button>
                    <span style={{ fontSize: 12, opacity: 0.75, alignSelf: 'center' }}>
                      {historicalEventsLoading
                        ? 'Searching retained events…'
                        : `Showing ${historicalEvents.length} of ${historicalEventsData?.total ?? 0} matching events`}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {historicalEventsData?.error && (
              <div className="stat-box" style={{ marginBottom: 12, fontSize: 12 }}>
                {historicalEventsData.error}
              </div>
            )}

            {historicalEvents.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Severity</th>
                      <th>Class</th>
                      <th>Device</th>
                      <th>User</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Payload</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historicalEvents.map((event, index) => (
                      <tr
                        key={`${event.timestamp || 'ts'}-${event.device_id || 'device'}-${index}`}
                      >
                        <td>{formatAuditTimestamp(event.timestamp)}</td>
                        <td>{event.severity ?? '—'}</td>
                        <td>{event.event_class ?? '—'}</td>
                        <td>{event.device_id || '—'}</td>
                        <td>{event.user_name || '—'}</td>
                        <td>{event.src_ip || '—'}</td>
                        <td>{event.dst_ip || '—'}</td>
                        <td>
                          <details>
                            <summary style={{ cursor: 'pointer', fontSize: 12 }}>Raw event</summary>
                            <pre
                              style={{
                                marginTop: 8,
                                whiteSpace: 'pre-wrap',
                                fontSize: 11,
                                maxWidth: 360,
                              }}
                            >
                              {event.raw_json || 'No raw payload available.'}
                            </pre>
                          </details>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : historicalEventsLoading ? (
              <div className="empty">Searching retained events...</div>
            ) : (
              <div className="empty">
                {historicalEventsData?.enabled === false
                  ? historicalEventsData?.error ||
                    'ClickHouse long-retention storage is not configured.'
                  : 'No retained events match the current filters.'}
              </div>
            )}

            <JsonDetails data={historicalEventsData} label="Historical storage diagnostics" />
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <span className="card-title">API Audit Trail</span>
              <div className="btn-group" style={{ alignItems: 'center' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  {auditLogLoading && auditLogPage.count === 0
                    ? 'Loading audit entries...'
                    : auditRangeLabel(auditLogPage)}
                </span>
                <button className="btn btn-sm" disabled={auditLogLoading} onClick={rAuditLog}>
                  ↻ Refresh
                </button>
              </div>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
                gap: 12,
                marginBottom: 12,
              }}
            >
              <div style={{ minWidth: 0 }}>
                <label htmlFor="audit-log-search" style={auditLabelStyle}>
                  Search
                </label>
                <input
                  id="audit-log-search"
                  type="search"
                  placeholder="Path, source, method, status"
                  value={auditQuery}
                  onChange={(event) => {
                    setAuditQuery(event.target.value);
                    setAuditPage(0);
                  }}
                  style={auditControlStyle}
                />
              </div>
              <div>
                <label htmlFor="audit-log-method" style={auditLabelStyle}>
                  Method
                </label>
                <select
                  id="audit-log-method"
                  value={auditMethod}
                  onChange={(event) => {
                    setAuditMethod(event.target.value);
                    setAuditPage(0);
                  }}
                  style={auditControlStyle}
                >
                  {AUDIT_METHOD_OPTIONS.map((option) => (
                    <option key={option} value={option}>
                      {option === 'all' ? 'All methods' : option}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="audit-log-status" style={auditLabelStyle}>
                  Status
                </label>
                <select
                  id="audit-log-status"
                  value={auditStatus}
                  onChange={(event) => {
                    setAuditStatus(event.target.value);
                    setAuditPage(0);
                  }}
                  style={auditControlStyle}
                >
                  {AUDIT_STATUS_OPTIONS.map((option) => (
                    <option key={option} value={option}>
                      {option === 'all' ? 'All statuses' : option}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="audit-log-auth" style={auditLabelStyle}>
                  Auth
                </label>
                <select
                  id="audit-log-auth"
                  value={auditAuth}
                  onChange={(event) => {
                    setAuditAuth(event.target.value);
                    setAuditPage(0);
                  }}
                  style={auditControlStyle}
                >
                  {AUDIT_AUTH_OPTIONS.map((option) => (
                    <option key={option} value={option}>
                      {option === 'all'
                        ? 'All requests'
                        : option === 'authenticated'
                          ? 'Authenticated'
                          : 'Anonymous'}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: 12,
                flexWrap: 'wrap',
                marginBottom: 12,
              }}
            >
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Filters apply to both the paged table and the CSV export.
              </span>
              <div className="btn-group">
                <button
                  className="btn btn-sm"
                  disabled={!auditFiltersActive}
                  onClick={clearAuditFilters}
                >
                  Clear Filters
                </button>
                <button className="btn btn-sm" disabled={auditLogLoading} onClick={exportAuditLog}>
                  Export CSV
                </button>
              </div>
            </div>

            {auditLogError ? (
              <div className="empty">Unable to load the API audit trail.</div>
            ) : auditLogPage.entries.length > 0 ? (
              <>
                <div style={{ overflowX: 'auto' }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Method</th>
                        <th>Path</th>
                        <th>Source</th>
                        <th>Status</th>
                        <th>Auth</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogPage.entries.map((entry, index) => (
                        <tr key={`${entry.timestamp || 'audit'}-${entry.path || 'path'}-${index}`}>
                          <td style={{ whiteSpace: 'nowrap' }}>
                            {formatAuditTimestamp(entry.timestamp)}
                          </td>
                          <td>
                            <span className="badge badge-info">
                              {String(entry.method || '—').toUpperCase()}
                            </span>
                          </td>
                          <td
                            style={{
                              maxWidth: 360,
                              fontFamily:
                                'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace',
                              wordBreak: 'break-word',
                            }}
                          >
                            {entry.path || '—'}
                          </td>
                          <td>{entry.source_ip || '—'}</td>
                          <td>
                            <span
                              className={`badge ${auditStatusClass(Number(entry.status_code) || 0)}`}
                            >
                              {entry.status_code ?? '—'}
                            </span>
                          </td>
                          <td>
                            <span
                              className={`badge ${entry.auth_used ? 'badge-ok' : 'badge-warn'}`}
                            >
                              {entry.auth_used ? 'Authenticated' : 'Anonymous'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: 12,
                    flexWrap: 'wrap',
                    marginTop: 12,
                  }}
                >
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Newest requests appear first. Use Older to walk back through the API trail.
                  </span>
                  <div className="btn-group" style={{ alignItems: 'center' }}>
                    <button
                      className="btn btn-sm"
                      disabled={auditLogLoading || auditPage === 0}
                      onClick={() => setAuditPage((current) => Math.max(0, current - 1))}
                    >
                      Newer
                    </button>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      Page {auditPage + 1}
                    </span>
                    <button
                      className="btn btn-sm"
                      disabled={auditLogLoading || !auditLogPage.has_more}
                      onClick={() => setAuditPage((current) => current + 1)}
                    >
                      Older
                    </button>
                  </div>
                </div>
              </>
            ) : auditLogLoading ? (
              <div className="empty">Loading audit log...</div>
            ) : (
              <div className="empty">{auditEmptyMessage(auditFiltersActive)}</div>
            )}
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Database Maintenance
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <button
                  className="btn"
                  disabled={compacting}
                  onClick={async () => {
                    setCompacting(true);
                    try {
                      const r = await api.adminDbCompact();
                      toast(`Compacted: ${formatBytes(r.bytes_reclaimed)} reclaimed`, 'success');
                      rSizes();
                    } catch {
                      toast('Compact failed', 'error');
                    }
                    setCompacting(false);
                  }}
                >
                  {compacting ? 'Compacting...' : 'Compact Database'}
                </button>
                <span style={{ fontSize: '0.85rem', opacity: 0.7 }}>
                  VACUUM + WAL checkpoint — reclaims unused space
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <label style={{ fontSize: '0.85rem' }}>Purge data older than</label>
                <input
                  type="number"
                  min="1"
                  max="3650"
                  value={purgeDays}
                  onChange={(e) => setPurgeDays(Number(e.target.value))}
                  style={{ width: 70, padding: '4px 8px' }}
                />
                <span style={{ fontSize: '0.85rem' }}>days</span>
                <button
                  className="btn"
                  disabled={purging}
                  onClick={async () => {
                    if (isNaN(purgeDays) || purgeDays < 1) {
                      toast('Invalid value — enter 1-3650 days', 'error');
                      return;
                    }
                    const ok = await confirm({
                      title: `Purge records older than ${purgeDays} days?`,
                      message:
                        'Alerts, audit events and metrics older than the retention window will be permanently deleted. This cannot be undone.',
                      confirmLabel: 'Purge records',
                      tone: 'danger',
                    });
                    if (!ok) return;
                    setPurging(true);
                    try {
                      const r = await api.adminDbPurge({ retention_days: purgeDays });
                      toast(
                        `Purged: ${r.alerts_purged} alerts, ${r.audit_purged} audit, ${r.metrics_purged} metrics`,
                        'success',
                      );
                      rSizes();
                      refreshAdminRetentionWorkspace();
                    } catch {
                      toast('Purge failed', 'error');
                    }
                    setPurging(false);
                  }}
                >
                  {purging ? 'Purging...' : 'Purge Old Data'}
                </button>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <button
                  className="btn"
                  disabled={cleaning}
                  onClick={async () => {
                    setCleaning(true);
                    try {
                      const r = await api.adminCleanupLegacy();
                      if (r.count > 0) toast(`Cleaned ${r.count} legacy files`, 'success');
                      else toast('No legacy files found', 'info');
                    } catch {
                      toast('Cleanup failed', 'error');
                    }
                    setCleaning(false);
                  }}
                >
                  {cleaning ? 'Cleaning...' : 'Clean Legacy Files'}
                </button>
                <span style={{ fontSize: '0.85rem', opacity: 0.7 }}>
                  Remove old .json/.jsonl flat files from var/
                </span>
              </div>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Admin Actions
            </div>
            <div className="btn-group">
              <button
                className="btn"
                onClick={async () => {
                  try {
                    await api.adminBackup();
                    toast('Backup created', 'success');
                  } catch {
                    toast('Backup failed', 'error');
                  }
                }}
              >
                Create Backup
              </button>
              <button
                className="btn btn-danger"
                style={{ marginLeft: 8 }}
                onClick={async () => {
                  const answer = prompt(
                    'Type RESET_ALL_DATA to confirm deleting all database records:',
                  );
                  if (answer !== 'RESET_ALL_DATA') {
                    toast('Reset cancelled', 'info');
                    return;
                  }
                  setResetting(true);
                  try {
                    const r = await api.adminDbReset({ confirm: 'RESET_ALL_DATA' });
                    toast(`Database reset: ${r.records_purged} records purged`, 'warning');
                    rSizes();
                    refreshAdminRetentionWorkspace();
                  } catch {
                    toast('Reset failed', 'error');
                  }
                  setResetting(false);
                }}
              >
                {resetting ? 'Resetting...' : 'Reset Database'}
              </button>
              <button
                className="btn btn-danger"
                onClick={async () => {
                  const ok = await confirm({
                    title: 'Shutdown the Wardex server?',
                    message:
                      'The server process will terminate. You will need out-of-band access to restart it.',
                    confirmLabel: 'Shutdown',
                    tone: 'danger',
                  });
                  if (!ok) return;
                  try {
                    await api.shutdown();
                    toast('Shutdown initiated', 'warning');
                  } catch {
                    toast('Shutdown failed', 'error');
                  }
                }}
              >
                Shutdown Server
              </button>
            </div>
          </div>
        </>
      )}
      {confirmUI}
    </div>
  );
}

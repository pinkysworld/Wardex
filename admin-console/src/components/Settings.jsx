import { useState, useEffect, useMemo, useId } from 'react';
import { useApi, useToast } from '../hooks.jsx';
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
  return {
    id: provider?.id || '',
    kind: String(provider?.kind || 'oidc').toLowerCase(),
    display_name: provider?.display_name || provider?.name || '',
    issuer_url: provider?.issuer_url || '',
    sso_url: provider?.sso_url || '',
    client_id: provider?.client_id || '',
    entity_id: provider?.entity_id || '',
    enabled: provider?.enabled ?? true,
    mappings_text: formatGroupRoleMappings(provider?.group_role_mappings),
  };
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

function auditEmptyMessage(filtersActive) {
  return filtersActive ? 'No audit entries match the current filters.' : 'No audit entries captured yet.';
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

function TextInput({ label, value, onChange, placeholder, description }) {
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
        type="text"
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
  const { data: siemSt } = useApi(api.siemStatus);
  const { data: siemCfg } = useApi(api.siemConfig);
  const { data: taxiiSt } = useApi(api.taxiiStatus);
  const { data: taxiiCfg } = useApi(api.taxiiConfig);
  const { data: enrichConn } = useApi(api.enrichmentConnectors);
  const { data: idp, reload: rIdp } = useApi(api.idpProviders);
  const { data: scim, reload: rScim } = useApi(api.scimConfig);
  const { data: sbomData } = useApi(api.sbom);
  const { data: dbVer } = useApi(api.adminDbVersion);
  const { data: dlqData } = useApi(api.dlqStats);
  const { data: dbSizes, reload: rSizes } = useApi(api.adminDbSizes);
  const { data: storageStats, reload: rStats } = useApi(api.storageStats);
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

  const scimConfigData = useMemo(() => {
    const candidate = scim?.config ?? scim;
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
    return candidate;
  }, [scim]);

  const scimValidation = useMemo(() => normalizeValidation(scim?.validation), [scim]);

  useEffect(() => {
    if (idpRows.length === 0) setIdpEditorOpen(true);
  }, [idpRows.length]);

  useEffect(() => {
    if (scimEditing) return;
    setScimDraft(createScimDraft(scimConfigData));
    setScimFormError(null);
  }, [scimConfigData, scimEditing]);

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
        entity_id: optionalTextValue(idpDraft.entity_id),
        enabled: idpDraft.enabled,
        group_role_mappings: mappings,
      });
      const validation = normalizeValidation(result?.validation);
      const provider = result?.provider ?? {};
      await rIdp();
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
      await rScim();
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
      message: 'Built-in defaults will overwrite the currently loaded values. You still have to click Save to apply them server-side.',
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
                <span className={`badge ${siemSt?.connected ? 'badge-ok' : 'badge-warn'}`}>
                  {siemSt?.connected ? 'Connected' : 'Not connected'}
                </span>
              </div>
              {siemCfg && typeof siemCfg === 'object' ? (
                <>
                  <SummaryGrid data={siemCfg} limit={10} />
                  <JsonDetails data={siemCfg} />
                </>
              ) : (
                <>
                  <div className="empty">No SIEM configuration available.</div>
                  <JsonDetails data={siemCfg} />
                </>
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
                              <button
                                className="btn btn-sm"
                                type="button"
                                onClick={() => openIdpEditor(p)}
                              >
                                Edit Provider
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {idpRows.some((provider) => provider.validation?.issues?.length > 0) && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 12 }}>
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
                        <div style={{ fontSize: 12, color: 'var(--danger, #b42318)', marginTop: 12 }}>
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
                        <div style={{ fontSize: 12, color: 'var(--danger, #b42318)', marginTop: 12 }}>
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
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}>
                      {scimValidation.issues.map((issue, index) => (
                        <div key={`scim-issue-${index}`} className="stat-box" style={{ fontSize: 12 }}>
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
                            message: 'The account is removed and any active sessions are revoked. This cannot be undone.',
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
                <button className="btn btn-sm" disabled={!auditFiltersActive} onClick={clearAuditFilters}>
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
                            <span className={`badge ${entry.auth_used ? 'badge-ok' : 'badge-warn'}`}>
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
                      message: 'Alerts, audit events and metrics older than the retention window will be permanently deleted. This cannot be undone.',
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
                      rStats();
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
                    rStats();
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
                    message: 'The server process will terminate. You will need out-of-band access to restart it.',
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

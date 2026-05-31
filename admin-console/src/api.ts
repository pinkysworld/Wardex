// Wardex Admin Console — API Client
// Auth-aware fetch wrapper + all endpoint functions for 254 API routes.
//
// Per-slice TypeScript migration: the wrapper layer (request / get / post /
// put / del / toQuery) is fully typed; each endpoint export takes typed
// parameters and returns Promise<unknown> by default. Endpoints whose SDK
// types are known are typed explicitly via Promise<T>; other endpoints stay
// Promise<unknown> until their callers are converted to .tsx (callers in
// .jsx files are not type-checked, so this is intentionally permissive).

import type {
  AlertSeverityCounts,
  AuthSession,
  CommandLaneResponse,
  CommandSummaryResponse,
  CursorPageResponse,
  HealthLiveResponse,
  HealthReadyResponse,
  HealthStatus,
  LaunchpadEvidencePackResponse,
  OperationalSnapshotsResponse,
  ReleaseDoctorResponse,
} from '@wardex/sdk';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

export interface WardexRequestOptions {
  /** Abort signal owned by the calling hook or workflow. */
  signal?: AbortSignal | null;
  /** Optional timeout override in milliseconds. */
  timeoutMs?: number;
  /** Optional retry attempt override. */
  retries?: number;
}

/** Error thrown by `request()` for non-OK HTTP responses. */
export class WardexApiError extends Error {
  status?: number;
  body?: string;
  requestId?: string;
  constructor(message: string) {
    super(message);
    this.name = 'WardexApiError';
  }
}

let _token = '';
let _baseUrl = '';
let _pendingSignal: AbortSignal | null = null;
let _csrfToken = '';

const DEFAULT_TIMEOUT_MS = 15000;
const RETRYABLE_STATUS = new Set<number>([408, 429, 500, 502, 503, 504]);

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface RequestSignalHandle {
  signal: AbortSignal;
  cleanup: () => void;
}

function createRequestSignal(
  parentSignal: AbortSignal | null | undefined,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): RequestSignalHandle {
  const controller = new AbortController();
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  const abortFromParent = () => controller.abort(parentSignal?.reason);

  if (parentSignal?.aborted) {
    abortFromParent();
  } else if (parentSignal) {
    parentSignal.addEventListener('abort', abortFromParent, { once: true });
  }

  if (timeoutMs > 0) {
    timeoutId = setTimeout(() => {
      const timeoutError = new Error(`Request timed out after ${timeoutMs}ms`);
      timeoutError.name = 'TimeoutError';
      controller.abort(timeoutError);
    }, timeoutMs);
  }

  return {
    signal: controller.signal,
    cleanup() {
      if (timeoutId) clearTimeout(timeoutId);
      if (parentSignal) parentSignal.removeEventListener('abort', abortFromParent);
    },
  };
}

function parseApiErrorMessage(status: number, statusText: string, text: string): string {
  if (!text) return `${status} ${statusText || 'Request failed'}`.trim();
  try {
    const parsed = JSON.parse(text);
    return (
      parsed?.error?.message ||
      parsed?.error ||
      parsed?.message ||
      parsed?.detail ||
      `${status} ${statusText || 'Request failed'}`
    );
  } catch {
    return text || `${status} ${statusText || 'Request failed'}`.trim();
  }
}

function isRetryable(method: HttpMethod, statusOrError: unknown): boolean {
  if (method !== 'GET') return false;
  if (typeof statusOrError === 'number') return RETRYABLE_STATUS.has(statusOrError);
  if (statusOrError && typeof statusOrError === 'object') {
    const obj = statusOrError as { status?: unknown; name?: unknown };
    if (typeof obj.status === 'number') return RETRYABLE_STATUS.has(obj.status);
    // Preserves original heuristic: retry timeouts but not user-initiated aborts.
    return obj.name === 'TimeoutError' || obj.name !== 'AbortError';
  }
  // Preserve original behaviour for undefined/null/string error shapes.
  return true;
}

export function setToken(t: string): void {
  _token = t;
}
export function getToken(): string {
  return _token;
}
export function setCsrfToken(t: string): void {
  _csrfToken = t;
}
export function getCsrfToken(): string {
  return _csrfToken;
}
export function setBaseUrl(u: string): void {
  _baseUrl = u;
}

/**
 * Set a request-scoped AbortSignal. The signal is captured synchronously
 * by request() before the first await, then cleared. Safe for concurrent
 * useApi hooks because JS is single-threaded.
 */
export function withSignal<T>(signal: AbortSignal | null | undefined, fn: () => T): T {
  _pendingSignal = signal ?? null;
  const result = fn();
  _pendingSignal = null;
  return result;
}

async function request<T = unknown>(
  method: HttpMethod,
  path: string,
  body?: unknown,
  opts: WardexRequestOptions = {},
): Promise<T> {
  const signal = opts.signal ?? _pendingSignal;
  const headers: Record<string, string> = {};
  if (_token) headers['Authorization'] = 'Bearer ' + _token;
  if (!_token && _csrfToken && method !== 'GET') headers['X-Wardex-CSRF'] = _csrfToken;
  let payload: BodyInit | null = null;
  if (body && typeof body === 'object') {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  } else if (typeof body === 'string') {
    headers['Content-Type'] = 'application/json';
    payload = body;
  }
  const url = _baseUrl + path;
  const maxAttempts = Math.max(1, opts.retries ?? (method === 'GET' ? 2 : 1));

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const requestSignal = createRequestSignal(signal, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method,
        headers,
        body: payload,
        signal: requestSignal.signal,
        credentials: 'include',
      });
      const requestId = res.headers.get('x-request-id') || res.headers.get('X-Request-Id') || null;
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        if (attempt < maxAttempts && isRetryable(method, res.status)) {
          requestSignal.cleanup();
          await delay(100 * attempt);
          continue;
        }
        const err = new WardexApiError(parseApiErrorMessage(res.status, res.statusText, text));
        err.status = res.status;
        err.body = text;
        if (requestId) err.requestId = requestId;
        throw err;
      }
      const ct = res.headers.get('content-type') || '';
      if (ct.includes('json')) {
        const parsed = (await res.json()) as T;
        if (
          parsed &&
          typeof parsed === 'object' &&
          'csrf_token' in parsed &&
          typeof (parsed as { csrf_token?: unknown }).csrf_token === 'string'
        ) {
          _csrfToken = (parsed as { csrf_token: string }).csrf_token;
        }
        return parsed;
      }
      return (await res.text()) as unknown as T;
    } catch (err) {
      if (signal?.aborted) {
        throw signal.reason || err;
      }
      if (requestSignal.signal.aborted) {
        const reason = requestSignal.signal.reason || err;
        if (attempt < maxAttempts && isRetryable(method, reason)) {
          requestSignal.cleanup();
          await delay(100 * attempt);
          continue;
        }
        throw reason;
      }
      if (attempt < maxAttempts && isRetryable(method, err)) {
        requestSignal.cleanup();
        await delay(100 * attempt);
        continue;
      }
      throw err;
    } finally {
      requestSignal.cleanup();
    }
  }
  // Unreachable: every iteration either returns or throws. Defensive throw
  // keeps the return type honest if the loop is ever restructured.
  throw new WardexApiError('request: exhausted retry attempts without resolution');
}

function get<T = unknown>(path: string, opts?: WardexRequestOptions): Promise<T> {
  return request<T>('GET', path, null, opts);
}
function post<T = unknown>(path: string, body?: unknown, opts?: WardexRequestOptions): Promise<T> {
  return request<T>('POST', path, body, opts);
}
function put<T = unknown>(path: string, body?: unknown, opts?: WardexRequestOptions): Promise<T> {
  return request<T>('PUT', path, body, opts);
}
function del<T = unknown>(path: string, opts?: WardexRequestOptions): Promise<T> {
  return request<T>('DELETE', path, null, opts);
}

type QueryValue = string | number | boolean | null | undefined | unknown;

const toQuery = (params: Record<string, QueryValue> = {}): string => {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  return query.toString();
};

// ── Auth ─────────────────────────────────────────────────────
export const authCheck = () => get('/api/auth/check');
export const authRotate = () => post('/api/auth/rotate');
/** @returns {Promise<AuthSession>} */
export const authSession = (): Promise<AuthSession> => get<AuthSession>('/api/auth/session');
export const createAuthSession = () => post('/api/auth/session');
export const authLogout = () => post('/api/auth/logout');
export const authSsoConfig = () => get('/api/auth/sso/config');
export const assistantStatus = () => get('/api/assistant/status');
export const assistantQuery = (body: unknown) => post('/api/assistant/query', body);
export const sessionInfo = () => get('/api/session/info');
export const userPreferences = () => get('/api/user/preferences');
export const setUserPreferences = (body: unknown) => put('/api/user/preferences', body);

// ── Health & System ──────────────────────────────────────────
/** @returns {Promise<HealthStatus>} */
export const health = (): Promise<HealthStatus> => get<HealthStatus>('/api/health');
/** @returns {Promise<HealthLiveResponse>} */
export const healthLive = (): Promise<HealthLiveResponse> =>
  get<HealthLiveResponse>('/api/healthz/live');
/** @returns {Promise<HealthReadyResponse>} */
export const healthReady = (): Promise<HealthReadyResponse> =>
  get<HealthReadyResponse>('/api/healthz/ready');
export const status = () => get('/api/status');
export const report = () => get('/api/report');
export const hostInfo = () => get('/api/host/info');
export const platform = () => get('/api/platform');
export const threadsStatus = () => get('/api/threads/status');
export const endpoints = () => get('/api/endpoints');
export const openapi = () => get('/api/openapi.json');
export const metrics = () => get('/api/metrics');
export const sloStatus = () => get('/api/slo/status');
export const supportDiag = () => get('/api/support/diagnostics');
export const supportReadinessEvidence = () => get('/api/support/readiness-evidence');
export const supportBundle = () => get('/api/support/bundle');
export const firstRunProof = () => post('/api/support/first-run-proof');
export const failoverDrill = () => post('/api/control/failover-drill');
export const productionDemoLab = () => post('/api/demo/lab');
/** @returns {Promise<OperationalSnapshotsResponse>} */
export const operationalSnapshots = ({
  kind,
  limit,
}: { kind?: string; limit?: number } = {}): Promise<OperationalSnapshotsResponse> => {
  const query = new URLSearchParams();
  if (kind) query.set('kind', String(kind));
  if (limit) query.set('limit', String(limit));
  const suffix = query.toString();
  return get<OperationalSnapshotsResponse>(
    `/api/operational/snapshots${suffix ? `?${suffix}` : ''}`,
  );
};
export const operationalSnapshotPolicy = () => get('/api/operational/snapshots/policy');
export const pruneOperationalSnapshots = (body = { dry_run: true }) =>
  post('/api/operational/snapshots/prune', body);
export const verifyOperationalSnapshot = ({
  storageKey,
  digest,
}: { storageKey?: string; digest?: string } = {}) => {
  const query = new URLSearchParams();
  if (storageKey) query.set('storage_key', String(storageKey));
  if (digest) query.set('digest', String(digest));
  const suffix = query.toString();
  return get(`/api/operational/snapshots/verify${suffix ? `?${suffix}` : ''}`);
};
/** @returns {Promise<LaunchpadEvidencePackResponse>} */
export const launchpadEvidencePack = (): Promise<LaunchpadEvidencePackResponse> =>
  get<LaunchpadEvidencePackResponse>('/api/launchpad/evidence-pack');
export const launchpadReleaseDiff = () => get('/api/launchpad/release-diff');
export const launchpadDemoStatus = () => get('/api/launchpad/demo-status');
export const launchpadDemoReset = () => post('/api/launchpad/demo-reset');
/** @returns {Promise<ReleaseDoctorResponse>} */
export const releaseDoctor = (): Promise<ReleaseDoctorResponse> =>
  get<ReleaseDoctorResponse>('/api/release/doctor');
export const releaseObservabilityGates = () => get('/api/release/observability-gates');
export const releaseProvenance = () => get('/api/release/provenance');
export const releaseUpgradeRehearsal = ({ targetVersion }: { targetVersion?: string } = {}) => {
  const query = new URLSearchParams();
  if (targetVersion) query.set('target_version', String(targetVersion));
  const suffix = query.toString();
  return get(`/api/release/upgrade-rehearsal${suffix ? `?${suffix}` : ''}`);
};
export const cleanReleaseCut = () => get('/api/release/clean-cut');
export const containerReleaseParity = () => get('/api/containers/release-parity');
export const releaseVerificationCenter = () => get('/api/release/verification-center');
export const deploymentTrustReport = () => get('/api/release/deployment-trust-report');
export const selfHostedDeploymentWizard = () => get('/api/deployment/self-hosted-wizard');
export const dataQualityDashboard = () => get('/api/data-quality/dashboard');
export const performanceScaleBaseline = () => get('/api/performance/scale-baseline');
export const clusterFailoverExecution = () => get('/api/cluster/failover-execution');
export const secretsRotationOperations = () => get('/api/secrets/rotation-operations');
export const operatorTaskAutomation = () => get('/api/operator/task-automation');
export const detectionValidationPacks = () => get('/api/detection/validation-packs');
export const syntheticConsoleMonitor = () => get('/api/monitoring/synthetic-console');
export const incidentTimelineReplay = ({ incidentId }: { incidentId?: string } = {}) => {
  const query = new URLSearchParams();
  if (incidentId) query.set('incident_id', String(incidentId));
  const suffix = query.toString();
  return get(`/api/incidents/timeline-replay${suffix ? `?${suffix}` : ''}`);
};
export const detectionTrustScore = () => get('/api/detection/trust-score');
export const fleetDriftCompliance = () => get('/api/fleet/drift-compliance');
export const operatorWorkQueue = () => get('/api/operator/work-queue');
export const retentionForecast = () => get('/api/retention/forecast');
export const searchPerformanceSlo = () => get('/api/search/performance-slo');
export const adversarialValidation = () => get('/api/validation/adversarial');
export const supportBundleDiff = () => get('/api/support/bundle-diff');
export const workflowPreflight = ({ workflow }: { workflow?: string } = {}) => {
  const query = new URLSearchParams();
  if (workflow) query.set('workflow', String(workflow));
  const suffix = query.toString();
  return get(`/api/workflows/preflight${suffix ? `?${suffix}` : ''}`);
};
export const tenantIsolationProof = () => get('/api/tenants/isolation-proof');
export const threadDetectionProof = () => get('/api/processes/thread-proof');
export const sdkContractStatus = () => get('/api/sdk/contract-status');
export const supportParity = () => get('/api/support/parity');
export const docsIndex = ({
  q,
  section,
  limit,
}: { q?: string; section?: string; limit?: number } = {}) => {
  const query = new URLSearchParams();
  if (q) query.set('q', String(q));
  if (section) query.set('section', String(section));
  if (limit) query.set('limit', String(limit));
  const suffix = query.toString();
  return get(`/api/docs/index${suffix ? `?${suffix}` : ''}`);
};
export const docsContent = (path: string) =>
  get(`/api/docs/content?path=${encodeURIComponent(String(path || ''))}`);
export const systemDeps = () => get('/api/system/health/dependencies');
export const shutdown = () => post('/api/shutdown');

// ── Telemetry ────────────────────────────────────────────────
export const telemetryCurrent = () => get('/api/telemetry/current');
export const telemetryHistory = () => get('/api/telemetry/history');

// ── Alerts ───────────────────────────────────────────────────
export const alerts = () => get('/api/alerts');
/** @returns {Promise<CursorPageResponse>} */
export const alertsPage = ({
  cursor,
  limit,
}: { cursor?: string | number; limit?: number } = {}): Promise<CursorPageResponse> => {
  const query = new URLSearchParams();
  if (cursor !== undefined) query.set('cursor', String(cursor));
  if (limit) query.set('limit', String(limit));
  const suffix = query.toString();
  return get<CursorPageResponse>(`/api/alerts/page${suffix ? `?${suffix}` : ''}`);
};
/** @returns {Promise<AlertSeverityCounts>} */
export const alertsCount = (): Promise<AlertSeverityCounts> =>
  get<AlertSeverityCounts>('/api/alerts/count');
export const alertById = (id: string) => get(`/api/alerts/${encodeURIComponent(id)}`);
export const alertsGrouped = () => get('/api/alerts/grouped');
export const alertHistogram = ({
  window = '24h',
  bucket = '1h',
  severity,
}: { window?: string; bucket?: string; severity?: string } = {}) => {
  const query = new URLSearchParams();
  if (window) query.set('window', String(window));
  if (bucket) query.set('bucket', String(bucket));
  if (severity) query.set('severity', String(severity));
  const suffix = query.toString();
  return get(`/api/alerts/histogram${suffix ? `?${suffix}` : ''}`);
};
export const alertsAnalysisLatest = () => get('/api/alerts/analysis');
export const alertsAnalysis = (body: unknown) => post('/api/alerts/analysis', body);
export const alertsSample = (body: unknown) => post('/api/alerts/sample', body);
export const alertsClear = () => del('/api/alerts');
export const operatorWorkspaces = () => get('/api/operator/workspaces');
export const alertFeedback = (body: unknown) => post('/api/alerts/feedback', body);
export const alertFeedbackSummary = () => get('/api/alerts/feedback/summary');
export const alertEvidenceChain = ({ alertId }: { alertId?: string } = {}) => {
  const query = new URLSearchParams();
  if (alertId !== undefined && alertId !== null && alertId !== '') {
    query.set('alert_id', String(alertId));
  }
  const suffix = query.toString();
  return get(`/api/alerts/evidence-chain${suffix ? `?${suffix}` : ''}`);
};
export const detectionLabStatus = () => get('/api/detection-lab/status');
export const detectionLabHistory = () => get('/api/detection-lab/history');
export const detectionLabReport = () => get('/api/detection-lab/report');
export const runDetectionLab = (body = { mode: 'replay' }) => post('/api/detection-lab/runs', body);
export const responseSafety = () => get('/api/response/safety');
export const responsePreview = (body: unknown) => post('/api/response/preview', body);
export const responseVerify = (body: unknown) => post('/api/response/verify', body);
export const integrationsMarketplace = () => get('/api/integrations/marketplace');
export const validateIntegration = (body: unknown) => post('/api/integrations/validate', body);
export const integrationSampleEvent = ({ provider }: { provider?: string } = {}) => {
  const query = new URLSearchParams();
  if (provider) query.set('provider', String(provider));
  const suffix = query.toString();
  return get(`/api/integrations/sample-event${suffix ? `?${suffix}` : ''}`);
};
export const operationsHealth = () => get('/api/operations/health');
export const operationsHealthSnapshot = () => get('/api/operations/health/snapshot');
export const malwareExplain = () => get('/api/malware/explain');
export const malwareScanDiff = () => get('/api/malware/scan-diff');

// ── Detection ────────────────────────────────────────────────
export const analyze = (body: unknown) => post('/api/analyze', body);
export const controlMode = (body: unknown) => post('/api/control/mode', body);
export const runDemo = () => post('/api/control/run-demo');
export const resetBaseline = () => post('/api/control/reset-baseline');
export const checkpoint = () => post('/api/control/checkpoint');
export const restoreCheckpoint = (body: unknown) => post('/api/control/restore-checkpoint', body);
/** @returns {Promise<CommandSummaryResponse>} */
export const commandSummary = (): Promise<CommandSummaryResponse> =>
  get<CommandSummaryResponse>('/api/command/summary');
/**
 * @param {string} lane
 * @returns {Promise<CommandLaneResponse>}
 */
export const commandLane = (lane: string): Promise<CommandLaneResponse> =>
  get<CommandLaneResponse>(`/api/command/lanes/${encodeURIComponent(lane)}`);
export const checkpoints = () => get('/api/checkpoints');
export const detectionProfile = () => get('/api/detection/profile');
export const setDetectionProfile = (body: unknown) => put('/api/detection/profile', body);
export const detectionSummary = () => get('/api/detection/summary');
export const detectionRecommendations = (limit = 10) =>
  get(`/api/detection/recommendations?limit=${encodeURIComponent(String(limit))}`);
export const detectionReadiness = (limit: number = 20) =>
  get(`/api/detection/readiness?limit=${encodeURIComponent(String(limit))}`);
export const detectionTrustOverview = () => get('/api/detection/trust/overview');
export const detectionTrustRules = () => get('/api/detection/trust/rules');
export const detectionTrustRule = (id: string) =>
  get(`/api/detection/trust/rules/${encodeURIComponent(id)}`);
export const detectionTrustTuningDrafts = () => get('/api/detection/trust/tuning-drafts');
export const createDetectionTrustTuningDraft = (body: unknown) =>
  post('/api/detection/trust/tuning-drafts', body);
export const previewDetectionTrustTuningDraft = (id: string, body: unknown = {}) =>
  post(`/api/detection/trust/tuning-drafts/${encodeURIComponent(id)}/preview`, body);
export const approveDetectionTrustTuningDraft = (id: string, body: unknown = {}) =>
  post(`/api/detection/trust/tuning-drafts/${encodeURIComponent(id)}/approve`, body);
export const detectionReplayCorpus = () => get('/api/detection/replay-corpus');
export const evaluateDetectionReplayCorpus = (body: unknown) =>
  post('/api/detection/replay-corpus', body);
export const efficacyCanaryPromote = () => post('/api/efficacy/canary-promote');
export const detectionWeights = () => get('/api/detection/weights');
export const setDetectionWeights = (body: unknown) => post('/api/detection/weights', body);
export const normalizeScore = () => get('/api/detection/score/normalize');
export const fpFeedback = (body: unknown) => post('/api/fp-feedback', body);
export const fpFeedbackStats = () => get('/api/fp-feedback/stats');

// ── Sigma ────────────────────────────────────────────────────
export const sigmaRules = () => get('/api/sigma/rules');
export const sigmaStats = () => get('/api/sigma/stats');

// ── Threat Intelligence ──────────────────────────────────────
export const threatIntelStatus = () => get('/api/threat-intel/status');
export const threatIntelLibrary = () => get('/api/threat-intel/library');
export const threatIntelStats = () => get('/api/threat-intel/stats');
export const threatIntelIoc = (body: unknown) => post('/api/threat-intel/ioc', body);
export const threatIntelPurge = (body: unknown) => post('/api/threat-intel/purge', body);

// ── MITRE ATT&CK ─────────────────────────────────────────────
export const mitreCoverage = () => get('/api/mitre/coverage');
export const mitreHeatmap = () => get('/api/mitre/heatmap');
export const mitreCoverageAlt = () => get('/api/coverage/mitre');

// ── Fleet & Agents ───────────────────────────────────────────
export const fleetStatus = () => get('/api/fleet/status');
export const fleetHealth = () => get('/api/fleet/health');
export const fleetDashboard = () => get('/api/fleet/dashboard');
export const fleetInventory = () => get('/api/fleet/inventory');
export const fleetRegister = (body: unknown) => post('/api/fleet/register', body);
export const fleetInstalls = () => get('/api/fleet/installs');
export const fleetInstallSsh = (body: unknown) => post('/api/fleet/install/ssh', body);
export const fleetInstallWinrm = (body: unknown) => post('/api/fleet/install/winrm', body);
export const agents = () => get('/api/agents');
export const agentsEnroll = (body: unknown) => post('/api/agents/enroll', body);
export const agentsToken = (body: unknown) => post('/api/agents/token', body);
export const agentDetails = (id: string) => get(`/api/agents/${encodeURIComponent(id)}/details`);
export const agentActivity = (id: string) => get(`/api/agents/${encodeURIComponent(id)}/activity`);
export const agentStatus = (id: string) => get(`/api/agents/${encodeURIComponent(id)}/status`);
export const agentScope = (id: string) => get(`/api/agents/${encodeURIComponent(id)}/scope`);
export const setAgentScope = (id: string, body: unknown) =>
  post(`/api/agents/${encodeURIComponent(id)}/scope`, body);
export const agentLogs = (id: string) => get(`/api/agents/${encodeURIComponent(id)}/logs`);
export const agentInventory = (id: string) =>
  get(`/api/agents/${encodeURIComponent(id)}/inventory`);
export const localConsoleInventory = () => get('/api/agents/local-console/inventory');
export const deleteAgent = (id: string) => del(`/api/agents/${encodeURIComponent(id)}`);

// ── Events ───────────────────────────────────────────────────
export const events = () => get('/api/events');
export const eventsPage = ({
  cursor,
  limit,
  q,
  source,
  severity,
}: {
  cursor?: string | number;
  limit?: number;
  q?: string;
  source?: string;
  severity?: string;
} = {}) => {
  const query = new URLSearchParams();
  if (cursor !== undefined) query.set('cursor', String(cursor));
  if (limit) query.set('limit', String(limit));
  if (q) query.set('q', String(q));
  if (source) query.set('source', String(source));
  if (severity) query.set('severity', String(severity));
  const suffix = query.toString();
  return get(`/api/events/page${suffix ? `?${suffix}` : ''}`);
};
export const postEvents = (body: unknown) => post('/api/events', body);
export const eventsExport = () => get('/api/events/export');
export const eventsSummary = () => get('/api/events/summary');
export const bulkTriage = (body: unknown) => post('/api/events/bulk-triage', body);
export const triageEvent = (id: string, body: unknown) =>
  post(`/api/events/${encodeURIComponent(id)}/triage`, body);

// ── Incidents ────────────────────────────────────────────────
export const incidents = () => get('/api/incidents');
export const createIncident = (body: unknown) => post('/api/incidents', body);
export const incidentById = (id: string) => get(`/api/incidents/${encodeURIComponent(id)}`);
export const updateIncident = (id: string, body: unknown) =>
  post(`/api/incidents/${encodeURIComponent(id)}/update`, body);
export const incidentReport = (id: string) =>
  get(`/api/incidents/${encodeURIComponent(id)}/report`);
export const incidentStoryline = (id: string) =>
  get(`/api/incidents/${encodeURIComponent(id)}/storyline`);

// ── Cases ────────────────────────────────────────────────────
export const cases = () => get('/api/cases');
export const createCase = (body: unknown) => post('/api/cases', body);
export const casesStats = () => get('/api/cases/stats');
export const caseById = (id: string) => get(`/api/cases/${encodeURIComponent(id)}`);
export const caseHandoffPacket = (id: string) =>
  get(`/api/cases/${encodeURIComponent(id)}/handoff-packet`);
export const caseComment = (id: string, body: unknown) =>
  post(`/api/cases/${encodeURIComponent(id)}/comment`, body);
export const updateCase = (id: string, body: unknown) =>
  post(`/api/cases/${encodeURIComponent(id)}/update`, body);
export const closeCase = (id: string) => post(`/api/cases/${encodeURIComponent(id)}/close`);

// ── SOC Queue ────────────────────────────────────────────────
export const queueAlerts = () => get('/api/queue/alerts');
export const queueStats = () => get('/api/queue/stats');
export const queueAck = (body: unknown) => post('/api/queue/acknowledge', body);
export const queueAssign = (body: unknown) => post('/api/queue/assign', body);

// ── Response Actions ─────────────────────────────────────────
export const responseRequest = (body: unknown) => post('/api/response/request', body);
export const responseApprove = (body: unknown) => post('/api/response/approve', body);
export const responseExecute = (body: unknown) => post('/api/response/execute', body);
export const responsePending = () => get('/api/response/pending');
export const responseRequests = () => get('/api/response/requests');
export const responseAudit = () => get('/api/response/audit');
export const responseExecutionAudit = ({
  requestId,
  actionId,
}: { requestId?: string; actionId?: string } = {}) => {
  const query = new URLSearchParams();
  if (requestId) query.set('request_id', String(requestId));
  if (actionId) query.set('action_id', String(actionId));
  const suffix = query.toString();
  return get(`/api/response/execution-audit${suffix ? `?${suffix}` : ''}`);
};
export const responseStats = () => get('/api/response/stats');
export const responseApprovals = () => get('/api/response/approvals');
export const responseApprovalOverview = () => get('/api/response/approval-overview');
export const remediationSafety = () => get('/api/remediation/safety');

// ── Policy ───────────────────────────────────────────────────
export const policyCurrent = () => get('/api/policy/current');
export const policyHistory = () => get('/api/policy/history');
export const policyPublish = (body: unknown) => post('/api/policy/publish', body);
export const policyCompose = (body: unknown) => post('/api/policy/compose', body);
export const policyVmExecute = (body: unknown) => post('/api/policy-vm/execute', body);

// ── Updates / Rollout ────────────────────────────────────────
export const updatesPublish = (body: unknown) => post('/api/updates/publish', body);
export const updatesDeploy = (body: unknown) => post('/api/updates/deploy', body);
export const updatesRollback = (body: unknown) => post('/api/updates/rollback', body);
export const updatesCancel = () => post('/api/updates/cancel');
export const updatesReleases = () => get('/api/updates/releases');
export const rolloutConfig = () => get('/api/rollout/config');

// ── Config ───────────────────────────────────────────────────
export const configCurrent = () => get('/api/config/current');
export const configReload = () => post('/api/config/reload');
export const configSave = (body: unknown) => post('/api/config/save', body);

// ── Enforcement ──────────────────────────────────────────────
export const enforcementStatus = () => get('/api/enforcement/status');
export const quarantine = (body: unknown) => post('/api/enforcement/quarantine', body);

// ── Deception ────────────────────────────────────────────────
export const deceptionStatus = () => get('/api/deception/status');
export const deceptionDeploy = (body: unknown) => post('/api/deception/deploy', body);

// ── Infrastructure ───────────────────────────────────────────
export const monitorStatus = () => get('/api/monitor/status');
export const monitorViolations = () => get('/api/monitor/violations');
export const correlation = () => get('/api/correlation');
export const driftStatus = () => get('/api/drift/status');
export const driftReset = () => post('/api/drift/reset');
export const fingerprintStatus = () => get('/api/fingerprint/status');
export const causalGraph = () => get('/api/causal/graph');
export const sideChannelStatus = () => get('/api/side-channel/status');
export const digitalTwinStatus = () => get('/api/digital-twin/status');
export const digitalTwinSimulate = (body: unknown) => post('/api/digital-twin/simulate', body);
export const harnessRun = (body: unknown) => post('/api/harness/run', body);
export const swarmPosture = () => get('/api/swarm/posture');
export const swarmIntel = () => get('/api/swarm/intel');
export const swarmIntelStats = () => get('/api/swarm/intel/stats');
export const tlsStatus = () => get('/api/tls/status');
export const meshHealth = () => get('/api/mesh/health');
export const meshHeal = () => post('/api/mesh/heal');
export const remediationPlan = (body: unknown) => post('/api/remediation/plan', body);
export const remediationResults = () => get('/api/remediation/results');
export const remediationStats = () => get('/api/remediation/stats');
export const remediationChangeReviews = () => get('/api/remediation/change-reviews');
export const recordRemediationChangeReview = (body: unknown) =>
  post('/api/remediation/change-reviews', body);
export const approveRemediationChangeReview = (id: string, body: unknown) =>
  post(`/api/remediation/change-reviews/${encodeURIComponent(id)}/approval`, body);
export const executeRemediationRollback = (id: string, body: unknown) =>
  post(`/api/remediation/change-reviews/${encodeURIComponent(id)}/rollback`, body);

// ── Energy & Edge ────────────────────────────────────────────
export const energyStatus = () => get('/api/energy/status');
export const energyConsume = (body: unknown) => post('/api/energy/consume', body);
export const energyHarvest = (body: unknown) => post('/api/energy/harvest', body);
export const offloadDecide = (body: unknown) => post('/api/offload/decide', body);
export const patches = () => get('/api/patches');
export const tenantsCount = () => get('/api/tenants/count');

// ── Compliance & Crypto ──────────────────────────────────────
export const complianceStatus = () => get('/api/compliance/status');
export const attestationStatus = () => get('/api/attestation/status');
export const privacyBudget = () => get('/api/privacy/budget');
export const quantumKeyStatus = () => get('/api/quantum/key-status');
export const quantumRotate = () => post('/api/quantum/rotate');

// ── Audit & Retention ────────────────────────────────────────
const buildAuditLogQuery = ({
  limit,
  offset,
  q,
  method,
  status,
  auth,
}: {
  limit?: number;
  offset?: number;
  q?: string;
  method?: string;
  status?: string | number;
  auth?: string;
} = {}) => {
  const query = new URLSearchParams();
  if (limit != null) query.set('limit', String(limit));
  if (offset != null) query.set('offset', String(offset));
  if (q) query.set('q', String(q));
  if (method) query.set('method', String(method));
  if (status) query.set('status', String(status));
  if (auth) query.set('auth', String(auth));
  return query.toString();
};

export const auditLog = ({
  limit = 50,
  offset = 0,
  q,
  method,
  status,
  auth,
}: {
  limit?: number;
  offset?: number;
  q?: string;
  method?: string;
  status?: string | number;
  auth?: string;
} = {}) => {
  const suffix = buildAuditLogQuery({ limit, offset, q, method, status, auth });
  return get(`/api/audit/log${suffix ? `?${suffix}` : ''}`);
};
export const auditLogPage = ({
  cursor = 0,
  limit = 50,
  q,
  method,
  status,
  auth,
}: {
  cursor?: string | number;
  limit?: number;
  q?: string;
  method?: string;
  status?: string | number;
  auth?: string;
} = {}) => {
  const suffix = buildAuditLogQuery({ limit, q, method, status, auth });
  const query = new URLSearchParams(suffix);
  query.set('cursor', String(cursor));
  const serialized = query.toString();
  return get(`/api/audit/log/page${serialized ? `?${serialized}` : ''}`);
};
export const auditLogExport = ({
  q,
  method,
  status,
  auth,
}: { q?: string; method?: string; status?: string | number; auth?: string } = {}) => {
  const suffix = buildAuditLogQuery({ q, method, status, auth });
  return get(`/api/audit/log/export${suffix ? `?${suffix}` : ''}`);
};
export const auditVerify = () => get('/api/audit/verify');
export const auditAdmin = () => get('/api/audit/admin');
export const retentionStatus = () => get('/api/retention/status');
export const retentionApply = (body: unknown) => post('/api/retention/apply', body);
export const historicalStorageEvents = (params: Record<string, unknown> = {}) => {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value != null && value !== '') query.set(key, String(value));
  });
  const suffix = query.toString();
  return get(`/api/storage/events/historical${suffix ? `?${suffix}` : ''}`);
};
export const collectorsStatus = () => get('/api/collectors/status');
export const collectorsAws = () => get('/api/collectors/aws');
export const saveAwsCollectorConfig = (body: unknown) => post('/api/collectors/aws/config', body);
export const validateAwsCollector = () => post('/api/collectors/aws/validate', {});
export const collectorsAzure = () => get('/api/collectors/azure');
export const saveAzureCollectorConfig = (body: unknown) =>
  post('/api/collectors/azure/config', body);
export const validateAzureCollector = () => post('/api/collectors/azure/validate', {});
export const collectorsGcp = () => get('/api/collectors/gcp');
export const saveGcpCollectorConfig = (body: unknown) => post('/api/collectors/gcp/config', body);
export const validateGcpCollector = () => post('/api/collectors/gcp/validate', {});
export const collectorsOkta = () => get('/api/collectors/okta');
export const saveOktaCollectorConfig = (body: unknown) => post('/api/collectors/okta/config', body);
export const validateOktaCollector = () => post('/api/collectors/okta/validate', {});
export const collectorsEntra = () => get('/api/collectors/entra');
export const saveEntraCollectorConfig = (body: unknown) =>
  post('/api/collectors/entra/config', body);
export const validateEntraCollector = () => post('/api/collectors/entra/validate', {});
export const collectorsM365 = () => get('/api/collectors/m365');
export const saveM365CollectorConfig = (body: unknown) => post('/api/collectors/m365/config', body);
export const validateM365Collector = () => post('/api/collectors/m365/validate', {});
export const collectorsWorkspace = () => get('/api/collectors/workspace');
export const saveWorkspaceCollectorConfig = (body: unknown) =>
  post('/api/collectors/workspace/config', body);
export const validateWorkspaceCollector = () => post('/api/collectors/workspace/validate', {});
export const collectorsGithub = () => get('/api/collectors/github');
export const saveGithubCollectorConfig = (body: unknown) =>
  post('/api/collectors/github/config', body);
export const validateGithubCollector = () => post('/api/collectors/github/validate', {});
export const collectorsCrowdStrike = () => get('/api/collectors/crowdstrike');
export const saveCrowdStrikeCollectorConfig = (body: unknown) =>
  post('/api/collectors/crowdstrike/config', body);
export const validateCrowdStrikeCollector = () => post('/api/collectors/crowdstrike/validate', {});
export const collectorsSyslog = () => get('/api/collectors/syslog');
export const saveSyslogCollectorConfig = (body: unknown) =>
  post('/api/collectors/syslog/config', body);
export const validateSyslogCollector = () => post('/api/collectors/syslog/validate', {});
export const secretsStatus = () => get('/api/secrets/status');
export const saveSecretsConfig = (body: unknown) => post('/api/secrets/config', body);
export const validateSecretReference = (body: unknown) => post('/api/secrets/validate', body);

// ── Reports ──────────────────────────────────────────────────
export const reports = ({
  caseId,
  incidentId,
  investigationId,
  source,
  scope,
}: {
  caseId?: string;
  incidentId?: string;
  investigationId?: string;
  source?: string;
  scope?: string;
} = {}) => {
  const query = new URLSearchParams();
  if (caseId) query.set('case_id', String(caseId));
  if (incidentId) query.set('incident_id', String(incidentId));
  if (investigationId) query.set('investigation_id', String(investigationId));
  if (source) query.set('source', String(source));
  if (scope) query.set('scope', String(scope));
  const suffix = query.toString();
  return get(`/api/reports${suffix ? `?${suffix}` : ''}`);
};
export const executiveSummary = () => get('/api/reports/executive-summary');
export const reportById = (id: string) => get(`/api/reports/${encodeURIComponent(id)}`);
export const annotateReportContext = (id: string, body: unknown) =>
  post(`/api/reports/${encodeURIComponent(id)}/context`, body);
export const deleteReport = (id: string) => del(`/api/reports/${encodeURIComponent(id)}`);
export const reportTemplates = ({
  caseId,
  incidentId,
  investigationId,
  source,
  scope,
}: {
  caseId?: string;
  incidentId?: string;
  investigationId?: string;
  source?: string;
  scope?: string;
} = {}) => {
  const query = new URLSearchParams();
  if (caseId) query.set('case_id', String(caseId));
  if (incidentId) query.set('incident_id', String(incidentId));
  if (investigationId) query.set('investigation_id', String(investigationId));
  if (source) query.set('source', String(source));
  if (scope) query.set('scope', String(scope));
  const suffix = query.toString();
  return get(`/api/report-templates${suffix ? `?${suffix}` : ''}`);
};
export const saveReportTemplate = (body: unknown) => post('/api/report-templates', body);
export const reportRuns = ({
  caseId,
  incidentId,
  investigationId,
  source,
  scope,
}: {
  caseId?: string;
  incidentId?: string;
  investigationId?: string;
  source?: string;
  scope?: string;
} = {}) => {
  const query = new URLSearchParams();
  if (caseId) query.set('case_id', String(caseId));
  if (incidentId) query.set('incident_id', String(incidentId));
  if (investigationId) query.set('investigation_id', String(investigationId));
  if (source) query.set('source', String(source));
  if (scope) query.set('scope', String(scope));
  const suffix = query.toString();
  return get(`/api/report-runs${suffix ? `?${suffix}` : ''}`);
};
export const createReportRun = (body: unknown) => post('/api/report-runs', body);
export const reportSchedules = ({
  caseId,
  incidentId,
  investigationId,
  source,
  scope,
}: {
  caseId?: string;
  incidentId?: string;
  investigationId?: string;
  source?: string;
  scope?: string;
} = {}) => {
  const query = new URLSearchParams();
  if (caseId) query.set('case_id', String(caseId));
  if (incidentId) query.set('incident_id', String(incidentId));
  if (investigationId) query.set('investigation_id', String(investigationId));
  if (source) query.set('source', String(source));
  if (scope) query.set('scope', String(scope));
  const suffix = query.toString();
  return get(`/api/report-schedules${suffix ? `?${suffix}` : ''}`);
};
export const saveReportSchedule = (body: unknown) => post('/api/report-schedules', body);
export const inbox = () => get('/api/inbox');
export const ackInbox = (body: unknown) => post('/api/inbox/ack', body);

// ── Export ───────────────────────────────────────────────────
export const exportTla = () => get('/api/export/tla');
export const exportAlloy = () => get('/api/export/alloy');
export const exportWitnesses = () => get('/api/export/witnesses');

// ── Hunts & Content ──────────────────────────────────────────
export const hunts = () => get('/api/hunts');
export const createHunt = (body: unknown) => post('/api/hunts', body);
export const huntById = (id: string) => get(`/api/hunts/${encodeURIComponent(id)}`);
export const runHunt = (id: string, body: unknown = {}) =>
  post(`/api/hunts/${encodeURIComponent(id)}/run`, body);
export const escalateHunt = (id: string, body: unknown = {}) =>
  post(`/api/hunts/${encodeURIComponent(id)}/escalate`, body);
export const contentRules = () => get('/api/content/rules');
export const createContentRule = (body: unknown) => post('/api/content/rules', body);
export const contentRuleLifecycle = (id: string, body: unknown) =>
  post(`/api/content/rules/${encodeURIComponent(id)}/lifecycle`, body);
export const contentRuleTest = (id: string, body: unknown = {}) =>
  post(`/api/content/rules/${encodeURIComponent(id)}/test`, body);
export const contentRulePreflight = (id: string, body: unknown = {}) =>
  post(`/api/content/rules/${encodeURIComponent(id)}/preflight`, body);
export const contentRulePromote = (id: string, body: unknown) =>
  post(`/api/content/rules/${encodeURIComponent(id)}/promote`, body);
export const contentRuleRollback = (id: string) =>
  post(`/api/content/rules/${encodeURIComponent(id)}/rollback`, {});
export const contentPacks = () => get('/api/content/packs');
export const createContentPack = (body: unknown) => post('/api/content/packs', body);
export const suppressions = () => get('/api/suppressions');
export const createSuppression = (body: unknown) => post('/api/suppressions', body);
export const deleteSuppression = (id: string) => del(`/api/suppressions/${encodeURIComponent(id)}`);

// ── Escalation ───────────────────────────────────────────────
export const escalationPolicies = () => get('/api/escalation/policies');
export const createEscalationPolicy = (body: unknown) => post('/api/escalation/policies', body);
export const escalationStart = (body: unknown) => post('/api/escalation/start', body);
export const escalationActive = () => get('/api/escalation/active');
export const escalationAck = (body: unknown) => post('/api/escalation/acknowledge', body);

// ── Integrations ─────────────────────────────────────────────
export const siemStatus = () => get('/api/siem/status');
export const siemConfig = () => get('/api/siem/config');
export const setSiemConfig = (body: unknown) => post('/api/siem/config', body);
export const validateSiemConfig = (body: unknown) => post('/api/siem/validate', body);
export const taxiiStatus = () => get('/api/taxii/status');
export const taxiiConfig = () => get('/api/taxii/config');
export const setTaxiiConfig = (body: unknown) => post('/api/taxii/config', body);
export const taxiiPull = () => post('/api/taxii/pull');
export const enrichmentConnectors = () => get('/api/enrichments/connectors');
export const createEnrichmentConnector = (body: unknown) =>
  post('/api/enrichments/connectors', body);
export const ticketsSync = (body: unknown) => post('/api/tickets/sync', body);
export const idpProviders = () => get('/api/idp/providers');
export const createIdpProvider = (body: unknown) => post('/api/idp/providers', body);
export const scimConfig = () => get('/api/scim/config');
export const setScimConfig = (body: unknown) => post('/api/scim/config', body);

// ── RBAC ─────────────────────────────────────────────────────
export const rbacUsers = () => get('/api/rbac/users');
export const rbacCoverage = () => get('/api/admin/rbac-coverage');
export const createRbacUser = (body: unknown) => post('/api/rbac/users', body);
export const deleteRbacUser = (u: string) => del(`/api/rbac/users/${encodeURIComponent(u)}`);

// ── UEBA & Entity ────────────────────────────────────────────
export const uebaEntity = (id: string) => get(`/api/ueba/entity/${encodeURIComponent(id)}`);
export const uebaRiskyEntities = (minRisk = 10) => get(`/api/ueba/risky?min_risk=${minRisk}`);
export const entityById = (id: string) => get(`/api/entities/${encodeURIComponent(id)}`);

// ── Process Tree ─────────────────────────────────────────────
export const processTree = () => get('/api/process-tree');
export const deepChains = () => get('/api/process-tree/deep-chains');
export const processesLive = () => get('/api/processes/live');
export const processesAnalysis = () => get('/api/processes/analysis');
export const processDetail = (pid: string | number) =>
  get(`/api/processes/detail?pid=${encodeURIComponent(pid)}`);
export const processThreads = (pid: string | number) =>
  get(`/api/processes/threads?pid=${encodeURIComponent(pid)}`);

// ── Host Info & Inventory ────────────────────────────────────
export const hostApps = () => get('/api/host/apps');
export const hostInventory = () => get('/api/host/inventory');

// ── Timelines ────────────────────────────────────────────────
export const timelineHost = (hostname: string) => {
  const value = String(hostname || '').trim();
  if (!value) return Promise.resolve({ timeline: [], host: '', count: 0 });
  return get(`/api/timeline/host?hostname=${encodeURIComponent(value)}`);
};
export const timelineAgent = (agentId: string) => {
  const value = String(agentId || '').trim();
  if (!value) return Promise.resolve({ timeline: [], agent_id: '', count: 0 });
  return get(`/api/timeline/agent?agent_id=${encodeURIComponent(value)}`);
};
export const timelineById = (id: string) => get(`/api/timeline/${encodeURIComponent(id)}`);

// ── Other ────────────────────────────────────────────────────
export const graphql = (body: unknown) => post('/api/graphql', body);
export const researchTracks = () => get('/api/research-tracks');
export const monitoringOptions = () => get('/api/monitoring/options');
export const monitoringPaths = () => get('/api/monitoring/paths');
export const featureFlags = () => get('/api/feature-flags');
export const ocsfSchema = () => get('/api/ocsf/schema');
export const ocsfSchemaVersion = () => get('/api/ocsf/schema/version');
export const workbenchOverview = () => get('/api/workbench/overview');
export const managerOverview = () => get('/api/manager/overview');
export const managerQueueDigest = () => get('/api/manager/queue-digest');
export const onboardingReadiness = () => get('/api/onboarding/readiness');
export const gdprForget = (entity: string) => del(`/api/gdpr/forget/${encodeURIComponent(entity)}`);
export const adminBackup = () => post('/api/admin/backup');
export const adminDbVersion = () => get('/api/admin/db/version');
export const adminDbRollback = () => post('/api/admin/db/rollback');
export const adminDbCompact = () => post('/api/admin/db/compact');
export const adminDbReset = (body: unknown) => post('/api/admin/db/reset', body);
export const adminDbSizes = () => get('/api/admin/db/sizes');
export const adminCleanupLegacy = () => post('/api/admin/cleanup-legacy');
export const adminDbPurge = (body: unknown) => post('/api/admin/db/purge', body);
export const storageStats = () => get('/api/storage/stats');
export const spoolStats = () => get('/api/spool/stats');
export const sbom = () => get('/api/sbom');
export const piiScan = (body: unknown) => post('/api/pii/scan', body);
export const dlq = () => get('/api/dlq');
export const dlqStats = () => get('/api/dlq/stats');
export const dlqClear = () => del('/api/dlq');

// ── ML Engine ────────────────────────────────────────────────
export const mlModels = () => get('/api/ml/models');
export const mlModelsStatus = () => get('/api/ml/models/status');
export const mlModelsRollback = () => post('/api/ml/models/rollback');
export const mlShadowRecent = (limit: number = 20) =>
  get(`/api/ml/shadow/recent?limit=${encodeURIComponent(limit)}`);
export const mlPredict = (body: unknown) => post('/api/ml/predict', body);
export const mlTriage = (body: unknown) => post('/api/ml/triage', body);
export const mlTriageV2 = (body: unknown) => post('/api/ml/triage/v2', body);

// ── Vulnerability Scanner ────────────────────────────────────
export const vulnerabilityScan = () => get('/api/vulnerability/scan');
export const vulnerabilitySummary = () => get('/api/vulnerability/summary');

// ── NDR Engine ───────────────────────────────────────────────
export const ndrNetflow = (body: unknown) => post('/api/ndr/netflow', body);
export const ndrReport = () => get('/api/ndr/report');
export const ndrTlsAnomalies = () => get('/api/ndr/tls-anomalies');
export const ndrDpiAnomalies = () => get('/api/ndr/dpi-anomalies');
export const ndrEntropyAnomalies = () => get('/api/ndr/entropy-anomalies');
export const ndrBeaconing = () => get('/api/ndr/beaconing');
export const ndrSelfSignedCerts = () => get('/api/ndr/self-signed-certs');
export const ndrTopTalkers = () => get('/api/ndr/top-talkers');
export const ndrProtocolDistribution = () => get('/api/ndr/protocol-distribution');

// ── Email Security ───────────────────────────────────────────
export const emailQuarantine = () => get('/api/email/quarantine');
export const emailQuarantineRelease = (id: string) =>
  post(`/api/email/quarantine/${encodeURIComponent(id)}/release`);
export const emailQuarantineDelete = (id: string) =>
  del(`/api/email/quarantine/${encodeURIComponent(id)}`);
export const emailStats = () => get('/api/email/stats');
export const emailPolicies = () => get('/api/email/policies');
export const emailPolicyUpdate = (body: unknown) => put('/api/email/policies', body);

// ── Container Detection ──────────────────────────────────────
export const containerEvent = (body: unknown) => post('/api/container/event', body);
export const containerAlerts = () => get('/api/container/alerts');
export const containerStats = () => get('/api/container/stats');

// ── Certificate Monitor ──────────────────────────────────────
export const certsRegister = (body: unknown) => post('/api/certs/register', body);
export const certsSummary = () => get('/api/certs/summary');
export const certsAlerts = () => get('/api/certs/alerts');

// ── Config Drift Detection ───────────────────────────────────
export const configDriftCheck = (body: unknown) => post('/api/config-drift/check', body);
export const configDriftBaselines = () => get('/api/config-drift/baselines');

// ── Asset Inventory ──────────────────────────────────────────
export const assets = () => get('/api/assets');
export const assetsSummary = () => get('/api/assets/summary');
export const assetsUpsert = (body: unknown) => post('/api/assets/upsert', body);
export const assetsSearch = (q: string) => get(`/api/assets/search?q=${encodeURIComponent(q)}`);

// ── Detection Efficacy ───────────────────────────────────────
export const efficacyTriage = (body: unknown) => post('/api/efficacy/triage', body);
export const efficacySummary = () => get('/api/efficacy/summary');
export const efficacyRule = (id: string) => get(`/api/efficacy/rule/${encodeURIComponent(id)}`);

// ── Investigation Workflows ──────────────────────────────────
export const investigationWorkflows = () => get('/api/investigations/workflows');
export const investigationGraph = (body: unknown) => post('/api/investigation/graph', body);
export const investigationWorkflow = (id: string) =>
  get(`/api/investigations/workflows/${encodeURIComponent(id)}`);
export const investigationStart = (body: unknown) => post('/api/investigations/start', body);
export const investigationActive = () => get('/api/investigations/active');
export const investigationProgress = (body: unknown) => post('/api/investigations/progress', body);
export const investigationHandoff = (body: unknown) => post('/api/investigations/handoff', body);
export const investigationSuggest = (body: unknown) => post('/api/investigations/suggest', body);
export const analystQuery = (body: unknown) => post('/api/events/search', body);

// ── Malware Detection / AV Scanning ──────────────────────────
export const scanBuffer = (body: unknown) => post('/api/scan/buffer', body);
export const scanBufferV2 = (body: unknown) => post('/api/scan/buffer/v2', body);
export const scanHash = (body: unknown) => post('/api/scan/hash', body);
export const malwareScanPath = (body: unknown) =>
  post('/api/malware/scan-path', body, { timeoutMs: 120000 });
export const rootkitScan = (body: unknown) =>
  post('/api/rootkit/scan', body, { timeoutMs: 120000 });
export const malwareStats = () => get('/api/malware/stats');
export const malwareRecent = () => get('/api/malware/recent');
export const malwareSignaturePresets = () => get('/api/malware/signatures/presets');
export const malwareLoadLocalSignatures = () => post('/api/malware/signatures/load-local');
export const malwareImport = (body: unknown, source?: string) =>
  post(
    `/api/malware/signatures/import${source ? `?source=${encodeURIComponent(source)}` : ''}`,
    body,
  );
export const detectionExplain = (params: Record<string, unknown> = {}) =>
  get(`/api/detection/explain${toQuery(params) ? `?${toQuery(params)}` : ''}`);
export const detectionFeedback = (params: Record<string, unknown> = {}) =>
  get(`/api/detection/feedback${toQuery(params) ? `?${toQuery(params)}` : ''}`);
export const detectionTuningFeedback = () => get('/api/detection/tuning/feedback');
export const recordDetectionFeedback = (body: unknown) => post('/api/detection/feedback', body);
export const threatIntelLibraryV2 = () => get('/api/threat-intel/library/v2');
export const threatIntelSightings = (limit = 50) =>
  get(`/api/threat-intel/sightings?limit=${encodeURIComponent(limit)}`);

// ── Threat Hunting ───────────────────────────────────────────
export const hunt = (query: string) => post('/api/hunt', { query });

// ── SIEM Export ──────────────────────────────────────────────
export const exportAlerts = (fmt = 'json') =>
  get(`/api/export/alerts?format=${encodeURIComponent(fmt)}`);

// ── Compliance ───────────────────────────────────────────────
export const complianceReport = (framework: string) =>
  get(
    framework
      ? `/api/compliance/report?framework=${encodeURIComponent(framework)}`
      : '/api/compliance/report',
  );
export const complianceSummary = () => get('/api/compliance/summary');

// ── Playbook Run ─────────────────────────────────────────────
export const runPlaybook = (body: unknown) => post('/api/playbooks/run', body);
export const resumePlaybook = (body: unknown) => post('/api/playbooks/resume', body);

// ── Alert Deduplication ──────────────────────────────────────
export const dedupAlerts = () => get('/api/alerts/dedup');

// ── API Analytics ────────────────────────────────────────────
export const apiAnalytics = () => get('/api/analytics');

// ── OpenTelemetry Traces ─────────────────────────────────────
export const traces = () => get('/api/traces');

// ── Backup Encryption ────────────────────────────────────────
export const backupEncrypt = (body: unknown) => post('/api/backup/encrypt', body);
export const backupDecrypt = (body: unknown) => post('/api/backup/decrypt', body);

// ── Detection Rules ──────────────────────────────────────────
export const detectionRules = () => get('/api/detection/rules');
export const addDetectionRule = (body: unknown) => post('/api/detection/rules', body);

// ── Feed Ingestion ───────────────────────────────────────────
export const feeds = () => get('/api/feeds');
export const addFeed = (body: unknown) => post('/api/feeds', body);
export const removeFeed = (id: string) => del(`/api/feeds/${encodeURIComponent(id)}`);
export const pollFeed = (id: string, body: unknown) =>
  post(`/api/feeds/${encodeURIComponent(id)}/poll`, body);
export const feedStats = () => get('/api/feeds/stats');
export const hotReloadHashes = (body: unknown) => post('/api/feeds/hot-reload/hashes', body);

// ── Playbook DSL ─────────────────────────────────────────────
export const playbookDslList = () => get('/api/playbook-dsl');
export const playbookDslCreate = (body: unknown) => post('/api/playbook-dsl', body);
export const playbookDslGet = (id: string) => get(`/api/playbook-dsl/${encodeURIComponent(id)}`);
export const playbookDslDelete = (id: string) => del(`/api/playbook-dsl/${encodeURIComponent(id)}`);

// ── ATT&CK Coverage Gaps ────────────────────────────────────
export const coverageGaps = () => get('/api/coverage/gaps');

// ── Container Image Inventory ────────────────────────────────
export const images = () => get('/api/images');
export const imagesSummary = () => get('/api/images/summary');
export const imagesCollect = () => post('/api/images/collect');

// ── Quarantine Store ─────────────────────────────────────────
export const quarantineList = () => get('/api/quarantine');
export const quarantineAdd = (body: unknown) => post('/api/quarantine', body);
export const quarantineStats = () => get('/api/quarantine/stats');
export const quarantineRelease = (id: string) =>
  post(`/api/quarantine/${encodeURIComponent(id)}/release`);
export const quarantineDelete = (id: string) => del(`/api/quarantine/${encodeURIComponent(id)}`);

// ── Agent Lifecycle ──────────────────────────────────────────
export const lifecycle = () => get('/api/lifecycle');
export const lifecycleStats = () => get('/api/lifecycle/stats');
export const lifecycleSweep = () => post('/api/lifecycle/sweep');

// ── IoC Confidence Decay ─────────────────────────────────────
export const iocDecayApply = () => post('/api/ioc-decay/apply');
export const iocDecayPreview = () => get('/api/ioc-decay/preview');

// ── Host SBOM ────────────────────────────────────────────────
export const sbomHost = () => get('/api/sbom/host');

// ── Phase 29: Advanced Detection ─────────────────────────────
export const entropyAnalyze = (body: unknown) => post('/api/entropy/analyze', body);
export const dnsThreatAnalyze = (domain: string) => post('/api/dns-threat/analyze', { domain });
export const dnsThreatSummary = () => get('/api/dns-threat/summary');
export const dnsThreatRecord = (query: string) => post('/api/dns-threat/record', query);
export const processScoreAssess = (body: unknown) => post('/api/process-scoring/assess', body);
export const emailAnalyze = (body: unknown) => post('/api/email/analyze', body);
export const memoryIndicatorsScanMaps = (body: unknown) =>
  post('/api/memory-indicators/scan-maps', body);
export const memoryIndicatorsScanBuffer = (body: unknown) =>
  post('/api/memory-indicators/scan-buffer', body);

// ── Phase 29: WebSocket Alert Streaming ──────────────────────
export const wsConnect = () => post('/api/ws/connect');
export const wsDisconnect = (subscriberId: string) =>
  post('/api/ws/disconnect', { subscriber_id: subscriberId });
export const wsPoll = (subscriberId: string) =>
  post('/api/ws/poll', { subscriber_id: subscriberId });
export const wsStats = () => get('/api/ws/stats');
export const wsHealth = () => get('/api/ws/health');
export const streamReadiness = () => get('/api/stream/readiness');
export const streamReliabilityLab = () => get('/api/stream/reliability-lab');
export const createSubscription = (body = { lanes: ['alerts'], filters: {} }) =>
  post('/api/subscriptions', body);
export const resumeSubscription = ({
  subscriptionId,
  cursor,
  limit,
}: { subscriptionId?: string; cursor?: string | number; limit?: number } = {}) => {
  const query = new URLSearchParams();
  if (subscriptionId) query.set('subscription_id', String(subscriptionId));
  if (cursor !== undefined && cursor !== null) query.set('cursor', String(cursor));
  if (limit !== undefined && limit !== null) query.set('limit', String(limit));
  const suffix = query.toString();
  return get(`/api/subscriptions/resume${suffix ? `?${suffix}` : ''}`);
};
export const wsBroadcast = (data: unknown) => post('/api/ws/broadcast', data);

// ── v0.44.0: Enhanced Detection & UX ─────────────────────────
export const dedupStats = () => get('/api/alerts/dedup-stats');
export const noisyRules = () => get('/api/detection/noisy-rules');
export const playbooks = () => get('/api/playbooks');
export const playbookById = (id: string) => get(`/api/playbooks/${encodeURIComponent(id)}`);
export const playbookRun = (id: string) => post('/api/playbooks/run', { playbook_id: id });
export const playbookRecoveryActions = (executionId: string) =>
  get(`/api/playbook/execution/${encodeURIComponent(executionId)}/recovery-actions`);
export const canaryStatus = () => get('/api/canary/status');
export const insiderRisk = (entityKind: string, entityId: string) =>
  get(`/api/ueba/insider-risk/${encodeURIComponent(entityKind)}/${encodeURIComponent(entityId)}`);
export const credentialSprayAlerts = () => get('/api/correlation/credential-spray');
export const campaigns = () => get('/api/correlation/campaigns');
export const rbacCreateUser = (body: unknown) => post('/api/rbac/users', body);
export const rbacDeleteUser = (username: string) =>
  del(`/api/rbac/users/${encodeURIComponent(username)}`);

// Wardex Admin Console — API Client
// Auth-aware fetch wrapper + all endpoint functions for ~160 API routes.

let _token = '';
let _baseUrl = '';
let _pendingSignal = null;

/**
 * @typedef {Object} WardexRequestOptions
 * @property {AbortSignal=} signal Abort signal owned by the calling hook or workflow.
 */

/**
 * @typedef {Error & {status?: number, body?: string, requestId?: string}} WardexApiError
 */

export function setToken(t) {
  _token = t;
}
export function getToken() {
  return _token;
}
export function setBaseUrl(u) {
  _baseUrl = u;
}

/**
 * Set a request-scoped AbortSignal. The signal is captured synchronously
 * by request() before the first await, then cleared. Safe for concurrent
 * useApi hooks because JS is single-threaded.
 */
export function withSignal(signal, fn) {
  _pendingSignal = signal;
  const result = fn();
  _pendingSignal = null;
  return result;
}

/**
 * @param {'GET'|'POST'|'PUT'|'DELETE'} method
 * @param {string} path
 * @param {unknown=} body
 * @param {WardexRequestOptions=} opts
 * @returns {Promise<unknown>}
 * @throws {WardexApiError}
 */
async function request(method, path, body, opts = {}) {
  const signal = opts.signal || _pendingSignal;
  const headers = {};
  if (_token) headers['Authorization'] = 'Bearer ' + _token;
  if (body && typeof body === 'object') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  } else if (body && typeof body === 'string') {
    headers['Content-Type'] = 'application/json';
  }
  const url = _baseUrl + path;
  const res = await fetch(url, { method, headers, body, signal, credentials: 'include' });
  const requestId = res.headers.get('x-request-id') || res.headers.get('X-Request-Id') || null;
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    /** @type {WardexApiError} */
    const err = new Error(`${res.status} ${res.statusText}`);
    err.status = res.status;
    err.body = text;
    if (requestId) err.requestId = requestId;
    throw err;
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('json')) return res.json();
  return res.text();
}

const get = (p, o) => request('GET', p, null, o);
const post = (p, b, o) => request('POST', p, b, o);
const put = (p, b, o) => request('PUT', p, b, o);
const del = (p, o) => request('DELETE', p, null, o);
const toQuery = (params = {}) => {
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
export const authSession = () => get('/api/auth/session');
export const createAuthSession = () => post('/api/auth/session');
export const authLogout = () => post('/api/auth/logout');
export const authSsoConfig = () => get('/api/auth/sso/config');
export const assistantStatus = () => get('/api/assistant/status');
export const assistantQuery = (body) => post('/api/assistant/query', body);
export const sessionInfo = () => get('/api/session/info');
export const userPreferences = () => get('/api/user/preferences');
export const setUserPreferences = (body) => put('/api/user/preferences', body);

// ── Health & System ──────────────────────────────────────────
export const health = () => get('/api/health');
export const healthLive = () => get('/api/healthz/live');
export const healthReady = () => get('/api/healthz/ready');
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
export const firstRunProof = () => post('/api/support/first-run-proof');
export const failoverDrill = () => post('/api/control/failover-drill');
export const productionDemoLab = () => post('/api/demo/lab');
export const supportParity = () => get('/api/support/parity');
export const docsIndex = ({ q, section, limit } = {}) => {
  const query = new URLSearchParams();
  if (q) query.set('q', String(q));
  if (section) query.set('section', String(section));
  if (limit) query.set('limit', String(limit));
  const suffix = query.toString();
  return get(`/api/docs/index${suffix ? `?${suffix}` : ''}`);
};
export const docsContent = (path) =>
  get(`/api/docs/content?path=${encodeURIComponent(String(path || ''))}`);
export const systemDeps = () => get('/api/system/health/dependencies');
export const shutdown = () => post('/api/shutdown');

// ── Telemetry ────────────────────────────────────────────────
export const telemetryCurrent = () => get('/api/telemetry/current');
export const telemetryHistory = () => get('/api/telemetry/history');

// ── Alerts ───────────────────────────────────────────────────
export const alerts = () => get('/api/alerts');
export const alertsCount = () => get('/api/alerts/count');
export const alertById = (id) => get(`/api/alerts/${encodeURIComponent(id)}`);
export const alertsGrouped = () => get('/api/alerts/grouped');
export const alertsAnalysis = (body) => post('/api/alerts/analysis', body);
export const alertsSample = (body) => post('/api/alerts/sample', body);
export const alertsClear = () => del('/api/alerts');

// ── Detection ────────────────────────────────────────────────
export const analyze = (body) => post('/api/analyze', body);
export const controlMode = (body) => post('/api/control/mode', body);
export const runDemo = () => post('/api/control/run-demo');
export const resetBaseline = () => post('/api/control/reset-baseline');
export const checkpoint = () => post('/api/control/checkpoint');
export const restoreCheckpoint = (body) => post('/api/control/restore-checkpoint', body);
export const commandSummary = () => get('/api/command/summary');
export const commandLane = (lane) => get(`/api/command/lanes/${encodeURIComponent(lane)}`);
export const checkpoints = () => get('/api/checkpoints');
export const detectionProfile = () => get('/api/detection/profile');
export const setDetectionProfile = (body) => put('/api/detection/profile', body);
export const detectionSummary = () => get('/api/detection/summary');
export const detectionReplayCorpus = () => get('/api/detection/replay-corpus');
export const evaluateDetectionReplayCorpus = (body) => post('/api/detection/replay-corpus', body);
export const efficacyCanaryPromote = () => post('/api/efficacy/canary-promote');
export const detectionWeights = () => get('/api/detection/weights');
export const setDetectionWeights = (body) => post('/api/detection/weights', body);
export const normalizeScore = () => get('/api/detection/score/normalize');
export const fpFeedback = (body) => post('/api/fp-feedback', body);
export const fpFeedbackStats = () => get('/api/fp-feedback/stats');

// ── Sigma ────────────────────────────────────────────────────
export const sigmaRules = () => get('/api/sigma/rules');
export const sigmaStats = () => get('/api/sigma/stats');

// ── Threat Intelligence ──────────────────────────────────────
export const threatIntelStatus = () => get('/api/threat-intel/status');
export const threatIntelLibrary = () => get('/api/threat-intel/library');
export const threatIntelStats = () => get('/api/threat-intel/stats');
export const threatIntelIoc = (body) => post('/api/threat-intel/ioc', body);
export const threatIntelPurge = (body) => post('/api/threat-intel/purge', body);

// ── MITRE ATT&CK ─────────────────────────────────────────────
export const mitreCoverage = () => get('/api/mitre/coverage');
export const mitreHeatmap = () => get('/api/mitre/heatmap');
export const mitreCoverageAlt = () => get('/api/coverage/mitre');

// ── Fleet & Agents ───────────────────────────────────────────
export const fleetStatus = () => get('/api/fleet/status');
export const fleetHealth = () => get('/api/fleet/health');
export const fleetDashboard = () => get('/api/fleet/dashboard');
export const fleetInventory = () => get('/api/fleet/inventory');
export const fleetRegister = (body) => post('/api/fleet/register', body);
export const fleetInstalls = () => get('/api/fleet/installs');
export const fleetInstallSsh = (body) => post('/api/fleet/install/ssh', body);
export const fleetInstallWinrm = (body) => post('/api/fleet/install/winrm', body);
export const agents = () => get('/api/agents');
export const agentsEnroll = (body) => post('/api/agents/enroll', body);
export const agentsToken = (body) => post('/api/agents/token', body);
export const agentDetails = (id) => get(`/api/agents/${encodeURIComponent(id)}/details`);
export const agentActivity = (id) => get(`/api/agents/${encodeURIComponent(id)}/activity`);
export const agentStatus = (id) => get(`/api/agents/${encodeURIComponent(id)}/status`);
export const agentScope = (id) => get(`/api/agents/${encodeURIComponent(id)}/scope`);
export const setAgentScope = (id, body) =>
  post(`/api/agents/${encodeURIComponent(id)}/scope`, body);
export const agentLogs = (id) => get(`/api/agents/${encodeURIComponent(id)}/logs`);
export const agentInventory = (id) => get(`/api/agents/${encodeURIComponent(id)}/inventory`);
export const localConsoleInventory = () => get('/api/agents/local-console/inventory');
export const deleteAgent = (id) => del(`/api/agents/${encodeURIComponent(id)}`);

// ── Events ───────────────────────────────────────────────────
export const events = () => get('/api/events');
export const postEvents = (body) => post('/api/events', body);
export const eventsExport = () => get('/api/events/export');
export const eventsSummary = () => get('/api/events/summary');
export const bulkTriage = (body) => post('/api/events/bulk-triage', body);
export const triageEvent = (id, body) => post(`/api/events/${encodeURIComponent(id)}/triage`, body);

// ── Incidents ────────────────────────────────────────────────
export const incidents = () => get('/api/incidents');
export const createIncident = (body) => post('/api/incidents', body);
export const incidentById = (id) => get(`/api/incidents/${encodeURIComponent(id)}`);
export const updateIncident = (id, body) =>
  post(`/api/incidents/${encodeURIComponent(id)}/update`, body);
export const incidentReport = (id) => get(`/api/incidents/${encodeURIComponent(id)}/report`);
export const incidentStoryline = (id) => get(`/api/incidents/${encodeURIComponent(id)}/storyline`);

// ── Cases ────────────────────────────────────────────────────
export const cases = () => get('/api/cases');
export const createCase = (body) => post('/api/cases', body);
export const casesStats = () => get('/api/cases/stats');
export const caseById = (id) => get(`/api/cases/${encodeURIComponent(id)}`);
export const caseHandoffPacket = (id) => get(`/api/cases/${encodeURIComponent(id)}/handoff-packet`);
export const caseComment = (id, body) => post(`/api/cases/${encodeURIComponent(id)}/comment`, body);
export const updateCase = (id, body) => post(`/api/cases/${encodeURIComponent(id)}/update`, body);
export const closeCase = (id) => post(`/api/cases/${encodeURIComponent(id)}/close`);

// ── SOC Queue ────────────────────────────────────────────────
export const queueAlerts = () => get('/api/queue/alerts');
export const queueStats = () => get('/api/queue/stats');
export const queueAck = (body) => post('/api/queue/acknowledge', body);
export const queueAssign = (body) => post('/api/queue/assign', body);

// ── Response Actions ─────────────────────────────────────────
export const responseRequest = (body) => post('/api/response/request', body);
export const responseApprove = (body) => post('/api/response/approve', body);
export const responseExecute = (body) => post('/api/response/execute', body);
export const responsePending = () => get('/api/response/pending');
export const responseRequests = () => get('/api/response/requests');
export const responseAudit = () => get('/api/response/audit');
export const responseStats = () => get('/api/response/stats');
export const responseApprovals = () => get('/api/response/approvals');

// ── Policy ───────────────────────────────────────────────────
export const policyCurrent = () => get('/api/policy/current');
export const policyHistory = () => get('/api/policy/history');
export const policyPublish = (body) => post('/api/policy/publish', body);
export const policyCompose = (body) => post('/api/policy/compose', body);
export const policyVmExecute = (body) => post('/api/policy-vm/execute', body);

// ── Updates / Rollout ────────────────────────────────────────
export const updatesPublish = (body) => post('/api/updates/publish', body);
export const updatesDeploy = (body) => post('/api/updates/deploy', body);
export const updatesRollback = (body) => post('/api/updates/rollback', body);
export const updatesCancel = () => post('/api/updates/cancel');
export const updatesReleases = () => get('/api/updates/releases');
export const rolloutConfig = () => get('/api/rollout/config');

// ── Config ───────────────────────────────────────────────────
export const configCurrent = () => get('/api/config/current');
export const configReload = () => post('/api/config/reload');
export const configSave = (body) => post('/api/config/save', body);

// ── Enforcement ──────────────────────────────────────────────
export const enforcementStatus = () => get('/api/enforcement/status');
export const quarantine = (body) => post('/api/enforcement/quarantine', body);

// ── Deception ────────────────────────────────────────────────
export const deceptionStatus = () => get('/api/deception/status');
export const deceptionDeploy = (body) => post('/api/deception/deploy', body);

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
export const digitalTwinSimulate = (body) => post('/api/digital-twin/simulate', body);
export const harnessRun = (body) => post('/api/harness/run', body);
export const swarmPosture = () => get('/api/swarm/posture');
export const swarmIntel = () => get('/api/swarm/intel');
export const swarmIntelStats = () => get('/api/swarm/intel/stats');
export const tlsStatus = () => get('/api/tls/status');
export const meshHealth = () => get('/api/mesh/health');
export const meshHeal = () => post('/api/mesh/heal');
export const remediationPlan = (body) => post('/api/remediation/plan', body);
export const remediationResults = () => get('/api/remediation/results');
export const remediationStats = () => get('/api/remediation/stats');
export const remediationChangeReviews = () => get('/api/remediation/change-reviews');
export const recordRemediationChangeReview = (body) =>
  post('/api/remediation/change-reviews', body);
export const approveRemediationChangeReview = (id, body) =>
  post(`/api/remediation/change-reviews/${encodeURIComponent(id)}/approval`, body);
export const executeRemediationRollback = (id, body) =>
  post(`/api/remediation/change-reviews/${encodeURIComponent(id)}/rollback`, body);

// ── Energy & Edge ────────────────────────────────────────────
export const energyStatus = () => get('/api/energy/status');
export const energyConsume = (body) => post('/api/energy/consume', body);
export const energyHarvest = (body) => post('/api/energy/harvest', body);
export const offloadDecide = (body) => post('/api/offload/decide', body);
export const patches = () => get('/api/patches');
export const tenantsCount = () => get('/api/tenants/count');

// ── Compliance & Crypto ──────────────────────────────────────
export const complianceStatus = () => get('/api/compliance/status');
export const attestationStatus = () => get('/api/attestation/status');
export const privacyBudget = () => get('/api/privacy/budget');
export const quantumKeyStatus = () => get('/api/quantum/key-status');
export const quantumRotate = () => post('/api/quantum/rotate');

// ── Audit & Retention ────────────────────────────────────────
const buildAuditLogQuery = ({ limit, offset, q, method, status, auth } = {}) => {
  const query = new URLSearchParams();
  if (limit != null) query.set('limit', String(limit));
  if (offset != null) query.set('offset', String(offset));
  if (q) query.set('q', String(q));
  if (method) query.set('method', String(method));
  if (status) query.set('status', String(status));
  if (auth) query.set('auth', String(auth));
  return query.toString();
};

export const auditLog = ({ limit = 50, offset = 0, q, method, status, auth } = {}) => {
  const suffix = buildAuditLogQuery({ limit, offset, q, method, status, auth });
  return get(`/api/audit/log${suffix ? `?${suffix}` : ''}`);
};
export const auditLogExport = ({ q, method, status, auth } = {}) => {
  const suffix = buildAuditLogQuery({ q, method, status, auth });
  return get(`/api/audit/log/export${suffix ? `?${suffix}` : ''}`);
};
export const auditVerify = () => get('/api/audit/verify');
export const auditAdmin = () => get('/api/audit/admin');
export const retentionStatus = () => get('/api/retention/status');
export const retentionApply = (body) => post('/api/retention/apply', body);
export const historicalStorageEvents = (params = {}) => {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value != null && value !== '') query.set(key, String(value));
  });
  const suffix = query.toString();
  return get(`/api/storage/events/historical${suffix ? `?${suffix}` : ''}`);
};
export const collectorsStatus = () => get('/api/collectors/status');
export const collectorsAws = () => get('/api/collectors/aws');
export const saveAwsCollectorConfig = (body) => post('/api/collectors/aws/config', body);
export const validateAwsCollector = () => post('/api/collectors/aws/validate', {});
export const collectorsAzure = () => get('/api/collectors/azure');
export const saveAzureCollectorConfig = (body) => post('/api/collectors/azure/config', body);
export const validateAzureCollector = () => post('/api/collectors/azure/validate', {});
export const collectorsGcp = () => get('/api/collectors/gcp');
export const saveGcpCollectorConfig = (body) => post('/api/collectors/gcp/config', body);
export const validateGcpCollector = () => post('/api/collectors/gcp/validate', {});
export const collectorsOkta = () => get('/api/collectors/okta');
export const saveOktaCollectorConfig = (body) => post('/api/collectors/okta/config', body);
export const validateOktaCollector = () => post('/api/collectors/okta/validate', {});
export const collectorsEntra = () => get('/api/collectors/entra');
export const saveEntraCollectorConfig = (body) => post('/api/collectors/entra/config', body);
export const validateEntraCollector = () => post('/api/collectors/entra/validate', {});
export const collectorsM365 = () => get('/api/collectors/m365');
export const saveM365CollectorConfig = (body) => post('/api/collectors/m365/config', body);
export const validateM365Collector = () => post('/api/collectors/m365/validate', {});
export const collectorsWorkspace = () => get('/api/collectors/workspace');
export const saveWorkspaceCollectorConfig = (body) =>
  post('/api/collectors/workspace/config', body);
export const validateWorkspaceCollector = () => post('/api/collectors/workspace/validate', {});
export const collectorsGithub = () => get('/api/collectors/github');
export const saveGithubCollectorConfig = (body) => post('/api/collectors/github/config', body);
export const validateGithubCollector = () => post('/api/collectors/github/validate', {});
export const collectorsCrowdStrike = () => get('/api/collectors/crowdstrike');
export const saveCrowdStrikeCollectorConfig = (body) =>
  post('/api/collectors/crowdstrike/config', body);
export const validateCrowdStrikeCollector = () => post('/api/collectors/crowdstrike/validate', {});
export const collectorsSyslog = () => get('/api/collectors/syslog');
export const saveSyslogCollectorConfig = (body) => post('/api/collectors/syslog/config', body);
export const validateSyslogCollector = () => post('/api/collectors/syslog/validate', {});
export const secretsStatus = () => get('/api/secrets/status');
export const saveSecretsConfig = (body) => post('/api/secrets/config', body);
export const validateSecretReference = (body) => post('/api/secrets/validate', body);

// ── Reports ──────────────────────────────────────────────────
export const reports = ({ caseId, incidentId, investigationId, source, scope } = {}) => {
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
export const reportById = (id) => get(`/api/reports/${encodeURIComponent(id)}`);
export const annotateReportContext = (id, body) =>
  post(`/api/reports/${encodeURIComponent(id)}/context`, body);
export const deleteReport = (id) => del(`/api/reports/${encodeURIComponent(id)}`);
export const reportTemplates = ({ caseId, incidentId, investigationId, source, scope } = {}) => {
  const query = new URLSearchParams();
  if (caseId) query.set('case_id', String(caseId));
  if (incidentId) query.set('incident_id', String(incidentId));
  if (investigationId) query.set('investigation_id', String(investigationId));
  if (source) query.set('source', String(source));
  if (scope) query.set('scope', String(scope));
  const suffix = query.toString();
  return get(`/api/report-templates${suffix ? `?${suffix}` : ''}`);
};
export const saveReportTemplate = (body) => post('/api/report-templates', body);
export const reportRuns = ({ caseId, incidentId, investigationId, source, scope } = {}) => {
  const query = new URLSearchParams();
  if (caseId) query.set('case_id', String(caseId));
  if (incidentId) query.set('incident_id', String(incidentId));
  if (investigationId) query.set('investigation_id', String(investigationId));
  if (source) query.set('source', String(source));
  if (scope) query.set('scope', String(scope));
  const suffix = query.toString();
  return get(`/api/report-runs${suffix ? `?${suffix}` : ''}`);
};
export const createReportRun = (body) => post('/api/report-runs', body);
export const reportSchedules = ({ caseId, incidentId, investigationId, source, scope } = {}) => {
  const query = new URLSearchParams();
  if (caseId) query.set('case_id', String(caseId));
  if (incidentId) query.set('incident_id', String(incidentId));
  if (investigationId) query.set('investigation_id', String(investigationId));
  if (source) query.set('source', String(source));
  if (scope) query.set('scope', String(scope));
  const suffix = query.toString();
  return get(`/api/report-schedules${suffix ? `?${suffix}` : ''}`);
};
export const saveReportSchedule = (body) => post('/api/report-schedules', body);
export const inbox = () => get('/api/inbox');
export const ackInbox = (body) => post('/api/inbox/ack', body);

// ── Export ───────────────────────────────────────────────────
export const exportTla = () => get('/api/export/tla');
export const exportAlloy = () => get('/api/export/alloy');
export const exportWitnesses = () => get('/api/export/witnesses');

// ── Hunts & Content ──────────────────────────────────────────
export const hunts = () => get('/api/hunts');
export const createHunt = (body) => post('/api/hunts', body);
export const huntById = (id) => get(`/api/hunts/${encodeURIComponent(id)}`);
export const runHunt = (id, body = {}) => post(`/api/hunts/${encodeURIComponent(id)}/run`, body);
export const escalateHunt = (id, body = {}) =>
  post(`/api/hunts/${encodeURIComponent(id)}/escalate`, body);
export const contentRules = () => get('/api/content/rules');
export const createContentRule = (body) => post('/api/content/rules', body);
export const contentRuleLifecycle = (id, body) =>
  post(`/api/content/rules/${encodeURIComponent(id)}/lifecycle`, body);
export const contentRuleTest = (id, body = {}) =>
  post(`/api/content/rules/${encodeURIComponent(id)}/test`, body);
export const contentRulePromote = (id, body) =>
  post(`/api/content/rules/${encodeURIComponent(id)}/promote`, body);
export const contentRuleRollback = (id) =>
  post(`/api/content/rules/${encodeURIComponent(id)}/rollback`, {});
export const contentPacks = () => get('/api/content/packs');
export const createContentPack = (body) => post('/api/content/packs', body);
export const suppressions = () => get('/api/suppressions');
export const createSuppression = (body) => post('/api/suppressions', body);
export const deleteSuppression = (id) => del(`/api/suppressions/${encodeURIComponent(id)}`);

// ── Escalation ───────────────────────────────────────────────
export const escalationPolicies = () => get('/api/escalation/policies');
export const createEscalationPolicy = (body) => post('/api/escalation/policies', body);
export const escalationStart = (body) => post('/api/escalation/start', body);
export const escalationActive = () => get('/api/escalation/active');
export const escalationAck = (body) => post('/api/escalation/acknowledge', body);

// ── Integrations ─────────────────────────────────────────────
export const siemStatus = () => get('/api/siem/status');
export const siemConfig = () => get('/api/siem/config');
export const setSiemConfig = (body) => post('/api/siem/config', body);
export const validateSiemConfig = (body) => post('/api/siem/validate', body);
export const taxiiStatus = () => get('/api/taxii/status');
export const taxiiConfig = () => get('/api/taxii/config');
export const setTaxiiConfig = (body) => post('/api/taxii/config', body);
export const taxiiPull = () => post('/api/taxii/pull');
export const enrichmentConnectors = () => get('/api/enrichments/connectors');
export const createEnrichmentConnector = (body) => post('/api/enrichments/connectors', body);
export const ticketsSync = (body) => post('/api/tickets/sync', body);
export const idpProviders = () => get('/api/idp/providers');
export const createIdpProvider = (body) => post('/api/idp/providers', body);
export const scimConfig = () => get('/api/scim/config');
export const setScimConfig = (body) => post('/api/scim/config', body);

// ── RBAC ─────────────────────────────────────────────────────
export const rbacUsers = () => get('/api/rbac/users');
export const createRbacUser = (body) => post('/api/rbac/users', body);
export const deleteRbacUser = (u) => del(`/api/rbac/users/${encodeURIComponent(u)}`);

// ── UEBA & Entity ────────────────────────────────────────────
export const uebaEntity = (id) => get(`/api/ueba/entity/${encodeURIComponent(id)}`);
export const uebaRiskyEntities = (minRisk = 10) => get(`/api/ueba/risky?min_risk=${minRisk}`);
export const entityById = (id) => get(`/api/entities/${encodeURIComponent(id)}`);

// ── Process Tree ─────────────────────────────────────────────
export const processTree = () => get('/api/process-tree');
export const deepChains = () => get('/api/process-tree/deep-chains');
export const processesLive = () => get('/api/processes/live');
export const processesAnalysis = () => get('/api/processes/analysis');
export const processDetail = (pid) => get(`/api/processes/detail?pid=${encodeURIComponent(pid)}`);
export const processThreads = (pid) => get(`/api/processes/threads?pid=${encodeURIComponent(pid)}`);

// ── Host Info & Inventory ────────────────────────────────────
export const hostApps = () => get('/api/host/apps');
export const hostInventory = () => get('/api/host/inventory');

// ── Timelines ────────────────────────────────────────────────
export const timelineHost = (hostname) => {
  const value = String(hostname || '').trim();
  if (!value) return Promise.resolve({ timeline: [], host: '', count: 0 });
  return get(`/api/timeline/host?hostname=${encodeURIComponent(value)}`);
};
export const timelineAgent = (agentId) => {
  const value = String(agentId || '').trim();
  if (!value) return Promise.resolve({ timeline: [], agent_id: '', count: 0 });
  return get(`/api/timeline/agent?agent_id=${encodeURIComponent(value)}`);
};
export const timelineById = (id) => get(`/api/timeline/${encodeURIComponent(id)}`);

// ── Other ────────────────────────────────────────────────────
export const graphql = (body) => post('/api/graphql', body);
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
export const gdprForget = (entity) => del(`/api/gdpr/forget/${encodeURIComponent(entity)}`);
export const adminBackup = () => post('/api/admin/backup');
export const adminDbVersion = () => get('/api/admin/db/version');
export const adminDbRollback = () => post('/api/admin/db/rollback');
export const adminDbCompact = () => post('/api/admin/db/compact');
export const adminDbReset = (body) => post('/api/admin/db/reset', body);
export const adminDbSizes = () => get('/api/admin/db/sizes');
export const adminCleanupLegacy = () => post('/api/admin/cleanup-legacy');
export const adminDbPurge = (body) => post('/api/admin/db/purge', body);
export const storageStats = () => get('/api/storage/stats');
export const spoolStats = () => get('/api/spool/stats');
export const sbom = () => get('/api/sbom');
export const piiScan = (body) => post('/api/pii/scan', body);
export const dlq = () => get('/api/dlq');
export const dlqStats = () => get('/api/dlq/stats');
export const dlqClear = () => del('/api/dlq');

// ── ML Engine ────────────────────────────────────────────────
export const mlModels = () => get('/api/ml/models');
export const mlModelsStatus = () => get('/api/ml/models/status');
export const mlModelsRollback = () => post('/api/ml/models/rollback');
export const mlShadowRecent = (limit = 20) =>
  get(`/api/ml/shadow/recent?limit=${encodeURIComponent(limit)}`);
export const mlPredict = (body) => post('/api/ml/predict', body);
export const mlTriage = (body) => post('/api/ml/triage', body);
export const mlTriageV2 = (body) => post('/api/ml/triage/v2', body);

// ── Vulnerability Scanner ────────────────────────────────────
export const vulnerabilityScan = () => get('/api/vulnerability/scan');
export const vulnerabilitySummary = () => get('/api/vulnerability/summary');

// ── NDR Engine ───────────────────────────────────────────────
export const ndrNetflow = (body) => post('/api/ndr/netflow', body);
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
export const emailQuarantineRelease = (id) =>
  post(`/api/email/quarantine/${encodeURIComponent(id)}/release`);
export const emailQuarantineDelete = (id) => del(`/api/email/quarantine/${encodeURIComponent(id)}`);
export const emailStats = () => get('/api/email/stats');
export const emailPolicies = () => get('/api/email/policies');
export const emailPolicyUpdate = (body) => put('/api/email/policies', body);

// ── Container Detection ──────────────────────────────────────
export const containerEvent = (body) => post('/api/container/event', body);
export const containerAlerts = () => get('/api/container/alerts');
export const containerStats = () => get('/api/container/stats');

// ── Certificate Monitor ──────────────────────────────────────
export const certsRegister = (body) => post('/api/certs/register', body);
export const certsSummary = () => get('/api/certs/summary');
export const certsAlerts = () => get('/api/certs/alerts');

// ── Config Drift Detection ───────────────────────────────────
export const configDriftCheck = (body) => post('/api/config-drift/check', body);
export const configDriftBaselines = () => get('/api/config-drift/baselines');

// ── Asset Inventory ──────────────────────────────────────────
export const assets = () => get('/api/assets');
export const assetsSummary = () => get('/api/assets/summary');
export const assetsUpsert = (body) => post('/api/assets/upsert', body);
export const assetsSearch = (q) => get(`/api/assets/search?q=${encodeURIComponent(q)}`);

// ── Detection Efficacy ───────────────────────────────────────
export const efficacyTriage = (body) => post('/api/efficacy/triage', body);
export const efficacySummary = () => get('/api/efficacy/summary');
export const efficacyRule = (id) => get(`/api/efficacy/rule/${encodeURIComponent(id)}`);

// ── Investigation Workflows ──────────────────────────────────
export const investigationWorkflows = () => get('/api/investigations/workflows');
export const investigationGraph = (body) => post('/api/investigation/graph', body);
export const investigationWorkflow = (id) =>
  get(`/api/investigations/workflows/${encodeURIComponent(id)}`);
export const investigationStart = (body) => post('/api/investigations/start', body);
export const investigationActive = () => get('/api/investigations/active');
export const investigationProgress = (body) => post('/api/investigations/progress', body);
export const investigationHandoff = (body) => post('/api/investigations/handoff', body);
export const investigationSuggest = (body) => post('/api/investigations/suggest', body);
export const analystQuery = (body) => post('/api/events/search', body);

// ── Malware Detection / AV Scanning ──────────────────────────
export const scanBuffer = (body) => post('/api/scan/buffer', body);
export const scanBufferV2 = (body) => post('/api/scan/buffer/v2', body);
export const scanHash = (body) => post('/api/scan/hash', body);
export const malwareStats = () => get('/api/malware/stats');
export const malwareRecent = () => get('/api/malware/recent');
export const malwareImport = (body) => post('/api/malware/signatures/import', body);
export const detectionExplain = (params = {}) =>
  get(`/api/detection/explain${toQuery(params) ? `?${toQuery(params)}` : ''}`);
export const detectionFeedback = (params = {}) =>
  get(`/api/detection/feedback${toQuery(params) ? `?${toQuery(params)}` : ''}`);
export const recordDetectionFeedback = (body) => post('/api/detection/feedback', body);
export const threatIntelLibraryV2 = () => get('/api/threat-intel/library/v2');
export const threatIntelSightings = (limit = 50) =>
  get(`/api/threat-intel/sightings?limit=${encodeURIComponent(limit)}`);

// ── Threat Hunting ───────────────────────────────────────────
export const hunt = (query) => post('/api/hunt', { query });

// ── SIEM Export ──────────────────────────────────────────────
export const exportAlerts = (fmt = 'json') =>
  get(`/api/export/alerts?format=${encodeURIComponent(fmt)}`);

// ── Compliance ───────────────────────────────────────────────
export const complianceReport = (framework) =>
  get(
    framework
      ? `/api/compliance/report?framework=${encodeURIComponent(framework)}`
      : '/api/compliance/report',
  );
export const complianceSummary = () => get('/api/compliance/summary');

// ── Playbook Run ─────────────────────────────────────────────
export const runPlaybook = (body) => post('/api/playbooks/run', body);

// ── Alert Deduplication ──────────────────────────────────────
export const dedupAlerts = () => get('/api/alerts/dedup');

// ── API Analytics ────────────────────────────────────────────
export const apiAnalytics = () => get('/api/analytics');

// ── OpenTelemetry Traces ─────────────────────────────────────
export const traces = () => get('/api/traces');

// ── Backup Encryption ────────────────────────────────────────
export const backupEncrypt = (body) => post('/api/backup/encrypt', body);
export const backupDecrypt = (body) => post('/api/backup/decrypt', body);

// ── Detection Rules ──────────────────────────────────────────
export const detectionRules = () => get('/api/detection/rules');
export const addDetectionRule = (body) => post('/api/detection/rules', body);

// ── Feed Ingestion ───────────────────────────────────────────
export const feeds = () => get('/api/feeds');
export const addFeed = (body) => post('/api/feeds', body);
export const removeFeed = (id) => del(`/api/feeds/${encodeURIComponent(id)}`);
export const pollFeed = (id, body) => post(`/api/feeds/${encodeURIComponent(id)}/poll`, body);
export const feedStats = () => get('/api/feeds/stats');
export const hotReloadHashes = (body) => post('/api/feeds/hot-reload/hashes', body);

// ── Playbook DSL ─────────────────────────────────────────────
export const playbookDslList = () => get('/api/playbook-dsl');
export const playbookDslCreate = (body) => post('/api/playbook-dsl', body);
export const playbookDslGet = (id) => get(`/api/playbook-dsl/${encodeURIComponent(id)}`);
export const playbookDslDelete = (id) => del(`/api/playbook-dsl/${encodeURIComponent(id)}`);

// ── ATT&CK Coverage Gaps ────────────────────────────────────
export const coverageGaps = () => get('/api/coverage/gaps');

// ── Container Image Inventory ────────────────────────────────
export const images = () => get('/api/images');
export const imagesSummary = () => get('/api/images/summary');
export const imagesCollect = () => post('/api/images/collect');

// ── Quarantine Store ─────────────────────────────────────────
export const quarantineList = () => get('/api/quarantine');
export const quarantineAdd = (body) => post('/api/quarantine', body);
export const quarantineStats = () => get('/api/quarantine/stats');
export const quarantineRelease = (id) => post(`/api/quarantine/${encodeURIComponent(id)}/release`);
export const quarantineDelete = (id) => del(`/api/quarantine/${encodeURIComponent(id)}`);

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
export const entropyAnalyze = (body) => post('/api/entropy/analyze', body);
export const dnsThreatAnalyze = (domain) => post('/api/dns-threat/analyze', { domain });
export const dnsThreatSummary = () => get('/api/dns-threat/summary');
export const dnsThreatRecord = (query) => post('/api/dns-threat/record', query);
export const processScoreAssess = (body) => post('/api/process-scoring/assess', body);
export const emailAnalyze = (body) => post('/api/email/analyze', body);
export const memoryIndicatorsScanMaps = (body) => post('/api/memory-indicators/scan-maps', body);
export const memoryIndicatorsScanBuffer = (body) =>
  post('/api/memory-indicators/scan-buffer', body);

// ── Phase 29: WebSocket Alert Streaming ──────────────────────
export const wsConnect = () => post('/api/ws/connect');
export const wsDisconnect = (subscriberId) =>
  post('/api/ws/disconnect', { subscriber_id: subscriberId });
export const wsPoll = (subscriberId) => post('/api/ws/poll', { subscriber_id: subscriberId });
export const wsStats = () => get('/api/ws/stats');
export const wsBroadcast = (data) => post('/api/ws/broadcast', data);

// ── v0.44.0: Enhanced Detection & UX ─────────────────────────
export const dedupStats = () => get('/api/alerts/dedup-stats');
export const noisyRules = () => get('/api/detection/noisy-rules');
export const playbooks = () => get('/api/playbooks');
export const playbookById = (id) => get(`/api/playbooks/${encodeURIComponent(id)}`);
export const playbookRun = (id) => post(`/api/playbooks/${encodeURIComponent(id)}/run`);
export const canaryStatus = () => get('/api/canary/status');
export const insiderRisk = (entityKind, entityId) =>
  get(`/api/ueba/insider-risk/${encodeURIComponent(entityKind)}/${encodeURIComponent(entityId)}`);
export const credentialSprayAlerts = () => get('/api/correlation/credential-spray');
export const campaigns = () => get('/api/correlation/campaigns');
export const rbacCreateUser = (body) => post('/api/rbac/users', body);
export const rbacDeleteUser = (username) => del(`/api/rbac/users/${encodeURIComponent(username)}`);

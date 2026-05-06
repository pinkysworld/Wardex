"use strict";
/**
 * Wardex TypeScript SDK
 *
 * Full-typed client for the Wardex XDR REST API.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.WardexClient = exports.ServerError = exports.RateLimitError = exports.NotFoundError = exports.AuthenticationError = exports.WardexError = void 0;
// ── Errors ───────────────────────────────────────────────────────────────────
/** Base error for all Wardex SDK errors. */
class WardexError extends Error {
    constructor(message, statusCode, body = "") {
        super(message);
        this.name = "WardexError";
        this.statusCode = statusCode;
        this.body = body;
    }
}
exports.WardexError = WardexError;
/** Raised on 401 / 403 responses. */
class AuthenticationError extends WardexError {
    constructor(message, statusCode, body = "") {
        super(message, statusCode, body);
        this.name = "AuthenticationError";
    }
}
exports.AuthenticationError = AuthenticationError;
/** Raised on 404 responses. */
class NotFoundError extends WardexError {
    constructor(message, statusCode, body = "") {
        super(message, statusCode, body);
        this.name = "NotFoundError";
    }
}
exports.NotFoundError = NotFoundError;
/** Raised on 429 responses. */
class RateLimitError extends WardexError {
    constructor(message, statusCode, body = "") {
        super(message, statusCode, body);
        this.name = "RateLimitError";
    }
}
exports.RateLimitError = RateLimitError;
/** Raised on 5xx responses. */
class ServerError extends WardexError {
    constructor(message, statusCode, body = "") {
        super(message, statusCode, body);
        this.name = "ServerError";
    }
}
exports.ServerError = ServerError;
function buildReportExecutionContextQuery(params = {}) {
    const query = new URLSearchParams();
    if (params.case_id)
        query.set("case_id", String(params.case_id));
    if (params.incident_id)
        query.set("incident_id", String(params.incident_id));
    if (params.investigation_id) {
        query.set("investigation_id", String(params.investigation_id));
    }
    if (params.source)
        query.set("source", String(params.source));
    if (params.scope && params.scope !== "all") {
        query.set("scope", String(params.scope));
    }
    const suffix = query.toString();
    return suffix ? `?${suffix}` : "";
}
// ── Client ───────────────────────────────────────────────────────────────────
class WardexClient {
    constructor(config) {
        if (!/^https?:\/\//i.test(config.baseUrl)) {
            throw new Error("baseUrl must start with http:// or https://");
        }
        this.baseUrl = config.baseUrl.replace(/\/$/, "");
        this.apiKey = config.apiKey;
        this.timeout = config.timeout ?? 30000;
        this.credentials = config.credentials;
    }
    async request(method, path, body, options) {
        const url = `${this.baseUrl}${path}`;
        const headers = {
            "Content-Type": options?.contentType ?? "application/json",
        };
        if (this.apiKey) {
            headers["Authorization"] = `Bearer ${this.apiKey}`;
        }
        const requestBody = options?.rawBody !== undefined
            ? options.rawBody
            : body !== undefined
                ? JSON.stringify(body)
                : undefined;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeout);
        try {
            const resp = await fetch(url, {
                method,
                headers,
                body: requestBody,
                signal: controller.signal,
                credentials: this.credentials,
            });
            if (!resp.ok) {
                const text = await resp.text().catch(() => "");
                const msg = `HTTP ${resp.status}: ${text}`;
                if (resp.status === 401 || resp.status === 403) {
                    throw new AuthenticationError(msg, resp.status, text);
                }
                if (resp.status === 404) {
                    throw new NotFoundError(msg, resp.status, text);
                }
                if (resp.status === 429) {
                    throw new RateLimitError(msg, resp.status, text);
                }
                if (resp.status >= 500) {
                    throw new ServerError(msg, resp.status, text);
                }
                throw new WardexError(msg, resp.status, text);
            }
            if (resp.status === 204) {
                return undefined;
            }
            if (options?.responseType === "text") {
                return (await resp.text());
            }
            const ct = resp.headers.get("content-type") ?? "";
            if (!ct.includes("application/json")) {
                const text = await resp.text().catch(() => "");
                throw new WardexError(`Expected JSON response, got ${ct || "unknown"}`, resp.status, text);
            }
            return (await resp.json());
        }
        finally {
            clearTimeout(timer);
        }
    }
    // ── Health ───────────────────────────────────────────────────────
    async health() {
        return this.request("GET", "/api/health");
    }
    async healthLive() {
        return this.request("GET", "/api/healthz/live");
    }
    async healthReady() {
        return this.request("GET", "/api/healthz/ready");
    }
    async wsStats() {
        return this.request("GET", "/api/ws/stats");
    }
    async commandSummary() {
        return this.request("GET", "/api/command/summary");
    }
    async commandLane(lane) {
        return this.request("GET", `/api/command/lanes/${encodeURIComponent(lane)}`);
    }
    async authCheck() {
        return this.request("GET", "/api/auth/check");
    }
    async authSession() {
        return this.request("GET", "/api/auth/session");
    }
    async createAuthSession() {
        return this.request("POST", "/api/auth/session");
    }
    async authLogout() {
        return this.request("POST", "/api/auth/logout");
    }
    async sessionInfo() {
        return this.request("GET", "/api/session/info");
    }
    async openApiSpec() {
        return this.request("GET", "/api/openapi.json");
    }
    async supportDiagnostics() {
        return this.request("GET", "/api/support/diagnostics");
    }
    async supportParity() {
        return this.request("GET", "/api/support/parity");
    }
    async readinessEvidence() {
        return this.request("GET", "/api/support/readiness-evidence");
    }
    async firstRunProof() {
        return this.request("POST", "/api/support/first-run-proof");
    }
    async failoverDrill() {
        return this.request("POST", "/api/control/failover-drill");
    }
    async productionDemoLab() {
        return this.request("POST", "/api/demo/lab");
    }
    async reportTemplates(params = {}) {
        const suffix = buildReportExecutionContextQuery(params);
        return this.request("GET", `/api/report-templates${suffix}`);
    }
    async saveReportTemplate(request) {
        return this.request("POST", "/api/report-templates", request);
    }
    async reportRuns(params = {}) {
        const suffix = buildReportExecutionContextQuery(params);
        return this.request("GET", `/api/report-runs${suffix}`);
    }
    async createReportRun(request) {
        return this.request("POST", "/api/report-runs", request);
    }
    async reportSchedules(params = {}) {
        const suffix = buildReportExecutionContextQuery(params);
        return this.request("GET", `/api/report-schedules${suffix}`);
    }
    async saveReportSchedule(request) {
        return this.request("POST", "/api/report-schedules", request);
    }
    async docsIndex(params = {}) {
        const query = new URLSearchParams();
        if (params.q)
            query.set("q", String(params.q));
        if (params.section)
            query.set("section", String(params.section));
        if (params.limit != null)
            query.set("limit", String(params.limit));
        const suffix = query.toString();
        return this.request("GET", `/api/docs/index${suffix ? `?${suffix}` : ""}`);
    }
    async docsContent(path) {
        return this.request("GET", `/api/docs/content?path=${encodeURIComponent(String(path ?? ""))}`);
    }
    async systemDeps() {
        return this.request("GET", "/api/system/health/dependencies");
    }
    // ── Alerts ───────────────────────────────────────────────────────
    async alerts() {
        return this.request("GET", "/api/alerts");
    }
    async alertsCount() {
        return this.request("GET", "/api/alerts/count");
    }
    async clearAlerts() {
        return this.request("DELETE", "/api/alerts");
    }
    async sampleAlert(request = {}) {
        return this.request("POST", "/api/alerts/sample", request);
    }
    async bulkAcknowledgeAlerts(request) {
        return this.request("POST", "/api/alerts/bulk/acknowledge", request);
    }
    async bulkResolveAlerts(request) {
        return this.request("POST", "/api/alerts/bulk/resolve", request);
    }
    async bulkCloseAlerts(request) {
        return this.request("POST", "/api/alerts/bulk/close", request);
    }
    async alertAnalysis() {
        return this.request("GET", "/api/alerts/analysis");
    }
    async runAlertAnalysis(request = {}) {
        return this.request("POST", "/api/alerts/analysis", request);
    }
    async groupedAlerts() {
        return this.request("GET", "/api/alerts/grouped");
    }
    async getAlert(index) {
        return this.request("GET", `/api/alerts/${encodeURIComponent(String(index))}`);
    }
    async queueStats() {
        return this.request("GET", "/api/queue/stats");
    }
    async dlqStats() {
        return this.request("GET", "/api/dlq/stats");
    }
    async dlq() {
        return this.request("GET", "/api/dlq");
    }
    async dlqClear() {
        return this.request("DELETE", "/api/dlq");
    }
    // ── Malware Scanning ─────────────────────────────────────────────
    async scanBuffer(data, filename) {
        const b64 = typeof data === "string"
            ? data
            : Buffer.from(data).toString("base64");
        return this.request("POST", "/api/scan/buffer", {
            data: b64,
            filename: filename ?? "upload",
        });
    }
    async scanHash(hash) {
        return this.request("POST", "/api/scan/hash", { hash });
    }
    async scanBufferV2(data, filename, behavior, allowlist) {
        const b64 = typeof data === "string"
            ? data
            : Buffer.from(data).toString("base64");
        return this.request("POST", "/api/scan/buffer/v2", {
            data: b64,
            filename: filename ?? "upload",
            behavior,
            allowlist,
        });
    }
    async memoryIndicatorsScanMaps(request) {
        return this.request("POST", "/api/memory-indicators/scan-maps", request);
    }
    async memoryIndicatorsScanBuffer(data) {
        const body = typeof data === "string" ? data : Buffer.from(data).toString("base64");
        return this.request("POST", "/api/memory-indicators/scan-buffer", undefined, {
            contentType: "text/plain",
            rawBody: body,
        });
    }
    async malwareStats() {
        return this.request("GET", "/api/malware/stats");
    }
    async malwareRecent() {
        return this.request("GET", "/api/malware/recent");
    }
    async collectorsStatus() {
        return this.request("GET", "/api/collectors/status");
    }
    async collectorsAws() {
        return this.request("GET", "/api/collectors/aws");
    }
    async saveAwsCollectorConfig(config) {
        return this.request("POST", "/api/collectors/aws/config", config);
    }
    async validateAwsCollector() {
        return this.request("POST", "/api/collectors/aws/validate");
    }
    async collectorsAzure() {
        return this.request("GET", "/api/collectors/azure");
    }
    async saveAzureCollectorConfig(config) {
        return this.request("POST", "/api/collectors/azure/config", config);
    }
    async validateAzureCollector() {
        return this.request("POST", "/api/collectors/azure/validate");
    }
    async collectorsGcp() {
        return this.request("GET", "/api/collectors/gcp");
    }
    async saveGcpCollectorConfig(config) {
        return this.request("POST", "/api/collectors/gcp/config", config);
    }
    async validateGcpCollector() {
        return this.request("POST", "/api/collectors/gcp/validate");
    }
    async collectorsOkta() {
        return this.request("GET", "/api/collectors/okta");
    }
    async saveOktaCollectorConfig(config) {
        return this.request("POST", "/api/collectors/okta/config", config);
    }
    async validateOktaCollector() {
        return this.request("POST", "/api/collectors/okta/validate");
    }
    async collectorsEntra() {
        return this.request("GET", "/api/collectors/entra");
    }
    async saveEntraCollectorConfig(config) {
        return this.request("POST", "/api/collectors/entra/config", config);
    }
    async validateEntraCollector() {
        return this.request("POST", "/api/collectors/entra/validate");
    }
    async collectorsM365() {
        return this.request("GET", "/api/collectors/m365");
    }
    async saveM365CollectorConfig(config) {
        return this.request("POST", "/api/collectors/m365/config", config);
    }
    async validateM365Collector() {
        return this.request("POST", "/api/collectors/m365/validate");
    }
    async collectorsWorkspace() {
        return this.request("GET", "/api/collectors/workspace");
    }
    async saveWorkspaceCollectorConfig(config) {
        return this.request("POST", "/api/collectors/workspace/config", config);
    }
    async validateWorkspaceCollector() {
        return this.request("POST", "/api/collectors/workspace/validate");
    }
    async collectorsGithub() {
        return this.request("GET", "/api/collectors/github");
    }
    async saveGithubCollectorConfig(config) {
        return this.request("POST", "/api/collectors/github/config", config);
    }
    async validateGithubCollector() {
        return this.request("POST", "/api/collectors/github/validate");
    }
    async collectorsCrowdStrike() {
        return this.request("GET", "/api/collectors/crowdstrike");
    }
    async saveCrowdStrikeCollectorConfig(config) {
        return this.request("POST", "/api/collectors/crowdstrike/config", config);
    }
    async validateCrowdStrikeCollector() {
        return this.request("POST", "/api/collectors/crowdstrike/validate");
    }
    async collectorsSyslog() {
        return this.request("GET", "/api/collectors/syslog");
    }
    async saveSyslogCollectorConfig(config) {
        return this.request("POST", "/api/collectors/syslog/config", config);
    }
    async validateSyslogCollector() {
        return this.request("POST", "/api/collectors/syslog/validate");
    }
    async secretsStatus() {
        return this.request("GET", "/api/secrets/status");
    }
    async saveSecretsConfig(config) {
        return this.request("POST", "/api/secrets/config", config);
    }
    async validateSecretReference(request) {
        return this.request("POST", "/api/secrets/validate", request);
    }
    async fleetInstalls() {
        return this.request("GET", "/api/fleet/installs");
    }
    async fleetInstallSsh(request) {
        return this.request("POST", "/api/fleet/install/ssh", request);
    }
    async fleetInstallWinrm(request) {
        return this.request("POST", "/api/fleet/install/winrm", request);
    }
    async processTree() {
        return this.request("GET", "/api/process-tree");
    }
    async processesLive() {
        return this.request("GET", "/api/processes/live");
    }
    async processesAnalysis() {
        return this.request("GET", "/api/processes/analysis");
    }
    async deepChains() {
        return this.request("GET", "/api/process-tree/deep-chains");
    }
    async processDetail(pid) {
        return this.request("GET", `/api/processes/detail?pid=${encodeURIComponent(String(pid))}`);
    }
    async processThreads(pid) {
        return this.request("GET", `/api/processes/threads?pid=${encodeURIComponent(String(pid))}`);
    }
    async hostApps() {
        return this.request("GET", "/api/host/apps");
    }
    async hostInventory() {
        return this.request("GET", "/api/host/inventory");
    }
    async remediationPlan(request) {
        return this.request("POST", "/api/remediation/plan", request);
    }
    async remediationResults() {
        return this.request("GET", "/api/remediation/results");
    }
    async remediationStats() {
        return this.request("GET", "/api/remediation/stats");
    }
    async remediationChangeReviews() {
        return this.request("GET", "/api/remediation/change-reviews");
    }
    async recordRemediationChangeReview(review) {
        return this.request("POST", "/api/remediation/change-reviews", review);
    }
    async approveRemediationChangeReview(id, approval) {
        return this.request("POST", `/api/remediation/change-reviews/${encodeURIComponent(id)}/approval`, approval);
    }
    async executeRemediationRollback(id, request) {
        return this.request("POST", `/api/remediation/change-reviews/${encodeURIComponent(id)}/rollback`, request);
    }
    async malwareImport(data) {
        return this.request("POST", "/api/malware/signatures/import", { data });
    }
    // ── Search & Hunt ────────────────────────────────────────────────
    async search(query, limit) {
        return this.request("POST", "/api/search", {
            query,
            limit: limit ?? 50,
        });
    }
    async analystQuery(query) {
        return this.request("POST", "/api/events/search", query);
    }
    async hunt(query) {
        return this.request("POST", "/api/hunt", { query });
    }
    async sigmaStats() {
        return this.request("GET", "/api/sigma/stats");
    }
    // ── Playbooks ────────────────────────────────────────────────────
    async listPlaybooks() {
        return this.request("GET", "/api/playbooks");
    }
    async runPlaybook(playbookId, alertId, variables) {
        return this.request("POST", "/api/playbooks/run", {
            playbook_id: playbookId,
            alert_id: alertId,
            variables: variables ?? {},
        });
    }
    async playbookExecution(executionId) {
        return this.request("GET", `/api/playbooks/executions/${encodeURIComponent(executionId)}`);
    }
    // ── Compliance ───────────────────────────────────────────────────
    async complianceStatus() {
        return this.request("GET", "/api/compliance/status");
    }
    async complianceReport(frameworkId) {
        const path = frameworkId
            ? `/api/compliance/report?framework=${encodeURIComponent(frameworkId)}`
            : "/api/compliance/report";
        return this.request("GET", path);
    }
    async complianceSummary() {
        return this.request("GET", "/api/compliance/summary");
    }
    // ── SIEM Export ──────────────────────────────────────────────────
    async siemStatus() {
        return this.request("GET", "/api/siem/status");
    }
    async siemConfig() {
        return this.request("GET", "/api/siem/config");
    }
    async saveSiemConfig(config) {
        return this.request("POST", "/api/siem/config", config);
    }
    async validateSiemConfig(config) {
        return this.request("POST", "/api/siem/validate", config);
    }
    async taxiiStatus() {
        return this.request("GET", "/api/taxii/status");
    }
    async taxiiConfig() {
        return this.request("GET", "/api/taxii/config");
    }
    async saveTaxiiConfig(config) {
        return this.request("POST", "/api/taxii/config", config);
    }
    async taxiiPull() {
        return this.request("POST", "/api/taxii/pull");
    }
    async exportAlerts(format) {
        return this.request("GET", `/api/export/alerts?format=${encodeURIComponent(format)}`, undefined, { responseType: "text" });
    }
    async exportTla() {
        return this.request("GET", "/api/export/tla", undefined, {
            responseType: "text",
        });
    }
    async exportAlloy() {
        return this.request("GET", "/api/export/alloy", undefined, {
            responseType: "text",
        });
    }
    async exportWitnesses() {
        return this.request("GET", "/api/export/witnesses");
    }
    // ── Backups ──────────────────────────────────────────────────────
    async listBackups() {
        return this.request("GET", "/api/backups");
    }
    async createBackup() {
        return this.request("POST", "/api/backups");
    }
    async adminBackup() {
        return this.request("POST", "/api/admin/backup");
    }
    async adminDbVersion() {
        return this.request("GET", "/api/admin/db/version");
    }
    async adminDbSizes() {
        return this.request("GET", "/api/admin/db/sizes");
    }
    async adminDbRollback() {
        return this.request("POST", "/api/admin/db/rollback");
    }
    async adminDbCompact() {
        return this.request("POST", "/api/admin/db/compact");
    }
    async adminDbReset(request) {
        return this.request("POST", "/api/admin/db/reset", request);
    }
    async adminDbPurge(request) {
        return this.request("POST", "/api/admin/db/purge", request);
    }
    async adminCleanupLegacy() {
        return this.request("POST", "/api/admin/cleanup-legacy");
    }
    async sbom() {
        return this.request("GET", "/api/sbom");
    }
    async sbomHost() {
        return this.request("GET", "/api/sbom/host");
    }
    async piiScan(sample) {
        return this.request("POST", "/api/pii/scan", undefined, {
            rawBody: sample,
            contentType: "text/plain",
        });
    }
    async license() {
        return this.request("GET", "/api/license");
    }
    async validateLicense(request) {
        return this.request("POST", "/api/license/validate", request);
    }
    async meteringUsage() {
        return this.request("GET", "/api/metering/usage");
    }
    async billingSubscription() {
        return this.request("GET", "/api/billing/subscription");
    }
    async billingInvoices() {
        return this.request("GET", "/api/billing/invoices");
    }
    async listMarketplacePacks() {
        return this.request("GET", "/api/marketplace/packs");
    }
    async getMarketplacePack(packId) {
        return this.request("GET", `/api/marketplace/packs/${encodeURIComponent(packId)}`);
    }
    async preventionPolicies() {
        return this.request("GET", "/api/prevention/policies");
    }
    async preventionStats() {
        return this.request("GET", "/api/prevention/stats");
    }
    async pipelineStatus() {
        return this.request("GET", "/api/pipeline/status");
    }
    // ── Audit ────────────────────────────────────────────────────────
    async auditVerify() {
        return this.request("GET", "/api/audit/verify");
    }
    async auditLogs(limit, offset) {
        return this.request("GET", `/api/audit/log?limit=${limit ?? 100}&offset=${offset ?? 0}`);
    }
    // ── Analytics ────────────────────────────────────────────────────
    async apiAnalytics() {
        return this.request("GET", "/api/analytics");
    }
    async traces() {
        return this.request("GET", "/api/traces");
    }
    async backupStatus() {
        return this.request("GET", "/api/backup/status");
    }
    async backupEncrypt(request) {
        return this.request("POST", "/api/backup/encrypt", request);
    }
    async backupDecrypt(request) {
        return this.request("POST", "/api/backup/decrypt", request);
    }
    // ── Dedup ────────────────────────────────────────────────────────
    async dedupAlerts() {
        return this.request("GET", "/api/alerts/dedup");
    }
    async autoCreateDedupIncidents() {
        return this.request("POST", "/api/alerts/dedup/auto-create");
    }
    // ── UEBA ─────────────────────────────────────────────────────────
    async uebaObserve(observation) {
        return this.request("POST", "/api/ueba/observe", observation);
    }
    async uebaRiskyEntities() {
        return this.request("GET", "/api/ueba/risky");
    }
    async uebaEntity(entityId) {
        return this.request("GET", `/api/ueba/entity/${encodeURIComponent(entityId)}`);
    }
    // ── NDR ──────────────────────────────────────────────────────────
    async ndrReport() {
        return this.request("GET", "/api/ndr/report");
    }
    async beaconConnection(connection) {
        return this.request("POST", "/api/beacon/connection", connection);
    }
    async beaconDns(dns) {
        return this.request("POST", "/api/beacon/dns", dns);
    }
    async beaconAnalyze() {
        return this.request("GET", "/api/beacon/analyze");
    }
    async ndrIngest(netflow) {
        return this.request("POST", "/api/ndr/netflow", netflow);
    }
    async ndrTlsAnomalies() {
        return this.request("GET", "/api/ndr/tls-anomalies");
    }
    async ndrDpiAnomalies() {
        return this.request("GET", "/api/ndr/dpi-anomalies");
    }
    async ndrEntropyAnomalies() {
        return this.request("GET", "/api/ndr/entropy-anomalies");
    }
    async ndrSelfSignedCerts() {
        return this.request("GET", "/api/ndr/self-signed-certs");
    }
    async ndrTopTalkers(limit) {
        const talkers = await this.request("GET", "/api/ndr/top-talkers");
        const normalizedLimit = limit === undefined ? 20 : Math.max(0, Math.trunc(limit));
        return talkers.slice(0, normalizedLimit);
    }
    async ndrBeaconing() {
        return this.request("GET", "/api/ndr/beaconing");
    }
    async ndrProtocolDistribution() {
        return this.request("GET", "/api/ndr/protocol-distribution");
    }
    // ── Email Security ───────────────────────────────────────────────
    async emailAnalyze(input) {
        return this.request("POST", "/api/email/analyze", {
            ...input,
            received_chain: input.received_chain ?? [],
            attachments: input.attachments ?? [],
        });
    }
    async emailQuarantine(limit) {
        return this.request("GET", `/api/email/quarantine?limit=${limit ?? 50}`);
    }
    async emailQuarantineRelease(messageId) {
        return this.request("POST", `/api/email/quarantine/${encodeURIComponent(messageId)}/release`);
    }
    async emailQuarantineDelete(messageId) {
        return this.request("DELETE", `/api/email/quarantine/${encodeURIComponent(messageId)}`);
    }
    async emailStats() {
        return this.request("GET", "/api/email/stats");
    }
    async emailPolicies() {
        return this.request("GET", "/api/email/policies");
    }
    // ── Incidents ────────────────────────────────────────────────────
    async listIncidents() {
        return this.request("GET", "/api/incidents");
    }
    async getIncident(incidentId) {
        return this.request("GET", `/api/incidents/${encodeURIComponent(incidentId)}`);
    }
    async createIncident(title, severity, summary, options) {
        return this.request("POST", "/api/incidents", {
            title,
            severity,
            summary: summary ?? "",
            event_ids: options?.event_ids ?? [],
            agent_ids: options?.agent_ids ?? [],
        });
    }
    // ── Fleet ────────────────────────────────────────────────────────
    async listAgents() {
        return this.request("GET", "/api/agents");
    }
    async getAgent(agentId) {
        return this.request("GET", `/api/agents/${encodeURIComponent(agentId)}/details`);
    }
    // ── Policy ───────────────────────────────────────────────────────
    async currentPolicy() {
        return this.request("GET", "/api/policy/current");
    }
    async publishPolicy(policy) {
        return this.request("POST", "/api/policy/publish", {
            version: policy.version ?? 0,
            published_at: policy.published_at ?? "",
            ...policy,
        });
    }
    // ── Assets ───────────────────────────────────────────────────────
    async assets() {
        return this.request("GET", "/api/assets");
    }
    async assetsSearch(query) {
        return this.request("GET", `/api/assets/search?q=${encodeURIComponent(query)}`);
    }
    async assetsSummary() {
        return this.request("GET", "/api/assets/summary");
    }
    async upsertAsset(asset) {
        return this.request("POST", "/api/assets/upsert", asset);
    }
    async lifecycle() {
        return this.request("GET", "/api/lifecycle");
    }
    async lifecycleStats() {
        return this.request("GET", "/api/lifecycle/stats");
    }
    async lifecycleSweep() {
        return this.request("POST", "/api/lifecycle/sweep");
    }
    async iocDecayApply() {
        return this.request("POST", "/api/ioc-decay/apply");
    }
    async iocDecayPreview() {
        return this.request("GET", "/api/ioc-decay/preview");
    }
    async certsRegister(certificate) {
        return this.request("POST", "/api/certs/register", certificate);
    }
    async certsSummary() {
        return this.request("GET", "/api/certs/summary");
    }
    async certsAlerts() {
        return this.request("GET", "/api/certs/alerts");
    }
    async quarantineList() {
        return this.request("GET", "/api/quarantine");
    }
    async quarantineAdd(request) {
        return this.request("POST", "/api/quarantine", request);
    }
    async quarantineStats() {
        return this.request("GET", "/api/quarantine/stats");
    }
    async quarantineRelease(id) {
        return this.request("POST", `/api/quarantine/${encodeURIComponent(id)}/release`);
    }
    async quarantineDelete(id) {
        return this.request("DELETE", `/api/quarantine/${encodeURIComponent(id)}`);
    }
    async entropyAnalyze(sample) {
        return this.request("POST", "/api/entropy/analyze", undefined, {
            rawBody: sample,
            contentType: "text/plain",
        });
    }
    async dnsThreatAnalyze(request) {
        const body = typeof request === "string" ? { domain: request } : request;
        return this.request("POST", "/api/dns-threat/analyze", body);
    }
    async dnsThreatSummary() {
        return this.request("GET", "/api/dns-threat/summary");
    }
    async dnsThreatRecord(query) {
        return this.request("POST", "/api/dns-threat/record", query);
    }
    async images() {
        return this.request("GET", "/api/images");
    }
    async imagesSummary() {
        return this.request("GET", "/api/images/summary");
    }
    async imagesCollect() {
        return this.request("POST", "/api/images/collect");
    }
    async configDriftCheck(request) {
        return this.request("POST", "/api/config-drift/check", request);
    }
    async configDriftBaselines() {
        return this.request("GET", "/api/config-drift/baselines");
    }
    async coverageGaps() {
        return this.request("GET", "/api/coverage/gaps");
    }
    async detectorSlowAttack() {
        return this.request("GET", "/api/detectors/slow-attack");
    }
    async detectorRansomware() {
        return this.request("GET", "/api/detectors/ransomware");
    }
    async retentionStatus() {
        return this.request("GET", "/api/retention/status");
    }
    async retentionApply() {
        return this.request("POST", "/api/retention/apply");
    }
    async evidencePlanLinux() {
        return this.request("GET", "/api/evidence/plan/linux");
    }
    async evidencePlanMacos() {
        return this.request("GET", "/api/evidence/plan/macos");
    }
    async evidencePlanWindows() {
        return this.request("GET", "/api/evidence/plan/windows");
    }
    // ── Vulnerability ────────────────────────────────────────────────
    async vulnerabilityScan() {
        return this.request("GET", "/api/vulnerability/scan");
    }
    async vulnerabilitySummary() {
        return this.request("GET", "/api/vulnerability/summary");
    }
    // ── Container ────────────────────────────────────────────────────
    async containerAlerts() {
        return this.request("GET", "/api/container/alerts");
    }
    async containerStats() {
        return this.request("GET", "/api/container/stats");
    }
    // ── Response Actions ─────────────────────────────────────────────
    async responseStats() {
        return this.request("GET", "/api/response/stats");
    }
    async casesStats() {
        return this.request("GET", "/api/cases/stats");
    }
    async platform() {
        return this.request("GET", "/api/platform");
    }
    async sloStatus() {
        return this.request("GET", "/api/slo/status");
    }
    async feedStats() {
        return this.request("GET", "/api/feeds/stats");
    }
    async responseRequests() {
        return this.request("GET", "/api/response/requests");
    }
    async requestResponseAction(action) {
        return this.request("POST", "/api/response/request", action);
    }
    async responseRequest(action) {
        return this.request("POST", "/api/response/request", action);
    }
    async approveResponseAction(requestId, approve = true) {
        return this.request("POST", "/api/response/approve", {
            request_id: requestId,
            decision: approve ? "approved" : "denied",
        });
    }
    async executeApprovedActions(requestId) {
        return this.request("POST", "/api/response/execute", requestId ? { request_id: requestId } : {});
    }
    async responseExecute(requestId) {
        return this.request("POST", "/api/response/execute", requestId ? { request_id: requestId } : {});
    }
    // ── Telemetry ────────────────────────────────────────────────────
    async ingestEvents(agentId, events) {
        return this.request("POST", "/api/events", { agent_id: agentId, events });
    }
    async onboardingReadiness() {
        return this.request("GET", "/api/onboarding/readiness");
    }
    async managerOverview() {
        return this.request("GET", "/api/manager/overview");
    }
    async managerQueueDigest() {
        return this.request("GET", "/api/manager/queue-digest");
    }
    async authSsoConfig() {
        return this.request("GET", "/api/auth/sso/config");
    }
    async authRotate() {
        return this.request("POST", "/api/auth/rotate");
    }
    async assistantStatus() {
        return this.request("GET", "/api/assistant/status");
    }
    async assistantQuery(query) {
        return this.request("POST", "/api/assistant/query", query);
    }
    async detectionExplain(params = {}) {
        const qs = new URLSearchParams();
        if (params.event_id != null)
            qs.set("event_id", String(params.event_id));
        if (params.alert_id)
            qs.set("alert_id", params.alert_id);
        return this.request("GET", `/api/detection/explain${qs.toString() ? `?${qs.toString()}` : ""}`);
    }
    async detectionFeedback(eventId, limit) {
        const qs = new URLSearchParams();
        if (eventId != null)
            qs.set("event_id", String(eventId));
        if (limit != null)
            qs.set("limit", String(limit));
        return this.request("GET", `/api/detection/feedback${qs.toString() ? `?${qs.toString()}` : ""}`);
    }
    async recordDetectionFeedback(feedback) {
        return this.request("POST", "/api/detection/feedback", feedback);
    }
    async detectionProfile() {
        return this.request("GET", "/api/detection/profile");
    }
    async setDetectionProfile(request) {
        return this.request("PUT", "/api/detection/profile", request);
    }
    async normalizeScore() {
        return this.request("GET", "/api/detection/score/normalize");
    }
    // ── Threat Intel ─────────────────────────────────────────────────
    async threatIntelStats() {
        return this.request("GET", "/api/threat-intel/stats");
    }
    async metrics() {
        return this.request("GET", "/api/metrics", undefined, { responseType: "text" });
    }
    async threatIntelStatus() {
        return this.request("GET", "/api/threat-intel/status");
    }
    async addIoc(ioc) {
        return this.request("POST", "/api/threat-intel/ioc", ioc);
    }
    async threatIntelLibraryV2() {
        return this.request("GET", "/api/threat-intel/library/v2");
    }
    async threatIntelSightings(limit = 50) {
        return this.request("GET", `/api/threat-intel/sightings?limit=${limit}`);
    }
    async efficacySummary() {
        return this.request("GET", "/api/efficacy/summary");
    }
    async efficacyRule(id) {
        return this.request("GET", `/api/efficacy/rule/${encodeURIComponent(id)}`);
    }
    async efficacyCanaryPromote() {
        return this.request("POST", "/api/efficacy/canary-promote");
    }
    async investigationWorkflows() {
        return this.request("GET", "/api/investigations/workflows");
    }
    async investigationWorkflow(id) {
        return this.request("GET", `/api/investigations/workflows/${encodeURIComponent(id)}`);
    }
    async investigationStart(request) {
        return this.request("POST", "/api/investigations/start", request);
    }
    async investigationActive() {
        return this.request("GET", "/api/investigations/active");
    }
    async investigationProgress(request) {
        return this.request("POST", "/api/investigations/progress", request);
    }
    async investigationHandoff(request) {
        return this.request("POST", "/api/investigations/handoff", request);
    }
    async investigationSuggest(request) {
        return this.request("POST", "/api/investigations/suggest", request);
    }
    async investigationGraph(request) {
        return this.request("POST", "/api/investigation/graph", request);
    }
    async timelineHost(hostname) {
        return this.request("GET", `/api/timeline/host?hostname=${encodeURIComponent(hostname)}`);
    }
    async timelineAgent(agentId) {
        return this.request("GET", `/api/timeline/agent?agent_id=${encodeURIComponent(agentId)}`);
    }
    async efficacyTriage(record) {
        return this.request("POST", "/api/efficacy/triage", record);
    }
    async fpFeedback(feedback) {
        return this.request("POST", "/api/fp-feedback", feedback);
    }
    async fpFeedbackStats() {
        return this.request("GET", "/api/fp-feedback/stats");
    }
    async mlModels() {
        return this.request("GET", "/api/ml/models");
    }
    async mlModelsStatus() {
        return this.request("GET", "/api/ml/models/status");
    }
    async mlModelStatus() {
        return this.mlModelsStatus();
    }
    async mlModelsRollback() {
        return this.request("POST", "/api/ml/models/rollback");
    }
    async mlRollback() {
        return this.mlModelsRollback();
    }
    async mlShadowRecent(limit = 20) {
        return this.request("GET", `/api/ml/shadow/recent?limit=${limit}`);
    }
    async mlTriage(features) {
        return this.request("POST", "/api/ml/triage", features);
    }
    async mlTriageV2(features) {
        return this.request("POST", "/api/ml/triage/v2", features);
    }
    // ── Campaigns ────────────────────────────────────────────────────
    async campaigns() {
        return this.request("GET", "/api/correlation/campaigns");
    }
}
exports.WardexClient = WardexClient;
exports.default = WardexClient;

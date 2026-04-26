/**
 * Wardex TypeScript SDK
 *
 * Full-typed client for the Wardex XDR REST API.
 */

// ── Errors ───────────────────────────────────────────────────────────────────

/** Base error for all Wardex SDK errors. */
export class WardexError extends Error {
  public readonly statusCode: number | undefined;
  public readonly body: string;

  constructor(message: string, statusCode?: number, body: string = "") {
    super(message);
    this.name = "WardexError";
    this.statusCode = statusCode;
    this.body = body;
  }
}

/** Raised on 401 / 403 responses. */
export class AuthenticationError extends WardexError {
  constructor(message: string, statusCode: number, body: string = "") {
    super(message, statusCode, body);
    this.name = "AuthenticationError";
  }
}

/** Raised on 404 responses. */
export class NotFoundError extends WardexError {
  constructor(message: string, statusCode: number, body: string = "") {
    super(message, statusCode, body);
    this.name = "NotFoundError";
  }
}

/** Raised on 429 responses. */
export class RateLimitError extends WardexError {
  constructor(message: string, statusCode: number, body: string = "") {
    super(message, statusCode, body);
    this.name = "RateLimitError";
  }
}

/** Raised on 5xx responses. */
export class ServerError extends WardexError {
  constructor(message: string, statusCode: number, body: string = "") {
    super(message, statusCode, body);
    this.name = "ServerError";
  }
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface WardexConfig {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
  credentials?: RequestCredentials;
}

export interface Alert {
  timestamp: string;
  hostname: string;
  platform: string;
  score: number;
  confidence: number;
  level: string;
  action: string;
  reasons: string[];
  enforced: boolean;
}

export interface ScanResult {
  verdict: "Clean" | "Suspicious" | "Malicious";
  confidence: number;
  matches: ScanMatch[];
  sha256: string;
  md5: string;
  scanned_bytes: number;
}

export interface ScanMatch {
  source: string;
  name: string;
  severity: string;
}

export interface DetectionEvidence {
  kind: string;
  label: string;
  value: string;
  confidence?: number;
  source?: string;
}

export interface DetectionFeedback {
  id: number;
  event_id?: number;
  alert_id?: string;
  rule_id?: string;
  analyst: string;
  verdict: string;
  reason_pattern?: string;
  notes: string;
  evidence: DetectionEvidence[];
  created_at: string;
}

export interface EntityRiskScore {
  entity_kind: string;
  entity_id: string;
  score: number;
  confidence: number;
  rationale: string[];
}

export interface OnboardingReadinessCheck {
  key: string;
  label: string;
  ready: boolean;
  status: string;
  detail: string;
}

export interface OnboardingReadiness {
  generated_at: string;
  ready: boolean;
  completed: number;
  total: number;
  estimated_minutes: number;
  checks: OnboardingReadinessCheck[];
}

export interface MalwareStaticProfile {
  file_type: string;
  platform_hint: string;
  executable_format: boolean;
  archive_format: boolean;
  script_like: boolean;
  magic: string;
  probable_signed: boolean;
  imports: string[];
  section_hints: string[];
  suspicious_traits: string[];
  trusted_publisher_match?: string;
  internal_tool_match?: string;
  analyst_summary: string[];
}

export interface MalwareBehaviorProfile {
  observed_tactics: string[];
  severity: string;
  allowlist_match?: string;
  recommended_actions: string[];
}

export interface DeepScanResult {
  scan: unknown;
  static_profile: MalwareStaticProfile;
  behavior_profile: MalwareBehaviorProfile;
  analyst_summary: string[];
}

export interface MalwareStats {
  total_hashes: number;
  total_families: number;
  total_scans: number;
  total_malicious: number;
  total_suspicious: number;
  yara_rules: number;
}

export interface PlaybookExecution {
  execution_id: string;
  playbook_id: string;
  status: string;
  started_at: number;
  finished_at?: number;
  step_results: StepResult[];
}

export interface StepResult {
  step_id: string;
  status: string;
  output?: string;
  error?: string;
}

export interface SearchResult {
  total: number;
  hits: SearchHit[];
  took_ms: number;
  query: string;
}

export interface SearchHit {
  score: number;
  timestamp: string;
  device_id: string;
  event_class: string;
  process_name: string;
  src_ip: string;
  dst_ip: string;
  snippet: string;
}

export interface ComplianceReport {
  framework_id: string;
  framework_name: string;
  generated_at: string;
  total_controls: number;
  passed: number;
  failed: number;
  score_percent: number;
  findings: ControlFinding[];
}

export interface ControlFinding {
  control_id: string;
  title: string;
  status: "pass" | "fail" | "not_applicable" | "manual_review";
  evidence: string;
  remediation: string;
}

export interface BackupRecord {
  name: string;
  timestamp: string;
  size_bytes: number;
  checksum: string;
  verified: boolean;
}

export interface AuditVerifyReport {
  intact: boolean;
  record_count: number;
  checkpoint_count: number;
  head_hash?: string;
  error?: string;
}

export interface AnalyticsSummary {
  total_requests: number;
  total_errors: number;
  error_rate: number;
  unique_endpoints: number;
  top_endpoints: EndpointMetrics[];
}

export interface EndpointMetrics {
  path: string;
  method: string;
  request_count: number;
  error_count: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
}

export interface HealthStatus {
  status: string;
  version: string;
  uptime_secs: number;
}

interface RequestOptions {
  responseType?: "json" | "text";
}

// ── Client ───────────────────────────────────────────────────────────────────

export class WardexClient {
  private baseUrl: string;
  private apiKey?: string;
  private timeout: number;
  private credentials?: RequestCredentials;

  constructor(config: WardexConfig) {
    if (!/^https?:\/\//i.test(config.baseUrl)) {
      throw new Error("baseUrl must start with http:// or https://");
    }
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? 30000;
    this.credentials = config.credentials;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
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

      if (options?.responseType === "text") {
        return (await resp.text()) as T;
      }

      const ct = resp.headers.get("content-type") ?? "";
      if (!ct.includes("application/json")) {
        const text = await resp.text().catch(() => "");
        throw new WardexError(
          `Expected JSON response, got ${ct || "unknown"}`,
          resp.status,
          text
        );
      }

      return (await resp.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Health ───────────────────────────────────────────────────────

  async health(): Promise<HealthStatus> {
    return this.request("GET", "/api/health");
  }

  async authSession(): Promise<unknown> {
    return this.request("GET", "/api/auth/session");
  }

  async createAuthSession(): Promise<unknown> {
    return this.request("POST", "/api/auth/session");
  }

  async openApiSpec(): Promise<unknown> {
    return this.request("GET", "/api/openapi.json");
  }

  async supportParity(): Promise<unknown> {
    return this.request("GET", "/api/support/parity");
  }

  async readinessEvidence(): Promise<unknown> {
    return this.request("GET", "/api/support/readiness-evidence");
  }

  async firstRunProof(): Promise<unknown> {
    return this.request("POST", "/api/support/first-run-proof");
  }

  // ── Alerts ───────────────────────────────────────────────────────

  async alerts(): Promise<Alert[]> {
    return this.request("GET", "/api/alerts");
  }

  // ── Malware Scanning ─────────────────────────────────────────────

  async scanBuffer(
    data: Uint8Array | string,
    filename?: string
  ): Promise<ScanResult> {
    const b64 =
      typeof data === "string"
        ? data
        : Buffer.from(data).toString("base64");
    return this.request("POST", "/api/scan/buffer", {
      data: b64,
      filename: filename ?? "upload",
    });
  }

  async scanHash(hash: string): Promise<ScanResult> {
    return this.request("POST", "/api/scan/hash", { hash });
  }

  async scanBufferV2(
    data: Uint8Array | string,
    filename?: string,
    behavior?: Record<string, unknown>,
    allowlist?: Record<string, unknown>
  ): Promise<DeepScanResult> {
    const b64 =
      typeof data === "string"
        ? data
        : Buffer.from(data).toString("base64");
    return this.request("POST", "/api/scan/buffer/v2", {
      data: b64,
      filename: filename ?? "upload",
      behavior,
      allowlist,
    });
  }

  async malwareStats(): Promise<MalwareStats> {
    return this.request("GET", "/api/malware/stats");
  }

  async malwareRecent(): Promise<ScanMatch[]> {
    return this.request("GET", "/api/malware/recent");
  }

  async collectorsStatus(): Promise<unknown> {
    return this.request("GET", "/api/collectors/status");
  }

  async remediationChangeReviews(): Promise<unknown> {
    return this.request("GET", "/api/remediation/change-reviews");
  }

  async recordRemediationChangeReview(review: unknown): Promise<unknown> {
    return this.request("POST", "/api/remediation/change-reviews", review);
  }

  async approveRemediationChangeReview(id: string, approval: unknown): Promise<unknown> {
    return this.request(
      "POST",
      `/api/remediation/change-reviews/${encodeURIComponent(id)}/approval`,
      approval,
    );
  }

  async malwareImport(data: string): Promise<{ imported: number }> {
    return this.request("POST", "/api/malware/signatures/import", { data });
  }

  // ── Search & Hunt ────────────────────────────────────────────────

  async search(query: string, limit?: number): Promise<SearchResult> {
    return this.request("POST", "/api/search", {
      query,
      limit: limit ?? 50,
    });
  }

  async hunt(query: string): Promise<SearchResult> {
    return this.request("POST", "/api/hunt", { query });
  }

  // ── Playbooks ────────────────────────────────────────────────────

  async listPlaybooks(): Promise<unknown[]> {
    return this.request("GET", "/api/playbooks");
  }

  async runPlaybook(
    playbookId: string,
    alertId?: string,
    variables?: Record<string, string>
  ): Promise<PlaybookExecution> {
    return this.request("POST", "/api/playbooks/run", {
      playbook_id: playbookId,
      alert_id: alertId,
      variables: variables ?? {},
    });
  }

  async playbookExecution(executionId: string): Promise<PlaybookExecution> {
    return this.request("GET", `/api/playbooks/executions/${encodeURIComponent(executionId)}`);
  }

  // ── Compliance ───────────────────────────────────────────────────

  async complianceReport(
    frameworkId?: string
  ): Promise<ComplianceReport | ComplianceReport[]> {
    const path = frameworkId
      ? `/api/compliance/report?framework=${encodeURIComponent(frameworkId)}`
      : "/api/compliance/report";
    return this.request("GET", path);
  }

  async complianceSummary(): Promise<unknown> {
    return this.request("GET", "/api/compliance/summary");
  }

  // ── SIEM Export ──────────────────────────────────────────────────

  async exportAlerts(
    format: "cef" | "syslog" | "leef" | "json" | "ecs" | "udm"
  ): Promise<string> {
    return this.request(
      "GET",
      `/api/export/alerts?format=${encodeURIComponent(format)}`,
      undefined,
      { responseType: "text" }
    );
  }

  // ── Backups ──────────────────────────────────────────────────────

  async listBackups(): Promise<BackupRecord[]> {
    return this.request("GET", "/api/backups");
  }

  async createBackup(): Promise<BackupRecord> {
    return this.request("POST", "/api/backups");
  }

  // ── Audit ────────────────────────────────────────────────────────

  async auditVerify(): Promise<AuditVerifyReport> {
    return this.request("GET", "/api/audit/verify");
  }

  async auditLogs(limit?: number): Promise<unknown[]> {
    return this.request("GET", `/api/audit/logs?limit=${limit ?? 100}`);
  }

  // ── Analytics ────────────────────────────────────────────────────

  async apiAnalytics(): Promise<AnalyticsSummary> {
    return this.request("GET", "/api/analytics");
  }

  // ── Dedup ────────────────────────────────────────────────────────

  async dedupAlerts(): Promise<unknown[]> {
    return this.request("GET", "/api/alerts/dedup");
  }

  // ── UEBA ─────────────────────────────────────────────────────────

  async uebaRiskyEntities(): Promise<unknown[]> {
    return this.request("GET", "/api/ueba/risky-entities");
  }

  async uebaAnomalies(limit?: number): Promise<unknown[]> {
    return this.request("GET", `/api/ueba/anomalies?limit=${limit ?? 50}`);
  }

  async uebaPeerGroups(): Promise<unknown[]> {
    return this.request("GET", "/api/ueba/peer-groups");
  }

  async uebaEntity(entityId: string): Promise<unknown> {
    return this.request("GET", `/api/ueba/entity/${encodeURIComponent(entityId)}`);
  }

  async uebaTimeline(entityId: string, hours?: number): Promise<unknown[]> {
    return this.request("GET", `/api/ueba/timeline/${encodeURIComponent(entityId)}?hours=${hours ?? 24}`);
  }

  // ── NDR ──────────────────────────────────────────────────────────

  async ndrReport(): Promise<unknown> {
    return this.request("GET", "/api/ndr/report");
  }

  async ndrIngest(netflow: Record<string, unknown>): Promise<unknown> {
    return this.request("POST", "/api/ndr/netflow", netflow);
  }

  async ndrTlsAnomalies(): Promise<unknown[]> {
    return this.request("GET", "/api/ndr/tls-anomalies");
  }

  async ndrDpiAnomalies(): Promise<unknown[]> {
    return this.request("GET", "/api/ndr/dpi-anomalies");
  }

  async ndrEntropyAnomalies(): Promise<unknown[]> {
    return this.request("GET", "/api/ndr/entropy-anomalies");
  }

  async ndrSelfSignedCerts(): Promise<unknown[]> {
    return this.request("GET", "/api/ndr/self-signed-certs");
  }

  async ndrTopTalkers(limit?: number): Promise<unknown[]> {
    return this.request("GET", `/api/ndr/top-talkers?limit=${limit ?? 20}`);
  }

  async ndrProtocolDistribution(): Promise<unknown> {
    return this.request("GET", "/api/ndr/protocol-distribution");
  }

  // ── Email Security ───────────────────────────────────────────────

  async emailAnalyze(headers: string): Promise<unknown> {
    return this.request("POST", "/api/email/analyze", { headers });
  }

  async emailQuarantine(limit?: number): Promise<unknown[]> {
    return this.request("GET", `/api/email/quarantine?limit=${limit ?? 50}`);
  }

  async emailQuarantineRelease(messageId: string): Promise<unknown> {
    return this.request("POST", `/api/email/quarantine/${encodeURIComponent(messageId)}/release`);
  }

  async emailQuarantineDelete(messageId: string): Promise<unknown> {
    return this.request("DELETE", `/api/email/quarantine/${encodeURIComponent(messageId)}`);
  }

  async emailStats(): Promise<unknown> {
    return this.request("GET", "/api/email/stats");
  }

  async emailPolicies(): Promise<unknown[]> {
    return this.request("GET", "/api/email/policies");
  }

  // ── Incidents ────────────────────────────────────────────────────

  async listIncidents(): Promise<unknown[]> {
    return this.request("GET", "/api/incidents");
  }

  async getIncident(incidentId: string): Promise<unknown> {
    return this.request("GET", `/api/incidents/${encodeURIComponent(incidentId)}`);
  }

  async createIncident(title: string, severity: string, summary?: string): Promise<unknown> {
    return this.request("POST", "/api/incidents", { title, severity, summary: summary ?? "" });
  }

  // ── Fleet ────────────────────────────────────────────────────────

  async listAgents(): Promise<unknown[]> {
    return this.request("GET", "/api/agents");
  }

  async getAgent(agentId: string): Promise<unknown> {
    return this.request("GET", `/api/agents/${encodeURIComponent(agentId)}/details`);
  }

  // ── Policy ───────────────────────────────────────────────────────

  async currentPolicy(): Promise<unknown> {
    return this.request("GET", "/api/policy/current");
  }

  async publishPolicy(policy: Record<string, unknown>): Promise<unknown> {
    return this.request("POST", "/api/policy/publish", policy);
  }

  // ── Assets ───────────────────────────────────────────────────────

  async assets(): Promise<unknown[]> {
    return this.request("GET", "/api/assets");
  }

  async assetsSummary(): Promise<unknown> {
    return this.request("GET", "/api/assets/summary");
  }

  async upsertAsset(asset: Record<string, unknown>): Promise<unknown> {
    return this.request("POST", "/api/assets/upsert", asset);
  }

  // ── Vulnerability ────────────────────────────────────────────────

  async vulnerabilityScan(): Promise<unknown> {
    return this.request("GET", "/api/vulnerability/scan");
  }

  async vulnerabilitySummary(): Promise<unknown> {
    return this.request("GET", "/api/vulnerability/summary");
  }

  // ── Container ────────────────────────────────────────────────────

  async containerAlerts(): Promise<unknown[]> {
    return this.request("GET", "/api/container/alerts");
  }

  async containerStats(): Promise<unknown> {
    return this.request("GET", "/api/container/stats");
  }

  // ── Response Actions ─────────────────────────────────────────────

  async requestResponseAction(action: Record<string, unknown>): Promise<unknown> {
    return this.request("POST", "/api/response/request", action);
  }

  async approveResponseAction(requestId: string, approve: boolean = true): Promise<unknown> {
    return this.request("POST", "/api/response/approve", {
      request_id: requestId,
      decision: approve ? "approve" : "deny",
    });
  }

  async executeApprovedActions(requestId?: string): Promise<unknown> {
    return this.request("POST", "/api/response/execute", requestId ? { request_id: requestId } : {});
  }

  // ── Telemetry ────────────────────────────────────────────────────

  async ingestEvents(agentId: string, events: Record<string, unknown>[]): Promise<unknown> {
    return this.request("POST", "/api/events", { agent_id: agentId, events });
  }

  async onboardingReadiness(): Promise<OnboardingReadiness> {
    return this.request("GET", "/api/onboarding/readiness");
  }

  async managerQueueDigest(): Promise<unknown> {
    return this.request("GET", "/api/manager/queue-digest");
  }

  async detectionExplain(
    params: { event_id?: number; alert_id?: string } = {}
  ): Promise<unknown> {
    const qs = new URLSearchParams();
    if (params.event_id != null) qs.set("event_id", String(params.event_id));
    if (params.alert_id) qs.set("alert_id", params.alert_id);
    return this.request("GET", `/api/detection/explain${qs.toString() ? `?${qs.toString()}` : ""}`);
  }

  async detectionFeedback(eventId?: number): Promise<{ items: DetectionFeedback[] }> {
    const qs = new URLSearchParams();
    if (eventId != null) qs.set("event_id", String(eventId));
    return this.request(
      "GET",
      `/api/detection/feedback${qs.toString() ? `?${qs.toString()}` : ""}`
    );
  }

  async recordDetectionFeedback(
    feedback: Omit<DetectionFeedback, "id" | "created_at">
  ): Promise<DetectionFeedback> {
    return this.request("POST", "/api/detection/feedback", feedback);
  }

  // ── Threat Intel ─────────────────────────────────────────────────

  async threatIntelStatus(): Promise<unknown> {
    return this.request("GET", "/api/threat-intel/status");
  }

  async addIoc(ioc: Record<string, unknown>): Promise<unknown> {
    return this.request("POST", "/api/threat-intel/ioc", ioc);
  }

  async threatIntelLibraryV2(): Promise<unknown> {
    return this.request("GET", "/api/threat-intel/library/v2");
  }

  async threatIntelSightings(limit: number = 50): Promise<unknown> {
    return this.request("GET", `/api/threat-intel/sightings?limit=${limit}`);
  }

  async mlModelStatus(): Promise<unknown> {
    return this.request("GET", "/api/ml/models/status");
  }

  async mlRollback(): Promise<unknown> {
    return this.request("POST", "/api/ml/models/rollback");
  }

  async mlShadowRecent(limit: number = 20): Promise<unknown> {
    return this.request("GET", `/api/ml/shadow/recent?limit=${limit}`);
  }

  async mlTriageV2(features: Record<string, unknown>): Promise<unknown> {
    return this.request("POST", "/api/ml/triage/v2", features);
  }

  // ── Campaigns ────────────────────────────────────────────────────

  async campaigns(): Promise<unknown> {
    return this.request("GET", "/api/campaigns");
  }
}

export default WardexClient;

/**
 * Wardex SentinelEdge TypeScript SDK
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

// ── Client ───────────────────────────────────────────────────────────────────

export class WardexClient {
  private baseUrl: string;
  private apiKey?: string;
  private timeout: number;

  constructor(config: WardexConfig) {
    if (!/^https?:\/\//i.test(config.baseUrl)) {
      throw new Error("baseUrl must start with http:// or https://");
    }
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? 30000;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
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

      return (await resp.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Health ───────────────────────────────────────────────────────

  async health(): Promise<HealthStatus> {
    return this.request("GET", "/api/health");
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

  async malwareStats(): Promise<MalwareStats> {
    return this.request("GET", "/api/malware/stats");
  }

  async malwareRecent(): Promise<ScanMatch[]> {
    return this.request("GET", "/api/malware/recent");
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
    return this.request("GET", `/api/export/alerts?format=${encodeURIComponent(format)}`);
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
}

export default WardexClient;

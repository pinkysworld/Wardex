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
  sample: EventTelemetrySample;
  enforced: boolean;
  mitre: MitreAttack[];
  narrative?: EventAlertNarrative | null;
  id: number;
  _index: number;
  entities: ExtractedEntity[];
  process_resolution: AlertProcessResolution;
  process_names?: string[];
  process_candidates?: AlertProcessPivot[];
  process?: AlertProcessPivot | null;
}

export interface AlertSeverityCounts {
  total: number;
  critical: number;
  severe: number;
  elevated: number;
}

export interface AlertDetailAnalysis {
  severity_class: "critical" | "severe" | "elevated";
  multi_axis: boolean;
  axis_count: number;
  recommendation: string;
}

export interface AlertDetail {
  id: number;
  index: number;
  timestamp: string;
  hostname: string;
  platform: string;
  score: number;
  confidence: number;
  level: string;
  action: string;
  reasons: string[];
  enforced: boolean;
  sample: EventTelemetrySample;
  analysis: AlertDetailAnalysis;
}

export type AlertPattern =
  | "Baseline"
  | "Escalating"
  | "Mixed"
  | {
      PeriodicBursts: {
        avg_interval_secs: number;
        burst_severity: string;
      };
    }
  | {
      Sustained: {
        severity: string;
      };
    };

export type ScoreTrend =
  | "Stable"
  | "Volatile"
  | {
      Rising: {
        slope: number;
      };
    }
  | {
      Falling: {
        slope: number;
      };
    };

export type AlertReasonCount = [string, number];

export interface AlertCluster {
  start: string;
  end: string;
  count: number;
  avg_score: number;
  max_score: number;
  representative_reasons: string[];
  level: string;
}

export interface AlertAnomaly {
  index: number;
  timestamp: string;
  score: number;
  reasons: string[];
  deviation_from_mean: number;
}

export interface SeverityBreakdown {
  critical: number;
  severe: number;
  elevated: number;
}

export interface IsolationGuidance {
  reason: string;
  threat_description: string;
  steps: string[];
}

export interface AlertAnalysis {
  window_start: string;
  window_end: string;
  total_alerts: number;
  pattern: AlertPattern;
  score_trend: ScoreTrend;
  dominant_reasons: AlertReasonCount[];
  clusters: AlertCluster[];
  anomalies: AlertAnomaly[];
  severity_breakdown: SeverityBreakdown;
  isolation_guidance: IsolationGuidance[];
  summary: string;
}

export interface AlertAnalysisRequest {
  window_minutes?: number;
}

export interface AlertGroup {
  id: number;
  first_seen: string;
  last_seen: string;
  count: number;
  avg_score: number;
  max_score: number;
  level: string;
  reason_fingerprint: string;
  representative_reasons: string[];
  indices: number[];
}

export type SampleAlertSeverity = "elevated" | "severe" | "critical";

export interface SampleAlertRequest {
  severity?: SampleAlertSeverity;
}

export interface SampleAlertResponse {
  status: "injected";
  severity: SampleAlertSeverity;
  score: number;
}

export interface AlertBulkActionRequest {
  ids: string[];
}

export interface AlertBulkAcknowledgeResponse {
  status: "ok";
  acknowledged: number;
  not_found: number;
  total_requested: number;
}

export interface AlertBulkResolveResponse {
  status: "ok";
  resolved: number;
  not_found: number;
  total_requested: number;
}

export interface AlertBulkCloseResponse {
  status: "ok";
  closed: number;
  not_found: number;
  total_requested: number;
}

export interface ClearAlertsResponse {
  status: "cleared";
  count: number;
}

export interface DedupAutoCreateResponse {
  status: "ok";
  created_incidents: string[];
  count: number;
}

export type EntityType =
  | "IpAddress"
  | "Domain"
  | "FilePath"
  | "ProcessName"
  | "Port"
  | "HashSha256"
  | "HashMd5"
  | "MitreTechnique"
  | "Username"
  | "Hostname";

export interface ExtractedEntity {
  entity_type: EntityType;
  value: string;
  start: number;
  end: number;
}

export type AlertProcessResolution =
  | "none"
  | "unique"
  | "multiple"
  | "remote_host"
  | "unresolved";

export interface AlertProcessPivot {
  pid: number;
  ppid?: number | null;
  name: string;
  display_name: string;
  user?: string | null;
  group?: string | null;
  cpu_percent?: number | null;
  mem_percent?: number | null;
  hostname: string;
  platform: string;
  cmd_line?: string | null;
  exe_path?: string | null;
}

export interface EventTelemetrySample {
  timestamp_ms: number;
  cpu_load_pct: number;
  memory_load_pct: number;
  temperature_c: number;
  network_kbps: number;
  auth_failures: number;
  battery_pct: number;
  integrity_drift: number;
  process_count: number;
  disk_pressure_pct: number;
}

export interface EventAlertNarrative {
  headline: string;
  summary: string;
  observations: string[];
  baseline_comparison?: string | null;
  time_window?: string | null;
  involved_entities: string[];
  suggested_queries: string[];
}

export interface EventAlertRecord {
  timestamp: string;
  hostname: string;
  platform: string;
  score: number;
  confidence: number;
  level: string;
  action: string;
  reasons: string[];
  sample: EventTelemetrySample;
  enforced: boolean;
  mitre: MitreAttack[];
  narrative?: EventAlertNarrative | null;
}

export interface EventCorrelationMatch {
  reason: string;
  agents: string[];
  event_ids: number[];
  severity: string;
  description: string;
}

export interface EventIngestResponse {
  ingested: number;
  total: number;
  correlations: EventCorrelationMatch[];
  sigma_matches?: number;
}

export interface OpenApiContact {
  name?: string | null;
  url?: string | null;
}

export interface OpenApiLicense {
  name: string;
  url?: string | null;
}

export interface OpenApiInfo {
  title: string;
  version: string;
  description?: string | null;
  license?: OpenApiLicense | null;
  contact?: OpenApiContact | null;
}

export interface OpenApiServer {
  url: string;
  description?: string | null;
}

export interface OpenApiTag {
  name: string;
  description?: string | null;
}

export interface OpenApiPathItem {
  get?: Record<string, unknown>;
  post?: Record<string, unknown>;
  put?: Record<string, unknown>;
  delete?: Record<string, unknown>;
  patch?: Record<string, unknown>;
}

export interface OpenApiSpecDocument {
  openapi: string;
  info: OpenApiInfo;
  servers?: OpenApiServer[];
  paths: Record<string, OpenApiPathItem>;
  components: Record<string, unknown>;
  security?: Record<string, string[]>[];
  tags?: OpenApiTag[];
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

export interface DetectionFeedbackSummary {
  total: number;
  by_verdict: Record<string, number>;
  analysts: number;
}

export interface DetectionFeedbackListResponse {
  items: DetectionFeedback[];
  summary: DetectionFeedbackSummary;
}

export interface DetectionExplainability {
  event_id?: number | null;
  alert_id?: string | null;
  severity: string;
  title: string;
  summary: string[];
  why_fired: string[];
  why_safe_or_noisy: string[];
  next_steps: string[];
  evidence: DetectionEvidence[];
  entity_scores: EntityRiskScore[];
  triage_status?: string | null;
  related_cases: string[];
  feedback: DetectionFeedback[];
}

export type DetectionProfileName = "aggressive" | "balanced" | "quiet";

export interface DetectionProfileResponse {
  profile: DetectionProfileName;
  description: string;
  threshold_multiplier: number;
  learn_threshold: number;
}

export interface SetDetectionProfileRequest {
  profile: DetectionProfileName;
}

export interface SetDetectionProfileResponse {
  profile: DetectionProfileName;
  applied: boolean;
}

export type NormalizedScoreSeverity = "info" | "low" | "medium" | "high" | "critical";

export type NormalizedScoreConfidence = "low" | "medium" | "high";

export interface NormalizedScore {
  raw_score: number;
  normalized: number;
  severity: NormalizedScoreSeverity;
  confidence: NormalizedScoreConfidence;
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

export type AuthSessionRole = "admin" | "analyst" | "viewer" | "service_account";

export type AuthSessionSource = "anonymous" | "admin_token" | "rbac_token" | "session";

export interface AuthCheckResponse {
  status: string;
  ttl_secs: number;
  remaining_secs: number;
  token_age_secs: number;
}

export interface AuthSession {
  user_id: string;
  role: AuthSessionRole;
  groups: string[];
  authenticated: boolean;
  source: AuthSessionSource;
}

export interface AuthSessionCookie {
  http_only: boolean;
  same_site: string;
  secure: boolean;
}

export interface AuthSessionCreateResponse extends AuthSession {
  expires_at: string;
  cookie: AuthSessionCookie;
}

export interface LogoutResponse {
  logged_out: boolean;
  session_revoked: boolean;
}

export interface SessionInfo {
  uptime_secs: number;
  token_age_secs: number;
  token_ttl_secs: number;
  token_expired: boolean;
  mtls_required: boolean;
}

export interface SupportParitySdkEntry {
  package: string;
  version: string;
  aligned: boolean;
}

export interface SupportParityRuntime {
  version: string;
  release_version: string;
  docs_version: string;
}

export interface SupportParityRest {
  openapi_version: string;
  openapi_path_count: number;
  endpoint_catalog_count: number;
  authenticated_endpoints: number;
  public_endpoints: number;
}

export interface SupportParityGraphql {
  documented: boolean;
  query_type: string;
  types: number;
  root_fields: string[];
  supports_introspection: boolean;
}

export interface SupportParitySdk {
  python: SupportParitySdkEntry;
  typescript: SupportParitySdkEntry;
}

export interface SupportParityResponse {
  generated_at: string;
  runtime: SupportParityRuntime;
  rest: SupportParityRest;
  graphql: SupportParityGraphql;
  sdk: SupportParitySdk;
  issues: string[];
}

export interface SupportReadinessVersion {
  package: string;
  runtime: string;
  edition: string;
}

export interface SupportReadinessConfigPosture {
  config_path: string;
  monitoring_enabled: boolean;
  siem_enabled: boolean;
  taxii_enabled: boolean;
  clickhouse_enabled: boolean;
  rate_limit_read_per_minute: number;
  rate_limit_write_per_minute: number;
}

export interface SupportReadinessAuth {
  token_ttl_secs: number;
  token_age_secs: number;
  rbac_users: number;
  idp_provider_count: number;
  session_store: string;
}

export interface SupportReadinessTls {
  enabled: boolean;
  mtls_required_for_agents: boolean;
  agent_ca_cert_path: string | null;
}

export interface SupportReadinessStorage {
  backend: string;
  stats: Record<string, unknown> | null;
  event_persistence: boolean;
  event_store_path: string;
}

export interface SupportReadinessRetention {
  audit_max_records: number;
  alert_max_records: number;
  event_max_records: number;
  audit_max_age_secs: number;
  remote_syslog_endpoint: string | null;
}

export interface SupportReadinessBackup {
  enabled: boolean;
  path: string;
  retention_count: number;
  observed_backups: number;
}

export interface SupportReadinessAuditChain {
  status: string;
  storage_chain_length: number | null;
}

export interface SupportCollectorPivot {
  surface: string;
  href: string;
  label: string;
}

export interface SupportCollectorIngestionEvidence {
  pivots: SupportCollectorPivot[];
  recent_runs: Record<string, unknown>[];
}

export interface SupportCollectorReadinessEntry {
  provider: string;
  label: string;
  lane: string;
  enabled: boolean;
  last_success_at: string | null;
  last_error_at: string | null;
  error_category: string | null;
  events_ingested: number;
  lag_seconds: number | null;
  checkpoint_id: string | null;
  retry_count: number;
  backoff_seconds: number;
  lifecycle_analytics: Record<string, unknown>;
  ingestion_evidence: SupportCollectorIngestionEvidence;
}

export interface SupportCollectorReadinessSummary {
  enabled: number;
  configured: number;
  collectors: SupportCollectorReadinessEntry[];
}

export interface SupportReadinessResponseHistory {
  requests: number;
  closed_or_reopenable: number;
  audit_entries: number;
}

export interface SupportReadinessEvidenceStats {
  stored_reports: number;
  reports_with_artifact_metadata: number;
  report_runs: number;
}

export interface SupportReadinessContracts {
  status: string;
  parity_issue_count: number;
  parity: SupportParityResponse;
}

export interface SupportExperimentalSurface {
  name: string;
  status: string;
  gate: string;
}

export interface SupportReadinessEvidence {
  generated_at: string;
  status: string;
  version: SupportReadinessVersion;
  config_posture: SupportReadinessConfigPosture;
  auth: SupportReadinessAuth;
  tls: SupportReadinessTls;
  storage: SupportReadinessStorage;
  retention: SupportReadinessRetention;
  backup: SupportReadinessBackup;
  audit_chain: SupportReadinessAuditChain;
  collectors: SupportCollectorReadinessSummary;
  response_history: SupportReadinessResponseHistory;
  evidence: SupportReadinessEvidenceStats;
  contracts: SupportReadinessContracts;
  experimental_surfaces: SupportExperimentalSurface[];
  known_limitations: string[];
}

export interface SupportReadinessEvidenceResponse {
  digest: string;
  evidence: SupportReadinessEvidence;
}

export interface SupportDiagnosticsSession {
  token_ttl_secs: number;
  token_age_secs: number;
}

export interface SupportDiagnosticsAuth {
  session: SupportDiagnosticsSession;
  rbac_users: number;
  idp_providers: Record<string, unknown>[];
  scim: Record<string, unknown>;
}

export interface SupportDiagnosticsContent {
  builtin_rules: number;
  native_rules: number;
  packs: Record<string, unknown>[];
  hunts: Record<string, unknown>[];
  suppressions: Record<string, unknown>[];
}

export interface SupportDiagnosticsEventAnalytics {
  correlation_rate: number;
  severity_counts: Record<string, number>;
  triage_counts: Record<string, number>;
  hot_agents: Record<string, unknown>[];
}

export interface SupportDiagnosticsOperations {
  metrics: Record<string, unknown>;
  request_count: number;
  error_count: number;
  queue_depth: number;
  event_count: number;
  incident_count: number;
  cases_count: Record<string, unknown>;
  event_analytics: SupportDiagnosticsEventAnalytics;
}

export interface SupportDiagnosticsDependencies {
  storage_path: string;
  event_persistence: boolean;
  siem: SiemStatus;
  connectors: Record<string, unknown>[];
  updates: Record<string, unknown>[];
}

export interface SupportDiagnosticsBundle {
  generated_at: string;
  auth: SupportDiagnosticsAuth;
  content: SupportDiagnosticsContent;
  operations: SupportDiagnosticsOperations;
  dependencies: SupportDiagnosticsDependencies;
  change_control: Record<string, unknown>[];
}

export interface SupportDiagnosticsResponse {
  bundle: SupportDiagnosticsBundle;
  digest: string;
}

export interface FirstRunProofTelemetry {
  samples: number;
  alerts: number;
  critical: number;
}

export interface FirstRunProofArtifactMetadata {
  report: Record<string, unknown> | null;
  support_run: Record<string, unknown> | null;
}

export interface FirstRunProofStep {
  name: string;
  status: string;
}

export interface FirstRunProof {
  status: string;
  estimated_minutes: number;
  generated_at: string;
  actor: string;
  case_id: number;
  report_id: number;
  report_run_id: string;
  response_request_id: string;
  response_status: string;
  telemetry: FirstRunProofTelemetry;
  artifact_metadata: FirstRunProofArtifactMetadata;
  demo_surfaces: Record<string, Record<string, unknown>>;
  response_history: ResponseRequestRecord | null;
  steps: FirstRunProofStep[];
}

export interface FirstRunProofResponse {
  proof: FirstRunProof;
  digest: string;
}

export interface SupportDocEntry {
  path: string;
  title: string;
  section: string;
  kind: string;
  tags: string[];
  summary: string;
  headings: string[];
  score: number;
}

export interface DocsIndexParams {
  q?: string;
  section?: string;
  limit?: number;
}

export interface DocsIndexResponse {
  version: string;
  generated_at: string;
  query: string;
  section: string;
  total: number;
  items: SupportDocEntry[];
}

export interface DocContentResponse {
  version: string;
  generated_at: string;
  path: string;
  title: string;
  section: string;
  kind: string;
  tags: string[];
  summary: string;
  headings: string[];
  content: string;
}

export interface SystemHealthStorage {
  backend: string;
  durable: boolean;
  path: string;
  event_count: number;
}

export interface SystemHealthHaMode {
  mode: string;
  status: string;
  leader: boolean;
}

export interface SystemHealthIdentity {
  providers_enabled: number;
  scim_enabled: boolean;
  status: string;
}

export interface SystemHealthConnectors {
  enabled: number;
  unhealthy: number;
  items: Record<string, unknown>[];
}

export interface SystemHealthDeployments {
  pending: number;
  stale_agents: number;
  compliant_agents: number;
  health_gate: string;
}

export interface SystemHealthDependenciesResponse {
  storage: SystemHealthStorage;
  ha_mode: SystemHealthHaMode;
  identity: SystemHealthIdentity;
  connectors: SystemHealthConnectors;
  deployments: SystemHealthDeployments;
  telemetry: Record<string, unknown>;
}

export interface WsConnectionStats {
  subscriber_id: number;
  uptime_secs: number;
  frames_sent: number;
  frames_received: number;
}

export interface WsStatsResponse {
  connected_clients: number;
  total_events: number;
  subscribers: number;
  native_websocket_supported: boolean;
  connections: WsConnectionStats[];
}

export type CommandCenterLaneName =
  | "incidents"
  | "remediation"
  | "connectors"
  | "rule_tuning"
  | "release"
  | "evidence";

export type CommandCenterMetricKey =
  | "open_incidents"
  | "pending_remediation_reviews"
  | "connector_issues"
  | "noisy_rules"
  | "release_candidates"
  | "compliance_packs";

export interface CommandCenterMetrics {
  open_incidents: number;
  active_cases: number;
  pending_remediation_reviews: number;
  rollback_ready_reviews: number;
  connector_issues: number;
  noisy_rules: number;
  stale_rules: number;
  release_candidates: number;
  compliance_packs: number;
  offline_agents: number;
}

export interface CommandCenterLanePayload {
  status: string;
  annotation: string;
  next_step: string;
  href?: string;
  count?: number;
  pending?: number;
  rollback_ready?: number;
  issues?: number;
  readiness?: Record<string, unknown>;
  planned?: string[];
  noisy?: number;
  stale?: number;
  active_suppressions?: number;
  candidates?: number;
  current_version?: string;
  score?: number;
  templates?: number;
}

export interface CommandCenterLanes {
  incidents: CommandCenterLanePayload;
  remediation: CommandCenterLanePayload;
  connectors: CommandCenterLanePayload;
  rule_tuning: CommandCenterLanePayload;
  release: CommandCenterLanePayload;
  evidence: CommandCenterLanePayload;
}

export interface CommandSummaryResponse {
  generated_at: string;
  metrics: CommandCenterMetrics;
  lanes: CommandCenterLanes;
}

export interface CommandLaneResponse {
  lane: CommandCenterLaneName;
  generated_at: string;
  metric_key: CommandCenterMetricKey;
  metric_value: number;
  payload: CommandCenterLanePayload;
}

export interface QueueAlertSummary {
  event_id: number;
  agent_id: string | null;
  score: number;
  severity: string;
  hostname: string;
  status: string;
  assignee: string | null;
  timestamp: string;
  age_secs: number | null;
  sla_deadline: string | null;
  sla_breached: boolean;
  reasons: string[];
}

export interface UrgentItem {
  kind: string;
  severity: string;
  title: string;
  subtitle: string;
  reference_id: string;
}

export interface ManagerQueueOverview {
  pending: number;
  acknowledged: number;
  assigned: number;
  sla_breached: number;
  critical_pending: number;
}

export interface ManagerFleetOverview {
  total_agents: number;
  online: number;
  stale: number;
  offline: number;
  coverage_pct: number;
}

export interface ManagerIncidentOverview {
  total: number;
  open: number;
  investigating: number;
  contained: number;
  resolved: number;
  false_positive: number;
}

export interface ManagerDeploymentOverview {
  published_releases: number;
  pending: number;
  by_status: Record<string, number>;
  by_ring: Record<string, number>;
}

export interface ManagerReportOverview {
  total_reports: number;
  total_alerts: number;
  critical_alerts: number;
  avg_score: number | null;
  max_score: number;
  open_incidents: number;
}

export interface ManagerComplianceOverview {
  score: number;
}

export interface ManagerOperationsOverview {
  pending_approvals: number;
  ready_to_execute: number;
  protected_assets: number;
}

export interface ManagerOverview {
  generated_at: string;
  fleet: ManagerFleetOverview;
  queue: ManagerQueueOverview;
  incidents: ManagerIncidentOverview;
  deployments: ManagerDeploymentOverview;
  reports: ManagerReportOverview;
  siem: SiemStatus;
  compliance: ManagerComplianceOverview;
  tenants: number;
  operations: ManagerOperationsOverview;
}

export interface ManagerSuppressionSummary {
  id: string;
  name: string;
  created_at: string;
  active: boolean;
  justification: string;
}

export interface ManagerQueueDigest {
  generated_at: string;
  queue: ManagerQueueOverview;
  stale_cases: number;
  degraded_collectors: number;
  pending_dry_run_approvals: number;
  ready_to_execute: number;
  recent_suppressions: ManagerSuppressionSummary[];
  noisy_reasons: string[];
  changes_since_last_shift: string[];
  top_queue_items: QueueAlertSummary[];
  urgent_items: UrgentItem[];
}

export interface AuthSsoProvider {
  id: string;
  display_name: string;
  kind: string;
  status: string;
  validation_status: string;
  login_path: string;
}

export interface AuthSsoScimStatus {
  enabled: boolean;
  status: string;
  mapping_count: number;
}

export interface AuthSsoConfigResponse {
  enabled: boolean;
  providers: AuthSsoProvider[];
  issuer: string;
  scopes: string[];
  scim: AuthSsoScimStatus;
}

export interface AuthRotateResponse {
  status: string;
  new_token: string;
  previous_prefix: string;
}

export interface AssistantStatusResponse {
  enabled: boolean;
  provider: string;
  model: string;
  has_api_key: boolean;
  active_conversations: number;
  endpoint: string;
  mode: string;
}

export interface AssistantContextFilter {
  time_range_hours?: number | null;
  severity_min?: string | null;
  device_filter?: string | null;
  alert_types?: string[] | null;
}

export interface AssistantCitation {
  source_type: string;
  source_id: string;
  summary: string;
  relevance_score: number;
}

export interface AssistantTokenUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface AssistantContextEvent {
  id: string;
  event_type: string;
  summary: string;
  severity: string;
  timestamp: string;
  device?: string | null;
  raw_data?: string | null;
  relevance: number;
}

export type AssistantCaseStatus =
  | "New"
  | "Triaging"
  | "Investigating"
  | "Escalated"
  | "Resolved"
  | "Closed";

export type AssistantCasePriority = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface AssistantCaseComment {
  author: string;
  timestamp: string;
  text: string;
}

export interface AssistantEvidenceRef {
  kind: string;
  reference_id: string;
  description: string;
  added_at: string;
}

export interface AssistantCase {
  id: number;
  title: string;
  description: string;
  status: AssistantCaseStatus;
  priority: AssistantCasePriority;
  assignee: string | null;
  created_at: string;
  updated_at: string;
  incident_ids: number[];
  event_ids: number[];
  tags: string[];
  comments: AssistantCaseComment[];
  evidence: AssistantEvidenceRef[];
  mitre_techniques: string[];
}

export interface AssistantCaseContext {
  case: AssistantCase;
  linked_events: AssistantContextEvent[];
}

export interface AssistantQueryRequest {
  question: string;
  case_id?: number;
  conversation_id?: string;
  context_filter?: AssistantContextFilter;
  limit?: number;
}

export interface AssistantQueryResponse {
  answer: string;
  citations: AssistantCitation[];
  confidence: number;
  model_used: string;
  tokens_used: AssistantTokenUsage;
  response_time_ms: number;
  conversation_id: string;
  mode: string;
  case_context: AssistantCaseContext | null;
  context_events: AssistantContextEvent[];
  warnings: string[];
}

export interface BehaviorSignals {
  suspicious_process_tree?: boolean;
  defense_evasion?: boolean;
  persistence_installed?: boolean;
  c2_beaconing_detected?: boolean;
  credential_access?: boolean;
}

export interface ScanAllowlist {
  trusted_publishers?: string[];
  internal_tools?: string[];
}

export interface MemoryRegion {
  address_start: string;
  address_end: string;
  permissions: string;
  size_bytes: number;
  backing: string;
  indicator: string;
}

export interface PatternMatch {
  pattern_name: string;
  offset: string;
  size: number;
  description: string;
}

export interface MemoryIndicatorReport {
  pid: number;
  process_name: string;
  rwx_regions: number;
  anonymous_executable: number;
  reflective_dll_suspects: MemoryRegion[];
  shellcode_patterns: PatternMatch[];
  hollowing_suspected: boolean;
  total_regions_scanned: number;
  risk_score: number;
  indicators: string[];
}

export interface MemoryIndicatorsScanMapsRequest {
  pid: number;
  process_name: string;
  maps_content: string;
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

export type IncidentStatus =
  | "Open"
  | "Investigating"
  | "Contained"
  | "Resolved"
  | "FalsePositive";

export interface MitreAttack {
  tactic: string;
  technique_id: string;
  technique_name: string;
}

export interface EventNote {
  author: string;
  timestamp: string;
  text: string;
}

export interface Incident {
  id: number;
  title: string;
  severity: string;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  event_ids: number[];
  agent_ids: string[];
  mitre_techniques: MitreAttack[];
  summary: string;
  assignee: string | null;
  notes: EventNote[];
}

export interface CreateIncidentOptions {
  event_ids?: number[] | null;
  agent_ids?: string[] | null;
}

export interface AgentHealthSummary {
  pending_alerts: number;
  telemetry_queue_depth: number;
  update_state?: string | null;
  update_target_version?: string | null;
  last_update_error?: string | null;
  last_update_at?: string | null;
}

export interface AgentSummary {
  id: string;
  hostname: string;
  platform: string;
  version: string;
  current_version: string;
  enrolled_at: string;
  last_seen: string;
  last_seen_age_secs?: number | null;
  status: string;
  labels: Record<string, string>;
  health: AgentHealthSummary;
  pending_alerts: number;
  telemetry_queue_depth: number;
  target_version?: string | null;
  rollout_group?: string | null;
  deployment_status?: string | null;
  scope_override: boolean;
  local_console?: boolean;
  local_monitoring?: boolean;
  source?: string;
  os_version?: string;
  arch?: string;
  telemetry_samples?: number;
  process_count?: number | null;
  inventory_available?: boolean;
}

export type AgentStatus = "online" | "stale" | "offline" | "deregistered";

export type AgentComputedStatus = AgentStatus | "unknown";

export interface DiskInfo {
  name: string;
  size_gb: number;
  mount_point: string;
}

export interface HardwareInfo {
  cpu_model: string;
  cpu_cores: number;
  total_ram_mb: number;
  disks: DiskInfo[];
}

export interface HostInstalledApp {
  name: string;
  path: string;
  version: string;
  bundle_id: string;
  size_mb: number;
  last_modified: string;
}

export interface HostAppsResponse {
  apps: HostInstalledApp[];
  count: number;
  platform?: string;
  message?: string;
}

export interface HostInstalledPackage {
  name: string;
  version: string;
  source: string;
}

export interface HostServiceInfo {
  name: string;
  status: string;
  pid?: number | null;
}

export interface HostNetworkPort {
  protocol: string;
  port: number;
  state: string;
  process?: string | null;
}

export interface HostUserAccount {
  username: string;
  uid?: number | null;
  groups: string[];
  last_login?: string | null;
}

export interface HostSystemInventory {
  collected_at: string;
  hardware: HardwareInfo;
  software: HostInstalledPackage[];
  services: HostServiceInfo[];
  network: HostNetworkPort[];
  users: HostUserAccount[];
}

export interface MonitorScopeSettings {
  cpu_load: boolean;
  memory_pressure: boolean;
  network_activity: boolean;
  disk_pressure: boolean;
  process_activity: boolean;
  auth_events: boolean;
  thermal_state: boolean;
  battery_state: boolean;
  file_integrity: boolean;
  service_persistence: boolean;
  launch_agents: boolean;
  systemd_units: boolean;
  scheduled_tasks: boolean;
}

export interface AgentIdentityDetails {
  id: string;
  hostname: string;
  platform: string;
  version: string;
  enrolled_at: string;
  last_seen: string;
  status: AgentStatus;
  labels: Record<string, string>;
  health: AgentHealthSummary;
  monitor_scope?: MonitorScopeSettings | null;
}

export interface AgentDeploymentDetails {
  agent_id: string;
  version: string;
  platform: string;
  mandatory: boolean;
  release_notes: string;
  status: string;
  status_reason?: string | null;
  rollout_group: string;
  allow_downgrade: boolean;
  assigned_at: string;
  acknowledged_at?: string | null;
  completed_at?: string | null;
  last_heartbeat_at?: string | null;
}

export interface AgentInventorySummary {
  collected_at: string;
  software_count: number;
  services_count: number;
  network_ports: number;
  users_count: number;
  hardware: HardwareInfo;
}

export interface AgentLogSummary {
  total_records: number;
  last_timestamp?: string | null;
  by_level: Record<string, number>;
}

export interface AgentEventAnalyticsSummary {
  event_count: number;
  correlated_count: number;
  critical_count: number;
  average_score: number;
  max_score: number;
  highest_level: string;
  risk: string;
  top_reasons: string[];
}

export interface AgentTimelineEntry {
  event_id: number;
  received_at: string;
  level: string;
  score: number;
  correlated: boolean;
  reasons: string[];
  action: string;
  triage?: Record<string, unknown> | null;
}

export interface AgentRiskTransition {
  event_id: number;
  received_at: string;
  from: string;
  to: string;
}

export interface AgentActivitySnapshot {
  agent: AgentIdentityDetails;
  local_console: boolean;
  computed_status: AgentComputedStatus;
  heartbeat_age_secs?: number | null;
  deployment?: AgentDeploymentDetails | null;
  scope_override: boolean;
  effective_scope: MonitorScopeSettings;
  health: AgentHealthSummary;
  analytics: AgentEventAnalyticsSummary;
  timeline: AgentTimelineEntry[];
  risk_transitions: AgentRiskTransition[];
  inventory?: AgentInventorySummary | null;
  log_summary: AgentLogSummary;
}

export type AssetType =
  | "OnPremHost"
  | "CloudVm"
  | "CloudService"
  | "Container"
  | "KubernetesCluster"
  | "Database"
  | "LoadBalancer"
  | "StorageBucket"
  | "NetworkDevice"
  | "IoTDevice";

export type CloudProvider = "None" | "Aws" | "Azure" | "Gcp" | { Custom: string };

export type AssetStatus = "Active" | "Inactive" | "Decommissioned" | "Unknown";

export interface UnifiedAsset {
  id: string;
  name: string;
  asset_type: AssetType;
  cloud_provider: CloudProvider;
  region?: string | null;
  account_id?: string | null;
  hostname?: string | null;
  ip_addresses: string[];
  os?: string | null;
  agent_id?: string | null;
  owner?: string | null;
  tags: Record<string, string>;
  risk_score: number;
  status: AssetStatus;
  first_seen: string;
  last_seen: string;
  metadata: Record<string, string>;
}

export interface AssetUpsertResponse {
  status: "upserted";
}

export interface Campaign {
  campaign_id: string;
  name: string;
  hosts: string[];
  alert_count: number;
  first_seen_ms: number;
  last_seen_ms: number;
  avg_score: number;
  max_score: number;
  shared_techniques: string[];
  shared_reasons: string[];
  severity: string;
  alert_ids: string[];
}

export interface TemporalChain {
  chain_id: string;
  host: string;
  alert_count: number;
  first_seen_ms: number;
  last_seen_ms: number;
  avg_score: number;
  max_score: number;
  severity: string;
  shared_techniques: string[];
  shared_reasons: string[];
  alert_ids: string[];
}

export interface CampaignCorrelationSummary {
  campaign_count: number;
  temporal_chain_count: number;
  temporal_chain_alerts: number;
  total_alerts: number;
  unclustered_alerts: number;
  fleet_coverage: number;
}

export interface CampaignSequenceSummary {
  campaign_id: string;
  name: string;
  severity: string;
  host_count: number;
  alert_count: number;
  max_score: number;
  avg_score: number;
  shared_techniques: string[];
  shared_reasons: string[];
  sequence_signals: string[];
  graph_context: string[];
  recommended_pivots: string[];
}

export interface CampaignGraphNode {
  id: string;
  label: string;
  type: string;
  risk_score: number;
  campaign_id: string;
  campaign_severity: string;
  sequence_signals: string[];
}

export interface CampaignGraphEdge {
  source: string;
  target: string;
  type: string;
  weight: number;
  campaign_id: string;
  shared_reasons: string[];
}

export interface CampaignGraph {
  nodes: CampaignGraphNode[];
  edges: CampaignGraphEdge[];
}

export interface CampaignCorrelationView {
  campaigns: Campaign[];
  temporal_chains: TemporalChain[];
  summary: CampaignCorrelationSummary;
  sequence_summaries: CampaignSequenceSummary[];
  graph: CampaignGraph;
}

export type IoCType =
  | "IpAddress"
  | "Domain"
  | "FileHash"
  | "ProcessName"
  | "BehaviorPattern"
  | "NetworkSignature"
  | "RegistryKey"
  | "Certificate";

export interface IndicatorSightingRecord {
  ioc_type: IoCType;
  value: string;
  severity: string;
  confidence: number;
  timestamp: string;
  source: string;
  context: string;
  weight: number;
}

export interface ThreatIntelSightingsResponse {
  count: number;
  items: IndicatorSightingRecord[];
}

export interface IndicatorMetadata {
  normalized_value: string;
  ttl_days: number;
  source_weight: number;
  confidence_decay: number;
  last_sighting?: string | null;
  sightings: number;
}

export interface IndicatorSighting {
  timestamp: string;
  source: string;
  context: string;
  weight: number;
}

export interface IoC {
  ioc_type: IoCType;
  value: string;
  confidence: number;
  severity: string;
  source: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  related_iocs: string[];
  metadata: IndicatorMetadata;
  sightings: IndicatorSighting[];
}

export interface ThreatFeed {
  feed_id: string;
  name: string;
  url: string;
  format: string;
  last_updated: string;
  ioc_count: number;
  active: boolean;
}

export interface ThreatIntelMatchResult {
  matched: boolean;
  ioc?: IoC | null;
  match_type: string;
  context: string;
}

export interface ThreatIntelLibraryV2Response {
  count: number;
  indicators: IoC[];
  feeds: ThreatFeed[];
  recent_matches: ThreatIntelMatchResult[];
  recent_sightings: IndicatorSightingRecord[];
  stats: IoCEnrichmentStats;
}

export type AddIocType = "ip" | "domain" | "hash" | "process";

export interface AddIocRequest {
  ioc_type: AddIocType;
  value: string;
  confidence?: number;
}

export interface AddIocResponse {
  status: "added";
  value: string;
}

export type ContainerSeverity = "Low" | "Medium" | "High" | "Critical";

export type ContainerAlertKind =
  | "PrivilegedContainer"
  | "ContainerEscape"
  | "SuspiciousExec"
  | "UnusualImagePull"
  | "SensitiveMount"
  | "CapabilityAbuse"
  | "K8sRbacEscalation"
  | "K8sSecretExfiltration";

export interface ContainerAlert {
  id: string;
  timestamp: string;
  severity: ContainerSeverity;
  kind: ContainerAlertKind;
  container_id: string;
  container_name: string;
  image: string;
  hostname: string;
  description: string;
  risk_score: number;
  mitre_techniques: string[];
  recommendations: string[];
}

export interface ContainerStatsResponse {
  total_events: number;
  total_alerts: number;
}

export interface DedupIncident {
  incident_id: string;
  first_seen: string;
  last_seen: string;
  alert_count: number;
  merged_alert_ids: number[];
  device_ids: string[];
  level: string;
  representative_reasons: string[];
  avg_score: number;
  max_score: number;
  fingerprint: string;
}

export type AdvisorySeverity = "None" | "Low" | "Medium" | "High" | "Critical";

export interface Advisory {
  id: string;
  title: string;
  package: string;
  affected_below: string;
  fixed_version: string;
  cvss: number;
  severity: AdvisorySeverity;
  exploit_known: boolean;
  mitre_techniques: string[];
  published: string;
}

export interface VulnerabilityMatch {
  advisory: Advisory;
  installed_version: string;
  package_source: string;
  risk_score: number;
  remediation: string;
}

export interface VulnerabilityReport {
  host_id: string;
  scan_timestamp: string;
  total_packages: number;
  vulnerable_packages: number;
  total_cves: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  exploit_available_count: number;
  risk_score: number;
  matches: VulnerabilityMatch[];
  top_actions: string[];
}

export interface VulnerabilitySummary {
  total_hosts: number;
  vulnerable_hosts: number;
  total_cves: number;
  critical_cves: number;
  high_cves: number;
  exploit_available: number;
  average_risk_score: number;
  advisory_database_size: number;
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

export interface AnalystSearchQuery {
  text?: string | null;
  hostname?: string | null;
  level?: string | null;
  agent_id?: string | null;
  from_ts?: string | null;
  to_ts?: string | null;
  limit?: number | null;
}

export interface AnalystSearchResultItem {
  id: number;
  agent_id: string;
  hostname: string;
  score: number;
  level: string;
  timestamp: string;
  reasons: string[];
  action: string;
}

export interface AnalystSearchResponse {
  results: AnalystSearchResultItem[];
  count: number;
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

export interface ComplianceSummaryFramework {
  framework: string;
  score: number;
  passed: number;
  failed: number;
  total: number;
}

export interface ComplianceSummaryResponse {
  generated_at: string;
  overall_score: number;
  frameworks: ComplianceSummaryFramework[];
}

export interface AssetSummaryResponse {
  total_assets: number;
  by_type: Record<string, number>;
  by_provider: Record<string, number>;
  by_status: Record<string, number>;
  high_risk_count: number;
  unmanaged_count: number;
  average_risk: number;
}

export type EmailAuthStatus = "pass" | "fail" | "softfail" | "none" | "unknown";

export interface EmailAuthResults {
  spf: EmailAuthStatus;
  dkim: EmailAuthStatus;
  dmarc: EmailAuthStatus;
  auth_score: number;
}

export interface EmailUrlFinding {
  url: string;
  risk_score: number;
  indicators: string[];
}

export interface EmailAttachmentInfo {
  filename: string;
  content_type?: string | null;
  sha256?: string | null;
  size_bytes?: number | null;
}

export interface EmailAttachmentFinding {
  filename: string;
  content_type?: string | null;
  sha256?: string | null;
  risk_score: number;
  indicators: string[];
}

export interface EmailAnalyzeRequest {
  from: string;
  reply_to?: string | null;
  return_path?: string | null;
  to?: string | null;
  subject?: string | null;
  received_chain?: string[];
  authentication_results?: string | null;
  body_text?: string | null;
  body_html?: string | null;
  attachments?: EmailAttachmentInfo[];
  message_id?: string | null;
}

export interface EmailThreatReport {
  message_id: string;
  auth_results: EmailAuthResults;
  sender_mismatch: boolean;
  url_findings: EmailUrlFinding[];
  attachment_findings: EmailAttachmentFinding[];
  urgency_score: number;
  phishing_score: number;
  indicators: string[];
}

export interface PolicyRecord {
  version: number;
  published_at?: string;
  alert_threshold?: number | null;
  interval_secs?: number | null;
  watch_paths?: string[] | null;
  dry_run?: boolean | null;
  syslog?: boolean | null;
  cef?: boolean | null;
  message?: string | null;
}

export interface PublishPolicyRequest {
  version?: number;
  published_at?: string;
  alert_threshold?: number | null;
  interval_secs?: number | null;
  watch_paths?: string[] | null;
  dry_run?: boolean | null;
  syslog?: boolean | null;
  cef?: boolean | null;
}

export interface ControlFinding {
  control_id: string;
  title: string;
  status: "pass" | "fail" | "not_applicable" | "manual_review";
  evidence: string;
  remediation: string;
}

export interface WitnessBundle {
  backend: string;
  label: string;
  pre_digest: string;
  post_digest: string;
  timestamp: string;
  witness_hex: string;
  proof_hex?: string | null;
  verified: boolean;
}

export interface DlqStatsResponse {
  count: number;
  empty: boolean;
}

export interface DlqClearResponse {
  cleared: number;
}

export interface DeadLetterEvent {
  original_payload: string;
  errors: string[];
  received_at: string;
  source_agent?: string | null;
}

export interface DlqListResponse {
  dead_letters: DeadLetterEvent[];
  count: number;
}

export interface SigmaStatsResponse {
  total_rules: number;
  engine_status: string;
}

export interface QueueStatsResponse {
  total: number;
  pending: number;
  unacknowledged: number;
  acknowledged: number;
  assigned: number;
  sla_breached: number;
}

export interface ResponseStatsResponse {
  auto_executed: number;
  executed: number;
  pending: number;
  pending_approval: number;
  ready_to_execute: number;
  approved_ready: number;
  total_requests: number;
  denied: number;
  protected_assets: number;
}

export interface CasesStatsResponse {
  total: number;
  open: number;
  resolved: number;
  triaging: number;
  investigating: number;
  escalated: number;
}

export interface PlatformCapabilitiesResponse {
  platform: string;
  has_tpm: boolean;
  has_seccomp: boolean;
  has_ebpf: boolean;
  has_firewall: boolean;
  max_threads: number;
}

export interface SloStatus {
  api_latency_p99_ms: number;
  error_rate_pct: number;
  availability_pct: number;
  budget_remaining_pct: number;
  uptime_seconds: number;
  total_requests: number;
  total_errors: number;
  successful_requests: number;
  request_count: number;
  error_count: number;
}

export interface FeedPollResult {
  feed_id: string;
  new_iocs: number;
  updated_iocs: number;
  new_hashes: number;
  new_yara_rules: number;
  errors: string[];
  poll_time_ms: number;
  timestamp: string;
}

export interface FeedIngestionStatsResponse {
  total_sources: number;
  active_sources: number;
  total_polls: number;
  total_iocs_ingested: number;
  total_hashes_imported: number;
  total_yara_imported: number;
  last_poll_results: FeedPollResult[];
  errors_last_24h: number;
}

export interface IoCEnrichmentStats {
  total_iocs: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  by_source: Record<string, number>;
  avg_confidence: number;
  active_feeds: number;
  total_feeds: number;
  match_history_size: number;
}

export interface ThreatIntelStatusResponse {
  ioc_count: number;
}

export type ResponseActionTier = "Auto" | "SingleApproval" | "DualApproval" | "BreakGlass";

export type ResponseRequestStatus =
  | "Pending"
  | "Approved"
  | "Denied"
  | "Expired"
  | "Executed"
  | "DryRunCompleted";

export type ResponseApprovalDecision = "Approve" | "Deny";

export type ResponseRequestActionKind =
  | "alert"
  | "isolate"
  | "throttle"
  | "kill_process"
  | "quarantine_file"
  | "block_ip"
  | "disable_account"
  | "rollback_config"
  | "custom";

export interface ResponseTarget {
  hostname: string;
  agent_uid: string | null;
  asset_tags: string[];
}

export interface ResponseApprovalRecord {
  approver: string;
  decision: ResponseApprovalDecision;
  timestamp: string;
  comment: string | null;
}

export interface ResponseBlastRadius {
  affected_services: number;
  affected_endpoints: number;
  risk_level: string;
  impact_summary: string;
}

export interface ResponseRequestInputContext {
  target: ResponseTarget;
  severity: string;
  tier: ResponseActionTier;
  dry_run: boolean;
  protected_asset: boolean;
  requested_at: string;
}

export interface ResponseDryRunResult {
  request_id: string;
  would_execute: boolean;
  tier: ResponseActionTier;
  blast_radius: ResponseBlastRadius | null;
  is_protected: boolean;
  approvals_required: number;
}

export interface ResponseRequestRecord {
  id: string;
  action: string;
  action_label: string;
  target: ResponseTarget;
  target_hostname: string;
  target_agent_uid: string | null;
  tier: ResponseActionTier;
  status: ResponseRequestStatus;
  created_at: string;
  requested_at: string;
  requested_by: string;
  reason: string;
  severity: string;
  approvals: ResponseApprovalRecord[];
  approval_count: number;
  approvals_required: number;
  dry_run: boolean;
  is_protected_asset: boolean;
  blast_radius: ResponseBlastRadius | null;
  blast_radius_summary: string | null;
  input_context: ResponseRequestInputContext;
  dry_run_result: ResponseDryRunResult | null;
  execution_result: string | null;
  reversal_path: string;
}

export interface ResponseRequestsResponse {
  requests: ResponseRequestRecord[];
  count: number;
  ready_to_execute: number;
}

export interface ResponseRequestCreateBase {
  action: ResponseRequestActionKind;
  agent_uid?: string;
  asset_tags?: string[];
  reason?: string;
  severity?: string;
  dry_run?: boolean;
  rate_limit_kbps?: number;
  pid?: number;
  process_name?: string;
  path?: string;
  ip?: string;
  username?: string;
  config_name?: string;
  name?: string;
  payload?: string;
}

export type ResponseRequestCreateRequest = ResponseRequestCreateBase &
  ({ hostname: string; target_hostname?: string } | { target_hostname: string; hostname?: string });

export interface ResponseRequestSubmissionResponse {
  status: string;
  request: ResponseRequestRecord;
}

export interface ResponseApprovalResponse {
  request_id: string;
  decision: ResponseApprovalDecision;
  status: Extract<ResponseRequestStatus, "Pending" | "Approved" | "Denied" | "DryRunCompleted">;
  approvals: number;
}

export interface ResponseExecuteResponse {
  executed_count: number;
  actions: string[];
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

export interface AuditEntry {
  timestamp: string;
  method: string;
  path: string;
  source_ip: string;
  status_code: number;
  auth_used: boolean;
}

export interface AuditLogPage {
  entries: AuditEntry[];
  total: number;
  offset: number;
  limit: number;
  count: number;
  has_more: boolean;
}

export interface AnalyticsSummary {
  total_requests: number;
  total_errors: number;
  error_rate: number;
  unique_endpoints: number;
  top_endpoints: EndpointMetrics[];
}

export type SpanStatus = "Unset" | "Ok" | "Error";

export type TraceAttribute = [string, string];

export interface OtelSpan {
  trace_id: string;
  span_id: string;
  parent_span_id?: string | null;
  operation_name: string;
  service_name: string;
  start_time_ms: number;
  end_time_ms?: number | null;
  status: SpanStatus;
  attributes: TraceAttribute[];
}

export interface TraceStats {
  total_spans: number;
  error_spans: number;
  avg_duration_ms: number;
}

export interface TracesResponse {
  stats: TraceStats;
  recent: OtelSpan[];
}

export interface BackupEncryptRequest {
  data: string;
  passphrase: string;
}

export interface BackupEncryptResponse {
  encrypted: string;
  size: number;
}

export interface BackupDecryptRequest {
  data: string;
  passphrase: string;
}

export interface BackupDecryptResponse {
  data: string;
  size: number;
}

export interface BackupStatus {
  enabled: boolean;
  retention_count: number;
  path: string;
  schedule_cron: string;
}

export interface AdminBackupResponse {
  status: string;
  path: string;
  timestamp: string;
}

export interface AdminDbMigration {
  version: number;
  name: string;
  sql_up: string;
  sql_down: string;
  applied_at?: string | null;
}

export interface AdminDbVersionResponse {
  current_version: number;
  migrations: AdminDbMigration[];
}

export interface AdminDbSizesResponse {
  db_bytes: number;
  wal_bytes: number;
  shm_bytes: number;
  total_bytes: number;
}

export interface AdminDbRollbackResponse {
  status: string;
  version: number;
  current_version: number;
}

export interface AdminDbCompactResponse {
  status: string;
  size_before_bytes: number;
  size_after_bytes: number;
  bytes_reclaimed: number;
  timestamp: string;
}

export interface AdminDbResetRequest {
  confirm: string;
}

export interface AdminDbResetResponse {
  status: string;
  records_purged: number;
  timestamp: string;
}

export interface AdminDbPurgeRequest {
  retention_days: number;
}

export interface AdminDbPurgeResponse {
  status: string;
  retention_days: number;
  alerts_purged: number;
  audit_purged: number;
  metrics_purged: number;
  timestamp: string;
}

export interface AdminCleanupLegacyResponse {
  status: string;
  files_removed: string[];
  count: number;
  timestamp: string;
}

export type SbomComponentType =
  | "library"
  | "application"
  | "framework"
  | "device"
  | "firmware";

export interface SbomHash {
  alg: string;
  content: string;
}

export interface SbomLicense {
  license: {
    id: string;
  };
}

export interface SbomComponent {
  type: SbomComponentType;
  name: string;
  version: string;
  purl: string;
  licenses?: SbomLicense[];
  hashes?: SbomHash[];
}

export interface SbomDependency {
  ref: string;
  dependsOn: string[];
}

export interface SbomMetadataTool {
  name: string;
  version: string;
}

export interface SbomMetadataComponent {
  type: string;
  name: string;
  version: string;
}

export interface SbomMetadata {
  timestamp: string;
  tools: SbomMetadataTool[];
  component: SbomMetadataComponent;
}

export interface SbomDocument {
  bomFormat: "CycloneDX";
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: SbomMetadata;
  components: SbomComponent[];
  dependencies: SbomDependency[];
}

export interface PiiScanResponse {
  has_pii: boolean;
  finding_count: number;
  categories: string[];
}

export interface LicenseStatusResponse {
  status: string;
  edition: string;
  features: string[];
  max_agents: number;
  expires: string;
}

export interface LicenseValidateRequest {
  key: string;
}

export interface LicenseValidateResponse {
  valid: boolean;
  key_prefix: string;
  validated_at: string;
}

export interface MeteringUsageResponse {
  events_ingested: number;
  api_calls: number;
  storage_bytes: number;
  plan: string;
  period_start: string;
}

export interface BillingSubscriptionResponse {
  plan: string;
  status: string;
  monthly_price: string;
  next_billing: string;
}

export type BillingInvoice = Record<string, unknown>;

export interface BillingInvoicesResponse {
  invoices: BillingInvoice[];
}

export type MarketplacePackCategory =
  | "DetectionRules"
  | "ResponsePlaybooks"
  | "DashboardTemplates"
  | "IntegrationConnectors"
  | "ThreatIntelFeeds"
  | "ComplianceTemplates";

export type MarketplacePackStatus =
  | "Available"
  | "Installed"
  | "UpdateAvailable"
  | "Deprecated";

export interface MarketplaceContentPack {
  id: string;
  name: string;
  version: string;
  author: string;
  description: string;
  category: MarketplacePackCategory;
  tags: string[];
  status: MarketplacePackStatus;
  downloads: number;
  rating: number;
  created: string;
  updated: string;
  size_bytes: number;
  checksum: string;
  dependencies: string[];
  min_wardex_version: string;
}

export type PreventionMode = "Detect" | "Prevent" | "Contain";

export type PreventionAction =
  | "Block"
  | "Quarantine"
  | "Kill"
  | "NetworkIsolate"
  | "AlertOnly";

export interface PreventionNetworkDestinationConditionValue {
  ip: string;
  port?: number | null;
}

export interface PreventionParentChildChainConditionValue {
  parent: string;
  child: string;
}

export type PreventionCondition =
  | { ProcessName: string }
  | { ProcessHash: string }
  | { NetworkDestination: PreventionNetworkDestinationConditionValue }
  | { FilePathPattern: string }
  | { RegistryKeyPattern: string }
  | { CommandLineContains: string }
  | { ParentChildChain: PreventionParentChildChainConditionValue }
  | { Composite: PreventionCondition[] };

export interface PreventionRule {
  id: string;
  name: string;
  condition: PreventionCondition;
  action: PreventionAction;
  severity: number;
  confidence_threshold: number;
  enabled: boolean;
}

export interface PreventionPolicy {
  id: string;
  name: string;
  enabled: boolean;
  mode: PreventionMode;
  rules: PreventionRule[];
  created: string;
  updated: string;
  description: string;
}

export interface PreventionStats {
  events_evaluated: number;
  events_blocked: number;
  events_allowed: number;
  events_quarantined: number;
  false_positives_reported: number;
}

export interface PipelineMetrics {
  events_ingested: number;
  events_normalized: number;
  events_enriched: number;
  events_detected: number;
  events_stored: number;
  events_forwarded: number;
  backpressure_count: number;
  dlq_count: number;
  errors: number;
  avg_latency_ms: number;
}

export interface PipelineStatusConfig {
  channel_capacity: number;
  batch_size: number;
  backpressure_threshold: number;
}

export interface PipelineManagerStatus {
  running: boolean;
  metrics: PipelineMetrics;
  dlq_size: number;
  config: PipelineStatusConfig;
}

export interface PipelineStatusSummaryMetrics {
  events_ingested: number;
  events_normalized: number;
  events_detected: number;
  events_stored: number;
  dlq_count: number;
}

export interface PipelineStatusResponse {
  status: PipelineManagerStatus;
  metrics: PipelineStatusSummaryMetrics;
}

export type AgentLifecycle =
  | "Active"
  | "Stale"
  | "Offline"
  | "Archived"
  | "Decommissioned";

export interface AgentLifecycleEntry {
  agent_id: string;
  hostname: string;
  state: AgentLifecycle;
  last_heartbeat: string;
  state_changed_at: string;
  notes: string | null;
}

export interface AgentLifecycleTransition {
  agent_id: string;
  from: AgentLifecycle;
  to: AgentLifecycle;
  reason: string;
}

export interface AgentLifecycleSweepResult {
  total_agents: number;
  active: number;
  stale: number;
  offline: number;
  archived: number;
  decommissioned: number;
  transitions: AgentLifecycleTransition[];
  timestamp: string;
}

export interface IocDecayResult {
  iocs_processed: number;
  iocs_decayed: number;
  iocs_removed: number;
  avg_confidence_before: number;
  avg_confidence_after: number;
  timestamp: string;
}

export interface IocDecayPreview {
  value: string;
  ioc_type: string;
  original_confidence: number;
  decayed_confidence: number;
  last_seen: string;
}

export interface CertificateRecord {
  hostname: string;
  port: number;
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  days_until_expiry: number;
  fingerprint_sha256: string;
  san_domains: string[];
  key_algorithm: string;
  key_size_bits: number;
  is_self_signed: boolean;
  is_expired: boolean;
  is_expiring_soon: boolean;
  agent_id: string | null;
  discovered_at: string;
}

export type CertHealth =
  | "Valid"
  | "ExpiringSoon"
  | "Expired"
  | "SelfSigned"
  | "WeakKey";

export interface CertAlert {
  certificate: CertificateRecord;
  health: CertHealth;
  severity: string;
  message: string;
}

export interface CertSummary {
  total_certificates: number;
  valid: number;
  expiring_30d: number;
  expiring_7d: number;
  expired: number;
  self_signed: number;
  weak_key: number;
  alerts: CertAlert[];
  certificates: CertificateRecord[];
}

export interface CertRegisterResponse {
  status: "registered";
}

export type QuarantineStatus =
  | "Quarantined"
  | "UnderAnalysis"
  | "Confirmed"
  | "FalsePositive"
  | "Released"
  | "Deleted";

export interface QuarantinedFile {
  id: string;
  original_path: string;
  filename: string;
  sha256: string;
  md5: string;
  size_bytes: number;
  quarantined_at: string;
  agent_id: string | null;
  hostname: string | null;
  verdict: string;
  malware_family: string | null;
  scan_matches: string[];
  status: QuarantineStatus;
  analyst_notes: string | null;
  released_at: string | null;
  released_by: string | null;
}

export interface QuarantineAddRequest {
  path: string;
  agent_id?: string | null;
  hostname?: string | null;
  verdict?: string | null;
  malware_family?: string | null;
}

export interface QuarantineAddResponse {
  id: string;
}

export interface QuarantineStats {
  total_files: number;
  quarantined: number;
  under_analysis: number;
  confirmed_malicious: number;
  false_positives: number;
  released: number;
  total_size_bytes: number;
  families: string[];
}

export interface QuarantineReleaseResponse {
  released: boolean;
}

export interface EntropySection {
  name: string;
  offset: number;
  size: number;
  entropy: number;
  suspicious: boolean;
}

export interface EntropyReport {
  overall_entropy: number;
  sections: EntropySection[];
  is_packed: boolean;
  packer_hint: string | null;
  suspicious: boolean;
  high_entropy_ratio: number;
  file_size: number;
}

export interface DnsThreatAnalyzeRequest {
  domain: string;
}

export interface DnsQuery {
  domain: string;
  query_type: string;
  response_ips: string[];
  ttl?: number | null;
  timestamp: string;
  response_size?: number | null;
}

export type DnsTopQueried = [string, number];

export interface DnsThreatSummary {
  total_queries_analyzed: number;
  suspicious_domains: DnsThreatReport[];
  dga_candidates: number;
  tunnel_candidates: number;
  fast_flux_candidates: number;
  top_queried: DnsTopQueried[];
}

export interface DnsThreatRecordResponse {
  status: "recorded";
}

export type ImageScanStatus =
  | "NotScanned"
  | "Scanning"
  | "Clean"
  | "Suspicious"
  | "Malicious";

export interface ImageVulnerability {
  cve_id: string;
  severity: string;
  package: string;
  installed_version: string;
  fixed_version: string | null;
  description: string;
}

export interface ContainerImage {
  id: string;
  repository: string;
  tag: string;
  digest: string;
  size_mb: number;
  created: string;
  labels: Record<string, string>;
  base_image: string | null;
  layers: number;
  risk_score: number;
  scan_status: ImageScanStatus;
  vulnerabilities: ImageVulnerability[];
}

export interface ImageInventorySummary {
  total_images: number;
  scanned: number;
  clean: number;
  suspicious: number;
  malicious: number;
  total_vulnerabilities: number;
  critical_vulns: number;
  registries: string[];
}

export type ConfigCategory =
  | "SshServer"
  | "Firewall"
  | "KernelParams"
  | "AuthConfig"
  | "NetworkConfig"
  | "DockerDaemon"
  | "KubeConfig"
  | "NtpConfig"
  | "AuditRules"
  | { Custom: string };

export type DriftSeverity = "Low" | "Medium" | "High" | "Critical";

export interface ConfigChange {
  path: string;
  category: ConfigCategory;
  key: string;
  expected: string;
  actual: string;
  severity: DriftSeverity;
  host_id: string;
  detected_at: string;
  mitre_techniques: string[];
}

export interface DriftReport {
  host_id: string;
  scan_timestamp: string;
  baselines_checked: number;
  drifts_found: number;
  critical_drifts: number;
  high_drifts: number;
  changes: ConfigChange[];
  compliant: boolean;
}

export interface ConfigDriftCheckRequest {
  host_id: string;
  configs: Record<string, Record<string, string>>;
}

export interface ConfigDriftBaselineSummary {
  total_hosts_scanned: number;
  compliant_hosts: number;
  non_compliant_hosts: number;
  compliance_pct: number;
  total_drifts: number;
  critical_drifts: number;
  baselines: number;
}

export type GapPriority = "Critical" | "High" | "Medium" | "Low";

export interface CoverageGap {
  technique_id: string;
  technique_name: string;
  tactic: string;
  priority: GapPriority;
  recommendation: string;
  suggested_sources: string[];
}

export interface TacticGapSummary {
  tactic: string;
  total: number;
  covered: number;
  uncovered: number;
  pct: number;
  gap_ids: string[];
}

export interface GapAnalysisReport {
  total_techniques: number;
  covered: number;
  uncovered: number;
  coverage_pct: number;
  gaps: CoverageGap[];
  by_tactic: TacticGapSummary[];
  top_recommendations: string[];
  generated_at: string;
}

export interface SlowAttackReport {
  score: number;
  alert: boolean;
  cumulative_auth_failures: number;
  auth_failure_rate: number;
  cumulative_network_kb: number;
  samples_observed: number;
  patterns: string[];
  mitre_techniques: string[];
}

export interface RansomwareContribution {
  signal: string;
  raw_value: number;
  weighted: number;
}

export interface RansomwareSignal {
  score: number;
  alert: boolean;
  velocity: number;
  extension_changes: number;
  canaries_triggered: number;
  canaries_total: number;
  fim_drift: number;
  contributions: RansomwareContribution[];
  mitre_techniques: string[];
}

export interface RetentionCurrentCounts {
  audit_entries: number;
  alerts: number;
  events: number;
}

export interface RetentionStatusResponse {
  audit_max_records: number;
  alert_max_records: number;
  event_max_records: number;
  audit_max_age_secs: number;
  remote_syslog_endpoint: string | null;
  current_counts: RetentionCurrentCounts;
}

export interface RetentionApplyResponse {
  status: "applied";
  trimmed_alerts: number;
  trimmed_events: number;
}

export type EvidencePlanPlatform = "linux" | "macos" | "windows";

export interface EvidenceArtifact {
  name: string;
  path: string;
  description: string;
  volatile: boolean;
}

export interface EvidenceCollectionPlan {
  platform: EvidencePlanPlatform;
  artifacts: EvidenceArtifact[];
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

export interface HealthLiveResponse {
  status: "alive";
}

export interface HealthReadyResponse {
  status: "ready" | "not_ready";
  storage: "ok" | "unreachable";
}

export interface RemoteInstallRecord {
  id: string;
  transport: "ssh" | "winrm";
  hostname: string;
  address: string;
  platform: "linux" | "macos" | "windows";
  manager_url: string;
  agent_id?: string;
  ssh_user: string;
  ssh_port: number;
  ssh_identity_file?: string;
  ssh_accept_new_host_key: boolean;
  use_sudo: boolean;
  winrm_username?: string;
  winrm_port?: number;
  winrm_use_tls?: boolean;
  winrm_skip_cert_check?: boolean;
  actor: string;
  status: string;
  started_at: string;
  completed_at?: string;
  first_heartbeat_at?: string;
  token_expires_at?: string;
  exit_code?: number;
  output_excerpt?: string;
  error?: string;
}

export interface FleetInstallHistoryResponse {
  attempts: RemoteInstallRecord[];
  total: number;
}

export interface FleetInstallSshRequest {
  hostname: string;
  address: string;
  platform: "linux" | "macos";
  manager_url: string;
  ssh_user: string;
  ssh_port?: number;
  ssh_identity_file?: string;
  ssh_accept_new_host_key?: boolean;
  use_sudo?: boolean;
  ttl_secs?: number;
}

export interface FleetInstallWinrmRequest {
  hostname: string;
  address: string;
  platform: "windows";
  manager_url: string;
  winrm_username: string;
  winrm_password: string;
  winrm_port?: number;
  winrm_use_tls?: boolean;
  winrm_skip_cert_check?: boolean;
  ttl_secs?: number;
}

export interface ProcessThread {
  thread_id: number;
  os_thread_id?: number | null;
  identifier_type?: string | null;
  state: string;
  state_label: string;
  priority?: string | null;
  cpu_percent: number;
  system_time?: string | null;
  user_time?: string | null;
  cpu_time?: string | null;
  wait_reason?: string | null;
  command?: string | null;
}

export interface ProcessThreadsSnapshot {
  pid: number;
  hostname: string;
  platform: string;
  identifier_type: string;
  note?: string | null;
  message?: string | null;
  thread_count: number;
  running_count: number;
  sleeping_count: number;
  blocked_count: number;
  hot_thread_count: number;
  top_cpu_percent: number;
  wait_reason_count: number;
  hot_threads: ProcessThread[];
  blocked_threads: ProcessThread[];
  threads: ProcessThread[];
}

export interface ProcessNode {
  pid: number;
  ppid: number;
  name: string;
  cmd_line?: string;
  user?: string;
  exe_path?: string;
  hostname?: string;
  start_time?: string;
  alive?: boolean;
}

export interface ProcessTreeResponse {
  processes: ProcessNode[];
  count?: number;
}

export interface ProcessLiveEntry {
  pid: number;
  ppid: number;
  name: string;
  user: string;
  group: string;
  cpu_percent: number;
  mem_percent: number;
}

export interface ProcessLiveResponse {
  processes: ProcessLiveEntry[];
  count: number;
  total_cpu_percent?: number;
  total_mem_percent?: number;
  platform?: string;
  message?: string | null;
}

export interface ProcessDeepChain {
  pid?: number | null;
  name?: string;
  cmd_line?: string | null;
  depth?: number | null;
  summary?: string | null;
}

export interface ProcessDeepChainsResponse {
  deep_chains: ProcessDeepChain[];
}

export interface ProcessDetailFinding {
  pid: number;
  name: string;
  user: string;
  risk_level: string;
  reason: string;
  cpu_percent?: number;
  mem_percent?: number;
}

export interface ProcessRiskSummary {
  critical: number;
  severe: number;
  elevated: number;
}

export interface ProcessAnalysisResponse {
  findings: ProcessDetailFinding[];
  total: number;
  risk_summary?: ProcessRiskSummary;
  process_count?: number;
  status: string;
  platform?: string;
  message?: string | null;
}

export interface ProcessNetworkActivity {
  protocol?: string;
  endpoint?: string;
  state?: string;
}

export interface ProcessDetailAnalysis {
  self_process: boolean;
  listener_count: number;
  recommendations: string[];
}

export interface ProcessDetail {
  pid: number;
  ppid: number;
  name: string;
  display_name: string;
  user: string;
  group: string;
  cpu_percent: number;
  mem_percent: number;
  hostname: string;
  platform: string;
  cmd_line: string;
  exe_path?: string | null;
  cwd?: string | null;
  start_time?: string | null;
  elapsed?: string | null;
  risk_level: string;
  findings: ProcessDetailFinding[];
  network_activity: ProcessNetworkActivity[];
  code_signature: Record<string, unknown>;
  analysis: ProcessDetailAnalysis;
}

export type UebaEntityKind =
  | "User"
  | "Host"
  | "IpAddress"
  | "Process"
  | "Service";

export type UebaAnomalyType =
  | "ImpossibleTravel"
  | "UnusualLoginTime"
  | "AnomalousAccess"
  | "PrivilegeEscalationChain"
  | "DataExfiltrationPattern"
  | "LateralMovement"
  | "AnomalousProcess"
  | "ServiceAnomaly"
  | "DataVolumeAnomaly"
  | "FirstTimeActivity";

export interface BehaviorObservation {
  timestamp_ms: number;
  entity_kind: UebaEntityKind;
  entity_id: string;
  hour_of_day?: number | null;
  geo_lat?: number | null;
  geo_lon?: number | null;
  resource?: string | null;
  data_bytes?: number | null;
  process?: string | null;
  port?: number | null;
  peer_group?: string | null;
}

export interface UebaAnomaly {
  anomaly_type: UebaAnomalyType;
  entity_kind: UebaEntityKind;
  entity_id: string;
  score: number;
  description: string;
  timestamp_ms: number;
  evidence: string[];
  mitre_technique?: string | null;
}

export interface UebaObserveResponse {
  anomalies: UebaAnomaly[];
}

export interface EntityRisk {
  entity_kind: UebaEntityKind;
  entity_id: string;
  risk_score: number;
  observation_count: number;
  last_seen_ms: number;
  anomaly_count: number;
  peer_group?: string | null;
}

export interface BeaconingAnomaly {
  src_addr: string;
  dst_addr: string;
  dst_port: number;
  protocol: string;
  avg_interval_ms: number;
  jitter_pct: number;
  total_bytes: number;
  flow_count: number;
  risk_score: number;
  reason: string;
}

export interface ProtocolDistribution {
  protocol: string;
  flow_count: number;
  total_bytes: number;
  encrypted_ratio: number;
}

export interface SelfSignedCert {
  dst_addr: string;
  dst_port: number;
  tls_sni: string;
  tls_issuer: string;
  tls_subject: string;
  flow_count: number;
  risk_score: number;
}

export interface TopTalker {
  addr: string;
  total_bytes: number;
  flow_count: number;
  unique_destinations: number;
  protocols: string[];
}

export interface TlsFingerprintAnomaly {
  ja3_hash: string;
  ja4_fingerprint: string;
  src_addr: string;
  dst_addr: string;
  dst_port: number;
  tls_sni: string;
  tls_version: string;
  risk_score: number;
  reason: string;
  flow_count: number;
}

export interface DpiAnomaly {
  src_addr: string;
  dst_addr: string;
  dst_port: number;
  expected_protocol: string;
  detected_protocol: string;
  risk_score: number;
  flow_count: number;
}

export interface EntropyAnomaly {
  src_addr: string;
  dst_addr: string;
  dst_port: number;
  avg_entropy: number;
  total_bytes: number;
  flow_count: number;
  risk_score: number;
}

export interface BeaconConnectionRecord {
  timestamp_ms: number;
  dst_addr: string;
  dst_port: number;
  hostname: string;
  process?: string | null;
  bytes_sent: number;
  bytes_received: number;
}

export interface BeaconRecordResponse {
  status: "recorded";
}

export interface NetFlowRecord {
  timestamp_ms: number;
  src_addr: string;
  src_port: number;
  dst_addr: string;
  dst_port: number;
  protocol: string;
  bytes_sent: number;
  bytes_received: number;
  packets: number;
  duration_ms: number;
  hostname: string;
  is_encrypted: boolean;
  ja3_hash?: string | null;
  ja3s_hash?: string | null;
  ja4_fingerprint?: string | null;
  tls_sni?: string | null;
  tls_issuer?: string | null;
  tls_subject?: string | null;
  tls_version?: string | null;
  tls_self_signed?: boolean;
  payload_entropy?: number | null;
  dpi_protocol?: string | null;
}

export interface NdrIngestResponse {
  status: "ingested";
}

export type DnsVerdict = "Clean" | "Suspicious" | "Malicious";

export interface DnsThreatReport {
  domain: string;
  dga_score: number;
  tunnel_score: number;
  fast_flux_score: number;
  verdict: DnsVerdict;
  indicators: string[];
  tld_risk: number;
  overall_score: number;
  doh_bypass_detected: boolean;
}

export interface UnusualDestination {
  dst_addr: string;
  dst_port: number;
  total_bytes: number;
  flow_count: number;
  first_seen_ms: number;
  risk_score: number;
  reason: string;
}

export interface ProtocolAnomaly {
  protocol: string;
  port: number;
  expected_protocol: string;
  flow_count: number;
  risk_score: number;
}

export interface EncryptedTrafficStats {
  total_flows: number;
  encrypted_flows: number;
  encrypted_ratio: number;
  encrypted_bytes: number;
  total_bytes: number;
}

export interface NdrReport {
  analysis_timestamp: string;
  total_flows_analysed: number;
  total_bytes: number;
  top_talkers: TopTalker[];
  unusual_destinations: UnusualDestination[];
  protocol_anomalies: ProtocolAnomaly[];
  encrypted_traffic: EncryptedTrafficStats;
  unique_external_destinations: number;
  connections_per_second: number;
  dns_threats: DnsThreatReport[];
  tls_anomalies: TlsFingerprintAnomaly[];
  dpi_anomalies: DpiAnomaly[];
  entropy_anomalies: EntropyAnomaly[];
  beaconing_anomalies: BeaconingAnomaly[];
  self_signed_certs: SelfSignedCert[];
}

export type DnsResponseCode =
  | "NoError"
  | "NxDomain"
  | "ServFail"
  | "Refused"
  | { Other: string };

export interface BeaconDnsRecord {
  timestamp_ms: number;
  domain: string;
  query_type: string;
  response_code: DnsResponseCode;
  hostname: string;
  process?: string | null;
}

export interface BeaconCandidate {
  dst_addr: string;
  dst_port: number;
  interval_ms: number;
  jitter: number;
  score: number;
  sample_count: number;
  hostname: string;
  process?: string | null;
  total_bytes: number;
}

export interface DgaCandidate {
  domain: string;
  entropy: number;
  consonant_ratio: number;
  score: number;
  query_count: number;
  nxdomain: boolean;
}

export interface TunnelIndicator {
  domain: string;
  avg_query_length: number;
  txt_ratio: number;
  nxdomain_ratio: number;
  score: number;
  query_count: number;
}

export interface BeaconSummary {
  beacons: BeaconCandidate[];
  dga_domains: DgaCandidate[];
  tunnel_indicators: TunnelIndicator[];
  total_connections_analysed: number;
  total_dns_queries_analysed: number;
}

export interface SiemStatus {
  enabled: boolean;
  siem_type: string;
  endpoint: string;
  pending_events: number;
  total_pushed: number;
  total_pulled: number;
  last_error?: string | null;
  pull_enabled: boolean;
}

export interface SiemConfigRequest {
  enabled?: boolean;
  siem_type?: string;
  endpoint?: string;
  auth_token?: string | null;
  index?: string;
  source_type?: string;
  poll_interval_secs?: number;
  pull_enabled?: boolean;
  pull_query?: string;
  batch_size?: number;
  verify_tls?: boolean;
}

export interface SiemPublicConfig {
  enabled: boolean;
  siem_type: string;
  endpoint: string;
  has_auth_token: boolean;
  index: string;
  source_type: string;
  poll_interval_secs: number;
  pull_enabled: boolean;
  pull_query: string;
  batch_size: number;
  verify_tls: boolean;
}

export type SiemValidationStatus = "disabled" | "error" | "ready" | "warning";

export interface SiemValidationIssue {
  level: "error" | "warning";
  field: string;
  message: string;
}

export interface SiemConfigValidation {
  status: SiemValidationStatus;
  issues: SiemValidationIssue[];
}

export interface SiemConfigEnvelope {
  config: SiemPublicConfig;
  validation: SiemConfigValidation;
}

export interface SaveSiemConfigResponse extends SiemConfigEnvelope {
  status: "saved";
}

export interface ValidateSiemConfigResponse extends SiemConfigEnvelope {
  success: boolean;
}

export interface SiemIntelRecord {
  indicator_type: string;
  indicator_value: string;
  severity: string;
  source: string;
  description: string;
}

export interface TaxiiConfig {
  url: string;
  auth_token: string;
  added_after: string;
  poll_interval_secs: number;
  enabled: boolean;
}

export interface TaxiiStatus {
  enabled: boolean;
  url: string;
  pull_count: number;
  last_error?: string | null;
}

export interface TaxiiConfigMutationResponse {
  status: "ok";
  message: string;
}

export interface TaxiiPullResponse {
  pulled: number;
  records: SiemIntelRecord[];
}

export interface SetupValidationIssue {
  field: string;
  level: "error" | "warning";
  message: string;
}

export type SetupValidationStatus = "disabled" | "ready" | "warning";

export interface SetupValidation {
  status: SetupValidationStatus;
  issues: SetupValidationIssue[];
}

export interface CollectorCheckpoint {
  last_success_at?: string | null;
  last_error_at?: string | null;
  error_category?: string | null;
  events_ingested: number;
  lag_seconds?: number | null;
  checkpoint_id?: string | null;
  retry_count: number;
  backoff_seconds: number;
}

export interface AwsCollectorSetupPatch {
  region?: string;
  access_key_id?: string;
  secret_access_key?: string | null;
  session_token?: string | null;
  poll_interval_secs?: number;
  max_results?: number;
  event_name_filter?: string[];
  enabled?: boolean;
}

export interface AwsCollectorConfigView {
  region: string;
  access_key_id: string;
  poll_interval_secs: number;
  max_results: number;
  event_name_filter: string[];
  enabled: boolean;
  has_secret_access_key: boolean;
  has_session_token: boolean;
}

export interface AwsCollectorConfigEnvelope {
  config: AwsCollectorConfigView;
  validation: SetupValidation;
}

export interface SaveAwsCollectorConfigResponse extends AwsCollectorConfigEnvelope {
  status: "saved";
  provider: "aws_cloudtrail";
}

export interface CloudTrailEvent {
  event_id: string;
  event_name: string;
  event_source: string;
  timestamp: string;
  region: string;
  source_ip?: string | null;
  user_arn?: string | null;
  user_agent?: string | null;
  error_code?: string | null;
  error_message?: string | null;
  read_only: boolean;
  risk_score: number;
  mitre_techniques: string[];
  raw_json?: string | null;
}

export interface AwsCollectorValidationResponse {
  provider: "aws_cloudtrail";
  success: boolean;
  event_count: number;
  polled_at?: string | null;
  next_token?: string | null;
  sample_events: CloudTrailEvent[];
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export interface AzureCollectorSetupPatch {
  tenant_id?: string;
  client_id?: string;
  client_secret?: string | null;
  subscription_id?: string;
  poll_interval_secs?: number;
  categories?: string[];
  enabled?: boolean;
}

export interface AzureCollectorConfigView {
  tenant_id: string;
  client_id: string;
  subscription_id: string;
  poll_interval_secs: number;
  categories: string[];
  enabled: boolean;
  has_client_secret: boolean;
}

export interface AzureCollectorConfigEnvelope {
  config: AzureCollectorConfigView;
  validation: SetupValidation;
}

export interface SaveAzureCollectorConfigResponse extends AzureCollectorConfigEnvelope {
  status: "saved";
  provider: "azure_activity";
}

export interface AzureActivityEvent {
  event_id: string;
  operation_name: string;
  category: string;
  result_type: string;
  caller?: string | null;
  timestamp: string;
  resource_id?: string | null;
  resource_group?: string | null;
  level: string;
  subscription_id: string;
  source_ip?: string | null;
  risk_score: number;
  mitre_techniques: string[];
}

export interface AzureCollectorValidationResponse {
  provider: "azure_activity";
  success: boolean;
  event_count: number;
  polled_at?: string | null;
  sample_events: AzureActivityEvent[];
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export interface GcpCollectorSetupPatch {
  project_id?: string;
  service_account_email?: string;
  key_file_path?: string | null;
  private_key_pem?: string | null;
  poll_interval_secs?: number;
  log_filter?: string;
  page_size?: number;
  enabled?: boolean;
}

export interface GcpCollectorConfigView {
  project_id: string;
  service_account_email: string;
  key_file_path?: string | null;
  poll_interval_secs: number;
  log_filter: string;
  page_size: number;
  enabled: boolean;
  has_private_key_pem: boolean;
}

export interface GcpCollectorConfigEnvelope {
  config: GcpCollectorConfigView;
  validation: SetupValidation;
}

export interface SaveGcpCollectorConfigResponse extends GcpCollectorConfigEnvelope {
  status: "saved";
  provider: "gcp_audit";
}

export interface GcpAuditEvent {
  insert_id: string;
  method_name: string;
  service_name: string;
  resource_name?: string | null;
  resource_type?: string | null;
  timestamp: string;
  caller_ip?: string | null;
  principal_email?: string | null;
  severity: string;
  status_code: number;
  status_message?: string | null;
  project_id: string;
  risk_score: number;
  mitre_techniques: string[];
}

export interface GcpCollectorValidationResponse {
  provider: "gcp_audit";
  success: boolean;
  event_count: number;
  polled_at?: string | null;
  next_page_token?: string | null;
  sample_events: GcpAuditEvent[];
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export type IdentityProvider = "Okta" | "MicrosoftEntra";

export interface IdentityEvent {
  event_id: string;
  provider: IdentityProvider;
  event_type: string;
  outcome: string;
  timestamp: string;
  user_principal?: string | null;
  user_display_name?: string | null;
  source_ip?: string | null;
  user_agent?: string | null;
  location?: string | null;
  target_app?: string | null;
  mfa_used: boolean;
  provider_risk?: string | null;
  risk_score: number;
  mitre_techniques: string[];
  failure_reason?: string | null;
}

export interface OktaCollectorSetupPatch {
  domain?: string;
  api_token?: string | null;
  poll_interval_secs?: number;
  event_type_filter?: string[];
  enabled?: boolean;
}

export interface OktaCollectorConfigView {
  domain: string;
  poll_interval_secs: number;
  event_type_filter: string[];
  enabled: boolean;
  has_api_token: boolean;
}

export interface OktaCollectorConfigEnvelope {
  config: OktaCollectorConfigView;
  validation: SetupValidation;
}

export interface SaveOktaCollectorConfigResponse extends OktaCollectorConfigEnvelope {
  status: "saved";
  provider: "okta_identity";
}

export interface OktaCollectorValidationResponse {
  provider: "okta_identity";
  success: boolean;
  event_count: number;
  polled_at?: string | null;
  sample_events: IdentityEvent[];
  summary: Record<string, unknown>;
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export interface EntraCollectorSetupPatch {
  tenant_id?: string;
  client_id?: string;
  client_secret?: string | null;
  poll_interval_secs?: number;
  enabled?: boolean;
}

export interface EntraCollectorConfigView {
  tenant_id: string;
  client_id: string;
  poll_interval_secs: number;
  enabled: boolean;
  has_client_secret: boolean;
}

export interface EntraCollectorConfigEnvelope {
  config: EntraCollectorConfigView;
  validation: SetupValidation;
}

export interface SaveEntraCollectorConfigResponse extends EntraCollectorConfigEnvelope {
  status: "saved";
  provider: "entra_identity";
}

export interface EntraCollectorValidationResponse {
  provider: "entra_identity";
  success: boolean;
  event_count: number;
  polled_at?: string | null;
  sample_events: IdentityEvent[];
  summary: Record<string, unknown>;
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export interface M365AuditSample {
  content_type: string;
  tenant_id: string;
  workload: string;
  sample_operation: string;
  ingest_status: string;
}

export interface M365CollectorSetupPatch {
  tenant_id?: string;
  client_id?: string;
  client_secret?: string | null;
  poll_interval_secs?: number;
  content_types?: string[];
  enabled?: boolean;
}

export interface M365CollectorConfigView {
  tenant_id: string;
  client_id: string;
  poll_interval_secs: number;
  content_types: string[];
  enabled: boolean;
  has_client_secret: boolean;
}

export interface M365CollectorConfigEnvelope {
  config: M365CollectorConfigView;
  validation: SetupValidation;
}

export interface SaveM365CollectorConfigResponse extends M365CollectorConfigEnvelope {
  status: "saved";
  provider: "m365_saas";
}

export interface M365CollectorValidationResponse {
  provider: "m365_saas";
  success: boolean;
  event_count: number;
  sample_events: M365AuditSample[];
  summary: Record<string, unknown>;
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export interface WorkspaceAuditSample {
  application: string;
  customer_id: string;
  actor_email: string;
  service_account_email: string;
  sample_event: string;
  ingest_status: string;
}

export interface WorkspaceCollectorSetupPatch {
  customer_id?: string;
  delegated_admin_email?: string;
  service_account_email?: string;
  credentials_json?: string | null;
  poll_interval_secs?: number;
  applications?: string[];
  enabled?: boolean;
}

export interface WorkspaceCollectorConfigView {
  customer_id: string;
  delegated_admin_email: string;
  service_account_email: string;
  poll_interval_secs: number;
  applications: string[];
  enabled: boolean;
  has_credentials_json: boolean;
}

export interface WorkspaceCollectorConfigEnvelope {
  config: WorkspaceCollectorConfigView;
  validation: SetupValidation;
}

export interface SaveWorkspaceCollectorConfigResponse extends WorkspaceCollectorConfigEnvelope {
  status: "saved";
  provider: "workspace_saas";
}

export interface WorkspaceCollectorValidationResponse {
  provider: "workspace_saas";
  success: boolean;
  event_count: number;
  sample_events: WorkspaceAuditSample[];
  summary: Record<string, unknown>;
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export interface GithubAuditSampleEvent {
  action: string;
  actor: string;
  organization?: string;
  repository?: string;
  route: string;
}

export interface GithubCollectorSummary {
  organization: string;
  repository_count: number;
  has_token_ref: boolean;
  has_webhook_secret_ref: boolean;
}

export interface GithubCollectorSetupPatch {
  enabled?: boolean;
  organization?: string;
  token_ref?: string | null;
  webhook_secret_ref?: string | null;
  poll_interval_secs?: number;
  repositories?: string[];
}

export interface GithubCollectorConfigView {
  provider: "github_audit";
  enabled?: boolean;
  organization?: string;
  token_ref?: string;
  webhook_secret_ref?: string;
  poll_interval_secs?: number;
  repositories?: string[];
  required_fields: string[];
  has_token_ref?: boolean;
  has_webhook_secret_ref?: boolean;
}

export interface GithubCollectorConfigEnvelope {
  provider: "github_audit";
  config: GithubCollectorConfigView;
  validation: SetupValidation;
}

export interface SaveGithubCollectorConfigResponse extends GithubCollectorConfigEnvelope {
  status: "saved";
}

export interface GithubCollectorValidationResponse {
  provider: "github_audit";
  success: boolean;
  event_count: number;
  sample_events: GithubAuditSampleEvent[];
  summary: GithubCollectorSummary;
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export interface CrowdStrikeSampleEvent {
  event_simple_name: string;
  hostname?: string;
  severity?: string;
  customer_id?: string;
  route: string;
}

export interface CrowdStrikeCollectorSummary {
  cloud: string;
  client_id: string;
  customer_id: string;
  has_client_secret_ref: boolean;
}

export interface CrowdStrikeCollectorSetupPatch {
  enabled?: boolean;
  cloud?: string;
  client_id?: string;
  client_secret_ref?: string | null;
  customer_id?: string;
  poll_interval_secs?: number;
}

export interface CrowdStrikeCollectorConfigView {
  provider: "crowdstrike_falcon";
  enabled?: boolean;
  cloud?: string;
  client_id?: string;
  client_secret_ref?: string;
  customer_id?: string;
  poll_interval_secs?: number;
  required_fields: string[];
  has_client_secret_ref?: boolean;
}

export interface CrowdStrikeCollectorConfigEnvelope {
  provider: "crowdstrike_falcon";
  config: CrowdStrikeCollectorConfigView;
  validation: SetupValidation;
}

export interface SaveCrowdStrikeCollectorConfigResponse extends CrowdStrikeCollectorConfigEnvelope {
  status: "saved";
}

export interface CrowdStrikeCollectorValidationResponse {
  provider: "crowdstrike_falcon";
  success: boolean;
  event_count: number;
  sample_events: CrowdStrikeSampleEvent[];
  summary: CrowdStrikeCollectorSummary;
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export interface SyslogSampleEvent {
  facility: string;
  severity: string;
  message: string;
  route: string;
}

export interface SyslogCollectorSummary {
  bind: string;
  port: number;
  protocol: string;
  parse_profile: string;
}

export interface SyslogCollectorSetupPatch {
  enabled?: boolean;
  bind?: string;
  port?: number;
  protocol?: string;
  facility?: string;
  parse_profile?: string;
  poll_interval_secs?: number;
}

export interface SyslogCollectorConfigView {
  provider: "generic_syslog";
  enabled?: boolean;
  bind?: string;
  port?: number;
  protocol?: string;
  facility?: string;
  parse_profile?: string;
  poll_interval_secs?: number;
  required_fields: string[];
}

export interface SyslogCollectorConfigEnvelope {
  provider: "generic_syslog";
  config: SyslogCollectorConfigView;
  validation: SetupValidation;
}

export interface SaveSyslogCollectorConfigResponse extends SyslogCollectorConfigEnvelope {
  status: "saved";
}

export interface SyslogCollectorValidationResponse {
  provider: "generic_syslog";
  success: boolean;
  event_count: number;
  sample_events: SyslogSampleEvent[];
  summary: SyslogCollectorSummary;
  validation: SetupValidation;
  error?: string | null;
  reliability: CollectorCheckpoint;
}

export interface VaultSetupPatch {
  address?: string;
  token?: string | null;
  mount?: string;
  namespace?: string | null;
  enabled?: boolean;
  cache_ttl_secs?: number;
}

export interface VaultSetupView {
  address: string;
  mount: string;
  namespace?: string | null;
  enabled: boolean;
  cache_ttl_secs: number;
  has_token: boolean;
}

export interface SecretsManagerSetupPatch {
  vault?: VaultSetupPatch;
  env_prefix?: string | null;
  secrets_dir?: string | null;
}

export interface SecretsManagerSetupView {
  vault: VaultSetupView;
  env_prefix?: string | null;
  secrets_dir?: string | null;
  supported_sources: string[];
}

export interface SecretsStatus {
  vault_enabled: boolean;
  vault_address: string;
  cache_size: number;
  env_prefix?: string | null;
  secrets_dir?: string | null;
}

export interface SecretsManagerStatusResponse {
  config: SecretsManagerSetupView;
  validation: SetupValidation;
  status: SecretsStatus;
}

export interface SaveSecretsManagerConfigResponse {
  status: "saved";
  config: SecretsManagerSetupView;
  validation: SetupValidation;
  status_summary: SecretsStatus;
}

export type SecretReferenceKind = "env" | "file" | "vault" | "literal";

export interface SecretReferenceValidationRequest {
  reference: string;
}

export interface SecretReferenceValidationResponse {
  ok: boolean;
  reference_kind: SecretReferenceKind;
  resolved_length?: number | null;
  preview?: string | null;
  status: SecretsStatus;
  validation: SetupValidation;
  error?: string | null;
}

export interface ModelInfo {
  name: string;
  version: string;
  input_shape: number[];
  output_shape: number[];
  description: string;
}

export interface ShadowInferenceRecord {
  slot: string;
  timestamp: string;
  active_backend: string;
  active_label: string;
  active_confidence: number;
  shadow_backend?: string | null;
  shadow_label?: string | null;
  shadow_confidence?: number | null;
  confidence_delta?: number | null;
}

export interface MlModelRegistryStatus {
  slot: string;
  active_backend: string;
  shadow_backend?: string | null;
  shadow_mode: boolean;
  onnx_loaded: boolean;
  last_refreshed_at: string;
  discovered_models: string[];
  loaded_models: ModelInfo[];
  available_models: ModelInfo[];
  recent_shadow_reports: ShadowInferenceRecord[];
}

export interface MlModelsResponse {
  loaded: ModelInfo[];
  available: ModelInfo[];
}

export interface MlModelsRollbackResponse {
  status: MlModelRegistryStatus;
  changed: boolean;
  rolled_back_at: string;
}

export type AlertOutcome =
  | "TruePositive"
  | "FalsePositive"
  | "Benign"
  | "Inconclusive"
  | "Pending";

export interface EfficacyTriageRecord {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  outcome: AlertOutcome;
  triaged_by: string;
  created_at_ms: number;
  triaged_at_ms: number;
  triage_duration_ms: number;
  agent_id?: string | null;
}

export interface EfficacyTriageRecordResponse {
  status: "recorded";
}

export interface FpFeedback {
  alert_fingerprint: string;
  marked_fp: boolean;
  analyst: string;
  timestamp: string;
  reason_pattern: string;
}

export interface FpFeedbackResponse {
  recorded: boolean;
}

export interface FpFeedbackStat {
  pattern: string;
  total_marked: number;
  false_positives: number;
  fp_ratio: number;
  suppression_weight: number;
}

export type EfficacyTrend =
  | "Improving"
  | "Stable"
  | "Degrading"
  | "InsufficientData";

export interface SeverityEfficacy {
  total: number;
  tp_rate: number;
  fp_rate: number;
  mean_triage_secs: number;
}

export interface RuleEfficacy {
  rule_id: string;
  rule_name: string;
  total_alerts: number;
  true_positives: number;
  false_positives: number;
  benign: number;
  inconclusive: number;
  pending: number;
  tp_rate: number;
  fp_rate: number;
  precision: number;
  mean_triage_secs: number;
  trend: EfficacyTrend;
}

export interface EfficacySummary {
  total_alerts_triaged: number;
  overall_tp_rate: number;
  overall_fp_rate: number;
  overall_precision: number;
  mean_triage_secs: number;
  rules_tracked: number;
  worst_rules: RuleEfficacy[];
  best_rules: RuleEfficacy[];
  by_severity: Record<string, SeverityEfficacy>;
}

export type CanaryAction = "promoted" | "rolled_back" | "no_change";

export interface CanaryPromotionResult {
  rule_id: string;
  rule_name: string;
  action: CanaryAction;
  reason: string;
}

export interface AutoQuery {
  name: string;
  endpoint: string;
  description: string;
}

export interface InvestigationStep {
  order: number;
  title: string;
  description: string;
  api_pivot?: string | null;
  recommended_actions: string[];
  evidence_to_collect: string[];
  auto_queries: AutoQuery[];
}

export interface InvestigationWorkflow {
  id: string;
  name: string;
  description: string;
  trigger_conditions: string[];
  severity: string;
  mitre_techniques: string[];
  estimated_minutes: number;
  steps: InvestigationStep[];
  completion_criteria: string[];
}

export interface InvestigationHandoff {
  from_analyst: string;
  to_analyst: string;
  summary: string;
  next_actions: string[];
  questions: string[];
  updated_at: string;
}

export interface InvestigationSnapshot {
  id: string;
  workflow_id: string;
  workflow_name: string;
  workflow_description: string;
  workflow_severity: string;
  mitre_techniques: string[];
  estimated_minutes: number;
  case_id?: string | null;
  analyst: string;
  started_at: string;
  updated_at: string;
  completed_steps: number[];
  notes: Record<string, string>;
  status: string;
  findings: string[];
  handoff?: InvestigationHandoff | null;
  total_steps: number;
  completion_percent: number;
  next_step?: InvestigationStep | null;
  steps: InvestigationStep[];
  completion_criteria: string[];
}

export interface InvestigationStartRequest {
  workflow_id: string;
  analyst: string;
  case_id?: string | null;
}

export interface InvestigationProgressRequest {
  investigation_id: string;
  step?: number | null;
  completed?: boolean | null;
  note?: string | null;
  status?: string | null;
  finding?: string | null;
}

export interface InvestigationHandoffRequest {
  investigation_id: string;
  to_analyst: string;
  summary: string;
  next_actions?: string[];
  questions?: string[];
  case_id?: string | null;
}

export interface InvestigationSuggestRequest {
  alert_reasons: string[];
}

export interface InvestigationGraphRequest {
  event_ids: number[];
}

export interface GraphNode {
  id: string;
  kind: string;
  label: string;
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
}

export interface InvestigationGraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count: number;
  edge_count: number;
}

export interface TimelineEntry {
  timestamp: string;
  event_id: number;
  event_type: string;
  severity: string;
  description: string;
  agent_id: string;
}

export interface AgentTimelineResponse {
  timeline: TimelineEntry[];
  agent_id: string;
  count: number;
}

export interface HostTimelineResponse {
  timeline: TimelineEntry[];
  host: string;
  count: number;
}

export type TriageLabel = "TruePositive" | "FalsePositive" | "NeedsReview";

export interface TriageFeatures {
  anomaly_score: number;
  confidence: number;
  suspicious_axes: number;
  hour_of_day: number;
  day_of_week: number;
  alert_frequency_1h: number;
  device_risk_score: number;
}

export interface TriageResult {
  label: TriageLabel;
  confidence: number;
  model_version: string;
}

export interface ConfidenceCalibration {
  raw_confidence: number;
  calibrated_confidence: number;
  band: string;
}

export interface ManagedTriageOutcome {
  result: TriageResult;
  shadow?: TriageResult | null;
  fallback_used: boolean;
  active_backend: string;
  shadow_backend?: string | null;
  calibration: ConfidenceCalibration;
  rationale: string[];
}

export interface MlShadowRecentResponse {
  count: number;
  items: ShadowInferenceRecord[];
}

export interface RemediationReviewApproval {
  approver: string;
  decision: "approve" | "deny";
  comment?: string;
  signed_at: string;
  signature: string;
}

export interface RemediationReviewApprovalRequest {
  decision?: "approve" | "deny";
  approver?: string;
  comment?: string;
}

export interface RemediationCommand {
  program: string;
  args: string[];
  requires_elevation: boolean;
}

export interface RemediationCommandExecution {
  program: string;
  args: string[];
  executed: boolean;
  exit_code?: number | null;
  stdout: string;
  stderr: string;
  duration_ms: number;
}

export type RemediationPlatform = "Linux" | "MacOs" | "Windows";

export type RemediationStatus =
  | "Success"
  | "PartialSuccess"
  | "Failed"
  | "RolledBack"
  | "Skipped"
  | "PendingApproval";

export type LaunchItemType = "Daemon" | "Agent";

export type PersistenceMechanism =
  | { SystemdUnit: { name: string } }
  | { CronJob: { user: string; pattern: string } }
  | { InitScript: { path: string } }
  | { LaunchItem: { path: string; item_type: LaunchItemType } }
  | { LoginItem: { name: string } }
  | { RegistryRunKey: { hive: string; value_name: string } }
  | { ScheduledTask: { name: string } }
  | { WmiSubscription: { name: string } }
  | { WindowsService: { name: string } };

export type RemediationAction =
  | { KillProcess: { pid: number; name: string } }
  | { QuarantineFile: { path: string } }
  | { RestoreFile: { path: string; source: string } }
  | { RemovePersistence: { mechanism: PersistenceMechanism } }
  | { RevertRegistry: { key: string; value_name: string; original_data: string } }
  | { BlockIp: { addr: string } }
  | { DisableAccount: { username: string } }
  | { RevokeTokens: { username: string } }
  | { RestartService: { service_name: string } }
  | { PatchPackage: { package: string; version: string } }
  | { ResetPermissions: { path: string; mode: string } }
  | { RemoveScheduledTask: { task_name: string } }
  | "FlushDns"
  | { Custom: { label: string; command: string; args: string[] } };

export interface RemediationResult {
  action: RemediationAction;
  status: RemediationStatus;
  commands_run: RemediationCommand[];
  snapshot_id: string | null;
  output: string | null;
  error: string | null;
  duration_ms: number;
}

export interface RemediationPlan {
  action: RemediationAction;
  platform: RemediationPlatform;
  commands: RemediationCommand[];
  prerequisites: string[];
  needs_approval: boolean;
}

export interface RemediationStats {
  succeeded: number;
  partial: number;
  failed: number;
  rolled_back: number;
  skipped: number;
  pending: number;
}

export type RemediationPlanPlatform =
  | "linux"
  | "macos"
  | "darwin"
  | "windows"
  | "win32";

export interface RemediationPlanRequestBase {
  platform?: RemediationPlanPlatform;
}

export type RemediationPlanRequest =
  | (RemediationPlanRequestBase & { action: "flush_dns" })
  | (RemediationPlanRequestBase & { action: "block_ip"; addr: string })
  | (RemediationPlanRequestBase & { action: "kill_process"; pid: number; name: string })
  | (RemediationPlanRequestBase & { action: "disable_account"; username: string })
  | (RemediationPlanRequestBase & { action: "quarantine_file"; path: string });

export interface RemediationRollbackExecutionResult {
  dry_run: boolean;
  platform: string;
  snapshot_id: string;
  commands: RemediationCommand[];
  command_executions: RemediationCommandExecution[];
  live_execution: string;
  result: RemediationResult;
}

export interface RemediationRollbackProof {
  proof_id: string;
  generated_at: string;
  status: string;
  pre_change_digest: string;
  recovery_plan: string[];
  verification_digest: string;
  verified_by?: string;
  executed_at?: string;
  execution_result?: RemediationRollbackExecutionResult;
}

export interface RemediationChangeReview {
  id: string;
  title: string;
  asset_id: string;
  change_type: string;
  source: string;
  summary: string;
  risk: string;
  approval_status: string;
  recovery_status: string;
  requested_by: string;
  requested_at: string;
  required_approvers: number;
  approvals: RemediationReviewApproval[];
  approval_chain_digest?: string;
  rollback_proof?: RemediationRollbackProof;
  evidence: Record<string, unknown>;
}

export interface RemediationChangeReviewSummary {
  total: number;
  pending: number;
  approved: number;
  recovery_ready: number;
  signed: number;
  multi_approver_ready: number;
  rollback_proofs: number;
}

export interface RemediationChangeReviewListResponse {
  summary: RemediationChangeReviewSummary;
  reviews: RemediationChangeReview[];
}

export interface RemediationChangeReviewRequest {
  id?: string;
  title: string;
  asset_id?: string;
  change_type?: string;
  source?: string;
  summary?: string;
  risk?: string;
  approval_status?: string;
  recovery_status?: string;
  required_approvers?: number;
  approvals?: RemediationReviewApprovalRequest[];
  evidence?: Record<string, unknown>;
}

export interface RemediationRollbackRequest {
  dry_run?: boolean;
  platform?: string;
  confirm_hostname?: string;
}

export interface RemediationChangeReviewMutationResponse {
  status: "recorded" | "approved" | "rollback_recorded";
  review: RemediationChangeReview;
}

interface RequestOptions {
  responseType?: "json" | "text";
  contentType?: string;
  rawBody?: BodyInit;
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
      "Content-Type": options?.contentType ?? "application/json",
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }

    const requestBody =
      options?.rawBody !== undefined
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
        return undefined as T;
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

  async healthLive(): Promise<HealthLiveResponse> {
    return this.request("GET", "/api/healthz/live");
  }

  async healthReady(): Promise<HealthReadyResponse> {
    return this.request("GET", "/api/healthz/ready");
  }

  async wsStats(): Promise<WsStatsResponse> {
    return this.request("GET", "/api/ws/stats");
  }

  async commandSummary(): Promise<CommandSummaryResponse> {
    return this.request("GET", "/api/command/summary");
  }

  async commandLane(lane: string): Promise<CommandLaneResponse> {
    return this.request("GET", `/api/command/lanes/${encodeURIComponent(lane)}`);
  }

  async authCheck(): Promise<AuthCheckResponse> {
    return this.request("GET", "/api/auth/check");
  }

  async authSession(): Promise<AuthSession> {
    return this.request("GET", "/api/auth/session");
  }

  async createAuthSession(): Promise<AuthSessionCreateResponse> {
    return this.request("POST", "/api/auth/session");
  }

  async authLogout(): Promise<LogoutResponse> {
    return this.request("POST", "/api/auth/logout");
  }

  async sessionInfo(): Promise<SessionInfo> {
    return this.request("GET", "/api/session/info");
  }

  async openApiSpec(): Promise<OpenApiSpecDocument> {
    return this.request("GET", "/api/openapi.json");
  }

  async supportDiagnostics(): Promise<SupportDiagnosticsResponse> {
    return this.request("GET", "/api/support/diagnostics");
  }

  async supportParity(): Promise<SupportParityResponse> {
    return this.request("GET", "/api/support/parity");
  }

  async readinessEvidence(): Promise<SupportReadinessEvidenceResponse> {
    return this.request("GET", "/api/support/readiness-evidence");
  }

  async firstRunProof(): Promise<FirstRunProofResponse> {
    return this.request("POST", "/api/support/first-run-proof");
  }

  async productionDemoLab(): Promise<FirstRunProofResponse> {
    return this.request("POST", "/api/demo/lab");
  }

  async docsIndex(params: DocsIndexParams = {}): Promise<DocsIndexResponse> {
    const query = new URLSearchParams();
    if (params.q) query.set("q", String(params.q));
    if (params.section) query.set("section", String(params.section));
    if (params.limit != null) query.set("limit", String(params.limit));
    const suffix = query.toString();
    return this.request("GET", `/api/docs/index${suffix ? `?${suffix}` : ""}`);
  }

  async docsContent(path: string): Promise<DocContentResponse> {
    return this.request("GET", `/api/docs/content?path=${encodeURIComponent(String(path ?? ""))}`);
  }

  async systemDeps(): Promise<SystemHealthDependenciesResponse> {
    return this.request("GET", "/api/system/health/dependencies");
  }

  // ── Alerts ───────────────────────────────────────────────────────

  async alerts(): Promise<Alert[]> {
    return this.request("GET", "/api/alerts");
  }

  async alertsCount(): Promise<AlertSeverityCounts> {
    return this.request("GET", "/api/alerts/count");
  }

  async clearAlerts(): Promise<ClearAlertsResponse> {
    return this.request("DELETE", "/api/alerts");
  }

  async sampleAlert(
    request: SampleAlertRequest = {}
  ): Promise<SampleAlertResponse> {
    return this.request("POST", "/api/alerts/sample", request);
  }

  async bulkAcknowledgeAlerts(
    request: AlertBulkActionRequest
  ): Promise<AlertBulkAcknowledgeResponse> {
    return this.request("POST", "/api/alerts/bulk/acknowledge", request);
  }

  async bulkResolveAlerts(
    request: AlertBulkActionRequest
  ): Promise<AlertBulkResolveResponse> {
    return this.request("POST", "/api/alerts/bulk/resolve", request);
  }

  async bulkCloseAlerts(
    request: AlertBulkActionRequest
  ): Promise<AlertBulkCloseResponse> {
    return this.request("POST", "/api/alerts/bulk/close", request);
  }

  async alertAnalysis(): Promise<AlertAnalysis> {
    return this.request("GET", "/api/alerts/analysis");
  }

  async runAlertAnalysis(
    request: AlertAnalysisRequest = {}
  ): Promise<AlertAnalysis> {
    return this.request("POST", "/api/alerts/analysis", request);
  }

  async groupedAlerts(): Promise<AlertGroup[]> {
    return this.request("GET", "/api/alerts/grouped");
  }

  async getAlert(index: number): Promise<AlertDetail> {
    return this.request("GET", `/api/alerts/${encodeURIComponent(String(index))}`);
  }

  async queueStats(): Promise<QueueStatsResponse> {
    return this.request("GET", "/api/queue/stats");
  }

  async dlqStats(): Promise<DlqStatsResponse> {
    return this.request("GET", "/api/dlq/stats");
  }

  async dlq(): Promise<DlqListResponse> {
    return this.request("GET", "/api/dlq");
  }

  async dlqClear(): Promise<DlqClearResponse> {
    return this.request("DELETE", "/api/dlq");
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
    behavior?: BehaviorSignals,
    allowlist?: ScanAllowlist
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

  async memoryIndicatorsScanMaps(
    request: MemoryIndicatorsScanMapsRequest
  ): Promise<MemoryIndicatorReport> {
    return this.request("POST", "/api/memory-indicators/scan-maps", request);
  }

  async memoryIndicatorsScanBuffer(
    data: Uint8Array | string
  ): Promise<PatternMatch[]> {
    const body =
      typeof data === "string" ? data : Buffer.from(data).toString("base64");
    return this.request("POST", "/api/memory-indicators/scan-buffer", undefined, {
      contentType: "text/plain",
      rawBody: body,
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

  async collectorsAws(): Promise<AwsCollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/aws");
  }

  async saveAwsCollectorConfig(
    config: AwsCollectorSetupPatch,
  ): Promise<SaveAwsCollectorConfigResponse> {
    return this.request("POST", "/api/collectors/aws/config", config);
  }

  async validateAwsCollector(): Promise<AwsCollectorValidationResponse> {
    return this.request("POST", "/api/collectors/aws/validate");
  }

  async collectorsAzure(): Promise<AzureCollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/azure");
  }

  async saveAzureCollectorConfig(
    config: AzureCollectorSetupPatch,
  ): Promise<SaveAzureCollectorConfigResponse> {
    return this.request("POST", "/api/collectors/azure/config", config);
  }

  async validateAzureCollector(): Promise<AzureCollectorValidationResponse> {
    return this.request("POST", "/api/collectors/azure/validate");
  }

  async collectorsGcp(): Promise<GcpCollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/gcp");
  }

  async saveGcpCollectorConfig(
    config: GcpCollectorSetupPatch,
  ): Promise<SaveGcpCollectorConfigResponse> {
    return this.request("POST", "/api/collectors/gcp/config", config);
  }

  async validateGcpCollector(): Promise<GcpCollectorValidationResponse> {
    return this.request("POST", "/api/collectors/gcp/validate");
  }

  async collectorsOkta(): Promise<OktaCollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/okta");
  }

  async saveOktaCollectorConfig(
    config: OktaCollectorSetupPatch,
  ): Promise<SaveOktaCollectorConfigResponse> {
    return this.request("POST", "/api/collectors/okta/config", config);
  }

  async validateOktaCollector(): Promise<OktaCollectorValidationResponse> {
    return this.request("POST", "/api/collectors/okta/validate");
  }

  async collectorsEntra(): Promise<EntraCollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/entra");
  }

  async saveEntraCollectorConfig(
    config: EntraCollectorSetupPatch,
  ): Promise<SaveEntraCollectorConfigResponse> {
    return this.request("POST", "/api/collectors/entra/config", config);
  }

  async validateEntraCollector(): Promise<EntraCollectorValidationResponse> {
    return this.request("POST", "/api/collectors/entra/validate");
  }

  async collectorsM365(): Promise<M365CollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/m365");
  }

  async saveM365CollectorConfig(
    config: M365CollectorSetupPatch,
  ): Promise<SaveM365CollectorConfigResponse> {
    return this.request("POST", "/api/collectors/m365/config", config);
  }

  async validateM365Collector(): Promise<M365CollectorValidationResponse> {
    return this.request("POST", "/api/collectors/m365/validate");
  }

  async collectorsWorkspace(): Promise<WorkspaceCollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/workspace");
  }

  async saveWorkspaceCollectorConfig(
    config: WorkspaceCollectorSetupPatch,
  ): Promise<SaveWorkspaceCollectorConfigResponse> {
    return this.request("POST", "/api/collectors/workspace/config", config);
  }

  async validateWorkspaceCollector(): Promise<WorkspaceCollectorValidationResponse> {
    return this.request("POST", "/api/collectors/workspace/validate");
  }

  async collectorsGithub(): Promise<GithubCollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/github");
  }

  async saveGithubCollectorConfig(
    config: GithubCollectorSetupPatch,
  ): Promise<SaveGithubCollectorConfigResponse> {
    return this.request("POST", "/api/collectors/github/config", config);
  }

  async validateGithubCollector(): Promise<GithubCollectorValidationResponse> {
    return this.request("POST", "/api/collectors/github/validate");
  }

  async collectorsCrowdStrike(): Promise<CrowdStrikeCollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/crowdstrike");
  }

  async saveCrowdStrikeCollectorConfig(
    config: CrowdStrikeCollectorSetupPatch,
  ): Promise<SaveCrowdStrikeCollectorConfigResponse> {
    return this.request("POST", "/api/collectors/crowdstrike/config", config);
  }

  async validateCrowdStrikeCollector(): Promise<CrowdStrikeCollectorValidationResponse> {
    return this.request("POST", "/api/collectors/crowdstrike/validate");
  }

  async collectorsSyslog(): Promise<SyslogCollectorConfigEnvelope> {
    return this.request("GET", "/api/collectors/syslog");
  }

  async saveSyslogCollectorConfig(
    config: SyslogCollectorSetupPatch,
  ): Promise<SaveSyslogCollectorConfigResponse> {
    return this.request("POST", "/api/collectors/syslog/config", config);
  }

  async validateSyslogCollector(): Promise<SyslogCollectorValidationResponse> {
    return this.request("POST", "/api/collectors/syslog/validate");
  }

  async secretsStatus(): Promise<SecretsManagerStatusResponse> {
    return this.request("GET", "/api/secrets/status");
  }

  async saveSecretsConfig(
    config: SecretsManagerSetupPatch,
  ): Promise<SaveSecretsManagerConfigResponse> {
    return this.request("POST", "/api/secrets/config", config);
  }

  async validateSecretReference(
    request: SecretReferenceValidationRequest,
  ): Promise<SecretReferenceValidationResponse> {
    return this.request("POST", "/api/secrets/validate", request);
  }

  async fleetInstalls(): Promise<FleetInstallHistoryResponse> {
    return this.request("GET", "/api/fleet/installs");
  }

  async fleetInstallSsh(
    request: FleetInstallSshRequest,
  ): Promise<RemoteInstallRecord> {
    return this.request("POST", "/api/fleet/install/ssh", request);
  }

  async fleetInstallWinrm(
    request: FleetInstallWinrmRequest,
  ): Promise<RemoteInstallRecord> {
    return this.request("POST", "/api/fleet/install/winrm", request);
  }

  async processTree(): Promise<ProcessTreeResponse> {
    return this.request("GET", "/api/process-tree");
  }

  async processesLive(): Promise<ProcessLiveResponse> {
    return this.request("GET", "/api/processes/live");
  }

  async processesAnalysis(): Promise<ProcessAnalysisResponse> {
    return this.request("GET", "/api/processes/analysis");
  }

  async deepChains(): Promise<ProcessDeepChainsResponse> {
    return this.request("GET", "/api/process-tree/deep-chains");
  }

  async processDetail(pid: number | string): Promise<ProcessDetail> {
    return this.request(
      "GET",
      `/api/processes/detail?pid=${encodeURIComponent(String(pid))}`,
    );
  }

  async processThreads(pid: number | string): Promise<ProcessThreadsSnapshot> {
    return this.request(
      "GET",
      `/api/processes/threads?pid=${encodeURIComponent(String(pid))}`,
    );
  }

  async hostApps(): Promise<HostAppsResponse> {
    return this.request("GET", "/api/host/apps");
  }

  async hostInventory(): Promise<HostSystemInventory> {
    return this.request("GET", "/api/host/inventory");
  }

  async remediationPlan(
    request: RemediationPlanRequest,
  ): Promise<RemediationPlan> {
    return this.request("POST", "/api/remediation/plan", request);
  }

  async remediationResults(): Promise<RemediationResult[]> {
    return this.request("GET", "/api/remediation/results");
  }

  async remediationStats(): Promise<RemediationStats> {
    return this.request("GET", "/api/remediation/stats");
  }

  async remediationChangeReviews(): Promise<RemediationChangeReviewListResponse> {
    return this.request("GET", "/api/remediation/change-reviews");
  }

  async recordRemediationChangeReview(
    review: RemediationChangeReviewRequest,
  ): Promise<RemediationChangeReviewMutationResponse> {
    return this.request("POST", "/api/remediation/change-reviews", review);
  }

  async approveRemediationChangeReview(
    id: string,
    approval: RemediationReviewApprovalRequest,
  ): Promise<RemediationChangeReviewMutationResponse> {
    return this.request(
      "POST",
      `/api/remediation/change-reviews/${encodeURIComponent(id)}/approval`,
      approval,
    );
  }

  async executeRemediationRollback(
    id: string,
    request: RemediationRollbackRequest,
  ): Promise<RemediationChangeReviewMutationResponse> {
    return this.request(
      "POST",
      `/api/remediation/change-reviews/${encodeURIComponent(id)}/rollback`,
      request,
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

  async analystQuery(query: AnalystSearchQuery): Promise<AnalystSearchResponse> {
    return this.request("POST", "/api/events/search", query);
  }

  async hunt(query: string): Promise<SearchResult> {
    return this.request("POST", "/api/hunt", { query });
  }

  async sigmaStats(): Promise<SigmaStatsResponse> {
    return this.request("GET", "/api/sigma/stats");
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

  async complianceStatus(): Promise<ComplianceReport> {
    return this.request("GET", "/api/compliance/status");
  }

  async complianceReport(
    frameworkId?: string
  ): Promise<ComplianceReport | ComplianceReport[]> {
    const path = frameworkId
      ? `/api/compliance/report?framework=${encodeURIComponent(frameworkId)}`
      : "/api/compliance/report";
    return this.request("GET", path);
  }

  async complianceSummary(): Promise<ComplianceSummaryResponse> {
    return this.request("GET", "/api/compliance/summary");
  }

  // ── SIEM Export ──────────────────────────────────────────────────

  async siemStatus(): Promise<SiemStatus> {
    return this.request("GET", "/api/siem/status");
  }

  async siemConfig(): Promise<SiemConfigEnvelope> {
    return this.request("GET", "/api/siem/config");
  }

  async saveSiemConfig(config: SiemConfigRequest): Promise<SaveSiemConfigResponse> {
    return this.request("POST", "/api/siem/config", config);
  }

  async validateSiemConfig(
    config: SiemConfigRequest,
  ): Promise<ValidateSiemConfigResponse> {
    return this.request("POST", "/api/siem/validate", config);
  }

  async taxiiStatus(): Promise<TaxiiStatus> {
    return this.request("GET", "/api/taxii/status");
  }

  async taxiiConfig(): Promise<TaxiiConfig> {
    return this.request("GET", "/api/taxii/config");
  }

  async saveTaxiiConfig(config: TaxiiConfig): Promise<TaxiiConfigMutationResponse> {
    return this.request("POST", "/api/taxii/config", config);
  }

  async taxiiPull(): Promise<TaxiiPullResponse> {
    return this.request("POST", "/api/taxii/pull");
  }

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

  async exportTla(): Promise<string> {
    return this.request("GET", "/api/export/tla", undefined, {
      responseType: "text",
    });
  }

  async exportAlloy(): Promise<string> {
    return this.request("GET", "/api/export/alloy", undefined, {
      responseType: "text",
    });
  }

  async exportWitnesses(): Promise<WitnessBundle[]> {
    return this.request("GET", "/api/export/witnesses");
  }

  // ── Backups ──────────────────────────────────────────────────────

  async listBackups(): Promise<BackupRecord[]> {
    return this.request("GET", "/api/backups");
  }

  async createBackup(): Promise<BackupRecord> {
    return this.request("POST", "/api/backups");
  }

  async adminBackup(): Promise<AdminBackupResponse> {
    return this.request("POST", "/api/admin/backup");
  }

  async adminDbVersion(): Promise<AdminDbVersionResponse> {
    return this.request("GET", "/api/admin/db/version");
  }

  async adminDbSizes(): Promise<AdminDbSizesResponse> {
    return this.request("GET", "/api/admin/db/sizes");
  }

  async adminDbRollback(): Promise<AdminDbRollbackResponse> {
    return this.request("POST", "/api/admin/db/rollback");
  }

  async adminDbCompact(): Promise<AdminDbCompactResponse> {
    return this.request("POST", "/api/admin/db/compact");
  }

  async adminDbReset(
    request: AdminDbResetRequest
  ): Promise<AdminDbResetResponse> {
    return this.request("POST", "/api/admin/db/reset", request);
  }

  async adminDbPurge(
    request: AdminDbPurgeRequest
  ): Promise<AdminDbPurgeResponse> {
    return this.request("POST", "/api/admin/db/purge", request);
  }

  async adminCleanupLegacy(): Promise<AdminCleanupLegacyResponse> {
    return this.request("POST", "/api/admin/cleanup-legacy");
  }

  async sbom(): Promise<SbomDocument> {
    return this.request("GET", "/api/sbom");
  }

  async sbomHost(): Promise<SbomDocument> {
    return this.request("GET", "/api/sbom/host");
  }

  async piiScan(sample: string): Promise<PiiScanResponse> {
    return this.request("POST", "/api/pii/scan", undefined, {
      rawBody: sample,
      contentType: "text/plain",
    });
  }

  async license(): Promise<LicenseStatusResponse> {
    return this.request("GET", "/api/license");
  }

  async validateLicense(
    request: LicenseValidateRequest
  ): Promise<LicenseValidateResponse> {
    return this.request("POST", "/api/license/validate", request);
  }

  async meteringUsage(): Promise<MeteringUsageResponse> {
    return this.request("GET", "/api/metering/usage");
  }

  async billingSubscription(): Promise<BillingSubscriptionResponse> {
    return this.request("GET", "/api/billing/subscription");
  }

  async billingInvoices(): Promise<BillingInvoicesResponse> {
    return this.request("GET", "/api/billing/invoices");
  }

  async listMarketplacePacks(): Promise<MarketplaceContentPack[]> {
    return this.request("GET", "/api/marketplace/packs");
  }

  async getMarketplacePack(packId: string): Promise<MarketplaceContentPack> {
    return this.request(
      "GET",
      `/api/marketplace/packs/${encodeURIComponent(packId)}`
    );
  }

  async preventionPolicies(): Promise<PreventionPolicy[]> {
    return this.request("GET", "/api/prevention/policies");
  }

  async preventionStats(): Promise<PreventionStats> {
    return this.request("GET", "/api/prevention/stats");
  }

  async pipelineStatus(): Promise<PipelineStatusResponse> {
    return this.request("GET", "/api/pipeline/status");
  }

  // ── Audit ────────────────────────────────────────────────────────

  async auditVerify(): Promise<AuditVerifyReport> {
    return this.request("GET", "/api/audit/verify");
  }

  async auditLogs(limit?: number, offset?: number): Promise<AuditLogPage> {
    return this.request(
      "GET",
      `/api/audit/log?limit=${limit ?? 100}&offset=${offset ?? 0}`,
    );
  }

  // ── Analytics ────────────────────────────────────────────────────

  async apiAnalytics(): Promise<AnalyticsSummary> {
    return this.request("GET", "/api/analytics");
  }

  async traces(): Promise<TracesResponse> {
    return this.request("GET", "/api/traces");
  }

  async backupStatus(): Promise<BackupStatus> {
    return this.request("GET", "/api/backup/status");
  }

  async backupEncrypt(
    request: BackupEncryptRequest
  ): Promise<BackupEncryptResponse> {
    return this.request("POST", "/api/backup/encrypt", request);
  }

  async backupDecrypt(
    request: BackupDecryptRequest
  ): Promise<BackupDecryptResponse> {
    return this.request("POST", "/api/backup/decrypt", request);
  }

  // ── Dedup ────────────────────────────────────────────────────────

  async dedupAlerts(): Promise<DedupIncident[]> {
    return this.request("GET", "/api/alerts/dedup");
  }

  async autoCreateDedupIncidents(): Promise<DedupAutoCreateResponse> {
    return this.request("POST", "/api/alerts/dedup/auto-create");
  }

  // ── UEBA ─────────────────────────────────────────────────────────

  async uebaObserve(
    observation: BehaviorObservation,
  ): Promise<UebaObserveResponse> {
    return this.request("POST", "/api/ueba/observe", observation);
  }

  async uebaRiskyEntities(): Promise<EntityRisk[]> {
    return this.request("GET", "/api/ueba/risky");
  }

  async uebaEntity(entityId: string): Promise<EntityRisk> {
    return this.request("GET", `/api/ueba/entity/${encodeURIComponent(entityId)}`);
  }

  // ── NDR ──────────────────────────────────────────────────────────

  async ndrReport(): Promise<NdrReport> {
    return this.request("GET", "/api/ndr/report");
  }

  async beaconConnection(connection: BeaconConnectionRecord): Promise<BeaconRecordResponse> {
    return this.request("POST", "/api/beacon/connection", connection);
  }

  async beaconDns(dns: BeaconDnsRecord): Promise<BeaconRecordResponse> {
    return this.request("POST", "/api/beacon/dns", dns);
  }

  async beaconAnalyze(): Promise<BeaconSummary> {
    return this.request("GET", "/api/beacon/analyze");
  }

  async ndrIngest(netflow: NetFlowRecord): Promise<NdrIngestResponse> {
    return this.request("POST", "/api/ndr/netflow", netflow);
  }

  async ndrTlsAnomalies(): Promise<TlsFingerprintAnomaly[]> {
    return this.request("GET", "/api/ndr/tls-anomalies");
  }

  async ndrDpiAnomalies(): Promise<DpiAnomaly[]> {
    return this.request("GET", "/api/ndr/dpi-anomalies");
  }

  async ndrEntropyAnomalies(): Promise<EntropyAnomaly[]> {
    return this.request("GET", "/api/ndr/entropy-anomalies");
  }

  async ndrSelfSignedCerts(): Promise<SelfSignedCert[]> {
    return this.request("GET", "/api/ndr/self-signed-certs");
  }

  async ndrTopTalkers(limit?: number): Promise<TopTalker[]> {
    const talkers = await this.request<TopTalker[]>("GET", "/api/ndr/top-talkers");
    const normalizedLimit = limit === undefined ? 20 : Math.max(0, Math.trunc(limit));
    return talkers.slice(0, normalizedLimit);
  }

  async ndrBeaconing(): Promise<BeaconingAnomaly[]> {
    return this.request("GET", "/api/ndr/beaconing");
  }

  async ndrProtocolDistribution(): Promise<ProtocolDistribution[]> {
    return this.request("GET", "/api/ndr/protocol-distribution");
  }

  // ── Email Security ───────────────────────────────────────────────

  async emailAnalyze(input: EmailAnalyzeRequest): Promise<EmailThreatReport> {
    return this.request("POST", "/api/email/analyze", {
      ...input,
      received_chain: input.received_chain ?? [],
      attachments: input.attachments ?? [],
    });
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

  async listIncidents(): Promise<Incident[]> {
    return this.request("GET", "/api/incidents");
  }

  async getIncident(incidentId: string): Promise<Incident> {
    return this.request("GET", `/api/incidents/${encodeURIComponent(incidentId)}`);
  }

  async createIncident(
    title: string,
    severity: string,
    summary?: string,
    options?: CreateIncidentOptions,
  ): Promise<Incident> {
    return this.request("POST", "/api/incidents", {
      title,
      severity,
      summary: summary ?? "",
      event_ids: options?.event_ids ?? [],
      agent_ids: options?.agent_ids ?? [],
    });
  }

  // ── Fleet ────────────────────────────────────────────────────────

  async listAgents(): Promise<AgentSummary[]> {
    return this.request("GET", "/api/agents");
  }

  async getAgent(agentId: string): Promise<AgentActivitySnapshot> {
    return this.request("GET", `/api/agents/${encodeURIComponent(agentId)}/details`);
  }

  // ── Policy ───────────────────────────────────────────────────────

  async currentPolicy(): Promise<PolicyRecord> {
    return this.request("GET", "/api/policy/current");
  }

  async publishPolicy(policy: PublishPolicyRequest): Promise<PolicyRecord> {
    return this.request("POST", "/api/policy/publish", {
      version: policy.version ?? 0,
      published_at: policy.published_at ?? "",
      ...policy,
    });
  }

  // ── Assets ───────────────────────────────────────────────────────

  async assets(): Promise<UnifiedAsset[]> {
    return this.request("GET", "/api/assets");
  }

  async assetsSearch(query: string): Promise<UnifiedAsset[]> {
    return this.request(
      "GET",
      `/api/assets/search?q=${encodeURIComponent(query)}`
    );
  }

  async assetsSummary(): Promise<AssetSummaryResponse> {
    return this.request("GET", "/api/assets/summary");
  }

  async upsertAsset(asset: UnifiedAsset): Promise<AssetUpsertResponse> {
    return this.request("POST", "/api/assets/upsert", asset);
  }

  async lifecycle(): Promise<AgentLifecycleEntry[]> {
    return this.request("GET", "/api/lifecycle");
  }

  async lifecycleStats(): Promise<AgentLifecycleSweepResult> {
    return this.request("GET", "/api/lifecycle/stats");
  }

  async lifecycleSweep(): Promise<AgentLifecycleSweepResult> {
    return this.request("POST", "/api/lifecycle/sweep");
  }

  async iocDecayApply(): Promise<IocDecayResult> {
    return this.request("POST", "/api/ioc-decay/apply");
  }

  async iocDecayPreview(): Promise<IocDecayPreview[]> {
    return this.request("GET", "/api/ioc-decay/preview");
  }

  async certsRegister(
    certificate: CertificateRecord
  ): Promise<CertRegisterResponse> {
    return this.request("POST", "/api/certs/register", certificate);
  }

  async certsSummary(): Promise<CertSummary> {
    return this.request("GET", "/api/certs/summary");
  }

  async certsAlerts(): Promise<CertAlert[]> {
    return this.request("GET", "/api/certs/alerts");
  }

  async quarantineList(): Promise<QuarantinedFile[]> {
    return this.request("GET", "/api/quarantine");
  }

  async quarantineAdd(
    request: QuarantineAddRequest
  ): Promise<QuarantineAddResponse> {
    return this.request("POST", "/api/quarantine", request);
  }

  async quarantineStats(): Promise<QuarantineStats> {
    return this.request("GET", "/api/quarantine/stats");
  }

  async quarantineRelease(id: string): Promise<QuarantineReleaseResponse> {
    return this.request(
      "POST",
      `/api/quarantine/${encodeURIComponent(id)}/release`
    );
  }

  async quarantineDelete(id: string): Promise<void> {
    return this.request("DELETE", `/api/quarantine/${encodeURIComponent(id)}`);
  }

  async entropyAnalyze(sample: string): Promise<EntropyReport> {
    return this.request("POST", "/api/entropy/analyze", undefined, {
      rawBody: sample,
      contentType: "text/plain",
    });
  }

  async dnsThreatAnalyze(
    request: DnsThreatAnalyzeRequest | string
  ): Promise<DnsThreatReport> {
    const body = typeof request === "string" ? { domain: request } : request;
    return this.request("POST", "/api/dns-threat/analyze", body);
  }

  async dnsThreatSummary(): Promise<DnsThreatSummary> {
    return this.request("GET", "/api/dns-threat/summary");
  }

  async dnsThreatRecord(query: DnsQuery): Promise<DnsThreatRecordResponse> {
    return this.request("POST", "/api/dns-threat/record", query);
  }

  async images(): Promise<ContainerImage[]> {
    return this.request("GET", "/api/images");
  }

  async imagesSummary(): Promise<ImageInventorySummary> {
    return this.request("GET", "/api/images/summary");
  }

  async imagesCollect(): Promise<ContainerImage[]> {
    return this.request("POST", "/api/images/collect");
  }

  async configDriftCheck(
    request: ConfigDriftCheckRequest
  ): Promise<DriftReport> {
    return this.request("POST", "/api/config-drift/check", request);
  }

  async configDriftBaselines(): Promise<ConfigDriftBaselineSummary> {
    return this.request("GET", "/api/config-drift/baselines");
  }

  async coverageGaps(): Promise<GapAnalysisReport> {
    return this.request("GET", "/api/coverage/gaps");
  }

  async detectorSlowAttack(): Promise<SlowAttackReport> {
    return this.request("GET", "/api/detectors/slow-attack");
  }

  async detectorRansomware(): Promise<RansomwareSignal> {
    return this.request("GET", "/api/detectors/ransomware");
  }

  async retentionStatus(): Promise<RetentionStatusResponse> {
    return this.request("GET", "/api/retention/status");
  }

  async retentionApply(): Promise<RetentionApplyResponse> {
    return this.request("POST", "/api/retention/apply");
  }

  async evidencePlanLinux(): Promise<EvidenceCollectionPlan> {
    return this.request("GET", "/api/evidence/plan/linux");
  }

  async evidencePlanMacos(): Promise<EvidenceCollectionPlan> {
    return this.request("GET", "/api/evidence/plan/macos");
  }

  async evidencePlanWindows(): Promise<EvidenceCollectionPlan> {
    return this.request("GET", "/api/evidence/plan/windows");
  }

  // ── Vulnerability ────────────────────────────────────────────────

  async vulnerabilityScan(): Promise<VulnerabilityReport[]> {
    return this.request("GET", "/api/vulnerability/scan");
  }

  async vulnerabilitySummary(): Promise<VulnerabilitySummary> {
    return this.request("GET", "/api/vulnerability/summary");
  }

  // ── Container ────────────────────────────────────────────────────

  async containerAlerts(): Promise<ContainerAlert[]> {
    return this.request("GET", "/api/container/alerts");
  }

  async containerStats(): Promise<ContainerStatsResponse> {
    return this.request("GET", "/api/container/stats");
  }

  // ── Response Actions ─────────────────────────────────────────────

  async responseStats(): Promise<ResponseStatsResponse> {
    return this.request("GET", "/api/response/stats");
  }

  async casesStats(): Promise<CasesStatsResponse> {
    return this.request("GET", "/api/cases/stats");
  }

  async platform(): Promise<PlatformCapabilitiesResponse> {
    return this.request("GET", "/api/platform");
  }

  async sloStatus(): Promise<SloStatus> {
    return this.request("GET", "/api/slo/status");
  }

  async feedStats(): Promise<FeedIngestionStatsResponse> {
    return this.request("GET", "/api/feeds/stats");
  }

  async responseRequests(): Promise<ResponseRequestsResponse> {
    return this.request("GET", "/api/response/requests");
  }

  async requestResponseAction(
    action: ResponseRequestCreateRequest | Record<string, unknown>
  ): Promise<ResponseRequestSubmissionResponse> {
    return this.request("POST", "/api/response/request", action);
  }

  async responseRequest(
    action: ResponseRequestCreateRequest
  ): Promise<ResponseRequestSubmissionResponse> {
    return this.request("POST", "/api/response/request", action);
  }

  async approveResponseAction(
    requestId: string,
    approve: boolean = true
  ): Promise<ResponseApprovalResponse> {
    return this.request("POST", "/api/response/approve", {
      request_id: requestId,
      decision: approve ? "approved" : "denied",
    });
  }

  async executeApprovedActions(requestId?: string): Promise<ResponseExecuteResponse> {
    return this.request("POST", "/api/response/execute", requestId ? { request_id: requestId } : {});
  }

  async responseExecute(requestId?: string): Promise<ResponseExecuteResponse> {
    return this.request("POST", "/api/response/execute", requestId ? { request_id: requestId } : {});
  }

  // ── Telemetry ────────────────────────────────────────────────────

  async ingestEvents(agentId: string, events: EventAlertRecord[]): Promise<EventIngestResponse> {
    return this.request("POST", "/api/events", { agent_id: agentId, events });
  }

  async onboardingReadiness(): Promise<OnboardingReadiness> {
    return this.request("GET", "/api/onboarding/readiness");
  }

  async managerOverview(): Promise<ManagerOverview> {
    return this.request("GET", "/api/manager/overview");
  }

  async managerQueueDigest(): Promise<ManagerQueueDigest> {
    return this.request("GET", "/api/manager/queue-digest");
  }

  async authSsoConfig(): Promise<AuthSsoConfigResponse> {
    return this.request("GET", "/api/auth/sso/config");
  }

  async authRotate(): Promise<AuthRotateResponse> {
    return this.request("POST", "/api/auth/rotate");
  }

  async assistantStatus(): Promise<AssistantStatusResponse> {
    return this.request("GET", "/api/assistant/status");
  }

  async assistantQuery(query: AssistantQueryRequest): Promise<AssistantQueryResponse> {
    return this.request("POST", "/api/assistant/query", query);
  }

  async detectionExplain(
    params: { event_id?: number; alert_id?: string } = {}
  ): Promise<DetectionExplainability> {
    const qs = new URLSearchParams();
    if (params.event_id != null) qs.set("event_id", String(params.event_id));
    if (params.alert_id) qs.set("alert_id", params.alert_id);
    return this.request("GET", `/api/detection/explain${qs.toString() ? `?${qs.toString()}` : ""}`);
  }

  async detectionFeedback(
    eventId?: number,
    limit?: number
  ): Promise<DetectionFeedbackListResponse> {
    const qs = new URLSearchParams();
    if (eventId != null) qs.set("event_id", String(eventId));
    if (limit != null) qs.set("limit", String(limit));
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

  async detectionProfile(): Promise<DetectionProfileResponse> {
    return this.request("GET", "/api/detection/profile");
  }

  async setDetectionProfile(
    request: SetDetectionProfileRequest
  ): Promise<SetDetectionProfileResponse> {
    return this.request("PUT", "/api/detection/profile", request);
  }

  async normalizeScore(): Promise<NormalizedScore> {
    return this.request("GET", "/api/detection/score/normalize");
  }

  // ── Threat Intel ─────────────────────────────────────────────────

  async threatIntelStats(): Promise<IoCEnrichmentStats> {
    return this.request("GET", "/api/threat-intel/stats");
  }

  async metrics(): Promise<string> {
    return this.request("GET", "/api/metrics", undefined, { responseType: "text" });
  }

  async threatIntelStatus(): Promise<ThreatIntelStatusResponse> {
    return this.request("GET", "/api/threat-intel/status");
  }

  async addIoc(ioc: AddIocRequest): Promise<AddIocResponse> {
    return this.request("POST", "/api/threat-intel/ioc", ioc);
  }

  async threatIntelLibraryV2(): Promise<ThreatIntelLibraryV2Response> {
    return this.request("GET", "/api/threat-intel/library/v2");
  }

  async threatIntelSightings(limit: number = 50): Promise<ThreatIntelSightingsResponse> {
    return this.request("GET", `/api/threat-intel/sightings?limit=${limit}`);
  }

  async efficacySummary(): Promise<EfficacySummary> {
    return this.request("GET", "/api/efficacy/summary");
  }

  async efficacyRule(id: string): Promise<RuleEfficacy | null> {
    return this.request("GET", `/api/efficacy/rule/${encodeURIComponent(id)}`);
  }

  async efficacyCanaryPromote(): Promise<CanaryPromotionResult[]> {
    return this.request("POST", "/api/efficacy/canary-promote");
  }

  async investigationWorkflows(): Promise<InvestigationWorkflow[]> {
    return this.request("GET", "/api/investigations/workflows");
  }

  async investigationWorkflow(id: string): Promise<InvestigationWorkflow> {
    return this.request(
      "GET",
      `/api/investigations/workflows/${encodeURIComponent(id)}`
    );
  }

  async investigationStart(
    request: InvestigationStartRequest
  ): Promise<InvestigationSnapshot> {
    return this.request("POST", "/api/investigations/start", request);
  }

  async investigationActive(): Promise<InvestigationSnapshot[]> {
    return this.request("GET", "/api/investigations/active");
  }

  async investigationProgress(
    request: InvestigationProgressRequest
  ): Promise<InvestigationSnapshot> {
    return this.request("POST", "/api/investigations/progress", request);
  }

  async investigationHandoff(
    request: InvestigationHandoffRequest
  ): Promise<InvestigationSnapshot> {
    return this.request("POST", "/api/investigations/handoff", request);
  }

  async investigationSuggest(
    request: InvestigationSuggestRequest
  ): Promise<InvestigationWorkflow[]> {
    return this.request("POST", "/api/investigations/suggest", request);
  }

  async investigationGraph(
    request: InvestigationGraphRequest
  ): Promise<InvestigationGraphResponse> {
    return this.request("POST", "/api/investigation/graph", request);
  }

  async timelineHost(hostname: string): Promise<HostTimelineResponse> {
    return this.request(
      "GET",
      `/api/timeline/host?hostname=${encodeURIComponent(hostname)}`
    );
  }

  async timelineAgent(agentId: string): Promise<AgentTimelineResponse> {
    return this.request(
      "GET",
      `/api/timeline/agent?agent_id=${encodeURIComponent(agentId)}`
    );
  }

  async efficacyTriage(
    record: EfficacyTriageRecord
  ): Promise<EfficacyTriageRecordResponse> {
    return this.request("POST", "/api/efficacy/triage", record);
  }

  async fpFeedback(feedback: FpFeedback): Promise<FpFeedbackResponse> {
    return this.request("POST", "/api/fp-feedback", feedback);
  }

  async fpFeedbackStats(): Promise<FpFeedbackStat[]> {
    return this.request("GET", "/api/fp-feedback/stats");
  }

  async mlModels(): Promise<MlModelsResponse> {
    return this.request("GET", "/api/ml/models");
  }

  async mlModelsStatus(): Promise<MlModelRegistryStatus> {
    return this.request("GET", "/api/ml/models/status");
  }

  async mlModelStatus(): Promise<MlModelRegistryStatus> {
    return this.mlModelsStatus();
  }

  async mlModelsRollback(): Promise<MlModelsRollbackResponse> {
    return this.request("POST", "/api/ml/models/rollback");
  }

  async mlRollback(): Promise<MlModelsRollbackResponse> {
    return this.mlModelsRollback();
  }

  async mlShadowRecent(limit: number = 20): Promise<MlShadowRecentResponse> {
    return this.request("GET", `/api/ml/shadow/recent?limit=${limit}`);
  }

  async mlTriage(features: TriageFeatures): Promise<TriageResult> {
    return this.request("POST", "/api/ml/triage", features);
  }

  async mlTriageV2(features: TriageFeatures): Promise<ManagedTriageOutcome> {
    return this.request("POST", "/api/ml/triage/v2", features);
  }

  // ── Campaigns ────────────────────────────────────────────────────

  async campaigns(): Promise<CampaignCorrelationView> {
    return this.request("GET", "/api/correlation/campaigns");
  }
}

export default WardexClient;

// ── OpenAPI 3.0 Specification Generator ──────────────────────────────────────
//
// Generates a machine-readable OpenAPI 3.0.3 JSON spec describing the Wardex
// REST API surface.  The spec is served at GET /api/openapi.json and can be
// consumed by Swagger UI, Redoc, or SDK code-generators.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ── Core types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: Info,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<Server>,
    pub paths: BTreeMap<String, PathItem>,
    pub components: Components,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security: Vec<BTreeMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub title: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<License>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Contact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub put: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<Operation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub operation_id: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<Parameter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<RequestBody>,
    pub responses: BTreeMap<String, Response>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security: Vec<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub required: bool,
    pub schema: SchemaRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub required: bool,
    pub content: BTreeMap<String, MediaType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaType {
    pub schema: SchemaRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<BTreeMap<String, MediaType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SchemaRef {
    Ref {
        #[serde(rename = "$ref")]
        reference: String,
    },
    Inline(Schema),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Schema {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub schema_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaRef>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub properties: BTreeMap<String, SchemaRef>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub required: Vec<String>,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Components {
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub schemas: BTreeMap<String, Schema>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub security_schemes: BTreeMap<String, SecurityScheme>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScheme {
    #[serde(rename = "type")]
    pub scheme_type: String,
    pub scheme: String,
    #[serde(rename = "bearerFormat", skip_serializing_if = "Option::is_none")]
    pub bearer_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ── Builder ──────────────────────────────────────────────────────────────────

pub struct OpenApiBuilder {
    spec: OpenApiSpec,
}

impl OpenApiBuilder {
    pub fn new(title: &str, version: &str) -> Self {
        let mut security_schemes = BTreeMap::new();
        security_schemes.insert(
            "bearerAuth".into(),
            SecurityScheme {
                scheme_type: "http".into(),
                scheme: "bearer".into(),
                bearer_format: Some("token".into()),
                description: Some("Admin or RBAC user API token".into()),
            },
        );

        Self {
            spec: OpenApiSpec {
                openapi: "3.0.3".into(),
                info: Info {
                    title: title.into(),
                    version: version.into(),
                    description: Some(
                        "Wardex XDR/SIEM REST API — detection, fleet management, incident response, and platform operations."
                            .into(),
                    ),
                    license: Some(License {
                        name: "BSL-1.1".into(),
                        url: Some("https://mariadb.com/bsl11/".into()),
                    }),
                    contact: None,
                },
                servers: vec![Server {
                    url: "http://localhost:8080".into(),
                    description: Some("Local development server".into()),
                }],
                paths: BTreeMap::new(),
                components: Components {
                    schemas: BTreeMap::new(),
                    security_schemes,
                },
                security: vec![{
                    let mut m = BTreeMap::new();
                    m.insert("bearerAuth".into(), vec![]);
                    m
                }],
                tags: Vec::new(),
            },
        }
    }

    pub fn tag(mut self, name: &str, desc: &str) -> Self {
        self.spec.tags.push(Tag {
            name: name.into(),
            description: Some(desc.into()),
        });
        self
    }

    pub fn schema(mut self, name: &str, schema: Schema) -> Self {
        self.spec.components.schemas.insert(name.into(), schema);
        self
    }

    pub fn path(mut self, path: &str, method: &str, op: Operation) -> Self {
        let item = self.spec.paths.entry(path.into()).or_default();
        match method {
            "get" => item.get = Some(op),
            "post" => item.post = Some(op),
            "put" => item.put = Some(op),
            "delete" => item.delete = Some(op),
            "patch" => item.patch = Some(op),
            _ => {}
        }
        self
    }

    pub fn build(self) -> OpenApiSpec {
        self.spec
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn json_response(desc: &str) -> BTreeMap<String, Response> {
    let mut m = BTreeMap::new();
    m.insert(
        "200".into(),
        Response {
            description: desc.into(),
            content: Some({
                let mut c = BTreeMap::new();
                c.insert(
                    "application/json".into(),
                    MediaType {
                        schema: SchemaRef::Inline(Schema {
                            schema_type: Some("object".into()),
                            ..Default::default()
                        }),
                    },
                );
                c
            }),
        },
    );
    m
}

fn error_responses() -> BTreeMap<String, Response> {
    let mut m = BTreeMap::new();
    m.insert("401".into(), Response { description: "Unauthorized — missing or invalid Bearer token".into(), content: None });
    m.insert("404".into(), Response { description: "Resource not found".into(), content: None });
    m.insert("429".into(), Response { description: "Rate limit exceeded".into(), content: None });
    m
}

fn json_body(desc: &str) -> Option<RequestBody> {
    Some(RequestBody {
        description: Some(desc.into()),
        required: true,
        content: {
            let mut c = BTreeMap::new();
            c.insert(
                "application/json".into(),
                MediaType {
                    schema: SchemaRef::Inline(Schema {
                        schema_type: Some("object".into()),
                        ..Default::default()
                    }),
                },
            );
            c
        },
    })
}

fn op(id: &str, summary: &str, tags: &[&str]) -> Operation {
    let mut resp = json_response(summary);
    resp.extend(error_responses());
    Operation {
        summary: summary.into(),
        description: None,
        operation_id: id.into(),
        tags: tags.iter().map(|t| t.to_string()).collect(),
        parameters: vec![],
        request_body: None,
        responses: resp,
        security: vec![],
    }
}

fn op_post(id: &str, summary: &str, tags: &[&str], body_desc: &str) -> Operation {
    let mut o = op(id, summary, tags);
    o.request_body = json_body(body_desc);
    o
}

fn op_public(id: &str, summary: &str, tags: &[&str]) -> Operation {
    let mut o = op(id, summary, tags);
    o.security = vec![BTreeMap::new()]; // empty = no auth required
    o
}

// ── Wardex spec factory ──────────────────────────────────────────────────────

pub fn wardex_openapi_spec(version: &str) -> OpenApiSpec {
    OpenApiBuilder::new("Wardex XDR/SIEM API", version)
        // Tags
        .tag("auth", "Authentication, session, and token management")
        .tag("status", "Platform health, status, and diagnostics")
        .tag("detection", "Detection engineering, rules, and analysis")
        .tag("alerts", "Alert queue, triage, and analysis")
        .tag("incidents", "Incident and case management")
        .tag("fleet", "Fleet enrollment, agents, and heartbeats")
        .tag("response", "Response orchestration and enforcement")
        .tag("policy", "Policy composition, publishing, and VM execution")
        .tag("threat-intel", "Threat intelligence, IoCs, and deception")
        .tag("telemetry", "Telemetry collection and event forwarding")
        .tag("compliance", "Compliance scoring and evidence")
        .tag("config", "Configuration management")
        .tag("reports", "Reports, exports, and executive summaries")
        .tag("updates", "Agent updates, releases, and rollouts")
        .tag("hunts", "Saved hunts, scheduling, and detection content")
        .tag("quantum", "Post-quantum cryptography status and key rotation")
        .tag("swarm", "Mesh networking, swarm posture, and peer management")
        .tag("observability", "Metrics, logging, and monitoring")
        // Schemas
        .schema("Error", Schema {
            schema_type: Some("object".into()),
            properties: {
                let mut p = BTreeMap::new();
                p.insert("error".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p
            },
            ..Default::default()
        })
        .schema("Alert", Schema {
            schema_type: Some("object".into()),
            properties: {
                let mut p = BTreeMap::new();
                p.insert("id".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p.insert("level".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), enum_values: Some(vec!["nominal".into(), "elevated".into(), "severe".into(), "critical".into()]), ..Default::default() }));
                p.insert("timestamp".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), format: Some("date-time".into()), ..Default::default() }));
                p.insert("device_id".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p.insert("reasons".into(), SchemaRef::Inline(Schema { schema_type: Some("array".into()), items: Some(Box::new(SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }))), ..Default::default() }));
                p.insert("score".into(), SchemaRef::Inline(Schema { schema_type: Some("number".into()), format: Some("float".into()), ..Default::default() }));
                p
            },
            required: vec!["id".into(), "level".into(), "timestamp".into()],
            ..Default::default()
        })
        .schema("Incident", Schema {
            schema_type: Some("object".into()),
            properties: {
                let mut p = BTreeMap::new();
                p.insert("id".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p.insert("title".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p.insert("severity".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p.insert("status".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), enum_values: Some(vec!["open".into(), "investigating".into(), "contained".into(), "closed".into()]), ..Default::default() }));
                p.insert("created_at".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), format: Some("date-time".into()), ..Default::default() }));
                p
            },
            required: vec!["id".into(), "title".into(), "severity".into()],
            ..Default::default()
        })
        .schema("Agent", Schema {
            schema_type: Some("object".into()),
            properties: {
                let mut p = BTreeMap::new();
                p.insert("agent_id".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p.insert("hostname".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p.insert("os".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p.insert("version".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), ..Default::default() }));
                p.insert("last_heartbeat".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), format: Some("date-time".into()), ..Default::default() }));
                p.insert("status".into(), SchemaRef::Inline(Schema { schema_type: Some("string".into()), enum_values: Some(vec!["online".into(), "offline".into(), "stale".into()]), ..Default::default() }));
                p
            },
            ..Default::default()
        })
        // ── Auth ──
        .path("/api/auth/check", "get", op("authCheck", "Check authentication status", &["auth"]))
        .path("/api/auth/rotate", "post", op_post("authRotate", "Rotate API token", &["auth"], "Token rotation request"))
        .path("/api/session/info", "get", op("sessionInfo", "Get session metadata, uptime, and TTL", &["auth"]))
        // ── Status & Health ──
        .path("/api/status", "get", op_public("getStatus", "Platform status and fleet overview", &["status"]))
        .path("/api/health", "get", op_public("getHealth", "Health check", &["status"]))
        .path("/api/report", "get", op_public("getReport", "Latest analysis report with samples", &["reports"]))
        .path("/api/host/info", "get", op("getHostInfo", "Host system information", &["status"]))
        .path("/api/platform/capabilities", "get", op("getPlatformCapabilities", "Platform feature capabilities", &["status"]))
        .path("/api/diagnostics/bundle", "get", op("getDiagnosticsBundle", "Diagnostics bundle for support", &["status"]))
        // ── Telemetry ──
        .path("/api/telemetry/current", "get", op("getTelemetryCurrent", "Current telemetry snapshot", &["telemetry"]))
        .path("/api/telemetry/history", "get", op("getTelemetryHistory", "Telemetry time-series history", &["telemetry"]))
        .path("/api/events", "post", op_post("pushEvents", "Push telemetry events from agent", &["telemetry"], "Array of telemetry events"))
        .path("/api/events", "get", op("getEvents", "List stored events", &["telemetry"]))
        .path("/api/events/bulk-triage", "post", op_post("bulkTriageEvents", "Bulk triage events by filter", &["telemetry"], "Triage filter and action"))
        // ── Alerts ──
        .path("/api/alerts", "get", op("getAlerts", "List alerts with optional severity filter", &["alerts"]))
        .path("/api/alerts", "delete", op("clearAlerts", "Clear all alerts", &["alerts"]))
        .path("/api/alerts/count", "get", op("getAlertCount", "Alert count by severity", &["alerts"]))
        .path("/api/alerts/sample", "post", op_post("sendSampleAlert", "Send a sample alert for testing", &["alerts"], "Sample alert definition"))
        .path("/api/alerts/analysis", "post", op_post("triggerAlertAnalysis", "Trigger alert analysis pipeline", &["alerts"], "Analysis parameters"))
        .path("/api/queue/alerts", "get", op("getAlertQueue", "SOC alert queue with SLA status", &["alerts"]))
        // ── Analysis ──
        .path("/api/analyze", "post", op_post("analyzeData", "Run detection pipeline on uploaded data", &["detection"], "Telemetry payload (JSONL or CSV)"))
        // ── Detection ──
        .path("/api/detection/rules", "get", op("getDetectionRules", "List active detection rules", &["detection"]))
        .path("/api/detection/test", "post", op_post("testDetectionRule", "Test a detection rule against sample data", &["detection"], "Rule definition and test data"))
        .path("/api/velocity/status", "get", op("getVelocityStatus", "Velocity anomaly detector status", &["detection"]))
        .path("/api/entropy/status", "get", op("getEntropyStatus", "Entropy anomaly detector status", &["detection"]))
        .path("/api/beacon/connections", "get", op("getBeaconConnections", "Beacon detector connections", &["detection"]))
        .path("/api/beacon/dns", "get", op("getBeaconDns", "DNS tunnelling analysis", &["detection"]))
        .path("/api/correlation", "get", op("getCorrelation", "Signal correlation matrix", &["detection"]))
        .path("/api/side-channel/status", "get", op("getSideChannelStatus", "Side-channel analysis report", &["detection"]))
        .path("/api/kill-chain/reconstruct", "post", op_post("reconstructKillChain", "Reconstruct kill-chain phases from alerts", &["detection"], "Alert IDs to reconstruct"))
        .path("/api/lateral/analyze", "post", op_post("analyzeLateral", "Lateral movement graph analysis", &["detection"], "Connection log entries"))
        .path("/api/ueba/observe", "post", op_post("uebaObserve", "Submit UEBA observation", &["detection"], "User/entity behavior observation"))
        .path("/api/ueba/risky", "get", op("getUebaRisky", "Top risky entities from UEBA", &["detection"]))
        // ── Hunts & Content ──
        .path("/api/hunts", "get", op("listHunts", "List saved hunts", &["hunts"]))
        .path("/api/hunts", "post", op_post("createHunt", "Create a new saved hunt", &["hunts"], "Hunt definition"))
        .path("/api/content/rules", "get", op("listContentRules", "List detection content rules", &["hunts"]))
        .path("/api/content/rules", "post", op_post("createContentRule", "Create detection content rule", &["hunts"], "Rule definition"))
        .path("/api/content/packs", "get", op("listContentPacks", "List content packs", &["hunts"]))
        .path("/api/content/packs", "post", op_post("createContentPack", "Create content pack", &["hunts"], "Pack definition"))
        .path("/api/coverage/mitre", "get", op("getMitreCoverage", "MITRE ATT&CK technique coverage", &["hunts"]))
        .path("/api/suppressions", "get", op("listSuppressions", "List alert suppressions", &["hunts"]))
        .path("/api/suppressions", "post", op_post("createSuppression", "Create alert suppression rule", &["hunts"], "Suppression definition"))
        // ── Incidents & Cases ──
        .path("/api/incidents", "get", op("listIncidents", "List incidents", &["incidents"]))
        .path("/api/incidents", "post", op_post("createIncident", "Create a new incident", &["incidents"], "Incident title and severity"))
        .path("/api/cases", "get", op("listCases", "List investigation cases", &["incidents"]))
        .path("/api/cases", "post", op_post("createCase", "Create investigation case", &["incidents"], "Case definition"))
        // ── Fleet & Agents ──
        .path("/api/fleet/register", "post", op_post("registerFleet", "Register new fleet member", &["fleet"], "Fleet registration payload"))
        .path("/api/fleet/agents", "get", op("listAgents", "List enrolled agents", &["fleet"]))
        .path("/api/fleet/dashboard", "get", op("fleetDashboard", "Fleet operations dashboard", &["fleet"]))
        .path("/api/agents/enroll", "post", op_post("enrollAgent", "Enroll a new agent", &["fleet"], "Agent enrollment request"))
        .path("/api/agents/token", "post", op_post("issueAgentToken", "Issue agent API token", &["fleet"], "Agent ID"))
        // ── Response & Enforcement ──
        .path("/api/response/request", "post", op_post("requestResponse", "Request a response action", &["response"], "Response action request"))
        .path("/api/response/approve", "post", op_post("approveResponse", "Approve a pending response action", &["response"], "Approval payload"))
        .path("/api/response/execute", "post", op_post("executeResponse", "Execute an approved response action", &["response"], "Execution payload"))
        .path("/api/enforcement/quarantine", "post", op_post("quarantineDevice", "Quarantine a device", &["response"], "Device ID and reason"))
        .path("/api/enforcement/status", "get", op("getEnforcementStatus", "Enforcement status and history", &["response"]))
        // ── Control Plane ──
        .path("/api/control/mode", "post", op_post("setMode", "Set detection mode (normal/frozen/decay)", &["config"], "Mode name"))
        .path("/api/control/reset-baseline", "post", op("resetBaseline", "Reset detection baseline", &["config"]))
        .path("/api/control/run-demo", "post", op("runDemo", "Run demo analysis", &["config"]))
        .path("/api/control/checkpoint", "post", op("createCheckpoint", "Create state checkpoint", &["config"]))
        .path("/api/control/restore-checkpoint", "post", op_post("restoreCheckpoint", "Restore from checkpoint", &["config"], "Checkpoint ID"))
        // ── Policy ──
        .path("/api/policy/compose", "post", op_post("composePolicy", "Compose policy from operators", &["policy"], "Policy composition request"))
        .path("/api/policy/publish", "post", op_post("publishPolicy", "Publish a policy version", &["policy"], "Policy payload"))
        .path("/api/policy/current", "get", op_public("getCurrentPolicy", "Get current active policy", &["policy"]))
        .path("/api/policy/history", "get", op("getPolicyHistory", "Policy version history", &["policy"]))
        .path("/api/policy-vm/execute", "post", op_post("executePolicyVm", "Execute policy in Wasm VM", &["policy"], "Wasm execution request"))
        // ── Threat Intel ──
        .path("/api/threat-intel/status", "get", op("getThreatIntelStatus", "Threat intelligence status", &["threat-intel"]))
        .path("/api/threat-intel/ioc", "post", op_post("addIoc", "Add indicator of compromise", &["threat-intel"], "IoC definition"))
        .path("/api/deception/deploy", "post", op_post("deployDeception", "Deploy deception canary", &["threat-intel"], "Canary configuration"))
        .path("/api/deception/status", "get", op("getDeceptionStatus", "Deception engine status", &["threat-intel"]))
        // ── Digital Twin & Energy ──
        .path("/api/digital-twin/simulate", "post", op_post("simulateTwin", "Run digital twin simulation", &["detection"], "Simulation parameters"))
        .path("/api/digital-twin/status", "get", op("getTwinStatus", "Digital twin status", &["detection"]))
        .path("/api/energy/budget", "get", op("getEnergyBudget", "Energy budget status", &["config"]))
        .path("/api/energy/consume", "post", op_post("consumeEnergy", "Report energy consumption", &["config"], "Consumption data"))
        // ── Quantum ──
        .path("/api/quantum/status", "get", op("getQuantumStatus", "Post-quantum key status", &["quantum"]))
        .path("/api/quantum/rotate", "post", op("rotateQuantumKeys", "Rotate post-quantum keys", &["quantum"]))
        // ── Updates & Rollouts ──
        .path("/api/updates/releases", "get", op("listReleases", "List published releases", &["updates"]))
        .path("/api/updates/publish", "post", op_post("publishRelease", "Publish a new release", &["updates"], "Release payload"))
        .path("/api/updates/deploy", "post", op_post("deployUpdate", "Deploy update to agent group", &["updates"], "Deployment target and version"))
        .path("/api/updates/rollback", "post", op_post("rollbackUpdate", "Rollback a deployment", &["updates"], "Rollback parameters"))
        .path("/api/updates/cancel", "post", op_post("cancelUpdate", "Cancel an in-progress deployment", &["updates"], "Deployment ID"))
        .path("/api/updates/check", "get", op("checkForUpdates", "Check for available updates", &["updates"]))
        // ── Swarm & Mesh ──
        .path("/api/swarm/posture", "get", op("getSwarmPosture", "Swarm cluster posture", &["swarm"]))
        .path("/api/mesh/peers", "get", op("getMeshPeers", "List mesh peers", &["swarm"]))
        .path("/api/mesh/heal", "post", op("healMesh", "Trigger mesh self-healing", &["swarm"]))
        // ── Compliance ──
        .path("/api/compliance/score", "get", op("getComplianceScore", "Overall compliance score", &["compliance"]))
        .path("/api/compliance/evidence", "get", op("getComplianceEvidence", "Compliance evidence packages", &["compliance"]))
        // ── Config ──
        .path("/api/config", "get", op("getConfig", "Current configuration", &["config"]))
        .path("/api/config/reload", "post", op("reloadConfig", "Hot-reload configuration", &["config"]))
        .path("/api/config/save", "post", op_post("saveConfig", "Save configuration changes", &["config"], "Config patch"))
        // ── Audit & Retention ──
        .path("/api/audit/log", "get", op("getAuditLog", "Audit log entries", &["observability"]))
        .path("/api/retention/status", "get", op("getRetentionStatus", "Data retention policy status", &["config"]))
        .path("/api/retention/apply", "post", op("applyRetention", "Apply retention policy now", &["config"]))
        // ── SIEM ──
        .path("/api/siem/status", "get", op("getSiemStatus", "SIEM connector status", &["telemetry"]))
        .path("/api/siem/config", "post", op_post("configureSiem", "Configure SIEM connector", &["telemetry"], "SIEM connector configuration"))
        // ── Metrics ──
        .path("/api/metrics", "get", op_public("getMetrics", "Prometheus-format metrics", &["observability"]))
        .path("/api/openapi.json", "get", op_public("getOpenApiSpec", "This OpenAPI specification", &["status"]))
        // ── Shutdown ──
        .path("/api/shutdown", "post", op("shutdownServer", "Gracefully shut down the server", &["config"]))
        // ── Workbench ──
        .path("/api/workbench/overview", "get", op("getWorkbenchOverview", "SOC Workbench overview", &["incidents"]))
        .path("/api/manager/overview", "get", op("getManagerOverview", "Manager operational overview", &["reports"]))
        // ── Research & Advanced ──
        .path("/api/drift/status", "get", op("getDriftStatus", "Feature drift status", &["detection"]))
        .path("/api/drift/reset", "post", op("resetDrift", "Reset drift tracking", &["detection"]))
        .path("/api/fingerprint/status", "get", op("getFingerprintStatus", "Device fingerprint status", &["detection"]))
        .path("/api/harness/run", "post", op_post("runHarness", "Run adversarial harness test", &["detection"], "Harness scenario"))
        .path("/api/privacy/budget", "get", op("getPrivacyBudget", "Differential privacy budget status", &["compliance"]))
        .path("/api/offload/decide", "post", op_post("decideOffload", "Edge/cloud offload decision", &["config"], "Offload parameters"))
        .path("/api/tenants", "get", op("listTenants", "List tenants", &["fleet"]))
        .path("/api/tenants/count", "get", op("getTenantCount", "Tenant count", &["fleet"]))
        // ── Entities & Enrichment ──
        .path("/api/enrichments/connectors", "get", op("listEnrichmentConnectors", "List enrichment connectors", &["threat-intel"]))
        .path("/api/enrichments/connectors", "post", op_post("addEnrichmentConnector", "Add enrichment connector", &["threat-intel"], "Connector definition"))
        .path("/api/tickets/sync", "post", op_post("syncTickets", "Sync with external ticket system", &["incidents"], "Ticket sync request"))
        .build()
}

pub fn openapi_json(version: &str) -> String {
    let spec = wardex_openapi_spec(version);
    serde_json::to_string_pretty(&spec).unwrap_or_else(|_| "{}".into())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_has_correct_version() {
        let spec = wardex_openapi_spec("0.35.0");
        assert_eq!(spec.openapi, "3.0.3");
        assert_eq!(spec.info.version, "0.35.0");
    }

    #[test]
    fn spec_has_paths() {
        let spec = wardex_openapi_spec("0.35.0");
        assert!(spec.paths.len() > 80);
        assert!(spec.paths.contains_key("/api/status"));
        assert!(spec.paths.contains_key("/api/alerts"));
        assert!(spec.paths.contains_key("/api/fleet/agents"));
    }

    #[test]
    fn spec_has_tags() {
        let spec = wardex_openapi_spec("0.35.0");
        let tag_names: Vec<&str> = spec.tags.iter().map(|t| t.name.as_str()).collect();
        assert!(tag_names.contains(&"auth"));
        assert!(tag_names.contains(&"alerts"));
        assert!(tag_names.contains(&"fleet"));
        assert!(tag_names.contains(&"detection"));
        assert!(tag_names.contains(&"observability"));
    }

    #[test]
    fn spec_has_security_scheme() {
        let spec = wardex_openapi_spec("0.35.0");
        assert!(spec.components.security_schemes.contains_key("bearerAuth"));
    }

    #[test]
    fn spec_has_schemas() {
        let spec = wardex_openapi_spec("0.35.0");
        assert!(spec.components.schemas.contains_key("Alert"));
        assert!(spec.components.schemas.contains_key("Incident"));
        assert!(spec.components.schemas.contains_key("Agent"));
        assert!(spec.components.schemas.contains_key("Error"));
    }

    #[test]
    fn spec_serializes_to_json() {
        let json = openapi_json("0.35.0");
        assert!(json.contains("\"openapi\":"));
        assert!(json.contains("3.0.3"));
        assert!(json.contains("/api/status"));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn operations_have_ids() {
        let spec = wardex_openapi_spec("0.35.0");
        for (_path, item) in &spec.paths {
            if let Some(ref o) = item.get {
                assert!(!o.operation_id.is_empty());
            }
            if let Some(ref o) = item.post {
                assert!(!o.operation_id.is_empty());
            }
        }
    }

    #[test]
    fn post_endpoints_have_request_body() {
        let spec = wardex_openapi_spec("0.35.0");
        let posts_with_body: Vec<&str> = spec
            .paths
            .iter()
            .filter(|(_, item)| item.post.as_ref().map_or(false, |o| o.request_body.is_some()))
            .map(|(p, _)| p.as_str())
            .collect();
        assert!(posts_with_body.contains(&"/api/analyze"));
        assert!(posts_with_body.contains(&"/api/response/request"));
    }

    #[test]
    fn public_endpoints_have_empty_security() {
        let spec = wardex_openapi_spec("0.35.0");
        let status_op = spec.paths.get("/api/status").unwrap().get.as_ref().unwrap();
        assert!(!status_op.security.is_empty());
    }

    #[test]
    fn metrics_endpoint_included() {
        let spec = wardex_openapi_spec("0.35.0");
        assert!(spec.paths.contains_key("/api/metrics"));
    }
}

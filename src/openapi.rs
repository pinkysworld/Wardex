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
    #[serde(rename = "x-wardex-auth", skip_serializing_if = "Option::is_none")]
    pub wardex_auth: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointCatalogEntry {
    pub method: String,
    pub path: String,
    pub auth: bool,
    pub description: String,
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
                        name: "AGPL-3.0-only".into(),
                        url: Some("https://www.gnu.org/licenses/agpl-3.0.html".into()),
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

    pub fn path(mut self, path: &str, method: &str, mut op: Operation) -> Self {
        let access = endpoint_route_access(method, path);
        op.security = security_for_route_access(access);
        op.wardex_auth = Some(access.as_str().to_string());
        for parameter in inferred_path_parameters(path) {
            let exists = op.parameters.iter().any(|existing| {
                existing.location == parameter.location && existing.name == parameter.name
            });
            if !exists {
                op.parameters.push(parameter);
            }
        }
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

fn object_schema() -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("object".into()),
        ..Default::default()
    })
}

fn schema_ref(name: &str) -> SchemaRef {
    SchemaRef::Ref {
        reference: format!("#/components/schemas/{name}"),
    }
}

fn string_schema() -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("string".into()),
        ..Default::default()
    })
}

fn binary_schema() -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("string".into()),
        format: Some("binary".into()),
        ..Default::default()
    })
}

fn string_datetime_schema() -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("string".into()),
        format: Some("date-time".into()),
        ..Default::default()
    })
}

fn integer_schema() -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("integer".into()),
        format: Some("int64".into()),
        ..Default::default()
    })
}

fn number_schema() -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("number".into()),
        format: Some("double".into()),
        ..Default::default()
    })
}

fn string_array_schema() -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("array".into()),
        items: Some(Box::new(string_schema())),
        ..Default::default()
    })
}

fn string_enum_schema(values: &[&str]) -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("string".into()),
        enum_values: Some(values.iter().map(|value| value.to_string()).collect()),
        ..Default::default()
    })
}

fn content_response_status(
    status: &str,
    desc: &str,
    content_type: &str,
    schema: SchemaRef,
) -> BTreeMap<String, Response> {
    let mut m = BTreeMap::new();
    m.insert(
        status.into(),
        Response {
            description: desc.into(),
            content: Some({
                let mut c = BTreeMap::new();
                c.insert(content_type.into(), MediaType { schema });
                c
            }),
        },
    );
    m
}

fn json_response(desc: &str) -> BTreeMap<String, Response> {
    json_response_status("200", desc)
}

fn json_response_status(status: &str, desc: &str) -> BTreeMap<String, Response> {
    content_response_status(status, desc, "application/json", object_schema())
}

fn error_response_status(status: &str, desc: &str) -> BTreeMap<String, Response> {
    content_response_status(status, desc, "application/json", schema_ref("Error"))
}

fn error_responses() -> BTreeMap<String, Response> {
    let mut m = BTreeMap::new();
    m.extend(error_response_status(
        "400",
        "Validation or request parsing error",
    ));
    m.extend(error_response_status(
        "401",
        "Unauthorized — missing or invalid Bearer token",
    ));
    m.extend(error_response_status("403", "Forbidden"));
    m.extend(error_response_status("404", "Resource not found"));
    m.extend(error_response_status(
        "409",
        "Conflict with existing resource state",
    ));
    m.extend(error_response_status("413", "Payload too large"));
    m.extend(error_response_status("429", "Rate limit exceeded"));
    m.extend(error_response_status("500", "Internal server error"));
    m.extend(error_response_status("503", "Service unavailable"));
    m
}

fn public_error_responses() -> BTreeMap<String, Response> {
    let mut m = BTreeMap::new();
    m.extend(error_response_status(
        "400",
        "Validation or request parsing error",
    ));
    m.extend(error_response_status("404", "Resource not found"));
    m.extend(error_response_status("429", "Rate limit exceeded"));
    m.extend(error_response_status("503", "Service unavailable"));
    m
}

fn json_request_body(desc: &str, required: bool) -> Option<RequestBody> {
    Some(RequestBody {
        description: Some(desc.into()),
        required,
        content: {
            let mut c = BTreeMap::new();
            c.insert(
                "application/json".into(),
                MediaType {
                    schema: object_schema(),
                },
            );
            c
        },
    })
}

fn json_body(desc: &str) -> Option<RequestBody> {
    json_request_body(desc, true)
}

fn optional_json_body(desc: &str) -> Option<RequestBody> {
    json_request_body(desc, false)
}

fn bearer_auth() -> Vec<BTreeMap<String, Vec<String>>> {
    vec![{
        let mut m = BTreeMap::new();
        m.insert("bearerAuth".into(), vec![]);
        m
    }]
}

fn public_auth() -> Vec<BTreeMap<String, Vec<String>>> {
    vec![BTreeMap::new()]
}

fn endpoint_route_access(method: &str, path: &str) -> crate::server::ApiRouteAccess {
    crate::server::classify_api_route_access(method, path).unwrap_or_else(|| {
        if path.starts_with("/api/") {
            crate::server::ApiRouteAccess::Authenticated
        } else {
            crate::server::ApiRouteAccess::Public
        }
    })
}

fn security_for_route_access(
    access: crate::server::ApiRouteAccess,
) -> Vec<BTreeMap<String, Vec<String>>> {
    if access.requires_bearer_auth() {
        bearer_auth()
    } else {
        public_auth()
    }
}

fn operation(
    id: &str,
    summary: &str,
    tags: &[&str],
    request_body: Option<RequestBody>,
    responses: BTreeMap<String, Response>,
    security: Vec<BTreeMap<String, Vec<String>>>,
) -> Operation {
    Operation {
        summary: summary.into(),
        description: None,
        operation_id: id.into(),
        tags: tags.iter().map(|t| t.to_string()).collect(),
        parameters: vec![],
        request_body,
        responses,
        security,
        wardex_auth: None,
    }
}

fn op(id: &str, summary: &str, tags: &[&str]) -> Operation {
    let mut resp = json_response(summary);
    resp.extend(error_responses());
    operation(id, summary, tags, None, resp, bearer_auth())
}

fn op_with_responses(
    id: &str,
    summary: &str,
    tags: &[&str],
    responses: BTreeMap<String, Response>,
) -> Operation {
    let mut resp = responses;
    resp.extend(error_responses());
    operation(id, summary, tags, None, resp, bearer_auth())
}

fn op_post(id: &str, summary: &str, tags: &[&str], body_desc: &str) -> Operation {
    let mut resp = json_response(summary);
    resp.extend(error_responses());
    operation(id, summary, tags, json_body(body_desc), resp, bearer_auth())
}

fn op_put(id: &str, summary: &str, tags: &[&str], body_desc: &str) -> Operation {
    let mut resp = json_response(summary);
    resp.extend(error_responses());
    operation(id, summary, tags, json_body(body_desc), resp, bearer_auth())
}

fn op_post_status(
    status: &str,
    id: &str,
    summary: &str,
    tags: &[&str],
    body_desc: &str,
) -> Operation {
    let mut resp = json_response_status(status, summary);
    resp.extend(error_responses());
    operation(id, summary, tags, json_body(body_desc), resp, bearer_auth())
}

fn op_post_optional(id: &str, summary: &str, tags: &[&str], body_desc: &str) -> Operation {
    let mut resp = json_response(summary);
    resp.extend(error_responses());
    operation(
        id,
        summary,
        tags,
        optional_json_body(body_desc),
        resp,
        bearer_auth(),
    )
}

fn op_post_without_body(id: &str, summary: &str, tags: &[&str]) -> Operation {
    let mut resp = json_response(summary);
    resp.extend(error_responses());
    operation(id, summary, tags, None, resp, bearer_auth())
}

fn op_public(id: &str, summary: &str, tags: &[&str]) -> Operation {
    let mut resp = json_response(summary);
    resp.extend(public_error_responses());
    operation(
        id,
        summary,
        tags,
        None,
        resp,
        public_auth(), // explicit empty = no auth required
    )
}

fn op_public_with_responses(
    id: &str,
    summary: &str,
    tags: &[&str],
    responses: BTreeMap<String, Response>,
) -> Operation {
    let mut resp = responses;
    resp.extend(public_error_responses());
    operation(id, summary, tags, None, resp, public_auth())
}

fn op_public_post_with_responses(
    id: &str,
    summary: &str,
    tags: &[&str],
    body_desc: &str,
    responses: BTreeMap<String, Response>,
) -> Operation {
    let mut resp = responses;
    resp.extend(public_error_responses());
    operation(id, summary, tags, json_body(body_desc), resp, public_auth())
}

fn with_parameters(mut op: Operation, parameters: Vec<Parameter>) -> Operation {
    op.parameters.extend(parameters);
    op
}

fn string_parameter(name: &str, location: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        location: location.into(),
        description: Some(description.into()),
        required,
        schema: string_schema(),
    }
}

fn integer_parameter(name: &str, location: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        location: location.into(),
        description: Some(description.into()),
        required,
        schema: SchemaRef::Inline(Schema {
            schema_type: Some("integer".into()),
            format: Some("int64".into()),
            ..Default::default()
        }),
    }
}

fn inferred_path_parameters(path: &str) -> Vec<Parameter> {
    path.split('/')
        .filter_map(|segment| {
            segment
                .strip_prefix('{')
                .and_then(|trimmed| trimmed.strip_suffix('}'))
                .map(|name| {
                    string_parameter(name, "path", &format!("Path parameter `{name}`"), true)
                })
        })
        .collect()
}

// ── Wardex spec factory ──────────────────────────────────────────────────────

pub fn wardex_openapi_spec(version: &str) -> OpenApiSpec {
    OpenApiBuilder::new("Wardex XDR/SIEM API", version)
        .tag("auth", "Authentication, session, and token management")
        .tag("status", "Platform health, status, and diagnostics")
        .tag("command", "Command Center lane health and operator action surfaces")
        .tag("detection", "Detection engineering, rules, and analysis")
        .tag("alerts", "Alert queue, triage, and analysis")
        .tag("incidents", "Incident and case management")
        .tag("fleet", "Fleet enrollment, agents, and inventory")
        .tag("response", "Response orchestration and approvals")
        .tag("policy", "Policy publishing and version history")
        .tag(
            "threat-intel",
            "Threat intelligence, enrichment, and investigation pivots",
        )
        .tag("telemetry", "Telemetry collection and event forwarding")
        .tag("config", "Configuration management")
        .tag("reports", "Reports, exports, and executive summaries")
        .tag("updates", "Agent updates, releases, and rollouts")
        .tag("hunts", "Saved hunts, rule lifecycle, and content packs")
        .tag("observability", "Metrics, audit, and SLO monitoring")
        .schema(
            "Error",
            Schema {
                schema_type: Some("object".into()),
                properties: {
                    let mut p = BTreeMap::new();
                    p.insert(
                        "error".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "code".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            description: Some("Machine-readable error code".into()),
                            ..Default::default()
                        }),
                    );
                    p
                },
                required: vec!["error".into(), "code".into()],
                ..Default::default()
            },
        )
        .schema(
            "Alert",
            Schema {
                schema_type: Some("object".into()),
                properties: {
                    let mut p = BTreeMap::new();
                    p.insert(
                        "id".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("integer".into()),
                            format: Some("int64".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "level".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            enum_values: Some(vec![
                                "Nominal".into(),
                                "Elevated".into(),
                                "Severe".into(),
                                "Critical".into(),
                            ]),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "timestamp".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            format: Some("date-time".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "score".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("number".into()),
                            format: Some("float".into()),
                            ..Default::default()
                        }),
                    );
                    p
                },
                required: vec![
                    "id".into(),
                    "level".into(),
                    "timestamp".into(),
                    "score".into(),
                ],
                ..Default::default()
            },
        )
        .schema(
            "Incident",
            Schema {
                schema_type: Some("object".into()),
                properties: {
                    let mut p = BTreeMap::new();
                    p.insert(
                        "id".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("integer".into()),
                            format: Some("int64".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "title".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "severity".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "status".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            enum_values: Some(vec![
                                "Open".into(),
                                "Investigating".into(),
                                "Contained".into(),
                                "Resolved".into(),
                                "FalsePositive".into(),
                            ]),
                            ..Default::default()
                        }),
                    );
                    p
                },
                required: vec!["id".into(), "title".into(), "severity".into()],
                ..Default::default()
            },
        )
        .schema(
            "Agent",
            Schema {
                schema_type: Some("object".into()),
                properties: {
                    let mut p = BTreeMap::new();
                    p.insert(
                        "id".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "hostname".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "platform".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "version".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            ..Default::default()
                        }),
                    );
                    p.insert(
                        "status".into(),
                        SchemaRef::Inline(Schema {
                            schema_type: Some("string".into()),
                            enum_values: Some(vec![
                                "online".into(),
                                "offline".into(),
                                "stale".into(),
                            ]),
                            ..Default::default()
                        }),
                    );
                    p
                },
                ..Default::default()
            },
        )
        .schema(
            "CommandCenterMetrics",
            Schema {
                schema_type: Some("object".into()),
                properties: {
                    let mut p = BTreeMap::new();
                    p.insert("open_incidents".into(), integer_schema());
                    p.insert("active_cases".into(), integer_schema());
                    p.insert("pending_remediation_reviews".into(), integer_schema());
                    p.insert("rollback_ready_reviews".into(), integer_schema());
                    p.insert("connector_issues".into(), integer_schema());
                    p.insert("noisy_rules".into(), integer_schema());
                    p.insert("stale_rules".into(), integer_schema());
                    p.insert("release_candidates".into(), integer_schema());
                    p.insert("compliance_packs".into(), integer_schema());
                    p.insert("offline_agents".into(), integer_schema());
                    p
                },
                required: vec![
                    "open_incidents".into(),
                    "active_cases".into(),
                    "pending_remediation_reviews".into(),
                    "rollback_ready_reviews".into(),
                    "connector_issues".into(),
                    "noisy_rules".into(),
                    "stale_rules".into(),
                    "release_candidates".into(),
                    "compliance_packs".into(),
                    "offline_agents".into(),
                ],
                ..Default::default()
            },
        )
        .schema(
            "CommandCenterLanePayload",
            Schema {
                schema_type: Some("object".into()),
                properties: {
                    let mut p = BTreeMap::new();
                    p.insert("status".into(), string_schema());
                    p.insert("annotation".into(), string_schema());
                    p.insert("next_step".into(), string_schema());
                    p.insert("href".into(), string_schema());
                    p.insert("count".into(), integer_schema());
                    p.insert("pending".into(), integer_schema());
                    p.insert("rollback_ready".into(), integer_schema());
                    p.insert("issues".into(), integer_schema());
                    p.insert("readiness".into(), object_schema());
                    p.insert("planned".into(), string_array_schema());
                    p.insert("noisy".into(), integer_schema());
                    p.insert("stale".into(), integer_schema());
                    p.insert("active_suppressions".into(), integer_schema());
                    p.insert("candidates".into(), integer_schema());
                    p.insert("current_version".into(), string_schema());
                    p.insert("score".into(), number_schema());
                    p.insert("templates".into(), integer_schema());
                    p
                },
                required: vec!["status".into(), "annotation".into(), "next_step".into()],
                ..Default::default()
            },
        )
        .schema(
            "CommandCenterLanes",
            Schema {
                schema_type: Some("object".into()),
                properties: {
                    let mut p = BTreeMap::new();
                    p.insert("incidents".into(), schema_ref("CommandCenterLanePayload"));
                    p.insert("remediation".into(), schema_ref("CommandCenterLanePayload"));
                    p.insert("connectors".into(), schema_ref("CommandCenterLanePayload"));
                    p.insert("rule_tuning".into(), schema_ref("CommandCenterLanePayload"));
                    p.insert("release".into(), schema_ref("CommandCenterLanePayload"));
                    p.insert("evidence".into(), schema_ref("CommandCenterLanePayload"));
                    p
                },
                required: vec![
                    "incidents".into(),
                    "remediation".into(),
                    "connectors".into(),
                    "rule_tuning".into(),
                    "release".into(),
                    "evidence".into(),
                ],
                ..Default::default()
            },
        )
        .schema(
            "CommandCenterSummaryResponse",
            Schema {
                schema_type: Some("object".into()),
                properties: {
                    let mut p = BTreeMap::new();
                    p.insert("generated_at".into(), string_datetime_schema());
                    p.insert("metrics".into(), schema_ref("CommandCenterMetrics"));
                    p.insert("lanes".into(), schema_ref("CommandCenterLanes"));
                    p
                },
                required: vec!["generated_at".into(), "metrics".into(), "lanes".into()],
                ..Default::default()
            },
        )
        .schema(
            "CommandCenterLaneResponse",
            Schema {
                schema_type: Some("object".into()),
                properties: {
                    let mut p = BTreeMap::new();
                    p.insert(
                        "lane".into(),
                        string_enum_schema(&[
                            "incidents",
                            "remediation",
                            "connectors",
                            "rule_tuning",
                            "release",
                            "evidence",
                        ]),
                    );
                    p.insert("generated_at".into(), string_datetime_schema());
                    p.insert(
                        "metric_key".into(),
                        string_enum_schema(&[
                            "open_incidents",
                            "pending_remediation_reviews",
                            "connector_issues",
                            "noisy_rules",
                            "release_candidates",
                            "compliance_packs",
                        ]),
                    );
                    p.insert("metric_value".into(), integer_schema());
                    p.insert("payload".into(), schema_ref("CommandCenterLanePayload"));
                    p
                },
                required: vec![
                    "lane".into(),
                    "generated_at".into(),
                    "metric_key".into(),
                    "metric_value".into(),
                    "payload".into(),
                ],
                ..Default::default()
            },
        )
        // Auth
        .path(
            "/api/auth/check",
            "get",
            op("authCheck", "Check authentication status", &["auth"]),
        )
        .path(
            "/api/auth/sso/login",
            "get",
            with_parameters(
                op_public_with_responses(
                    "startSsoLogin",
                    "Start SSO login and redirect to the configured identity provider",
                    &["auth"],
                    {
                        let mut resp = BTreeMap::new();
                        resp.insert(
                            "302".into(),
                            Response {
                                description: "Redirect to the configured identity provider".into(),
                                content: None,
                            },
                        );
                        resp
                    },
                ),
                vec![
                    string_parameter(
                        "provider_id",
                        "query",
                        "Optional identity provider ID when more than one SSO provider is configured",
                        false,
                    ),
                    string_parameter(
                        "provider",
                        "query",
                        "Legacy alias for provider_id",
                        false,
                    ),
                    string_parameter(
                        "redirect",
                        "query",
                        "Optional console path to resume after authentication",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/auth/sso/callback",
            "get",
            with_parameters(
                op_public_with_responses(
                    "completeSsoCallbackRedirect",
                    "Complete browser-based SSO callback and redirect back to the console",
                    &["auth"],
                    {
                        let mut resp = BTreeMap::new();
                        resp.insert(
                            "302".into(),
                            Response {
                                description: "Redirect to the post-login or error destination".into(),
                                content: None,
                            },
                        );
                        resp
                    },
                ),
                vec![
                    string_parameter(
                        "code",
                        "query",
                        "Authorization code from the identity provider",
                        true,
                    ),
                    string_parameter(
                        "state",
                        "query",
                        "CSRF state value returned by the identity provider",
                        true,
                    ),
                    string_parameter(
                        "provider_id",
                        "query",
                        "Optional identity provider ID hint for multi-provider deployments",
                        false,
                    ),
                    string_parameter(
                        "provider",
                        "query",
                        "Legacy alias for provider_id",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/auth/sso/callback",
            "post",
            op_public_post_with_responses(
                "completeSsoCallback",
                "Complete programmatic SSO callback and create a Wardex session",
                &["auth"],
                "SSO authorization code, state token, and optional provider hint",
                json_response("Programmatic SSO callback completed"),
            ),
        )
        .path(
            "/api/auth/rotate",
            "post",
            op_post_without_body("authRotate", "Rotate API token", &["auth"]),
        )
        .path(
            "/api/session/info",
            "get",
            op(
                "sessionInfo",
                "Get session metadata, uptime, and TTL",
                &["auth"],
            ),
        )
        // Public diagnostics
        .path(
            "/api/health",
            "get",
            op_public("getHealth", "Health check", &["status"]),
        )
        .path(
            "/api/openapi.json",
            "get",
            op_public(
                "getOpenApiSpec",
                "Stable OpenAPI specification for the public Wardex API surface",
                &["status"],
            ),
        )
        .path(
            "/api/metrics",
            "get",
            op_public_with_responses(
                "getMetrics",
                "Prometheus-format metrics",
                &["observability"],
                content_response_status(
                    "200",
                    "Prometheus-format metrics",
                    "text/plain",
                    string_schema(),
                ),
            ),
        )
        .path(
            "/api/ws/stats",
            "get",
            op_public(
                "getWsStats",
                "Realtime stream transport capability and subscriber statistics",
                &["observability"],
            ),
        )
        .path(
            "/api/policy/current",
            "get",
            op_public("getCurrentPolicy", "Get current active policy", &["policy"]),
        )
        // Status & reports
        .path(
            "/api/status",
            "get",
            op("getStatus", "Platform status manifest", &["status"]),
        )
        .path(
            "/api/report",
            "get",
            op(
                "getReport",
                "Latest analysis report with samples",
                &["reports"],
            ),
        )
        .path(
            "/api/host/info",
            "get",
            op("getHostInfo", "Host system information", &["status"]),
        )
        .path(
            "/api/slo/status",
            "get",
            op(
                "getSloStatus",
                "Service level objective metrics",
                &["observability"],
            ),
        )
        .path(
            "/api/reports",
            "get",
            with_parameters(
                op("listReports", "List stored reports", &["reports"]),
                vec![
                    string_parameter(
                        "case_id",
                        "query",
                        "Filter reports by case handoff id",
                        false,
                    ),
                    string_parameter(
                        "incident_id",
                        "query",
                        "Filter reports by incident handoff id",
                        false,
                    ),
                    string_parameter(
                        "investigation_id",
                        "query",
                        "Filter reports by investigation handoff id",
                        false,
                    ),
                    string_parameter(
                        "source",
                        "query",
                        "Filter reports by execution-context source",
                        false,
                    ),
                    string_parameter(
                        "scope",
                        "query",
                        "Return all, scoped, or unscoped reports (`all`, `scoped`, `unscoped`)",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/reports/{id}",
            "get",
            op("getReportById", "Retrieve a specific report", &["reports"]),
        )
        .path(
            "/api/reports/{id}/context",
            "post",
            op_post(
                "setReportExecutionContext",
                "Attach or update execution context for a stored report",
                &["reports"],
                "Execution context fields for the stored report",
            ),
        )
        .path(
            "/api/reports/{id}/html",
            "get",
            op_with_responses(
                "getReportHtml",
                "HTML report download",
                &["reports"],
                content_response_status(
                    "200",
                    "HTML report download",
                    "text/html",
                    string_schema(),
                ),
            ),
        )
        .path(
            "/api/reports/executive-summary",
            "get",
            op(
                "getExecutiveSummary",
                "Executive summary across reports and incidents",
                &["reports"],
            ),
        )
        .path(
            "/api/report-templates",
            "get",
            with_parameters(
                op(
                    "listReportTemplates",
                    "List reusable report templates and presets",
                    &["reports"],
                ),
                vec![
                    string_parameter(
                        "case_id",
                        "query",
                        "Filter templates by case handoff id",
                        false,
                    ),
                    string_parameter(
                        "incident_id",
                        "query",
                        "Filter templates by incident handoff id",
                        false,
                    ),
                    string_parameter(
                        "investigation_id",
                        "query",
                        "Filter templates by investigation handoff id",
                        false,
                    ),
                    string_parameter(
                        "source",
                        "query",
                        "Filter templates by execution-context source",
                        false,
                    ),
                    string_parameter(
                        "scope",
                        "query",
                        "Return all, scoped, or unscoped templates (`all`, `scoped`, `unscoped`)",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/report-templates",
            "post",
            op_post_status(
                "201",
                "saveReportTemplate",
                "Create or update a reusable report template",
                &["reports"],
                "Report template upsert payload",
            ),
        )
        .path(
            "/api/report-runs",
            "get",
            with_parameters(
                op("listReportRuns", "List persisted report runs", &["reports"]),
                vec![
                    string_parameter("case_id", "query", "Filter runs by case handoff id", false),
                    string_parameter(
                        "incident_id",
                        "query",
                        "Filter runs by incident handoff id",
                        false,
                    ),
                    string_parameter(
                        "investigation_id",
                        "query",
                        "Filter runs by investigation handoff id",
                        false,
                    ),
                    string_parameter(
                        "source",
                        "query",
                        "Filter runs by execution-context source",
                        false,
                    ),
                    string_parameter(
                        "scope",
                        "query",
                        "Return all, scoped, or unscoped runs (`all`, `scoped`, `unscoped`)",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/report-runs",
            "post",
            op_post_status(
                "201",
                "createReportRun",
                "Create a report run and persist its preview artifact",
                &["reports"],
                "Report run creation payload",
            ),
        )
        .path(
            "/api/report-schedules",
            "get",
            with_parameters(
                op(
                    "listReportSchedules",
                    "List saved report schedules",
                    &["reports"],
                ),
                vec![
                    string_parameter(
                        "case_id",
                        "query",
                        "Filter schedules by case handoff id",
                        false,
                    ),
                    string_parameter(
                        "incident_id",
                        "query",
                        "Filter schedules by incident handoff id",
                        false,
                    ),
                    string_parameter(
                        "investigation_id",
                        "query",
                        "Filter schedules by investigation handoff id",
                        false,
                    ),
                    string_parameter(
                        "source",
                        "query",
                        "Filter schedules by execution-context source",
                        false,
                    ),
                    string_parameter(
                        "scope",
                        "query",
                        "Return all, scoped, or unscoped schedules (`all`, `scoped`, `unscoped`)",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/report-schedules",
            "post",
            op_post_status(
                "201",
                "saveReportSchedule",
                "Create or update a report delivery schedule",
                &["reports"],
                "Report schedule upsert payload",
            ),
        )
        .path(
            "/api/workbench/overview",
            "get",
            op(
                "getWorkbenchOverview",
                "SOC Workbench overview",
                &["incidents"],
            ),
        )
        .path(
            "/api/manager/overview",
            "get",
            op(
                "getManagerOverview",
                "Manager operational overview",
                &["reports"],
            ),
        )
        .path(
            "/api/command/summary",
            "get",
            op_with_responses(
                "getCommandSummary",
                "Command Center lane-health summary",
                &["command"],
                content_response_status(
                    "200",
                    "Lane health across incidents, approvals, connectors, rule tuning, releases, and evidence packs",
                    "application/json",
                    schema_ref("CommandCenterSummaryResponse"),
                ),
            ),
        )
        .path(
            "/api/command/lanes/{lane}",
            "get",
            with_parameters(
                op_with_responses(
                    "getCommandLane",
                    "Per-lane slice of the Command Center summary",
                    &["command"],
                    content_response_status(
                        "200",
                        "Single-lane payload with metric key, value, and shared timestamp",
                        "application/json",
                        schema_ref("CommandCenterLaneResponse"),
                    ),
                ),
                vec![Parameter {
                    name: "lane".into(),
                    location: "path".into(),
                    description: Some(
                        "Command Center lane name (incidents, remediation, connectors, rule_tuning, release, evidence)"
                            .into(),
                    ),
                    required: true,
                    schema: string_enum_schema(&[
                        "incidents",
                        "remediation",
                        "connectors",
                        "rule_tuning",
                        "release",
                        "evidence",
                    ]),
                }],
            ),
        )
        // Config
        .path(
            "/api/config/current",
            "get",
            op("getConfig", "Current configuration", &["config"]),
        )
        .path(
            "/api/config/reload",
            "post",
            op_post(
                "reloadConfig",
                "Hot-reload configuration",
                &["config"],
                "Config patch",
            ),
        )
        .path(
            "/api/config/save",
            "post",
            op_post(
                "saveConfig",
                "Persist configuration changes to disk",
                &["config"],
                "Config patch",
            ),
        )
        .path(
            "/api/monitoring/options",
            "get",
            op(
                "getMonitoringOptions",
                "OS-aware monitoring points and recommendations",
                &["config"],
            ),
        )
        .path(
            "/api/monitoring/paths",
            "get",
            op(
                "getMonitoringPaths",
                "Active file-integrity and persistence monitoring paths",
                &["config"],
            ),
        )
        .path(
            "/api/retention/status",
            "get",
            op(
                "getRetentionStatus",
                "Data retention policy status",
                &["config"],
            ),
        )
        .path(
            "/api/retention/apply",
            "post",
            op_post(
                "applyRetention",
                "Apply retention policy now",
                &["config"],
                "Retention application payload",
            ),
        )
        // Telemetry & alerts
        .path(
            "/api/telemetry/current",
            "get",
            op(
                "getTelemetryCurrent",
                "Current telemetry snapshot",
                &["telemetry"],
            ),
        )
        .path(
            "/api/telemetry/history",
            "get",
            op(
                "getTelemetryHistory",
                "Telemetry time-series history",
                &["telemetry"],
            ),
        )
        .path(
            "/api/events",
            "get",
            op("getEvents", "List stored events", &["telemetry"]),
        )
        .path(
            "/api/events",
            "post",
            op_post(
                "pushEvents",
                "Push an event batch from an agent",
                &["telemetry"],
                "Event batch payload",
            ),
        )
        .path(
            "/api/events/export",
            "get",
            op_with_responses(
                "exportEvents",
                "Export filtered events as CSV",
                &["telemetry"],
                content_response_status(
                    "200",
                    "Export filtered events as CSV",
                    "text/csv",
                    string_schema(),
                ),
            ),
        )
        .path(
            "/api/events/summary",
            "get",
            op(
                "getEventsSummary",
                "Fleet event analytics summary",
                &["telemetry"],
            ),
        )
        .path(
            "/api/events/search",
            "post",
            op_post(
                "searchEvents",
                "Search events with structured analyst filters",
                &["telemetry"],
                "Event search query",
            ),
        )
        .path(
            "/api/events/{id}/triage",
            "post",
            op_post(
                "triageEvent",
                "Update event triage state, assignee, tags, and notes",
                &["telemetry"],
                "Triage update payload",
            ),
        )
        .path(
            "/api/collectors/github",
            "get",
            op("getGithubCollector", "GitHub audit collector setup", &["telemetry"]),
        )
        .path(
            "/api/collectors/github/config",
            "post",
            op_post(
                "saveGithubCollectorConfig",
                "Save GitHub audit collector setup",
                &["telemetry"],
                "GitHub audit connector setup fields",
            ),
        )
        .path(
            "/api/collectors/github/validate",
            "post",
            op_post_without_body(
                "validateGithubCollector",
                "Validate GitHub audit collector setup",
                &["telemetry"],
            ),
        )
        .path(
            "/api/collectors/crowdstrike",
            "get",
            op(
                "getCrowdStrikeCollector",
                "CrowdStrike Falcon collector setup",
                &["telemetry"],
            ),
        )
        .path(
            "/api/collectors/crowdstrike/config",
            "post",
            op_post(
                "saveCrowdStrikeCollectorConfig",
                "Save CrowdStrike Falcon collector setup",
                &["telemetry"],
                "CrowdStrike Falcon connector setup fields",
            ),
        )
        .path(
            "/api/collectors/crowdstrike/validate",
            "post",
            op_post_without_body(
                "validateCrowdStrikeCollector",
                "Validate CrowdStrike Falcon collector setup",
                &["telemetry"],
            ),
        )
        .path(
            "/api/collectors/syslog",
            "get",
            op("getSyslogCollector", "Generic syslog collector setup", &["telemetry"]),
        )
        .path(
            "/api/collectors/syslog/config",
            "post",
            op_post(
                "saveSyslogCollectorConfig",
                "Save generic syslog collector setup",
                &["telemetry"],
                "Generic syslog connector setup fields",
            ),
        )
        .path(
            "/api/collectors/syslog/validate",
            "post",
            op_post_without_body(
                "validateSyslogCollector",
                "Validate generic syslog collector setup",
                &["telemetry"],
            ),
        )
        .path(
            "/api/alerts",
            "get",
            with_parameters(
                op("getAlerts", "List recent alerts", &["alerts"]),
                vec![
                    integer_parameter("limit", "query", "Maximum alerts to return", false),
                    integer_parameter(
                        "offset",
                        "query",
                        "Number of alerts to skip before returning results",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/alerts/{id}",
            "get",
            op("getAlert", "Get alert detail", &["alerts"]),
        )
        .path(
            "/api/alerts",
            "delete",
            op("clearAlerts", "Clear all alerts", &["alerts"]),
        )
        .path(
            "/api/alerts/count",
            "get",
            op("getAlertCount", "Alert count by severity", &["alerts"]),
        )
        .path(
            "/api/alerts/analysis",
            "get",
            op(
                "getAlertAnalysis",
                "Latest alert pattern analysis",
                &["alerts"],
            ),
        )
        .path(
            "/api/alerts/analysis",
            "post",
            op_post_optional(
                "runAlertAnalysis",
                "Run on-demand alert analysis",
                &["alerts"],
                "Alert analysis parameters",
            ),
        )
        .path(
            "/api/alerts/grouped",
            "get",
            op(
                "getGroupedAlerts",
                "Alerts grouped by reason fingerprint",
                &["alerts"],
            ),
        )
        .path(
            "/api/queue/alerts",
            "get",
            op(
                "getAlertQueue",
                "SOC alert queue with SLA status",
                &["alerts"],
            ),
        )
        .path(
            "/api/queue/acknowledge",
            "post",
            op_post(
                "acknowledgeQueueAlert",
                "Acknowledge a queued alert",
                &["alerts"],
                "Queue acknowledgement payload",
            ),
        )
        .path(
            "/api/queue/stats",
            "get",
            op(
                "getAlertQueueStats",
                "Alert queue backlog and SLA summary",
                &["alerts"],
            ),
        )
        .path(
            "/api/queue/assign",
            "post",
            op_post(
                "assignQueueAlert",
                "Assign a queued alert to an analyst",
                &["alerts"],
                "Queue assignment payload",
            ),
        )
        .path(
            "/api/detection/summary",
            "get",
            op(
                "getDetectionSummary",
                "Detector state across velocity, entropy, and compound models",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/replay-corpus",
            "get",
            op(
                "getDetectionReplayCorpus",
                "Evaluate the built-in replay corpus against precision, recall, and false-positive gates",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/replay-corpus",
            "post",
            op_post(
                "evaluateDetectionReplayCorpus",
                "Evaluate a custom labeled or retained-event replay-corpus validation pack",
                &["detection"],
                "Replay corpus validation pack",
            ),
        )
        .path(
            "/api/detection/explain",
            "get",
            op(
                "getDetectionExplainability",
                "Explain a detection with evidence, entity scores, feedback, and next steps",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/profile",
            "get",
            op(
                "getDetectionProfile",
                "Current detection tuning profile and sensitivity thresholds",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/profile",
            "put",
            op_put(
                "setDetectionProfile",
                "Set the active detection tuning profile",
                &["detection"],
                "Detection tuning profile payload",
            ),
        )
        .path(
            "/api/detection/score/normalize",
            "get",
            op(
                "normalizeDetectionScore",
                "Normalized 0-100 threat score with severity and confidence labels",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/feedback",
            "get",
            op(
                "listDetectionFeedback",
                "List analyst feedback for detection calibration",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/feedback",
            "post",
            op_post(
                "recordDetectionFeedback",
                "Record analyst detection feedback",
                &["detection"],
                "Detection feedback payload",
            ),
        )
        .path(
            "/api/detection/weights",
            "get",
            op(
                "getDetectionWeights",
                "Current per-dimension detection weights",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/weights",
            "post",
            op_post(
                "setDetectionWeights",
                "Set per-dimension detection weights",
                &["detection"],
                "Detection weight payload",
            ),
        )
        .path(
            "/api/correlation/campaigns",
            "get",
            op(
                "getCorrelationCampaigns",
                "Cluster stored events into campaign summaries, sequence signals, and graph edges",
                &["detection"],
            ),
        )
        // Incidents & cases
        .path(
            "/api/cases",
            "get",
            op("listCases", "List investigation cases", &["incidents"]),
        )
        .path(
            "/api/cases",
            "post",
            op_post_status(
                "201",
                "createCase",
                "Create investigation case",
                &["incidents"],
                "Case definition",
            ),
        )
        .path(
            "/api/cases/{id}",
            "get",
            op("getCase", "Get case detail", &["incidents"]),
        )
        .path(
            "/api/cases/{id}/handoff-packet",
            "get",
            op(
                "getCaseHandoffPacket",
                "Get a structured handoff packet for a case",
                &["incidents"],
            ),
        )
        .path(
            "/api/incidents",
            "get",
            with_parameters(
                op("listIncidents", "List incidents", &["incidents"]),
                vec![
                    string_parameter("status", "query", "Filter incidents by status", false),
                    string_parameter("severity", "query", "Filter incidents by severity", false),
                    integer_parameter("limit", "query", "Maximum incidents to return", false),
                    integer_parameter(
                        "offset",
                        "query",
                        "Number of incidents to skip before returning results",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/incidents",
            "post",
            op_post(
                "createIncident",
                "Create a new incident",
                &["incidents"],
                "Incident title, severity, and optional links",
            ),
        )
        .path(
            "/api/incidents/{id}",
            "get",
            op("getIncident", "Get incident detail", &["incidents"]),
        )
        .path(
            "/api/incidents/{id}/update",
            "post",
            op_post(
                "updateIncident",
                "Update incident status, assignee, or notes",
                &["incidents"],
                "Incident update payload",
            ),
        )
        .path(
            "/api/incidents/{id}/report",
            "get",
            op(
                "getIncidentReport",
                "Generate incident report",
                &["incidents"],
            ),
        )
        .path(
            "/api/incidents/{id}/storyline",
            "get",
            op(
                "getIncidentStoryline",
                "Narrative storyline and evidence package",
                &["incidents"],
            ),
        )
        // Fleet & agents
        .path(
            "/api/agents",
            "get",
            op("listAgents", "List enrolled agents", &["fleet"]),
        )
        .path(
            "/api/agents/{id}/details",
            "get",
            op(
                "getAgentDetails",
                "Retrieve detailed agent snapshot",
                &["fleet"],
            ),
        )
        .path(
            "/api/agents/{id}/activity",
            "get",
            op(
                "getAgentActivity",
                "Deep activity snapshot for a single agent",
                &["fleet"],
            ),
        )
        .path(
            "/api/agents/{id}/logs",
            "get",
            op("getAgentLogs", "Retrieve agent logs", &["fleet"]),
        )
        .path(
            "/api/agents/{id}/inventory",
            "get",
            op("getAgentInventory", "Retrieve agent inventory", &["fleet"]),
        )
        .path(
            "/api/fleet/installs",
            "get",
            op(
                "listFleetRemoteInstalls",
                "Recent remote install attempts and heartbeat outcomes",
                &["fleet"],
            ),
        )
        .path(
            "/api/fleet/install/ssh",
            "post",
            op_post_status(
                "202",
                "runFleetSshInstall",
                "Run a remote Linux or macOS agent install over SSH",
                &["fleet"],
                "SSH remote install request",
            ),
        )
        .path(
            "/api/fleet/install/winrm",
            "post",
            op_post_status(
                "202",
                "runFleetWinrmInstall",
                "Run a remote Windows agent install over WinRM",
                &["fleet"],
                "WinRM remote install request",
            ),
        )
        .path(
            "/api/fleet/inventory",
            "get",
            op(
                "getFleetInventory",
                "Fleet-wide inventory summary",
                &["fleet"],
            ),
        )
        .path(
            "/api/fleet/dashboard",
            "get",
            op(
                "getFleetDashboard",
                "Operational fleet dashboard across agents, events, and deployments",
                &["fleet"],
            ),
        )
        .path(
            "/api/rollout/config",
            "get",
            op(
                "getRolloutConfig",
                "Rollout channel and staged deployment configuration",
                &["updates"],
            ),
        )
        .path(
            "/api/agents/update",
            "get",
            with_parameters(
                op(
                    "checkAgentUpdate",
                    "Check whether an agent update is available",
                    &["updates"],
                ),
                vec![
                    string_parameter("agent_id", "query", "Agent identifier", false),
                    string_parameter("current_version", "query", "Current agent version", false),
                    string_parameter("platform", "query", "Agent platform", false),
                ],
            ),
        )
        .path(
            "/api/updates/releases",
            "get",
            op("listReleases", "List published releases", &["updates"]),
        )
        .path(
            "/api/updates/download/{file_name}",
            "get",
            op_with_responses(
                "downloadRelease",
                "Download an agent release artifact",
                &["updates"],
                content_response_status(
                    "200",
                    "Download an agent release artifact",
                    "application/octet-stream",
                    binary_schema(),
                ),
            ),
        )
        .path(
            "/api/updates/publish",
            "post",
            op_post(
                "publishRelease",
                "Publish a new agent release",
                &["updates"],
                "Release payload",
            ),
        )
        .path(
            "/api/updates/deploy",
            "post",
            op_post(
                "deployUpdate",
                "Assign a published release to an agent",
                &["updates"],
                "Deployment target and version",
            ),
        )
        .path(
            "/api/updates/rollback",
            "post",
            op_post(
                "rollbackUpdate",
                "Rollback a deployment",
                &["updates"],
                "Rollback parameters",
            ),
        )
        .path(
            "/api/updates/cancel",
            "post",
            op_post(
                "cancelUpdate",
                "Cancel an in-progress deployment",
                &["updates"],
                "Deployment ID",
            ),
        )
        // Response
        .path(
            "/api/response/request",
            "post",
            op_post(
                "requestResponse",
                "Submit an approval-gated response action",
                &["response"],
                "Response action request",
            ),
        )
        .path(
            "/api/response/requests",
            "get",
            op(
                "listResponseRequests",
                "List response requests with approval state",
                &["response"],
            ),
        )
        .path(
            "/api/response/approve",
            "post",
            op_post(
                "approveResponse",
                "Approve or deny a pending response action",
                &["response"],
                "Approval payload",
            ),
        )
        .path(
            "/api/response/execute",
            "post",
            op_post_optional(
                "executeResponse",
                "Execute approved response actions",
                &["response"],
                "Optional execution payload",
            ),
        )
        .path(
            "/api/response/approvals",
            "get",
            op(
                "listResponseApprovals",
                "Approval history for response actions",
                &["response"],
            ),
        )
        .path(
            "/api/playbooks",
            "get",
            op(
                "listPlaybooks",
                "List registered automated response playbooks",
                &["response"],
            ),
        )
        .path(
            "/api/playbooks",
            "post",
            op_post(
                "savePlaybook",
                "Register or update an automated response playbook",
                &["response"],
                "Playbook definition",
            ),
        )
        .path(
            "/api/playbooks/execute",
            "post",
            op_post(
                "executePlaybook",
                "Start a playbook execution for a specific alert",
                &["response"],
                "Playbook execution request",
            ),
        )
        .path(
            "/api/playbooks/executions",
            "get",
            op(
                "listPlaybookExecutions",
                "List recent automated response playbook executions",
                &["response"],
            ),
        )
        // Policy
        .path(
            "/api/policy/history",
            "get",
            op("getPolicyHistory", "Policy version history", &["policy"]),
        )
        .path(
            "/api/policy/publish",
            "post",
            op_post(
                "publishPolicy",
                "Publish a policy version",
                &["policy"],
                "Policy payload",
            ),
        )
        // Hunts & content
        .path(
            "/api/hunts",
            "get",
            op("listHunts", "List saved hunts", &["hunts"]),
        )
        .path(
            "/api/hunts",
            "post",
            op_post_status(
                "201",
                "saveHunt",
                "Create or update a saved hunt",
                &["hunts"],
                "Hunt definition",
            ),
        )
        .path(
            "/api/hunts/{id}/run",
            "post",
            op_post_optional(
                "runHunt",
                "Execute a saved hunt immediately",
                &["hunts"],
                "Optional hunt execution payload",
            ),
        )
        .path(
            "/api/hunts/{id}/history",
            "get",
            op(
                "getHuntHistory",
                "Retrieve saved hunt run history",
                &["hunts"],
            ),
        )
        .path(
            "/api/content/rules",
            "get",
            op(
                "listContentRules",
                "List detection content rules",
                &["hunts"],
            ),
        )
        .path(
            "/api/content/rules",
            "post",
            op_post_status(
                "201",
                "saveContentRule",
                "Create or update managed content rules",
                &["hunts"],
                "Rule definition",
            ),
        )
        .path(
            "/api/content/rules/{id}/test",
            "post",
            op_post(
                "testContentRule",
                "Replay a content rule against retained events",
                &["hunts"],
                "Rule test payload",
            ),
        )
        .path(
            "/api/content/rules/{id}/promote",
            "post",
            op_post(
                "promoteContentRule",
                "Promote a content rule through its lifecycle",
                &["hunts"],
                "Promotion payload",
            ),
        )
        .path(
            "/api/content/rules/{id}/rollback",
            "post",
            op_post(
                "rollbackContentRule",
                "Rollback a content rule to a previous lifecycle state",
                &["hunts"],
                "Rollback payload",
            ),
        )
        .path(
            "/api/content/packs",
            "get",
            op("listContentPacks", "List content packs", &["hunts"]),
        )
        .path(
            "/api/content/packs",
            "post",
            op_post_status(
                "201",
                "saveContentPack",
                "Create or update a content pack",
                &["hunts"],
                "Pack definition",
            ),
        )
        .path(
            "/api/coverage/mitre",
            "get",
            op(
                "getMitreCoverage",
                "MITRE ATT&CK coverage across rules and packs",
                &["hunts"],
            ),
        )
        .path(
            "/api/suppressions",
            "get",
            op("listSuppressions", "List alert suppressions", &["hunts"]),
        )
        .path(
            "/api/suppressions",
            "post",
            op_post_status(
                "201",
                "saveSuppression",
                "Create or update an alert suppression",
                &["hunts"],
                "Suppression definition",
            ),
        )
        // Enterprise investigation & admin
        .path(
            "/api/entities/{kind}/{id}",
            "get",
            op(
                "getEntityProfile",
                "Entity profile pivot",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/entities/{kind}/{id}/timeline",
            "get",
            op(
                "getEntityTimeline",
                "Entity timeline pivot",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/enrichments/connectors",
            "get",
            op(
                "listEnrichmentConnectors",
                "List enrichment connectors",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/enrichments/connectors",
            "post",
            op_post(
                "saveEnrichmentConnector",
                "Create or update an enrichment connector",
                &["threat-intel"],
                "Connector definition",
            ),
        )
        .path(
            "/api/tickets/sync",
            "post",
            op_post(
                "syncTickets",
                "Sync a case or incident to an external ticket system",
                &["incidents"],
                "Ticket sync request",
            ),
        )
        .path(
            "/api/investigations/workflows",
            "get",
            op(
                "listInvestigationWorkflows",
                "List available investigation workflow templates",
                &["incidents"],
            ),
        )
        .path(
            "/api/investigations/workflows/{id}",
            "get",
            op(
                "getInvestigationWorkflow",
                "Get a single investigation workflow template",
                &["incidents"],
            ),
        )
        .path(
            "/api/investigations/start",
            "post",
            op_post(
                "startInvestigationWorkflow",
                "Start a guided investigation workflow",
                &["incidents"],
                "Investigation start request",
            ),
        )
        .path(
            "/api/investigations/active",
            "get",
            op(
                "listActiveInvestigations",
                "List active investigations with workflow metadata and progress",
                &["incidents"],
            ),
        )
        .path(
            "/api/investigations/progress",
            "post",
            op_post(
                "updateInvestigationProgress",
                "Update step completion, notes, findings, or status for an active investigation",
                &["incidents"],
                "Investigation progress update",
            ),
        )
        .path(
            "/api/investigations/handoff",
            "post",
            op_post(
                "handoffInvestigation",
                "Hand an active investigation to another analyst and sync the linked case",
                &["incidents"],
                "Investigation handoff request",
            ),
        )
        .path(
            "/api/investigations/suggest",
            "post",
            op_post(
                "suggestInvestigationWorkflow",
                "Suggest workflows that match the current alert or incident context",
                &["incidents"],
                "Investigation suggestion request",
            ),
        )
        .path(
            "/api/threat-intel/status",
            "get",
            op(
                "getThreatIntelStatus",
                "Threat intelligence indicator inventory status",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/threat-intel/library",
            "get",
            op(
                "getThreatIntelLibrary",
                "List tracked indicators, feeds, and recent matches",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/threat-intel/stats",
            "get",
            op(
                "getThreatIntelStats",
                "Threat intelligence enrichment and feed statistics",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/threat-intel/ioc",
            "post",
            op_post(
                "submitThreatIntelIoc",
                "Submit a new indicator of compromise",
                &["threat-intel"],
                "Indicator submission payload",
            ),
        )
        .path(
            "/api/threat-intel/purge",
            "post",
            op_post(
                "purgeThreatIntelIndicators",
                "Purge expired indicators from the threat intelligence store",
                &["threat-intel"],
                "Threat intelligence purge request",
            ),
        )
        .path(
            "/api/deception/status",
            "get",
            op(
                "getDeceptionStatus",
                "Deception engine status and artifact coverage",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/deception/deploy",
            "post",
            op_post(
                "deployDeceptionArtifacts",
                "Deploy deception artifacts and decoys",
                &["threat-intel"],
                "Decoy deployment request",
            ),
        )
        .path(
            "/api/idp/providers",
            "get",
            op(
                "listIdentityProviders",
                "List configured identity providers",
                &["auth"],
            ),
        )
        .path(
            "/api/idp/providers",
            "post",
            op_post(
                "saveIdentityProvider",
                "Create or update an identity provider",
                &["auth"],
                "Identity provider definition",
            ),
        )
        .path(
            "/api/scim/config",
            "get",
            op(
                "getScimConfig",
                "Get SCIM provisioning configuration",
                &["auth"],
            ),
        )
        .path(
            "/api/scim/config",
            "post",
            op_post(
                "saveScimConfig",
                "Update SCIM provisioning configuration",
                &["auth"],
                "SCIM configuration",
            ),
        )
        .path(
            "/api/processes/threads",
            "get",
            with_parameters(
                op(
                    "getProcessThreads",
                    "Per-process OS thread snapshot with live state, CPU, and wait context",
                    &["observability"],
                ),
                vec![integer_parameter(
                    "pid",
                    "query",
                    "Process identifier to inspect",
                    true,
                )],
            ),
        )
        .path(
            "/api/audit/admin",
            "get",
            op(
                "getAdminAudit",
                "Enterprise admin audit trail",
                &["observability"],
            ),
        )
        .path(
            "/api/audit/log",
            "get",
            op(
                "getAuditLog",
                "Recent API audit log entries",
                &["observability"],
            ),
        )
        .path(
            "/api/backups",
            "get",
            op(
                "listBackups",
                "List available database backups",
                &["observability"],
            ),
        )
        .path(
            "/api/backups",
            "post",
            op_post_without_body(
                "createBackup",
                "Create a database backup",
                &["observability"],
            ),
        )
        .path(
            "/api/backup/status",
            "get",
            op(
                "getBackupStatus",
                "Backup configuration and retention status",
                &["observability"],
            ),
        )
        .path(
            "/api/backup/encrypt",
            "post",
            op_post(
                "encryptBackupPayload",
                "Encrypt a backup payload with a passphrase",
                &["observability"],
                "Backup encryption payload",
            ),
        )
        .path(
            "/api/backup/decrypt",
            "post",
            op_post(
                "decryptBackupPayload",
                "Decrypt a backup payload with a passphrase",
                &["observability"],
                "Backup decryption payload",
            ),
        )
        .path(
            "/api/audit/verify",
            "get",
            op(
                "verifyAuditLog",
                "Verify integrity of the cryptographic audit chain",
                &["observability"],
            ),
        )
        .path(
            "/api/support/diagnostics",
            "get",
            op(
                "getSupportDiagnostics",
                "Support diagnostics bundle",
                &["status"],
            ),
        )
        .path(
            "/api/support/readiness-evidence",
            "get",
            op(
                "getReadinessEvidence",
                "Production readiness evidence pack",
                &["status"],
            ),
        )
        .path(
            "/api/support/first-run-proof",
            "post",
            op(
                "runFirstRunProof",
                "Run the first-run operator proof scenario",
                &["status"],
            ),
        )
        .path(
            "/api/control/failover-drill",
            "post",
            op(
                "runFailoverDrill",
                "Run an automated control-plane failover drill against current recovery artifacts",
                &["control"],
            ),
        )
        .path(
            "/api/support/parity",
            "get",
            op(
                "getSupportParity",
                "API, SDK, and GraphQL parity diagnostics",
                &["status"],
            ),
        )
        .path(
            "/api/docs/index",
            "get",
            op(
                "listSupportDocs",
                "Search embedded documentation and runbooks",
                &["status"],
            ),
        )
        .path(
            "/api/docs/content",
            "get",
            op(
                "getSupportDocContent",
                "Load a specific embedded documentation page",
                &["status"],
            ),
        )
        .path(
            "/api/graphql",
            "post",
            op_post(
                "executeGraphql",
                "Execute GraphQL queries against the Wardex schema",
                &["status"],
                "GraphQL request payload",
            ),
        )
        .path(
            "/api/system/health/dependencies",
            "get",
            op(
                "getDependencyHealth",
                "Dependency and rollout health",
                &["status"],
            ),
        )
        .build()
}

pub fn openapi_json(version: &str) -> String {
    let spec = wardex_openapi_spec(version);
    serde_json::to_string_pretty(&spec).unwrap_or_else(|_| "{}".into())
}

fn endpoint_auth_required(method: &str, path: &str) -> bool {
    endpoint_route_access(method, path).requires_bearer_auth()
}

pub fn endpoint_catalog(version: &str) -> Vec<EndpointCatalogEntry> {
    let spec = wardex_openapi_spec(version);
    let mut entries = Vec::new();
    for (path, item) in spec.paths {
        for (method, operation) in [
            ("GET", item.get),
            ("POST", item.post),
            ("PUT", item.put),
            ("DELETE", item.delete),
            ("PATCH", item.patch),
        ] {
            if let Some(op) = operation {
                entries.push(EndpointCatalogEntry {
                    method: method.to_string(),
                    path: path.clone(),
                    auth: endpoint_auth_required(method, &path),
                    description: op.summary,
                });
            }
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));
    entries
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
        assert!(spec.paths.len() > 50);
        assert!(spec.paths.contains_key("/api/status"));
        assert!(spec.paths.contains_key("/api/alerts"));
        assert!(spec.paths.contains_key("/api/agents"));
        assert!(spec.paths.contains_key("/api/config/current"));
        assert!(spec.paths.contains_key("/api/playbooks"));
        assert!(spec.paths.contains_key("/api/fleet/dashboard"));
        assert!(spec.paths.contains_key("/api/fleet/installs"));
        assert!(spec.paths.contains_key("/api/detection/profile"));
        assert!(spec.paths.contains_key("/api/detection/score/normalize"));
        assert!(spec.paths.contains_key("/api/processes/threads"));
        assert!(spec.paths.contains_key("/api/backups"));
        assert!(spec.paths.contains_key("/api/events/search"));
        assert!(spec.paths.contains_key("/api/ws/stats"));
        assert!(spec.paths.contains_key("/api/rollout/config"));
        assert!(spec.paths.contains_key("/api/support/readiness-evidence"));
        assert!(spec.paths.contains_key("/api/support/first-run-proof"));
        assert!(spec.paths.contains_key("/api/control/failover-drill"));
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
        assert!(
            spec.components
                .schemas
                .contains_key("CommandCenterSummaryResponse")
        );
        assert!(
            spec.components
                .schemas
                .contains_key("CommandCenterLaneResponse")
        );
        let error_schema = spec.components.schemas.get("Error").unwrap();
        assert!(error_schema.required.contains(&"error".to_string()));
        assert!(error_schema.required.contains(&"code".to_string()));
        assert!(error_schema.properties.contains_key("code"));
    }

    #[test]
    fn command_center_paths_use_explicit_response_schemas() {
        let spec = wardex_openapi_spec("0.35.0");

        let summary = spec
            .paths
            .get("/api/command/summary")
            .and_then(|item| item.get.as_ref())
            .expect("summary path");
        let summary_schema = summary
            .responses
            .get("200")
            .and_then(|response| response.content.as_ref())
            .and_then(|content| content.get("application/json"))
            .map(|media| &media.schema)
            .expect("summary response schema");
        match summary_schema {
            SchemaRef::Ref { reference } => {
                assert_eq!(
                    reference,
                    "#/components/schemas/CommandCenterSummaryResponse"
                )
            }
            SchemaRef::Inline(_) => panic!("expected command summary schema ref"),
        }

        let lane = spec
            .paths
            .get("/api/command/lanes/{lane}")
            .and_then(|item| item.get.as_ref())
            .expect("lane path");
        let lane_schema = lane
            .responses
            .get("200")
            .and_then(|response| response.content.as_ref())
            .and_then(|content| content.get("application/json"))
            .map(|media| &media.schema)
            .expect("lane response schema");
        match lane_schema {
            SchemaRef::Ref { reference } => {
                assert_eq!(reference, "#/components/schemas/CommandCenterLaneResponse")
            }
            SchemaRef::Inline(_) => panic!("expected command lane schema ref"),
        }
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
        for item in spec.paths.values() {
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
            .filter(|(_, item)| item.post.as_ref().is_some_and(|o| o.request_body.is_some()))
            .map(|(p, _)| p.as_str())
            .collect();
        assert!(posts_with_body.contains(&"/api/events"));
        assert!(posts_with_body.contains(&"/api/response/request"));
    }

    #[test]
    fn public_endpoints_have_empty_security() {
        let spec = wardex_openapi_spec("0.35.0");
        let health_op = spec.paths.get("/api/health").unwrap().get.as_ref().unwrap();
        assert_eq!(health_op.security.len(), 1);
        assert!(health_op.security[0].is_empty());
        assert_eq!(health_op.wardex_auth.as_deref(), Some("public"));
        let status_op = spec.paths.get("/api/status").unwrap().get.as_ref().unwrap();
        assert_eq!(status_op.security.len(), 1);
        assert!(status_op.security[0].contains_key("bearerAuth"));
        assert_eq!(status_op.wardex_auth.as_deref(), Some("authenticated"));
    }

    #[test]
    fn openapi_auth_metadata_matches_runtime_classifier() {
        let spec = wardex_openapi_spec("0.35.0");
        let catalog = endpoint_catalog("0.35.0")
            .into_iter()
            .map(|entry| ((entry.method, entry.path), entry.auth))
            .collect::<BTreeMap<_, _>>();

        for (path, item) in &spec.paths {
            for (method, operation) in [
                ("GET", item.get.as_ref()),
                ("POST", item.post.as_ref()),
                ("PUT", item.put.as_ref()),
                ("DELETE", item.delete.as_ref()),
                ("PATCH", item.patch.as_ref()),
            ] {
                let Some(operation) = operation else {
                    continue;
                };
                let access = endpoint_route_access(method, path);
                let has_security = operation.security.iter().any(|scheme| !scheme.is_empty());
                assert_eq!(
                    operation.wardex_auth.as_deref(),
                    Some(access.as_str()),
                    "{method} {path} should expose runtime auth metadata"
                );
                assert_eq!(
                    has_security,
                    access.requires_bearer_auth(),
                    "{method} {path} security should match runtime classifier"
                );
                assert_eq!(
                    catalog.get(&(method.to_string(), path.clone())).copied(),
                    Some(access.requires_bearer_auth()),
                    "{method} {path} catalog auth should match runtime classifier"
                );
            }
        }

        let events = spec
            .paths
            .get("/api/events")
            .and_then(|item| item.post.as_ref())
            .expect("events ingest path");
        assert_eq!(events.wardex_auth.as_deref(), Some("agent"));
        let update_check = spec
            .paths
            .get("/api/agents/update")
            .and_then(|item| item.get.as_ref())
            .expect("agent update-check path");
        assert_eq!(update_check.wardex_auth.as_deref(), Some("agent"));
        let update_download = spec
            .paths
            .get("/api/updates/download/{file_name}")
            .and_then(|item| item.get.as_ref())
            .expect("agent update download path");
        assert_eq!(update_download.wardex_auth.as_deref(), Some("agent"));
    }

    #[test]
    fn metrics_endpoint_included() {
        let spec = wardex_openapi_spec("0.35.0");
        assert!(spec.paths.contains_key("/api/metrics"));
    }

    #[test]
    fn dynamic_paths_include_path_parameters() {
        let spec = wardex_openapi_spec("0.35.0");
        let report_html = spec
            .paths
            .get("/api/reports/{id}/html")
            .unwrap()
            .get
            .as_ref()
            .unwrap();
        assert!(
            report_html
                .parameters
                .iter()
                .any(|parameter| parameter.location == "path" && parameter.name == "id")
        );
    }

    #[test]
    fn metrics_and_html_routes_use_non_json_content_types() {
        let spec = wardex_openapi_spec("0.35.0");
        let metrics = spec
            .paths
            .get("/api/metrics")
            .unwrap()
            .get
            .as_ref()
            .unwrap();
        let metrics_response = metrics.responses.get("200").unwrap();
        assert!(
            metrics_response
                .content
                .as_ref()
                .unwrap()
                .contains_key("text/plain")
        );

        let report_html = spec
            .paths
            .get("/api/reports/{id}/html")
            .unwrap()
            .get
            .as_ref()
            .unwrap();
        let report_html_response = report_html.responses.get("200").unwrap();
        assert!(
            report_html_response
                .content
                .as_ref()
                .unwrap()
                .contains_key("text/html")
        );
    }

    #[test]
    fn optional_and_bodyless_posts_are_described_correctly() {
        let spec = wardex_openapi_spec("0.35.0");
        let auth_rotate = spec
            .paths
            .get("/api/auth/rotate")
            .unwrap()
            .post
            .as_ref()
            .unwrap();
        assert!(auth_rotate.request_body.is_none());

        let execute_response = spec
            .paths
            .get("/api/response/execute")
            .unwrap()
            .post
            .as_ref()
            .unwrap();
        assert!(!execute_response.request_body.as_ref().unwrap().required);

        let sso_callback = spec
            .paths
            .get("/api/auth/sso/callback")
            .unwrap()
            .post
            .as_ref()
            .unwrap();
        assert!(sso_callback.request_body.as_ref().unwrap().required);
    }

    #[test]
    fn public_sso_auth_endpoints_are_documented() {
        let spec = wardex_openapi_spec("0.35.0");

        let sso_login = spec
            .paths
            .get("/api/auth/sso/login")
            .unwrap()
            .get
            .as_ref()
            .unwrap();
        assert_eq!(sso_login.security.len(), 1);
        assert!(sso_login.security[0].is_empty());
        assert!(sso_login.responses.contains_key("302"));
        assert!(sso_login.responses.contains_key("400"));
        assert!(sso_login.responses.contains_key("503"));
        assert!(
            sso_login
                .parameters
                .iter()
                .any(|parameter| parameter.location == "query" && parameter.name == "provider_id")
        );

        let sso_callback = spec.paths.get("/api/auth/sso/callback").unwrap();
        let sso_callback_get = sso_callback.get.as_ref().unwrap();
        assert_eq!(sso_callback_get.security.len(), 1);
        assert!(sso_callback_get.security[0].is_empty());
        assert!(sso_callback_get.responses.contains_key("302"));
        assert!(
            sso_callback_get
                .parameters
                .iter()
                .any(|parameter| parameter.location == "query" && parameter.name == "code")
        );

        let sso_callback_post = sso_callback.post.as_ref().unwrap();
        assert_eq!(sso_callback_post.security.len(), 1);
        assert!(sso_callback_post.security[0].is_empty());
        assert!(sso_callback_post.responses.contains_key("200"));
        assert!(sso_callback_post.responses.contains_key("400"));
        assert!(sso_callback_post.responses.contains_key("503"));
    }

    #[test]
    fn create_endpoints_use_created_status_when_server_returns_201() {
        let spec = wardex_openapi_spec("0.35.0");
        for path in [
            "/api/cases",
            "/api/hunts",
            "/api/content/rules",
            "/api/content/packs",
            "/api/suppressions",
        ] {
            let post = spec.paths.get(path).unwrap().post.as_ref().unwrap();
            assert!(
                post.responses.contains_key("201"),
                "{path} should document 201"
            );
            assert!(
                !post.responses.contains_key("200"),
                "{path} should not claim 200"
            );
        }
    }

    #[test]
    fn endpoint_catalog_uses_spec_auth_and_includes_new_routes() {
        let catalog = endpoint_catalog("0.35.0");
        assert!(catalog.iter().any(|entry| {
            entry.method == "GET"
                && entry.path == "/api/metrics"
                && !entry.auth
                && entry.description == "Prometheus-format metrics"
        }));
        assert!(catalog.iter().any(|entry| {
            entry.method == "GET" && entry.path == "/api/playbooks" && entry.auth
        }));
        assert!(catalog.iter().any(|entry| {
            entry.method == "POST" && entry.path == "/api/events/search" && entry.auth
        }));
        assert!(catalog.iter().any(|entry| {
            entry.method == "GET" && entry.path == "/api/fleet/dashboard" && entry.auth
        }));
        assert!(catalog.iter().any(|entry| {
            entry.method == "GET"
                && entry.path == "/api/support/parity"
                && entry.auth
                && entry.description == "API, SDK, and GraphQL parity diagnostics"
        }));
        assert!(catalog.iter().any(|entry| {
            entry.method == "GET"
                && entry.path == "/api/docs/index"
                && entry.auth
                && entry.description == "Search embedded documentation and runbooks"
        }));
    }
}

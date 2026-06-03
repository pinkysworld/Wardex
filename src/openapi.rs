// ── OpenAPI 3.0 Specification Generator ──────────────────────────────────────
//
// Generates a machine-readable OpenAPI 3.0.3 JSON spec describing the Wardex
// REST API surface.  The spec is served at GET /api/openapi.json and can be
// consumed by Swagger UI, Redoc, or SDK code-generators.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[path = "openapi_core_routes.rs"]
mod openapi_core_routes;
#[path = "openapi_enterprise_routes.rs"]
mod openapi_enterprise_routes;
#[path = "openapi_operational_routes.rs"]
mod openapi_operational_routes;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<bool>,
    #[serde(
        rename = "x-wardex-deprecated-since",
        skip_serializing_if = "Option::is_none"
    )]
    pub deprecated_since: Option<String>,
    #[serde(rename = "x-wardex-sunset", skip_serializing_if = "Option::is_none")]
    pub sunset: Option<String>,
    #[serde(
        rename = "x-wardex-replacement",
        skip_serializing_if = "Option::is_none"
    )]
    pub replacement: Option<String>,
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
    #[serde(
        rename = "x-wardex-auth-conditions",
        skip_serializing_if = "Option::is_none"
    )]
    pub wardex_auth_conditions: Option<Vec<String>>,
}

impl Operation {
    pub fn with_deprecation(
        mut self,
        since: impl Into<String>,
        sunset: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        self.deprecated = Some(true);
        self.deprecated_since = Some(since.into());
        self.sunset = Some(sunset.into());
        self.replacement = Some(replacement.into());
        self
    }
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
        op.wardex_auth_conditions = endpoint_auth_conditions(path);
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

fn boolean_schema() -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("boolean".into()),
        ..Default::default()
    })
}

fn array_schema(items: SchemaRef) -> SchemaRef {
    SchemaRef::Inline(Schema {
        schema_type: Some("array".into()),
        items: Some(Box::new(items)),
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
        enum_values: Some(
            values
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        ),
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

fn endpoint_auth_conditions(path: &str) -> Option<Vec<String>> {
    match path {
        "/api/metrics" => Some(vec![
            "Requires bearer auth when `server.metrics_bearer_token` or `WARDEX_METRICS_TOKEN` is set.".to_string(),
        ]),
        "/api/openapi.json" => Some(vec![
            "Requires authentication in production when `server.openapi_public=false` or `WARDEX_OPENAPI_PUBLIC=false`.".to_string(),
        ]),
        _ => None,
    }
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
        deprecated: None,
        deprecated_since: None,
        sunset: None,
        replacement: None,
        operation_id: id.into(),
        tags: tags.iter().map(std::string::ToString::to_string).collect(),
        parameters: vec![],
        request_body,
        responses,
        security,
        wardex_auth: None,
        wardex_auth_conditions: None,
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

fn op_with_schema(id: &str, summary: &str, tags: &[&str], schema: SchemaRef) -> Operation {
    op_with_responses(
        id,
        summary,
        tags,
        content_response_status("200", summary, "application/json", schema),
    )
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

fn operational_snapshot_metadata_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("persisted".into(), boolean_schema());
            p.insert("digest".into(), string_schema());
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("storage_key".into(), string_schema());
            p.insert("verified".into(), boolean_schema());
            p
        },
        required: vec!["digest".into()],
        ..Default::default()
    }
}

fn operational_snapshot_entry_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("kind".into(), string_schema());
            p.insert("digest".into(), string_schema());
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("storage_key".into(), string_schema());
            p.insert("size_bytes".into(), integer_schema());
            p.insert("verified".into(), boolean_schema());
            p
        },
        required: vec![
            "kind".into(),
            "digest".into(),
            "storage_key".into(),
            "verified".into(),
        ],
        ..Default::default()
    }
}

fn operational_snapshots_response_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("status".into(), string_schema());
            p.insert("count".into(), integer_schema());
            p.insert("verified_count".into(), integer_schema());
            p.insert(
                "snapshots".into(),
                array_schema(schema_ref("OperationalSnapshotEntry")),
            );
            p
        },
        required: vec!["generated_at".into(), "status".into(), "snapshots".into()],
        ..Default::default()
    }
}

fn operational_snapshot_verify_response_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("status".into(), string_schema());
            p.insert("verified".into(), boolean_schema());
            p.insert("snapshot".into(), schema_ref("OperationalSnapshotEntry"));
            p
        },
        required: vec!["generated_at".into(), "status".into(), "verified".into()],
        ..Default::default()
    }
}

fn stream_readiness_response_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("status".into(), string_schema());
            p.insert("score".into(), integer_schema());
            p.insert("queue_depth".into(), integer_schema());
            p.insert("dropped_events".into(), integer_schema());
            p.insert("promotion_guard".into(), string_schema());
            p.insert("next_action".into(), string_schema());
            p.insert("snapshot".into(), schema_ref("OperationalSnapshotMetadata"));
            p
        },
        required: vec!["generated_at".into(), "status".into(), "score".into()],
        ..Default::default()
    }
}

fn stream_reliability_lab_response_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("status".into(), string_schema());
            p.insert("scenario_count".into(), integer_schema());
            p.insert("fail_count".into(), integer_schema());
            p.insert("warn_count".into(), integer_schema());
            p.insert("scenarios".into(), array_schema(object_schema()));
            p.insert("snapshot".into(), schema_ref("OperationalSnapshotMetadata"));
            p
        },
        required: vec!["generated_at".into(), "status".into(), "scenarios".into()],
        ..Default::default()
    }
}

fn release_doctor_response_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("status".into(), string_schema());
            p.insert("runtime_version".into(), string_schema());
            p.insert("fail_count".into(), integer_schema());
            p.insert("warn_count".into(), integer_schema());
            p.insert("checks".into(), array_schema(object_schema()));
            p.insert("next_action".into(), string_schema());
            p.insert("snapshot".into(), schema_ref("OperationalSnapshotMetadata"));
            p
        },
        required: vec!["generated_at".into(), "status".into(), "checks".into()],
        ..Default::default()
    }
}

fn support_bundle_response_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("status".into(), string_schema());
            p.insert("digest".into(), string_schema());
            p.insert("bundle".into(), object_schema());
            p.insert("redaction".into(), object_schema());
            p.insert("snapshot".into(), schema_ref("OperationalSnapshotMetadata"));
            p
        },
        required: vec!["generated_at".into(), "status".into(), "digest".into()],
        ..Default::default()
    }
}

fn operator_work_queue_item_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("id".into(), string_schema());
            p.insert("priority".into(), string_schema());
            p.insert("title".into(), string_schema());
            p.insert("status".into(), string_schema());
            p.insert("href".into(), string_schema());
            p.insert("detail".into(), string_schema());
            p
        },
        required: vec![
            "id".into(),
            "priority".into(),
            "title".into(),
            "status".into(),
            "href".into(),
            "detail".into(),
        ],
        ..Default::default()
    }
}

fn operator_work_queue_response_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("status".into(), string_schema());
            p.insert("item_count".into(), integer_schema());
            p.insert("high_priority_count".into(), integer_schema());
            p.insert(
                "items".into(),
                array_schema(schema_ref("OperatorWorkQueueItem")),
            );
            p
        },
        required: vec![
            "generated_at".into(),
            "status".into(),
            "item_count".into(),
            "high_priority_count".into(),
            "items".into(),
        ],
        ..Default::default()
    }
}

fn operator_task_action_blueprint_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("action".into(), string_schema());
            p.insert("method".into(), string_schema());
            p.insert("required_fields".into(), string_array_schema());
            p.insert("audit".into(), boolean_schema());
            p
        },
        required: vec![
            "action".into(),
            "method".into(),
            "required_fields".into(),
            "audit".into(),
        ],
        ..Default::default()
    }
}

fn operator_task_automation_entry_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("task_id".into(), string_schema());
            p.insert("status".into(), string_schema());
            p.insert("available_actions".into(), string_array_schema());
            p.insert("owner".into(), string_schema());
            p.insert("due_at".into(), string_datetime_schema());
            p.insert("sla_age".into(), string_schema());
            p.insert("next_escalation_target".into(), string_schema());
            p.insert("recommended_action".into(), string_schema());
            p.insert(
                "action_blueprint".into(),
                schema_ref("OperatorTaskActionBlueprint"),
            );
            p.insert("source".into(), schema_ref("OperatorWorkQueueItem"));
            p
        },
        required: vec![
            "task_id".into(),
            "status".into(),
            "available_actions".into(),
            "owner".into(),
            "due_at".into(),
            "sla_age".into(),
            "next_escalation_target".into(),
            "recommended_action".into(),
            "action_blueprint".into(),
            "source".into(),
        ],
        ..Default::default()
    }
}

fn operator_task_automation_mutation_guard_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("status".into(), string_schema());
            p.insert("reason".into(), string_schema());
            p
        },
        required: vec!["status".into(), "reason".into()],
        ..Default::default()
    }
}

fn operator_task_automation_response_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("generated_at".into(), string_datetime_schema());
            p.insert("status".into(), string_schema());
            p.insert("automation_count".into(), integer_schema());
            p.insert("queue".into(), schema_ref("OperatorWorkQueueResponse"));
            p.insert(
                "automations".into(),
                array_schema(schema_ref("OperatorTaskAutomationEntry")),
            );
            p.insert(
                "action_blueprints".into(),
                array_schema(schema_ref("OperatorTaskActionBlueprint")),
            );
            p.insert(
                "mutation_guard".into(),
                schema_ref("OperatorTaskAutomationMutationGuard"),
            );
            p.insert("audit_requirements".into(), string_array_schema());
            p.insert("next_action".into(), string_schema());
            p
        },
        required: vec![
            "generated_at".into(),
            "status".into(),
            "automation_count".into(),
            "queue".into(),
            "automations".into(),
            "action_blueprints".into(),
            "mutation_guard".into(),
            "audit_requirements".into(),
            "next_action".into(),
        ],
        ..Default::default()
    }
}

fn subscription_resume_response_schema() -> Schema {
    Schema {
        schema_type: Some("object".into()),
        properties: {
            let mut p = BTreeMap::new();
            p.insert("subscription_id".into(), string_schema());
            p.insert("cursor".into(), string_schema());
            p.insert("requested_cursor".into(), string_schema());
            p.insert("next_cursor".into(), string_schema());
            p.insert("events".into(), array_schema(object_schema()));
            p.insert("has_more".into(), boolean_schema());
            p.insert("gap_detected".into(), boolean_schema());
            p.insert("replay_gap".into(), integer_schema());
            p.insert("durable".into(), boolean_schema());
            p
        },
        required: vec![
            "subscription_id".into(),
            "cursor".into(),
            "next_cursor".into(),
            "events".into(),
            "gap_detected".into(),
        ],
        ..Default::default()
    }
}

// ── Wardex spec factory ──────────────────────────────────────────────────────

pub fn wardex_openapi_spec(version: &str) -> OpenApiSpec {
    let builder = OpenApiBuilder::new("Wardex XDR/SIEM API", version)
        .tag("auth", "Authentication, session, and token management")
        .tag("status", "Platform health, status, and diagnostics")
        .tag(
            "command",
            "Command Center lane health and operator action surfaces",
        )
        .tag("detection", "Detection engineering, rules, and analysis")
        .tag("alerts", "Alert queue, triage, and analysis")
        .tag("incidents", "Incident and case management")
        .tag("fleet", "Fleet enrollment, agents, and inventory")
        .tag("response", "Response orchestration and approvals")
        .tag(
            "operator-trust",
            "Operator trust, usability, evidence clarity, and safety workspaces",
        )
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
            "OperationalSnapshotMetadata",
            operational_snapshot_metadata_schema(),
        )
        .schema(
            "OperationalSnapshotEntry",
            operational_snapshot_entry_schema(),
        )
        .schema(
            "OperationalSnapshotsResponse",
            operational_snapshots_response_schema(),
        )
        .schema(
            "OperationalSnapshotVerifyResponse",
            operational_snapshot_verify_response_schema(),
        )
        .schema(
            "StreamReadinessResponse",
            stream_readiness_response_schema(),
        )
        .schema(
            "StreamReliabilityLabResponse",
            stream_reliability_lab_response_schema(),
        )
        .schema("ReleaseDoctorResponse", release_doctor_response_schema())
        .schema("SupportBundleResponse", support_bundle_response_schema())
        .schema("OperatorWorkQueueItem", operator_work_queue_item_schema())
        .schema(
            "OperatorWorkQueueResponse",
            operator_work_queue_response_schema(),
        )
        .schema(
            "OperatorTaskActionBlueprint",
            operator_task_action_blueprint_schema(),
        )
        .schema(
            "OperatorTaskAutomationEntry",
            operator_task_automation_entry_schema(),
        )
        .schema(
            "OperatorTaskAutomationMutationGuard",
            operator_task_automation_mutation_guard_schema(),
        )
        .schema(
            "OperatorTaskAutomationResponse",
            operator_task_automation_response_schema(),
        )
        .schema(
            "SubscriptionResumeResponse",
            subscription_resume_response_schema(),
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
        );
    let builder = openapi_core_routes::register(builder);
    let builder = openapi_operational_routes::register(builder);
    let builder = openapi_enterprise_routes::register(builder);
    builder.build()
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
        assert!(spec.paths.contains_key("/api/alerts/histogram"));
        assert!(spec.paths.contains_key("/api/config/current"));
        assert!(spec.paths.contains_key("/api/playbooks"));
        assert!(spec.paths.contains_key("/api/fleet/dashboard"));
        assert!(spec.paths.contains_key("/api/fleet/installs"));
        assert!(spec.paths.contains_key("/api/stream/readiness"));
        assert!(spec.paths.contains_key("/api/subscriptions"));
        assert!(spec.paths.contains_key("/api/subscriptions/resume"));
        assert!(spec.paths.contains_key("/api/detection/profile"));
        assert!(spec.paths.contains_key("/api/detection/score/normalize"));
        assert!(spec.paths.contains_key("/api/processes/threads"));
        assert!(spec.paths.contains_key("/api/backups"));
        assert!(spec.paths.contains_key("/api/events/search"));
        assert!(spec.paths.contains_key("/api/ws/stats"));
        assert!(spec.paths.contains_key("/api/ws/health"));
        assert!(spec.paths.contains_key("/api/rollout/config"));
        assert!(spec.paths.contains_key("/api/detection/recommendations"));
        assert!(spec.paths.contains_key("/api/detection/readiness"));
        assert!(spec.paths.contains_key("/api/support/readiness-evidence"));
        assert!(spec.paths.contains_key("/api/launchpad/evidence-pack"));
        assert!(spec.paths.contains_key("/api/launchpad/release-diff"));
        assert!(spec.paths.contains_key("/api/launchpad/demo-status"));
        assert!(spec.paths.contains_key("/api/launchpad/demo-reset"));
        assert!(spec.paths.contains_key("/api/remediation/safety"));
        assert!(spec.paths.contains_key("/api/response/approval-overview"));
        assert!(spec.paths.contains_key("/api/response/execution-audit"));
        assert!(spec.paths.contains_key("/api/admin/rbac-coverage"));
        assert!(spec.paths.contains_key("/api/sdk/contract-status"));
        assert!(spec.paths.contains_key("/api/support/first-run-proof"));
        assert!(spec.paths.contains_key("/api/control/failover-drill"));
        assert!(spec.paths.contains_key("/api/release/clean-cut"));
        assert!(spec.paths.contains_key("/api/containers/release-parity"));
        assert!(spec.paths.contains_key("/api/release/verification-center"));
        assert!(
            spec.paths
                .contains_key("/api/release/deployment-trust-report")
        );
        assert!(
            spec.paths
                .contains_key("/api/deployment/self-hosted-wizard")
        );
        assert!(spec.paths.contains_key("/api/data-quality/dashboard"));
        assert!(spec.paths.contains_key("/api/performance/scale-baseline"));
        assert!(spec.paths.contains_key("/api/cluster/failover-execution"));
        assert!(spec.paths.contains_key("/api/secrets/rotation-operations"));
        assert!(spec.paths.contains_key("/api/operator/task-automation"));
        assert!(spec.paths.contains_key("/api/detection/validation-packs"));
    }

    #[test]
    fn operation_deprecation_metadata_serializes() {
        let operation = op("getLegacyEndpoint", "Legacy endpoint", &["admin"]).with_deprecation(
            "v1.0.27",
            "v1.2.0",
            "/api/replacement",
        );
        let value = serde_json::to_value(operation).unwrap();
        assert_eq!(value["deprecated"], true);
        assert_eq!(value["x-wardex-deprecated-since"], "v1.0.27");
        assert_eq!(value["x-wardex-sunset"], "v1.2.0");
        assert_eq!(value["x-wardex-replacement"], "/api/replacement");
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
    fn conditional_public_auth_annotations_are_exposed() {
        let spec = wardex_openapi_spec("0.35.0");
        let metrics = spec
            .paths
            .get("/api/metrics")
            .and_then(|item| item.get.as_ref())
            .expect("metrics route");
        assert!(
            metrics
                .wardex_auth_conditions
                .as_ref()
                .is_some_and(|conditions| conditions
                    .iter()
                    .any(|item| item.contains("metrics_bearer_token")))
        );

        let openapi = spec
            .paths
            .get("/api/openapi.json")
            .and_then(|item| item.get.as_ref())
            .expect("openapi route");
        assert!(
            openapi
                .wardex_auth_conditions
                .as_ref()
                .is_some_and(|conditions| conditions
                    .iter()
                    .any(|item| item.contains("openapi_public")))
        );
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

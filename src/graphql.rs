// ── GraphQL Query Layer ───────────────────────────────────────────────────────
//
// Lightweight GraphQL execution engine for threat-hunting queries.
// Supports introspection, filtering, pagination, and nested resolution
// without pulling in a heavy framework.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum allowed query string size (100 KiB).
const MAX_QUERY_SIZE: usize = 100 * 1024;
/// Maximum nesting depth for selection sets.
const MAX_DEPTH: usize = 50;

// ── Schema Definition ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlSchema {
    pub types: Vec<GqlType>,
    pub query_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlType {
    pub name: String,
    pub kind: GqlTypeKind,
    pub fields: Vec<GqlField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GqlTypeKind {
    Object,
    Scalar,
    List,
    NonNull,
    Enum,
    InputObject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlField {
    pub name: String,
    pub field_type: String,
    pub args: Vec<GqlArg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlArg {
    pub name: String,
    pub arg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
}

// ── Query/Response ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlRequest {
    pub query: String,
    #[serde(default)]
    pub variables: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<GqlError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlError {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
}

impl GqlResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            data: Some(data),
            errors: vec![],
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            data: None,
            errors: vec![GqlError {
                message: msg.into(),
                path: None,
            }],
        }
    }
}

// ── Parsed Query AST ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub operation: String, // "query" or "mutation"
    pub name: Option<String>,
    pub selections: Vec<Selection>,
}

#[derive(Debug, Clone)]
pub struct Selection {
    pub field: String,
    pub alias: Option<String>,
    pub args: HashMap<String, serde_json::Value>,
    pub sub_fields: Vec<Selection>,
}

// ── Parser ───────────────────────────────────────────────────────────────────

pub fn parse_query(query: &str) -> Result<ParsedQuery, String> {
    if query.len() > MAX_QUERY_SIZE {
        return Err(format!(
            "Query exceeds maximum size of {MAX_QUERY_SIZE} bytes"
        ));
    }
    let trimmed = query.trim();
    let (operation, rest) = if trimmed.starts_with("mutation") {
        (
            "mutation".to_string(),
            trimmed.strip_prefix("mutation").unwrap_or(trimmed),
        )
    } else if trimmed.starts_with("query") {
        (
            "query".to_string(),
            trimmed.strip_prefix("query").unwrap_or(trimmed),
        )
    } else if trimmed.starts_with('{') {
        ("query".to_string(), trimmed)
    } else {
        return Err("Expected 'query' or 'mutation' or '{'".into());
    };

    let rest = rest.trim();

    // Extract optional name before first {
    let (name, body) = if let Some(brace_pos) = rest.find('{') {
        let before = rest[..brace_pos].trim();
        let name = if before.is_empty() {
            None
        } else {
            // Strip parenthesized variables if present
            let n = before.split('(').next().unwrap_or(before).trim();
            if n.is_empty() {
                None
            } else {
                Some(n.to_string())
            }
        };
        (name, &rest[brace_pos..])
    } else {
        return Err("Expected '{'".into());
    };

    let selections = parse_selection_set(body, 0)?;

    Ok(ParsedQuery {
        operation,
        name,
        selections,
    })
}

fn parse_selection_set(input: &str, depth: usize) -> Result<Vec<Selection>, String> {
    if depth >= MAX_DEPTH {
        return Err(format!(
            "Selection nesting exceeds maximum depth of {MAX_DEPTH}"
        ));
    }
    let trimmed = input.trim();
    if !trimmed.starts_with('{') {
        return Err("Expected '{'".into());
    }

    let inner = match find_matching_brace(trimmed) {
        Some(end) => &trimmed[1..end],
        None => return Err("Unmatched '{'".into()),
    };

    parse_fields(inner, depth)
}

fn find_matching_brace(s: &str) -> Option<usize> {
    let mut depth = 0;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_fields(input: &str, depth: usize) -> Result<Vec<Selection>, String> {
    let mut fields = Vec::new();
    let mut chars = input.chars().peekable();
    let mut buf = String::new();

    while chars.peek().is_some() {
        skip_whitespace(&mut chars);

        if chars.peek().is_none() {
            break;
        }

        // Read field name (possibly alias: name)
        buf.clear();
        while let Some(&c) = chars.peek() {
            if c.is_alphanumeric() || c == '_' {
                buf.push(c);
                chars.next();
            } else {
                break;
            }
        }

        if buf.is_empty() {
            // Report unexpected character instead of silently skipping
            if let Some(&c) = chars.peek() {
                return Err(format!("Unexpected character '{c}' in selection set"));
            }
            break;
        }

        skip_whitespace(&mut chars);

        // Check for alias
        let (alias, field_name) = if chars.peek() == Some(&':') {
            chars.next(); // consume ':'
            skip_whitespace(&mut chars);
            let mut name = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '_' {
                    name.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            (Some(buf.clone()), name)
        } else {
            (None, buf.clone())
        };

        skip_whitespace(&mut chars);

        // Parse arguments
        let args = if chars.peek() == Some(&'(') {
            chars.next(); // consume '('
            let mut arg_str = String::new();
            let mut paren_depth = 1;
            for c in chars.by_ref() {
                if c == '(' {
                    paren_depth += 1;
                }
                if c == ')' {
                    paren_depth -= 1;
                    if paren_depth == 0 {
                        break;
                    }
                }
                arg_str.push(c);
            }
            parse_args(&arg_str)
        } else {
            HashMap::new()
        };

        skip_whitespace(&mut chars);

        // Parse sub-fields
        let sub_fields = if chars.peek() == Some(&'{') {
            let mut brace_str = String::new();
            let mut brace_depth = 0;
            for c in chars.by_ref() {
                brace_str.push(c);
                if c == '{' {
                    brace_depth += 1;
                }
                if c == '}' {
                    brace_depth -= 1;
                    if brace_depth == 0 {
                        break;
                    }
                }
            }
            parse_selection_set(&brace_str, depth + 1).unwrap_or_default()
        } else {
            vec![]
        };

        fields.push(Selection {
            field: field_name,
            alias,
            args,
            sub_fields,
        });
    }

    Ok(fields)
}

fn skip_whitespace(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
        chars.next();
    }
}

fn parse_args(input: &str) -> HashMap<String, serde_json::Value> {
    let mut args = HashMap::new();
    let mut remaining = input.trim();

    while !remaining.is_empty() {
        // Find the key (everything up to ':')
        let Some(colon_pos) = remaining.find(':') else {
            break;
        };
        let key = remaining[..colon_pos].trim().to_string();
        remaining = remaining[colon_pos + 1..].trim();

        // Parse the value, respecting quotes
        let (val, rest) = if remaining.starts_with('"') {
            // Find closing quote (handle escaped quotes and escaped backslashes)
            let mut end = 1;
            while end < remaining.len() {
                if remaining.as_bytes()[end] == b'\\' && end + 1 < remaining.len() {
                    end += 2; // skip escaped character (\\, \", etc.)
                    continue;
                }
                if remaining.as_bytes()[end] == b'"' {
                    break;
                }
                end += 1;
            }
            let s = &remaining[1..end];
            let after = remaining
                .get(end + 1..)
                .unwrap_or("")
                .trim_start_matches(',')
                .trim();
            (serde_json::Value::String(s.to_string()), after)
        } else {
            // Non-quoted: take until comma or end
            let comma = remaining.find(',').unwrap_or(remaining.len());
            let raw = remaining[..comma].trim();
            let after = remaining.get(comma + 1..).unwrap_or("").trim();
            let value = if let Ok(n) = raw.parse::<i64>() {
                serde_json::Value::Number(n.into())
            } else if raw == "true" {
                serde_json::Value::Bool(true)
            } else if raw == "false" {
                serde_json::Value::Bool(false)
            } else {
                serde_json::Value::String(raw.to_string())
            };
            (value, after)
        };

        args.insert(key, val);
        remaining = rest;
    }

    args
}

// ── Wardex Schema Definition ─────────────────────────────────────────────────

pub fn wardex_schema() -> GqlSchema {
    GqlSchema {
        query_type: "Query".into(),
        types: vec![
            GqlType {
                name: "Query".into(),
                kind: GqlTypeKind::Object,
                description: Some("Root query type".into()),
                fields: vec![
                    field(
                        "alerts",
                        "[Alert]",
                        &[
                            arg("limit", "Int", Some("50")),
                            arg("level", "String", None),
                            arg("device_id", "String", None),
                        ],
                        Some("List alerts with optional filters"),
                    ),
                    field(
                        "alert",
                        "Alert",
                        &[arg("id", "String!", None)],
                        Some("Get alert by ID"),
                    ),
                    field(
                        "incidents",
                        "[Incident]",
                        &[
                            arg("limit", "Int", Some("50")),
                            arg("status", "String", None),
                        ],
                        Some("List incidents"),
                    ),
                    field(
                        "incident",
                        "Incident",
                        &[arg("id", "String!", None)],
                        Some("Get incident by ID"),
                    ),
                    field(
                        "agents",
                        "[Agent]",
                        &[arg("status", "String", None)],
                        Some("List fleet agents"),
                    ),
                    field(
                        "agent",
                        "Agent",
                        &[arg("id", "String!", None)],
                        Some("Get agent by ID"),
                    ),
                    field(
                        "events",
                        "[Event]",
                        &[
                            arg("limit", "Int", Some("100")),
                            arg("device_id", "String", None),
                            arg("since", "String", None),
                        ],
                        Some("Query telemetry events"),
                    ),
                    field("policies", "[Policy]", &[], Some("List all policies")),
                    field(
                        "iocs",
                        "[IOC]",
                        &[arg("type", "String", None)],
                        Some("List threat indicators"),
                    ),
                    field("status", "Status", &[], Some("System status")),
                    field(
                        "compliance",
                        "ComplianceReport",
                        &[arg("framework", "String!", None)],
                        Some("Run compliance check"),
                    ),
                    field(
                        "hunts",
                        "[Hunt]",
                        &[arg("limit", "Int", Some("20"))],
                        Some("List threat hunts"),
                    ),
                    field(
                        "aggregate",
                        "AggregateResult",
                        &[
                            arg("source", "String!", None),
                            arg("op", "String!", None),
                            arg("field", "String!", None),
                            arg("group_by", "String", None),
                        ],
                        Some(
                            "Run aggregation (COUNT/SUM/AVG/MIN/MAX/DISTINCT) with optional GROUP BY",
                        ),
                    ),
                ],
            },
            gql_type(
                "Alert",
                &[
                    "id: String!",
                    "level: String!",
                    "timestamp: String!",
                    "device_id: String!",
                    "score: Float!",
                    "reasons: [String]!",
                    "status: String!",
                ],
            ),
            gql_type(
                "Incident",
                &[
                    "id: String!",
                    "title: String!",
                    "severity: String!",
                    "status: String!",
                    "created_at: String!",
                    "alert_count: Int!",
                ],
            ),
            gql_type(
                "Agent",
                &[
                    "id: String!",
                    "hostname: String!",
                    "os: String!",
                    "version: String!",
                    "status: String!",
                    "last_heartbeat: String!",
                ],
            ),
            gql_type(
                "Event",
                &[
                    "timestamp: String!",
                    "device_id: String!",
                    "event_type: String!",
                    "data: JSON!",
                ],
            ),
            gql_type(
                "Policy",
                &[
                    "id: String!",
                    "name: String!",
                    "enabled: Boolean!",
                    "rules: Int!",
                ],
            ),
            gql_type(
                "IOC",
                &[
                    "value: String!",
                    "ioc_type: String!",
                    "source: String!",
                    "added: String!",
                ],
            ),
            gql_type(
                "Status",
                &[
                    "version: String!",
                    "uptime_secs: Float!",
                    "agents_online: Int!",
                    "alerts_total: Int!",
                    "incidents_open: Int!",
                ],
            ),
            gql_type(
                "ComplianceReport",
                &[
                    "framework: String!",
                    "score: Float!",
                    "passed: Int!",
                    "failed: Int!",
                    "findings: [Finding]!",
                ],
            ),
            gql_type(
                "Finding",
                &[
                    "control_id: String!",
                    "title: String!",
                    "status: String!",
                    "evidence: String!",
                ],
            ),
            gql_type(
                "Hunt",
                &[
                    "id: String!",
                    "name: String!",
                    "status: String!",
                    "matches: Int!",
                    "created_at: String!",
                ],
            ),
            gql_type(
                "AggregateResult",
                &[
                    "op: String!",
                    "field: String!",
                    "value: JSON",
                    "group_by: String",
                    "groups: [AggregateGroup]",
                ],
            ),
            gql_type(
                "AggregateGroup",
                &["key: String!", "value: JSON", "count: Int!"],
            ),
        ],
    }
}

fn field(name: &str, ftype: &str, args: &[GqlArg], desc: Option<&str>) -> GqlField {
    GqlField {
        name: name.into(),
        field_type: ftype.into(),
        args: args.to_vec(),
        description: desc.map(std::convert::Into::into),
    }
}

fn arg(name: &str, atype: &str, default: Option<&str>) -> GqlArg {
    GqlArg {
        name: name.into(),
        arg_type: atype.into(),
        default_value: default.map(std::convert::Into::into),
    }
}

fn gql_type(name: &str, field_defs: &[&str]) -> GqlType {
    let fields = field_defs
        .iter()
        .map(|def| {
            let parts: Vec<&str> = def.splitn(2, ':').collect();
            GqlField {
                name: parts[0].trim().into(),
                field_type: parts.get(1).unwrap_or(&"String").trim().into(),
                args: vec![],
                description: None,
            }
        })
        .collect();

    GqlType {
        name: name.into(),
        kind: GqlTypeKind::Object,
        fields,
        description: None,
    }
}

// ── Aggregation Engine ───────────────────────────────────────────────────────

/// Supported aggregation functions for threat-hunting queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregateOp {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    Distinct,
}

impl std::str::FromStr for AggregateOp {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "count" => Ok(Self::Count),
            "sum" => Ok(Self::Sum),
            "avg" => Ok(Self::Avg),
            "min" => Ok(Self::Min),
            "max" => Ok(Self::Max),
            "distinct" => Ok(Self::Distinct),
            _ => Err(format!("unknown aggregate op: {s}")),
        }
    }
}

/// Request for an aggregation query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateRequest {
    pub source: String,
    pub op: AggregateOp,
    pub field: String,
    pub group_by: Option<String>,
    pub filters: HashMap<String, serde_json::Value>,
}

/// Result of an aggregation query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateResult {
    pub op: String,
    pub field: String,
    pub value: serde_json::Value,
    pub group_by: Option<String>,
    pub groups: Vec<AggregateGroup>,
}

/// A single group in a GROUP BY aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateGroup {
    pub key: String,
    pub value: serde_json::Value,
    pub count: usize,
}

/// Run an aggregation over a JSON array of objects.
pub fn aggregate(
    data: &[serde_json::Value],
    op: AggregateOp,
    field: &str,
    group_by: Option<&str>,
) -> AggregateResult {
    if let Some(gb) = group_by {
        // GROUP BY mode
        let mut groups: HashMap<String, Vec<&serde_json::Value>> = HashMap::new();
        for item in data {
            let key = item.get(gb).map_or_else(
                || "null".to_string(),
                |v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                },
            );
            groups.entry(key).or_default().push(item);
        }

        let mut agg_groups: Vec<AggregateGroup> = groups
            .into_iter()
            .map(|(key, items)| {
                let vals: Vec<f64> = items
                    .iter()
                    .filter_map(|i| i.get(field).and_then(serde_json::Value::as_f64))
                    .collect();
                let value = compute_agg(op, &vals, items.len(), &items, field);
                AggregateGroup {
                    key,
                    value,
                    count: items.len(),
                }
            })
            .collect();
        agg_groups.sort_by(|a, b| a.key.cmp(&b.key));

        AggregateResult {
            op: format!("{op:?}"),
            field: field.to_string(),
            value: serde_json::Value::Null,
            group_by: Some(gb.to_string()),
            groups: agg_groups,
        }
    } else {
        // Simple aggregation
        let vals: Vec<f64> = data
            .iter()
            .filter_map(|i| i.get(field).and_then(serde_json::Value::as_f64))
            .collect();
        let refs: Vec<&serde_json::Value> = data.iter().collect();
        let value = compute_agg(op, &vals, data.len(), &refs, field);

        AggregateResult {
            op: format!("{op:?}"),
            field: field.to_string(),
            value,
            group_by: None,
            groups: vec![],
        }
    }
}

fn compute_agg(
    op: AggregateOp,
    vals: &[f64],
    item_count: usize,
    items: &[&serde_json::Value],
    field: &str,
) -> serde_json::Value {
    match op {
        AggregateOp::Count => serde_json::json!(item_count),
        AggregateOp::Sum => {
            let s: f64 = vals.iter().sum();
            serde_json::json!(s)
        }
        AggregateOp::Avg => {
            if vals.is_empty() {
                serde_json::Value::Null
            } else {
                let avg = vals.iter().sum::<f64>() / vals.len() as f64;
                serde_json::json!(avg)
            }
        }
        AggregateOp::Min => vals
            .iter()
            .copied()
            .reduce(f64::min)
            .map_or(serde_json::Value::Null, |v| serde_json::json!(v)),
        AggregateOp::Max => vals
            .iter()
            .copied()
            .reduce(f64::max)
            .map_or(serde_json::Value::Null, |v| serde_json::json!(v)),
        AggregateOp::Distinct => {
            let mut unique: Vec<String> = items
                .iter()
                .filter_map(|i| i.get(field))
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            unique.sort();
            serde_json::json!(unique)
        }
    }
}

// ── Executor ─────────────────────────────────────────────────────────────────

pub struct GqlExecutor {
    pub schema: GqlSchema,
    resolvers: HashMap<
        String,
        Box<dyn Fn(&HashMap<String, serde_json::Value>) -> serde_json::Value + Send + Sync>,
    >,
}

impl GqlExecutor {
    pub fn new(schema: GqlSchema) -> Self {
        Self {
            schema,
            resolvers: HashMap::new(),
        }
    }

    pub fn register_resolver(
        &mut self,
        field_name: &str,
        resolver: Box<
            dyn Fn(&HashMap<String, serde_json::Value>) -> serde_json::Value + Send + Sync,
        >,
    ) {
        self.resolvers.insert(field_name.to_string(), resolver);
    }

    pub fn execute(&self, request: &GqlRequest) -> GqlResponse {
        if serde_json::to_vec(&request.variables)
            .map(|payload| payload.len() > MAX_QUERY_SIZE)
            .unwrap_or(true)
        {
            return GqlResponse::error(format!(
                "Variables exceed maximum size of {MAX_QUERY_SIZE} bytes"
            ));
        }

        let parsed = match parse_query(&request.query) {
            Ok(p) => p,
            Err(e) => return GqlResponse::error(e),
        };

        if parsed.operation != "query" {
            return GqlResponse::error("Only queries are supported");
        }

        // Handle introspection
        if parsed.selections.iter().any(|s| s.field == "__schema") {
            return GqlResponse::ok(self.introspect());
        }

        let mut result = serde_json::Map::new();

        for sel in &parsed.selections {
            let key = sel.alias.as_deref().unwrap_or(&sel.field);

            // Merge request variables into args
            let mut args = sel.args.clone();
            for (k, v) in &request.variables {
                args.entry(k.clone()).or_insert_with(|| v.clone());
            }

            if let Some(resolver) = self.resolvers.get(&sel.field) {
                let value = resolver(&args);
                // Apply sub-field selection
                let filtered = self.apply_selection(&value, &sel.sub_fields);
                result.insert(key.to_string(), filtered);
            } else {
                result.insert(key.to_string(), serde_json::Value::Null);
            }
        }

        GqlResponse::ok(serde_json::Value::Object(result))
    }

    fn apply_selection(
        &self,
        value: &serde_json::Value,
        selections: &[Selection],
    ) -> serde_json::Value {
        if selections.is_empty() {
            return value.clone();
        }

        match value {
            serde_json::Value::Object(map) => {
                let mut filtered = serde_json::Map::new();
                for sel in selections {
                    let key = sel.alias.as_deref().unwrap_or(&sel.field);
                    if let Some(v) = map.get(&sel.field) {
                        filtered.insert(key.to_string(), self.apply_selection(v, &sel.sub_fields));
                    }
                }
                serde_json::Value::Object(filtered)
            }
            serde_json::Value::Array(arr) => serde_json::Value::Array(
                arr.iter()
                    .map(|v| self.apply_selection(v, selections))
                    .collect(),
            ),
            _ => value.clone(),
        }
    }

    fn introspect(&self) -> serde_json::Value {
        serde_json::json!({
            "__schema": {
                "queryType": { "name": &self.schema.query_type },
                "types": self.schema.types.iter().map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "kind": t.kind,
                        "fields": t.fields.iter().map(|f| {
                            serde_json::json!({
                                "name": f.name,
                                "type": f.field_type,
                                "args": f.args.iter().map(|a| {
                                    serde_json::json!({
                                        "name": a.name,
                                        "type": a.arg_type,
                                    })
                                }).collect::<Vec<_>>(),
                            })
                        }).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
            }
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_simple_query() {
        let q = parse_query("{ alerts { id level } }").unwrap();
        assert_eq!(q.operation, "query");
        assert_eq!(q.selections.len(), 1);
        assert_eq!(q.selections[0].field, "alerts");
        assert_eq!(q.selections[0].sub_fields.len(), 2);
    }

    #[test]
    fn parse_named_query() {
        let q = parse_query("query GetAlerts { alerts { id } }").unwrap();
        assert_eq!(q.operation, "query");
        assert_eq!(q.name, Some("GetAlerts".into()));
    }

    #[test]
    fn parse_query_with_args() {
        let q = parse_query(r#"{ alerts(limit: 10, level: "critical") { id } }"#).unwrap();
        let sel = &q.selections[0];
        assert_eq!(sel.args.get("limit"), Some(&serde_json::json!(10)));
        assert_eq!(sel.args.get("level"), Some(&serde_json::json!("critical")));
    }

    #[test]
    fn parse_multiple_fields() {
        let q = parse_query("{ alerts { id } incidents { id title } status { version } }").unwrap();
        assert_eq!(q.selections.len(), 3);
    }

    #[test]
    fn parse_alias() {
        let q = parse_query("{ criticalAlerts: alerts(level: \"critical\") { id } }").unwrap();
        assert_eq!(q.selections[0].alias, Some("criticalAlerts".into()));
        assert_eq!(q.selections[0].field, "alerts");
    }

    #[test]
    fn parse_error_no_brace() {
        let result = parse_query("alerts id");
        assert!(result.is_err());
    }

    #[test]
    fn wardex_schema_has_types() {
        let schema = wardex_schema();
        assert!(!schema.types.is_empty());
        let query_type = schema.types.iter().find(|t| t.name == "Query").unwrap();
        assert!(query_type.fields.len() >= 10);
    }

    #[test]
    fn executor_resolves_field() {
        let schema = wardex_schema();
        let mut exec = GqlExecutor::new(schema);
        exec.register_resolver(
            "status",
            Box::new(|_args| {
                serde_json::json!({
                    "version": "0.35.0",
                    "uptime_secs": 3600.0,
                    "agents_online": 5,
                    "alerts_total": 42,
                    "incidents_open": 2,
                })
            }),
        );

        let req = GqlRequest {
            query: "{ status { version uptime_secs } }".into(),
            variables: HashMap::new(),
            operation_name: None,
        };
        let resp = exec.execute(&req);
        assert!(resp.errors.is_empty());
        let data = resp.data.unwrap();
        assert_eq!(data["status"]["version"], "0.35.0");
        // Sub-field filtering: only requested fields returned
        assert!(data["status"].get("agents_online").is_none());
    }

    #[test]
    fn executor_introspection() {
        let schema = wardex_schema();
        let exec = GqlExecutor::new(schema);
        let req = GqlRequest {
            query: "{ __schema { types { name } } }".into(),
            variables: HashMap::new(),
            operation_name: None,
        };
        let resp = exec.execute(&req);
        assert!(resp.errors.is_empty());
        let data = resp.data.unwrap();
        assert!(data["__schema"]["types"].is_array());
    }

    #[test]
    fn executor_unknown_field_returns_null() {
        let exec = GqlExecutor::new(wardex_schema());
        let req = GqlRequest {
            query: "{ nonexistent { id } }".into(),
            variables: HashMap::new(),
            operation_name: None,
        };
        let resp = exec.execute(&req);
        assert!(resp.errors.is_empty());
        assert_eq!(resp.data.unwrap()["nonexistent"], serde_json::Value::Null);
    }

    #[test]
    fn executor_with_list_resolver() {
        let mut exec = GqlExecutor::new(wardex_schema());
        exec.register_resolver(
            "alerts",
            Box::new(|args| {
                let limit = args
                    .get("limit")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(50);
                let alerts: Vec<_> = (0..limit.min(3))
                    .map(|i| {
                        serde_json::json!({
                            "id": format!("alert-{}", i),
                            "level": "elevated",
                            "timestamp": "2025-01-01T00:00:00Z",
                        })
                    })
                    .collect();
                serde_json::json!(alerts)
            }),
        );

        let req = GqlRequest {
            query: r"{ alerts(limit: 2) { id level } }".into(),
            variables: HashMap::new(),
            operation_name: None,
        };
        let resp = exec.execute(&req);
        let alerts = &resp.data.unwrap()["alerts"];
        assert_eq!(alerts.as_array().unwrap().len(), 2);
        // Only requested fields
        assert!(alerts[0].get("timestamp").is_none());
    }

    #[test]
    fn gql_response_ok_and_error() {
        let ok = GqlResponse::ok(serde_json::json!({"test": true}));
        assert!(ok.errors.is_empty());
        assert!(ok.data.is_some());

        let err = GqlResponse::error("bad query");
        assert!(err.data.is_none());
        assert_eq!(err.errors[0].message, "bad query");
    }

    #[test]
    fn execute_rejects_oversized_variables() {
        let exec = GqlExecutor::new(wardex_schema());
        let req = GqlRequest {
            query: "{ status { version } }".into(),
            variables: HashMap::from([(
                "blob".to_string(),
                serde_json::json!("x".repeat(MAX_QUERY_SIZE + 1)),
            )]),
            operation_name: None,
        };

        let resp = exec.execute(&req);
        assert!(resp.data.is_none());
        assert!(
            resp.errors[0]
                .message
                .contains("Variables exceed maximum size")
        );
    }

    #[test]
    fn schema_serializes() {
        let schema = wardex_schema();
        let json = serde_json::to_string(&schema).unwrap();
        assert!(json.contains("Query"));
        assert!(json.contains("Alert"));
    }

    #[test]
    fn aggregate_count() {
        let data = vec![
            serde_json::json!({"level": "Critical", "score": 9.0}),
            serde_json::json!({"level": "Severe", "score": 6.0}),
            serde_json::json!({"level": "Critical", "score": 8.5}),
        ];
        let result = aggregate(&data, AggregateOp::Count, "score", None);
        assert_eq!(result.value, serde_json::json!(3));
    }

    #[test]
    fn aggregate_avg_sum() {
        let data = vec![
            serde_json::json!({"score": 10.0}),
            serde_json::json!({"score": 20.0}),
            serde_json::json!({"score": 30.0}),
        ];
        let avg = aggregate(&data, AggregateOp::Avg, "score", None);
        assert_eq!(avg.value, serde_json::json!(20.0));
        let sum = aggregate(&data, AggregateOp::Sum, "score", None);
        assert_eq!(sum.value, serde_json::json!(60.0));
    }

    #[test]
    fn aggregate_min_max() {
        let data = vec![
            serde_json::json!({"score": 3.0}),
            serde_json::json!({"score": 7.0}),
            serde_json::json!({"score": 1.5}),
        ];
        let min = aggregate(&data, AggregateOp::Min, "score", None);
        assert_eq!(min.value, serde_json::json!(1.5));
        let max = aggregate(&data, AggregateOp::Max, "score", None);
        assert_eq!(max.value, serde_json::json!(7.0));
    }

    #[test]
    fn aggregate_distinct() {
        let data = vec![
            serde_json::json!({"level": "Critical"}),
            serde_json::json!({"level": "Severe"}),
            serde_json::json!({"level": "Critical"}),
        ];
        let distinct = aggregate(&data, AggregateOp::Distinct, "level", None);
        let arr = distinct.value.as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn aggregate_group_by() {
        let data = vec![
            serde_json::json!({"level": "Critical", "score": 9.0}),
            serde_json::json!({"level": "Severe", "score": 6.0}),
            serde_json::json!({"level": "Critical", "score": 8.0}),
            serde_json::json!({"level": "Severe", "score": 5.0}),
        ];
        let result = aggregate(&data, AggregateOp::Avg, "score", Some("level"));
        assert_eq!(result.groups.len(), 2);
        let critical = result.groups.iter().find(|g| g.key == "Critical").unwrap();
        assert_eq!(critical.count, 2);
        assert_eq!(critical.value, serde_json::json!(8.5));
        let severe = result.groups.iter().find(|g| g.key == "Severe").unwrap();
        assert_eq!(severe.value, serde_json::json!(5.5));
    }

    #[test]
    fn aggregate_op_from_str() {
        assert_eq!(AggregateOp::from_str("count"), Ok(AggregateOp::Count));
        assert_eq!(AggregateOp::from_str("AVG"), Ok(AggregateOp::Avg));
        assert!(AggregateOp::from_str("invalid").is_err());
    }

    #[test]
    fn aggregate_empty_data() {
        let data: Vec<serde_json::Value> = vec![];
        let result = aggregate(&data, AggregateOp::Avg, "score", None);
        assert_eq!(result.value, serde_json::Value::Null);
    }
}

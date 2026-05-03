use include_dir::{Dir, include_dir};
use serde::Serialize;
use std::collections::BTreeSet;

const EMBEDDED_DOCS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/docs");
const TYPESCRIPT_SDK_PACKAGE: &str = include_str!("../sdk/typescript/package.json");
const PYTHON_SDK_PROJECT: &str = include_str!("../sdk/python/pyproject.toml");
const TYPESCRIPT_SDK_CLIENT: &str = include_str!("../sdk/typescript/src/index.ts");
const PYTHON_SDK_CLIENT: &str = include_str!("../sdk/python/wardex/client.py");
const OPENAPI_DOCS_SNAPSHOT: &str = include_str!("../docs/openapi.yaml");
const REQUIRED_REPORT_WORKFLOW_OPERATIONS: &[(&str, &str)] = &[
    ("GET", "/api/report-templates"),
    ("POST", "/api/report-templates"),
    ("GET", "/api/report-runs"),
    ("POST", "/api/report-runs"),
    ("GET", "/api/report-schedules"),
    ("POST", "/api/report-schedules"),
];
const REQUIRED_REPORT_WORKFLOW_ENDPOINTS: &[&str] = &[
    "/api/report-templates",
    "/api/report-runs",
    "/api/report-schedules",
];

#[derive(Debug, Clone, Serialize)]
struct DocumentEntry {
    path: String,
    title: String,
    section: String,
    kind: String,
    tags: Vec<String>,
    summary: String,
    headings: Vec<String>,
    score: usize,
}

#[derive(Debug, Clone, Serialize)]
struct SdkParityEntry {
    package: String,
    version: String,
    aligned: bool,
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn prettify_title(value: &str) -> String {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            let first = chars
                .next()
                .map(|ch| ch.to_ascii_uppercase())
                .unwrap_or_default();
            let rest = chars.as_str().to_ascii_lowercase();
            format!("{first}{rest}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn markdown_title(content: &str, path: &str) -> String {
    content
        .lines()
        .find_map(|line| line.strip_prefix("# "))
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| {
            let stem = path
                .rsplit('/')
                .next()
                .unwrap_or(path)
                .trim_end_matches(".md");
            prettify_title(stem)
        })
}

fn markdown_summary(content: &str) -> String {
    let mut collected = Vec::new();
    let mut in_code_block = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
            continue;
        }
        if in_code_block
            || trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with('-')
            || trimmed.starts_with('*')
        {
            if !collected.is_empty() {
                break;
            }
            continue;
        }
        collected.push(trimmed);
        if collected.len() >= 3 {
            break;
        }
    }
    let summary = collected.join(" ");
    if summary.len() > 220 {
        format!("{}…", summary[..219].trim_end())
    } else {
        summary
    }
}

fn markdown_headings(content: &str, limit: usize) -> Vec<String> {
    let mut headings = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            let heading = trimmed.trim_start_matches('#').trim();
            if !heading.is_empty() {
                headings.push(heading.to_string());
                if headings.len() >= limit {
                    break;
                }
            }
        }
    }
    headings
}

fn document_tags(path: &str, title: &str, summary: &str) -> Vec<String> {
    let haystack = format!("{} {} {}", path, title, summary).to_ascii_lowercase();
    let mut tags = Vec::new();
    if path.starts_with("runbooks/") {
        tags.push("runbooks".to_string());
    } else {
        tags.push("guides".to_string());
    }
    if haystack.contains("deploy") || haystack.contains("install") || haystack.contains("upgrade") {
        tags.push("deployment".to_string());
    }
    if haystack.contains("sdk")
        || haystack.contains("openapi")
        || haystack.contains("graphql")
        || haystack.contains("api")
    {
        tags.push("api".to_string());
    }
    if haystack.contains("runbook") {
        tags.push("operations".to_string());
    }
    tags.sort();
    tags.dedup();
    tags
}

fn document_section(path: &str, tags: &[String]) -> String {
    if path.starts_with("runbooks/") {
        "runbooks".to_string()
    } else if tags.iter().any(|tag| tag == "deployment") {
        "deployment".to_string()
    } else if tags.iter().any(|tag| tag == "api") {
        "api".to_string()
    } else {
        "guides".to_string()
    }
}

fn document_kind(path: &str) -> String {
    if path.starts_with("runbooks/") {
        "runbook".to_string()
    } else if path.ends_with("README.md") {
        "index".to_string()
    } else {
        "guide".to_string()
    }
}

fn document_matches_section(entry: &DocumentEntry, section: &str) -> bool {
    match section {
        "all" | "" => true,
        "runbooks" => entry.path.starts_with("runbooks/"),
        "deployment" => entry.tags.iter().any(|tag| tag == "deployment"),
        "api" => entry.tags.iter().any(|tag| tag == "api"),
        "guides" => !entry.path.starts_with("runbooks/"),
        other => entry.section == other || entry.tags.iter().any(|tag| tag == other),
    }
}

fn document_match_score(entry: &DocumentEntry, query: &str, content: &str) -> Option<usize> {
    let terms = query
        .split_whitespace()
        .map(|term| term.to_ascii_lowercase())
        .filter(|term| !term.is_empty())
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return Some(0);
    }

    let title = entry.title.to_ascii_lowercase();
    let path = entry.path.to_ascii_lowercase();
    let summary = entry.summary.to_ascii_lowercase();
    let headings = entry.headings.join(" ").to_ascii_lowercase();
    let content = content.to_ascii_lowercase();
    let mut score = 0;
    for term in terms {
        let mut matched = false;
        if title.contains(&term) {
            matched = true;
            score += 6;
        }
        if path.contains(&term) {
            matched = true;
            score += 4;
        }
        if summary.contains(&term) {
            matched = true;
            score += 3;
        }
        if headings.contains(&term) {
            matched = true;
            score += 2;
        }
        if content.contains(&term) {
            matched = true;
            score += 1;
        }
        if !matched {
            return None;
        }
    }
    Some(score)
}

fn collect_markdown_files(dir: &Dir<'_>, out: &mut Vec<(String, String)>) {
    for file in dir.files() {
        let path = normalize_path(&file.path().to_string_lossy());
        if !path.ends_with(".md") {
            continue;
        }
        let Some(content) = std::str::from_utf8(file.contents()).ok() else {
            continue;
        };
        out.push((path, content.to_string()));
    }
    for child in dir.dirs() {
        collect_markdown_files(child, out);
    }
}

fn build_document_entry(path: &str, content: &str, query: &str) -> Option<DocumentEntry> {
    let title = markdown_title(content, path);
    let summary = markdown_summary(content);
    let headings = markdown_headings(content, 6);
    let tags = document_tags(path, &title, &summary);
    let section = document_section(path, &tags);
    let kind = document_kind(path);
    let mut entry = DocumentEntry {
        path: path.to_string(),
        title,
        section,
        kind,
        tags,
        summary,
        headings,
        score: 0,
    };
    entry.score = document_match_score(&entry, query, content)?;
    Some(entry)
}

fn normalized_release_version(version: &str) -> &str {
    version.strip_suffix("-local").unwrap_or(version)
}

fn load_typescript_sdk() -> Option<SdkParityEntry> {
    let package: serde_json::Value = serde_json::from_str(TYPESCRIPT_SDK_PACKAGE).ok()?;
    Some(SdkParityEntry {
        package: package.get("name")?.as_str()?.to_string(),
        version: package.get("version")?.as_str()?.to_string(),
        aligned: false,
    })
}

fn load_python_sdk() -> Option<SdkParityEntry> {
    let project: toml::Value = toml::from_str(PYTHON_SDK_PROJECT).ok()?;
    let project = project.get("project")?;
    Some(SdkParityEntry {
        package: project.get("name")?.as_str()?.to_string(),
        version: project.get("version")?.as_str()?.to_string(),
        aligned: false,
    })
}

fn format_operation(method: &str, path: &str) -> String {
    format!("{method} {path}")
}

fn runtime_openapi_operations(openapi_value: &serde_json::Value) -> BTreeSet<(String, String)> {
    let mut operations = BTreeSet::new();
    let Some(paths) = openapi_value
        .get("paths")
        .and_then(serde_json::Value::as_object)
    else {
        return operations;
    };

    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        for method in ["get", "post", "put", "delete", "patch"] {
            if item.contains_key(method) {
                operations.insert((method.to_ascii_uppercase(), path.to_string()));
            }
        }
    }

    operations
}

fn docs_openapi_operations(source: &str) -> BTreeSet<(String, String)> {
    let mut operations = BTreeSet::new();
    let mut current_path: Option<String> = None;

    for line in source.lines() {
        if let Some(path) = line
            .strip_prefix("  ")
            .and_then(|value| value.strip_suffix(':'))
            .filter(|value| value.starts_with("/api/"))
        {
            current_path = Some(path.to_string());
            continue;
        }
        if !line.starts_with(' ') && !line.is_empty() {
            current_path = None;
            continue;
        }
        let Some(method) = line
            .strip_prefix("    ")
            .and_then(|value| value.strip_suffix(':'))
            .filter(|value| matches!(*value, "get" | "post" | "put" | "delete" | "patch"))
        else {
            continue;
        };
        let Some(path) = current_path.as_ref() else {
            continue;
        };
        operations.insert((method.to_ascii_uppercase(), path.clone()));
    }

    operations
}

fn report_operation_coverage(inventory: &BTreeSet<(String, String)>) -> (Vec<String>, Vec<String>) {
    let mut present = Vec::new();
    let mut missing = Vec::new();

    for (method, path) in REQUIRED_REPORT_WORKFLOW_OPERATIONS {
        let operation = format_operation(method, path);
        if inventory.contains(&(method.to_string(), path.to_string())) {
            present.push(operation);
        } else {
            missing.push(operation);
        }
    }

    (present, missing)
}

fn report_endpoint_coverage(source: &str) -> (Vec<String>, Vec<String>) {
    let mut present = Vec::new();
    let mut missing = Vec::new();

    for endpoint in REQUIRED_REPORT_WORKFLOW_ENDPOINTS {
        if source.contains(endpoint) {
            present.push(endpoint.to_string());
        } else {
            missing.push(endpoint.to_string());
        }
    }

    (present, missing)
}

pub fn docs_index(
    version: &str,
    query: Option<&str>,
    section: Option<&str>,
    limit: usize,
) -> serde_json::Value {
    let mut files = Vec::new();
    collect_markdown_files(&EMBEDDED_DOCS, &mut files);
    let query = query.unwrap_or("").trim();
    let section = section.unwrap_or("all").trim();
    let limit = limit.clamp(1, 100);
    let mut items = files
        .iter()
        .filter_map(|(path, content)| build_document_entry(path, content, query))
        .filter(|entry| document_matches_section(entry, section))
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then(left.section.cmp(&right.section))
            .then(left.title.cmp(&right.title))
    });
    let total = items.len();
    items.truncate(limit);
    serde_json::json!({
        "version": version,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "query": query,
        "section": section,
        "total": total,
        "items": items,
    })
}

pub fn doc_content(version: &str, path: &str) -> Option<serde_json::Value> {
    if path.is_empty() || path.contains("..") || !path.ends_with(".md") {
        return None;
    }
    let normalized = normalize_path(path);
    let file = EMBEDDED_DOCS.get_file(&normalized)?;
    let content = std::str::from_utf8(file.contents()).ok()?;
    let title = markdown_title(content, &normalized);
    let summary = markdown_summary(content);
    let headings = markdown_headings(content, 10);
    let tags = document_tags(&normalized, &title, &summary);
    let section = document_section(&normalized, &tags);
    Some(serde_json::json!({
        "version": version,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "path": normalized,
        "title": title,
        "section": section,
        "kind": document_kind(path),
        "tags": tags,
        "summary": summary,
        "headings": headings,
        "content": content,
    }))
}

pub fn support_parity(version: &str) -> serde_json::Value {
    let release_version = normalized_release_version(version).to_string();
    let openapi_json = crate::openapi::openapi_json(version);
    let openapi_value: serde_json::Value =
        serde_json::from_str(&openapi_json).unwrap_or_else(|_| serde_json::json!({}));
    let openapi_version = openapi_value
        .pointer("/info/version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(version)
        .to_string();
    let openapi_path_count = openapi_value
        .get("paths")
        .and_then(serde_json::Value::as_object)
        .map(|paths| paths.len())
        .unwrap_or(0);
    let runtime_openapi_inventory = runtime_openapi_operations(&openapi_value);
    let endpoint_catalog = crate::openapi::endpoint_catalog(version);
    let graphql_schema = crate::graphql::wardex_schema();
    let query_fields = graphql_schema
        .types
        .iter()
        .find(|ty| ty.name == graphql_schema.query_type)
        .map(|ty| {
            ty.fields
                .iter()
                .map(|field| field.name.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut python_sdk = load_python_sdk().unwrap_or_else(|| SdkParityEntry {
        package: "wardex".to_string(),
        version: "unknown".to_string(),
        aligned: false,
    });
    python_sdk.aligned = python_sdk.version == release_version;
    let mut typescript_sdk = load_typescript_sdk().unwrap_or_else(|| SdkParityEntry {
        package: "@wardex/sdk".to_string(),
        version: "unknown".to_string(),
        aligned: false,
    });
    typescript_sdk.aligned = typescript_sdk.version == release_version;

    let graphql_documented = openapi_value
        .get("paths")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|paths| paths.contains_key("/api/graphql"));

    let runtime_route_inventory = endpoint_catalog
        .iter()
        .map(|entry| (entry.method.to_ascii_uppercase(), entry.path.clone()))
        .collect::<BTreeSet<_>>();
    let docs_openapi_inventory = docs_openapi_operations(OPENAPI_DOCS_SNAPSHOT);
    let (runtime_routes_present, runtime_routes_missing) =
        report_operation_coverage(&runtime_route_inventory);
    let (runtime_openapi_present, runtime_openapi_missing) =
        report_operation_coverage(&runtime_openapi_inventory);
    let (docs_openapi_present, docs_openapi_missing) =
        report_operation_coverage(&docs_openapi_inventory);
    let (typescript_sdk_present, typescript_sdk_missing) =
        report_endpoint_coverage(TYPESCRIPT_SDK_CLIENT);
    let (python_sdk_present, python_sdk_missing) = report_endpoint_coverage(PYTHON_SDK_CLIENT);
    let report_workflow_aligned = runtime_routes_missing.is_empty()
        && runtime_openapi_missing.is_empty()
        && docs_openapi_missing.is_empty()
        && typescript_sdk_missing.is_empty()
        && python_sdk_missing.is_empty();

    let mut issues = Vec::new();
    if openapi_version != version {
        issues.push(format!(
            "OpenAPI schema version {openapi_version} differs from runtime version {version}."
        ));
    }
    if !python_sdk.aligned {
        issues.push(format!(
            "Python SDK version {} differs from runtime release {}.",
            python_sdk.version, release_version
        ));
    }
    if !typescript_sdk.aligned {
        issues.push(format!(
            "TypeScript SDK version {} differs from runtime release {}.",
            typescript_sdk.version, release_version
        ));
    }
    if !graphql_documented {
        issues.push("/api/graphql is not described in the runtime OpenAPI schema.".to_string());
    }
    if !runtime_routes_missing.is_empty() {
        issues.push(format!(
            "Report workflow missing from runtime endpoint catalog: {}.",
            runtime_routes_missing.join(", ")
        ));
    }
    if !runtime_openapi_missing.is_empty() {
        issues.push(format!(
            "Report workflow missing from runtime OpenAPI schema: {}.",
            runtime_openapi_missing.join(", ")
        ));
    }
    if !docs_openapi_missing.is_empty() {
        issues.push(format!(
            "Report workflow missing from docs/openapi.yaml: {}.",
            docs_openapi_missing.join(", ")
        ));
    }
    if !typescript_sdk_missing.is_empty() {
        issues.push(format!(
            "Report workflow missing from TypeScript SDK client: {}.",
            typescript_sdk_missing.join(", ")
        ));
    }
    if !python_sdk_missing.is_empty() {
        issues.push(format!(
            "Report workflow missing from Python SDK client: {}.",
            python_sdk_missing.join(", ")
        ));
    }

    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "runtime": {
            "version": version,
            "release_version": release_version,
            "docs_version": version,
        },
        "rest": {
            "openapi_version": openapi_version,
            "openapi_path_count": openapi_path_count,
            "endpoint_catalog_count": endpoint_catalog.len(),
            "authenticated_endpoints": endpoint_catalog.iter().filter(|entry| entry.auth).count(),
            "public_endpoints": endpoint_catalog.iter().filter(|entry| !entry.auth).count(),
        },
        "graphql": {
            "documented": graphql_documented,
            "query_type": graphql_schema.query_type,
            "types": graphql_schema.types.len(),
            "root_fields": query_fields,
            "supports_introspection": true,
        },
        "sdk": {
            "python": python_sdk,
            "typescript": typescript_sdk,
        },
        "report_workflow": {
            "aligned": report_workflow_aligned,
            "required_operations": REQUIRED_REPORT_WORKFLOW_OPERATIONS
                .iter()
                .map(|(method, path)| format_operation(method, path))
                .collect::<Vec<_>>(),
            "required_sdk_endpoints": REQUIRED_REPORT_WORKFLOW_ENDPOINTS,
            "runtime_routes": {
                "present": runtime_routes_present,
                "missing": runtime_routes_missing,
            },
            "runtime_openapi": {
                "present": runtime_openapi_present,
                "missing": runtime_openapi_missing,
            },
            "docs_openapi": {
                "present": docs_openapi_present,
                "missing": docs_openapi_missing,
            },
            "typescript_sdk": {
                "present": typescript_sdk_present,
                "missing": typescript_sdk_missing,
            },
            "python_sdk": {
                "present": python_sdk_present,
                "missing": python_sdk_missing,
            },
        },
        "issues": issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_index_filters_query_and_section() {
        let payload = docs_index("0.53.1-local", Some("deployment"), Some("runbooks"), 20);
        let items = payload["items"].as_array().unwrap();
        assert!(!items.is_empty());
        assert!(items.iter().all(|item| {
            item["path"]
                .as_str()
                .unwrap_or_default()
                .starts_with("runbooks/")
        }));
        assert!(items.iter().any(|item| {
            item["path"]
                .as_str()
                .unwrap_or_default()
                .contains("deployment")
        }));
    }

    #[test]
    fn doc_content_returns_embedded_markdown() {
        let payload = doc_content("0.53.1-local", "runbooks/deployment.md").unwrap();
        assert_eq!(payload["path"], "runbooks/deployment.md");
        assert!(payload["title"].as_str().unwrap().contains("Deployment"));
        assert!(payload["content"].as_str().unwrap().contains("Runbook"));
    }

    #[test]
    fn support_parity_reports_sdk_versions_and_graphql() {
        let payload = support_parity("0.53.1-local");
        let python_sdk = load_python_sdk().unwrap();
        let typescript_sdk = load_typescript_sdk().unwrap();

        assert_eq!(payload["runtime"]["version"], "0.53.1-local");
        assert_eq!(payload["sdk"]["python"]["version"], python_sdk.version);
        assert_eq!(
            payload["sdk"]["typescript"]["version"],
            typescript_sdk.version
        );
        assert!(!payload["sdk"]["python"]["aligned"].as_bool().unwrap());
        assert!(!payload["sdk"]["typescript"]["aligned"].as_bool().unwrap());
        assert!(payload["graphql"]["documented"].as_bool().unwrap());
        assert!(payload["report_workflow"]["aligned"].as_bool().unwrap());
        assert!(
            payload["report_workflow"]["runtime_routes"]["missing"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            payload["report_workflow"]["runtime_openapi"]["missing"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            payload["report_workflow"]["docs_openapi"]["missing"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            payload["report_workflow"]["typescript_sdk"]["missing"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            payload["report_workflow"]["python_sdk"]["missing"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            payload["report_workflow"]["required_operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry.as_str() == Some("POST /api/report-runs"))
        );
        assert!(payload["issues"].as_array().unwrap().iter().any(|issue| {
            issue
                .as_str()
                .unwrap_or_default()
                .contains("TypeScript SDK version")
        }));
    }
}

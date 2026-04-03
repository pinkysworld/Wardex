// ── Sigma Rule Library ────────────────────────────────────────────────────────
//
// Loads, parses, and matches Sigma-format detection rules from YAML files.
// Ships with 50+ built-in rules covering authentication, network, endpoint,
// IoT/OT, cloud, and supply-chain categories.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ── Sigma Rule ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub logsource: LogSource,
    #[serde(default)]
    pub detection: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub falsepositives: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogSource {
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub service: String,
}

// ── Rule Library ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SigmaLibrary {
    rules: Vec<SigmaRule>,
}

impl SigmaLibrary {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Load all .yml files from a directory (supports multi-document YAML separated by ---).
    pub fn load_directory(&mut self, dir: &str) -> Result<usize, String> {
        let path = Path::new(dir);
        if !path.is_dir() {
            return Err(format!("{} is not a directory", dir));
        }

        let mut count = 0;
        let entries = std::fs::read_dir(path).map_err(|e| e.to_string())?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "yml" || e == "yaml") {
                let content = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
                count += self.load_yaml(&content)?;
            }
        }
        Ok(count)
    }

    /// Parse multi-document YAML text (--- separated).
    pub fn load_yaml(&mut self, yaml_text: &str) -> Result<usize, String> {
        let mut count = 0;
        // Split on document separator
        let docs: Vec<&str> = yaml_text.split("\n---").collect();
        for doc in docs {
            let trimmed = doc.trim();
            if trimmed.is_empty() {
                continue;
            }
            match self.parse_sigma_yaml(trimmed) {
                Ok(rule) => {
                    self.rules.push(rule);
                    count += 1;
                }
                Err(_) => continue, // Skip malformed documents
            }
        }
        Ok(count)
    }

    fn parse_sigma_yaml(&self, text: &str) -> Result<SigmaRule, String> {
        // Minimal YAML parser for Sigma-format rules
        let mut rule = SigmaRule {
            title: String::new(),
            id: String::new(),
            status: String::new(),
            level: String::new(),
            description: String::new(),
            author: String::new(),
            date: String::new(),
            tags: Vec::new(),
            logsource: LogSource::default(),
            detection: HashMap::new(),
            falsepositives: Vec::new(),
        };

        let mut section = "";
        let mut logsource_section = false;
        let mut detection_section = false;
        let mut detection_key = String::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Top-level keys
            if !line.starts_with(' ') && !line.starts_with('\t') {
                logsource_section = false;
                detection_section = false;

                if let Some(val) = trimmed.strip_prefix("title:") {
                    rule.title = val.trim().to_string();
                    section = "title";
                } else if let Some(val) = trimmed.strip_prefix("id:") {
                    rule.id = val.trim().to_string();
                    section = "id";
                } else if let Some(val) = trimmed.strip_prefix("status:") {
                    rule.status = val.trim().to_string();
                    section = "status";
                } else if let Some(val) = trimmed.strip_prefix("level:") {
                    rule.level = val.trim().to_string();
                    section = "level";
                } else if let Some(val) = trimmed.strip_prefix("description:") {
                    rule.description = val.trim().to_string();
                    section = "description";
                } else if let Some(val) = trimmed.strip_prefix("author:") {
                    rule.author = val.trim().to_string();
                    section = "author";
                } else if let Some(val) = trimmed.strip_prefix("date:") {
                    rule.date = val.trim().to_string();
                    section = "date";
                } else if trimmed == "tags:" {
                    section = "tags";
                } else if trimmed == "logsource:" {
                    section = "logsource";
                    logsource_section = true;
                } else if trimmed == "detection:" {
                    section = "detection";
                    detection_section = true;
                } else if trimmed == "falsepositives:" {
                    section = "falsepositives";
                }
                continue;
            }

            // Indented content
            match section {
                "tags" => {
                    if let Some(tag) = trimmed.strip_prefix("- ") {
                        rule.tags.push(tag.trim().to_string());
                    }
                }
                "falsepositives" => {
                    if let Some(fp) = trimmed.strip_prefix("- ") {
                        rule.falsepositives.push(fp.trim().to_string());
                    }
                }
                "logsource" if logsource_section => {
                    if let Some(val) = trimmed.strip_prefix("category:") {
                        rule.logsource.category = val.trim().to_string();
                    } else if let Some(val) = trimmed.strip_prefix("product:") {
                        rule.logsource.product = val.trim().to_string();
                    } else if let Some(val) = trimmed.strip_prefix("service:") {
                        rule.logsource.service = val.trim().to_string();
                    }
                }
                "detection" if detection_section => {
                    // Detect sub-sections and key-value pairs
                    let indent_level = line.len() - line.trim_start().len();
                    if indent_level == 2 {
                        if let Some((key, val)) = trimmed.split_once(':') {
                            let val = val.trim();
                            detection_key = key.trim().to_string();
                            if !val.is_empty() {
                                rule.detection.insert(
                                    detection_key.clone(),
                                    serde_json::Value::String(val.to_string()),
                                );
                            }
                        }
                    } else if indent_level >= 4 {
                        // Nested detection field
                        let full_key = format!("{}.{}", detection_key, trimmed.trim_start_matches("- ").split(':').next().unwrap_or("").trim());
                        if let Some(val) = trimmed.split_once(':').map(|(_, v)| v.trim().to_string()) {
                            if !val.is_empty() {
                                rule.detection.insert(full_key, serde_json::Value::String(val));
                            }
                        } else if let Some(item) = trimmed.strip_prefix("- ") {
                            rule.detection
                                .entry(detection_key.clone())
                                .and_modify(|v| {
                                    if let serde_json::Value::Array(arr) = v {
                                        arr.push(serde_json::Value::String(item.to_string()));
                                    }
                                })
                                .or_insert_with(|| serde_json::json!([item]));
                        }
                    }
                }
                _ => {}
            }
        }

        if rule.id.is_empty() && rule.title.is_empty() {
            return Err("Not a valid Sigma rule".into());
        }

        Ok(rule)
    }

    // ── Query API ────────────────────────────────────────────────────────

    pub fn rules(&self) -> &[SigmaRule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn find_by_id(&self, id: &str) -> Option<&SigmaRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn find_by_tag(&self, tag: &str) -> Vec<&SigmaRule> {
        self.rules.iter().filter(|r| r.tags.iter().any(|t| t == tag)).collect()
    }

    pub fn find_by_level(&self, level: &str) -> Vec<&SigmaRule> {
        self.rules.iter().filter(|r| r.level == level).collect()
    }

    pub fn find_by_category(&self, category: &str) -> Vec<&SigmaRule> {
        self.rules.iter().filter(|r| r.logsource.category == category).collect()
    }

    pub fn categories(&self) -> Vec<String> {
        let mut cats: Vec<String> = self.rules.iter()
            .map(|r| r.logsource.category.clone())
            .filter(|c| !c.is_empty())
            .collect();
        cats.sort();
        cats.dedup();
        cats
    }

    pub fn summary(&self) -> SigmaLibrarySummary {
        let mut by_level: HashMap<String, usize> = HashMap::new();
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut by_status: HashMap<String, usize> = HashMap::new();

        for rule in &self.rules {
            *by_level.entry(rule.level.clone()).or_default() += 1;
            *by_category.entry(rule.logsource.category.clone()).or_default() += 1;
            *by_status.entry(rule.status.clone()).or_default() += 1;
        }

        SigmaLibrarySummary {
            total: self.rules.len(),
            by_level,
            by_category,
            by_status,
        }
    }

    /// Simple event matching: checks if an event JSON matches any rule's detection selection.
    pub fn match_event(&self, event: &serde_json::Value) -> Vec<&SigmaRule> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if self.event_matches_rule(event, rule) {
                matches.push(rule);
            }
        }
        matches
    }

    fn event_matches_rule(&self, event: &serde_json::Value, rule: &SigmaRule) -> bool {
        // Match selection fields from detection
        if let Some(selection) = rule.detection.get("selection") {
            if let serde_json::Value::Object(sel_map) = selection {
                for (key, expected) in sel_map {
                    let actual = event.get(key);
                    match actual {
                        Some(val) if val == expected => continue,
                        _ => return false,
                    }
                }
                return true;
            }
        }

        // Check simple key-value detection matches
        for (key, expected) in &rule.detection {
            if key == "condition" || key == "timeframe" {
                continue;
            }
            if let Some(val) = event.get(key) {
                if val == expected {
                    return true;
                }
            }
        }

        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaLibrarySummary {
    pub total: usize,
    pub by_level: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub by_status: HashMap<String, usize>,
}

// ── Built-in rules ───────────────────────────────────────────────────────────

pub fn builtin_rules_dir() -> &'static str {
    "rules/sigma"
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r#"
title: Test Rule Alpha
id: test-001
status: stable
level: high
description: A test rule.
author: Test
date: 2025/01/01
tags:
  - attack.t1110
  - wardex.test
logsource:
  category: authentication
  product: wardex
detection:
  selection:
    event_type: auth_failure
  condition: selection | count() > 5
  timeframe: 5m
falsepositives:
  - Test scenario
---
title: Test Rule Beta
id: test-002
status: experimental
level: medium
description: Another test rule.
author: Test
date: 2025/01/01
tags:
  - wardex.test
logsource:
  category: network
  product: wardex
detection:
  selection:
    event_type: connection
  condition: selection
falsepositives:
  - Normal traffic
"#;

    #[test]
    fn parse_multi_document_yaml() {
        let mut lib = SigmaLibrary::new();
        let count = lib.load_yaml(SAMPLE_YAML).unwrap();
        assert_eq!(count, 2);
        assert_eq!(lib.len(), 2);
    }

    #[test]
    fn find_by_id() {
        let mut lib = SigmaLibrary::new();
        lib.load_yaml(SAMPLE_YAML).unwrap();
        let rule = lib.find_by_id("test-001").unwrap();
        assert_eq!(rule.title, "Test Rule Alpha");
        assert_eq!(rule.level, "high");
    }

    #[test]
    fn find_by_tag() {
        let mut lib = SigmaLibrary::new();
        lib.load_yaml(SAMPLE_YAML).unwrap();
        let rules = lib.find_by_tag("attack.t1110");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test-001");
    }

    #[test]
    fn find_by_level() {
        let mut lib = SigmaLibrary::new();
        lib.load_yaml(SAMPLE_YAML).unwrap();
        assert_eq!(lib.find_by_level("high").len(), 1);
        assert_eq!(lib.find_by_level("medium").len(), 1);
    }

    #[test]
    fn find_by_category() {
        let mut lib = SigmaLibrary::new();
        lib.load_yaml(SAMPLE_YAML).unwrap();
        assert_eq!(lib.find_by_category("authentication").len(), 1);
        assert_eq!(lib.find_by_category("network").len(), 1);
    }

    #[test]
    fn categories() {
        let mut lib = SigmaLibrary::new();
        lib.load_yaml(SAMPLE_YAML).unwrap();
        let cats = lib.categories();
        assert!(cats.contains(&"authentication".to_string()));
        assert!(cats.contains(&"network".to_string()));
    }

    #[test]
    fn summary() {
        let mut lib = SigmaLibrary::new();
        lib.load_yaml(SAMPLE_YAML).unwrap();
        let summary = lib.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.by_level.get("high"), Some(&1));
        assert_eq!(summary.by_status.get("stable"), Some(&1));
        assert_eq!(summary.by_status.get("experimental"), Some(&1));
    }

    #[test]
    fn logsource_parsed() {
        let mut lib = SigmaLibrary::new();
        lib.load_yaml(SAMPLE_YAML).unwrap();
        let rule = lib.find_by_id("test-001").unwrap();
        assert_eq!(rule.logsource.category, "authentication");
        assert_eq!(rule.logsource.product, "wardex");
    }

    #[test]
    fn tags_parsed() {
        let mut lib = SigmaLibrary::new();
        lib.load_yaml(SAMPLE_YAML).unwrap();
        let rule = lib.find_by_id("test-001").unwrap();
        assert_eq!(rule.tags.len(), 2);
        assert!(rule.tags.contains(&"attack.t1110".to_string()));
    }

    #[test]
    fn falsepositives_parsed() {
        let mut lib = SigmaLibrary::new();
        lib.load_yaml(SAMPLE_YAML).unwrap();
        let rule = lib.find_by_id("test-001").unwrap();
        assert_eq!(rule.falsepositives, vec!["Test scenario"]);
    }

    #[test]
    fn empty_library() {
        let lib = SigmaLibrary::new();
        assert!(lib.is_empty());
        assert_eq!(lib.len(), 0);
    }
}

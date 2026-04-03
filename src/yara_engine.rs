//! Built-in YARA-style pattern matching engine.
//!
//! Provides a lightweight rule language for matching byte patterns
//! and string signatures in files or memory buffers — without requiring
//! the native libyara C library.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Rule model ───────────────────────────────────────────────────────

/// A YARA-style detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub meta: RuleMeta,
    pub strings: Vec<RuleString>,
    pub condition: RuleCondition,
    pub enabled: bool,
}

/// Rule metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMeta {
    pub author: String,
    pub description: String,
    pub severity: String,
    pub mitre_ids: Vec<String>,
    pub created: String,
}

/// A string/byte pattern to search for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleString {
    pub id: String,
    pub pattern: StringPattern,
    pub nocase: bool,
}

/// Pattern variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringPattern {
    /// Plain text match.
    Text(String),
    /// Hex byte sequence (e.g., "4D 5A 90 00").
    Hex(Vec<u8>),
    /// Simple regex-like glob (supports * and ?).
    Glob(String),
}

/// Match condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    /// All strings must match.
    AllOf,
    /// Any one string must match.
    AnyOf,
    /// At least N strings must match.
    AtLeast(usize),
    /// File size must be below limit AND all strings match.
    AllOfWithMaxSize(u64),
}

/// A single match location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchLocation {
    pub string_id: String,
    pub offset: usize,
    pub length: usize,
    pub matched_bytes: Vec<u8>,
}

/// Result of scanning a buffer against a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub rule_name: String,
    pub matched: bool,
    pub severity: String,
    pub locations: Vec<MatchLocation>,
    pub scan_time_us: u64,
}

/// Result of scanning a buffer against all rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub total_rules: usize,
    pub matched_rules: usize,
    pub results: Vec<ScanResult>,
    pub total_scan_time_us: u64,
}

// ── Engine ───────────────────────────────────────────────────────────

/// The YARA scanning engine.
#[derive(Debug)]
pub struct YaraEngine {
    rules: Vec<YaraRule>,
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Load a rule.
    pub fn add_rule(&mut self, rule: YaraRule) {
        self.rules.push(rule);
    }

    /// Load multiple rules from a JSON string.
    pub fn load_rules_json(&mut self, json: &str) -> Result<usize, String> {
        let rules: Vec<YaraRule> =
            serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
        let count = rules.len();
        self.rules.extend(rules);
        Ok(count)
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan a byte buffer against all enabled rules.
    pub fn scan(&self, data: &[u8]) -> ScanReport {
        let start = std::time::Instant::now();
        let mut results = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            let r = self.evaluate_rule(rule, data);
            results.push(r);
        }

        let matched_rules = results.iter().filter(|r| r.matched).count();
        ScanReport {
            total_rules: self.rules.iter().filter(|r| r.enabled).count(),
            matched_rules,
            results,
            total_scan_time_us: start.elapsed().as_micros() as u64,
        }
    }

    /// Scan a file by path.
    pub fn scan_file(&self, path: &str) -> Result<ScanReport, String> {
        let data =
            std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        Ok(self.scan(&data))
    }

    /// Get names of all loaded rules.
    pub fn rule_names(&self) -> Vec<String> {
        self.rules.iter().map(|r| r.name.clone()).collect()
    }

    /// Remove a rule by name.
    pub fn remove_rule(&mut self, name: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.name != name);
        self.rules.len() < before
    }

    // ── Internal matching ────────────────────────────────────────────

    fn evaluate_rule(&self, rule: &YaraRule, data: &[u8]) -> ScanResult {
        let start = std::time::Instant::now();

        // Size check for AllOfWithMaxSize.
        if let RuleCondition::AllOfWithMaxSize(max) = &rule.condition {
            if data.len() as u64 > *max {
                return ScanResult {
                    rule_name: rule.name.clone(),
                    matched: false,
                    severity: rule.meta.severity.clone(),
                    locations: Vec::new(),
                    scan_time_us: start.elapsed().as_micros() as u64,
                };
            }
        }

        let mut all_locations: HashMap<String, Vec<MatchLocation>> = HashMap::new();

        for rs in &rule.strings {
            let locs = self.find_pattern(rs, data);
            all_locations.insert(rs.id.clone(), locs);
        }

        let matched_count = all_locations.values().filter(|v| !v.is_empty()).count();
        let total_strings = rule.strings.len();

        let matched = match &rule.condition {
            RuleCondition::AllOf | RuleCondition::AllOfWithMaxSize(_) => {
                matched_count == total_strings && total_strings > 0
            }
            RuleCondition::AnyOf => matched_count > 0,
            RuleCondition::AtLeast(n) => matched_count >= *n,
        };

        let locations: Vec<MatchLocation> =
            all_locations.into_values().flatten().collect();

        ScanResult {
            rule_name: rule.name.clone(),
            matched,
            severity: rule.meta.severity.clone(),
            locations,
            scan_time_us: start.elapsed().as_micros() as u64,
        }
    }

    fn find_pattern(&self, rs: &RuleString, data: &[u8]) -> Vec<MatchLocation> {
        match &rs.pattern {
            StringPattern::Text(text) => {
                self.find_text(data, text.as_bytes(), &rs.id, rs.nocase)
            }
            StringPattern::Hex(bytes) => {
                self.find_bytes(data, bytes, &rs.id)
            }
            StringPattern::Glob(pattern) => {
                self.find_glob(data, pattern, &rs.id, rs.nocase)
            }
        }
    }

    fn find_text(
        &self,
        data: &[u8],
        needle: &[u8],
        id: &str,
        nocase: bool,
    ) -> Vec<MatchLocation> {
        if needle.is_empty() {
            return Vec::new();
        }

        let haystack: Vec<u8> = if nocase {
            data.iter().map(|b| b.to_ascii_lowercase()).collect()
        } else {
            data.to_vec()
        };
        let needle_norm: Vec<u8> = if nocase {
            needle.iter().map(|b| b.to_ascii_lowercase()).collect()
        } else {
            needle.to_vec()
        };

        let mut results = Vec::new();
        let mut offset = 0;
        while offset + needle_norm.len() <= haystack.len() {
            if haystack[offset..offset + needle_norm.len()] == needle_norm[..] {
                results.push(MatchLocation {
                    string_id: id.to_string(),
                    offset,
                    length: needle_norm.len(),
                    matched_bytes: data[offset..offset + needle_norm.len()].to_vec(),
                });
            }
            offset += 1;
        }
        results
    }

    fn find_bytes(
        &self,
        data: &[u8],
        needle: &[u8],
        id: &str,
    ) -> Vec<MatchLocation> {
        self.find_text(data, needle, id, false)
    }

    fn find_glob(
        &self,
        data: &[u8],
        pattern: &str,
        id: &str,
        nocase: bool,
    ) -> Vec<MatchLocation> {
        // Split data into lines and match each line against the glob.
        let text = String::from_utf8_lossy(data);
        let mut results = Vec::new();
        let mut offset = 0;

        for line in text.split('\n') {
            if glob_match(pattern, line, nocase) {
                results.push(MatchLocation {
                    string_id: id.to_string(),
                    offset,
                    length: line.len(),
                    matched_bytes: line.as_bytes().to_vec(),
                });
            }
            offset += line.len() + 1; // +1 for the newline
        }
        results
    }
}

/// Simple glob matcher supporting `*` (any chars) and `?` (one char).
fn glob_match(pattern: &str, text: &str, nocase: bool) -> bool {
    let pat = if nocase {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };
    let txt = if nocase {
        text.to_lowercase()
    } else {
        text.to_string()
    };

    let pat_chars: Vec<char> = pat.chars().collect();
    let txt_chars: Vec<char> = txt.chars().collect();
    let (plen, tlen) = (pat_chars.len(), txt_chars.len());

    // DP match.
    let mut dp = vec![vec![false; tlen + 1]; plen + 1];
    dp[0][0] = true;

    // Leading *'s can match empty.
    for i in 1..=plen {
        if pat_chars[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=plen {
        for j in 1..=tlen {
            if pat_chars[i - 1] == '*' {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            } else if pat_chars[i - 1] == '?' || pat_chars[i - 1] == txt_chars[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }

    dp[plen][tlen]
}

// ── Built-in rules ──────────────────────────────────────────────────

/// Load a set of default detection rules for common threats.
pub fn builtin_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "suspicious_elf_packed".into(),
            meta: RuleMeta {
                author: "Wardex".into(),
                description: "Detects UPX-packed ELF binaries".into(),
                severity: "Severe".into(),
                mitre_ids: vec!["T1027.002".into()],
                created: "2026-01-01".into(),
            },
            strings: vec![
                RuleString {
                    id: "$elf_magic".into(),
                    pattern: StringPattern::Hex(vec![0x7f, 0x45, 0x4c, 0x46]),
                    nocase: false,
                },
                RuleString {
                    id: "$upx_sig".into(),
                    pattern: StringPattern::Text("UPX!".into()),
                    nocase: false,
                },
            ],
            condition: RuleCondition::AllOf,
            enabled: true,
        },
        YaraRule {
            name: "webshell_php".into(),
            meta: RuleMeta {
                author: "Wardex".into(),
                description: "Detects common PHP web shell patterns".into(),
                severity: "Critical".into(),
                mitre_ids: vec!["T1505.003".into()],
                created: "2026-01-01".into(),
            },
            strings: vec![
                RuleString {
                    id: "$eval".into(),
                    pattern: StringPattern::Text("eval($_".into()),
                    nocase: true,
                },
                RuleString {
                    id: "$base64".into(),
                    pattern: StringPattern::Text("base64_decode".into()),
                    nocase: true,
                },
                RuleString {
                    id: "$system".into(),
                    pattern: StringPattern::Text("system($_".into()),
                    nocase: true,
                },
            ],
            condition: RuleCondition::AnyOf,
            enabled: true,
        },
        YaraRule {
            name: "cryptominer_strings".into(),
            meta: RuleMeta {
                author: "Wardex".into(),
                description: "Detects cryptocurrency miner indicators".into(),
                severity: "Severe".into(),
                mitre_ids: vec!["T1496".into()],
                created: "2026-01-01".into(),
            },
            strings: vec![
                RuleString {
                    id: "$stratum".into(),
                    pattern: StringPattern::Text("stratum+tcp://".into()),
                    nocase: true,
                },
                RuleString {
                    id: "$xmrig".into(),
                    pattern: StringPattern::Text("xmrig".into()),
                    nocase: true,
                },
                RuleString {
                    id: "$pool".into(),
                    pattern: StringPattern::Glob("*pool.*:*".into()),
                    nocase: true,
                },
            ],
            condition: RuleCondition::AnyOf,
            enabled: true,
        },
        YaraRule {
            name: "ransomware_note".into(),
            meta: RuleMeta {
                author: "Wardex".into(),
                description: "Detects ransomware note patterns".into(),
                severity: "Critical".into(),
                mitre_ids: vec!["T1486".into()],
                created: "2026-01-01".into(),
            },
            strings: vec![
                RuleString {
                    id: "$bitcoin".into(),
                    pattern: StringPattern::Text("bitcoin".into()),
                    nocase: true,
                },
                RuleString {
                    id: "$decrypt".into(),
                    pattern: StringPattern::Text("decrypt your files".into()),
                    nocase: true,
                },
                RuleString {
                    id: "$payment".into(),
                    pattern: StringPattern::Text("payment".into()),
                    nocase: true,
                },
            ],
            condition: RuleCondition::AtLeast(2),
            enabled: true,
        },
    ]
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_pattern_match() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "test_text".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Elevated".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
            },
            strings: vec![RuleString {
                id: "$s1".into(),
                pattern: StringPattern::Text("malware".into()),
                nocase: false,
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
        });

        let report = engine.scan(b"this contains malware inside");
        assert_eq!(report.matched_rules, 1);
        assert!(report.results[0].matched);
        assert_eq!(report.results[0].locations[0].offset, 14);
    }

    #[test]
    fn nocase_match() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "nocase_test".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Elevated".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
            },
            strings: vec![RuleString {
                id: "$s1".into(),
                pattern: StringPattern::Text("eval".into()),
                nocase: true,
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
        });

        let report = engine.scan(b"EVAL(code);");
        assert_eq!(report.matched_rules, 1);
    }

    #[test]
    fn hex_pattern_match() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "elf_header".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Elevated".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
            },
            strings: vec![RuleString {
                id: "$elf".into(),
                pattern: StringPattern::Hex(vec![0x7f, 0x45, 0x4c, 0x46]),
                nocase: false,
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
        });

        let mut data = vec![0x7f, 0x45, 0x4c, 0x46];
        data.extend_from_slice(&[0x00; 100]);
        let report = engine.scan(&data);
        assert!(report.results[0].matched);
    }

    #[test]
    fn all_of_condition() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "multi_match".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Severe".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
            },
            strings: vec![
                RuleString {
                    id: "$a".into(),
                    pattern: StringPattern::Text("alpha".into()),
                    nocase: false,
                },
                RuleString {
                    id: "$b".into(),
                    pattern: StringPattern::Text("beta".into()),
                    nocase: false,
                },
            ],
            condition: RuleCondition::AllOf,
            enabled: true,
        });

        // Only one present → no match
        let report = engine.scan(b"just alpha here");
        assert!(!report.results[0].matched);

        // Both present → match
        let report = engine.scan(b"alpha and beta together");
        assert!(report.results[0].matched);
    }

    #[test]
    fn at_least_condition() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "at_least2".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Severe".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
            },
            strings: vec![
                RuleString { id: "$a".into(), pattern: StringPattern::Text("one".into()), nocase: false },
                RuleString { id: "$b".into(), pattern: StringPattern::Text("two".into()), nocase: false },
                RuleString { id: "$c".into(), pattern: StringPattern::Text("three".into()), nocase: false },
            ],
            condition: RuleCondition::AtLeast(2),
            enabled: true,
        });

        let report = engine.scan(b"just one here");
        assert!(!report.results[0].matched);

        let report = engine.scan(b"one and two here");
        assert!(report.results[0].matched);
    }

    #[test]
    fn glob_pattern_match() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "glob_test".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Elevated".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
            },
            strings: vec![RuleString {
                id: "$g".into(),
                pattern: StringPattern::Glob("*pool.*:*".into()),
                nocase: true,
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
        });

        let report = engine.scan(b"connecting to mining-pool.example:3333\n");
        assert!(report.results[0].matched);
    }

    #[test]
    fn disabled_rule_skipped() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "disabled".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Elevated".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
            },
            strings: vec![RuleString {
                id: "$s".into(),
                pattern: StringPattern::Text("match-me".into()),
                nocase: false,
            }],
            condition: RuleCondition::AnyOf,
            enabled: false,
        });

        let report = engine.scan(b"match-me");
        assert_eq!(report.total_rules, 0);
        assert_eq!(report.matched_rules, 0);
    }

    #[test]
    fn builtin_rules_load() {
        let mut engine = YaraEngine::new();
        for r in builtin_rules() {
            engine.add_rule(r);
        }
        assert_eq!(engine.rule_count(), 4);
    }

    #[test]
    fn builtin_webshell_detects_eval() {
        let mut engine = YaraEngine::new();
        for r in builtin_rules() {
            engine.add_rule(r);
        }

        let php = b"<?php eval($_POST['cmd']); ?>";
        let report = engine.scan(php);
        let ws = report.results.iter().find(|r| r.rule_name == "webshell_php");
        assert!(ws.unwrap().matched);
    }

    #[test]
    fn builtin_ransomware_needs_two() {
        let mut engine = YaraEngine::new();
        for r in builtin_rules() {
            engine.add_rule(r);
        }

        // Only one keyword → should not match (requires AtLeast(2))
        let report = engine.scan(b"send bitcoin please");
        let rr = report.results.iter().find(|r| r.rule_name == "ransomware_note");
        assert!(!rr.unwrap().matched);

        // Two keywords → match
        let report = engine.scan(b"send bitcoin to decrypt your files");
        let rr = report.results.iter().find(|r| r.rule_name == "ransomware_note");
        assert!(rr.unwrap().matched);
    }

    #[test]
    fn remove_rule_works() {
        let mut engine = YaraEngine::new();
        for r in builtin_rules() {
            engine.add_rule(r);
        }
        assert!(engine.remove_rule("webshell_php"));
        assert_eq!(engine.rule_count(), 3);
        assert!(!engine.remove_rule("nonexistent"));
    }

    #[test]
    fn load_rules_from_json() {
        let mut engine = YaraEngine::new();
        let json = serde_json::to_string(&builtin_rules()).unwrap();
        let count = engine.load_rules_json(&json).unwrap();
        assert_eq!(count, 4);
        assert_eq!(engine.rule_count(), 4);
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("hello*", "hello world", false));
        assert!(glob_match("*world", "hello world", false));
        assert!(!glob_match("hello*", "HeLLo world", false));
        assert!(glob_match("hello*", "HeLLo world", true));
        assert!(glob_match("h?llo", "hello", false));
        assert!(!glob_match("h?llo", "heello", false));
    }

    #[test]
    fn max_size_condition() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "small_only".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Elevated".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
            },
            strings: vec![RuleString {
                id: "$s".into(),
                pattern: StringPattern::Text("x".into()),
                nocase: false,
            }],
            condition: RuleCondition::AllOfWithMaxSize(10),
            enabled: true,
        });

        // Within size limit → match
        let report = engine.scan(b"x");
        assert!(report.results[0].matched);

        // Exceeds size limit → no match
        let report = engine.scan(&vec![b'x'; 100]);
        assert!(!report.results[0].matched);
    }
}

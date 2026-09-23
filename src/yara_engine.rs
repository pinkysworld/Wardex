//! Built-in YARA-style pattern matching engine.
//!
//! Provides a rule language for matching byte patterns and string
//! signatures in files or memory buffers — without requiring the native
//! libyara C library. Rules can be authored either as JSON (the original,
//! still-supported format) or as genuine `.yar` source compiled by
//! [`crate::yara_parser`] for the documented subset described in
//! `docs/YARA_COMPATIBILITY.md`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

// ── Rule model ───────────────────────────────────────────────────────

/// A YARA-style detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub meta: RuleMeta,
    pub strings: Vec<RuleString>,
    pub condition: RuleCondition,
    pub enabled: bool,
    /// Tags declared as `rule name : tag1 tag2 { ... }`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// `private rule` — excluded from scan reports but still evaluated so
    /// other rules' conditions can reference it by name.
    #[serde(default)]
    pub is_private: bool,
    /// `global rule` — parsed and recorded, but Wardex does not implement
    /// YARA's "AND'd into every rule" global-rule semantics; a global rule
    /// behaves like an ordinary named rule that other conditions can
    /// reference explicitly.
    #[serde(default)]
    pub is_global: bool,
}

/// Rule metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleMeta {
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub mitre_ids: Vec<String>,
    #[serde(default)]
    pub created: String,
    /// Arbitrary `meta:` key/value pairs from `.yar` source that do not map
    /// to one of the fixed fields above (real YARA meta values are
    /// unstructured `identifier = value` pairs).
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A string/byte pattern to search for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleString {
    pub id: String,
    pub pattern: StringPattern,
    #[serde(default)]
    pub nocase: bool,
    /// Match the pattern encoded as UTF-16LE ("wide") bytes.
    #[serde(default)]
    pub wide: bool,
    /// Match the pattern as raw ASCII/UTF-8 bytes. Defaults to `true`; only
    /// set to `false` when a `.yar` string declares `wide` without `ascii`
    /// (YARA then matches wide-only).
    #[serde(default = "default_ascii_modifier")]
    pub ascii: bool,
    /// Require the match to be bounded by non-alphanumeric bytes (or the
    /// buffer edges) on both sides.
    #[serde(default)]
    pub fullword: bool,
}

fn default_ascii_modifier() -> bool {
    true
}

impl Default for RuleString {
    fn default() -> Self {
        Self {
            id: String::new(),
            pattern: StringPattern::Text(String::new()),
            nocase: false,
            wide: false,
            ascii: true,
            fullword: false,
        }
    }
}

/// Pattern variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringPattern {
    /// Plain text match.
    Text(String),
    /// Hex byte sequence (e.g., "4D 5A 90 00") — a legacy, exact-bytes-only
    /// form kept for JSON backward compatibility. New hex strings compiled
    /// from `.yar` source (which may contain `??`, nibble wildcards, `[n-m]`
    /// jumps, and `( .. | .. )` alternatives) use [`StringPattern::HexTokens`].
    Hex(Vec<u8>),
    /// Simple glob (supports `*` and `?`), matched per line.
    Glob(String),
    /// Compiled hex string: a sequence of tokens that may include
    /// wildcards, nibble wildcards, jumps, and alternatives.
    HexTokens(Vec<HexToken>),
    /// A regular expression string (`/pattern/` in `.yar` source), matched
    /// with the `regex` crate's bytes API.
    Regex {
        source: String,
        case_insensitive: bool,
        dotall: bool,
    },
}

/// One token of a compiled hex string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HexToken {
    /// A fixed byte, e.g. `4D`.
    Byte(u8),
    /// `??` — any byte.
    Wildcard,
    /// `A?` — high nibble fixed, low nibble any.
    HighNibble(u8),
    /// `?A` — low nibble fixed, high nibble any.
    LowNibble(u8),
    /// `[n]` or `[n-m]` or `[n-]` — skip a variable number of bytes.
    /// `[n-]` is represented as `(n, None)`, meaning "n or more" up to a
    /// bounded scan limit applied by the matcher.
    Jump(usize, Option<usize>),
    /// `( AA BB | CC DD )` — one of several alternative token sequences.
    Alternative(Vec<Vec<HexToken>>),
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
    /// A genuine YARA boolean condition expression, compiled from `.yar`
    /// source — see [`crate::yara_parser`] and `docs/YARA_COMPATIBILITY.md`.
    Expr(BoolExpr),
}

// ── Condition expression AST (compiled from `.yar` `condition:` blocks) ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    fn apply(self, lhs: i64, rhs: i64) -> bool {
        match self {
            CmpOp::Eq => lhs == rhs,
            CmpOp::Ne => lhs != rhs,
            CmpOp::Lt => lhs < rhs,
            CmpOp::Le => lhs <= rhs,
            CmpOp::Gt => lhs > rhs,
            CmpOp::Ge => lhs >= rhs,
        }
    }
}

/// An integer-valued expression (`filesize`, `#a`, `@a[i]`, `uint32(off)`, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NumExpr {
    Int(i64),
    FileSize,
    /// `#id` — number of matches of a string.
    Count(String),
    /// `@id[index]` — offset of the `index`-th (1-based) match.
    OffsetOf(String, Box<NumExpr>),
    /// `uintN`/`uintNbe(offset)` — read `width` bytes (1/2/4) at `offset`.
    UintAt {
        width: u8,
        big_endian: bool,
        offset: Box<NumExpr>,
    },
    Add(Box<NumExpr>, Box<NumExpr>),
    Sub(Box<NumExpr>, Box<NumExpr>),
}

/// A quantifier for `<quantifier> of <string-set>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OfQuantifier {
    All,
    Any,
    Exactly(Box<NumExpr>),
}

/// The set of strings a `of` expression ranges over.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringSet {
    /// `them` — every string declared in the rule.
    Them,
    /// An explicit list, which may include `$prefix*` wildcard entries.
    Ids(Vec<String>),
}

/// A boolean-valued condition expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BoolExpr {
    Bool(bool),
    /// `$id` — the string matched at least once.
    StringRef(String),
    Not(Box<BoolExpr>),
    And(Box<BoolExpr>, Box<BoolExpr>),
    Or(Box<BoolExpr>, Box<BoolExpr>),
    Cmp(NumExpr, CmpOp, NumExpr),
    /// `$id at N`.
    StringAt(String, Box<NumExpr>),
    /// `$id in (N..M)`.
    StringInRange(String, Box<NumExpr>, Box<NumExpr>),
    OfThem(OfQuantifier, StringSet),
    /// A bare identifier referencing another rule, true iff that rule matched.
    RuleRef(String),
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

    /// Compile and load rules from genuine `.yar` source (see
    /// [`crate::yara_parser`] and `docs/YARA_COMPATIBILITY.md` for the
    /// supported subset). Returns the number of rules loaded and any
    /// non-fatal warnings (e.g. ignored imports); a malformed or
    /// unsupported construct is a hard error with line/column, never a
    /// silently-mismatched rule.
    pub fn load_rules_yar(
        &mut self,
        source: &str,
    ) -> Result<(usize, Vec<String>), crate::yara_parser::CompileError> {
        let compiled = crate::yara_parser::compile(source)?;
        let count = compiled.rules.len();
        self.rules.extend(compiled.rules);
        Ok((count, compiled.warnings))
    }

    /// Compile and load a `.yar` file by path.
    pub fn load_rules_yar_file(&mut self, path: &str) -> Result<(usize, Vec<String>), String> {
        let source = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let source = String::from_utf8_lossy(&source);
        self.load_rules_yar(&source)
            .map_err(|e| format!("{path}: {e}"))
    }

    /// Load every `.yar`/`.yara` rule file in a directory (non-recursive).
    /// JSON rule files are intentionally left to whatever loader already
    /// handles them (e.g. the community malware pack) so this does not
    /// double-load rules from a directory that mixes both formats. Returns
    /// the total number of rules loaded and any warnings; a single bad file
    /// is reported but does not stop the rest from loading.
    pub fn load_rules_dir(&mut self, dir: &str) -> (usize, Vec<String>) {
        let mut total = 0usize;
        let mut messages = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return (0, messages);
        };
        let mut paths: Vec<std::path::PathBuf> = entries
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .collect();
        paths.sort();
        for path in paths {
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if ext != "yar" && ext != "yara" {
                continue;
            }
            let path_str = path.to_string_lossy().to_string();
            match self.load_rules_yar_file(&path_str) {
                Ok((n, warnings)) => {
                    total += n;
                    messages.extend(warnings);
                }
                Err(e) => messages.push(format!("error loading {path_str}: {e}")),
            }
        }
        (total, messages)
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan a byte buffer against all enabled rules. Rules are evaluated in
    /// load order so a rule's condition may reference an earlier rule by
    /// name; `private` rules are evaluated (so later rules can reference
    /// them) but excluded from the returned results, matching YARA's
    /// behaviour.
    pub fn scan(&self, data: &[u8]) -> ScanReport {
        let start = std::time::Instant::now();
        let mut results = Vec::new();
        let mut rule_results: HashMap<String, bool> = HashMap::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            let r = self.evaluate_rule(rule, data, &rule_results);
            rule_results.insert(rule.name.clone(), r.matched);
            if !rule.is_private {
                results.push(r);
            }
        }

        let matched_rules = results.iter().filter(|r| r.matched).count();
        ScanReport {
            total_rules: self
                .rules
                .iter()
                .filter(|r| r.enabled && !r.is_private)
                .count(),
            matched_rules,
            results,
            total_scan_time_us: start.elapsed().as_micros() as u64,
        }
    }

    /// Scan a file by path.
    pub fn scan_file(&self, path: &str) -> Result<ScanReport, String> {
        let data = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
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

    fn evaluate_rule(
        &self,
        rule: &YaraRule,
        data: &[u8],
        rule_results: &HashMap<String, bool>,
    ) -> ScanResult {
        let start = std::time::Instant::now();

        // Size check for AllOfWithMaxSize.
        if let RuleCondition::AllOfWithMaxSize(max) = &rule.condition
            && data.len() as u64 > *max
        {
            return ScanResult {
                rule_name: rule.name.clone(),
                matched: false,
                severity: rule.meta.severity.clone(),
                locations: Vec::new(),
                scan_time_us: start.elapsed().as_micros() as u64,
            };
        }

        let mut all_locations: HashMap<String, Vec<MatchLocation>> = HashMap::new();

        for rs in &rule.strings {
            let locs = self.find_pattern(rs, data);
            all_locations.insert(rs.id.clone(), locs);
        }

        let matched = match &rule.condition {
            RuleCondition::AllOf | RuleCondition::AllOfWithMaxSize(_) => {
                let matched_count = all_locations.values().filter(|v| !v.is_empty()).count();
                matched_count == rule.strings.len() && !rule.strings.is_empty()
            }
            RuleCondition::AnyOf => all_locations.values().any(|v| !v.is_empty()),
            RuleCondition::AtLeast(n) => {
                all_locations.values().filter(|v| !v.is_empty()).count() >= *n
            }
            RuleCondition::Expr(expr) => {
                let ctx = ExprContext {
                    data,
                    locations: &all_locations,
                    strings: &rule.strings,
                    rule_results,
                };
                expr.eval(&ctx)
            }
        };

        let locations: Vec<MatchLocation> = all_locations.into_values().flatten().collect();

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
            StringPattern::Text(text) => find_text_modifiers(data, text, &rs.id, rs),
            StringPattern::Hex(bytes) => self.find_bytes(data, bytes, &rs.id),
            StringPattern::Glob(pattern) => self.find_glob(data, pattern, &rs.id, rs.nocase),
            StringPattern::HexTokens(tokens) => find_hex_tokens(data, tokens, &rs.id),
            StringPattern::Regex {
                source,
                case_insensitive,
                dotall,
            } => find_regex(data, source, *case_insensitive, *dotall, &rs.id),
        }
    }

    fn find_bytes(&self, data: &[u8], needle: &[u8], id: &str) -> Vec<MatchLocation> {
        find_text_bytes(data, needle, id, false)
    }

    fn find_glob(&self, data: &[u8], pattern: &str, id: &str, nocase: bool) -> Vec<MatchLocation> {
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

// ── Text / hex-token / regex matching ─────────────────────────────────

/// Exact-bytes substring search (used by the legacy [`StringPattern::Hex`]
/// form and as the ASCII/wide primitive below).
fn find_text_bytes(data: &[u8], needle: &[u8], id: &str, nocase: bool) -> Vec<MatchLocation> {
    if needle.is_empty() {
        return Vec::new();
    }
    let haystack: Vec<u8> = if nocase {
        data.iter().map(u8::to_ascii_lowercase).collect()
    } else {
        data.to_vec()
    };
    let needle_norm: Vec<u8> = if nocase {
        needle.iter().map(u8::to_ascii_lowercase).collect()
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

/// A byte is a "word" byte for `fullword` boundary checks if it is
/// alphanumeric or `_`, matching YARA's definition.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn fullword_ok(data: &[u8], offset: usize, length: usize) -> bool {
    let before_ok = offset == 0 || !is_word_byte(data[offset - 1]);
    let after_ok = offset + length >= data.len() || !is_word_byte(data[offset + length]);
    before_ok && after_ok
}

/// Encode a text string as UTF-16LE bytes (ASCII-range text is
/// representative of the common `wide` use case: matching a narrow string
/// as it appears inside a UTF-16LE-encoded buffer).
fn to_utf16le_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Find a [`StringPattern::Text`] applying its `nocase`/`wide`/`ascii`/
/// `fullword` modifiers.
fn find_text_modifiers(data: &[u8], text: &str, id: &str, rs: &RuleString) -> Vec<MatchLocation> {
    let mut results = Vec::new();
    if rs.ascii {
        for loc in find_text_bytes(data, text.as_bytes(), id, rs.nocase) {
            if !rs.fullword || fullword_ok(data, loc.offset, loc.length) {
                results.push(loc);
            }
        }
    }
    if rs.wide {
        let wide_needle = to_utf16le_bytes(text);
        for loc in find_text_bytes(data, &wide_needle, id, rs.nocase) {
            if !rs.fullword || fullword_ok(data, loc.offset, loc.length) {
                results.push(loc);
            }
        }
    }
    results
}

/// Advance a *set* of reachable data positions through a hex-token
/// sequence, Thompson-NFA style, instead of recursively backtracking
/// through every combination of alternative/jump choices.
///
/// A naive recursive backtracker (the previous implementation) explores
/// the cross product of every alternative and jump choice: ~100
/// sequential `( AA | AB )` groups — well within the hex-body length cap
/// — yield roughly 2^100 paths per scan start offset, hanging the scan on
/// an uploaded rule. Here, alternatives take the *union* of each branch's
/// resulting position set instead of trying each branch's full
/// continuation separately, and a jump expands each position into a
/// bounded range of positions. Because the position set is deduplicated
/// (via `BTreeSet`), its size never exceeds `data.len() + 1` no matter how
/// many alternatives or jumps the pattern has, so the total cost of
/// matching one token sequence from one start position is
/// O(pattern_len * data.len()) rather than exponential.
fn hex_run(tokens: &[HexToken], data: &[u8], starts: BTreeSet<usize>) -> BTreeSet<usize> {
    let mut current = starts;
    for token in tokens {
        if current.is_empty() {
            return current;
        }
        current = match token {
            HexToken::Byte(b) => current
                .into_iter()
                .filter(|&p| data.get(p) == Some(b))
                .map(|p| p + 1)
                .collect(),
            HexToken::Wildcard => current
                .into_iter()
                .filter(|&p| p < data.len())
                .map(|p| p + 1)
                .collect(),
            HexToken::HighNibble(hi) => current
                .into_iter()
                .filter(|&p| data.get(p).is_some_and(|b| (b >> 4) == *hi))
                .map(|p| p + 1)
                .collect(),
            HexToken::LowNibble(lo) => current
                .into_iter()
                .filter(|&p| data.get(p).is_some_and(|b| (b & 0x0F) == *lo))
                .map(|p| p + 1)
                .collect(),
            HexToken::Jump(min, max) => {
                // Bound unbounded jumps ([n-]) to avoid pathological scans
                // (and, combined with the hex-body length cap in
                // `yara_parser`, pathological cost too).
                const MAX_JUMP: usize = 512;
                let mut next = BTreeSet::new();
                for p in current {
                    let hi = max.unwrap_or(MAX_JUMP).min(data.len().saturating_sub(p));
                    if hi < *min {
                        continue;
                    }
                    for skip in *min..=hi {
                        next.insert(p + skip);
                    }
                }
                next
            }
            HexToken::Alternative(branches) => {
                let mut next = BTreeSet::new();
                for branch in branches {
                    next.extend(hex_run(branch, data, current.clone()));
                }
                next
            }
        };
    }
    current
}

/// Try to match a hex-token sequence starting exactly at `data[pos]`.
/// Returns the shortest matching end offset (exclusive) on success. See
/// [`hex_run`] for why this is a bounded set simulation rather than a
/// recursive backtracker.
fn hex_match_at(tokens: &[HexToken], data: &[u8], pos: usize) -> Option<usize> {
    let mut starts = BTreeSet::new();
    starts.insert(pos);
    hex_run(tokens, data, starts).into_iter().next()
}

fn find_hex_tokens(data: &[u8], tokens: &[HexToken], id: &str) -> Vec<MatchLocation> {
    let mut results = Vec::new();
    for start in 0..=data.len() {
        if let Some(end) = hex_match_at(tokens, data, start) {
            results.push(MatchLocation {
                string_id: id.to_string(),
                offset: start,
                length: end - start,
                matched_bytes: data[start..end].to_vec(),
            });
        }
    }
    results
}

fn find_regex(
    data: &[u8],
    source: &str,
    case_insensitive: bool,
    dotall: bool,
    id: &str,
) -> Vec<MatchLocation> {
    let mut builder = regex::bytes::RegexBuilder::new(source);
    builder
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(dotall);
    let Ok(re) = builder.build() else {
        // Compile-time validation (see `yara_parser`) should already have
        // rejected an invalid pattern; fail closed (no matches) if not.
        return Vec::new();
    };
    re.find_iter(data)
        .map(|m| MatchLocation {
            string_id: id.to_string(),
            offset: m.start(),
            length: m.end() - m.start(),
            matched_bytes: data[m.start()..m.end()].to_vec(),
        })
        .collect()
}

// ── Condition expression evaluation ───────────────────────────────────

struct ExprContext<'a> {
    data: &'a [u8],
    locations: &'a HashMap<String, Vec<MatchLocation>>,
    strings: &'a [RuleString],
    rule_results: &'a HashMap<String, bool>,
}

impl ExprContext<'_> {
    fn resolve_set(&self, set: &StringSet) -> Vec<String> {
        match set {
            StringSet::Them => self.strings.iter().map(|s| s.id.clone()).collect(),
            StringSet::Ids(ids) => {
                let mut resolved = Vec::new();
                for id in ids {
                    if let Some(prefix) = id.strip_suffix('*') {
                        for s in self.strings {
                            if s.id.starts_with(prefix) {
                                resolved.push(s.id.clone());
                            }
                        }
                    } else {
                        resolved.push(id.clone());
                    }
                }
                resolved
            }
        }
    }
}

impl NumExpr {
    fn eval(&self, ctx: &ExprContext) -> Option<i64> {
        match self {
            NumExpr::Int(v) => Some(*v),
            NumExpr::FileSize => Some(ctx.data.len() as i64),
            NumExpr::Count(id) => Some(ctx.locations.get(id).map_or(0, Vec::len) as i64),
            NumExpr::OffsetOf(id, index) => {
                let idx = index.eval(ctx)?;
                if idx < 1 {
                    return None;
                }
                ctx.locations
                    .get(id)
                    .and_then(|locs| locs.get((idx - 1) as usize))
                    .map(|loc| loc.offset as i64)
            }
            NumExpr::UintAt {
                width,
                big_endian,
                offset,
            } => {
                let off = offset.eval(ctx)?;
                if off < 0 {
                    return None;
                }
                let off = off as usize;
                let n = *width as usize;
                let bytes = ctx.data.get(off..off + n)?;
                Some(if *big_endian {
                    match n {
                        1 => bytes[0] as i64,
                        2 => u16::from_be_bytes([bytes[0], bytes[1]]) as i64,
                        _ => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
                    }
                } else {
                    match n {
                        1 => bytes[0] as i64,
                        2 => u16::from_le_bytes([bytes[0], bytes[1]]) as i64,
                        _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
                    }
                })
            }
            NumExpr::Add(a, b) => Some(a.eval(ctx)? + b.eval(ctx)?),
            NumExpr::Sub(a, b) => Some(a.eval(ctx)? - b.eval(ctx)?),
        }
    }
}

impl BoolExpr {
    fn eval(&self, ctx: &ExprContext) -> bool {
        match self {
            BoolExpr::Bool(b) => *b,
            BoolExpr::StringRef(id) => ctx.locations.get(id).is_some_and(|v| !v.is_empty()),
            BoolExpr::Not(inner) => !inner.eval(ctx),
            BoolExpr::And(a, b) => a.eval(ctx) && b.eval(ctx),
            BoolExpr::Or(a, b) => a.eval(ctx) || b.eval(ctx),
            BoolExpr::Cmp(lhs, op, rhs) => match (lhs.eval(ctx), rhs.eval(ctx)) {
                (Some(l), Some(r)) => op.apply(l, r),
                _ => false,
            },
            BoolExpr::StringAt(id, offset) => {
                let Some(target) = offset.eval(ctx) else {
                    return false;
                };
                ctx.locations
                    .get(id)
                    .is_some_and(|locs| locs.iter().any(|loc| loc.offset as i64 == target))
            }
            BoolExpr::StringInRange(id, lo, hi) => {
                let (Some(lo), Some(hi)) = (lo.eval(ctx), hi.eval(ctx)) else {
                    return false;
                };
                ctx.locations.get(id).is_some_and(|locs| {
                    locs.iter()
                        .any(|loc| (loc.offset as i64) >= lo && (loc.offset as i64) <= hi)
                })
            }
            BoolExpr::OfThem(quantifier, set) => {
                let ids = ctx.resolve_set(set);
                let matched = ids
                    .iter()
                    .filter(|id| ctx.locations.get(*id).is_some_and(|v| !v.is_empty()))
                    .count();
                match quantifier {
                    OfQuantifier::All => !ids.is_empty() && matched == ids.len(),
                    OfQuantifier::Any => matched >= 1,
                    OfQuantifier::Exactly(n) => {
                        n.eval(ctx).is_some_and(|need| matched as i64 >= need)
                    }
                }
            }
            BoolExpr::RuleRef(name) => ctx.rule_results.get(name).copied().unwrap_or(false),
        }
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
                ..Default::default()
            },
            strings: vec![
                RuleString {
                    id: "$elf_magic".into(),
                    pattern: StringPattern::Hex(vec![0x7f, 0x45, 0x4c, 0x46]),
                    nocase: false,
                    ..Default::default()
                },
                RuleString {
                    id: "$upx_sig".into(),
                    pattern: StringPattern::Text("UPX!".into()),
                    nocase: false,
                    ..Default::default()
                },
            ],
            condition: RuleCondition::AllOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
        },
        YaraRule {
            name: "webshell_php".into(),
            meta: RuleMeta {
                author: "Wardex".into(),
                description: "Detects common PHP web shell patterns".into(),
                severity: "Critical".into(),
                mitre_ids: vec!["T1505.003".into()],
                created: "2026-01-01".into(),
                ..Default::default()
            },
            strings: vec![
                RuleString {
                    id: "$eval".into(),
                    pattern: StringPattern::Text("eval($_".into()),
                    nocase: true,
                    ..Default::default()
                },
                RuleString {
                    id: "$base64".into(),
                    pattern: StringPattern::Text("base64_decode".into()),
                    nocase: true,
                    ..Default::default()
                },
                RuleString {
                    id: "$system".into(),
                    pattern: StringPattern::Text("system($_".into()),
                    nocase: true,
                    ..Default::default()
                },
            ],
            condition: RuleCondition::AnyOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
        },
        YaraRule {
            name: "cryptominer_strings".into(),
            meta: RuleMeta {
                author: "Wardex".into(),
                description: "Detects cryptocurrency miner indicators".into(),
                severity: "Severe".into(),
                mitre_ids: vec!["T1496".into()],
                created: "2026-01-01".into(),
                ..Default::default()
            },
            strings: vec![
                RuleString {
                    id: "$stratum".into(),
                    pattern: StringPattern::Text("stratum+tcp://".into()),
                    nocase: true,
                    ..Default::default()
                },
                RuleString {
                    id: "$xmrig".into(),
                    pattern: StringPattern::Text("xmrig".into()),
                    nocase: true,
                    ..Default::default()
                },
                RuleString {
                    id: "$pool".into(),
                    pattern: StringPattern::Glob("*pool.*:*".into()),
                    nocase: true,
                    ..Default::default()
                },
            ],
            condition: RuleCondition::AnyOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
        },
        YaraRule {
            name: "ransomware_note".into(),
            meta: RuleMeta {
                author: "Wardex".into(),
                description: "Detects ransomware note patterns".into(),
                severity: "Critical".into(),
                mitre_ids: vec!["T1486".into()],
                created: "2026-01-01".into(),
                ..Default::default()
            },
            strings: vec![
                RuleString {
                    id: "$bitcoin".into(),
                    pattern: StringPattern::Text("bitcoin".into()),
                    nocase: true,
                    ..Default::default()
                },
                RuleString {
                    id: "$decrypt".into(),
                    pattern: StringPattern::Text("decrypt your files".into()),
                    nocase: true,
                    ..Default::default()
                },
                RuleString {
                    id: "$payment".into(),
                    pattern: StringPattern::Text("payment".into()),
                    nocase: true,
                    ..Default::default()
                },
            ],
            condition: RuleCondition::AtLeast(2),
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
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
                ..Default::default()
            },
            strings: vec![RuleString {
                id: "$s1".into(),
                pattern: StringPattern::Text("malware".into()),
                nocase: false,
                ..Default::default()
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
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
                ..Default::default()
            },
            strings: vec![RuleString {
                id: "$s1".into(),
                pattern: StringPattern::Text("eval".into()),
                nocase: true,
                ..Default::default()
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
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
                ..Default::default()
            },
            strings: vec![RuleString {
                id: "$elf".into(),
                pattern: StringPattern::Hex(vec![0x7f, 0x45, 0x4c, 0x46]),
                nocase: false,
                ..Default::default()
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
        });

        let mut data = vec![0x7f, 0x45, 0x4c, 0x46];
        data.extend_from_slice(&[0x00; 100]);
        let report = engine.scan(&data);
        assert!(report.results[0].matched);
    }

    /// A regression test for the hex-alternative DoS: a naive recursive
    /// backtracker exploring every `(AA|AB)` choice independently would
    /// take ~2^100 paths per start offset for a pattern built from 100
    /// sequential two-way alternatives. The bounded set-simulation matcher
    /// must instead run in time roughly linear in pattern length * data
    /// length, so this completes quickly rather than hanging the scan.
    #[test]
    fn hex_many_sequential_alternatives_does_not_hang() {
        // ( AA | AB ) repeated 100 times, i.e. 2^100 naive backtracking
        // paths per start offset.
        let mut tokens = Vec::new();
        for _ in 0..100 {
            tokens.push(HexToken::Alternative(vec![
                vec![HexToken::Byte(0xAA)],
                vec![HexToken::Byte(0xAB)],
            ]));
        }

        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "many_alts".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Elevated".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
                ..Default::default()
            },
            strings: vec![RuleString {
                id: "$a".into(),
                pattern: StringPattern::HexTokens(tokens),
                nocase: false,
                ..Default::default()
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
        });

        // Every position taken is 0xAA — matches every branch of every
        // alternative, so this also exercises the "no match" path where
        // the byte doesn't match on top of the alternation.
        let data = vec![0xAAu8; 100];
        let start = std::time::Instant::now();
        let report = engine.scan(&data);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "hex alternative scan took too long: {:?}",
            start.elapsed()
        );
        assert!(report.results[0].matched);

        // Data too short to satisfy the pattern at all: must terminate
        // quickly and report no match rather than hang.
        let short_data = vec![0xAAu8; 10];
        let start = std::time::Instant::now();
        let report = engine.scan(&short_data);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "hex alternative non-match scan took too long: {:?}",
            start.elapsed()
        );
        assert!(!report.results[0].matched);
    }

    #[test]
    fn hex_alternative_matches_either_branch() {
        // { ( AA BB | CC DD ) } — direct HexToken construction, matching
        // the parser-level test in yara_parser.rs but exercised here at
        // the engine level.
        let tokens = vec![HexToken::Alternative(vec![
            vec![HexToken::Byte(0xAA), HexToken::Byte(0xBB)],
            vec![HexToken::Byte(0xCC), HexToken::Byte(0xDD)],
        ])];

        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "alt_either".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Elevated".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
                ..Default::default()
            },
            strings: vec![RuleString {
                id: "$a".into(),
                pattern: StringPattern::HexTokens(tokens),
                nocase: false,
                ..Default::default()
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
        });

        assert!(engine.scan(&[0xAA, 0xBB]).results[0].matched);
        assert!(engine.scan(&[0xCC, 0xDD]).results[0].matched);
        assert!(!engine.scan(&[0x11, 0x22]).results[0].matched);
    }

    #[test]
    fn hex_jump_and_alternative_combined() {
        // { AA [1-3] ( BB | CC ) DD } — jump followed by an alternative
        // followed by a fixed byte, checking the position-set simulation
        // correctly threads jumps through alternation.
        let tokens = vec![
            HexToken::Byte(0xAA),
            HexToken::Jump(1, Some(3)),
            HexToken::Alternative(vec![vec![HexToken::Byte(0xBB)], vec![HexToken::Byte(0xCC)]]),
            HexToken::Byte(0xDD),
        ];

        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "jump_alt".into(),
            meta: RuleMeta {
                author: "test".into(),
                description: "test".into(),
                severity: "Elevated".into(),
                mitre_ids: vec![],
                created: "2026-01-01".into(),
                ..Default::default()
            },
            strings: vec![RuleString {
                id: "$a".into(),
                pattern: StringPattern::HexTokens(tokens),
                nocase: false,
                ..Default::default()
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
        });

        // AA, jump 1, BB, DD → matches (jump of exactly 1).
        assert!(engine.scan(&[0xAA, 0x00, 0xBB, 0xDD]).results[0].matched);
        // AA, jump 2, CC, DD → matches.
        assert!(engine.scan(&[0xAA, 0x00, 0x00, 0xCC, 0xDD]).results[0].matched);
        // Jump of 0 is below the minimum of 1 → no match.
        assert!(!engine.scan(&[0xAA, 0xBB, 0xDD]).results[0].matched);
        // Neither BB nor CC after the jump → no match.
        assert!(!engine.scan(&[0xAA, 0x00, 0x11, 0xDD]).results[0].matched);
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
                ..Default::default()
            },
            strings: vec![
                RuleString {
                    id: "$a".into(),
                    pattern: StringPattern::Text("alpha".into()),
                    nocase: false,
                    ..Default::default()
                },
                RuleString {
                    id: "$b".into(),
                    pattern: StringPattern::Text("beta".into()),
                    nocase: false,
                    ..Default::default()
                },
            ],
            condition: RuleCondition::AllOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
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
                ..Default::default()
            },
            strings: vec![
                RuleString {
                    id: "$a".into(),
                    pattern: StringPattern::Text("one".into()),
                    nocase: false,
                    ..Default::default()
                },
                RuleString {
                    id: "$b".into(),
                    pattern: StringPattern::Text("two".into()),
                    nocase: false,
                    ..Default::default()
                },
                RuleString {
                    id: "$c".into(),
                    pattern: StringPattern::Text("three".into()),
                    nocase: false,
                    ..Default::default()
                },
            ],
            condition: RuleCondition::AtLeast(2),
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
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
                ..Default::default()
            },
            strings: vec![RuleString {
                id: "$g".into(),
                pattern: StringPattern::Glob("*pool.*:*".into()),
                nocase: true,
                ..Default::default()
            }],
            condition: RuleCondition::AnyOf,
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
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
                ..Default::default()
            },
            strings: vec![RuleString {
                id: "$s".into(),
                pattern: StringPattern::Text("match-me".into()),
                nocase: false,
                ..Default::default()
            }],
            condition: RuleCondition::AnyOf,
            enabled: false,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
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
        let ws = report
            .results
            .iter()
            .find(|r| r.rule_name == "webshell_php");
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
        let rr = report
            .results
            .iter()
            .find(|r| r.rule_name == "ransomware_note");
        assert!(!rr.unwrap().matched);

        // Two keywords → match
        let report = engine.scan(b"send bitcoin to decrypt your files");
        let rr = report
            .results
            .iter()
            .find(|r| r.rule_name == "ransomware_note");
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
                ..Default::default()
            },
            strings: vec![RuleString {
                id: "$s".into(),
                pattern: StringPattern::Text("x".into()),
                nocase: false,
                ..Default::default()
            }],
            condition: RuleCondition::AllOfWithMaxSize(10),
            enabled: true,
            tags: Vec::new(),
            is_private: false,
            is_global: false,
        });

        // Within size limit → match
        let report = engine.scan(b"x");
        assert!(report.results[0].matched);

        // Exceeds size limit → no match
        let report = engine.scan(&[b'x'; 100]);
        assert!(!report.results[0].matched);
    }
}

//! Extracts `[section]`-style TOML snippets from the docs/runbooks and
//! checks that each one deserializes cleanly into `Config`, so a config
//! key documented in a runbook or `docs/CONFIGURATION.md` is guaranteed
//! to exist (and parse) in the real config schema.
//!
//! Snippets are overlaid onto `Config::default()`'s serialized TOML
//! (table-by-table) rather than parsed standalone, because several
//! top-level sections (`[detector]`, `[policy]`, `[output]`) are
//! required and won't appear in a docs snippet that only demonstrates
//! one unrelated section.

use std::fs;
use std::path::Path;

use wardex::config::Config;

/// Extract fenced ```toml code blocks from a Markdown file.
fn extract_toml_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut lines = markdown.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("```toml") {
            let mut block = String::new();
            for inner in lines.by_ref() {
                if inner.trim_start().starts_with("```") {
                    break;
                }
                block.push_str(inner);
                block.push('\n');
            }
            if !block.trim().is_empty() {
                blocks.push(block);
            }
        }
    }
    blocks
}

/// Dot-separated table paths (relative to a documented section's root,
/// e.g. `"compliance.controls"`) whose child keys are intentionally
/// dynamic (a free-form map, not a fixed set of fields) and therefore
/// exempt from the "documented key must exist in the schema" check below.
/// Add an entry here only with a comment explaining why the section's
/// keys aren't a fixed struct shape.
const DYNAMIC_KEY_ALLOWLIST: &[&str] = &[
    // (none yet — every documented section so far is a fixed struct shape)
];

/// Recursively confirm every key in `snippet_table` (as documented) also
/// exists at the same path in `real`, the re-serialized, schema-accurate
/// `Config`. This catches typo'd or removed config keys that would
/// otherwise pass silently, since no `Config` struct uses
/// `deny_unknown_fields` and unknown keys are simply dropped at
/// deserialize time.
fn assert_documented_keys_exist(
    source: &str,
    path: &str,
    snippet_table: &toml::value::Table,
    real: &toml::Value,
) {
    if DYNAMIC_KEY_ALLOWLIST.contains(&path) {
        return;
    }
    let real_table = real.as_table().unwrap_or_else(|| {
        panic!("{source}: expected `[{path}]` to be a table in the real config schema")
    });
    for (key, value) in snippet_table {
        let child_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        let Some(real_value) = real_table.get(key) else {
            panic!(
                "{source}: documented key `{child_path}` does not exist in Config's real \
                 schema (typo'd or stale docs — check the field actually exists in src/config.rs)"
            );
        };
        if let Some(sub_table) = value.as_table() {
            assert_documented_keys_exist(source, &child_path, sub_table, real_value);
        }
    }
}

/// Overlay a documented snippet's top-level tables onto a full default
/// config, then confirm the merged document still deserializes, and that
/// every key documented in the snippet actually exists in the real,
/// deserialized `Config` schema (recursively, for nested tables).
fn assert_snippet_merges_into_config(source: &str, snippet: &str) {
    let snippet_value: toml::Value = match toml::from_str(snippet) {
        Ok(v) => v,
        Err(e) => panic!("{source}: snippet is not valid TOML: {e}\n---\n{snippet}"),
    };
    let Some(snippet_table) = snippet_value.as_table() else {
        return;
    };

    let default_config = Config::default();
    let default_toml =
        toml::to_string_pretty(&default_config).expect("Config::default() must serialize to TOML");
    let mut merged: toml::Value =
        toml::from_str(&default_toml).expect("default TOML must reparse as a Value");
    let merged_table = merged
        .as_table_mut()
        .expect("top-level Config TOML must be a table");

    let mut sections_to_check: Vec<(String, toml::Value)> = Vec::new();
    for (key, value) in snippet_table {
        // Only merge/check keys that name a real top-level config section;
        // some doc snippets show unrelated one-off examples (e.g. audit
        // rule fragments) that aren't config sections at all.
        if merged_table.contains_key(key) {
            merged_table.insert(key.clone(), value.clone());
            sections_to_check.push((key.clone(), value.clone()));
        }
    }

    let merged_str = toml::to_string(&merged).expect("merged Value must reserialize");
    let parsed_config: Config = match toml::from_str(&merged_str) {
        Ok(c) => c,
        Err(e) => panic!(
            "{source}: snippet failed to deserialize once merged into Config: {e}\n---\n{snippet}"
        ),
    };

    // Re-serialize the *parsed* Config (not the pre-deserialize merged
    // Value) so the comparison reflects the real, schema-validated shape —
    // any key the snippet set that Config silently dropped is caught here.
    let real_toml = toml::to_string(&parsed_config).expect("parsed Config must reserialize");
    let real_value: toml::Value =
        toml::from_str(&real_toml).expect("reserialized Config TOML must reparse as a Value");
    let real_table = real_value
        .as_table()
        .expect("top-level Config TOML must be a table");

    for (section, value) in sections_to_check {
        if let Some(sub_table) = value.as_table() {
            let real_section = real_table
                .get(&section)
                .unwrap_or_else(|| panic!("{source}: `[{section}]` missing from real Config"));
            assert_documented_keys_exist(source, &section, sub_table, real_section);
        }
    }
}

fn check_file_snippets(path: &Path) {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let source = path.display().to_string();
    for block in extract_toml_blocks(&text) {
        // Skip snippets that are clearly not config-file examples (env
        // var tables, audit rule fragments, JSON-in-disguise, etc.) —
        // recognisable because they contain no top-level `key = value`
        // or `[section]` TOML at all once whitespace/comments are
        // stripped, which `toml::from_str` on the whole block already
        // guards against inside `assert_snippet_merges_into_config`.
        assert_snippet_merges_into_config(&source, &block);
    }
}

#[test]
fn configuration_reference_snippets_match_config_schema() {
    check_file_snippets(Path::new("docs/CONFIGURATION.md"));
}

#[test]
fn deployment_models_relay_snippet_matches_config_schema() {
    check_file_snippets(Path::new("docs/DEPLOYMENT_MODELS.md"));
}

#[test]
fn supply_chain_attestation_snippet_matches_config_schema() {
    check_file_snippets(Path::new("docs/DESIGN_SUPPLY_CHAIN.md"));
}

#[test]
fn linux_agent_runbook_collectors_snippet_matches_config_schema() {
    check_file_snippets(Path::new("docs/runbooks/linux-agent.md"));
}

#[test]
fn windows_agent_runbook_collectors_snippets_match_config_schema() {
    check_file_snippets(Path::new("docs/runbooks/windows-agent.md"));
}

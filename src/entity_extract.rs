//! Named entity extraction from alert reason strings.
//!
//! Extracts IPs, domains, file paths, process names, ports, and
//! hashes from free-text alert reasons to enable 1-click pivots
//! and structured enrichment.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A recognized entity extracted from alert text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ExtractedEntity {
    pub entity_type: EntityType,
    pub value: String,
    pub start: usize,
    pub end: usize,
}

/// Types of entities we can extract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntityType {
    IpAddress,
    Domain,
    FilePath,
    ProcessName,
    Port,
    HashSha256,
    HashMd5,
    MitreTechnique,
    Username,
    Hostname,
}

/// Extract all recognizable entities from a slice of reason strings.
pub fn extract_entities(reasons: &[String]) -> Vec<ExtractedEntity> {
    let mut seen = HashSet::new();
    let mut entities = Vec::new();

    for reason in reasons {
        for entity in extract_from_text(reason) {
            let key = (entity.entity_type.clone(), entity.value.clone());
            if seen.insert(key) {
                entities.push(entity);
            }
        }
    }
    entities
}

/// Extract entities from a single text string.
fn extract_from_text(text: &str) -> Vec<ExtractedEntity> {
    let mut results = Vec::new();

    // IPv4 addresses
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            if let Some((ip, end)) = try_parse_ipv4(text, i) {
                results.push(ExtractedEntity {
                    entity_type: EntityType::IpAddress,
                    value: ip,
                    start: i,
                    end,
                });
                i = end;
                continue;
            }
        }
        i += 1;
    }

    // File paths (Unix and Windows)
    for (start, _) in text.match_indices('/') {
        if start == 0 || !text.as_bytes()[start - 1].is_ascii_alphanumeric() {
            if let Some(end) = find_path_end(text, start) {
                let path = &text[start..end];
                if path.len() > 2 && path.contains('/') {
                    results.push(ExtractedEntity {
                        entity_type: EntityType::FilePath,
                        value: path.to_string(),
                        start,
                        end,
                    });
                }
            }
        }
    }
    // Windows paths like C:\...
    for (start, _) in text.match_indices('\\') {
        if start >= 2 && text.as_bytes()[start - 1] == b':' && text.as_bytes()[start - 2].is_ascii_alphabetic() {
            let path_start = start - 2;
            if let Some(end) = find_path_end(text, path_start) {
                let path = &text[path_start..end];
                if path.len() > 3 {
                    results.push(ExtractedEntity {
                        entity_type: EntityType::FilePath,
                        value: path.to_string(),
                        start: path_start,
                        end,
                    });
                }
            }
        }
    }

    // Hex hashes: SHA-256 (64 hex chars) and MD5 (32 hex chars)
    {
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if (bytes[i] as char).is_ascii_hexdigit() {
                let start = i;
                while i < bytes.len() && (bytes[i] as char).is_ascii_hexdigit() {
                    i += 1;
                }
                let word = &text[start..i];
                if word.len() == 64 {
                    results.push(ExtractedEntity {
                        entity_type: EntityType::HashSha256,
                        value: word.to_lowercase(),
                        start,
                        end: i,
                    });
                } else if word.len() == 32 {
                    results.push(ExtractedEntity {
                        entity_type: EntityType::HashMd5,
                        value: word.to_lowercase(),
                        start,
                        end: i,
                    });
                }
            } else {
                i += 1;
            }
        }
    }

    // MITRE technique IDs (T1xxx, T1xxx.xxx)
    let mut idx = 0;
    while idx < text.len().saturating_sub(4) {
        if text[idx..].starts_with('T') {
            if let Some(end) = try_parse_mitre(text, idx) {
                results.push(ExtractedEntity {
                    entity_type: EntityType::MitreTechnique,
                    value: text[idx..end].to_string(),
                    start: idx,
                    end,
                });
                idx = end;
                continue;
            }
        }
        idx += 1;
    }

    // Port numbers (port NNNN or :NNNN)
    for pat in &["port ", "Port ", "PORT ", ":"] {
        for (offset, _) in text.match_indices(pat) {
            let after = offset + pat.len();
            let num_end = text[after..]
                .find(|c: char| !c.is_ascii_digit())
                .map(|p| after + p)
                .unwrap_or(text.len());
            if num_end > after {
                if let Ok(port) = text[after..num_end].parse::<u16>() {
                    if port > 0 {
                        results.push(ExtractedEntity {
                            entity_type: EntityType::Port,
                            value: port.to_string(),
                            start: after,
                            end: num_end,
                        });
                    }
                }
            }
        }
    }

    // Domain names (simple heuristic: word.tld patterns)
    let mut domain_search_from = 0;
    for word in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '"' || c == '\'') {
        if word.is_empty() { continue; }
        let word_start = text[domain_search_from..].find(word)
            .map(|p| p + domain_search_from).unwrap_or(domain_search_from);
        domain_search_from = word_start + word.len();
        let w = word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
        if looks_like_domain(w) {
            let trim_offset = word.find(w).unwrap_or(0);
            let start_pos = word_start + trim_offset;
            results.push(ExtractedEntity {
                entity_type: EntityType::Domain,
                value: w.to_string(),
                start: start_pos,
                end: start_pos + w.len(),
            });
        }
    }

    // Process names (known suspicious)
    let known_procs = [
        "powershell", "cmd.exe", "bash", "sh", "python", "python3", "perl",
        "ruby", "nc", "ncat", "netcat", "wget", "curl", "certutil",
        "mshta", "wscript", "cscript", "regsvr32", "rundll32", "bitsadmin",
        "psexec", "mimikatz", "procdump",
    ];
    let lower = text.to_lowercase();
    for proc in &known_procs {
        if let Some(pos) = lower.find(proc) {
            results.push(ExtractedEntity {
                entity_type: EntityType::ProcessName,
                value: proc.to_string(),
                start: pos,
                end: pos + proc.len(),
            });
        }
    }

    results
}

fn try_parse_ipv4(text: &str, start: usize) -> Option<(String, usize)> {
    let rest = &text[start..];
    let mut octets = 0;
    let mut pos = 0;
    while octets < 4 {
        let num_start = pos;
        while pos < rest.len() && rest.as_bytes()[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == num_start {
            return None;
        }
        let octet: u32 = rest[num_start..pos].parse().ok()?;
        if octet > 255 {
            return None;
        }
        octets += 1;
        if octets < 4 {
            if pos >= rest.len() || rest.as_bytes()[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    // Must not be followed by another digit or dot
    if pos < rest.len() && (rest.as_bytes()[pos].is_ascii_digit() || rest.as_bytes()[pos] == b'.') {
        return None;
    }
    Some((rest[..pos].to_string(), start + pos))
}

fn try_parse_mitre(text: &str, start: usize) -> Option<usize> {
    let rest = &text[start..];
    if rest.len() < 5 {
        return None;
    }
    if !rest.starts_with('T') {
        return None;
    }
    let mut pos = 1;
    while pos < rest.len() && rest.as_bytes()[pos].is_ascii_digit() {
        pos += 1;
    }
    if pos < 5 {
        return None; // Need at least T + 4 digits
    }
    // Optional sub-technique .NNN
    if pos < rest.len() && rest.as_bytes()[pos] == b'.' {
        let dot_pos = pos;
        pos += 1;
        let sub_start = pos;
        while pos < rest.len() && rest.as_bytes()[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == sub_start {
            pos = dot_pos; // No digits after dot, ignore the dot
        }
    }
    Some(start + pos)
}

fn find_path_end(text: &str, start: usize) -> Option<usize> {
    let mut end = start;
    for (i, c) in text[start..].char_indices() {
        if c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';' || c == ')' || c == '>' {
            break;
        }
        end = start + i + c.len_utf8();
    }
    if end > start {
        Some(end)
    } else {
        None
    }
}

fn looks_like_domain(s: &str) -> bool {
    if s.len() < 4 || !s.contains('.') {
        return false;
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let tld = parts.last().unwrap();
    let known_tlds = [
        "com", "net", "org", "io", "co", "uk", "de", "fr", "ru", "cn", "jp",
        "info", "biz", "xyz", "top", "site", "online", "club", "app", "dev",
        "onion", "local", "internal", "example",
    ];
    if !known_tlds.contains(tld) {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ipv4() {
        let reasons = vec!["connection from 10.0.0.99 flagged".into()];
        let ents = extract_entities(&reasons);
        assert!(ents.iter().any(|e| e.entity_type == EntityType::IpAddress && e.value == "10.0.0.99"));
    }

    #[test]
    fn extracts_file_path() {
        let reasons = vec!["suspicious write to /tmp/evil.sh detected".into()];
        let ents = extract_entities(&reasons);
        assert!(ents.iter().any(|e| e.entity_type == EntityType::FilePath && e.value == "/tmp/evil.sh"));
    }

    #[test]
    fn extracts_mitre_technique() {
        let reasons = vec!["matches T1059.001 command interpreter".into()];
        let ents = extract_entities(&reasons);
        assert!(ents.iter().any(|e| e.entity_type == EntityType::MitreTechnique && e.value == "T1059.001"));
    }

    #[test]
    fn extracts_sha256() {
        let hash = "a" .repeat(64);
        let reasons = vec![format!("hash {} flagged", hash)];
        let ents = extract_entities(&reasons);
        assert!(ents.iter().any(|e| e.entity_type == EntityType::HashSha256));
    }

    #[test]
    fn extracts_domain() {
        let reasons = vec!["DNS query to evil.example.com blocked".into()];
        let ents = extract_entities(&reasons);
        assert!(ents.iter().any(|e| e.entity_type == EntityType::Domain && e.value == "evil.example.com"));
    }

    #[test]
    fn extracts_process() {
        let reasons = vec!["powershell executed suspicious command".into()];
        let ents = extract_entities(&reasons);
        assert!(ents.iter().any(|e| e.entity_type == EntityType::ProcessName && e.value == "powershell"));
    }

    #[test]
    fn dedup_across_reasons() {
        let reasons = vec![
            "alert from 10.0.0.1".into(),
            "second alert from 10.0.0.1".into(),
        ];
        let ents = extract_entities(&reasons);
        let ip_count = ents.iter().filter(|e| e.entity_type == EntityType::IpAddress && e.value == "10.0.0.1").count();
        assert_eq!(ip_count, 1);
    }
}

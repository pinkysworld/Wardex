//! Process behavior scoring: parent-child chain analysis, LOLBIN detection,
//! and command-line heuristics for identifying suspicious process lineage.

use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

/// Risk assessment for a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRiskAssessment {
    pub pid: u32,
    pub name: String,
    pub chain: Vec<String>,
    pub lineage_score: f32,
    pub cmdline_score: f32,
    pub lolbin_match: Option<String>,
    pub total_risk: f32,
    pub reasons: Vec<String>,
}

/// Summary of fleet-wide process risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRiskSummary {
    pub total_scored: usize,
    pub high_risk: usize,
    pub medium_risk: usize,
    pub low_risk: usize,
    pub top_risks: Vec<ProcessRiskAssessment>,
    pub lolbin_detections: usize,
}

// ── LOLBIN Database ──────────────────────────────────────────────────────────

/// Living-Off-the-Land binaries with base risk score.
const LOLBINS: &[(&str, f32)] = &[
    ("powershell.exe", 0.4), ("powershell", 0.4),
    ("pwsh.exe", 0.4), ("pwsh", 0.4),
    ("cmd.exe", 0.3), ("cmd", 0.3),
    ("wscript.exe", 0.5), ("wscript", 0.5),
    ("cscript.exe", 0.5), ("cscript", 0.5),
    ("mshta.exe", 0.6), ("mshta", 0.6),
    ("rundll32.exe", 0.5), ("rundll32", 0.5),
    ("regsvr32.exe", 0.5), ("regsvr32", 0.5),
    ("certutil.exe", 0.5), ("certutil", 0.5),
    ("bitsadmin.exe", 0.4), ("bitsadmin", 0.4),
    ("msiexec.exe", 0.3), ("msiexec", 0.3),
    ("installutil.exe", 0.5), ("installutil", 0.5),
    ("regasm.exe", 0.5), ("regasm", 0.5),
    ("regsvcs.exe", 0.5), ("regsvcs", 0.5),
    ("msbuild.exe", 0.5), ("msbuild", 0.5),
    ("cmstp.exe", 0.6), ("cmstp", 0.6),
    ("wmic.exe", 0.4), ("wmic", 0.4),
    ("forfiles.exe", 0.3), ("forfiles", 0.3),
    ("pcalua.exe", 0.4), ("pcalua", 0.4),
    ("explorer.exe", 0.1), ("explorer", 0.1),
    ("schtasks.exe", 0.4), ("schtasks", 0.4),
    ("at.exe", 0.4), ("sc.exe", 0.3),
    ("net.exe", 0.2), ("net", 0.2),
    ("netsh.exe", 0.3), ("netsh", 0.3),
    ("python.exe", 0.2), ("python", 0.2), ("python3", 0.2),
    ("perl.exe", 0.3), ("perl", 0.3),
    ("bash", 0.2), ("sh", 0.2), ("zsh", 0.2),
    ("curl", 0.2), ("wget", 0.2),
    ("nslookup.exe", 0.2), ("nslookup", 0.2),
    ("whoami.exe", 0.2), ("whoami", 0.2),
];

// ── Suspicious Lineage Rules ─────────────────────────────────────────────────

/// Known suspicious parent-child patterns.
const SUSPICIOUS_LINEAGE: &[(&[&str], &str, f32)] = &[
    // (parent patterns, child pattern, risk score)
    (&["winword", "excel", "powerpnt", "outlook", "msaccess"],
        "cmd", 0.8),
    (&["winword", "excel", "powerpnt", "outlook", "msaccess"],
        "powershell", 0.9),
    (&["winword", "excel", "powerpnt", "outlook", "msaccess"],
        "wscript", 0.9),
    (&["winword", "excel", "powerpnt", "outlook", "msaccess"],
        "mshta", 0.9),
    (&["services"],
        "cmd", 0.6),
    (&["iexplore", "chrome", "firefox", "msedge", "safari"],
        "cmd", 0.7),
    (&["iexplore", "chrome", "firefox", "msedge", "safari"],
        "powershell", 0.8),
    (&["iexplore", "chrome", "firefox", "msedge", "safari"],
        "bash", 0.7),
    (&["svchost"],
        "wscript", 0.7),
    (&["wmiprvse"],
        "powershell", 0.6),
    (&["wmiprvse"],
        "cmd", 0.6),
];

// ── Process Scorer ───────────────────────────────────────────────────────────

pub struct ProcessScorer;

impl ProcessScorer {
    /// Score process lineage. `chain` = process names from child → root.
    pub fn score_lineage(chain: &[String]) -> (f32, Vec<String>) {
        let mut score = 0.0_f32;
        let mut reasons = Vec::new();

        // Chain depth suspicion
        if chain.len() > 6 {
            score += 0.15;
            reasons.push(format!("deep process chain ({} levels)", chain.len()));
        }

        // Check parent-child patterns
        if chain.len() >= 2 {
            let child = normalize_name(&chain[0]);
            let parent = normalize_name(&chain[1]);

            for &(parent_pats, child_pat, risk) in SUSPICIOUS_LINEAGE {
                if parent_pats.iter().any(|p| parent.contains(p)) && child.contains(child_pat) {
                    score += risk;
                    reasons.push(format!("suspicious lineage: {} → {}", chain[1], chain[0]));
                    break;
                }
            }

            // svchost.exe without services.exe parent (injection indicator)
            if child.contains("svchost") && !parent.contains("services") && !parent.contains("wininit") {
                score += 0.5;
                reasons.push(format!("svchost.exe with unexpected parent: {}", chain[1]));
            }
        }

        (score.min(1.0), reasons)
    }

    /// Score command-line arguments for suspicious patterns.
    pub fn score_cmdline(cmdline: &str) -> (f32, Vec<String>) {
        let mut score = 0.0_f32;
        let mut reasons = Vec::new();
        let lower = cmdline.to_lowercase();

        // Encoded PowerShell
        if lower.contains("-enc ") || lower.contains("-encodedcommand")
            || lower.contains("-e ") && lower.contains("powershell")
        {
            score += 0.6;
            reasons.push("encoded PowerShell command".into());
        }

        // Base64 payload (long base64-looking strings)
        if has_base64_payload(cmdline) {
            score += 0.4;
            reasons.push("possible base64 payload in cmdline".into());
        }

        // Download cradles
        if (lower.contains("invoke-webrequest") || lower.contains("iwr ")
            || lower.contains("wget ") || lower.contains("curl ")
            || lower.contains("downloadstring") || lower.contains("downloadfile")
            || lower.contains("net.webclient"))
            && (lower.contains("http://") || lower.contains("https://"))
        {
            score += 0.5;
            reasons.push("download cradle detected".into());
        }

        // Registry modification
        if lower.contains("reg add") || lower.contains("set-itemproperty")
            || lower.contains("new-itemproperty")
        {
            score += 0.3;
            reasons.push("registry modification".into());
        }

        // Disabling security tools
        if lower.contains("set-mppreference") || lower.contains("disablerealtimemonitoring")
            || lower.contains("disable-windowsoptionalfeature")
            || lower.contains("tamper") && lower.contains("protect")
        {
            score += 0.7;
            reasons.push("security tool tampering".into());
        }

        // Hidden window
        if lower.contains("-windowstyle hidden") || lower.contains("-w hidden")
            || lower.contains("-nop") || lower.contains("-noprofile")
        {
            score += 0.3;
            reasons.push("hidden/stealthy execution".into());
        }

        // Suspicious temp/appdata execution
        if lower.contains("\\temp\\") || lower.contains("/tmp/")
            || lower.contains("\\appdata\\local\\temp")
            || lower.contains("/dev/shm/")
        {
            score += 0.2;
            reasons.push("execution from temp directory".into());
        }

        (score.min(1.0), reasons)
    }

    /// Check if a process name matches any known LOLBIN.
    pub fn check_lolbin(name: &str) -> Option<(String, f32)> {
        let lower = normalize_name(name);
        for &(lolbin, risk) in LOLBINS {
            if lower == lolbin || lower.ends_with(&format!("/{lolbin}")) || lower.ends_with(&format!("\\{lolbin}")) {
                return Some((lolbin.to_string(), risk));
            }
        }
        None
    }

    /// Full risk assessment for a process given its tree context.
    pub fn assess(
        pid: u32,
        name: &str,
        chain: &[String],
        cmdline: Option<&str>,
    ) -> ProcessRiskAssessment {
        let (lineage_score, mut reasons) = Self::score_lineage(chain);
        let (cmdline_score, cmd_reasons) = cmdline
            .map(|c| Self::score_cmdline(c))
            .unwrap_or((0.0, vec![]));
        reasons.extend(cmd_reasons);

        let lolbin_match = Self::check_lolbin(name);
        let lolbin_bonus = lolbin_match.as_ref().map(|(_, r)| *r).unwrap_or(0.0);

        if let Some((ref lb, _)) = lolbin_match {
            reasons.push(format!("LOLBIN: {lb}"));
        }

        let total_risk = (lineage_score * 0.4 + cmdline_score * 0.4 + lolbin_bonus * 0.2).min(1.0);

        ProcessRiskAssessment {
            pid,
            name: name.to_string(),
            chain: chain.to_vec(),
            lineage_score,
            cmdline_score,
            lolbin_match: lolbin_match.map(|(n, _)| n),
            total_risk,
            reasons,
        }
    }

    /// Build a fleet-wide risk summary from a list of assessments.
    pub fn summarize(assessments: &[ProcessRiskAssessment]) -> ProcessRiskSummary {
        let high = assessments.iter().filter(|a| a.total_risk > 0.7).count();
        let medium = assessments.iter().filter(|a| a.total_risk > 0.4 && a.total_risk <= 0.7).count();
        let low = assessments.len() - high - medium;
        let lolbin = assessments.iter().filter(|a| a.lolbin_match.is_some()).count();

        let mut top: Vec<_> = assessments.iter()
            .filter(|a| a.total_risk > 0.3)
            .cloned()
            .collect();
        top.sort_by(|a, b| b.total_risk.partial_cmp(&a.total_risk).unwrap_or(std::cmp::Ordering::Equal));
        top.truncate(20);

        ProcessRiskSummary {
            total_scored: assessments.len(),
            high_risk: high,
            medium_risk: medium,
            low_risk: low,
            top_risks: top,
            lolbin_detections: lolbin,
        }
    }
}

fn normalize_name(name: &str) -> String {
    let n = name.to_lowercase();
    n.rsplit(['/', '\\']).next().unwrap_or(&n).trim_end_matches(".exe").to_string()
}

fn has_base64_payload(cmdline: &str) -> bool {
    // Look for long base64-like tokens (>40 chars of [A-Za-z0-9+/=])
    cmdline.split_whitespace().any(|token| {
        token.len() > 40
            && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn office_spawning_cmd_is_suspicious() {
        let chain = vec!["cmd.exe".into(), "WINWORD.EXE".into(), "explorer.exe".into()];
        let (score, reasons) = ProcessScorer::score_lineage(&chain);
        assert!(score > 0.5, "score={score}");
        assert!(!reasons.is_empty());
    }

    #[test]
    fn normal_shell_chain_is_low_risk() {
        let chain = vec!["ls".into(), "bash".into(), "sshd".into()];
        let (score, _) = ProcessScorer::score_lineage(&chain);
        assert!(score < 0.3, "score={score}");
    }

    #[test]
    fn encoded_powershell_flagged() {
        let (score, reasons) = ProcessScorer::score_cmdline(
            "powershell.exe -enc SQBFAHgAIAAoA...",
        );
        assert!(score > 0.3, "score={score}");
        assert!(reasons.iter().any(|r| r.contains("encoded")));
    }

    #[test]
    fn lolbin_detection() {
        assert!(ProcessScorer::check_lolbin("mshta.exe").is_some());
        assert!(ProcessScorer::check_lolbin("notepad.exe").is_none());
    }

    #[test]
    fn full_assessment() {
        let chain = vec!["powershell.exe".into(), "EXCEL.EXE".into()];
        let assessment = ProcessScorer::assess(
            1234, "powershell.exe", &chain,
            Some("powershell.exe -enc SQBFAHgA..."),
        );
        assert!(assessment.total_risk > 0.5);
        assert!(assessment.lolbin_match.is_some());
    }
}

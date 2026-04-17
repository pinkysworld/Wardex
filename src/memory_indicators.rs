//! Memory-resident malware indicator detection.
//!
//! Scans process memory maps for indicators of reflective DLL injection,
//! shellcode, process hollowing, and suspicious RWX memory regions.
//! Works with /proc/{pid}/maps on Linux; macOS fallback uses `vmmap`.

use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

/// A suspicious memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub address_start: String,
    pub address_end: String,
    pub permissions: String,
    pub size_bytes: usize,
    pub backing: String,
    pub indicator: String,
}

/// A shellcode pattern match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub offset: String,
    pub size: usize,
    pub description: String,
}

/// Complete memory indicator report for one process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryIndicatorReport {
    pub pid: u32,
    pub process_name: String,
    pub rwx_regions: usize,
    pub anonymous_executable: usize,
    pub reflective_dll_suspects: Vec<MemoryRegion>,
    pub shellcode_patterns: Vec<PatternMatch>,
    pub hollowing_suspected: bool,
    pub total_regions_scanned: usize,
    pub risk_score: f32,
    pub indicators: Vec<String>,
}

/// Fleet-wide memory indicator overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryIndicatorSummary {
    pub processes_scanned: usize,
    pub processes_flagged: usize,
    pub total_rwx_regions: usize,
    pub total_reflective_dll: usize,
    pub total_shellcode: usize,
    pub flagged_processes: Vec<MemoryIndicatorReport>,
}

/// Parsed memory map entry.
#[derive(Debug, Clone)]
struct MapEntry {
    addr_start: u64,
    addr_end: u64,
    permissions: String,
    #[allow(dead_code)]
    offset: u64,
    path: String,
}

// ── Shellcode Signatures ─────────────────────────────────────────────────────

/// Known shellcode patterns (byte sequences).
struct ShellcodeSignature {
    name: &'static str,
    pattern: &'static [u8],
    description: &'static str,
}

const SHELLCODE_SIGS: &[ShellcodeSignature] = &[
    ShellcodeSignature {
        name: "NOP_sled_x86",
        pattern: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        description: "x86 NOP sled (8+ consecutive NOPs)",
    },
    ShellcodeSignature {
        name: "syscall_stub_linux_x64",
        pattern: &[0x0F, 0x05, 0x48, 0x3D],
        description: "Linux x86_64 syscall followed by comparison",
    },
    ShellcodeSignature {
        name: "int80_linux_x86",
        pattern: &[0xCD, 0x80],
        description: "Linux x86 int 0x80 syscall",
    },
    ShellcodeSignature {
        name: "PE_header_MZ",
        pattern: b"MZ",
        description: "MZ header (possible reflective DLL or PE in memory)",
    },
    ShellcodeSignature {
        name: "ELF_header",
        pattern: b"\x7fELF",
        description: "ELF header in memory (possible injected binary)",
    },
    ShellcodeSignature {
        name: "metasploit_x86_shikata",
        pattern: &[0xD9, 0x74, 0x24, 0xF4],
        description: "Metasploit shikata_ga_nai encoder stub",
    },
    ShellcodeSignature {
        name: "cobalt_strike_beacon",
        pattern: &[0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00],
        description: "Cobalt Strike default beacon shellcode prefix",
    },
];

// ── Memory Map Parsing ───────────────────────────────────────────────────────

/// Parse /proc/{pid}/maps format.
fn parse_proc_maps(content: &str) -> Vec<MapEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            continue;
        }

        let Ok(addr_start) = u64::from_str_radix(addr_range[0], 16) else {
            continue;
        };
        let Ok(addr_end) = u64::from_str_radix(addr_range[1], 16) else {
            continue;
        };
        let permissions = parts[1].to_string();
        let Ok(offset) = u64::from_str_radix(parts[2], 16) else {
            continue;
        };
        let path = if parts.len() >= 6 {
            parts[5..].join(" ")
        } else {
            String::new()
        };

        entries.push(MapEntry {
            addr_start,
            addr_end,
            permissions,
            offset,
            path,
        });
    }
    entries
}

// ── Analysis Logic ───────────────────────────────────────────────────────────

/// Analyze memory maps for an indicator report (without reading actual memory).
pub fn analyze_maps(pid: u32, process_name: &str, maps_content: &str) -> MemoryIndicatorReport {
    let entries = parse_proc_maps(maps_content);
    let mut rwx_regions = 0;
    let mut anonymous_executable = 0;
    let mut reflective_suspects = Vec::new();
    let mut indicators = Vec::new();
    let total = entries.len();

    for entry in &entries {
        let perms = &entry.permissions;
        let is_rwx = perms.contains('r') && perms.contains('w') && perms.contains('x');
        let is_executable = perms.contains('x');
        let is_anonymous =
            entry.path.is_empty() || entry.path == "[heap]" || entry.path == "[stack]";
        let size = (entry.addr_end - entry.addr_start) as usize;

        // RWX detection
        if is_rwx {
            rwx_regions += 1;
            if is_anonymous {
                reflective_suspects.push(MemoryRegion {
                    address_start: format!("0x{:x}", entry.addr_start),
                    address_end: format!("0x{:x}", entry.addr_end),
                    permissions: perms.clone(),
                    size_bytes: size,
                    backing: if entry.path.is_empty() {
                        "anonymous".into()
                    } else {
                        entry.path.clone()
                    },
                    indicator: "RWX anonymous region (possible code injection)".into(),
                });
            }
        }

        // Anonymous executable (not RWX but still executable + anonymous)
        if is_executable && is_anonymous && !is_rwx {
            anonymous_executable += 1;
        }
    }

    // Score calculation
    let mut risk_score = 0.0_f32;

    if rwx_regions > 0 {
        risk_score += (rwx_regions as f32 * 0.15).min(0.4);
        indicators.push(format!("{rwx_regions} RWX memory region(s)"));
    }

    if anonymous_executable > 2 {
        risk_score += 0.2;
        indicators.push(format!(
            "{anonymous_executable} anonymous executable regions"
        ));
    }

    if !reflective_suspects.is_empty() {
        risk_score += 0.3;
        indicators.push(format!(
            "{} potential reflective DLL region(s)",
            reflective_suspects.len()
        ));
    }

    let hollowing_suspected = false; // Requires comparing on-disk vs in-memory — needs actual memory reads

    MemoryIndicatorReport {
        pid,
        process_name: process_name.to_string(),
        rwx_regions,
        anonymous_executable,
        reflective_dll_suspects: reflective_suspects,
        shellcode_patterns: vec![], // Pattern matching requires reading actual memory bytes
        hollowing_suspected,
        total_regions_scanned: total,
        risk_score: risk_score.min(1.0),
        indicators,
    }
}

/// Scan a memory buffer for shellcode patterns (used when memory content is available).
pub fn scan_buffer_for_shellcode(data: &[u8]) -> Vec<PatternMatch> {
    let mut matches = Vec::new();

    for sig in SHELLCODE_SIGS {
        if sig.pattern.len() > data.len() {
            continue;
        }

        for (offset, window) in data.windows(sig.pattern.len()).enumerate() {
            if window == sig.pattern {
                // For NOP sleds, only report if it's a long sequence
                if sig.name == "NOP_sled_x86" {
                    let nop_count = data[offset..].iter().take_while(|&&b| b == 0x90).count();
                    if nop_count < 8 {
                        continue;
                    }
                }

                // For MZ headers, skip if at file start (normal) or in file-backed region
                if sig.name == "PE_header_MZ" && offset == 0 {
                    continue;
                }

                matches.push(PatternMatch {
                    pattern_name: sig.name.to_string(),
                    offset: format!("0x{offset:x}"),
                    size: sig.pattern.len(),
                    description: sig.description.to_string(),
                });

                break; // One match per signature per scan
            }
        }
    }

    matches
}

/// Scan a process by reading its /proc maps (Linux only, stub on other platforms).
pub fn scan_process(pid: u32) -> MemoryIndicatorReport {
    let process_name = get_process_name(pid);

    #[cfg(target_os = "linux")]
    {
        let maps_path = format!("/proc/{pid}/maps");
        let maps_content = std::fs::read_to_string(&maps_path).unwrap_or_default();
        if maps_content.is_empty() {
            return empty_report(pid, &process_name, "cannot read /proc maps");
        }
        analyze_maps(pid, &process_name, &maps_content)
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: try vmmap (requires SIP disabled or debug entitlement)
        let output = std::process::Command::new("vmmap")
            .arg(pid.to_string())
            .output();
        match output {
            Ok(out) => {
                let content = String::from_utf8_lossy(&out.stdout);
                analyze_vmmap(pid, &process_name, &content)
            }
            Err(_) => empty_report(pid, &process_name, "vmmap not available"),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        empty_report(pid, &process_name, "unsupported platform")
    }
}

/// Build summary from multiple process scans.
pub fn summarize(reports: &[MemoryIndicatorReport]) -> MemoryIndicatorSummary {
    let flagged: Vec<_> = reports
        .iter()
        .filter(|r| r.risk_score > 0.1)
        .cloned()
        .collect();
    MemoryIndicatorSummary {
        processes_scanned: reports.len(),
        processes_flagged: flagged.len(),
        total_rwx_regions: reports.iter().map(|r| r.rwx_regions).sum(),
        total_reflective_dll: reports
            .iter()
            .map(|r| r.reflective_dll_suspects.len())
            .sum(),
        total_shellcode: reports.iter().map(|r| r.shellcode_patterns.len()).sum(),
        flagged_processes: flagged,
    }
}

fn get_process_name(pid: u32) -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_else(|_| format!("pid_{pid}"))
            .trim()
            .to_string()
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!("pid_{pid}")
    }
}

fn empty_report(pid: u32, name: &str, reason: &str) -> MemoryIndicatorReport {
    MemoryIndicatorReport {
        pid,
        process_name: name.into(),
        rwx_regions: 0,
        anonymous_executable: 0,
        reflective_dll_suspects: vec![],
        shellcode_patterns: vec![],
        hollowing_suspected: false,
        total_regions_scanned: 0,
        risk_score: 0.0,
        indicators: vec![format!("scan skipped: {reason}")],
    }
}

#[cfg(target_os = "macos")]
fn analyze_vmmap(pid: u32, process_name: &str, _vmmap_out: &str) -> MemoryIndicatorReport {
    // vmmap output parsing is very different from /proc/maps.
    // Simplified stub: report basic info only.
    MemoryIndicatorReport {
        pid,
        process_name: process_name.into(),
        rwx_regions: 0,
        anonymous_executable: 0,
        reflective_dll_suspects: vec![],
        shellcode_patterns: vec![],
        hollowing_suspected: false,
        total_regions_scanned: 0,
        risk_score: 0.0,
        indicators: vec!["macOS vmmap analysis (limited)".into()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_maps_basic() {
        let maps = "\
00400000-00452000 r-xp 00000000 08:01 12345 /usr/bin/test
00651000-00652000 rwxp 00251000 08:01 12345
7f1234560000-7f1234580000 rwxp 00000000 00:00 0
";
        let report = analyze_maps(42, "test", maps);
        assert_eq!(report.rwx_regions, 2);
        assert!(report.risk_score > 0.0);
    }

    #[test]
    fn shellcode_nop_sled_detected() {
        let mut data = vec![0u8; 256];
        // Insert NOP sled at offset 10
        for i in 10..26 {
            data[i] = 0x90;
        }
        let matches = scan_buffer_for_shellcode(&data);
        assert!(matches.iter().any(|m| m.pattern_name.contains("NOP")));
    }

    #[test]
    fn mz_header_at_nonzero_offset() {
        let mut data = vec![0u8; 256];
        data[50] = b'M';
        data[51] = b'Z';
        let matches = scan_buffer_for_shellcode(&data);
        assert!(matches.iter().any(|m| m.pattern_name.contains("PE_header")));
    }

    #[test]
    fn mz_header_at_offset_zero_ignored() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        let matches = scan_buffer_for_shellcode(&data);
        assert!(!matches.iter().any(|m| m.pattern_name.contains("PE_header")));
    }

    #[test]
    fn empty_maps_safe() {
        let report = analyze_maps(1, "init", "");
        assert_eq!(report.risk_score, 0.0);
        assert_eq!(report.total_regions_scanned, 0);
    }

    #[test]
    fn summary_counts() {
        let r1 = empty_report(1, "a", "test");
        let r2 = analyze_maps(2, "b", "00400000-00500000 rwxp 00000000 00:00 0\n");
        let summary = summarize(&[r1, r2]);
        assert_eq!(summary.processes_scanned, 2);
        assert_eq!(summary.processes_flagged, 1);
    }
}

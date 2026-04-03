//! Volatile memory forensics collection and analysis.
//!
//! Provides structures and platform-specific commands for live
//! memory capture, injected code detection, and process memory
//! artifact scanning.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A memory region of interest in a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub pid: u32,
    pub process_name: String,
    pub base_address: u64,
    pub size_bytes: u64,
    pub permissions: String,
    pub region_type: RegionType,
    pub file_backed: Option<String>,
    pub suspicious: bool,
    pub reason: Option<String>,
}

/// Type of memory region.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegionType {
    Code,
    Stack,
    Heap,
    MappedFile,
    Anonymous,
    Shared,
    Unknown,
}

/// A suspicious finding in process memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryFinding {
    pub pid: u32,
    pub process_name: String,
    pub finding_type: FindingType,
    pub description: String,
    pub severity: String,
    pub evidence: HashMap<String, String>,
}

/// Types of suspicious memory patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingType {
    InjectedCode,
    HollowedProcess,
    UnbackedExecutable,
    ShellcodePattern,
    HookedFunction,
    SuspiciousString,
    HiddenModule,
    RwxRegion,
}

/// Plan for memory forensic collection per platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCollectionPlan {
    pub platform: String,
    pub artifacts: Vec<MemoryArtifact>,
}

/// A memory artifact to collect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryArtifact {
    pub name: String,
    pub description: String,
    pub command: String,
    pub volatile: bool,
}

/// Memory forensics engine.
pub struct MemoryForensics {
    findings: Vec<MemoryFinding>,
    regions: Vec<MemoryRegion>,
}

impl Default for MemoryForensics {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryForensics {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            regions: Vec::new(),
        }
    }

    /// Analyze a set of memory regions for suspicious patterns.
    pub fn analyze_regions(&mut self, regions: &[MemoryRegion]) -> Vec<MemoryFinding> {
        let mut findings = Vec::new();
        self.regions.extend(regions.iter().cloned());

        for region in regions {
            // RWX regions are suspicious (writable + executable)
            if region.permissions.contains('w') && region.permissions.contains('x') {
                let finding = MemoryFinding {
                    pid: region.pid,
                    process_name: region.process_name.clone(),
                    finding_type: FindingType::RwxRegion,
                    description: format!(
                        "RWX region at 0x{:x} ({} bytes) — writable+executable memory is suspicious",
                        region.base_address, region.size_bytes
                    ),
                    severity: "elevated".into(),
                    evidence: HashMap::from([
                        ("address".into(), format!("0x{:x}", region.base_address)),
                        ("size".into(), region.size_bytes.to_string()),
                        ("perms".into(), region.permissions.clone()),
                    ]),
                };
                findings.push(finding);
            }

            // Unbacked executable regions (no file, but executable)
            if region.file_backed.is_none()
                && region.permissions.contains('x')
                && region.region_type == RegionType::Anonymous
            {
                let finding = MemoryFinding {
                    pid: region.pid,
                    process_name: region.process_name.clone(),
                    finding_type: FindingType::UnbackedExecutable,
                    description: format!(
                        "Anonymous executable region at 0x{:x} — possible injected code",
                        region.base_address
                    ),
                    severity: "severe".into(),
                    evidence: HashMap::from([
                        ("address".into(), format!("0x{:x}", region.base_address)),
                        ("type".into(), format!("{:?}", region.region_type)),
                    ]),
                };
                findings.push(finding);
            }

            // User-flagged suspicious regions
            if region.suspicious {
                if let Some(reason) = &region.reason {
                    findings.push(MemoryFinding {
                        pid: region.pid,
                        process_name: region.process_name.clone(),
                        finding_type: FindingType::InjectedCode,
                        description: reason.clone(),
                        severity: "severe".into(),
                        evidence: HashMap::from([
                            ("address".into(), format!("0x{:x}", region.base_address)),
                        ]),
                    });
                }
            }
        }

        self.findings.extend(findings.clone());
        findings
    }

    /// Check a process for signs of process hollowing.
    pub fn check_hollowing(
        &mut self,
        pid: u32,
        process_name: &str,
        image_base_matches_disk: bool,
        section_entropy: f64,
    ) -> Option<MemoryFinding> {
        // High entropy in code section + image base mismatch = hollowing
        if !image_base_matches_disk && section_entropy > 7.0 {
            let finding = MemoryFinding {
                pid,
                process_name: process_name.to_string(),
                finding_type: FindingType::HollowedProcess,
                description: format!(
                    "Process {} (PID {}) shows signs of hollowing: image base mismatch + high entropy ({:.2})",
                    process_name, pid, section_entropy
                ),
                severity: "critical".into(),
                evidence: HashMap::from([
                    ("entropy".into(), format!("{:.2}", section_entropy)),
                    ("image_match".into(), "false".into()),
                ]),
            };
            self.findings.push(finding.clone());
            Some(finding)
        } else {
            None
        }
    }

    /// Get all findings.
    pub fn findings(&self) -> &[MemoryFinding] {
        &self.findings
    }

    /// Get findings for a specific PID.
    pub fn findings_for_pid(&self, pid: u32) -> Vec<&MemoryFinding> {
        self.findings.iter().filter(|f| f.pid == pid).collect()
    }

    /// Generate platform-specific collection plan.
    pub fn collection_plan(platform: &str) -> MemoryCollectionPlan {
        let artifacts = match platform {
            "linux" => vec![
                MemoryArtifact {
                    name: "Process maps".into(),
                    description: "Virtual memory layout of all processes".into(),
                    command: "cat /proc/[0-9]*/maps".into(),
                    volatile: true,
                },
                MemoryArtifact {
                    name: "Process status".into(),
                    description: "Process state and memory usage".into(),
                    command: "cat /proc/[0-9]*/status".into(),
                    volatile: true,
                },
                MemoryArtifact {
                    name: "Loaded modules".into(),
                    description: "Kernel and shared library modules".into(),
                    command: "cat /proc/modules && lsmod".into(),
                    volatile: true,
                },
                MemoryArtifact {
                    name: "Open file descriptors".into(),
                    description: "Files and sockets held by processes".into(),
                    command: "ls -la /proc/[0-9]*/fd/".into(),
                    volatile: true,
                },
                MemoryArtifact {
                    name: "Network connections".into(),
                    description: "Active network state".into(),
                    command: "ss -tupnla".into(),
                    volatile: true,
                },
                MemoryArtifact {
                    name: "eBPF programs".into(),
                    description: "Loaded eBPF programs (potential rootkit)".into(),
                    command: "bpftool prog list 2>/dev/null || true".into(),
                    volatile: true,
                },
            ],
            "macos" => vec![
                MemoryArtifact {
                    name: "VM regions".into(),
                    description: "Virtual memory regions per process".into(),
                    command: "vmmap --summary <pid>".into(),
                    volatile: true,
                },
                MemoryArtifact {
                    name: "Loaded dylibs".into(),
                    description: "Dynamic libraries loaded by processes".into(),
                    command: "dyld_info -all".into(),
                    volatile: true,
                },
                MemoryArtifact {
                    name: "Code signatures".into(),
                    description: "Validate process code signatures".into(),
                    command: "codesign --verify --deep --verbose".into(),
                    volatile: false,
                },
                MemoryArtifact {
                    name: "Process list".into(),
                    description: "Extended process listing".into(),
                    command: "ps -eo pid,ppid,user,%mem,command".into(),
                    volatile: true,
                },
            ],
            "windows" => vec![
                MemoryArtifact {
                    name: "Loaded DLLs".into(),
                    description: "DLLs loaded per process".into(),
                    command: "tasklist /m".into(),
                    volatile: true,
                },
                MemoryArtifact {
                    name: "Handles".into(),
                    description: "Open handles per process".into(),
                    command: "handle.exe -a".into(),
                    volatile: true,
                },
                MemoryArtifact {
                    name: "Unsigned modules".into(),
                    description: "Detect unsigned loaded modules".into(),
                    command: "Get-Process | ForEach-Object { Get-AuthenticodeSignature $_.Path }".into(),
                    volatile: false,
                },
                MemoryArtifact {
                    name: "Network state".into(),
                    description: "Active connections with owning process".into(),
                    command: "netstat -anob".into(),
                    volatile: true,
                },
            ],
            _ => Vec::new(),
        };

        MemoryCollectionPlan {
            platform: platform.to_string(),
            artifacts,
        }
    }

    /// Count suspicious findings by severity.
    pub fn severity_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for f in &self.findings {
            *counts.entry(f.severity.clone()).or_default() += 1;
        }
        counts
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_rwx_region() {
        let mut mf = MemoryForensics::new();
        let regions = vec![MemoryRegion {
            pid: 1234,
            process_name: "suspicious".into(),
            base_address: 0x7f0000,
            size_bytes: 4096,
            permissions: "rwx".into(),
            region_type: RegionType::Anonymous,
            file_backed: None,
            suspicious: false,
            reason: None,
        }];
        let findings = mf.analyze_regions(&regions);
        assert!(findings.iter().any(|f| f.finding_type == FindingType::RwxRegion));
    }

    #[test]
    fn detects_unbacked_executable() {
        let mut mf = MemoryForensics::new();
        let regions = vec![MemoryRegion {
            pid: 5678,
            process_name: "victim".into(),
            base_address: 0x400000,
            size_bytes: 8192,
            permissions: "r-x".into(),
            region_type: RegionType::Anonymous,
            file_backed: None,
            suspicious: false,
            reason: None,
        }];
        let findings = mf.analyze_regions(&regions);
        assert!(findings.iter().any(|f| f.finding_type == FindingType::UnbackedExecutable));
    }

    #[test]
    fn detects_hollowing() {
        let mut mf = MemoryForensics::new();
        let finding = mf.check_hollowing(999, "svchost.exe", false, 7.8);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().finding_type, FindingType::HollowedProcess);
    }

    #[test]
    fn no_hollowing_when_image_matches() {
        let mut mf = MemoryForensics::new();
        assert!(mf.check_hollowing(999, "svchost.exe", true, 7.8).is_none());
    }

    #[test]
    fn collection_plan_linux() {
        let plan = MemoryForensics::collection_plan("linux");
        assert!(!plan.artifacts.is_empty());
        assert!(plan.artifacts.iter().any(|a| a.name.contains("maps")));
    }

    #[test]
    fn severity_counts() {
        let mut mf = MemoryForensics::new();
        mf.analyze_regions(&[
            MemoryRegion {
                pid: 1, process_name: "p".into(), base_address: 0, size_bytes: 1,
                permissions: "rwx".into(), region_type: RegionType::Anonymous,
                file_backed: None, suspicious: false, reason: None,
            },
            MemoryRegion {
                pid: 2, process_name: "q".into(), base_address: 0, size_bytes: 1,
                permissions: "r-x".into(), region_type: RegionType::Anonymous,
                file_backed: None, suspicious: false, reason: None,
            },
        ]);
        let counts = mf.severity_counts();
        assert!(counts.contains_key("elevated") || counts.contains_key("severe"));
    }
}

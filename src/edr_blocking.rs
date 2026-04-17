//! EDR behavioral blocking engine.
//!
//! Provides real-time process blocking based on behavioral analysis,
//! memory corruption detection (ROP chains, heap spraying), and
//! exploit mitigation. Integrates with platform-specific endpoint
//! security frameworks (macOS Endpoint Security, Linux eBPF,
//! Windows ETW).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Configuration ───────────────────────────────────────────────────

/// EDR blocking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrBlockingConfig {
    /// Enable real-time process blocking.
    pub enabled: bool,
    /// Score threshold for automatic blocking (0.0–10.0).
    pub block_threshold: f64,
    /// Score threshold for alerting without blocking.
    pub alert_threshold: f64,
    /// Maximum events in the sliding window.
    pub window_size: usize,
    /// Sliding window duration in milliseconds.
    pub window_ms: u64,
    /// Allowlisted process paths (never blocked).
    pub allowlist: Vec<String>,
    /// Enable memory corruption detection.
    pub memory_protection: bool,
    /// Enable exploit mitigation heuristics.
    pub exploit_mitigation: bool,
    /// Weight for ROP chain detection signal.
    pub rop_weight: f64,
    /// Weight for heap spray detection signal.
    pub heap_spray_weight: f64,
    /// Weight for shellcode detection signal.
    pub shellcode_weight: f64,
    /// Weight for process injection signal.
    pub injection_weight: f64,
    /// Weight for privilege escalation signal.
    pub privesc_weight: f64,
}

impl Default for EdrBlockingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_threshold: 7.5,
            alert_threshold: 4.0,
            window_size: 500,
            window_ms: 60_000,
            allowlist: Vec::new(),
            memory_protection: true,
            exploit_mitigation: true,
            rop_weight: 3.0,
            heap_spray_weight: 2.5,
            shellcode_weight: 3.5,
            injection_weight: 2.0,
            privesc_weight: 2.5,
        }
    }
}

// ── Threat Patterns ─────────────────────────────────────────────────

/// Classification of memory corruption attack type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryAttackType {
    /// Return-oriented programming chain detected.
    RopChain,
    /// Heap spray pattern (large identical allocations).
    HeapSpray,
    /// Executable shellcode in data region.
    ShellcodeInjection,
    /// Process hollowing or DLL injection.
    ProcessInjection,
    /// Stack pivot / stack buffer overflow.
    StackPivot,
    /// Use-after-free exploitation pattern.
    UseAfterFree,
}

/// A detected behavioral indicator from endpoint telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorIndicator {
    /// Process ID generating the behavior.
    pub pid: u32,
    /// Process name or path.
    pub process_name: String,
    /// Parent process ID.
    pub ppid: u32,
    /// User context.
    pub user: String,
    /// Indicator type.
    pub indicator: IndicatorType,
    /// Timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
    /// Additional context.
    pub details: HashMap<String, String>,
}

/// Types of behavioral indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndicatorType {
    /// Suspicious system call sequence.
    SyscallSequence { calls: Vec<String> },
    /// Memory region with executable + writable permissions.
    MemoryAnomaly {
        attack_type: MemoryAttackType,
        confidence: f64,
    },
    /// Credential access attempt (e.g., LSASS, /etc/shadow, Keychain).
    CredentialAccess { target: String },
    /// Privilege escalation attempt.
    PrivilegeEscalation {
        from_uid: u32,
        to_uid: u32,
        method: String,
    },
    /// Suspicious child process spawn.
    SuspiciousSpawn {
        child_path: String,
        child_args: Vec<String>,
    },
    /// File-less execution (memory-only payload).
    FilelessExecution {
        region_addr: u64,
        region_size: usize,
    },
    /// Network callback to known C2 pattern.
    C2Callback {
        dest_ip: String,
        dest_port: u16,
        pattern: String,
    },
    /// Persistence mechanism installation.
    PersistenceInstall { mechanism: String, path: String },
}

// ── Blocking Decision ───────────────────────────────────────────────

/// Outcome of behavioral analysis for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingDecision {
    /// Process ID evaluated.
    pub pid: u32,
    /// Process name/path.
    pub process_name: String,
    /// Combined threat score (0.0–10.0).
    pub score: f64,
    /// Whether the process should be blocked.
    pub block: bool,
    /// Whether an alert should be raised.
    pub alert: bool,
    /// Contributing signals.
    pub signals: Vec<BlockSignal>,
    /// Recommended action.
    pub action: BlockAction,
    /// Decision timestamp.
    pub timestamp_ms: u64,
}

/// Individual signal contributing to a blocking decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSignal {
    pub category: String,
    pub weight: f64,
    pub raw_score: f64,
    pub description: String,
}

/// Action to take on a detected threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockAction {
    /// Allow process to continue.
    Allow,
    /// Raise alert but do not block.
    Alert,
    /// Terminate the process.
    Kill,
    /// Suspend the process for investigation.
    Suspend,
    /// Quarantine the process binary.
    Quarantine,
    /// Isolate the host from the network.
    Isolate,
}

// ── Engine ───────────────────────────────────────────────────────────

/// Per-process behavioral state.
#[derive(Debug, Clone)]
struct ProcessState {
    #[allow(dead_code)]
    pid: u32,
    process_name: String,
    indicators: VecDeque<BehaviorIndicator>,
    cumulative_score: f64,
    last_seen_ms: u64,
}

/// Real-time EDR behavioral blocking engine.
pub struct EdrBlockingEngine {
    config: EdrBlockingConfig,
    /// Per-PID behavioral state.
    processes: HashMap<u32, ProcessState>,
    /// History of blocking decisions.
    decisions: VecDeque<BlockingDecision>,
    /// Total indicators processed.
    total_indicators: u64,
    /// Total blocks issued.
    total_blocks: u64,
}

impl EdrBlockingEngine {
    /// Create a new EDR blocking engine with the given configuration.
    pub fn new(config: EdrBlockingConfig) -> Self {
        Self {
            config,
            processes: HashMap::new(),
            decisions: VecDeque::new(),
            total_indicators: 0,
            total_blocks: 0,
        }
    }

    /// Process a behavioral indicator and return a blocking decision
    /// if the process crosses a threshold.
    pub fn evaluate(&mut self, indicator: BehaviorIndicator) -> Option<BlockingDecision> {
        self.total_indicators += 1;
        let now = indicator.timestamp_ms;
        let pid = indicator.pid;

        // Skip allowlisted processes
        if self
            .config
            .allowlist
            .iter()
            .any(|p| indicator.process_name.contains(p))
        {
            return None;
        }

        // Get or create process state
        let state = self.processes.entry(pid).or_insert_with(|| ProcessState {
            pid,
            process_name: indicator.process_name.clone(),
            indicators: VecDeque::new(),
            cumulative_score: 0.0,
            last_seen_ms: now,
        });

        // Expire old indicators outside the window
        let cutoff = now.saturating_sub(self.config.window_ms);
        while state
            .indicators
            .front()
            .map_or(false, |i| i.timestamp_ms < cutoff)
        {
            state.indicators.pop_front();
        }

        // Enforce window size limit
        while state.indicators.len() >= self.config.window_size {
            state.indicators.pop_front();
        }

        state.indicators.push_back(indicator.clone());
        state.last_seen_ms = now;

        // Score the indicator (use free functions to avoid borrow conflicts)
        let signal = score_indicator(&self.config, &indicator);
        state.cumulative_score = compute_process_score(&self.config, state);

        let score = state.cumulative_score;
        let should_block = self.config.enabled && score >= self.config.block_threshold;
        let should_alert = score >= self.config.alert_threshold;

        if should_alert || should_block {
            let action = if should_block {
                if score >= 9.0 {
                    BlockAction::Kill
                } else {
                    BlockAction::Suspend
                }
            } else {
                BlockAction::Alert
            };

            let decision = BlockingDecision {
                pid,
                process_name: state.process_name.clone(),
                score,
                block: should_block,
                alert: should_alert,
                signals: vec![signal],
                action,
                timestamp_ms: now,
            };

            if should_block {
                self.total_blocks += 1;
            }

            self.decisions.push_back(decision.clone());
            if self.decisions.len() > 10_000 {
                self.decisions.pop_front();
            }

            Some(decision)
        } else {
            None
        }
    }

    /// Get statistics about the engine state.
    pub fn stats(&self) -> EdrStats {
        EdrStats {
            tracked_processes: self.processes.len(),
            total_indicators: self.total_indicators,
            total_blocks: self.total_blocks,
            recent_decisions: self.decisions.len(),
            enabled: self.config.enabled,
        }
    }

    /// Get recent blocking decisions.
    pub fn recent_decisions(&self, limit: usize) -> Vec<&BlockingDecision> {
        self.decisions.iter().rev().take(limit).collect()
    }

    /// Remove stale process state (not seen in the last `max_age_ms`).
    pub fn gc(&mut self, max_age_ms: u64) {
        let now = now_ms();
        self.processes
            .retain(|_, s| now.saturating_sub(s.last_seen_ms) < max_age_ms);
    }
}

/// Score an individual indicator based on its type (free function to avoid borrow conflicts).
fn score_indicator(config: &EdrBlockingConfig, indicator: &BehaviorIndicator) -> BlockSignal {
    match &indicator.indicator {
        IndicatorType::MemoryAnomaly {
            attack_type,
            confidence,
        } => {
            let weight = match attack_type {
                MemoryAttackType::RopChain => config.rop_weight,
                MemoryAttackType::HeapSpray => config.heap_spray_weight,
                MemoryAttackType::ShellcodeInjection => config.shellcode_weight,
                MemoryAttackType::ProcessInjection => config.injection_weight,
                MemoryAttackType::StackPivot => config.rop_weight,
                MemoryAttackType::UseAfterFree => config.heap_spray_weight,
            };
            BlockSignal {
                category: format!("memory:{attack_type:?}"),
                weight,
                raw_score: confidence * weight,
                description: format!(
                    "{attack_type:?} detected with {:.0}% confidence",
                    confidence * 100.0
                ),
            }
        }
        IndicatorType::CredentialAccess { target } => BlockSignal {
            category: "credential_access".into(),
            weight: config.privesc_weight,
            raw_score: config.privesc_weight * 0.8,
            description: format!("Credential access: {target}"),
        },
        IndicatorType::PrivilegeEscalation {
            from_uid,
            to_uid,
            method,
        } => {
            let raw = if *to_uid == 0 {
                config.privesc_weight
            } else {
                config.privesc_weight * 0.6
            };
            BlockSignal {
                category: "privilege_escalation".into(),
                weight: config.privesc_weight,
                raw_score: raw,
                description: format!("Privesc {from_uid} → {to_uid} via {method}"),
            }
        }
        IndicatorType::SuspiciousSpawn { child_path, .. } => BlockSignal {
            category: "suspicious_spawn".into(),
            weight: config.injection_weight,
            raw_score: config.injection_weight * 0.5,
            description: format!("Suspicious child: {child_path}"),
        },
        IndicatorType::FilelessExecution { region_size, .. } => {
            let confidence = if *region_size > 1_000_000 { 0.9 } else { 0.6 };
            BlockSignal {
                category: "fileless_execution".into(),
                weight: config.shellcode_weight,
                raw_score: config.shellcode_weight * confidence,
                description: format!("Fileless execution, region size: {region_size}"),
            }
        }
        IndicatorType::C2Callback {
            dest_ip,
            dest_port,
            pattern,
        } => BlockSignal {
            category: "c2_callback".into(),
            weight: config.injection_weight * 1.5,
            raw_score: config.injection_weight * 1.2,
            description: format!("C2 callback {dest_ip}:{dest_port} pattern={pattern}"),
        },
        IndicatorType::PersistenceInstall { mechanism, path } => BlockSignal {
            category: "persistence".into(),
            weight: config.privesc_weight,
            raw_score: config.privesc_weight * 0.7,
            description: format!("Persistence via {mechanism}: {path}"),
        },
        IndicatorType::SyscallSequence { calls } => {
            let suspicious = calls
                .iter()
                .any(|c| c.contains("ptrace") || c.contains("mprotect") || c.contains("execve"));
            let raw = if suspicious { 1.5 } else { 0.3 };
            BlockSignal {
                category: "syscall_sequence".into(),
                weight: 1.0,
                raw_score: raw,
                description: format!("Syscall sequence: {}", calls.join(" → ")),
            }
        }
    }
}

/// Compute combined score for a process from all indicators in the window.
fn compute_process_score(config: &EdrBlockingConfig, state: &ProcessState) -> f64 {
    let mut category_scores: HashMap<String, f64> = HashMap::new();
    for ind in &state.indicators {
        let signal = score_indicator(config, ind);
        let entry = category_scores.entry(signal.category).or_insert(0.0);
        *entry += signal.raw_score;
    }
    // Sum top-N category scores capped at 10.0
    let mut scores: Vec<f64> = category_scores.values().copied().collect();
    scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    scores.iter().take(5).sum::<f64>().min(10.0)
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrStats {
    pub tracked_processes: usize,
    pub total_indicators: u64,
    pub total_blocks: u64,
    pub recent_decisions: usize,
    pub enabled: bool,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── ROP Chain Heuristics ─────────────────────────────────────────────

/// Heuristic check for ROP gadget chain patterns in a memory region.
/// Returns confidence 0.0–1.0.
pub fn detect_rop_chain(bytes: &[u8]) -> f64 {
    if bytes.len() < 16 {
        return 0.0;
    }
    // Count potential gadget endings (ret = 0xc3 on x86/x64)
    let ret_count = bytes.iter().filter(|&&b| b == 0xc3).count();
    // ROP chains have many short gadgets ending in ret
    let density = ret_count as f64 / (bytes.len() as f64 / 8.0);
    // High density of ret instructions relative to region size is suspicious
    if density > 0.5 {
        (density.min(2.0) / 2.0).min(1.0)
    } else {
        0.0
    }
}

/// Heuristic check for heap spray patterns (repeated NOP sleds or
/// identical allocations). Returns confidence 0.0–1.0.
pub fn detect_heap_spray(allocation_sizes: &[usize]) -> f64 {
    if allocation_sizes.len() < 10 {
        return 0.0;
    }
    // Count how many allocations share the same size
    let mut size_counts: HashMap<usize, usize> = HashMap::new();
    for &sz in allocation_sizes {
        *size_counts.entry(sz).or_insert(0) += 1;
    }
    let max_same = size_counts.values().copied().max().unwrap_or(0);
    let ratio = max_same as f64 / allocation_sizes.len() as f64;
    if ratio > 0.7 { ratio.min(1.0) } else { 0.0 }
}

/// Detect potential shellcode by looking for common NOP sled patterns
/// and syscall/int instructions. Returns confidence 0.0–1.0.
pub fn detect_shellcode(bytes: &[u8]) -> f64 {
    if bytes.len() < 8 {
        return 0.0;
    }
    let nop_count = bytes.iter().filter(|&&b| b == 0x90).count();
    let nop_ratio = nop_count as f64 / bytes.len() as f64;

    // Check for int 0x80 (Linux syscall) or syscall instruction (0x0f 0x05)
    let mut syscall_count = 0;
    for window in bytes.windows(2) {
        if window == [0xcd, 0x80] || window == [0x0f, 0x05] {
            syscall_count += 1;
        }
    }

    let nop_score = if nop_ratio > 0.3 { nop_ratio } else { 0.0 };
    let syscall_score = if syscall_count > 0 { 0.5 } else { 0.0 };

    (nop_score + syscall_score).min(1.0)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_indicator(pid: u32, indicator: IndicatorType, ts: u64) -> BehaviorIndicator {
        BehaviorIndicator {
            pid,
            process_name: "test_proc".into(),
            ppid: 1,
            user: "root".into(),
            indicator,
            timestamp_ms: ts,
            details: HashMap::new(),
        }
    }

    #[test]
    fn test_benign_process_no_block() {
        let mut engine = EdrBlockingEngine::new(EdrBlockingConfig::default());
        let ind = make_indicator(
            100,
            IndicatorType::SyscallSequence {
                calls: vec!["read".into(), "write".into(), "close".into()],
            },
            1000,
        );
        let decision = engine.evaluate(ind);
        assert!(decision.is_none() || !decision.unwrap().block);
    }

    #[test]
    fn test_rop_chain_triggers_alert() {
        let mut engine = EdrBlockingEngine::new(EdrBlockingConfig {
            alert_threshold: 2.0,
            ..Default::default()
        });
        let ind = make_indicator(
            200,
            IndicatorType::MemoryAnomaly {
                attack_type: MemoryAttackType::RopChain,
                confidence: 0.9,
            },
            1000,
        );
        let decision = engine.evaluate(ind);
        assert!(decision.is_some());
        let d = decision.unwrap();
        assert!(d.alert);
        assert!(d.score > 0.0);
    }

    #[test]
    fn test_cumulative_score_triggers_block() {
        let mut engine = EdrBlockingEngine::new(EdrBlockingConfig {
            block_threshold: 5.0,
            ..Default::default()
        });
        // Multiple high-confidence memory attacks should trigger block
        for i in 0..5 {
            engine.evaluate(make_indicator(
                300,
                IndicatorType::MemoryAnomaly {
                    attack_type: MemoryAttackType::ShellcodeInjection,
                    confidence: 0.85,
                },
                1000 + i * 100,
            ));
        }
        let last = engine.evaluate(make_indicator(
            300,
            IndicatorType::CredentialAccess {
                target: "/etc/shadow".into(),
            },
            2000,
        ));
        assert!(last.is_some());
        assert!(last.unwrap().block);
    }

    #[test]
    fn test_allowlisted_process_not_blocked() {
        let config = EdrBlockingConfig {
            allowlist: vec!["/usr/bin/systemd".into()],
            ..Default::default()
        };
        let mut engine = EdrBlockingEngine::new(config);
        let mut ind = make_indicator(
            400,
            IndicatorType::MemoryAnomaly {
                attack_type: MemoryAttackType::ProcessInjection,
                confidence: 1.0,
            },
            1000,
        );
        ind.process_name = "/usr/bin/systemd-journald".into();
        let decision = engine.evaluate(ind);
        assert!(decision.is_none());
    }

    #[test]
    fn test_rop_chain_detection_heuristic() {
        // Simulate high density of ret instructions
        let mut bytes = vec![0x41; 64];
        for i in (0..64).step_by(4) {
            bytes[i] = 0xc3; // ret
        }
        let confidence = detect_rop_chain(&bytes);
        assert!(confidence > 0.5, "ROP chain confidence={confidence}");
    }

    #[test]
    fn test_heap_spray_detection() {
        let sizes = vec![0x1000; 50]; // 50 identical allocations
        let confidence = detect_heap_spray(&sizes);
        assert!(confidence > 0.9, "Heap spray confidence={confidence}");
    }

    #[test]
    fn test_shellcode_detection() {
        let mut bytes = vec![0x90; 100]; // NOP sled
        bytes.extend_from_slice(&[0x0f, 0x05]); // syscall
        let confidence = detect_shellcode(&bytes);
        assert!(confidence > 0.3, "Shellcode confidence={confidence}");
    }

    #[test]
    fn test_stats() {
        let mut engine = EdrBlockingEngine::new(EdrBlockingConfig::default());
        engine.evaluate(make_indicator(
            500,
            IndicatorType::SyscallSequence {
                calls: vec!["open".into()],
            },
            1000,
        ));
        let stats = engine.stats();
        assert_eq!(stats.total_indicators, 1);
        assert_eq!(stats.tracked_processes, 1);
        assert!(stats.enabled);
    }

    #[test]
    fn test_gc_removes_stale() {
        let mut engine = EdrBlockingEngine::new(EdrBlockingConfig::default());
        engine.evaluate(make_indicator(
            600,
            IndicatorType::SyscallSequence {
                calls: vec!["read".into()],
            },
            1000,
        ));
        assert_eq!(engine.processes.len(), 1);
        // GC with very short max age
        engine.gc(1);
        assert_eq!(engine.processes.len(), 0);
    }
}

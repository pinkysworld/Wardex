//! SOAR-style playbook engine.
//!
//! Defines declarative playbooks with trigger conditions, ordered steps,
//! conditional branching, parallel fans, approval gates, and full
//! execution-state tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Playbook definition ─────────────────────────────────────────

/// A complete SOAR playbook definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: u32,
    pub enabled: bool,
    pub trigger: PlaybookTrigger,
    pub steps: Vec<PlaybookStep>,
    /// Max seconds before the playbook is considered timed out.
    pub timeout_secs: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Conditions that can start a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookTrigger {
    /// Minimum alert severity to trigger (0–100).
    pub min_severity: Option<f32>,
    /// Alert reason substrings to match.
    pub alert_reasons: Vec<String>,
    /// MITRE technique IDs to match.
    pub mitre_techniques: Vec<String>,
    /// Kill-chain phase matches.
    pub kill_chain_phases: Vec<String>,
    /// Specific host patterns (glob).
    pub host_patterns: Vec<String>,
    /// Manual-only trigger.
    pub manual_only: bool,
}

impl PlaybookTrigger {
    /// Evaluate whether this trigger matches an alert.
    pub fn matches(&self, severity: f32, reason: &str, techniques: &[String], host: &str) -> bool {
        if self.manual_only {
            return false;
        }
        if let Some(min) = self.min_severity {
            if severity < min {
                return false;
            }
        }
        let reason_ok = self.alert_reasons.is_empty()
            || self
                .alert_reasons
                .iter()
                .any(|r| reason.to_lowercase().contains(&r.to_lowercase()));
        let tech_ok = self.mitre_techniques.is_empty()
            || self.mitre_techniques.iter().any(|t| techniques.contains(t));
        let host_ok = self.host_patterns.is_empty()
            || self
                .host_patterns
                .iter()
                .any(|p| glob_match(p, host));
        reason_ok && tech_ok && host_ok
    }
}

/// A single step in a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub id: String,
    pub name: String,
    pub step_type: StepType,
    /// Step to jump to on failure (default: abort).
    pub on_failure: Option<String>,
    /// Max seconds for this step before timeout.
    pub timeout_secs: Option<u64>,
}

/// The type/action of a playbook step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepType {
    /// Execute a response action.
    RunAction {
        action: String,
        params: HashMap<String, String>,
    },
    /// Send a notification via a channel.
    Notify {
        channel: NotifyChannel,
        message_template: String,
    },
    /// Enrich context with an external lookup.
    Enrich {
        source: String,
        query_template: String,
    },
    /// Conditional branch.
    Conditional {
        condition: String,
        then_step: String,
        else_step: Option<String>,
    },
    /// Fan out to parallel steps.
    Parallel { step_ids: Vec<String> },
    /// Wait for a duration (seconds).
    Wait { seconds: u64 },
    /// Escalate to a person or group.
    Escalate {
        target: String,
        message_template: String,
    },
    /// Create or update an incident case.
    CreateCase { case_template: String },
    /// Approval gate – waits for human approval.
    Approval {
        approver: String,
        message_template: String,
    },
    /// Collect evidence/artifacts.
    CollectEvidence { artifact_types: Vec<String> },
    /// Containment action.
    Contain {
        action: String,
        params: HashMap<String, String>,
    },
}

/// Notification channels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotifyChannel {
    Email,
    Slack,
    Webhook,
    PagerDuty,
    MsTeams,
    Syslog,
}

// ── Execution tracking ──────────────────────────────────────────

/// Runtime state of a playbook execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecution {
    pub execution_id: String,
    pub playbook_id: String,
    pub alert_id: Option<String>,
    pub status: ExecutionStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub step_results: Vec<StepResult>,
    pub variables: HashMap<String, String>,
    pub error: Option<String>,
}

/// Step-level result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub status: ExecutionStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub output: Option<String>,
    pub error: Option<String>,
}

/// Playbook or step execution status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Skipped,
    AwaitingApproval,
    Cancelled,
}

// ── Engine ──────────────────────────────────────────────────────

/// The playbook engine manages definitions and executions.
pub struct PlaybookEngine {
    playbooks: Vec<Playbook>,
    executions: Vec<PlaybookExecution>,
    next_exec_id: u64,
}

impl Default for PlaybookEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaybookEngine {
    pub fn new() -> Self {
        Self {
            playbooks: Vec::new(),
            executions: Vec::new(),
            next_exec_id: 1,
        }
    }

    /// Register a playbook definition.
    pub fn register(&mut self, playbook: Playbook) {
        // Replace if same id exists
        self.playbooks.retain(|p| p.id != playbook.id);
        self.playbooks.push(playbook);
    }

    /// Remove a playbook by id.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.playbooks.len();
        self.playbooks.retain(|p| p.id != id);
        self.playbooks.len() < before
    }

    /// List all registered playbook definitions.
    pub fn list_playbooks(&self) -> &[Playbook] {
        &self.playbooks
    }

    /// Find playbooks whose triggers match the given alert context.
    pub fn find_matching(
        &self,
        severity: f32,
        reason: &str,
        techniques: &[String],
        host: &str,
    ) -> Vec<&Playbook> {
        self.playbooks
            .iter()
            .filter(|p| p.enabled && p.trigger.matches(severity, reason, techniques, host))
            .collect()
    }

    /// Begin execution of a playbook (returns execution id).
    /// Steps are not actually run (no IO) — this prepares the execution record.
    pub fn start_execution(
        &mut self,
        playbook_id: &str,
        alert_id: Option<&str>,
        now_ms: u64,
    ) -> Option<String> {
        let pb = self.playbooks.iter().find(|p| p.id == playbook_id)?;
        if !pb.enabled {
            return None;
        }

        let exec_id = format!("exec-{}", self.next_exec_id);
        self.next_exec_id += 1;

        let step_results: Vec<StepResult> = pb
            .steps
            .iter()
            .map(|s| StepResult {
                step_id: s.id.clone(),
                status: ExecutionStatus::Pending,
                started_at: 0,
                finished_at: None,
                output: None,
                error: None,
            })
            .collect();

        self.executions.push(PlaybookExecution {
            execution_id: exec_id.clone(),
            playbook_id: playbook_id.to_string(),
            alert_id: alert_id.map(|s| s.to_string()),
            status: ExecutionStatus::Running,
            started_at: now_ms,
            finished_at: None,
            step_results,
            variables: HashMap::new(),
            error: None,
        });

        Some(exec_id)
    }

    /// Advance a step to a new status.
    pub fn update_step(
        &mut self,
        execution_id: &str,
        step_id: &str,
        status: ExecutionStatus,
        output: Option<String>,
        error: Option<String>,
        now_ms: u64,
    ) -> bool {
        let exec = match self.executions.iter_mut().find(|e| e.execution_id == execution_id) {
            Some(e) => e,
            None => return false,
        };
        let step = match exec.step_results.iter_mut().find(|s| s.step_id == step_id) {
            Some(s) => s,
            None => return false,
        };

        if step.started_at == 0 {
            step.started_at = now_ms;
        }
        if matches!(
            status,
            ExecutionStatus::Succeeded
                | ExecutionStatus::Failed
                | ExecutionStatus::TimedOut
                | ExecutionStatus::Skipped
                | ExecutionStatus::Cancelled
        ) {
            step.finished_at = Some(now_ms);
        }
        step.status = status;
        step.output = output;
        step.error = error;
        true
    }

    /// Complete (or fail) an entire execution.
    pub fn finish_execution(
        &mut self,
        execution_id: &str,
        status: ExecutionStatus,
        error: Option<String>,
        now_ms: u64,
    ) -> bool {
        if let Some(exec) = self.executions.iter_mut().find(|e| e.execution_id == execution_id) {
            exec.status = status;
            exec.error = error;
            exec.finished_at = Some(now_ms);
            true
        } else {
            false
        }
    }

    /// Get execution record.
    pub fn get_execution(&self, execution_id: &str) -> Option<&PlaybookExecution> {
        self.executions.iter().find(|e| e.execution_id == execution_id)
    }

    /// List recent executions.
    pub fn recent_executions(&self, limit: usize) -> Vec<&PlaybookExecution> {
        let start = self.executions.len().saturating_sub(limit);
        self.executions[start..].iter().collect()
    }

    /// Count active (running) executions.
    pub fn active_count(&self) -> usize {
        self.executions
            .iter()
            .filter(|e| e.status == ExecutionStatus::Running)
            .count()
    }
}

// ── Helpers ─────────────────────────────────────────────────────

/// Lightweight condition evaluator for playbook conditional steps.
///
/// Supported syntax:
///   - `score > 7.0`
///   - `reason CONTAINS 'auth'`
///   - `level == 'Critical'`
///   - compound: `score > 5 AND reason CONTAINS 'burst'`
///   - compound: `level == 'Severe' OR score > 8`
///
/// Variables are resolved from the execution's `variables` map.
pub fn evaluate_condition(condition: &str, variables: &HashMap<String, String>) -> bool {
    let condition = condition.trim();
    // Handle OR first (lower precedence = outermost split), then AND
    if let Some(pos) = find_top_level(condition, " OR ") {
        let left = &condition[..pos];
        let right = &condition[pos + 4..];
        return evaluate_condition(left, variables) || evaluate_condition(right, variables);
    }
    if let Some(pos) = find_top_level(condition, " AND ") {
        let left = &condition[..pos];
        let right = &condition[pos + 5..];
        return evaluate_condition(left, variables) && evaluate_condition(right, variables);
    }

    // Single predicate
    if let Some(r) = try_compare(condition, " CONTAINS ", variables) {
        return r;
    }
    if let Some(r) = try_numeric_op(condition, ">=", variables) {
        return r;
    }
    if let Some(r) = try_numeric_op(condition, "<=", variables) {
        return r;
    }
    if let Some(r) = try_numeric_op(condition, "!=", variables) {
        return r;
    }
    if let Some(r) = try_numeric_op(condition, ">", variables) {
        return r;
    }
    if let Some(r) = try_numeric_op(condition, "<", variables) {
        return r;
    }
    if let Some(r) = try_string_eq(condition, "==", variables) {
        return r;
    }
    // fallback: treat as truthy variable lookup
    variables
        .get(condition.trim())
        .map(|v| v != "0" && v != "false" && !v.is_empty())
        .unwrap_or(false)
}

fn find_top_level(s: &str, sep: &str) -> Option<usize> {
    let sep_upper = sep.to_uppercase();
    let s_upper = s.to_uppercase();
    s_upper.find(&sep_upper)
}

fn try_compare(cond: &str, op: &str, vars: &HashMap<String, String>) -> Option<bool> {
    let upper = cond.to_uppercase();
    let pos = upper.find(&op.to_uppercase())?;
    let lhs_name = cond[..pos].trim();
    let rhs_raw = cond[pos + op.len()..].trim().trim_matches('\'').trim_matches('"');
    let lhs_val = vars.get(lhs_name).cloned().unwrap_or_default();
    Some(lhs_val.to_lowercase().contains(&rhs_raw.to_lowercase()))
}

fn try_numeric_op(cond: &str, op: &str, vars: &HashMap<String, String>) -> Option<bool> {
    let pos = cond.find(op)?;
    // Make sure it's not part of a longer operator (e.g., > vs >=)
    if op == ">" && cond.get(pos..pos + 2) == Some(">=") {
        return None;
    }
    if op == "<" && cond.get(pos..pos + 2) == Some("<=") {
        return None;
    }
    if op == "!" && cond.get(pos..pos + 2) == Some("!=") {
        return None;
    }
    let lhs_name = cond[..pos].trim();
    let rhs_str = cond[pos + op.len()..].trim().trim_matches('\'').trim_matches('"');
    let lhs_val: f64 = vars.get(lhs_name)?.parse().ok()?;
    let rhs_val: f64 = rhs_str.parse().ok()?;
    Some(match op {
        ">=" => lhs_val >= rhs_val,
        "<=" => lhs_val <= rhs_val,
        "!=" => (lhs_val - rhs_val).abs() > f64::EPSILON,
        ">" => lhs_val > rhs_val,
        "<" => lhs_val < rhs_val,
        _ => false,
    })
}

fn try_string_eq(cond: &str, op: &str, vars: &HashMap<String, String>) -> Option<bool> {
    let pos = cond.find(op)?;
    // Skip if it's actually != 
    if pos > 0 && cond.as_bytes().get(pos - 1) == Some(&b'!') {
        return None;
    }
    let lhs_name = cond[..pos].trim();
    let rhs_raw = cond[pos + op.len()..].trim().trim_matches('\'').trim_matches('"');
    let lhs_val = vars.get(lhs_name).cloned().unwrap_or_default();
    Some(lhs_val == rhs_raw)
}

/// Simple glob matching supporting `*` and `?`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut px = 0usize;
    let mut tx = 0usize;
    let pb = pattern.as_bytes();
    let tb = text.as_bytes();
    let mut star_px = usize::MAX;
    let mut star_tx = 0usize;

    while tx < tb.len() {
        if px < pb.len() && (pb[px] == b'?' || pb[px] == tb[tx]) {
            px += 1;
            tx += 1;
        } else if px < pb.len() && pb[px] == b'*' {
            star_px = px;
            star_tx = tx;
            px += 1;
        } else if star_px != usize::MAX {
            px = star_px + 1;
            star_tx += 1;
            tx = star_tx;
        } else {
            return false;
        }
    }

    while px < pb.len() && pb[px] == b'*' {
        px += 1;
    }
    px == pb.len()
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_playbook(id: &str) -> Playbook {
        Playbook {
            id: id.into(),
            name: format!("Playbook {id}"),
            description: "Test".into(),
            version: 1,
            enabled: true,
            trigger: PlaybookTrigger {
                min_severity: Some(50.0),
                alert_reasons: vec!["lateral".into()],
                mitre_techniques: vec![],
                kill_chain_phases: vec![],
                host_patterns: vec![],
                manual_only: false,
            },
            steps: vec![
                PlaybookStep {
                    id: "s1".into(),
                    name: "Isolate".into(),
                    step_type: StepType::Contain {
                        action: "isolate_host".into(),
                        params: HashMap::new(),
                    },
                    on_failure: None,
                    timeout_secs: Some(60),
                },
                PlaybookStep {
                    id: "s2".into(),
                    name: "Notify SOC".into(),
                    step_type: StepType::Notify {
                        channel: NotifyChannel::Slack,
                        message_template: "Alert: {alert_id}".into(),
                    },
                    on_failure: None,
                    timeout_secs: None,
                },
            ],
            timeout_secs: 300,
            created_at: "2025-01-01T00:00:00Z".into(),
            updated_at: "2025-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn trigger_matches_severity_and_reason() {
        let t = PlaybookTrigger {
            min_severity: Some(40.0),
            alert_reasons: vec!["brute".into()],
            mitre_techniques: vec![],
            kill_chain_phases: vec![],
            host_patterns: vec![],
            manual_only: false,
        };
        assert!(t.matches(50.0, "brute force attack", &[], "host1"));
        assert!(!t.matches(30.0, "brute force", &[], "host1")); // below severity
        assert!(!t.matches(50.0, "normal event", &[], "host1")); // no reason match
    }

    #[test]
    fn trigger_manual_never_auto_matches() {
        let t = PlaybookTrigger {
            min_severity: None,
            alert_reasons: vec![],
            mitre_techniques: vec![],
            kill_chain_phases: vec![],
            host_patterns: vec![],
            manual_only: true,
        };
        assert!(!t.matches(99.0, "anything", &[], "host"));
    }

    #[test]
    fn engine_register_and_find() {
        let mut engine = PlaybookEngine::new();
        engine.register(sample_playbook("pb1"));
        let matches = engine.find_matching(60.0, "lateral movement", &[], "host1");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn engine_no_match_low_severity() {
        let mut engine = PlaybookEngine::new();
        engine.register(sample_playbook("pb1"));
        let matches = engine.find_matching(10.0, "lateral movement", &[], "host1");
        assert!(matches.is_empty());
    }

    #[test]
    fn execution_lifecycle() {
        let mut engine = PlaybookEngine::new();
        engine.register(sample_playbook("pb1"));

        let eid = engine
            .start_execution("pb1", Some("alert-1"), 1000)
            .unwrap();
        assert_eq!(engine.active_count(), 1);

        engine.update_step(&eid, "s1", ExecutionStatus::Succeeded, None, None, 2000);
        engine.update_step(&eid, "s2", ExecutionStatus::Succeeded, None, None, 3000);
        engine.finish_execution(&eid, ExecutionStatus::Succeeded, None, 3000);

        let exec = engine.get_execution(&eid).unwrap();
        assert_eq!(exec.status, ExecutionStatus::Succeeded);
        assert_eq!(exec.finished_at, Some(3000));
        assert_eq!(engine.active_count(), 0);
    }

    #[test]
    fn remove_playbook() {
        let mut engine = PlaybookEngine::new();
        engine.register(sample_playbook("pb1"));
        assert!(engine.remove("pb1"));
        assert!(engine.list_playbooks().is_empty());
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("host-*", "host-web01"));
        assert!(glob_match("*.example.com", "web.example.com"));
        assert!(!glob_match("host-?", "host-web01"));
        assert!(glob_match("host-?", "host-1"));
    }

    #[test]
    fn trigger_host_pattern() {
        let t = PlaybookTrigger {
            min_severity: None,
            alert_reasons: vec![],
            mitre_techniques: vec![],
            kill_chain_phases: vec![],
            host_patterns: vec!["web-*".into()],
            manual_only: false,
        };
        assert!(t.matches(10.0, "test", &[], "web-server01"));
        assert!(!t.matches(10.0, "test", &[], "db-server01"));
    }

    #[test]
    fn condition_dsl_numeric() {
        let mut vars = HashMap::new();
        vars.insert("score".into(), "7.5".into());
        assert!(evaluate_condition("score > 5", &vars));
        assert!(!evaluate_condition("score > 10", &vars));
        assert!(evaluate_condition("score >= 7.5", &vars));
        assert!(evaluate_condition("score <= 8", &vars));
        assert!(evaluate_condition("score != 3", &vars));
    }

    #[test]
    fn condition_dsl_contains() {
        let mut vars = HashMap::new();
        vars.insert("reason".into(), "network burst detected".into());
        assert!(evaluate_condition("reason CONTAINS 'burst'", &vars));
        assert!(!evaluate_condition("reason CONTAINS 'auth'", &vars));
    }

    #[test]
    fn condition_dsl_compound() {
        let mut vars = HashMap::new();
        vars.insert("score".into(), "8.0".into());
        vars.insert("reason".into(), "auth failure burst".into());
        vars.insert("level".into(), "Critical".into());
        assert!(evaluate_condition("score > 5 AND reason CONTAINS 'auth'", &vars));
        assert!(!evaluate_condition("score > 10 AND reason CONTAINS 'auth'", &vars));
        assert!(evaluate_condition("score > 10 OR level == 'Critical'", &vars));
    }

    #[test]
    fn condition_dsl_string_eq() {
        let mut vars = HashMap::new();
        vars.insert("level".into(), "Severe".into());
        assert!(evaluate_condition("level == 'Severe'", &vars));
        assert!(!evaluate_condition("level == 'Critical'", &vars));
    }
}

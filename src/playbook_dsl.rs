//! Dynamic playbook DSL for composing investigation workflows at runtime.
//!
//! Allows analysts to define conditional branching, loops, and parallel
//! steps in investigation playbooks using a lightweight JSON DSL.
//! Supports variables, condition evaluation, and action routing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::investigation::{AutoQuery, InvestigationStep, InvestigationWorkflow};

// ── DSL Node Types ───────────────────────────────────────────────────

/// A node in a playbook DSL graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PlaybookNode {
    /// Execute an investigation step.
    Step {
        id: String,
        title: String,
        description: String,
        api_pivot: Option<String>,
        actions: Vec<String>,
        evidence: Vec<String>,
        auto_queries: Vec<AutoQuery>,
    },
    /// Conditional branch based on a variable comparison.
    Condition {
        id: String,
        variable: String,
        operator: ConditionOp,
        value: serde_json::Value,
        then_branch: Vec<String>,
        else_branch: Vec<String>,
    },
    /// Execute multiple branches in parallel.
    Parallel {
        id: String,
        branches: Vec<Vec<String>>,
    },
    /// Loop over a list variable, executing steps for each item.
    ForEach {
        id: String,
        variable: String,
        item_var: String,
        body: Vec<String>,
    },
    /// Route an alert to a specific response action.
    Action {
        id: String,
        action_type: String,
        parameters: HashMap<String, serde_json::Value>,
    },
    /// Set a variable in the execution context.
    SetVariable {
        id: String,
        variable: String,
        value: serde_json::Value,
    },
}

/// Comparison operators for conditions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConditionOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    In,
}

/// A complete playbook definition using the DSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    pub severity: String,
    pub mitre_techniques: Vec<String>,
    pub trigger_conditions: Vec<String>,
    pub nodes: Vec<PlaybookNode>,
    pub entry_nodes: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub status: PlaybookStatus,
}

/// Lifecycle status for authored playbooks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PlaybookStatus {
    Draft,
    Testing,
    Active,
    Deprecated,
}

/// Runtime execution context for a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub playbook_id: String,
    pub run_id: String,
    pub analyst: String,
    pub variables: HashMap<String, serde_json::Value>,
    pub completed_nodes: Vec<String>,
    pub current_node: Option<String>,
    pub status: ExecutionStatus,
    pub started_at: String,
    pub findings: Vec<String>,
    pub actions_taken: Vec<ActionRecord>,
}

/// Execution status of a running playbook.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExecutionStatus {
    Running,
    WaitingForInput,
    WaitingForApproval,
    Completed,
    Failed,
    Cancelled,
}

/// Record of an action taken during playbook execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub node_id: String,
    pub action_type: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub result: Option<String>,
    pub timestamp: String,
}

// ── Playbook DSL Store ───────────────────────────────────────────────

/// Store for custom playbook definitions and execution tracking.
#[derive(Debug)]
pub struct PlaybookDslStore {
    definitions: Vec<PlaybookDefinition>,
    executions: Vec<ExecutionContext>,
    next_run_id: u64,
}

impl Default for PlaybookDslStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaybookDslStore {
    pub fn new() -> Self {
        Self {
            definitions: Vec::new(),
            executions: Vec::new(),
            next_run_id: 1,
        }
    }

    /// Create a new playbook definition.
    pub fn create(&mut self, def: PlaybookDefinition) -> String {
        let id = def.id.clone();
        // Replace existing definition with same ID
        self.definitions.retain(|d| d.id != id);
        self.definitions.push(def);
        id
    }

    /// List all playbook definitions.
    pub fn list(&self) -> &[PlaybookDefinition] {
        &self.definitions
    }

    /// Get a specific definition by ID.
    pub fn get(&self, id: &str) -> Option<&PlaybookDefinition> {
        self.definitions.iter().find(|d| d.id == id)
    }

    /// Update playbook status (lifecycle transition).
    pub fn set_status(&mut self, id: &str, status: PlaybookStatus) -> bool {
        if let Some(def) = self.definitions.iter_mut().find(|d| d.id == id) {
            def.status = status;
            def.updated_at = chrono::Utc::now().to_rfc3339();
            true
        } else {
            false
        }
    }

    /// Delete a playbook definition (only if Draft or Deprecated).
    pub fn delete(&mut self, id: &str) -> bool {
        if let Some(pos) = self.definitions.iter().position(|d| {
            d.id == id && matches!(d.status, PlaybookStatus::Draft | PlaybookStatus::Deprecated)
        }) {
            self.definitions.remove(pos);
            true
        } else {
            false
        }
    }

    /// Start executing a playbook.
    pub fn start_execution(
        &mut self,
        playbook_id: &str,
        analyst: &str,
        initial_vars: HashMap<String, serde_json::Value>,
    ) -> Result<ExecutionContext, String> {
        let def = self
            .definitions
            .iter()
            .find(|d| d.id == playbook_id && d.status == PlaybookStatus::Active)
            .ok_or_else(|| format!("playbook '{playbook_id}' not found or not active"))?;

        let run_id = format!("run-{}", self.next_run_id);
        self.next_run_id += 1;

        let first_node = def.entry_nodes.first().cloned();

        let ctx = ExecutionContext {
            playbook_id: playbook_id.to_string(),
            run_id: run_id.clone(),
            analyst: analyst.to_string(),
            variables: initial_vars,
            completed_nodes: Vec::new(),
            current_node: first_node,
            status: ExecutionStatus::Running,
            started_at: chrono::Utc::now().to_rfc3339(),
            findings: Vec::new(),
            actions_taken: Vec::new(),
        };
        self.executions.push(ctx.clone());
        Ok(ctx)
    }

    /// Advance execution to the next node.
    pub fn advance_execution(
        &mut self,
        run_id: &str,
        result: Option<String>,
    ) -> Result<ExecutionContext, String> {
        let ctx = self
            .executions
            .iter_mut()
            .find(|e| e.run_id == run_id)
            .ok_or_else(|| format!("execution '{run_id}' not found"))?;

        if ctx.status != ExecutionStatus::Running && ctx.status != ExecutionStatus::WaitingForInput
        {
            return Err(format!("execution '{run_id}' is not in a runnable state"));
        }

        let def = self
            .definitions
            .iter()
            .find(|d| d.id == ctx.playbook_id)
            .ok_or("playbook definition not found")?;

        // Complete current node
        if let Some(current) = ctx.current_node.take() {
            ctx.completed_nodes.push(current.clone());

            // Find the current node definition
            if let Some(node) = def.nodes.iter().find(|n| node_id(n) == current) {
                match node {
                    PlaybookNode::Condition {
                        variable,
                        operator,
                        value,
                        then_branch,
                        else_branch,
                        ..
                    } => {
                        let var_val = ctx.variables.get(variable);
                        let cond_met = evaluate_condition(var_val, operator, value);
                        let branch = if cond_met { then_branch } else { else_branch };
                        ctx.current_node = branch.first().cloned();
                    }
                    PlaybookNode::Action {
                        id,
                        action_type,
                        parameters,
                    } => {
                        ctx.actions_taken.push(ActionRecord {
                            node_id: id.clone(),
                            action_type: action_type.clone(),
                            parameters: parameters.clone(),
                            result: result.clone(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                        // Move to next node in entry order
                        ctx.current_node = find_next_node(def, &ctx.completed_nodes);
                    }
                    _ => {
                        if let Some(r) = &result {
                            ctx.findings.push(r.clone());
                        }
                        ctx.current_node = find_next_node(def, &ctx.completed_nodes);
                    }
                }
            } else {
                ctx.current_node = find_next_node(def, &ctx.completed_nodes);
            }
        }

        // Check if completed
        if ctx.current_node.is_none() {
            ctx.status = ExecutionStatus::Completed;
        }

        Ok(ctx.clone())
    }

    /// Get active executions.
    pub fn active_executions(&self) -> Vec<&ExecutionContext> {
        self.executions
            .iter()
            .filter(|e| {
                matches!(
                    e.status,
                    ExecutionStatus::Running | ExecutionStatus::WaitingForInput
                )
            })
            .collect()
    }

    /// Get execution by run ID.
    pub fn get_execution(&self, run_id: &str) -> Option<&ExecutionContext> {
        self.executions.iter().find(|e| e.run_id == run_id)
    }

    /// Convert a DSL playbook to a static InvestigationWorkflow for compatibility.
    pub fn to_investigation_workflow(&self, id: &str) -> Option<InvestigationWorkflow> {
        let def = self.get(id)?;
        let steps: Vec<InvestigationStep> = def
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(i, node)| match node {
                PlaybookNode::Step {
                    title,
                    description,
                    api_pivot,
                    actions,
                    evidence,
                    auto_queries,
                    ..
                } => Some(InvestigationStep {
                    order: i + 1,
                    title: title.clone(),
                    description: description.clone(),
                    api_pivot: api_pivot.clone(),
                    recommended_actions: actions.clone(),
                    evidence_to_collect: evidence.clone(),
                    auto_queries: auto_queries.clone(),
                }),
                _ => None,
            })
            .collect();

        Some(InvestigationWorkflow {
            id: def.id.clone(),
            name: def.name.clone(),
            description: def.description.clone(),
            trigger_conditions: def.trigger_conditions.clone(),
            severity: def.severity.clone(),
            mitre_techniques: def.mitre_techniques.clone(),
            estimated_minutes: (steps.len() as u32) * 5,
            steps,
            completion_criteria: vec!["All nodes completed".into()],
        })
    }

    /// Suggest playbooks based on alert content.
    pub fn suggest_for_alert(&self, alert_reasons: &[String]) -> Vec<&PlaybookDefinition> {
        let reasons_lower: Vec<String> = alert_reasons.iter().map(|r| r.to_lowercase()).collect();
        self.definitions
            .iter()
            .filter(|d| {
                d.status == PlaybookStatus::Active
                    && d.trigger_conditions.iter().any(|tc| {
                        let tc_lower = tc.to_lowercase();
                        reasons_lower
                            .iter()
                            .any(|r| r.contains(&tc_lower) || tc_lower.contains(r.as_str()))
                    })
            })
            .collect()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn node_id(node: &PlaybookNode) -> &str {
    match node {
        PlaybookNode::Step { id, .. }
        | PlaybookNode::Condition { id, .. }
        | PlaybookNode::Parallel { id, .. }
        | PlaybookNode::ForEach { id, .. }
        | PlaybookNode::Action { id, .. }
        | PlaybookNode::SetVariable { id, .. } => id,
    }
}

fn evaluate_condition(
    var_val: Option<&serde_json::Value>,
    operator: &ConditionOp,
    expected: &serde_json::Value,
) -> bool {
    let val = match var_val {
        Some(v) => v,
        None => return false,
    };

    match operator {
        ConditionOp::Eq => val == expected,
        ConditionOp::Ne => val != expected,
        ConditionOp::Gt => compare_numbers(val, expected).is_some_and(|ord| ord > 0),
        ConditionOp::Gte => compare_numbers(val, expected).is_some_and(|ord| ord >= 0),
        ConditionOp::Lt => compare_numbers(val, expected).is_some_and(|ord| ord < 0),
        ConditionOp::Lte => compare_numbers(val, expected).is_some_and(|ord| ord <= 0),
        ConditionOp::Contains => {
            if let (Some(s), Some(sub)) = (val.as_str(), expected.as_str()) {
                s.contains(sub)
            } else {
                false
            }
        }
        ConditionOp::In => {
            if let Some(arr) = expected.as_array() {
                arr.contains(val)
            } else {
                false
            }
        }
    }
}

fn compare_numbers(a: &serde_json::Value, b: &serde_json::Value) -> Option<i8> {
    let a_f = a.as_f64()?;
    let b_f = b.as_f64()?;
    if a_f > b_f {
        Some(1)
    } else if a_f < b_f {
        Some(-1)
    } else {
        Some(0)
    }
}

fn find_next_node(def: &PlaybookDefinition, completed: &[String]) -> Option<String> {
    // Walk entry_nodes and all node IDs in order, find first uncompleted
    for node in &def.nodes {
        let id = node_id(node);
        if !completed.contains(&id.to_string()) {
            return Some(id.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_playbook() -> PlaybookDefinition {
        PlaybookDefinition {
            id: "test-pb".into(),
            name: "Test Playbook".into(),
            description: "A test dynamic playbook".into(),
            version: "1.0".into(),
            author: "analyst".into(),
            severity: "High".into(),
            mitre_techniques: vec!["T1110".into()],
            trigger_conditions: vec!["credential".into(), "brute_force".into()],
            nodes: vec![
                PlaybookNode::Step {
                    id: "s1".into(),
                    title: "Check accounts".into(),
                    description: "Identify affected accounts".into(),
                    api_pivot: Some("/api/ueba/risky".into()),
                    actions: vec!["List affected users".into()],
                    evidence: vec!["Usernames".into()],
                    auto_queries: vec![],
                },
                PlaybookNode::Condition {
                    id: "c1".into(),
                    variable: "compromised_count".into(),
                    operator: ConditionOp::Gt,
                    value: serde_json::json!(0),
                    then_branch: vec!["s2".into()],
                    else_branch: vec!["s3".into()],
                },
                PlaybookNode::Step {
                    id: "s2".into(),
                    title: "Contain compromise".into(),
                    description: "Block attacking IPs, reset passwords".into(),
                    api_pivot: None,
                    actions: vec!["Block IPs".into(), "Reset passwords".into()],
                    evidence: vec!["Actions taken".into()],
                    auto_queries: vec![],
                },
                PlaybookNode::Step {
                    id: "s3".into(),
                    title: "Close investigation".into(),
                    description: "No compromise found, document findings".into(),
                    api_pivot: None,
                    actions: vec!["Document findings".into()],
                    evidence: vec![],
                    auto_queries: vec![],
                },
            ],
            entry_nodes: vec!["s1".into()],
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            status: PlaybookStatus::Active,
        }
    }

    #[test]
    fn create_and_list_playbooks() {
        let mut store = PlaybookDslStore::new();
        store.create(sample_playbook());
        assert_eq!(store.list().len(), 1);
        assert!(store.get("test-pb").is_some());
    }

    #[test]
    fn start_and_advance_execution() {
        let mut store = PlaybookDslStore::new();
        store.create(sample_playbook());

        let ctx = store
            .start_execution("test-pb", "analyst1", HashMap::new())
            .unwrap();
        assert_eq!(ctx.current_node, Some("s1".into()));
        assert_eq!(ctx.status, ExecutionStatus::Running);

        let ctx = store
            .advance_execution(&ctx.run_id, Some("Found 3 accounts".into()))
            .unwrap();
        assert!(ctx.completed_nodes.contains(&"s1".to_string()));
    }

    #[test]
    fn condition_evaluation() {
        assert!(evaluate_condition(
            Some(&serde_json::json!(5)),
            &ConditionOp::Gt,
            &serde_json::json!(0)
        ));
        assert!(!evaluate_condition(
            Some(&serde_json::json!(0)),
            &ConditionOp::Gt,
            &serde_json::json!(0)
        ));
        assert!(evaluate_condition(
            Some(&serde_json::json!("hello world")),
            &ConditionOp::Contains,
            &serde_json::json!("world")
        ));
    }

    #[test]
    fn lifecycle_transitions() {
        let mut store = PlaybookDslStore::new();
        let mut pb = sample_playbook();
        pb.status = PlaybookStatus::Draft;
        store.create(pb);

        assert!(store.set_status("test-pb", PlaybookStatus::Active));
        assert_eq!(store.get("test-pb").unwrap().status, PlaybookStatus::Active);
    }

    #[test]
    fn suggest_for_alert() {
        let mut store = PlaybookDslStore::new();
        store.create(sample_playbook());

        let suggestions = store.suggest_for_alert(&["credential storm detected".into()]);
        assert_eq!(suggestions.len(), 1);

        let suggestions = store.suggest_for_alert(&["network anomaly".into()]);
        assert_eq!(suggestions.len(), 0);
    }

    #[test]
    fn to_investigation_workflow() {
        let mut store = PlaybookDslStore::new();
        store.create(sample_playbook());

        let wf = store.to_investigation_workflow("test-pb").unwrap();
        assert_eq!(wf.id, "test-pb");
        assert!(!wf.steps.is_empty());
    }
}

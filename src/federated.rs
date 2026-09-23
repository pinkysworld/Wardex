//! Cross-agent federated learning protocol (R27).
//!
//! Extends the in-process differential-privacy primitives in
//! [`crate::privacy`] with a real network protocol for federated averaging
//! between the Wardex server (the *coordinator*) and enrolled agents (the
//! *participants*), running over the existing authenticated agent↔server
//! HTTP channel (see `src/agent_client.rs`, `src/server_agents.rs`).
//!
//! Protocol summary:
//!  1. An operator opens a federation with [`FederationCoordinator::start`],
//!     which opens round 1 against the current global model.
//!  2. Agents poll for the open round (`fetch_round`), train locally on
//!     their own labelled data using a [`FederatedModel`] implementation,
//!     clip the resulting update to an L2-norm bound `C`, and add
//!     Gaussian noise calibrated to the round's `(epsilon, delta)` budget
//!     (see [`clip_and_privatize`]).
//!  3. Agents submit the noised update (`submit_update`); the coordinator
//!     authenticates the caller (handled by the HTTP layer), validates the
//!     submission (shape, round id, norm bound, replay), and charges the
//!     agent's cumulative privacy budget.
//!  4. Once `min_participants` have submitted, or the round deadline has
//!     passed with at least one submission, the coordinator aggregates with
//!     FedAvg weighted by sample count, checks convergence, and either
//!     opens the next round or stops the federation.
//!
//! Threat model and what is *not* protected are documented in
//! `docs/FEDERATED_LEARNING.md`. In particular: secure aggregation is out
//! of scope, so the coordinator sees each agent's individual noised update
//! (not just the aggregate) — only differential privacy noise protects
//! individual training examples from a coordinator that inspects updates.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::privacy::{GaussianMechanism, PrivacyAccountant};

// ── Configuration ────────────────────────────────────────────────────────────

/// Federated-learning configuration. Disabled by default: federation is an
/// opt-in feature that operators must explicitly turn on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Privacy budget (epsilon) spent by each agent for each round it
    /// participates in.
    #[serde(default = "default_epsilon_per_round")]
    pub epsilon_per_round: f64,
    /// Failure probability delta of the Gaussian mechanism.
    #[serde(default = "default_delta")]
    pub delta: f64,
    /// L2-norm clipping bound `C` applied to each agent's local update
    /// before noise is added.
    #[serde(default = "default_clip_norm")]
    pub clip_norm: f64,
    /// Minimum number of agent submissions required before a round can be
    /// aggregated ahead of its deadline.
    #[serde(default = "default_min_participants")]
    pub min_participants: usize,
    /// Wall-clock seconds a round stays open before it is force-aggregated
    /// (with whatever submissions arrived) or abandoned if empty.
    #[serde(default = "default_round_deadline_secs")]
    pub round_deadline_secs: u64,
    /// Hard cap on the number of rounds a federation will run before it
    /// stops, even if convergence was not reached.
    #[serde(default = "default_max_rounds")]
    pub max_rounds: usize,
    /// Convergence threshold: a round is the last one once the L2 norm of
    /// the aggregated parameter delta drops below this value.
    #[serde(default = "default_target_convergence_delta")]
    pub target_convergence_delta: f64,
    /// Total lifetime epsilon budget allotted to each participating agent.
    /// Once exhausted the agent is refused further rounds.
    #[serde(default = "default_total_epsilon_budget")]
    pub total_epsilon_budget_per_agent: f64,
    /// Local SGD epochs an agent should run per round.
    #[serde(default = "default_local_epochs")]
    pub local_epochs: usize,
    /// Local SGD learning rate.
    #[serde(default = "default_learning_rate")]
    pub learning_rate: f64,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            epsilon_per_round: default_epsilon_per_round(),
            delta: default_delta(),
            clip_norm: default_clip_norm(),
            min_participants: default_min_participants(),
            round_deadline_secs: default_round_deadline_secs(),
            max_rounds: default_max_rounds(),
            target_convergence_delta: default_target_convergence_delta(),
            total_epsilon_budget_per_agent: default_total_epsilon_budget(),
            local_epochs: default_local_epochs(),
            learning_rate: default_learning_rate(),
        }
    }
}

fn default_epsilon_per_round() -> f64 {
    1.0
}
fn default_delta() -> f64 {
    1e-5
}
fn default_clip_norm() -> f64 {
    5.0
}
fn default_min_participants() -> usize {
    3
}
fn default_round_deadline_secs() -> u64 {
    3600
}
fn default_max_rounds() -> usize {
    50
}
fn default_target_convergence_delta() -> f64 {
    0.001
}
fn default_total_epsilon_budget() -> f64 {
    20.0
}
fn default_local_epochs() -> usize {
    5
}
fn default_learning_rate() -> f64 {
    0.1
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Generic federated model trait ────────────────────────────────────────────

/// Any model with a flat numeric parameter vector can participate in
/// FedAvg. Implement this trait to plug a model into the federation.
pub trait FederatedModel {
    /// Current parameter vector.
    fn parameters(&self) -> Vec<f64>;
    /// Replace the parameter vector (e.g. with the aggregated global model).
    fn set_parameters(&mut self, params: &[f64]);
    /// Train locally for one round and return the parameter delta plus
    /// bookkeeping (sample count, training loss) that the caller will clip,
    /// privatize, and submit to the coordinator.
    fn local_update(
        &self,
        samples: &[(Vec<f64>, f64)],
        learning_rate: f64,
        epochs: usize,
    ) -> LocalTrainResult;
}

/// Result of one agent's local training pass, before clipping/noising.
#[derive(Debug, Clone)]
pub struct LocalTrainResult {
    /// `new_local_params - global_params_at_round_open`.
    pub weight_delta: Vec<f64>,
    pub sample_count: usize,
    pub loss: f64,
}

/// A logistic-regression anomaly/triage scorer over a fixed-size numeric
/// feature vector (e.g. [`crate::ml_engine::TriageFeatures::to_vec`]). The
/// last weight is the bias term. This is the concrete model FedAvg is
/// implemented against: linear models have parameter vectors that average
/// meaningfully across participants, unlike tree ensembles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogisticRegressionModel {
    /// weights[0..n] are feature weights, weights[n] is the bias.
    pub weights: Vec<f64>,
}

impl LogisticRegressionModel {
    /// Create a zero-initialized model for `feature_dim` input features
    /// (plus one implicit bias weight).
    pub fn new(feature_dim: usize) -> Self {
        Self {
            weights: vec![0.0; feature_dim + 1],
        }
    }

    fn sigmoid(z: f64) -> f64 {
        1.0 / (1.0 + (-z).exp())
    }

    /// Predicted probability of the positive class (e.g. "true positive").
    pub fn predict_proba(&self, x: &[f64]) -> f64 {
        let n = x.len().min(self.weights.len().saturating_sub(1));
        let bias = self.weights.last().copied().unwrap_or(0.0);
        let z: f64 = self.weights[..n]
            .iter()
            .zip(&x[..n])
            .map(|(w, v)| w * v)
            .sum::<f64>()
            + bias;
        Self::sigmoid(z)
    }
}

impl FederatedModel for LogisticRegressionModel {
    fn parameters(&self) -> Vec<f64> {
        self.weights.clone()
    }

    fn set_parameters(&mut self, params: &[f64]) {
        self.weights = params.to_vec();
    }

    fn local_update(
        &self,
        samples: &[(Vec<f64>, f64)],
        learning_rate: f64,
        epochs: usize,
    ) -> LocalTrainResult {
        let dim = self.weights.len();
        let mut w = self.weights.clone();
        let n = samples.len().max(1) as f64;
        let mut last_loss = 0.0;
        for _ in 0..epochs.max(1) {
            let mut grad = vec![0.0; dim];
            let mut loss_sum = 0.0;
            for (x, y) in samples {
                let features = x.len().min(dim.saturating_sub(1));
                let bias = w.last().copied().unwrap_or(0.0);
                let z: f64 = w[..features]
                    .iter()
                    .zip(&x[..features])
                    .map(|(a, b)| a * b)
                    .sum::<f64>()
                    + bias;
                let p = Self::sigmoid(z).clamp(1e-9, 1.0 - 1e-9);
                let err = p - y;
                for (g, xi) in grad.iter_mut().zip(x.iter()).take(features) {
                    *g += err * xi;
                }
                if let Some(last) = grad.last_mut() {
                    *last += err;
                }
                loss_sum += -(y * p.ln() + (1.0 - y) * (1.0 - p).ln());
            }
            for g in &mut grad {
                *g /= n;
            }
            for (wi, gi) in w.iter_mut().zip(grad.iter()) {
                *wi -= learning_rate * gi;
            }
            last_loss = loss_sum / n;
        }
        let weight_delta: Vec<f64> = w
            .iter()
            .zip(self.weights.iter())
            .map(|(a, b)| a - b)
            .collect();
        LocalTrainResult {
            weight_delta,
            sample_count: samples.len(),
            loss: last_loss,
        }
    }
}

// ── Clipping and DP noise (agent-side, run before submission) ───────────────

/// Scale `v` down (never up) so its L2 norm does not exceed `max_norm`.
pub fn clip_l2(v: &mut [f64], max_norm: f64) {
    if max_norm <= 0.0 {
        for x in v.iter_mut() {
            *x = 0.0;
        }
        return;
    }
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > max_norm && norm > 0.0 {
        let scale = max_norm / norm;
        for x in v.iter_mut() {
            *x *= scale;
        }
    }
}

pub fn l2_norm(v: &[f64]) -> f64 {
    v.iter().map(|x| x * x).sum::<f64>().sqrt()
}

/// Clip an update to `clip_norm` and add Gaussian noise calibrated to
/// `(epsilon, delta)` with sensitivity `clip_norm`. This is what an agent
/// runs on its raw `weight_delta` before submitting it to the coordinator.
pub fn clip_and_privatize(update: &[f64], clip_norm: f64, epsilon: f64, delta: f64) -> Vec<f64> {
    let mut clipped = update.to_vec();
    clip_l2(&mut clipped, clip_norm);
    let mechanism = GaussianMechanism::new(epsilon, delta, clip_norm);
    mechanism.privatize_vec(&clipped)
}

// ── Protocol types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RoundStatus {
    Open,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoundHyperparams {
    pub epsilon: f64,
    pub delta: f64,
    pub clip_norm: f64,
    pub learning_rate: f64,
    pub local_epochs: usize,
}

/// A single agent's submission for a round. `params` is the noised, clipped
/// weight delta the agent computed locally — the coordinator only ever sees
/// this noised value, never the agent's raw local data or raw gradient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSubmission {
    pub agent_id: String,
    pub params: Vec<f64>,
    pub sample_count: usize,
    pub loss: f64,
    pub submitted_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationRound {
    pub round_id: u64,
    pub model_version: u64,
    pub global_params: Vec<f64>,
    pub hyperparams: RoundHyperparams,
    pub min_participants: usize,
    pub opened_at_ms: u64,
    pub deadline_ms: u64,
    pub status: RoundStatus,
    #[serde(default)]
    pub submissions: Vec<AgentSubmission>,
}

impl FederationRound {
    fn has_submission_from(&self, agent_id: &str) -> bool {
        self.submissions.iter().any(|s| s.agent_id == agent_id)
    }
}

/// Public, read-only view of a round handed to an agent (identical to
/// [`FederationRound`] minus other agents' submissions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundView {
    pub round_id: u64,
    pub model_version: u64,
    pub global_params: Vec<f64>,
    pub hyperparams: RoundHyperparams,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedRound {
    pub round_id: u64,
    pub model_version: u64,
    pub participants: usize,
    pub total_samples: usize,
    pub convergence_delta: f64,
    pub avg_loss: f64,
    pub closed_at_ms: u64,
}

/// Errors the protocol can reject a submission or fetch with. Every variant
/// maps to a distinct, stable HTTP-facing error code in `server_federated.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FedError {
    Disabled,
    NoOpenRound,
    WrongRound { expected: u64, got: u64 },
    DuplicateSubmission,
    InvalidShape { expected: usize, got: usize },
    NormExceeded { max: String },
    BudgetExhausted,
}

impl FedError {
    pub fn code(&self) -> &'static str {
        match self {
            FedError::Disabled => "federation_disabled",
            FedError::NoOpenRound => "no_open_round",
            FedError::WrongRound { .. } => "wrong_round",
            FedError::DuplicateSubmission => "duplicate_submission",
            FedError::InvalidShape { .. } => "invalid_shape",
            FedError::NormExceeded { .. } => "norm_exceeded",
            FedError::BudgetExhausted => "budget_exhausted",
        }
    }
}

impl std::fmt::Display for FedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FedError::Disabled => write!(f, "federated learning is not enabled"),
            FedError::NoOpenRound => write!(f, "no federation round is currently open"),
            FedError::WrongRound { expected, got } => {
                write!(f, "round mismatch: expected {expected}, got {got}")
            }
            FedError::DuplicateSubmission => {
                write!(f, "this agent already submitted an update for this round")
            }
            FedError::InvalidShape { expected, got } => {
                write!(
                    f,
                    "parameter vector shape mismatch: expected {expected}, got {got}"
                )
            }
            FedError::NormExceeded { max } => {
                write!(f, "submitted update norm exceeds allowed bound ({max})")
            }
            FedError::BudgetExhausted => write!(f, "agent privacy budget exhausted"),
        }
    }
}

// ── Coordinator ───────────────────────────────────────────────────────────────

/// Server-side federated-learning coordinator. Owns the global model,
/// the currently open round (if any), completed-round history, and each
/// agent's cumulative privacy budget. This struct is pure/in-memory;
/// `server_federated.rs` is responsible for persisting/restoring its state
/// via the existing SQLite `config_store` key-value table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationCoordinator {
    pub config: FederationConfig,
    pub running: bool,
    pub model_version: u64,
    pub global_params: Vec<f64>,
    pub current_round: Option<FederationRound>,
    #[serde(default)]
    pub history: Vec<CompletedRound>,
    #[serde(default)]
    pub budgets: HashMap<String, PrivacyAccountant>,
    pub converged: bool,
}

/// Cap on retained round history to bound persisted-state size.
const MAX_HISTORY: usize = 500;

impl FederationCoordinator {
    pub fn new(config: FederationConfig, param_dim: usize) -> Self {
        Self {
            config,
            running: false,
            model_version: 0,
            global_params: vec![0.0; param_dim],
            current_round: None,
            history: Vec::new(),
            budgets: HashMap::new(),
            converged: false,
        }
    }

    /// Start (or restart) a federation from the given initial global
    /// parameters, opening round 1 immediately.
    pub fn start(&mut self, config: FederationConfig, initial_params: Vec<f64>, now: u64) {
        self.config = config;
        self.running = true;
        self.converged = false;
        self.model_version = 0;
        self.global_params = initial_params;
        self.history.clear();
        self.current_round = None;
        self.open_round(now);
    }

    pub fn stop(&mut self) {
        self.running = false;
        self.current_round = None;
    }

    pub fn is_running(&self) -> bool {
        self.running && !self.converged
    }

    fn open_round(&mut self, now: u64) {
        if !self.running || self.converged {
            return;
        }
        if self.history.len() >= self.config.max_rounds {
            self.running = false;
            return;
        }
        let round_id = self.model_version + 1;
        self.current_round = Some(FederationRound {
            round_id,
            model_version: self.model_version,
            global_params: self.global_params.clone(),
            hyperparams: RoundHyperparams {
                epsilon: self.config.epsilon_per_round,
                delta: self.config.delta,
                clip_norm: self.config.clip_norm,
                learning_rate: self.config.learning_rate,
                local_epochs: self.config.local_epochs,
            },
            min_participants: self.config.min_participants,
            opened_at_ms: now,
            deadline_ms: now.saturating_add(self.config.round_deadline_secs.saturating_mul(1000)),
            status: RoundStatus::Open,
            submissions: Vec::new(),
        });
    }

    /// Agent-facing: fetch the currently open round, if the federation is
    /// running and the agent's budget is not exhausted.
    pub fn fetch_round(&self, agent_id: &str) -> Result<RoundView, FedError> {
        if !self.config.enabled || !self.is_running() {
            return Err(FedError::Disabled);
        }
        let round = self.current_round.as_ref().ok_or(FedError::NoOpenRound)?;
        if round.status != RoundStatus::Open {
            return Err(FedError::NoOpenRound);
        }
        // An agent whose remaining budget can no longer cover even one more
        // round's epsilon cost is refused here, not just at submission time
        // — otherwise it would keep polling successfully only to have every
        // submission rejected.
        if let Some(acct) = self.budgets.get(agent_id)
            && acct.budget_remaining() < self.config.epsilon_per_round
        {
            return Err(FedError::BudgetExhausted);
        }
        Ok(RoundView {
            round_id: round.round_id,
            model_version: round.model_version,
            global_params: round.global_params.clone(),
            hyperparams: round.hyperparams.clone(),
            deadline_ms: round.deadline_ms,
        })
    }

    /// Agent-facing: submit a (already clipped + noised) update for a round.
    /// Validates shape, round id, replay, and a generous norm bound (defense
    /// in depth — the agent is expected to have clipped before noising, but
    /// noise can push the observed norm slightly above `clip_norm`).
    pub fn submit_update(
        &mut self,
        agent_id: &str,
        round_id: u64,
        params: Vec<f64>,
        sample_count: usize,
        loss: f64,
        now: u64,
    ) -> Result<(), FedError> {
        if !self.config.enabled || !self.is_running() {
            return Err(FedError::Disabled);
        }
        let expected_dim = self.global_params.len();
        let clip_norm = self.config.clip_norm;
        let epsilon_cost = self.config.epsilon_per_round;

        {
            let round = self.current_round.as_ref().ok_or(FedError::NoOpenRound)?;
            if round.status != RoundStatus::Open {
                return Err(FedError::NoOpenRound);
            }
            if round.round_id != round_id {
                return Err(FedError::WrongRound {
                    expected: round.round_id,
                    got: round_id,
                });
            }
            if round.has_submission_from(agent_id) {
                return Err(FedError::DuplicateSubmission);
            }
            if params.len() != expected_dim {
                return Err(FedError::InvalidShape {
                    expected: expected_dim,
                    got: params.len(),
                });
            }
            // Generous defense-in-depth bound: clipped norm plus a wide
            // multiple of the noise scale so legitimate noised submissions
            // are never rejected, but a wildly out-of-range payload is.
            let mechanism =
                GaussianMechanism::new(self.config.epsilon_per_round, self.config.delta, clip_norm);
            let max_allowed = clip_norm + 12.0 * mechanism.sigma.max(0.001) + 1.0;
            let observed = l2_norm(&params);
            if observed > max_allowed {
                return Err(FedError::NormExceeded {
                    max: format!("{max_allowed:.4}"),
                });
            }
        }

        let accountant = self
            .budgets
            .entry(agent_id.to_string())
            .or_insert_with(|| PrivacyAccountant::new(self.config.total_epsilon_budget_per_agent));
        if !accountant.record_query(epsilon_cost) {
            return Err(FedError::BudgetExhausted);
        }

        if let Some(round) = self.current_round.as_mut() {
            round.submissions.push(AgentSubmission {
                agent_id: agent_id.to_string(),
                params,
                sample_count,
                loss,
                submitted_at_ms: now,
            });
        }
        Ok(())
    }

    /// Returns true if the current round is ready to be aggregated: either
    /// enough participants have submitted, or the deadline has passed and
    /// at least one submission exists.
    pub fn round_ready(&self, now: u64) -> bool {
        let Some(round) = &self.current_round else {
            return false;
        };
        if round.status != RoundStatus::Open {
            return false;
        }
        round.submissions.len() >= round.min_participants
            || (now >= round.deadline_ms && !round.submissions.is_empty())
    }

    /// Aggregate the current round with FedAvg (weighted by sample count),
    /// apply the result to the global model, evaluate convergence, and open
    /// the next round (or stop the federation). Returns `None` if the round
    /// was not ready or there was nothing to aggregate (e.g. deadline
    /// passed with zero submissions — the round is simply re-opened).
    pub fn try_aggregate(&mut self, now: u64) -> Option<CompletedRound> {
        if !self.round_ready(now) {
            // Deadline passed with no submissions at all: re-open a fresh
            // round window so a temporarily offline fleet doesn't stall.
            if let Some(round) = &self.current_round
                && round.status == RoundStatus::Open
                && now >= round.deadline_ms
                && round.submissions.is_empty()
            {
                self.open_round(now);
            }
            return None;
        }
        let round = self.current_round.take()?;
        let total_samples: usize = round.submissions.iter().map(|s| s.sample_count).sum();
        if total_samples == 0 {
            self.open_round(now);
            return None;
        }
        let dim = self.global_params.len();
        let mut aggregated_delta = vec![0.0f64; dim];
        for submission in &round.submissions {
            let weight = submission.sample_count as f64 / total_samples as f64;
            for (i, &v) in submission.params.iter().enumerate() {
                if i < dim {
                    aggregated_delta[i] += v * weight;
                }
            }
        }
        for (g, d) in self.global_params.iter_mut().zip(aggregated_delta.iter()) {
            *g += d;
        }
        self.model_version += 1;
        let convergence_delta = l2_norm(&aggregated_delta);
        let avg_loss =
            round.submissions.iter().map(|s| s.loss).sum::<f64>() / round.submissions.len() as f64;

        let completed = CompletedRound {
            round_id: round.round_id,
            model_version: self.model_version,
            participants: round.submissions.len(),
            total_samples,
            convergence_delta,
            avg_loss,
            closed_at_ms: now,
        };
        self.history.push(completed.clone());
        if self.history.len() > MAX_HISTORY {
            let excess = self.history.len() - MAX_HISTORY;
            self.history.drain(0..excess);
        }

        if convergence_delta < self.config.target_convergence_delta {
            self.converged = true;
            self.running = false;
        } else if self.history.len() >= self.config.max_rounds {
            self.running = false;
        } else {
            self.open_round(now);
        }
        Some(completed)
    }

    pub fn budget_status(&self) -> Vec<(String, f64, f64)> {
        self.budgets
            .iter()
            .map(|(id, acct)| (id.clone(), acct.spent_epsilon, acct.total_epsilon))
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FederationConfig {
        FederationConfig {
            enabled: true,
            epsilon_per_round: 2.0,
            delta: 1e-5,
            clip_norm: 10.0,
            min_participants: 2,
            round_deadline_secs: 3600,
            max_rounds: 20,
            target_convergence_delta: 0.05,
            total_epsilon_budget_per_agent: 100.0,
            local_epochs: 5,
            learning_rate: 0.5,
        }
    }

    // ── clipping / noise calibration ────────────────────────────────────────

    #[test]
    fn clip_l2_scales_down_over_bound() {
        let mut v = vec![3.0, 4.0]; // norm 5
        clip_l2(&mut v, 2.5);
        assert!((l2_norm(&v) - 2.5).abs() < 1e-9);
    }

    #[test]
    fn clip_l2_leaves_under_bound_unchanged() {
        let mut v = vec![1.0, 1.0];
        let original = v.clone();
        clip_l2(&mut v, 10.0);
        assert_eq!(v, original);
    }

    #[test]
    fn clip_and_privatize_bounds_then_adds_noise() {
        let update = vec![100.0, 100.0, 100.0];
        let privatized = clip_and_privatize(&update, 5.0, 1.0, 1e-5);
        assert_eq!(privatized.len(), update.len());
        // The clipped-but-unnoised vector would have norm 5; noise should
        // move individual coordinates away from an exact uniform split.
        assert_ne!(privatized, vec![5.0 / 3f64.sqrt(); 3]);
    }

    #[test]
    fn noise_calibration_scales_with_epsilon() {
        let tight = GaussianMechanism::new(0.1, 1e-5, 5.0);
        let loose = GaussianMechanism::new(10.0, 1e-5, 5.0);
        assert!(tight.sigma > loose.sigma);
    }

    // ── aggregation math ──────────────────────────────────────────────────

    #[test]
    fn fedavg_weights_by_sample_count() {
        let mut coord = FederationCoordinator::new(cfg(), 2);
        coord.start(cfg(), vec![0.0, 0.0], 1000);
        let round_id = coord.current_round.as_ref().unwrap().round_id;

        coord
            .submit_update("agent-a", round_id, vec![10.0, 0.0], 300, 0.1, 1001)
            .unwrap();
        coord
            .submit_update("agent-b", round_id, vec![0.0, 10.0], 100, 0.1, 1002)
            .unwrap();

        let completed = coord.try_aggregate(1003).unwrap();
        assert_eq!(completed.participants, 2);
        assert_eq!(completed.total_samples, 400);
        // Weighted average: 0.75*[10,0] + 0.25*[0,10] = [7.5, 2.5]
        assert!((coord.global_params[0] - 7.5).abs() < 1e-9);
        assert!((coord.global_params[1] - 2.5).abs() < 1e-9);
    }

    #[test]
    fn aggregation_waits_for_min_participants() {
        let mut coord = FederationCoordinator::new(cfg(), 2);
        coord.start(cfg(), vec![0.0, 0.0], 1000);
        let round_id = coord.current_round.as_ref().unwrap().round_id;
        coord
            .submit_update("agent-a", round_id, vec![1.0, 1.0], 10, 0.1, 1001)
            .unwrap();
        assert!(coord.try_aggregate(1002).is_none());
        assert!(coord.current_round.is_some());
    }

    #[test]
    fn aggregation_proceeds_at_deadline_with_partial_participants() {
        let mut config = cfg();
        config.round_deadline_secs = 10;
        let mut coord = FederationCoordinator::new(config.clone(), 2);
        coord.start(config, vec![0.0, 0.0], 1000);
        let round_id = coord.current_round.as_ref().unwrap().round_id;
        coord
            .submit_update("agent-a", round_id, vec![2.0, 2.0], 10, 0.1, 1001)
            .unwrap();
        // Deadline is opened_at(1000) + 10_000ms = 11000
        assert!(coord.try_aggregate(11500).is_some());
    }

    #[test]
    fn convergence_detected_and_federation_stops() {
        let mut config = cfg();
        config.target_convergence_delta = 100.0; // trivially satisfied
        let mut coord = FederationCoordinator::new(config.clone(), 2);
        coord.start(config, vec![0.0, 0.0], 1000);
        let round_id = coord.current_round.as_ref().unwrap().round_id;
        coord
            .submit_update("agent-a", round_id, vec![1.0, 1.0], 10, 0.1, 1001)
            .unwrap();
        coord
            .submit_update("agent-b", round_id, vec![1.0, 1.0], 10, 0.1, 1002)
            .unwrap();
        coord.try_aggregate(1003).unwrap();
        assert!(coord.converged);
        assert!(!coord.is_running());
    }

    // ── protocol validation ───────────────────────────────────────────────

    #[test]
    fn rejects_wrong_round_id() {
        let mut coord = FederationCoordinator::new(cfg(), 2);
        coord.start(cfg(), vec![0.0, 0.0], 1000);
        let err = coord
            .submit_update("agent-a", 999, vec![1.0, 1.0], 10, 0.1, 1001)
            .unwrap_err();
        assert_eq!(err.code(), "wrong_round");
    }

    #[test]
    fn rejects_bad_shape() {
        let mut coord = FederationCoordinator::new(cfg(), 2);
        coord.start(cfg(), vec![0.0, 0.0], 1000);
        let round_id = coord.current_round.as_ref().unwrap().round_id;
        let err = coord
            .submit_update("agent-a", round_id, vec![1.0], 10, 0.1, 1001)
            .unwrap_err();
        assert_eq!(err.code(), "invalid_shape");
    }

    #[test]
    fn rejects_duplicate_submission() {
        let mut coord = FederationCoordinator::new(cfg(), 2);
        coord.start(cfg(), vec![0.0, 0.0], 1000);
        let round_id = coord.current_round.as_ref().unwrap().round_id;
        coord
            .submit_update("agent-a", round_id, vec![1.0, 1.0], 10, 0.1, 1001)
            .unwrap();
        let err = coord
            .submit_update("agent-a", round_id, vec![1.0, 1.0], 10, 0.1, 1002)
            .unwrap_err();
        assert_eq!(err.code(), "duplicate_submission");
    }

    #[test]
    fn rejects_norm_exceeding_submission() {
        let mut coord = FederationCoordinator::new(cfg(), 2);
        coord.start(cfg(), vec![0.0, 0.0], 1000);
        let round_id = coord.current_round.as_ref().unwrap().round_id;
        let err = coord
            .submit_update("agent-a", round_id, vec![1e6, 1e6], 10, 0.1, 1001)
            .unwrap_err();
        assert_eq!(err.code(), "norm_exceeded");
    }

    #[test]
    fn refuses_participation_when_budget_exhausted() {
        let mut config = cfg();
        config.total_epsilon_budget_per_agent = 1.0; // less than one round's cost
        let mut coord = FederationCoordinator::new(config.clone(), 2);
        coord.start(config, vec![0.0, 0.0], 1000);
        let round_id = coord.current_round.as_ref().unwrap().round_id;
        let err = coord
            .submit_update("agent-a", round_id, vec![1.0, 1.0], 10, 0.1, 1001)
            .unwrap_err();
        assert_eq!(err.code(), "budget_exhausted");
        // fetch_round should now also refuse this agent.
        assert!(coord.fetch_round("agent-a").is_err());
    }

    #[test]
    fn disabled_federation_refuses_everything() {
        let mut config = cfg();
        config.enabled = false;
        let coord = FederationCoordinator::new(config, 2);
        assert!(matches!(
            coord.fetch_round("agent-a"),
            Err(FedError::Disabled)
        ));
    }

    // ── multi-participant convergence simulation ───────────────────────────

    #[test]
    fn multi_participant_simulation_converges_on_separable_data() {
        // Synthetic linearly separable dataset split across 4 simulated
        // agents: label = 1 if x0 + x1 > 0 else 0, plus small per-agent
        // noise in the features so no single agent sees the whole picture.
        fn make_agent_data(seed: u64, n: usize) -> Vec<(Vec<f64>, f64)> {
            let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut next = || {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                // Top 53 bits give a uniform value in [0, 1); keep the full
                // mantissa's worth of entropy rather than truncating to
                // `u32`, which would bias the sample toward negative values.
                (((state >> 11) as f64) / (1u64 << 53) as f64) * 4.0 - 2.0
            };
            (0..n)
                .map(|_| {
                    let x0 = next();
                    let x1 = next();
                    let label = if x0 + x1 > 0.0 { 1.0 } else { 0.0 };
                    (vec![x0, x1], label)
                })
                .collect()
        }

        let mut config = cfg();
        config.min_participants = 4;
        config.clip_norm = 20.0;
        config.epsilon_per_round = 50.0; // large epsilon -> small noise, for a deterministic-ish test
        config.delta = 1e-3;
        config.max_rounds = 30;
        config.target_convergence_delta = 1e-6; // force it to run to max_rounds/measure accuracy instead
        config.local_epochs = 10;
        config.learning_rate = 0.3;

        let model = LogisticRegressionModel::new(2);
        let mut coord = FederationCoordinator::new(config.clone(), model.parameters().len());
        coord.start(config.clone(), model.parameters(), 0);

        let agents: Vec<Vec<(Vec<f64>, f64)>> =
            (0..4).map(|i| make_agent_data(i + 1, 200)).collect();

        let mut current_global = LogisticRegressionModel::new(2);
        for round_num in 0..config.max_rounds {
            let Some(round) = coord.current_round.clone() else {
                break;
            };
            current_global.set_parameters(&round.global_params);
            let now = (round_num as u64 + 1) * 1000;
            for (i, data) in agents.iter().enumerate() {
                let result = current_global.local_update(
                    data,
                    round.hyperparams.learning_rate,
                    round.hyperparams.local_epochs,
                );
                let privatized = clip_and_privatize(
                    &result.weight_delta,
                    round.hyperparams.clip_norm,
                    round.hyperparams.epsilon,
                    round.hyperparams.delta,
                );
                let _ = coord.submit_update(
                    &format!("agent-{i}"),
                    round.round_id,
                    privatized,
                    result.sample_count,
                    result.loss,
                    now,
                );
            }
            coord.try_aggregate(now + 1);
            if coord.converged {
                break;
            }
        }

        // Evaluate the final global model against held-out separable data.
        let mut final_model = LogisticRegressionModel::new(2);
        final_model.set_parameters(&coord.global_params);
        let test_set = make_agent_data(999, 200);
        let correct = test_set
            .iter()
            .filter(|(x, y)| {
                let pred = if final_model.predict_proba(x) > 0.5 {
                    1.0
                } else {
                    0.0
                };
                (pred - y).abs() < 1e-9
            })
            .count();
        let accuracy = correct as f64 / test_set.len() as f64;
        assert!(
            accuracy > 0.75,
            "federated model should learn the separable boundary, got accuracy {accuracy}"
        );
    }
}

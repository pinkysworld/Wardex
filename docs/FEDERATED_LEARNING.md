# Federated Learning

Wardex supports cross-agent federated learning: enrolled agents train a
shared anomaly/triage model on their own local, labelled data and
periodically contribute a differentially-private update to a global model
hosted by the server, without ever sending raw telemetry or training
examples off the agent's host.

This document describes the protocol, the privacy accounting, and — just
as importantly — what is **not** protected.

Implementation: `src/federated.rs` (protocol + model + DP clipping/noise),
`src/server_federated.rs` (HTTP handlers), `src/privacy.rs` (differential
privacy primitives). Disabled by default (`config.federation.enabled =
false`); see `FederationConfig` for tunables.

## Roles

- **Coordinator** (the Wardex server): opens rounds, aggregates updates,
  tracks per-agent privacy budget, persists round/model history.
- **Participants** (enrolled agents): poll for the open round, train
  locally, clip and noise their update, and submit it.

There is no peer-to-peer communication between agents; everything goes
over the existing authenticated agent↔server HTTP channel used for
enrollment, heartbeats, and policy distribution (`src/agent_client.rs`,
`src/server_agents.rs`). Federation endpoints use the per-agent
`X-Wardex-Agent-Id` / `X-Wardex-Agent-Token` identity issued at enrollment
— see `is_federation_agent_route` in `src/server_routing.rs` and
`agent_request_bound_to_agent` in `src/server_core_helpers.rs`. Unlike
other agent routes, the federation routes **always** require this
per-agent binding: the shared `WARDEX_AGENT_TOKEN` and mTLS client
certificates are not accepted on their own, because they do not bind a
specific agent id and would let one caller claim arbitrarily many
identities (Sybil) to bypass duplicate-submission and budget checks or to
fill `min_participants`.

## Model

The federation trains a **logistic-regression scorer**
(`LogisticRegressionModel` in `src/federated.rs`) over the same numeric
feature vector already used for ML triage
(`crate::ml_engine::TriageFeatures::to_vec`, 7 features) plus one bias
weight — 8 parameters total. A linear model was chosen deliberately: its
parameter vector averages meaningfully across participants (FedAvg is a
weighted mean of parameter vectors), unlike the coefficients of tree
ensembles (`RandomForest`, `GradientBoostedClassifier` in
`src/ml_engine.rs`), which do not.

Any model can participate by implementing the generic trait:

```rust
pub trait FederatedModel {
    fn parameters(&self) -> Vec<f64>;
    fn set_parameters(&mut self, params: &[f64]);
    fn local_update(&self, samples: &[(Vec<f64>, f64)], learning_rate: f64, epochs: usize) -> LocalTrainResult;
}
```

## Protocol

1. **Start.** An operator calls `POST /api/federation/start` (admin,
   `Permission::ManageAgents`). The coordinator resets the global model to
   zero-initialized parameters and opens round 1.
2. **Fetch.** An agent polls `GET /api/federation/round`. If a round is
   open and the agent's cumulative privacy budget is not exhausted, it
   receives the round id, the current global parameters, and the round's
   hyperparameters (`epsilon`, `delta`, `clip_norm`, `learning_rate`,
   `local_epochs`). A 204 means "nothing to do right now" (federation
   disabled, not running, or no round open).
3. **Local training.** The agent runs `local_update` against its own
   labelled examples for `local_epochs` epochs of SGD, producing a
   parameter delta (`new_local_params - global_params`).
4. **Clip + noise.** The agent calls
   `clip_and_privatize(delta, clip_norm, epsilon, delta_param)`, which:
   - clips the delta's L2 norm to `clip_norm` (`C`) — this bounds the
     per-round sensitivity of any single agent's contribution;
   - adds i.i.d. Gaussian noise with `sigma = C * sqrt(2 * ln(1.25/δ)) /
     ε` to every coordinate (the classical (ε, δ)-Gaussian mechanism —
     `GaussianMechanism` in `src/privacy.rs`).
5. **Submit.** `POST /api/federation/round/submit` with `{round_id,
   params, sample_count, loss}`. The coordinator:
   - authenticates the request via the per-agent enrollment credential
     bound to the claimed agent id (enforced in `src/server.rs` before
     the handler runs, and re-checked by the handler);
   - validates the round id (rejects stale/future rounds), the vector
     shape, that every value is finite, a generous norm bound (clip norm
     plus a wide multiple of the noise scale — defense in depth against a
     corrupted/malicious payload, not a privacy control), rejects a
     `sample_count` above `max_sample_count_per_update` (default 100 000;
     `sample_count_exceeded`), and rejects a second submission from the
     same agent in the same round (replay/duplicate);
   - charges the agent's cumulative epsilon budget for the round; refuses
     with `budget_exhausted` if that would exceed the agent's lifetime
     allowance.
6. **Aggregate.** Once `min_participants` agents have submitted, or the
   round's deadline passes with at least one submission, the coordinator
   computes FedAvg — the sample-count-weighted mean of submitted deltas —
   and adds it to the global model. Weights are computed in floating
   point from the (clamped) sample counts, and with two or more
   participants no single agent's weight may exceed
   `max_agent_weight_share` (default 0.5); excess weight is redistributed
   to the other participants in proportion to their sample counts, and if
   the cap cannot be met (`participants × cap < 1`) equal weights are used.
   This bounds how far one agent that over-reports its sample count can
   pull the model in a round, at the cost of under-weighting an agent
   that genuinely holds most of the data; set the cap to `1.0` to restore
   plain FedAvg. If the aggregate (or the resulting global model) is not
   finite, the round's submissions are discarded and the round is
   re-opened on the unchanged model. If the deadline passes with **zero**
   submissions, the round is simply re-opened with a fresh deadline
   (a temporarily offline fleet does not stall the federation).
7. **Convergence.** The L2 norm of the aggregated delta is the
   convergence signal. Once it drops below
   `target_convergence_delta`, the federation marks itself converged and
   stops. It also stops after `max_rounds` regardless of convergence.
8. **Status / history.** `GET /api/federation/status` and
   `GET /api/federation/rounds` (admin, `Permission::ViewAgents`) expose
   the current round, model version, convergence state, and per-agent
   budget spend for observability.

## Privacy accounting

Each agent has a `PrivacyAccountant` (`src/privacy.rs`) tracking
cumulative epsilon spend against `total_epsilon_budget_per_agent`. Every
*accepted* submission costs that round's `epsilon_per_round`; an agent
that has exhausted its budget is refused at both `fetch_round` and
`submit_update`. Budgets are per-agent, not global, so one heavy
participant cannot exhaust the model's usefulness for others, and
operators can see exactly how much privacy loss each agent has accrued
via `GET /api/federation/status`.

The privacy unit of protection here is **the individual training
example**: an agent's noised update is a linear function of its local
gradient (a sum over its own examples), so the Gaussian mechanism, applied
with sensitivity equal to the clip norm, gives each agent's whole local
dataset (ε, δ)-differential privacy for that round under the standard
Gaussian-mechanism composition. Composing epsilon by simple summation
across rounds (as this implementation does) is deliberately conservative;
operators who need tighter multi-round composition bounds (e.g. via
Rényi DP accounting) should track `total_epsilon_budget_per_agent`
correspondingly tighter, since Wardex does not currently implement
advanced composition.

## Threat model — what this protects

- **A coordinator that only stores/observes updates** cannot recover an
  individual agent's raw training examples: it only ever sees a
  norm-clipped, Gaussian-noised aggregate direction, calibrated to a
  known (ε, δ) budget.
- **Replay / duplicate submission** for a round is rejected.
- **Stale or forged round ids** are rejected (an agent cannot submit
  against a round that is not the one currently open).
- **A malformed or extreme payload** (wrong dimension, non-finite values,
  wildly out-of-range norm) is rejected before it can corrupt the global
  model.
- **Unbounded privacy loss** from one agent's continued participation is
  bounded by its per-agent lifetime budget.
- **Unauthenticated or unbound submissions** are rejected: the agent id
  must name a registered agent and the presented per-agent token must
  belong to it (enforced in `src/server.rs` and again in
  `src/server_federated.rs`). An agent cannot submit, or spend budget,
  under another agent's id, and only registered agents can create
  budget-ledger entries.

## Threat model — what this does **not** protect

- **Secure aggregation is out of scope.** The coordinator sees each
  agent's individual noised update, not just the sum. A coordinator
  operator (or anyone who compromises the coordinator process or its
  storage) can inspect any single agent's submitted (noised) parameter
  vector. Only the differential-privacy noise — not cryptographic
  aggregation — stands between that observation and the agent's raw
  local data. `src/privacy.rs` includes a `SecureAggregator`
  (mask-based secure aggregation) that is *not* wired into this protocol;
  integrating it so the coordinator only ever sees the sum is a natural
  next step for a stronger threat model, and would remove the need for
  per-round DP noise against the coordinator (though not against an
  agent colluding with the coordinator, or a compromised coordinator that
  can also see the pre-aggregation shares from participants it colludes
  with).
- **A malicious or compromised agent** can submit an arbitrary vector
  within the accepted shape/norm bounds — nothing here defends against a
  poisoning attack from a fully authenticated, budget-having agent. There
  is no Byzantine-robust aggregation (e.g. coordinate-wise median,
  trimmed mean); FedAvg is a weighted mean. The per-update sample-count
  limit and the per-agent weight-share cap bound, but do not remove, a
  single malicious agent's influence: with the default cap it can still
  contribute up to half of a round's aggregate direction (within the
  norm bound).
- **A coordinator that colludes with, or is, an attacker** learns
  everything an honest coordinator learns (individual noised updates) and
  can additionally choose to skip aggregation, replay stale rounds to a
  single victim agent to average out its noise across repeated queries,
  or otherwise deviate from the protocol as specified. There is no
  attestation that the coordinator is running the code described here.
- **Membership inference / property inference on the aggregate** across
  many rounds is only bounded by cumulative epsilon (see the composition
  caveat above), not eliminated. A very large lifetime budget provides
  little practical protection even though it is technically "accounted
  for."
- **Model-quality attacks that stay within budget** (e.g. an agent that
  trains on adversarially constructed local data to shift the decision
  boundary) are not detected; this protocol validates protocol-shape
  properties (round id, vector shape, norm bound, replay), not the
  semantic validity of a submission.

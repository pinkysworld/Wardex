//! End-to-end federated-learning protocol test: a real HTTP server plus
//! three simulated agent "clients" that enroll, poll for rounds, train
//! locally on a synthetic separable dataset, clip + privatize their
//! update, and submit it — driving the federation to convergence over the
//! real network stack (not the in-process simulation covered by the unit
//! tests in `src/federated.rs`).

mod common;
use common::*;
use wardex::federated::{
    FederatedModel, FederationConfig, LogisticRegressionModel, RoundView, clip_and_privatize,
};

struct EnrolledAgent {
    agent_id: String,
    agent_token: String,
    data: Vec<(Vec<f64>, f64)>,
}

fn enroll_agent(port: u16, admin_token: &str, hostname: &str) -> EnrolledAgent {
    let created: serde_json::Value = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Authorization", &auth_header(admin_token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"max_uses":1}"#)
        .unwrap_or_else(|e| panic!("create enrollment token: {e}"))
        .into_json()
        .unwrap_or_else(|e| panic!("enrollment token json: {e}"));
    let enrollment_token = created["token"]
        .as_str()
        .unwrap_or_else(|| panic!("missing enrollment token"))
        .to_string();

    let enrolled: serde_json::Value = ureq::post(&format!("{}/api/agents/enroll", base(port)))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "enrollment_token": enrollment_token,
                "hostname": hostname,
                "platform": "linux",
                "version": "1.0.0",
            })
            .to_string(),
        )
        .unwrap_or_else(|e| panic!("enroll agent: {e}"))
        .into_json()
        .unwrap_or_else(|e| panic!("enroll response json: {e}"));

    let agent_id = enrolled["agent_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing agent_id"))
        .to_string();
    let agent_token = enrolled["agent_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    EnrolledAgent {
        agent_id,
        agent_token,
        data: Vec::new(),
    }
}

/// Deterministic pseudo-random linearly separable dataset: label = 1 iff
/// x0 + x1 > 0. Padded to the 7-feature `TriageFeatures` shape used by the
/// server's built-in federation model (extra dimensions held at 0).
fn synthetic_dataset(seed: u64, n: usize) -> Vec<(Vec<f64>, f64)> {
    let mut state = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // Top 53 bits give a uniform value in [0, 1); keep the full
        // mantissa's worth of entropy rather than truncating to `u32`,
        // which would bias the sample toward negative values.
        (((state >> 11) as f64) / (1u64 << 53) as f64) * 4.0 - 2.0
    };
    (0..n)
        .map(|_| {
            let x0 = next();
            let x1 = next();
            let label = if x0 + x1 > 0.0 { 1.0 } else { 0.0 };
            (vec![x0, x1, 0.0, 0.0, 0.0, 0.0, 0.0], label)
        })
        .collect()
}

fn fetch_round(port: u16, agent: &EnrolledAgent) -> Option<RoundView> {
    let resp = ureq::get(&format!("{}/api/federation/round", base(port)))
        .set("X-Wardex-Agent-Id", &agent.agent_id)
        .set("X-Wardex-Agent-Token", &agent.agent_token)
        .call()
        .unwrap_or_else(|e| panic!("fetch round: {e}"));
    if resp.status() == 204 {
        return None;
    }
    Some(
        resp.into_json()
            .unwrap_or_else(|e| panic!("round view json: {e}")),
    )
}

#[test]
fn federation_lifecycle_start_train_submit_aggregate_status() {
    let (port, admin_token) = spawn_test_server();

    let mut agents: Vec<EnrolledAgent> = (0..3)
        .map(|i| enroll_agent(port, &admin_token, &format!("fed-agent-{i}")))
        .collect();
    for (i, agent) in agents.iter_mut().enumerate() {
        agent.data = synthetic_dataset(i as u64 + 1, 150);
    }

    // Start the federation with a config tuned for a fast, near-deterministic
    // test: few rounds (each round is 3 real HTTP submissions, and the test
    // server's write-rate limiter caps writes per minute), a generous
    // epsilon (small noise) for stability, and a convergence target that is
    // reachable within the round budget.
    let config = FederationConfig {
        enabled: true,
        epsilon_per_round: 80.0, // large epsilon -> small noise, for test stability
        delta: 1e-3,
        clip_norm: 8.0,
        min_participants: 3,
        round_deadline_secs: 3600,
        max_rounds: 8,
        target_convergence_delta: 0.05,
        total_epsilon_budget_per_agent: 100_000.0,
        local_epochs: 8,
        learning_rate: 0.3,
    };
    let start_resp: serde_json::Value = ureq::post(&format!("{}/api/federation/start", base(port)))
        .set("Authorization", &auth_header(&admin_token))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({ "config": config }).to_string())
        .unwrap_or_else(|e| panic!("start federation: {e}"))
        .into_json()
        .unwrap_or_else(|e| panic!("start response json: {e}"));
    assert_eq!(start_resp["status"], "started");

    // Drive rounds until convergence/max_rounds, exactly as three real
    // agents polling and submitting would.
    for _ in 0..config.max_rounds {
        let mut model = LogisticRegressionModel::new(7);
        let mut submitted_any = false;
        for agent in &agents {
            let Some(round) = fetch_round(port, agent) else {
                continue;
            };
            model.set_parameters(&round.global_params);
            let result = model.local_update(
                &agent.data,
                round.hyperparams.learning_rate,
                round.hyperparams.local_epochs,
            );
            let privatized = clip_and_privatize(
                &result.weight_delta,
                round.hyperparams.clip_norm,
                round.hyperparams.epsilon,
                round.hyperparams.delta,
            );
            let resp = ureq::post(&format!("{}/api/federation/round/submit", base(port)))
                .set("X-Wardex-Agent-Id", &agent.agent_id)
                .set("X-Wardex-Agent-Token", &agent.agent_token)
                .set("Content-Type", "application/json")
                .send_string(
                    &serde_json::json!({
                        "round_id": round.round_id,
                        "params": privatized,
                        "sample_count": result.sample_count,
                        "loss": result.loss,
                    })
                    .to_string(),
                )
                .unwrap_or_else(|e| panic!("submit update: {e}"));
            assert_eq!(resp.status(), 200);
            submitted_any = true;
        }
        if !submitted_any {
            break; // federation converged/stopped and closed its last round
        }
    }

    let status: serde_json::Value = ureq::get(&format!("{}/api/federation/status", base(port)))
        .set("Authorization", &auth_header(&admin_token))
        .call()
        .unwrap_or_else(|e| panic!("status: {e}"))
        .into_json()
        .unwrap_or_else(|e| panic!("status json: {e}"));
    assert!(status["model_version"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(status["agent_budgets"].as_array().map(|a| a.len()), Some(3));

    let rounds: serde_json::Value = ureq::get(&format!("{}/api/federation/rounds", base(port)))
        .set("Authorization", &auth_header(&admin_token))
        .call()
        .unwrap_or_else(|e| panic!("rounds: {e}"))
        .into_json()
        .unwrap_or_else(|e| panic!("rounds json: {e}"));
    assert!(rounds["total"].as_u64().unwrap_or(0) >= 1);

    // Stop the federation; subsequent round fetches should 204.
    let stop = ureq::post(&format!("{}/api/federation/stop", base(port)))
        .set("Authorization", &auth_header(&admin_token))
        .call()
        .unwrap_or_else(|e| panic!("stop: {e}"));
    assert_eq!(stop.status(), 200);
    assert!(fetch_round(port, &agents[0]).is_none());
}

#[test]
fn federation_round_endpoints_require_agent_identity() {
    let (port, _admin_token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/federation/round", base(port))).call();
    match resp {
        Ok(r) => assert_eq!(r.status(), 401),
        Err(ureq::Error::Status(status, _)) => assert_eq!(status, 401),
        Err(e) => panic!("unexpected transport error: {e}"),
    }
}

#[test]
fn federation_admin_endpoints_require_bearer_auth() {
    let (port, _admin_token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/federation/start", base(port))).send_string("{}");
    match resp {
        Ok(r) => assert_eq!(r.status(), 401),
        Err(ureq::Error::Status(status, _)) => assert_eq!(status, 401),
        Err(e) => panic!("unexpected transport error: {e}"),
    }
}

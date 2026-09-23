//! Regression test for `POST /api/ml/train` after refactoring it to run the
//! actual `RandomForest::train` computation off the global AppState lock
//! (see `src/server_ml.rs::handle_ml_train`). Confirms both the
//! insufficient-data fallback and the trained-and-persisted path still work
//! end to end through the HTTP API.

mod common;
use common::*;

#[test]
fn ml_train_reports_insufficient_data_without_feedback() {
    let (port, token) = spawn_test_server();

    let outcome: serde_json::Value = ureq::post(&format!("{}/api/ml/train", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("train call")
        .into_json()
        .unwrap();
    assert_eq!(outcome["trained"].as_bool(), Some(false));
    assert!(outcome["reason"].as_str().unwrap().contains("insufficient"));

    let status: serde_json::Value = ureq::get(&format!("{}/api/ml/train/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("train status")
        .into_json()
        .unwrap();
    assert_eq!(status["trained"].as_bool(), Some(false));
}

#[test]
fn ml_train_trains_and_persists_forest_with_enough_labelled_feedback() {
    let (port, token) = spawn_test_server();
    // Just over `ml_engine::DEFAULT_MIN_TRAINING_SAMPLES` (50), while staying
    // under the test server's write rate limit (60/min shared across all
    // POSTs this test makes: enroll + event ingest + one feedback POST per
    // event + the train call itself).
    let (_agent_id, event_ids) = setup_agent_with_events(port, &token, "ml-train-host", 52);

    // Alternate true/false-positive verdicts across the seeded events so
    // both classes are represented and the sample-count threshold is met.
    for (i, event_id) in event_ids.iter().enumerate() {
        let state = if i % 2 == 0 {
            "true_positive"
        } else {
            "false_positive"
        };
        let _ = ureq::post(&format!("{}/api/alerts/feedback", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "event_id": event_id,
                // `rule_id` is required for this to be recorded as
                // per-event detection feedback (rather than only the
                // legacy fingerprint-keyed FP feedback), which is what
                // `POST /api/ml/train`'s training-set builder reads.
                "rule_id": "ml-train-test-rule",
                "state": state,
                "analyst": "ml-train-test"
            }))
            .expect("record feedback");
    }

    let outcome: serde_json::Value = ureq::post(&format!("{}/api/ml/train", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("train call")
        .into_json()
        .unwrap();
    assert_eq!(outcome["trained"].as_bool(), Some(true));
    assert!(outcome["metrics"].is_object());

    let status: serde_json::Value = ureq::get(&format!("{}/api/ml/train/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("train status")
        .into_json()
        .unwrap();
    assert_eq!(status["trained"].as_bool(), Some(true));
}

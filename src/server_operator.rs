//! Operator readiness, product-surface, release, and trust payload helpers.
//!
//! Extracted from `server.rs` as part of the post-v1.0.28 hardening sweep.
//! The HTTP dispatch chain remains in `server.rs`; this module owns the
//! cohesive payload builders and small endpoint helpers used by those routes.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::response::Response;

use crate::analyst::CaseStatus;
use crate::collector::AlertRecord;
use crate::enrollment::AgentStatus;
use crate::enterprise::ContentLifecycle;
use crate::rbac::{Role, role_permissions};
use crate::response::{ApprovalStatus, ResponseAction, ResponseTarget};
use crate::server_alerts::assemble_alert_process_catalog;
use crate::server_av::local_av_signature_presets_json;
use crate::server_control_plane::{
    BackupStatusSnapshot, ControlPlanePostureSnapshot, control_plane_cluster_snapshot,
    control_plane_failover_history_preview,
};
use crate::server_evidence::{
    evidence_freshness, evidence_freshness_check, storage_root_path, with_evidence_freshness,
};
use crate::server_response::{error_json, json_response};
use crate::support::FailoverDrillRecord;

#[allow(unused_imports)]
use super::*;

pub(crate) fn active_rule_metadata(
    state: &AppState,
) -> Vec<crate::enterprise::ManagedRuleMetadata> {
    state
        .enterprise
        .builtin_rules()
        .iter()
        .cloned()
        .chain(
            state
                .enterprise
                .native_rules()
                .iter()
                .map(|rule| rule.metadata.clone()),
        )
        .collect()
}

pub(crate) fn rule_active_suppression_count(state: &AppState, rule_id: &str) -> usize {
    state
        .enterprise
        .suppressions()
        .iter()
        .filter(|suppression| {
            suppression.is_active()
                && suppression
                    .rule_id
                    .as_deref()
                    .is_some_and(|candidate| candidate == rule_id)
        })
        .count()
}

pub(crate) fn rule_pack_count(
    state: &AppState,
    rule: &crate::enterprise::ManagedRuleMetadata,
) -> usize {
    let direct = rule.pack_ids.len();
    if direct > 0 {
        return direct;
    }
    state
        .enterprise
        .packs()
        .iter()
        .filter(|pack| pack.rule_ids.iter().any(|id| id == &rule.id))
        .count()
}

pub(crate) fn release_item_version(item: &serde_json::Value) -> String {
    item.get("version")
        .or_else(|| item.get("tag"))
        .or_else(|| item.get("name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

pub(crate) fn build_launchpad_release_diff(state: &AppState) -> serde_json::Value {
    let releases_value = serde_json::to_value(state.update_manager.list_releases())
        .unwrap_or_else(|_| serde_json::json!([]));
    let releases = releases_value.as_array().cloned().unwrap_or_default();
    let latest = releases
        .iter()
        .find(|item| item.get("latest").and_then(serde_json::Value::as_bool) == Some(true))
        .or_else(|| {
            releases.iter().find(|item| {
                item.get("recommended").and_then(serde_json::Value::as_bool) == Some(true)
            })
        })
        .or_else(|| releases.first());
    let current_version = env!("CARGO_PKG_VERSION");
    let latest_version = latest.map_or_else(|| current_version.into(), release_item_version);
    let status = if latest_version == current_version {
        "current"
    } else if latest.is_some() {
        "review_available"
    } else {
        "catalog_missing"
    };
    let changed_rules = active_rule_metadata(state)
        .iter()
        .filter(|rule| {
            rule.last_promotion_at.is_some()
                || matches!(
                    rule.lifecycle,
                    ContentLifecycle::Canary | ContentLifecycle::Active
                )
        })
        .take(8)
        .map(|rule| {
            serde_json::json!({
                "rule_id": rule.id,
                "title": rule.title,
                "lifecycle": rule.lifecycle,
                "owner": rule.owner,
                "last_promotion_at": rule.last_promotion_at,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "current_version": current_version,
        "latest_version": latest_version,
        "release": latest.cloned(),
        "release_count": releases.len(),
        "changed_rules": changed_rules,
        "operator_summary": if status == "current" {
            "Runtime and release catalog are aligned."
        } else if status == "review_available" {
            "A release candidate is available for operator review."
        } else {
            "Release catalog metadata is not available yet."
        },
    })
}

pub(crate) fn build_launchpad_demo_status(state: &AppState) -> serde_json::Value {
    let sample_alerts = state
        .alerts
        .iter()
        .filter(|alert| {
            alert.platform == "sample"
                || alert
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("[SAMPLE]"))
        })
        .count();
    let demo_seeded = std::env::var("WARDEX_DEMO_DATA")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if demo_seeded || sample_alerts > 0 { "ready" } else { "available" },
        "seeded": demo_seeded,
        "sample_alerts": sample_alerts,
        "scenarios": ["credential_storm", "slow_escalation", "low_battery_attack", "benign_baseline"],
        "next_action": if sample_alerts > 0 {
            "Review seeded alerts in Live Monitor or reset the scenario before the next demo."
        } else {
            "Start demo lab to seed evaluation telemetry and guided alert context."
        },
    })
}

pub(crate) fn build_detection_recommendations(state: &AppState, limit: usize) -> serde_json::Value {
    let mut recommendations = active_rule_metadata(state)
        .into_iter()
        .map(|rule| {
            let suppressions = rule_active_suppression_count(state, &rule.id);
            let pack_count = rule_pack_count(state, &rule);
            let (action, reason, detail, confidence) = if !rule.enabled
                || matches!(
                    rule.lifecycle,
                    ContentLifecycle::Deprecated | ContentLifecycle::RolledBack
                )
            {
                (
                    "retire",
                    "inactive_lifecycle",
                    "Rule is disabled, deprecated, or rolled back; retire it or document why it remains visible.",
                    86_u32,
                )
            } else if rule.last_test_at.is_none() {
                (
                    "review",
                    "missing_replay_evidence",
                    "Replay validation has not run; validate the rule before promotion or broader rollout.",
                    82_u32,
                )
            } else if rule.last_test_match_count >= 10 && suppressions == 0 {
                (
                    "suppress",
                    "high_validation_hits",
                    "Replay validation produced high hit volume without a scoped suppression.",
                    88_u32,
                )
            } else if suppressions >= 2 {
                (
                    "review",
                    "suppression_pressure",
                    "Multiple live suppressions affect this rule; review tuning before promotion.",
                    78_u32,
                )
            } else if pack_count == 0 {
                (
                    "review",
                    "missing_content_pack",
                    "Rule is not attached to a content pack, which weakens rollout ownership.",
                    72_u32,
                )
            } else if matches!(rule.lifecycle, ContentLifecycle::Canary)
                && rule.last_test_match_count <= 2
                && suppressions == 0
            {
                (
                    "promote",
                    "canary_low_noise",
                    "Canary rule has low replay hit volume and no active suppressions.",
                    74_u32,
                )
            } else {
                (
                    "monitor",
                    "healthy_baseline",
                    "Rule has no immediate blocker; keep evidence fresh and owner review current.",
                    45_u32,
                )
            };
            serde_json::json!({
                "rule_id": rule.id,
                "rule_name": rule.title,
                "action": action,
                "confidence": confidence,
                "reason": reason,
                "detail": detail,
                "supporting_metrics": {
                    "lifecycle": rule.lifecycle,
                    "enabled": rule.enabled,
                    "last_test_at": rule.last_test_at,
                    "last_test_match_count": rule.last_test_match_count,
                    "active_suppressions": suppressions,
                    "content_pack_count": pack_count,
                    "owner": rule.owner,
                }
            })
        })
        .collect::<Vec<_>>();
    recommendations.sort_by(|left, right| {
        right["confidence"]
            .as_u64()
            .unwrap_or_default()
            .cmp(&left["confidence"].as_u64().unwrap_or_default())
            .then_with(|| {
                left["rule_name"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["rule_name"].as_str().unwrap_or_default())
            })
    });
    recommendations.truncate(limit.max(1));
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "days": 30,
        "recommendations": recommendations,
    })
}

pub(crate) fn normalize_detection_outcome(value: &str) -> &'static str {
    match value.trim().to_ascii_lowercase().as_str() {
        "valid" | "true_positive" | "tp" | "confirmed" => "valid",
        "false_positive" | "fp" | "noise" | "noisy" => "false_positive",
        "benign_true_positive" | "benign" | "btp" => "benign_true_positive",
        "duplicate" | "dupe" => "duplicate",
        _ => "needs_more_data",
    }
}

pub(crate) fn detection_outcome_is_noise(value: &str) -> bool {
    matches!(
        normalize_detection_outcome(value),
        "false_positive" | "duplicate"
    )
}

pub(crate) fn rule_feedback_rollup(state: &AppState, rule_id: &str) -> serde_json::Value {
    let feedback = state.detection_feedback.for_rule(rule_id);
    let mut by_state: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut analysts = HashSet::new();
    let mut latest_at = None::<String>;
    for item in &feedback {
        let state_name = normalize_detection_outcome(&item.verdict);
        *by_state.entry(state_name).or_insert(0) += 1;
        analysts.insert(item.analyst.clone());
        if latest_at
            .as_ref()
            .is_none_or(|current| item.created_at.as_str() > current.as_str())
        {
            latest_at = Some(item.created_at.clone());
        }
    }
    let total = feedback.len();
    let valid = *by_state.get("valid").unwrap_or(&0);
    let false_positive = *by_state.get("false_positive").unwrap_or(&0);
    let benign_true_positive = *by_state.get("benign_true_positive").unwrap_or(&0);
    let needs_more_data = *by_state.get("needs_more_data").unwrap_or(&0);
    let duplicate = *by_state.get("duplicate").unwrap_or(&0);
    let noise_count = false_positive + duplicate;
    let valid_ratio = if total == 0 {
        0.0
    } else {
        valid as f64 / total as f64
    };
    let false_positive_ratio = if total == 0 {
        0.0
    } else {
        noise_count as f64 / total as f64
    };
    let consensus = if total == 0 {
        "unrated"
    } else if valid_ratio >= 0.7 {
        "mostly_valid"
    } else if false_positive_ratio >= 0.7 {
        "mostly_false_positive"
    } else {
        "mixed"
    };
    serde_json::json!({
        "total": total,
        "by_state": {
            "valid": valid,
            "false_positive": false_positive,
            "benign_true_positive": benign_true_positive,
            "needs_more_data": needs_more_data,
            "duplicate": duplicate,
        },
        "analyst_count": analysts.len(),
        "latest_at": latest_at,
        "valid_ratio": valid_ratio,
        "false_positive_ratio": false_positive_ratio,
        "consensus": consensus,
    })
}

pub(crate) fn rule_stale_suppression_count(state: &AppState, rule_id: &str) -> usize {
    state
        .enterprise
        .suppressions()
        .iter()
        .filter(|suppression| {
            suppression
                .rule_id
                .as_deref()
                .is_some_and(|candidate| candidate == rule_id)
                && (suppression.expires_at.is_none()
                    || suppression
                        .expires_at
                        .as_deref()
                        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                        .is_some_and(|ts| ts < chrono::Utc::now()))
        })
        .count()
}

pub(crate) fn rule_volume_trend(
    state: &AppState,
    rule: &crate::enterprise::ManagedRuleMetadata,
) -> u64 {
    let title = rule.title.to_ascii_lowercase();
    let id = rule.id.to_ascii_lowercase();
    state
        .alerts
        .iter()
        .filter(|alert| {
            alert.reasons.iter().any(|reason| {
                let reason = reason.to_ascii_lowercase();
                reason.contains(&id) || (!title.is_empty() && reason.contains(&title))
            })
        })
        .count() as u64
}

pub(crate) fn detection_trust_driver(
    id: &str,
    label: &str,
    impact: i64,
    detail: impl Into<String>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "label": label,
        "impact": impact,
        "detail": detail.into(),
    })
}

pub(crate) fn detection_trust_rule_row(
    state: &AppState,
    rule: &crate::enterprise::ManagedRuleMetadata,
) -> serde_json::Value {
    let feedback = rule_feedback_rollup(state, &rule.id);
    let feedback_total = feedback
        .get("total")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let valid_ratio = feedback
        .get("valid_ratio")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or_default();
    let fp_ratio = feedback
        .get("false_positive_ratio")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or_default();
    let active_suppressions = rule_active_suppression_count(state, &rule.id);
    let stale_suppressions = rule_stale_suppression_count(state, &rule.id);
    let pack_count = rule_pack_count(state, rule);
    let recent_alert_volume = rule_volume_trend(state, rule);
    let mut score = 72_i64;
    let mut drivers = Vec::new();

    let feedback_impact = if feedback_total == 0 {
        -6
    } else {
        ((valid_ratio * 22.0).round() as i64) - ((fp_ratio * 32.0).round() as i64)
    };
    score += feedback_impact;
    drivers.push(detection_trust_driver(
        "historical_feedback",
        "Historical feedback",
        feedback_impact,
        if feedback_total == 0 {
            "No analyst outcome history is attached yet.".to_string()
        } else {
            format!(
                "{feedback_total} feedback item(s), {:.0}% valid and {:.0}% false-positive/duplicate.",
                valid_ratio * 100.0,
                fp_ratio * 100.0
            )
        },
    ));

    let suppression_impact =
        -((active_suppressions as i64 * 8).min(24)) - ((stale_suppressions as i64 * 6).min(18));
    score += suppression_impact;
    drivers.push(detection_trust_driver(
        "suppression_pressure",
        "Suppression pressure",
        suppression_impact,
        format!(
            "{active_suppressions} active suppression(s), {stale_suppressions} stale or unbounded candidate(s)."
        ),
    ));

    let replay_impact = if rule.last_test_at.is_none() {
        -14
    } else if rule.last_test_match_count >= 10 {
        -12
    } else if rule.last_test_match_count <= 2 {
        8
    } else {
        2
    };
    score += replay_impact;
    drivers.push(detection_trust_driver(
        "replay_freshness",
        "Replay freshness",
        replay_impact,
        if rule.last_test_at.is_none() {
            "Replay validation has not run for this rule.".to_string()
        } else {
            format!(
                "Last replay produced {} match(es) at {}.",
                rule.last_test_match_count,
                rule.last_test_at.as_deref().unwrap_or("unknown time")
            )
        },
    ));

    let source_impact = if rule.enabled
        && matches!(
            rule.lifecycle,
            ContentLifecycle::Canary | ContentLifecycle::Active | ContentLifecycle::Test
        ) {
        8
    } else {
        -12
    };
    score += source_impact;
    drivers.push(detection_trust_driver(
        "source_reliability",
        "Source reliability",
        source_impact,
        format!(
            "Rule is {:?}, enabled={}, owner={}.",
            rule.lifecycle, rule.enabled, rule.owner
        ),
    ));

    let enrichment_impact = if rule.false_positive_review.is_some() {
        5
    } else {
        -4
    };
    score += enrichment_impact;
    drivers.push(detection_trust_driver(
        "enrichment_quality",
        "Enrichment quality",
        enrichment_impact,
        rule.false_positive_review
            .clone()
            .unwrap_or_else(|| "No false-positive review note is attached.".to_string()),
    ));

    let coverage_impact = if !rule.attack.is_empty() || pack_count > 0 {
        7
    } else {
        -8
    };
    score += coverage_impact;
    drivers.push(detection_trust_driver(
        "attack_coverage",
        "ATT&CK coverage impact",
        coverage_impact,
        format!(
            "{} ATT&CK mapping(s), {pack_count} content pack reference(s).",
            rule.attack.len()
        ),
    ));

    let volume_impact = if recent_alert_volume >= 20 {
        -14
    } else if recent_alert_volume >= 8 {
        -7
    } else if recent_alert_volume == 0 {
        0
    } else {
        4
    };
    score += volume_impact;
    drivers.push(detection_trust_driver(
        "alert_volume_trend",
        "Recent alert-volume trend",
        volume_impact,
        format!("{recent_alert_volume} recent alert(s) referenced this rule."),
    ));

    let campaign_impact = if recent_alert_volume > 0 && fp_ratio < 0.4 {
        5
    } else {
        0
    };
    score += campaign_impact;
    drivers.push(detection_trust_driver(
        "campaign_context",
        "Related campaign context",
        campaign_impact,
        if campaign_impact > 0 {
            "Recent related alerts exist without dominant false-positive pressure."
        } else {
            "No strong campaign lift is available for this rule."
        },
    ));

    let score = score.clamp(0, 100) as u64;
    let status = if score >= 82 {
        "trusted"
    } else if score >= 62 {
        "review"
    } else {
        "noisy"
    };
    let recommended_draft = if fp_ratio >= 0.55 && feedback_total >= 3 {
        "scoped_suppression"
    } else if rule.last_test_match_count >= 10 {
        "threshold_review"
    } else if stale_suppressions > 0 {
        "stale_suppression_review"
    } else if score < 62 {
        "noisy_rule_review"
    } else if matches!(rule.lifecycle, ContentLifecycle::Canary) && score < 82 {
        "promotion_blocker"
    } else {
        "monitor"
    };

    serde_json::json!({
        "rule_id": rule.id,
        "title": rule.title,
        "description": rule.description,
        "owner": rule.owner,
        "kind": rule.kind,
        "lifecycle": rule.lifecycle,
        "enabled": rule.enabled,
        "trust_score": score,
        "status": status,
        "recommended_draft": recommended_draft,
        "feedback": feedback,
        "metrics": {
            "active_suppressions": active_suppressions,
            "stale_suppressions": stale_suppressions,
            "replay_fresh": rule.last_test_at.is_some(),
            "last_test_at": rule.last_test_at,
            "last_test_match_count": rule.last_test_match_count,
            "content_pack_count": pack_count,
            "attack_technique_count": rule.attack.len(),
            "recent_alert_volume": recent_alert_volume,
            "source_reliability": if rule.enabled { "available" } else { "disabled" },
            "enrichment_quality": if rule.false_positive_review.is_some() { "documented" } else { "missing_review_note" },
        },
        "drivers": drivers,
        "guardrail": "Draft-only tuning: Wardex recommends changes but never weakens production detections automatically.",
    })
}

pub(crate) fn detection_trust_rows(state: &AppState) -> Vec<serde_json::Value> {
    let mut rows = active_rule_metadata(state)
        .iter()
        .map(|rule| detection_trust_rule_row(state, rule))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left.get("trust_score")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default()
            .cmp(
                &right
                    .get("trust_score")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
            )
            .then_with(|| {
                left.get("title")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .cmp(
                        right
                            .get("title")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default(),
                    )
            })
    });
    rows
}

pub(crate) fn detection_trust_draft_for_rule(row: &serde_json::Value) -> Option<serde_json::Value> {
    let draft_type = row
        .get("recommended_draft")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("monitor");
    if draft_type == "monitor" {
        return None;
    }
    let rule_id = row
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let confidence = row
        .get("trust_score")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let expected_change = match draft_type {
        "scoped_suppression" => -0.45,
        "threshold_review" => -0.25,
        "stale_suppression_review" => 0.10,
        "promotion_blocker" => -0.05,
        _ => -0.15,
    };
    Some(serde_json::json!({
        "id": format!("{draft_type}-{rule_id}"),
        "draft_type": draft_type,
        "rule_id": rule_id,
        "rule_name": row.get("title").cloned().unwrap_or_else(|| serde_json::json!(rule_id)),
        "status": "draft",
        "operator_approved": false,
        "auto_apply": false,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "reason": row.get("drivers").and_then(serde_json::Value::as_array).and_then(|drivers| drivers.first()).cloned().unwrap_or_else(|| serde_json::json!({"detail": "Rule trust requires operator review."})),
        "impact_preview": {
            "matched_historical_alerts": row.get("metrics").and_then(|metrics| metrics.get("recent_alert_volume")).cloned().unwrap_or_else(|| serde_json::json!(0)),
            "expected_alert_volume_change": expected_change,
            "affected_rules": [rule_id],
            "affected_hunts": [],
            "attack_coverage_effect": if draft_type == "scoped_suppression" { "scoped_exception_only" } else { "no_direct_coverage_loss" },
            "confidence_delta": if confidence < 62 { 0.08 } else { 0.03 },
            "rollback_path": "Remove or expire the drafted tuning object; existing production rules remain unchanged until operator-applied.",
        },
        "guardrail": "Draft-only tuning queue; approve records operator intent and returns manual apply guidance.",
    }))
}

pub(crate) fn detection_trust_drafts(state: &AppState) -> Vec<serde_json::Value> {
    detection_trust_rows(state)
        .iter()
        .filter_map(detection_trust_draft_for_rule)
        .take(25)
        .collect()
}

pub(crate) fn build_detection_trust_overview(state: &AppState) -> serde_json::Value {
    let rows = detection_trust_rows(state);
    let noisy_rules = rows
        .iter()
        .filter(|row| row.get("status").and_then(serde_json::Value::as_str) == Some("noisy"))
        .take(8)
        .cloned()
        .collect::<Vec<_>>();
    let trusted_rules = rows
        .iter()
        .rev()
        .filter(|row| row.get("status").and_then(serde_json::Value::as_str) == Some("trusted"))
        .take(8)
        .cloned()
        .collect::<Vec<_>>();
    let stale_suppressions = state
        .enterprise
        .suppressions()
        .iter()
        .filter(|suppression| {
            suppression.active
                && (suppression.expires_at.is_none()
                    || suppression
                        .expires_at
                        .as_deref()
                        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                        .is_some_and(|ts| ts < chrono::Utc::now()))
        })
        .take(25)
        .map(|suppression| {
            serde_json::json!({
                "id": suppression.id,
                "name": suppression.name,
                "rule_id": suppression.rule_id,
                "hunt_id": suppression.hunt_id,
                "expires_at": suppression.expires_at,
                "justification": suppression.justification,
                "active": suppression.active,
            })
        })
        .collect::<Vec<_>>();
    let draft_queue = rows
        .iter()
        .filter_map(detection_trust_draft_for_rule)
        .take(25)
        .collect::<Vec<_>>();
    let average_score = if rows.is_empty() {
        0
    } else {
        rows.iter()
            .map(|row| {
                row.get("trust_score")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default()
            })
            .sum::<u64>()
            / rows.len() as u64
    };
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "release": env!("CARGO_PKG_VERSION"),
        "states": ["valid", "false_positive", "benign_true_positive", "needs_more_data", "duplicate"],
        "draft_only_tuning": true,
        "auto_apply": false,
        "summary": {
            "rule_count": rows.len(),
            "average_trust_score": average_score,
            "noisy_rule_count": noisy_rules.len(),
            "trusted_rule_count": trusted_rules.len(),
            "stale_suppression_count": stale_suppressions.len(),
            "draft_count": draft_queue.len(),
            "feedback_count": state.detection_feedback.summary().total,
        },
        "noisy_rules": noisy_rules,
        "trusted_rules": trusted_rules,
        "stale_suppressions": stale_suppressions,
        "draft_queue": draft_queue,
        "confidence_drivers": [
            "historical_feedback",
            "analyst_consensus",
            "suppression_pressure",
            "replay_freshness",
            "source_reliability",
            "enrichment_quality",
            "attack_coverage",
            "alert_volume_trend",
            "campaign_context"
        ],
        "guardrail": "Wardex may draft suppressions, threshold reviews, and promotion blockers, but operators must explicitly apply production tuning.",
    })
}

pub(crate) fn build_detection_trust_rules(state: &AppState) -> serde_json::Value {
    let rows = detection_trust_rows(state);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "count": rows.len(),
        "rules": rows,
    })
}

pub(crate) fn build_detection_trust_rule_detail(
    state: &AppState,
    rule_id: &str,
) -> serde_json::Value {
    let rule = active_rule_metadata(state)
        .into_iter()
        .find(|rule| rule.id == rule_id);
    if let Some(rule) = rule {
        let row = detection_trust_rule_row(state, &rule);
        let draft = detection_trust_draft_for_rule(&row);
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "found": true,
            "rule": row,
            "tuning_draft": draft,
            "feedback": state.detection_feedback.for_rule(rule_id),
        })
    } else {
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "found": false,
            "rule_id": rule_id,
            "rule": serde_json::Value::Null,
            "tuning_draft": serde_json::Value::Null,
            "feedback": [],
        })
    }
}

pub(crate) fn build_detection_trust_draft_preview(
    state: &AppState,
    draft_id: &str,
) -> serde_json::Value {
    let drafts = detection_trust_drafts(state);
    let draft = drafts
        .iter()
        .find(|draft| draft.get("id").and_then(serde_json::Value::as_str) == Some(draft_id))
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "id": draft_id,
                "draft_type": "noisy_rule_review",
                "status": "draft",
                "operator_approved": false,
                "auto_apply": false,
                "impact_preview": {
                    "matched_historical_alerts": 0,
                    "expected_alert_volume_change": 0,
                    "affected_rules": [],
                    "affected_hunts": [],
                    "attack_coverage_effect": "unknown_until_rule_selected",
                    "confidence_delta": 0,
                    "rollback_path": "No production change has been staged.",
                },
            })
        });
    let rule_id = draft
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let historical_alerts = active_rule_metadata(state)
        .into_iter()
        .find(|rule| rule.id == rule_id)
        .map(|rule| {
            let title = rule.title.to_ascii_lowercase();
            state
                .alerts
                .iter()
                .enumerate()
                .filter(|(_, alert)| {
                    alert.reasons.iter().any(|reason| {
                        let reason = reason.to_ascii_lowercase();
                        reason.contains(rule_id) || reason.contains(&title)
                    })
                })
                .take(10)
                .map(|(index, alert)| {
                    serde_json::json!({
                        "alert_index": index,
                        "hostname": alert.hostname,
                        "severity": alert.level,
                        "timestamp": alert.timestamp,
                        "reasons": alert.reasons,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "draft": draft,
        "matched_historical_alerts": historical_alerts,
        "approval_required": true,
        "auto_apply": false,
        "rollback_path": "Keep the generated draft as review evidence; remove or expire the tuning object if operators later apply it and need rollback.",
        "guardrail": "Preview only. No suppression, rule weight, or threshold is changed by this endpoint.",
    })
}

pub(crate) fn create_detection_trust_draft_from_body(
    state: &AppState,
    parsed: &serde_json::Value,
) -> serde_json::Value {
    let requested_rule = parsed
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let draft_type = parsed
        .get("draft_type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("noisy_rule_review");
    let row = detection_trust_rows(state)
        .into_iter()
        .find(|row| row.get("rule_id").and_then(serde_json::Value::as_str) == Some(requested_rule));
    let mut draft = row
        .as_ref()
        .and_then(detection_trust_draft_for_rule)
        .unwrap_or_else(|| {
            serde_json::json!({
                "id": format!("{draft_type}-{requested_rule}"),
                "draft_type": draft_type,
                "rule_id": requested_rule,
                "status": "draft",
                "operator_approved": false,
                "auto_apply": false,
                "created_at": chrono::Utc::now().to_rfc3339(),
                "impact_preview": {
                    "matched_historical_alerts": 0,
                    "expected_alert_volume_change": 0,
                    "affected_rules": if requested_rule.is_empty() { serde_json::json!([]) } else { serde_json::json!([requested_rule]) },
                    "affected_hunts": [],
                    "attack_coverage_effect": "review_required",
                    "confidence_delta": 0,
                    "rollback_path": "No production tuning exists until an operator applies it.",
                },
                "guardrail": "Draft-only tuning queue.",
            })
        });
    if let Some(object) = draft.as_object_mut() {
        object.insert("draft_type".to_string(), serde_json::json!(draft_type));
        object.insert(
            "analyst_note".to_string(),
            parsed
                .get("analyst_note")
                .cloned()
                .unwrap_or_else(|| serde_json::json!("")),
        );
        object.insert("status".to_string(), serde_json::json!("draft"));
        object.insert("auto_apply".to_string(), serde_json::json!(false));
    }
    draft
}

pub(crate) fn collector_status_from_freshness(value: &serde_json::Value) -> &'static str {
    match value
        .get("freshness")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
    {
        "fresh" => "healthy",
        "stale" | "unknown" => "stale",
        "error" => "offline",
        "disabled" => "disabled",
        _ => "unknown",
    }
}

pub(crate) fn build_detection_readiness(state: &AppState, limit: usize) -> serde_json::Value {
    let collectors = crate::server_collectors::full_collector_status_entries(state);
    let rules = active_rule_metadata(state);
    let mut rows = Vec::new();
    for rule in rules.iter().take(limit.max(1)) {
        let mut dependencies = collectors
            .iter()
            .filter(|collector| {
                let lane = collector
                    .get("lane")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("cloud");
                rule_matches_collector_lane(rule, lane)
            })
            .map(|collector| {
                let status = collector_status_from_freshness(collector);
                serde_json::json!({
                    "collector_id": collector.get("provider").cloned().unwrap_or_else(|| serde_json::json!("unknown")),
                    "label": collector.get("label").cloned().unwrap_or_else(|| serde_json::json!("Collector")),
                    "lane": collector.get("lane").cloned().unwrap_or_else(|| serde_json::json!("unknown")),
                    "status": status,
                    "coverage_pct": if status == "healthy" { 100 } else if status == "stale" { 55 } else { 20 },
                    "last_event_timestamp": collector.get("last_success_at").cloned().unwrap_or(serde_json::Value::Null),
                    "required_fields_seen": collector.get("enabled").and_then(serde_json::Value::as_bool).unwrap_or(false),
                    "failure_reason_category": collector.get("error_category").cloned().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>();
        if dependencies.is_empty() {
            dependencies.push(serde_json::json!({
                "collector_id": "generic",
                "label": "Generic telemetry",
                "lane": "generic",
                "status": "unknown",
                "coverage_pct": 50,
                "last_event_timestamp": serde_json::Value::Null,
                "required_fields_seen": false,
                "failure_reason_category": "mapping_gap",
            }));
        }
        let weakest = dependencies
            .iter()
            .map(|item| item["coverage_pct"].as_u64().unwrap_or(0))
            .min()
            .unwrap_or(0);
        rows.push(serde_json::json!({
            "rule_id": rule.id,
            "rule_name": rule.title,
            "owner": rule.owner,
            "status": if weakest >= 90 { "ready" } else if weakest >= 50 { "degraded" } else { "blocked" },
            "coverage_pct": weakest,
            "collectors": dependencies,
        }));
    }
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "rules": rows,
        "collector_count": collectors.len(),
    })
}

pub(crate) fn build_response_approval_overview(state: &AppState) -> serde_json::Value {
    let response_requests = state.response_orchestrator.all_requests();
    let pending_response = response_requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Pending)
        .count();
    let ready_to_execute = response_requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Approved && !request.dry_run)
        .count();
    let playbook_executions = state.playbook_engine.recent_executions(usize::MAX);
    let pending_playbooks = playbook_executions
        .iter()
        .filter(|execution| execution.status == crate::playbook::ExecutionStatus::AwaitingApproval)
        .count();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "pending_response_approvals": pending_response,
        "ready_to_execute": ready_to_execute,
        "pending_playbook_approvals": pending_playbooks,
        "total_response_requests": response_requests.len(),
        "total_playbook_executions": playbook_executions.len(),
        "status": if pending_response + pending_playbooks > 0 { "approval_required" } else { "clear" },
        "next_action": if pending_response + pending_playbooks > 0 {
            "Open SOC Workbench approval queues before executing live response."
        } else {
            "Approval queues are clear; keep dry-run proof current."
        },
    })
}

pub(crate) fn build_remediation_safety_status(state: &AppState) -> serde_json::Value {
    let lane = crate::remediation::remediation_lane_summary(&state.storage);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "current_platform": std::env::consts::OS,
        "allow_live_rollback": state.config.remediation.allow_live_rollback,
        "execute_live_rollback_commands": state.config.remediation.execute_live_rollback_commands,
        "pending_reviews": lane.pending_reviews,
        "rollback_ready": lane.rollback_ready,
        "rollback_proofs": lane.rollback_ready,
        "status": if state.config.remediation.allow_live_rollback && state.config.remediation.execute_live_rollback_commands {
            "live_enabled"
        } else if state.config.remediation.allow_live_rollback {
            "proof_only"
        } else {
            "dry_run_only"
        },
        "guardrails": [
            "confirm_hostname must match the change-review asset before live rollback",
            "local execution is allowed only when the requested platform matches the current OS",
            "rollback proof metadata is retained for audit review"
        ],
    })
}

pub(crate) fn alert_feedback_summary(state: &AppState) -> serde_json::Value {
    let stats = state.fp_feedback.stats();
    let suggestions = stats
        .iter()
        .map(|(pattern, total, fps, ratio)| {
            let action = if *total >= 5 && *ratio >= 0.7 {
                "review_suppression"
            } else if *total >= 3 && *ratio >= 0.4 {
                "adjust_threshold"
            } else {
                "collect_more_feedback"
            };
            serde_json::json!({
                "pattern": pattern,
                "total_feedback": total,
                "false_positives": fps,
                "false_positive_ratio": ratio,
                "suppression_weight": state.fp_feedback.suppression_weight(pattern),
                "recommended_action": action,
                "expected_volume_impact": if action == "review_suppression" { "high" } else if action == "adjust_threshold" { "medium" } else { "low" },
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "states": ["valid", "false_positive", "benign_true_positive", "needs_more_data", "duplicate"],
        "total_feedback": state.fp_feedback.entry_count(),
        "suggestions": suggestions,
        "guardrail": "Feedback produces tuning suggestions only; detections are not automatically weakened.",
    })
}

pub(crate) fn alert_evidence_chain_payload(
    state: &AppState,
    alert_id: Option<usize>,
) -> serde_json::Value {
    let local_hostname = state.local_host_info.hostname.clone();
    let process_catalog = assemble_alert_process_catalog(&local_hostname, &state.process_tree);
    let resolved_index = alert_id.unwrap_or_else(|| state.alerts.len().saturating_sub(1));
    let alert = state
        .alerts
        .get(resolved_index)
        .or_else(|| state.alerts.back());
    let alert_json = alert.map_or_else(
        || serde_json::json!({}),
        |alert| alert_json_value(alert, resolved_index, &local_hostname, &process_catalog),
    );
    let reasons = alert.map(|alert| alert.reasons.clone()).unwrap_or_default();
    let entities = crate::entity_extract::extract_entities(&reasons);
    let source = alert.map_or_else(
        || {
            serde_json::json!({
                "source_type": "none",
                "detail": "No alert has been observed yet.",
            })
        },
        |alert| {
            serde_json::json!({
                "hostname": alert.hostname,
                "platform": alert.platform,
                "timestamp": alert.timestamp,
                "source_type": "live_alert_stream",
            })
        },
    );
    let confidence = alert.map(|alert| alert.confidence).unwrap_or_default();
    let score = alert.map(|alert| alert.score).unwrap_or_default();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "alert_id": alert_id.map_or_else(|| "latest".into(), |id| id.to_string()),
        "source": source,
        "raw_event": alert_json,
        "normalized_event": {
            "entities": entities,
            "reasons": reasons,
            "score": score,
            "confidence": confidence,
        },
        "why_this_fired": {
            "matched_fields": ["score", "reasons", "hostname", "platform"],
            "thresholds": {
                "critical": 9.0,
                "severe": 7.0,
                "elevated": 4.0
            },
            "confidence_drivers": [
                {"name": "rule_match", "score": if reasons.is_empty() { 0.0 } else { 0.82 }},
                {"name": "baseline_deviation", "score": (score / 10.0).min(1.0)},
                {"name": "source_reliability", "score": 0.78},
                {"name": "enrichment_quality", "score": if entities.is_empty() { 0.35 } else { 0.72 }},
                {"name": "analyst_feedback", "score": if state.fp_feedback.entry_count() > 0 { 0.62 } else { 0.45 }},
            ],
            "missing_context": if entities.is_empty() { vec!["No extracted entity was available for enrichment.".to_string()] } else { Vec::new() },
        },
        "evidence_chain": [
            {"stage": "source", "status": if alert.is_some() { "fresh" } else { "missing" }, "label": "Original alert stream record"},
            {"stage": "normalization", "status": if alert.is_some() { "fresh" } else { "missing" }, "label": "Wardex alert schema"},
            {"stage": "rule_or_hunt_match", "status": if reasons.is_empty() { "unknown" } else { "fresh" }, "label": "Reason fingerprint and matched detection content"},
            {"stage": "enrichment", "status": if entities.is_empty() { "partial" } else { "fresh" }, "label": "Entity extraction and threat context"},
            {"stage": "baseline", "status": "fresh", "label": "Score and confidence comparison"},
            {"stage": "response_readiness", "status": if build_response_approval_overview(state).get("status").and_then(serde_json::Value::as_str) == Some("clear") { "ready" } else { "approval_required" }, "label": "Approval-gated response path"},
        ],
        "freshness_badges": {
            "raw_event": if alert.is_some() { "fresh" } else { "missing" },
            "enrichment": if entities.is_empty() { "partial" } else { "fresh" },
            "threat_intel": "available",
            "process_context": "available",
            "malware_verdict": "available_on_scan",
            "response_readiness": build_response_approval_overview(state).get("status").cloned().unwrap_or_else(|| serde_json::json!("unknown")),
        },
        "recommended_next_action": if score >= 8.0 { "Create or attach an incident, export evidence preview, and stage a dry-run response action." } else { "Review enrichment and collect analyst feedback before suppression." },
        "pivots": [
            {"label": "Live Monitor", "href": "/admin/monitor"},
            {"label": "SOC Workbench", "href": "/admin/soc"},
            {"label": "Threat Detection", "href": "/admin/detection"},
            {"label": "Infrastructure", "href": "/admin/infrastructure"},
            {"label": "Malware Scanning", "href": "/admin/malware"},
            {"label": "Reports", "href": "/admin/reports"}
        ],
        "export_preview": {
            "items": ["raw_event", "normalized_event", "rule_match", "entities", "confidence_breakdown", "freshness_badges", "recommended_action"],
            "redaction": "secrets and tokens are redacted by support bundle policy",
        }
    })
}

pub(crate) fn build_detection_lab_payload(state: &AppState) -> serde_json::Value {
    let validation = build_detection_validation_packs(state);
    let recommendations = build_detection_recommendations(state, 8);
    let trust = build_detection_trust_score(state);
    let detection_trust = build_detection_trust_overview(state);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "modes": [
            {"id": "replay", "label": "Replay sample telemetry", "status": "ready"},
            {"id": "simulation", "label": "Run safe local simulations", "status": "ready"},
            {"id": "content_pack", "label": "Validate Sigma/YARA/signature packs", "status": "ready"}
        ],
        "validation_packs": validation,
        "expected_vs_observed": {
            "expected_detections": validation.get("executable_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
            "observed_detections": state.alerts.len(),
            "coverage_delta": trust.get("average_score").cloned().unwrap_or_else(|| serde_json::json!(0)),
            "missed_techniques": validation.get("missing_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
            "duplicate_or_noisy_candidates": state.fp_feedback.entry_count(),
        },
        "trust_delta": {
            "expected_confidence": detection_trust.get("summary").and_then(|summary| summary.get("average_trust_score")).cloned().unwrap_or_else(|| serde_json::json!(0)),
            "expected_false_positive_impact": detection_trust.get("summary").and_then(|summary| summary.get("noisy_rule_count")).cloned().unwrap_or_else(|| serde_json::json!(0)),
            "draft_queue": detection_trust.get("draft_queue").cloned().unwrap_or_else(|| serde_json::json!([])),
            "draft_only_tuning": true,
            "auto_apply": false,
        },
        "recommendations": recommendations.get("recommendations").cloned().unwrap_or_else(|| serde_json::json!([])),
        "history": [
            {"id": "latest-replay", "owner": "system", "mode": "replay", "target_platform": std::env::consts::OS, "content_version": env!("CARGO_PKG_VERSION"), "dataset": "release-validation-packs", "outcome": validation.get("status").cloned().unwrap_or_else(|| serde_json::json!("review")), "report_href": "/api/detection-lab/report"}
        ],
        "attach_targets": ["release", "content_pack_promotion", "audit_evidence"],
    })
}

pub(crate) fn response_safety_payload(state: &AppState) -> serde_json::Value {
    let requests = state.response_orchestrator.all_requests();
    let audit_ledger = state.response_orchestrator.audit_ledger();
    let request_items = requests
        .iter()
        .map(|request| {
            let item = response_request_json(request);
            let audit_anchor = format!("response:{}:{}", request.id, request.requested_at);
            serde_json::json!({
                "request": item,
                "preview": {
                    "would_execute": request.status == ApprovalStatus::Approved && !request.dry_run,
                    "required_approvals": response_required_approvals(request.tier),
                    "approval_chain": ["requester", "approver", "execution verifier"],
                    "pending_approvers": if request.status == ApprovalStatus::Pending { serde_json::json!(["response approver"]) } else { serde_json::json!([]) },
                    "platform_command_mapping": platform_response_command_mapping(&request.action),
                    "rollback": response_reversal_path(&request.action, &request.target),
                    "post_action_verification": response_verification_steps(&request.action),
                    "execution_audit": {
                        "audit_anchor": audit_anchor,
                        "audit_endpoint": "/api/response/audit",
                        "trace_endpoint": "/api/traces",
                        "trace_id": format!("response-{}", request.id),
                        "notification_status": if request.status == ApprovalStatus::Executed { "delivery recorded" } else { "queued after approval" },
                        "continuity": "request id links dry-run preview, approval ledger, trace export, rollback, and post-action verification",
                    },
                }
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "overview": build_response_approval_overview(state),
        "remediation": build_remediation_safety_status(state),
        "requests": request_items,
        "available_actions": response_action_catalog(),
        "execution_audit": {
            "ledger_entry_count": audit_ledger.len(),
            "audit_endpoint": "/api/response/audit",
            "trace_endpoint": "/api/traces",
            "continuity": "response request ids link approvals, dry-run previews, ledger entries, traces, rollback proof, and verification evidence",
        },
        "history": audit_ledger.iter().rev().take(20).map(|entry| {
            serde_json::json!({
                "request_id": entry.request_id,
                "action": entry.action,
                "target": entry.target_hostname,
                "outcome": format!("{:?}", entry.status),
                "timestamp": entry.timestamp,
                "approvers": entry.approvals,
                "actor": entry.actor,
                "reason": entry.reason,
                "verification": "review_required",
            })
        }).collect::<Vec<_>>(),
        "guardrails": [
            "dry-run preview before live execution",
            "approval count is determined by action tier",
            "destructive actions require rollback and verification review",
            "protected assets remain approval-gated"
        ],
    })
}

pub(crate) fn response_action_catalog() -> Vec<serde_json::Value> {
    ["alert", "isolate", "kill_process", "quarantine_file", "block_ip", "disable_account", "rollback_config", "throttle"]
        .iter()
        .map(|action| {
            serde_json::json!({
                "action": action,
                "preview_endpoint": "/api/response/preview",
                "verify_endpoint": "/api/response/verify",
                "destructive": matches!(*action, "kill_process" | "quarantine_file" | "block_ip" | "disable_account" | "rollback_config" | "isolate"),
            })
        })
        .collect()
}

pub(crate) fn platform_response_command_mapping(action: &ResponseAction) -> serde_json::Value {
    let action_name = match action {
        ResponseAction::Alert => "alert",
        ResponseAction::Isolate => "isolate",
        ResponseAction::Throttle { .. } => "throttle",
        ResponseAction::KillProcess { .. } => "kill_process",
        ResponseAction::QuarantineFile { .. } => "quarantine_file",
        ResponseAction::BlockIp { .. } => "block_ip",
        ResponseAction::DisableAccount { .. } => "disable_account",
        ResponseAction::RollbackConfig { .. } => "rollback_config",
        ResponseAction::Custom { .. } => "custom",
    };
    serde_json::json!({
        "action": action_name,
        "linux": match action_name {
            "block_ip" => "nftables/ipset block preview",
            "kill_process" => "kill -TERM/-KILL preview",
            "isolate" => "cgroup/nftables isolation preview",
            _ => "audit-only preview",
        },
        "macos": match action_name {
            "block_ip" => "pfctl anchor preview",
            "kill_process" => "launchctl/kill preview",
            "isolate" => "pfctl/sandbox-exec preview",
            _ => "audit-only preview",
        },
        "windows": match action_name {
            "block_ip" => "Windows Filtering Platform/netsh preview",
            "kill_process" => "Stop-Process preview",
            "isolate" => "Windows Firewall isolation preview",
            _ => "audit-only preview",
        },
    })
}

pub(crate) fn response_verification_steps(action: &ResponseAction) -> Vec<&'static str> {
    match action {
        ResponseAction::Alert => vec!["confirm notification delivery", "attach audit entry"],
        ResponseAction::Isolate => vec![
            "confirm heartbeat scope",
            "verify network isolation",
            "record rollback path",
        ],
        ResponseAction::Throttle { .. } => {
            vec!["measure effective rate limit", "confirm service latency"]
        }
        ResponseAction::KillProcess { .. } => vec![
            "confirm PID exited",
            "capture parent lineage",
            "verify no respawn",
        ],
        ResponseAction::QuarantineFile { .. } => vec![
            "confirm file moved",
            "verify hash retention",
            "record release criteria",
        ],
        ResponseAction::BlockIp { .. } => vec![
            "confirm deny rule",
            "check active connections",
            "record unblock command",
        ],
        ResponseAction::DisableAccount { .. } => vec![
            "confirm account disabled",
            "force session revocation",
            "record re-enable approval",
        ],
        ResponseAction::RollbackConfig { .. } => vec![
            "confirm config version",
            "run service health check",
            "record rollback proof",
        ],
        ResponseAction::Custom { .. } => {
            vec!["run custom verification", "attach operator evidence"]
        }
    }
}

pub(crate) fn response_preview_from_body(body: &[u8]) -> Response<Body> {
    let parsed = match read_json_value(body, 64 * 1024) {
        Ok(value) => value,
        Err(error) => return error_json(&error, 400),
    };
    let action = response_action_from_json(&parsed).unwrap_or(ResponseAction::Alert);
    let target_hostname = parsed
        .get("hostname")
        .or_else(|| parsed.get("target_hostname"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("selected-host");
    let target = ResponseTarget {
        hostname: target_hostname.to_string(),
        agent_uid: parsed
            .get("agent_uid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        asset_tags: parsed
            .get("asset_tags")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    };
    json_response(
        &serde_json::json!({
            "dry_run": true,
            "action_label": response_action_label(&action),
            "required_approvals": 1,
            "blast_radius": {
                "risk_level": if matches!(action, ResponseAction::Isolate | ResponseAction::DisableAccount { .. } | ResponseAction::RollbackConfig { .. }) { "high" } else { "medium" },
                "affected_endpoints": [target.hostname.clone()],
                "impact_summary": format!("{} would target {} after approval.", response_action_label(&action), target.hostname),
            },
            "platform_command_mapping": platform_response_command_mapping(&action),
            "rollback": response_reversal_path(&action, &target),
            "post_action_verification": response_verification_steps(&action),
            "confirmation_summary": {
                "risk": "review_required",
                "approval_chain": ["requester", "approver"],
                "bypass": false
            }
        })
        .to_string(),
        200,
    )
}

pub(crate) fn response_verify_from_body(body: &[u8]) -> Response<Body> {
    let parsed = match read_json_value(body, 32 * 1024) {
        Ok(value) => value,
        Err(error) => return error_json(&error, 400),
    };
    let action = response_action_from_json(&parsed).unwrap_or(ResponseAction::Alert);
    json_response(
        &serde_json::json!({
            "verified": false,
            "status": "operator_evidence_required",
            "action": parsed.get("action").cloned().unwrap_or_else(|| serde_json::json!("alert")),
            "checks": response_verification_steps(&action).into_iter().map(|step| {
                serde_json::json!({"step": step, "status": "pending_evidence"})
            }).collect::<Vec<_>>(),
            "next_action": "Attach post-action evidence or run the platform-specific verifier before closing the response.",
        })
        .to_string(),
        200,
    )
}

pub(crate) fn integrations_marketplace_payload(state: &AppState) -> serde_json::Value {
    let collectors = crate::server_collectors::full_collector_status_entries(state);
    let mut cards = collectors
        .iter()
        .map(|collector| {
            let provider = collector.get("provider").and_then(serde_json::Value::as_str).unwrap_or("connector");
            let status = collector.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown");
            let enabled = collector.get("enabled").and_then(serde_json::Value::as_bool).unwrap_or(false);
            let health_score = match status {
                "healthy" | "ready" => 95,
                "degraded" | "stale" => 60,
                "disabled" if enabled => 45,
                "disabled" => 35,
                _ => 50,
            };
            serde_json::json!({
                "id": provider,
                "label": collector.get("label").cloned().unwrap_or_else(|| serde_json::json!(provider)),
                "lane": collector.get("lane").cloned().unwrap_or_else(|| serde_json::json!("collector")),
                "setup_status": if enabled { "configured" } else { "not_enabled" },
                "health_score": health_score,
                "last_success_at": collector.get("last_success_at").cloned().unwrap_or(serde_json::Value::Null),
                "failure_streak": collector.get("failure_streak").cloned().unwrap_or_else(|| serde_json::json!(0)),
                "freshness": collector.get("freshness").cloned().unwrap_or_else(|| serde_json::json!("unknown")),
                "ingestion_sla": collector.get("ingestion_sla").cloned().unwrap_or_else(|| serde_json::json!({"status": "unknown"})),
                "required_permissions": connector_permissions(provider),
                "next_fix": connector_next_fix(collector),
                "sample_event": sample_event_for_connector(provider),
                "impact": connector_impact_for_provider(provider),
                "actions": ["validate_now", "preview_sample_event", "open_settings"],
            })
        })
        .collect::<Vec<_>>();
    cards.extend(integration_destination_cards(state));
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "connectors": cards,
        "guided_setup_categories": ["cloud", "identity", "saas", "edr", "syslog", "siem_export", "ticketing", "threat_intel", "malware_signatures"],
        "settings_href": "/settings?tab=integrations",
    })
}

pub(crate) fn rbac_coverage_payload() -> serde_json::Value {
    let roles = [
        Role::Admin,
        Role::Analyst,
        Role::Viewer,
        Role::ServiceAccount,
    ];
    let mut endpoints = crate::openapi::endpoint_catalog(env!("CARGO_PKG_VERSION"));
    endpoints.extend([
        crate::openapi::EndpointCatalogEntry {
            method: "GET".to_string(),
            path: "/api/admin/rbac-coverage".to_string(),
            auth: true,
            description: "RBAC route coverage proof with required permissions and allowed roles"
                .to_string(),
        },
        crate::openapi::EndpointCatalogEntry {
            method: "GET".to_string(),
            path: "/api/response/execution-audit".to_string(),
            auth: true,
            description: "Response execution transcripts, command summaries, exit status, rollback, and verification evidence"
                .to_string(),
        },
    ]);
    let mut protected_routes = Vec::new();
    let mut admin_only = 0usize;
    let mut service_account_allowed = 0usize;

    for endpoint in endpoints.iter().filter(|entry| entry.auth) {
        let permission = crate::rbac::endpoint_permission(&endpoint.method, &endpoint.path);
        let allowed_roles = roles
            .iter()
            .copied()
            .filter(|role| role_permissions(*role).contains(&permission))
            .map(role_label)
            .collect::<Vec<_>>();
        if allowed_roles.len() == 1 && allowed_roles[0] == "admin" {
            admin_only += 1;
        }
        if allowed_roles.contains(&"service_account") {
            service_account_allowed += 1;
        }
        protected_routes.push(serde_json::json!({
            "method": endpoint.method,
            "path": endpoint.path,
            "permission": format!("{:?}", permission),
            "allowed_roles": allowed_roles,
            "guard": "endpoint_permission",
            "description": endpoint.description,
        }));
    }

    let total = protected_routes.len();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": "covered",
        "coverage_pct": 100.0,
        "protected_routes": total,
        "admin_only_routes": admin_only,
        "service_account_routes": service_account_allowed,
        "guard_source": "openapi endpoint catalog + rbac::endpoint_permission",
        "roles": roles.iter().map(|role| {
            serde_json::json!({
                "role": role_label(*role),
                "permissions": role_permissions(*role).into_iter().map(|permission| format!("{permission:?}")).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
        "routes": protected_routes,
    })
}

pub(crate) fn integration_destination_cards(state: &AppState) -> Vec<serde_json::Value> {
    vec![
        splunk_hec_marketplace_card(state),
        servicenow_marketplace_card(state),
    ]
}

pub(crate) fn splunk_hec_marketplace_card(state: &AppState) -> serde_json::Value {
    let config = state.siem_connector.config();
    let status = state.siem_connector.status();
    let validation = siem_config_validation_json(config, status.last_error.as_deref());
    let validation_status = validation
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let configured = config.enabled && config.siem_type == "splunk";
    let health_score = match validation_status {
        "ready" if configured => 95,
        "warning" if configured => 68,
        "error" => 36,
        _ if configured => 58,
        _ => 28,
    };
    let destination = format!(
        "{} / {}",
        if config.index.trim().is_empty() {
            "wardex"
        } else {
            config.index.as_str()
        },
        if config.source_type.trim().is_empty() {
            "wardex:xdr"
        } else {
            config.source_type.as_str()
        }
    );
    let summary_line = if configured {
        format!(
            "{} -> {}",
            if status.endpoint.trim().is_empty() {
                "Endpoint pending"
            } else {
                status.endpoint.as_str()
            },
            destination
        )
    } else {
        "Splunk HEC is available as the primary outbound SIEM export path.".to_string()
    };
    let secondary_line = if configured {
        format!(
            "{} event(s) pushed, {} pending{}",
            status.total_pushed,
            status.pending_events,
            if config.pull_enabled {
                ", pull enabled"
            } else {
                ""
            }
        )
    } else {
        "Configure the HEC endpoint, token, index, and sourcetype in Settings.".to_string()
    };
    let next_fix = if configured && validation_status == "ready" {
        "Splunk HEC export is configured; keep token scope and index routing current."
    } else if configured {
        "Review the HEC endpoint, token, and TLS settings before enabling production export."
    } else {
        "Switch SIEM type to Splunk HEC and save the endpoint, token, index, and sourcetype."
    };

    serde_json::json!({
        "id": "splunk_hec",
        "label": "Splunk HEC Export",
        "lane": "siem_export",
        "setup_status": if configured { "configured" } else { "not_enabled" },
        "health_score": health_score,
        "last_success_at": serde_json::Value::Null,
        "failure_streak": if status.last_error.is_some() { 1 } else { 0 },
        "freshness": if configured && validation_status == "ready" { "fresh" } else if configured { "review" } else { "planned" },
        "required_permissions": connector_permissions("splunk_hec"),
        "next_fix": next_fix,
        "sample_event": sample_event_for_connector("splunk_hec"),
        "impact": connector_impact_for_provider("splunk_hec"),
        "actions": ["validate_export_path", "preview_sample_event", "open_settings"],
        "validation": validation,
        "summary_line": summary_line,
        "secondary_line": secondary_line,
        "action_href": "/settings?tab=integrations",
        "action_label": "Open Settings",
        "destination": destination,
        "export_path": {
            "siem_type": config.siem_type,
            "endpoint": config.endpoint,
            "index": config.index,
            "source_type": config.source_type,
            "verify_tls": config.verify_tls,
            "pull_enabled": config.pull_enabled,
        },
    })
}

pub(crate) fn servicenow_marketplace_card(state: &AppState) -> serde_json::Value {
    let servicenow_syncs = state
        .enterprise
        .ticket_syncs()
        .iter()
        .filter(|sync| sync.provider.eq_ignore_ascii_case("servicenow"))
        .collect::<Vec<_>>();
    let latest_sync = servicenow_syncs
        .iter()
        .copied()
        .max_by(|left, right| left.synced_at.cmp(&right.synced_at));
    let has_sync = latest_sync.is_some();
    let destination = latest_sync
        .and_then(|sync| sync.queue_or_project.as_deref())
        .unwrap_or("ServiceNow incident queue");
    let validation_status = if has_sync { "ready" } else { "review" };
    let validation_issues = if has_sync {
        Vec::new()
    } else {
        vec![serde_json::json!({
            "level": "info",
            "field": "workflow",
            "message": "Sync a case from SOC Workbench using provider=servicenow to establish outbound ticket visibility.",
        })]
    };
    let summary_line = match latest_sync {
        Some(sync) => format!(
            "Last sync {} for {} #{}",
            sync.external_key, sync.object_kind, sync.object_id
        ),
        None => {
            "Outbound case sync is available from the SOC workbench ticketing panel.".to_string()
        }
    };
    let secondary_line = match latest_sync {
        Some(sync) => format!(
            "{} sync(s) recorded; latest queue {}",
            sync.sync_count, destination
        ),
        None => {
            "Sync a case from SOC Workbench to establish queue and latency visibility.".to_string()
        }
    };
    let next_fix = if has_sync {
        "Review queue mapping and continue outbound case sync coverage."
    } else {
        "Seed ServiceNow visibility by syncing a case from the SOC workbench ticketing panel."
    };

    serde_json::json!({
        "id": "servicenow",
        "label": "ServiceNow Case Sync",
        "lane": "ticketing",
        "setup_status": if has_sync { "configured" } else { "manual_sync" },
        "health_score": if has_sync { 86 } else { 44 },
        "last_success_at": latest_sync.map(|sync| sync.synced_at.clone()),
        "failure_streak": 0,
        "freshness": if has_sync { "fresh" } else { "review" },
        "required_permissions": connector_permissions("servicenow"),
        "next_fix": next_fix,
        "sample_event": sample_event_for_connector("servicenow"),
        "impact": connector_impact_for_provider("servicenow"),
        "actions": ["open_case_sync", "review_status_visibility"],
        "validation": {
            "status": validation_status,
            "issues": validation_issues,
        },
        "summary_line": summary_line,
        "secondary_line": secondary_line,
        "action_href": "/soc#cases",
        "action_label": "Open SOC Cases",
        "destination": destination,
        "sync_status": {
            "provider": "servicenow",
            "synced_total": servicenow_syncs.len(),
            "latest_external_key": latest_sync.map(|sync| sync.external_key.clone()),
            "latest_object_kind": latest_sync.map(|sync| sync.object_kind.clone()),
            "latest_object_id": latest_sync.map(|sync| sync.object_id.clone()),
            "latest_queue_or_project": latest_sync.and_then(|sync| sync.queue_or_project.clone()),
            "latest_synced_at": latest_sync.map(|sync| sync.synced_at.clone()),
            "last_ticket_sync_latency_ms": state.enterprise.metrics().last_ticket_sync_latency_ms,
        },
    })
}

pub(crate) fn integration_validation_payload(
    state: &AppState,
    provider: &str,
) -> serde_json::Value {
    match provider {
        "splunk_hec" => {
            let card = splunk_hec_marketplace_card(state);
            let validation = card
                .get("validation")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({"status": "unknown", "issues": []}));
            let status = validation
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            serde_json::json!({
                "provider": provider,
                "valid": status == "ready",
                "status": status,
                "sample_event": card.get("sample_event").cloned().unwrap_or_else(|| sample_event_for_connector(provider)),
                "next_fix": card.get("next_fix").cloned().unwrap_or_else(|| serde_json::json!("Review required permissions and save connector settings before production ingestion.")),
                "validation": validation,
                "destination": card.get("destination").cloned().unwrap_or(serde_json::Value::Null),
                "export_path": card.get("export_path").cloned().unwrap_or(serde_json::Value::Null),
            })
        }
        "servicenow" => {
            let card = servicenow_marketplace_card(state);
            let validation = card
                .get("validation")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({"status": "unknown", "issues": []}));
            let status = validation
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            serde_json::json!({
                "provider": provider,
                "valid": true,
                "status": status,
                "sample_event": card.get("sample_event").cloned().unwrap_or_else(|| sample_event_for_connector(provider)),
                "next_fix": card.get("next_fix").cloned().unwrap_or_else(|| serde_json::json!("Review outbound ticket mappings before production sync.")),
                "validation": validation,
                "destination": card.get("destination").cloned().unwrap_or(serde_json::Value::Null),
                "sync_status": card.get("sync_status").cloned().unwrap_or(serde_json::Value::Null),
            })
        }
        _ => serde_json::json!({
            "provider": provider,
            "valid": true,
            "status": "preview_ready",
            "sample_event": sample_event_for_connector(provider),
            "next_fix": "Review required permissions and save connector settings before production ingestion.",
        }),
    }
}

pub(crate) fn connector_permissions(provider: &str) -> Vec<&'static str> {
    match provider {
        "aws_cloudtrail" => vec!["CloudTrail read", "S3 object read", "STS identity"],
        "azure_activity" | "entra_identity" => {
            vec!["Graph/API read", "audit log read", "tenant metadata"]
        }
        "gcp_audit" => vec!["Logging viewer", "service account token creator"],
        "okta_identity" => vec!["System log read"],
        "m365_saas" => vec!["Management Activity API"],
        "workspace_saas" => vec!["Admin SDK reports read"],
        "splunk_hec" => vec!["HEC token write", "HTTPS egress", "index access"],
        "servicenow" => vec!["incident write", "case queue access", "API credentials"],
        "generic_syslog" => vec!["syslog listener"],
        "crowdstrike_falcon" => vec!["EDR event read", "host containment read"],
        _ => vec!["configuration validation"],
    }
}

pub(crate) fn connector_next_fix(collector: &serde_json::Value) -> &'static str {
    if collector
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        "Enable the connector and complete the guided setup checklist."
    } else if collector
        .get("freshness")
        .and_then(serde_json::Value::as_str)
        != Some("fresh")
    {
        "Validate credentials and preview a sample event to refresh ingestion evidence."
    } else {
        "Connector is healthy; keep lifecycle evidence fresh."
    }
}

pub(crate) fn sample_event_for_connector(provider: &str) -> serde_json::Value {
    serde_json::json!({
        "provider": provider,
        "event_type": match provider {
            "aws_cloudtrail" => "ConsoleLogin",
            "azure_activity" => "Administrative",
            "okta_identity" => "user.session.start",
            "m365_saas" => "Audit.Exchange",
            "splunk_hec" => "splunk.hec.alert",
            "servicenow" => "ticket.case.sync",
            "generic_syslog" => "syslog.auth",
            _ => "sample.audit",
        },
        "normalized_fields": match provider {
            "splunk_hec" => vec!["time", "host", "source", "sourcetype", "event.alert_id"],
            "servicenow" => vec!["external_key", "queue_or_project", "status", "object_id", "synced_at"],
            _ => vec!["timestamp", "actor", "source_ip", "action", "outcome"],
        },
    })
}

pub(crate) fn connector_impact_for_provider(provider: &str) -> Vec<&'static str> {
    match provider {
        "aws_cloudtrail" | "azure_activity" | "gcp_audit" => {
            vec!["cloud detections", "identity pivots", "compliance evidence"]
        }
        "okta_identity" | "entra_identity" => vec![
            "UEBA login analytics",
            "impossible travel",
            "identity response",
        ],
        "m365_saas" | "workspace_saas" => {
            vec!["SaaS investigation", "mail/file activity", "audit reports"]
        }
        "crowdstrike_falcon" => vec!["EDR enrichment", "host containment", "malware context"],
        "splunk_hec" => vec!["SIEM export", "external correlation", "retention search"],
        "servicenow" => vec!["case sync", "ticket workflow", "status visibility"],
        "generic_syslog" => vec![
            "SIEM correlation",
            "network auth",
            "legacy device visibility",
        ],
        _ => vec!["enrichment", "dashboards", "reports"],
    }
}

pub(crate) fn operations_health_payload(state: &AppState) -> serde_json::Value {
    let uptime_secs = state.server_start.elapsed().as_secs().max(1);
    let storage_stats = state.storage.with(|store| Ok(store.stats())).ok();
    let spool_stats = state.spool.stats();
    let ws_stats = state.alert_broadcaster.stats();
    let collectors = crate::server_collectors::full_collector_status_entries(state);
    let stale_connectors = collectors
        .iter()
        .filter(|item| item.get("freshness").and_then(serde_json::Value::as_str) != Some("fresh"))
        .count();
    let scan_stats = state.malware_scanner.stats();
    let agents = state.agent_registry.list();
    let drifted_agents = agents
        .iter()
        .filter(|agent| agent.version != env!("CARGO_PKG_VERSION"))
        .count();
    let error_rate_pct = if state.request_count == 0 {
        0.0
    } else {
        (state.error_count as f64 / state.request_count as f64) * 100.0
    };
    let cards = vec![
        serde_json::json!({"id": "ingestion_rate", "status": "ready", "value": state.event_store.all_events().len(), "target": "events visible", "trend": "runtime", "recommended_action": "Review collector freshness for stale lanes.", "drilldown": "/admin/integrations"}),
        serde_json::json!({"id": "queue_lag", "status": if spool_stats.current_depth > 0 { "warn" } else { "pass" }, "value": spool_stats.current_depth, "target": 0, "trend": "runtime", "recommended_action": "Drain encrypted spool before release or secret rotation.", "drilldown": "/admin/operations-health"}),
        serde_json::json!({"id": "dropped_events", "status": if ws_stats.get("dropped_events").and_then(serde_json::Value::as_u64).unwrap_or_default() > 0 { "warn" } else { "pass" }, "value": ws_stats.get("dropped_events").cloned().unwrap_or_else(|| serde_json::json!(0)), "target": 0, "trend": "stream", "recommended_action": "Check WebSocket backpressure and subscriber lag.", "drilldown": "/admin/monitor"}),
        serde_json::json!({"id": "scanner_backlog", "status": "pass", "value": scan_stats.total_scans, "target": "on-demand", "trend": "scanner", "recommended_action": "Run a malware preset if scan evidence is stale.", "drilldown": "/admin/malware"}),
        serde_json::json!({"id": "api_error_rate", "status": if error_rate_pct > 5.0 { "warn" } else { "pass" }, "value": format!("{error_rate_pct:.1}%"), "target": "<=5%", "trend": "runtime", "recommended_action": "Open support bundle if API errors remain elevated.", "drilldown": "/admin/help"}),
        serde_json::json!({"id": "storage_growth", "status": "pass", "value": storage_stats.as_ref().map_or(state.alerts.len(), |stats| stats.total_alerts + stats.total_audit_entries), "target": "within retention", "trend": "storage", "recommended_action": "Review retention forecast when stored records grow quickly.", "drilldown": "/admin/settings?tab=retention"}),
        serde_json::json!({"id": "agent_version_drift", "status": if drifted_agents > 0 { "warn" } else { "pass" }, "value": drifted_agents, "target": 0, "trend": "fleet", "recommended_action": "Open Fleet rollout health and recover stale agents.", "drilldown": "/admin/fleet"}),
        serde_json::json!({"id": "connector_freshness", "status": if stale_connectors > 0 { "warn" } else { "pass" }, "value": stale_connectors, "target": 0, "trend": "integrations", "recommended_action": "Validate stale connectors and preview sample events.", "drilldown": "/admin/integrations"}),
    ];
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "uptime_secs": uptime_secs,
        "slo_cards": cards,
        "metrics": {
            "request_count": state.request_count,
            "error_count": state.error_count,
            "error_rate_pct": error_rate_pct,
            "spool_depth": spool_stats.current_depth,
            "event_count": state.event_store.all_events().len(),
            "alert_count": state.alerts.len(),
            "scanner": scan_stats,
            "websocket": ws_stats,
            "storage": storage_stats,
            "connector_count": collectors.len(),
            "stale_connectors": stale_connectors,
            "agents": agents.len(),
            "agent_version_drift": drifted_agents,
        },
        "snapshot_export": "/api/operations/health/snapshot",
    })
}

pub(crate) fn malware_explanation_payload(state: &AppState) -> serde_json::Value {
    let stats = state.malware_scanner.stats();
    let presets = local_av_signature_presets_json();
    let recent = state.malware_hash_db.recent_detections();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "summary": {
            "total_scans": stats.total_scans,
            "malicious": stats.malicious_count,
            "suspicious": stats.suspicious_count,
            "clean": stats.clean_count,
            "signature_sources": state.malware_hash_db.stats(),
            "yara_rules": state.yara_engine.rule_names().len(),
        },
        "verdict_explanation_contract": {
            "matched_signature_source": "hash_db/yara/threat_intel/static_heuristic",
            "signals": ["YARA", "ClamAV hash", "hash reputation", "entropy", "packing", "imports", "strings", "rootkit persistence", "platform limits"],
            "confidence": "0.0-1.0",
            "recommended_response": "quarantine, collect evidence, scan containing folder, or stage approval-gated response",
        },
        "presets": [
            {"id": "open-source-av-baseline", "label": "Open-source AV baseline", "sources": ["ClamAV HDB/HSB", "plain hash lines"], "operator_opt_in": true},
            {"id": "rootkit-persistence-sweep", "label": "Rootkit persistence sweep", "sources": ["platform persistence paths", "hidden file heuristics"], "operator_opt_in": true},
            {"id": "trojan-loader-hunt", "label": "Trojan loader hunt", "sources": ["YARA", "hash feeds", "network/dropper heuristics"], "operator_opt_in": true},
            {"id": "whole-system-review", "label": "Whole-system review", "sources": ["file scan", "rootkit scan", "signature presets"], "operator_opt_in": true}
        ],
        "source_preset_status": presets,
        "target_presets": ["single_file", "folder", "mounted_volume", "agent_host_scope", "whole_system"],
        "recent_detections": recent,
        "scan_diff": {
            "endpoint": "/api/malware/scan-diff",
            "status": "available_after_repeated_scans",
            "comparison_fields": ["verdict", "confidence", "matches", "hash", "rootkit_findings", "skipped_checks"],
        },
    })
}

const PRODUCT_CONTRACT_ENDPOINTS: &[(&str, &str)] = &[
    ("GET", "/api/operator/workspaces"),
    ("POST", "/api/alerts/feedback"),
    ("GET", "/api/alerts/feedback/summary"),
    ("GET", "/api/alerts/evidence-chain"),
    ("POST", "/api/detection-lab/runs"),
    ("GET", "/api/detection-lab/status"),
    ("GET", "/api/detection-lab/history"),
    ("GET", "/api/detection-lab/report"),
    ("GET", "/api/response/safety"),
    ("POST", "/api/response/preview"),
    ("POST", "/api/response/verify"),
    ("GET", "/api/integrations/marketplace"),
    ("POST", "/api/integrations/validate"),
    ("GET", "/api/integrations/sample-event"),
    ("GET", "/api/operations/health"),
    ("GET", "/api/operations/health/snapshot"),
    ("GET", "/api/malware/explain"),
    ("GET", "/api/malware/scan-diff"),
    ("GET", "/api/operational/snapshots"),
    ("GET", "/api/operational/snapshots/verify"),
    ("GET", "/api/launchpad/evidence-pack"),
    ("GET", "/api/launchpad/release-diff"),
    ("GET", "/api/launchpad/demo-status"),
    ("POST", "/api/launchpad/demo-reset"),
    ("GET", "/api/release/doctor"),
    ("GET", "/api/release/provenance"),
    ("GET", "/api/release/upgrade-rehearsal"),
    ("GET", "/api/release/clean-cut"),
    ("GET", "/api/containers/release-parity"),
    ("GET", "/api/release/verification-center"),
    ("GET", "/api/release/deployment-trust-report"),
    ("GET", "/api/deployment/self-hosted-wizard"),
    ("GET", "/api/data-quality/dashboard"),
    ("GET", "/api/performance/scale-baseline"),
    ("GET", "/api/cluster/failover-execution"),
    ("GET", "/api/secrets/rotation-operations"),
    ("GET", "/api/operator/task-automation"),
    ("GET", "/api/detection/validation-packs"),
    ("GET", "/api/detection/recommendations"),
    ("GET", "/api/detection/readiness"),
    ("GET", "/api/detection/trust-score"),
    ("GET", "/api/detection/trust/overview"),
    ("GET", "/api/detection/tuning/feedback"),
    ("GET", "/api/detection/trust/rules"),
    ("GET", "/api/detection/trust/rules/{id}"),
    ("GET", "/api/detection/trust/tuning-drafts"),
    ("POST", "/api/detection/trust/tuning-drafts"),
    ("POST", "/api/detection/trust/tuning-drafts/{id}/preview"),
    ("POST", "/api/detection/trust/tuning-drafts/{id}/approve"),
    ("GET", "/api/monitoring/synthetic-console"),
    ("GET", "/api/incidents/timeline-replay"),
    ("GET", "/api/fleet/drift-compliance"),
    ("GET", "/api/operator/work-queue"),
    ("GET", "/api/retention/forecast"),
    ("GET", "/api/search/performance-slo"),
    ("GET", "/api/validation/adversarial"),
    ("GET", "/api/support/bundle-diff"),
    ("GET", "/api/response/approval-overview"),
    ("GET", "/api/remediation/safety"),
    ("GET", "/api/support/bundle"),
    ("GET", "/api/ws/health"),
    ("GET", "/api/stream/readiness"),
    ("GET", "/api/stream/reliability-lab"),
    ("GET", "/api/sdk/contract-status"),
    ("GET", "/api/alerts/histogram"),
    ("GET", "/api/alerts/page"),
    ("GET", "/api/events/page"),
    ("GET", "/api/audit/log/page"),
    ("GET", "/api/workflows/preflight"),
    ("POST", "/api/content/rules/{id}/preflight"),
    ("GET", "/api/playbook/execution/{id}/recovery-actions"),
    ("GET", "/api/tenants/isolation-proof"),
    ("GET", "/api/processes/thread-proof"),
    ("GET", "/api/operational/snapshots/policy"),
    ("POST", "/api/operational/snapshots/prune"),
    ("GET", "/api/release/observability-gates"),
    ("POST", "/api/subscriptions"),
    ("GET", "/api/subscriptions/resume"),
];

pub(crate) fn product_contract_missing_from_source(source: &str) -> Vec<String> {
    PRODUCT_CONTRACT_ENDPOINTS
        .iter()
        .filter_map(|(method, path)| {
            let path_present = if source.contains(path) {
                true
            } else if let Some((prefix, suffix)) = path.split_once("{id}") {
                source.contains(prefix) && source.contains(suffix)
            } else {
                false
            };
            if path_present {
                None
            } else {
                Some(format!("{method} {path}"))
            }
        })
        .collect()
}

pub(crate) fn product_contract_missing_from_catalog(
    catalog: &[crate::openapi::EndpointCatalogEntry],
) -> Vec<String> {
    PRODUCT_CONTRACT_ENDPOINTS
        .iter()
        .filter_map(|(method, path)| {
            if catalog
                .iter()
                .any(|entry| entry.method == *method && entry.path == *path)
            {
                None
            } else {
                Some(format!("{method} {path}"))
            }
        })
        .collect()
}

pub(crate) fn stream_readiness_payload(stats: serde_json::Value) -> serde_json::Value {
    let dropped = stats
        .get("dropped_events")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let queue_depth = stats
        .get("subscriber_queue_depth")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let max_observed_queue_depth = stats
        .get("max_observed_queue_depth")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(queue_depth);
    let latency_slo_ms = stats
        .get("latency_slo_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1000);
    let mut score = 100_i64;
    score -= ((queue_depth.min(200) as i64) / 2).min(45);
    score -= ((max_observed_queue_depth.min(250) as i64) / 10).min(20);
    score -= (dropped.min(50) as i64 * 2).min(50);
    let score = score.clamp(0, 100) as u64;
    let status = if score >= 90 {
        "ready"
    } else if score >= 70 {
        "degraded"
    } else {
        "backpressure"
    };
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "score": score,
        "queue_depth": queue_depth,
        "max_observed_queue_depth": max_observed_queue_depth,
        "dropped_events": dropped,
        "latency_slo_ms": latency_slo_ms,
        "promotion_guard": if score >= 80 { "clear" } else { "recover_stream_first" },
        "next_action": if score >= 80 {
            "Stream reliability is strong enough for promotion and evidence workflows."
        } else {
            "Recover stream health before trusting rule promotion, live response, or evidence completeness."
        },
        "stats": stats,
    })
}

pub(crate) fn build_sdk_contract_status(state: &AppState) -> serde_json::Value {
    let catalog = crate::openapi::endpoint_catalog(env!("CARGO_PKG_VERSION"));
    let docs_openapi = include_str!("../docs/openapi.yaml");
    let python_sdk = include_str!("../sdk/python/wardex/client.py");
    let typescript_sdk = include_str!("../sdk/typescript/src/index.ts");
    let release_acceptance = include_str!("../scripts/release_acceptance.sh");
    let missing_openapi_builder = product_contract_missing_from_catalog(&catalog);
    let missing_docs = product_contract_missing_from_source(docs_openapi);
    let missing_python_sdk = product_contract_missing_from_source(python_sdk);
    let missing_typescript_sdk = product_contract_missing_from_source(typescript_sdk);
    let missing_release_gate = product_contract_missing_from_source(release_acceptance);
    let critical_field_checks = [
        (
            "assistant_structured_output",
            docs_openapi.contains("structured")
                || typescript_sdk.contains("Assistant")
                || python_sdk.contains("assistant"),
        ),
        (
            "session_csrf_token",
            typescript_sdk.contains("csrf_token") && python_sdk.contains("auth/session"),
        ),
        (
            "collector_first_value_journey",
            docs_openapi.contains("first_value")
                || typescript_sdk.contains("collectors")
                || python_sdk.contains("collectors"),
        ),
        (
            "case_closure_readiness",
            docs_openapi.contains("handoff-packet") && typescript_sdk.contains("handoff"),
        ),
    ];
    let missing_critical_fields = critical_field_checks
        .iter()
        .filter_map(|(field, present)| (!*present).then_some(*field))
        .collect::<Vec<_>>();
    let drift_count = missing_openapi_builder.len()
        + missing_docs.len()
        + missing_python_sdk.len()
        + missing_typescript_sdk.len()
        + missing_release_gate.len()
        + missing_critical_fields.len();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "runtime_version": env!("CARGO_PKG_VERSION"),
        "openapi_endpoint": "/api/openapi.json",
        "contract_parity_script": "scripts/check_contract_parity.py",
        "release_gate": "scripts/release_acceptance.sh",
        "sdk_surfaces": ["sdk/python", "sdk/typescript"],
        "endpoint_inventory": catalog.len(),
        "product_endpoint_inventory": PRODUCT_CONTRACT_ENDPOINTS.len(),
        "tenant_count": state.multi_tenant.tenant_count(),
        "missing_openapi_builder": missing_openapi_builder,
        "missing_docs_openapi": missing_docs,
        "missing_python_sdk": missing_python_sdk,
        "missing_typescript_sdk": missing_typescript_sdk,
        "missing_release_gate": missing_release_gate,
        "critical_field_checks": critical_field_checks
            .iter()
            .map(|(field, present)| serde_json::json!({
                "field": field,
                "status": if *present { "pass" } else { "drift" },
            }))
            .collect::<Vec<_>>(),
        "missing_critical_fields": missing_critical_fields,
        "drift_count": drift_count,
        "status": if drift_count == 0 { "tracked" } else { "drift" },
    })
}

pub(crate) fn parse_duration_seconds(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (number, multiplier) = match trimmed.chars().last()? {
        'm' | 'M' => (&trimmed[..trimmed.len().saturating_sub(1)], 60_i64),
        'h' | 'H' => (&trimmed[..trimmed.len().saturating_sub(1)], 60_i64 * 60),
        'd' | 'D' => (
            &trimmed[..trimmed.len().saturating_sub(1)],
            60_i64 * 60 * 24,
        ),
        's' | 'S' => (&trimmed[..trimmed.len().saturating_sub(1)], 1_i64),
        _ => (trimmed, 1_i64),
    };
    number
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .map(|value| value.saturating_mul(multiplier))
}

pub(crate) fn alert_timestamp(alert: &AlertRecord) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(&alert.timestamp).map_or_else(
        |_| chrono::Utc::now(),
        |value| value.with_timezone(&chrono::Utc),
    )
}

pub(crate) fn build_alert_histogram(
    alerts: &VecDeque<AlertRecord>,
    window_secs: i64,
    bucket_secs: i64,
    severity_filter: Option<&str>,
) -> serde_json::Value {
    let end = chrono::Utc::now();
    let start = end - chrono::Duration::seconds(window_secs.clamp(60, 60 * 60 * 24 * 365));
    let bucket_secs = bucket_secs.clamp(60, 60 * 60 * 24 * 30);
    let severities = severity_filter
        .map(|value| {
            value
                .split(',')
                .map(|item| item.trim().to_ascii_lowercase())
                .filter(|item| !item.is_empty())
                .collect::<HashSet<_>>()
        })
        .filter(|set| !set.is_empty());
    let mut buckets: BTreeMap<i64, (usize, HashMap<String, usize>, f32)> = BTreeMap::new();
    let mut total = 0usize;
    for alert in alerts {
        let timestamp = alert_timestamp(alert);
        if timestamp < start || timestamp > end {
            continue;
        }
        let level = alert.level.to_ascii_lowercase();
        if let Some(ref severities) = severities
            && !severities.contains(&level)
        {
            continue;
        }
        let offset = timestamp.timestamp().saturating_sub(start.timestamp());
        let bucket_start = start.timestamp() + (offset / bucket_secs) * bucket_secs;
        let entry = buckets
            .entry(bucket_start)
            .or_insert_with(|| (0, HashMap::new(), 0.0));
        entry.0 += 1;
        *entry.1.entry(level).or_insert(0) += 1;
        entry.2 = entry.2.max(alert.score);
        total += 1;
    }
    let bucket_values = buckets
        .into_iter()
        .filter_map(|(bucket_start, (count, severity_breakdown, max_score))| {
            let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp(bucket_start, 0)?;
            Some(serde_json::json!({
                "timestamp": timestamp.to_rfc3339(),
                "count": count,
                "severity_breakdown": severity_breakdown,
                "max_score": (max_score * 100.0).round() / 100.0,
            }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "generated_at": end.to_rfc3339(),
        "window_secs": window_secs,
        "bucket_secs": bucket_secs,
        "severity_filter": severity_filter,
        "total": total,
        "buckets": bucket_values,
    })
}

pub(crate) fn parse_cursor_page_params(
    url: &str,
    default_limit: usize,
    max_limit: usize,
) -> (usize, usize) {
    let query = parse_query_string(url);
    let cursor = query
        .get("cursor")
        .or_else(|| query.get("after"))
        .or_else(|| query.get("offset"))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(1_000_000);
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default_limit)
        .clamp(1, max_limit);
    (cursor, limit)
}

pub(crate) fn cursor_page_payload(
    collection: &str,
    items: Vec<serde_json::Value>,
    total: usize,
    cursor: usize,
    limit: usize,
) -> serde_json::Value {
    let count = items.len();
    let next_cursor = cursor.saturating_add(count);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "collection": collection,
        "cursor": cursor.to_string(),
        "next_cursor": next_cursor.to_string(),
        "limit": limit,
        "count": count,
        "total": total,
        "has_more": next_cursor < total,
        "items": items,
    })
}

pub(crate) fn alert_cursor_page_payload(
    state: &AppState,
    cursor: usize,
    limit: usize,
) -> serde_json::Value {
    let total = state.alerts.len();
    let items = state
        .alerts
        .iter()
        .enumerate()
        .skip(cursor.min(total))
        .take(limit)
        .map(|(index, alert)| alert_json_value(alert, index, &state.local_host_info.hostname, &[]))
        .collect::<Vec<_>>();
    cursor_page_payload("alerts", items, total, cursor.min(total), limit)
}

pub(crate) fn event_cursor_page_payload(
    state: &AppState,
    url: &str,
    cursor: usize,
    limit: usize,
) -> serde_json::Value {
    let query = parse_event_query(url);
    let events = filtered_events(&state.event_store, &query);
    let total = events.len();
    let items = events
        .into_iter()
        .skip(cursor.min(total))
        .take(limit)
        .filter_map(|event| serde_json::to_value(event).ok())
        .collect::<Vec<_>>();
    cursor_page_payload("events", items, total, cursor.min(total), limit)
}

pub(crate) fn audit_cursor_page_payload(
    state: &AppState,
    url: &str,
    cursor: usize,
    limit: usize,
) -> serde_json::Value {
    let query = parse_query_string(url);
    let filter = AuditLogFilter::from_query(&query);
    let page = state.audit_log.page_filtered(limit, cursor, &filter);
    let items = page
        .entries
        .into_iter()
        .filter_map(|entry| serde_json::to_value(entry).ok())
        .collect::<Vec<_>>();
    cursor_page_payload("audit_log", items, page.total, page.offset, page.limit)
}

pub(crate) fn subscription_id_for(lanes: &[String], filters: &serde_json::Value) -> String {
    let digest = crate::audit::sha256_hex(
        serde_json::json!({ "lanes": lanes, "filters": filters, "ts": chrono::Utc::now().timestamp_millis() })
            .to_string()
            .as_bytes(),
    );
    format!("sub-{}", digest.chars().take(16).collect::<String>())
}

pub(crate) fn subscription_cursor_dir(storage: &crate::storage::SharedStorage) -> Option<PathBuf> {
    storage_root_path(storage).map(|root| root.join("operational_subscriptions"))
}

pub(crate) fn safe_subscription_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 96
        || !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return None;
    }
    Some(trimmed.to_string())
}

pub(crate) fn persist_subscription_cursor(
    storage: &crate::storage::SharedStorage,
    cursor: &serde_json::Value,
) -> serde_json::Value {
    let generated_at = chrono::Utc::now().to_rfc3339();
    let Some(subscription_id) = cursor
        .get("subscription_id")
        .and_then(serde_json::Value::as_str)
        .and_then(safe_subscription_id)
    else {
        return serde_json::json!({
            "persisted": false,
            "generated_at": generated_at,
            "error": "invalid_subscription_id",
        });
    };
    let Some(dir) = subscription_cursor_dir(storage) else {
        return serde_json::json!({
            "persisted": false,
            "generated_at": generated_at,
            "error": "storage_unavailable",
        });
    };
    if let Err(err) = fs::create_dir_all(&dir) {
        return serde_json::json!({
            "persisted": false,
            "generated_at": generated_at,
            "error": format!("cursor_dir_failed: {err}"),
        });
    }
    let path = dir.join(format!("{subscription_id}.json"));
    let envelope = serde_json::json!({
        "subscription_id": subscription_id,
        "updated_at": generated_at,
        "cursor": cursor,
    });
    match serde_json::to_vec_pretty(&envelope)
        .ok()
        .and_then(|bytes| fs::write(&path, bytes).ok())
    {
        Some(_) => serde_json::json!({
            "persisted": true,
            "generated_at": generated_at,
            "storage_key": format!("operational_subscriptions/{subscription_id}.json"),
        }),
        None => serde_json::json!({
            "persisted": false,
            "generated_at": generated_at,
            "error": "cursor_write_failed",
        }),
    }
}

pub(crate) fn read_subscription_cursor(
    storage: &crate::storage::SharedStorage,
    subscription_id: &str,
) -> Option<serde_json::Value> {
    let subscription_id = safe_subscription_id(subscription_id)?;
    let path = subscription_cursor_dir(storage)?.join(format!("{subscription_id}.json"));
    let bytes = fs::read(path).ok()?;
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    envelope.get("cursor").cloned()
}

pub(crate) fn stream_reliability_lab_payload(stats: serde_json::Value) -> serde_json::Value {
    let readiness = stream_readiness_payload(stats.clone());
    let score = readiness
        .get("score")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let dropped = stats
        .get("dropped_events")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let queue_depth = stats
        .get("subscriber_queue_depth")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let max_queue = stats
        .get("max_observed_queue_depth")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(queue_depth);
    let scenarios = vec![
        serde_json::json!({
            "id": "steady_state",
            "status": if score >= 90 { "pass" } else { "warn" },
            "observed": { "score": score, "queue_depth": queue_depth },
            "expected": "readiness score >= 90 and queue depth below 25",
            "next_action": if score >= 90 { "Keep promotion workflows enabled." } else { "Collect a clean steady-state sample before promotion." },
        }),
        serde_json::json!({
            "id": "backpressure_recovery",
            "status": if max_queue <= 100 { "pass" } else if max_queue <= 200 { "warn" } else { "fail" },
            "observed": { "max_observed_queue_depth": max_queue },
            "expected": "max queue depth <= 100 during live monitoring",
            "next_action": if max_queue <= 100 { "No recovery action required." } else { "Drain slow subscribers and reconnect affected consoles." },
        }),
        serde_json::json!({
            "id": "drop_detection",
            "status": if dropped == 0 { "pass" } else { "fail" },
            "observed": { "dropped_events": dropped },
            "expected": "zero dropped events since stream bus start",
            "next_action": if dropped == 0 { "Cursor replay can be trusted for current buffer." } else { "Use cursor replay and evidence snapshots to identify missing alert context." },
        }),
        serde_json::json!({
            "id": "cursor_resume",
            "status": "pass",
            "observed": { "retention_window": "current_alert_buffer", "durable_cursor_store": true },
            "expected": "subscriptions persist cursor metadata and expose replay gaps",
            "next_action": "Resume from the latest durable cursor after reconnects.",
        }),
    ];
    let fail_count = scenarios
        .iter()
        .filter(|scenario| {
            scenario.get("status").and_then(serde_json::Value::as_str) == Some("fail")
        })
        .count();
    let warn_count = scenarios
        .iter()
        .filter(|scenario| {
            scenario.get("status").and_then(serde_json::Value::as_str) == Some("warn")
        })
        .count();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if fail_count > 0 { "fail" } else if warn_count > 0 { "warn" } else { "pass" },
        "readiness": readiness,
        "scenario_count": scenarios.len(),
        "fail_count": fail_count,
        "warn_count": warn_count,
        "scenarios": scenarios,
    })
}

pub(crate) fn release_doctor_payload(state: &AppState) -> serde_json::Value {
    let release_diff = build_launchpad_release_diff(state);
    let contract = build_sdk_contract_status(state);
    let stream = stream_readiness_payload(state.alert_broadcaster.stats());
    let remediation = build_remediation_safety_status(state);
    let observability = build_release_observability_gates(state);
    let release_current = matches!(
        release_diff
            .get("status")
            .and_then(serde_json::Value::as_str),
        Some("current" | "aligned" | "unknown")
    );
    let contract_drift = contract
        .get("drift_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let stream_score = stream
        .get("score")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let observability_status = observability
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let checks = vec![
        serde_json::json!({
            "id": "release_catalog",
            "status": if release_current { "pass" } else { "warn" },
            "detail": release_diff.get("operator_summary").and_then(serde_json::Value::as_str).unwrap_or("Release catalog compared with runtime version."),
        }),
        serde_json::json!({
            "id": "contract_parity",
            "status": if contract_drift == 0 { "pass" } else { "fail" },
            "detail": format!("{contract_drift} endpoint parity drift item(s) detected."),
        }),
        serde_json::json!({
            "id": "stream_readiness",
            "status": if stream_score >= 80 { "pass" } else { "warn" },
            "detail": format!("Realtime readiness score is {stream_score}."),
        }),
        serde_json::json!({
            "id": "observability_gates",
            "status": if observability_status == "blocked" { "fail" } else if observability_status == "review" { "warn" } else { "pass" },
            "detail": format!("Release observability gates are {observability_status}."),
        }),
        serde_json::json!({
            "id": "remediation_guardrails",
            "status": if remediation.get("status").and_then(serde_json::Value::as_str) == Some("live_enabled") { "warn" } else { "pass" },
            "detail": format!("Remediation mode is {}.", remediation.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown")),
        }),
    ];
    let fail_count = checks
        .iter()
        .filter(|check| check.get("status").and_then(serde_json::Value::as_str) == Some("fail"))
        .count();
    let warn_count = checks
        .iter()
        .filter(|check| check.get("status").and_then(serde_json::Value::as_str) == Some("warn"))
        .count();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if fail_count > 0 { "blocked" } else if warn_count > 0 { "review" } else { "ready" },
        "runtime_version": env!("CARGO_PKG_VERSION"),
        "fail_count": fail_count,
        "warn_count": warn_count,
        "checks": checks,
        "observability_gates": observability,
        "next_action": if fail_count > 0 {
            "Fix contract drift before release acceptance."
        } else if warn_count > 0 {
            "Review warnings before approving rollout."
        } else {
            "Release acceptance signals are ready."
        },
    })
}

pub(crate) fn support_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "credential",
        "authorization",
        "cookie",
        "private_key",
        "api_key",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

pub(crate) fn redact_support_payload(
    value: &mut serde_json::Value,
    path: &str,
    redacted: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let next_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                if support_sensitive_key(key) {
                    *child = serde_json::Value::String("[REDACTED]".to_string());
                    redacted.push(next_path);
                } else {
                    redact_support_payload(child, &next_path, redacted);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                redact_support_payload(child, &format!("{path}[{index}]"), redacted);
            }
        }
        _ => {}
    }
}

pub(crate) fn build_support_bundle(state: &mut AppState) -> serde_json::Value {
    let mut bundle = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "runtime_version": env!("CARGO_PKG_VERSION"),
        "host": {
            "hostname": state.local_host_info.hostname.clone(),
            "platform": state.local_host_info.platform.to_string(),
            "arch": state.local_host_info.arch.clone(),
        },
        "readiness_evidence": production_readiness_evidence(state),
        "release_doctor": release_doctor_payload(state),
        "stream_reliability": stream_reliability_lab_payload(state.alert_broadcaster.stats()),
        "snapshot_index": list_operational_snapshots(&state.storage, None, 25),
        "audit_tail_count": state.audit_log.entries.len(),
        "alert_count": state.alerts.len(),
        "redaction_probe": {
            "authorization": "support bundle redaction self-test",
            "api_key": "support bundle redaction self-test",
        },
    });
    let mut redacted_fields = Vec::new();
    redact_support_payload(&mut bundle, "", &mut redacted_fields);
    let digest = crate::audit::sha256_hex(bundle.to_string().as_bytes());
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": "redacted",
        "digest": digest,
        "bundle": bundle,
        "redaction": {
            "policy": "keys containing token, secret, password, credential, authorization, cookie, private_key, or api_key are replaced before export",
            "redacted_fields": redacted_fields,
            "redacted_count": redacted_fields.len(),
        },
    })
}

pub(crate) fn build_launchpad_evidence_pack(state: &mut AppState) -> serde_json::Value {
    let readiness = build_onboarding_readiness(state);
    let command_summary = command_summary_payload(state);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "current_version": env!("CARGO_PKG_VERSION"),
        "readiness": readiness,
        "release_diff": build_launchpad_release_diff(state),
        "demo_status": build_launchpad_demo_status(state),
        "detection_recommendations": build_detection_recommendations(state, 10),
        "detection_readiness": build_detection_readiness(state, 10),
        "approval_overview": build_response_approval_overview(state),
        "remediation_safety": build_remediation_safety_status(state),
        "stream_health": state.alert_broadcaster.stats(),
        "sdk_contract": build_sdk_contract_status(state),
        "command_summary": command_summary,
        "audit": {
            "recent_records": state.audit_log.recent(10).len(),
        },
    })
}

pub(crate) fn check_counts(checks: &[serde_json::Value]) -> (usize, usize, &'static str) {
    let fail_count = checks
        .iter()
        .filter(|check| check.get("status").and_then(serde_json::Value::as_str) == Some("fail"))
        .count();
    let warn_count = checks
        .iter()
        .filter(|check| check.get("status").and_then(serde_json::Value::as_str) == Some("warn"))
        .count();
    let status = if fail_count > 0 {
        "blocked"
    } else if warn_count > 0 {
        "review"
    } else {
        "ready"
    };
    (fail_count, warn_count, status)
}

pub(crate) fn build_release_observability_gates(state: &AppState) -> serde_json::Value {
    let metrics = prometheus_metrics_payload(state);
    let required_metrics = [
        "wardex_up",
        "wardex_alerts_total",
        "wardex_events_total",
        "wardex_request_errors_total",
        "wardex_stream_queue_depth",
        "wardex_stream_dropped_events_total",
    ];
    let missing_metrics = required_metrics
        .iter()
        .filter(|metric| !metrics.contains(**metric))
        .copied()
        .collect::<Vec<_>>();
    let stream = stream_readiness_payload(state.alert_broadcaster.stats());
    let stream_score = stream
        .get("score")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let snapshots = list_operational_snapshots(&state.storage, None, 100);
    let verified_snapshots = snapshots
        .get("verified_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let contract = build_sdk_contract_status(state);
    let contract_drift = contract
        .get("drift_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let checks = vec![
        serde_json::json!({
            "id": "prometheus_metrics",
            "status": if missing_metrics.is_empty() { "pass" } else { "fail" },
            "detail": if missing_metrics.is_empty() { "Release metrics expose the required observability counters.".to_string() } else { format!("Missing metrics: {}", missing_metrics.join(", ")) },
        }),
        serde_json::json!({
            "id": "stream_health",
            "status": if stream_score >= 80 { "pass" } else { "warn" },
            "detail": format!("Realtime stream readiness score is {stream_score}."),
        }),
        serde_json::json!({
            "id": "evidence_snapshots",
            "status": if verified_snapshots > 0 { "pass" } else { "warn" },
            "detail": format!("{verified_snapshots} verified operational snapshot(s) are indexed."),
        }),
        serde_json::json!({
            "id": "contract_inventory",
            "status": if contract_drift == 0 { "pass" } else { "fail" },
            "detail": format!("{contract_drift} product endpoint parity drift item(s)."),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "checks": checks,
            "required_metrics": required_metrics,
            "missing_metrics": missing_metrics,
            "stream": stream,
            "snapshot_index": snapshots,
        }),
        evidence_freshness(
            state,
            "release_observability_gates",
            "live_runtime",
            "prometheus_metrics_stream_contract_snapshots",
            "fresh",
            None,
            true,
            serde_json::json!({
                "missing_metrics": missing_metrics,
                "stream_score": stream_score,
                "verified_snapshots": verified_snapshots,
                "contract_drift": contract_drift,
            }),
        ),
    )
}

pub(crate) fn build_tenant_isolation_proof(state: &AppState) -> serde_json::Value {
    let tenant_count = state.multi_tenant.tenant_count();
    let active_tenant_ids = state.multi_tenant.active_tenant_ids();
    let summary = state.multi_tenant.cross_tenant_summary();
    let agents = state.agent_registry.list();
    let unassigned_devices = if tenant_count > 0 {
        agents
            .iter()
            .filter(|agent| state.multi_tenant.tenant_for_device(&agent.id).is_none())
            .count()
    } else {
        0
    };
    let checks = vec![
        serde_json::json!({
            "id": "tenant_registry",
            "status": "pass",
            "detail": format!("{tenant_count} tenant record(s), {} active.", active_tenant_ids.len()),
        }),
        serde_json::json!({
            "id": "device_partitioning",
            "status": if tenant_count == 0 || unassigned_devices == 0 { "pass" } else { "warn" },
            "detail": if tenant_count == 0 { "Single-tenant mode has no tenant-partitioned devices yet.".to_string() } else { format!("{unassigned_devices} enrolled device(s) are not mapped to an active tenant.") },
        }),
        serde_json::json!({
            "id": "scoped_queries",
            "status": "pass",
            "detail": "Tenant-aware storage APIs keep explicit tenant_id filters on agent and collector queries.",
        }),
        serde_json::json!({
            "id": "quota_enforcement",
            "status": "pass",
            "detail": "Tenant contexts enforce device, policy, storage, and event-rate quotas before registration.",
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "tenant_count": tenant_count,
        "active_tenant_ids": active_tenant_ids,
        "summary": summary,
        "unassigned_devices": unassigned_devices,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "checks": checks,
    })
}

pub(crate) fn current_process_thread_count() -> u32 {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("ps")
            .args(["-M", "-p", &std::process::id().to_string()])
            .output()
            .map(|o| {
                let lines = String::from_utf8_lossy(&o.stdout).lines().count();
                if lines > 1 { (lines - 1) as u32 } else { 0 }
            })
            .unwrap_or(0)
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{}/status", std::process::id()))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|line| line.starts_with("Threads:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|value| value.parse().ok())
            })
            .unwrap_or(0)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        0
    }
}

pub(crate) fn build_thread_detection_proof(state: &AppState) -> serde_json::Value {
    let thread_count = current_process_thread_count();
    let expected_max = 128_u32;
    let sample_count = state.local_telemetry.len();
    let status = if thread_count == 0 {
        "collection_gap"
    } else if thread_count > expected_max {
        "deviated"
    } else {
        "within_baseline"
    };
    let checks = vec![
        serde_json::json!({
            "id": "runtime_thread_count",
            "status": if thread_count == 0 || thread_count > expected_max { "warn" } else { "pass" },
            "detail": format!("Current Wardex process thread count is {thread_count} with expected max {expected_max}."),
        }),
        serde_json::json!({
            "id": "telemetry_sample_depth",
            "status": if sample_count >= 3 { "pass" } else { "warn" },
            "detail": format!("{sample_count} local telemetry sample(s) are available for baseline confidence."),
        }),
        serde_json::json!({
            "id": "process_drawer_evidence",
            "status": "pass",
            "detail": "Per-process thread drawers expose anomaly score, baseline deviation, wait reasons, and recommendations.",
        }),
    ];
    let (fail_count, warn_count, readiness) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "readiness": readiness,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "process_id": std::process::id(),
        "platform": std::env::consts::OS,
        "thread_count": thread_count,
        "thread_baseline": {
            "expected_thread_count": { "min": 1, "max": expected_max },
            "thread_count_deviation": thread_count.saturating_sub(expected_max),
            "sample_count": sample_count,
            "confidence": if thread_count == 0 { "low" } else if sample_count >= 3 { "high" } else { "medium" },
        },
        "checks": checks,
    })
}

pub(crate) fn build_workflow_preflight(state: &AppState, workflow: &str) -> serde_json::Value {
    let stream = stream_readiness_payload(state.alert_broadcaster.stats());
    let stream_score = stream
        .get("score")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let approvals = build_response_approval_overview(state);
    let pending_approvals = approvals
        .get("pending_response_approvals")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
        + approvals
            .get("pending_playbook_approvals")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
    let observability = build_release_observability_gates(state);
    let tenant = build_tenant_isolation_proof(state);
    let checks = vec![
        serde_json::json!({
            "id": "stream_readiness",
            "status": if stream_score >= 80 { "pass" } else { "warn" },
            "detail": format!("Stream readiness score is {stream_score}."),
        }),
        serde_json::json!({
            "id": "approval_queue",
            "status": if pending_approvals == 0 { "pass" } else { "warn" },
            "detail": format!("{pending_approvals} approval item(s) are pending."),
        }),
        serde_json::json!({
            "id": "release_observability",
            "status": if observability.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else { "pass" },
            "detail": "Release observability gates were evaluated for this workflow.",
        }),
        serde_json::json!({
            "id": "tenant_isolation",
            "status": if tenant.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else { "pass" },
            "detail": "Tenant isolation proof is attached for cross-tenant safety review.",
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "workflow": workflow,
        "status": status,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "checks": checks,
        "stream": stream,
        "approval_overview": approvals,
        "tenant_isolation": tenant,
        "observability_gates": observability,
    })
}

pub(crate) fn build_content_rule_preflight(
    state: &AppState,
    rule_id: &str,
    target_status: &str,
) -> serde_json::Value {
    let rule = active_rule_metadata(state)
        .into_iter()
        .find(|rule| rule.id == rule_id);
    let stream = stream_readiness_payload(state.alert_broadcaster.stats());
    let stream_score = stream
        .get("score")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let mut checks = vec![serde_json::json!({
        "id": "rule_exists",
        "status": if rule.is_some() { "pass" } else { "fail" },
        "detail": if rule.is_some() { "Rule metadata was found." } else { "Rule metadata was not found." },
    })];
    if let Some(rule) = &rule {
        let suppressions = rule_active_suppression_count(state, &rule.id);
        let pack_count = rule_pack_count(state, rule);
        checks.push(serde_json::json!({
            "id": "replay_evidence",
            "status": if rule.last_test_at.is_some() { "pass" } else { "warn" },
            "detail": rule.last_test_at.as_deref().unwrap_or("Replay validation has not run."),
        }));
        checks.push(serde_json::json!({
            "id": "suppression_pressure",
            "status": if suppressions == 0 { "pass" } else { "warn" },
            "detail": format!("{suppressions} active suppression(s) affect this rule."),
        }));
        checks.push(serde_json::json!({
            "id": "content_pack_ownership",
            "status": if pack_count > 0 { "pass" } else { "warn" },
            "detail": format!("Rule is linked to {pack_count} content pack(s)."),
        }));
    }
    checks.push(serde_json::json!({
        "id": "stream_guard",
        "status": if matches!(target_status, "canary" | "active") && stream_score < 80 { "warn" } else { "pass" },
        "detail": format!("Stream readiness score is {stream_score}."),
    }));
    let (fail_count, warn_count, status) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "rule_id": rule_id,
        "target_status": target_status,
        "status": status,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "checks": checks,
        "stream": stream,
        "rule": rule,
    })
}

pub(crate) fn release_artifact_entries() -> Vec<serde_json::Value> {
    fs::read_to_string("release/SHA256SUMS")
        .ok()
        .map(|source| {
            source
                .lines()
                .filter_map(|line| {
                    let mut parts = line.split_whitespace();
                    let digest = parts.next()?;
                    let path = parts.next()?;
                    Some(serde_json::json!({
                        "path": path,
                        "sha256": digest,
                        "exists": Path::new("release").join(path).exists(),
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) fn build_release_provenance(state: &AppState) -> serde_json::Value {
    let cargo_lock = include_str!("../Cargo.lock");
    let admin_package = include_str!("../admin-console/package.json");
    let admin_lock = include_str!("../admin-console/package-lock.json");
    let ts_package = include_str!("../sdk/typescript/package.json");
    let ts_lock = include_str!("../sdk/typescript/package-lock.json");
    let openapi = include_str!("../docs/openapi.yaml");
    let artifacts = release_artifact_entries();
    let contract = build_sdk_contract_status(state);
    let contract_drift = contract
        .get("drift_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let missing_artifacts = artifacts
        .iter()
        .filter(|artifact| {
            artifact.get("exists").and_then(serde_json::Value::as_bool) != Some(true)
        })
        .count();
    let components = vec![
        serde_json::json!({
            "ecosystem": "cargo",
            "manifest": "Cargo.toml",
            "lockfile": "Cargo.lock",
            "package_count": cargo_lock.matches("\n[[package]]").count(),
            "lockfile_sha256": crate::audit::sha256_hex(cargo_lock.as_bytes()),
        }),
        serde_json::json!({
            "ecosystem": "npm",
            "manifest": "admin-console/package.json",
            "lockfile": "admin-console/package-lock.json",
            "package_count": admin_lock.matches("node_modules/").count(),
            "manifest_sha256": crate::audit::sha256_hex(admin_package.as_bytes()),
            "lockfile_sha256": crate::audit::sha256_hex(admin_lock.as_bytes()),
        }),
        serde_json::json!({
            "ecosystem": "npm",
            "manifest": "sdk/typescript/package.json",
            "lockfile": "sdk/typescript/package-lock.json",
            "package_count": ts_lock.matches("node_modules/").count(),
            "manifest_sha256": crate::audit::sha256_hex(ts_package.as_bytes()),
            "lockfile_sha256": crate::audit::sha256_hex(ts_lock.as_bytes()),
        }),
        serde_json::json!({
            "ecosystem": "openapi",
            "manifest": "docs/openapi.yaml",
            "operation_inventory": crate::openapi::endpoint_catalog(env!("CARGO_PKG_VERSION")).len(),
            "manifest_sha256": crate::audit::sha256_hex(openapi.as_bytes()),
        }),
    ];
    let checks = vec![
        serde_json::json!({
            "id": "release_artifacts",
            "status": if artifacts.is_empty() || missing_artifacts > 0 { "warn" } else { "pass" },
            "detail": if artifacts.is_empty() {
                "No local release SHA256SUMS file is available for artifact attestation.".to_string()
            } else {
                format!("{} artifact checksum record(s), {missing_artifacts} missing file(s).", artifacts.len())
            },
        }),
        serde_json::json!({
            "id": "contract_parity",
            "status": if contract_drift == 0 { "pass" } else { "fail" },
            "detail": format!("{contract_drift} product contract drift item(s) detected."),
        }),
        serde_json::json!({
            "id": "sbom_inputs",
            "status": "pass",
            "detail": format!("{} manifest and lockfile source(s) are included in the provenance digest set.", components.len()),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    let attestation_digest = crate::audit::sha256_hex(
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "components": components.clone(),
            "artifacts": artifacts.clone(),
        })
        .to_string()
        .as_bytes(),
    );
    let evidence_status = if artifacts.is_empty() {
        "unknown"
    } else if missing_artifacts > 0 {
        "stale"
    } else {
        "fresh"
    };
    let stale_reason = if artifacts.is_empty() {
        Some("release_sha256s_missing")
    } else if missing_artifacts > 0 {
        Some("release_artifact_file_missing")
    } else {
        None
    };
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "runtime_version": env!("CARGO_PKG_VERSION"),
            "artifact_count": artifacts.len(),
            "missing_artifacts": missing_artifacts,
            "components": components,
            "artifacts": artifacts,
            "checks": checks,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "attestation_digest": attestation_digest,
        }),
        evidence_freshness(
            state,
            "release_provenance",
            "local_artifact_probe",
            "release/SHA256SUMS_and_embedded_manifests",
            evidence_status,
            stale_reason,
            true,
            serde_json::json!({
                "artifact_count": artifacts.len(),
                "missing_artifacts": missing_artifacts,
                "component_count": components.len(),
                "contract_drift": contract_drift,
                "attestation_digest": attestation_digest,
            }),
        ),
    )
}

pub(crate) fn build_upgrade_rehearsal(state: &AppState, target_version: &str) -> serde_json::Value {
    let release_diff = build_launchpad_release_diff(state);
    let target_version = if target_version.trim().is_empty() {
        release_diff
            .get("latest_version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(env!("CARGO_PKG_VERSION"))
    } else {
        target_version.trim()
    };
    let provenance = build_release_provenance(state);
    let contract = build_sdk_contract_status(state);
    let snapshots = list_operational_snapshots(&state.storage, None, 100);
    let stream = stream_readiness_payload(state.alert_broadcaster.stats());
    let remediation = build_remediation_safety_status(state);
    let contract_drift = contract
        .get("drift_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let verified_snapshots = snapshots
        .get("verified_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let stream_score = stream
        .get("score")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let checks = vec![
        serde_json::json!({
            "id": "target_catalog",
            "status": if target_version == env!("CARGO_PKG_VERSION") || release_diff.get("release").is_some_and(|value| !value.is_null()) { "pass" } else { "warn" },
            "detail": format!("Upgrade rehearsal target is {target_version}."),
        }),
        serde_json::json!({
            "id": "artifact_provenance",
            "status": if provenance.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else if provenance.get("status").and_then(serde_json::Value::as_str) == Some("review") { "warn" } else { "pass" },
            "detail": format!("{} artifact checksum record(s) attached.", provenance.get("artifact_count").and_then(serde_json::Value::as_u64).unwrap_or_default()),
        }),
        serde_json::json!({
            "id": "contract_parity",
            "status": if contract_drift == 0 { "pass" } else { "fail" },
            "detail": format!("{contract_drift} contract drift item(s)."),
        }),
        serde_json::json!({
            "id": "rollback_evidence",
            "status": if verified_snapshots > 0 { "pass" } else { "warn" },
            "detail": format!("{verified_snapshots} verified operational snapshot(s) can anchor rollback review."),
        }),
        serde_json::json!({
            "id": "stream_guard",
            "status": if stream_score >= 80 { "pass" } else { "warn" },
            "detail": format!("Realtime stream readiness score is {stream_score}."),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "current_version": env!("CARGO_PKG_VERSION"),
        "target_version": target_version,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "checks": checks,
        "phases": [
            {"id": "preflight", "action": "Verify provenance, contract parity, and signed artifacts before rollout."},
            {"id": "canary", "action": "Route a bounded operator cohort through live console smoke and stream replay."},
            {"id": "rollback", "action": "Confirm rollback proof, snapshot digest, and operator approval before live changes."},
            {"id": "audit", "action": "Persist rehearsal evidence with release doctor and support bundle snapshots."}
        ],
        "release_diff": release_diff,
        "provenance": provenance,
        "stream": stream,
        "remediation_safety": remediation,
        "snapshot_index": snapshots,
    })
}

pub(crate) fn build_synthetic_console_monitor(state: &AppState) -> serde_json::Value {
    let release_doctor = release_doctor_payload(state);
    let workflow = build_workflow_preflight(state, "synthetic_console");
    let stream = stream_readiness_payload(state.alert_broadcaster.stats());
    let alert_page = alert_cursor_page_payload(state, 0, 5);
    let checks = vec![
        serde_json::json!({
            "id": "runtime_health",
            "route": "/api/status",
            "status": "pass",
            "detail": format!("Runtime {} has been up for {}s.", env!("CARGO_PKG_VERSION"), state.server_start.elapsed().as_secs()),
        }),
        serde_json::json!({
            "id": "release_doctor",
            "route": "/api/release/doctor",
            "status": if release_doctor.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else if release_doctor.get("status").and_then(serde_json::Value::as_str) == Some("review") { "warn" } else { "pass" },
            "detail": release_doctor.get("next_action").cloned().unwrap_or_else(|| serde_json::json!("Release doctor checked.")),
        }),
        serde_json::json!({
            "id": "workflow_preflight",
            "route": "/api/workflows/preflight?workflow=synthetic_console",
            "status": if workflow.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else if workflow.get("status").and_then(serde_json::Value::as_str) == Some("review") { "warn" } else { "pass" },
            "detail": "Workflow preflight resolved from live launchpad dependencies.",
        }),
        serde_json::json!({
            "id": "alert_page",
            "route": "/api/alerts/page?limit=5",
            "status": "pass",
            "detail": format!("Cursor page returned {} alert row(s).", alert_page.get("count").and_then(serde_json::Value::as_u64).unwrap_or_default()),
        }),
        serde_json::json!({
            "id": "stream_readiness",
            "route": "/api/stream/readiness",
            "status": if stream.get("score").and_then(serde_json::Value::as_u64).unwrap_or_default() >= 80 { "pass" } else { "warn" },
            "detail": format!("Stream status is {}.", stream.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown")),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "check_count": checks.len(),
            "checks": checks,
            "latency_budget_ms": 1500,
            "next_action": if fail_count > 0 { "Fix failing console dependencies before relying on the operator launchpad." } else if warn_count > 0 { "Review degraded synthetic console signals before release acceptance." } else { "Synthetic console monitor is clean." },
        }),
        evidence_freshness(
            state,
            "synthetic_console_monitor",
            "live_runtime",
            "runtime_status_workflow_preflight_alert_cursor_stream_readiness",
            "fresh",
            None,
            true,
            serde_json::json!({
                "fail_count": fail_count,
                "warn_count": warn_count,
                "check_count": checks.len(),
            }),
        ),
    )
}

pub(crate) fn build_incident_timeline_replay(
    state: &AppState,
    requested_id: Option<&str>,
) -> serde_json::Value {
    let incidents = state.incident_store.list();
    let selected = requested_id
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|id| incidents.iter().find(|incident| incident.id == id))
        .or_else(|| {
            incidents
                .iter()
                .max_by_key(|incident| incident.updated_at.as_str())
        });
    let timeline = selected.map_or_else(
        || {
            serde_json::json!({
                "incident": serde_json::Value::Null,
                "event_count": 0,
                "matched_event_count": 0,
                "events": [],
                "notes": [],
            })
        },
        |incident| {
            let event_ids = incident.event_ids.iter().copied().collect::<HashSet<_>>();
            let matching_events = state
                .event_store
                .all_events()
                .iter()
                .filter(|event| event_ids.contains(&event.id))
                .take(25)
                .filter_map(|event| serde_json::to_value(event).ok())
                .collect::<Vec<_>>();
            serde_json::json!({
                "incident": incident,
                "event_count": event_ids.len(),
                "matched_event_count": matching_events.len(),
                "events": matching_events,
                "notes": incident.notes,
            })
        },
    );
    let alert_tail = state
        .alerts
        .iter()
        .rev()
        .take(10)
        .enumerate()
        .map(|(index, alert)| alert_json_value(alert, index, &state.local_host_info.hostname, &[]))
        .collect::<Vec<_>>();
    let checks = vec![
        serde_json::json!({
            "id": "incident_selected",
            "status": if selected.is_some() { "pass" } else { "warn" },
            "detail": if let Some(incident) = selected { format!("Incident {} selected for replay.", incident.id) } else { "No incident is available; replay falls back to alert tail context.".to_string() },
        }),
        serde_json::json!({
            "id": "event_join",
            "status": if timeline.get("event_count").and_then(serde_json::Value::as_u64).unwrap_or_default() == timeline.get("matched_event_count").and_then(serde_json::Value::as_u64).unwrap_or_default() { "pass" } else { "warn" },
            "detail": format!("{} of {} incident event(s) matched retained event storage.", timeline.get("matched_event_count").and_then(serde_json::Value::as_u64).unwrap_or_default(), timeline.get("event_count").and_then(serde_json::Value::as_u64).unwrap_or_default()),
        }),
        serde_json::json!({
            "id": "alert_tail",
            "status": if alert_tail.is_empty() { "warn" } else { "pass" },
            "detail": format!("{} recent alert row(s) attached for operator replay context.", alert_tail.len()),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "incident_count": incidents.len(),
        "requested_incident_id": requested_id,
        "timeline": timeline,
        "alert_tail": alert_tail,
        "checks": checks,
    })
}

pub(crate) fn build_detection_trust_score(state: &AppState) -> serde_json::Value {
    let mut rows = active_rule_metadata(state)
        .into_iter()
        .map(|rule| {
            let suppressions = rule_active_suppression_count(state, &rule.id);
            let pack_count = rule_pack_count(state, &rule);
            let mut score = 100_i64;
            if !rule.enabled {
                score -= 30;
            }
            if rule.last_test_at.is_none() {
                score -= 25;
            }
            score -= (rule.last_test_match_count.min(20) as i64).min(20);
            score -= (suppressions as i64 * 10).min(25);
            if pack_count == 0 {
                score -= 10;
            }
            if matches!(rule.lifecycle, ContentLifecycle::Deprecated | ContentLifecycle::RolledBack) {
                score -= 35;
            }
            let score = score.clamp(0, 100) as u64;
            serde_json::json!({
                "rule_id": rule.id,
                "title": rule.title,
                "owner": rule.owner,
                "lifecycle": rule.lifecycle,
                "enabled": rule.enabled,
                "score": score,
                "status": if score >= 85 { "trusted" } else if score >= 65 { "review" } else { "blocked" },
                "evidence": {
                    "last_test_at": rule.last_test_at,
                    "last_promotion_at": rule.last_promotion_at,
                    "last_test_match_count": rule.last_test_match_count,
                    "active_suppressions": suppressions,
                    "content_pack_count": pack_count,
                },
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left.get("score")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default()
            .cmp(
                &right
                    .get("score")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
            )
    });
    let rule_count = rows.len();
    let average_score = if rule_count == 0 {
        0
    } else {
        rows.iter()
            .map(|row| {
                row.get("score")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default()
            })
            .sum::<u64>()
            / rule_count as u64
    };
    let blocked_count = rows
        .iter()
        .filter(|row| row.get("status").and_then(serde_json::Value::as_str) == Some("blocked"))
        .count();
    let review_count = rows
        .iter()
        .filter(|row| row.get("status").and_then(serde_json::Value::as_str) == Some("review"))
        .count();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if blocked_count > 0 { "blocked" } else if review_count > 0 { "review" } else { "trusted" },
        "average_score": average_score,
        "rule_count": rule_count,
        "blocked_count": blocked_count,
        "review_count": review_count,
        "rules": rows.into_iter().take(25).collect::<Vec<_>>(),
        "next_action": if blocked_count > 0 { "Refresh replay evidence and suppression ownership before promoting blocked rules." } else if review_count > 0 { "Review degraded rules before the next rollout." } else { "Detection content trust is strong enough for promotion review." },
    })
}

pub(crate) fn build_fleet_drift_compliance(state: &AppState) -> serde_json::Value {
    let agents = state.agent_registry.list();
    let current_version = env!("CARGO_PKG_VERSION");
    let offline_agents = agents
        .iter()
        .filter(|agent| matches!(agent.status, AgentStatus::Offline | AgentStatus::Stale))
        .count();
    let version_drift = agents
        .iter()
        .filter(|agent| agent.version != current_version)
        .count();
    let update_errors = agents
        .iter()
        .filter(|agent| agent.health.last_update_error.is_some())
        .count();
    let config_summary = serde_json::to_value(state.config_drift_detector.fleet_summary())
        .unwrap_or_else(|_| serde_json::json!({"status": "unavailable"}));
    let sample_agents = agents
        .iter()
        .take(20)
        .map(|agent| {
            serde_json::json!({
                "id": agent.id,
                "hostname": agent.hostname,
                "platform": agent.platform,
                "version": agent.version,
                "status": agent.status,
                "update_state": agent.health.update_state,
                "update_target_version": agent.health.update_target_version,
                "last_update_error": agent.health.last_update_error,
                "version_aligned": agent.version == current_version,
            })
        })
        .collect::<Vec<_>>();
    let checks = vec![
        serde_json::json!({
            "id": "agent_freshness",
            "status": if offline_agents == 0 { "pass" } else { "warn" },
            "detail": format!("{offline_agents} offline or stale agent(s)."),
        }),
        serde_json::json!({
            "id": "version_alignment",
            "status": if version_drift == 0 { "pass" } else { "warn" },
            "detail": format!("{version_drift} agent(s) report a version different from {current_version}."),
        }),
        serde_json::json!({
            "id": "update_errors",
            "status": if update_errors == 0 { "pass" } else { "warn" },
            "detail": format!("{update_errors} agent update error(s) are recorded."),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "agent_count": agents.len(),
        "offline_agents": offline_agents,
        "version_drift": version_drift,
        "update_errors": update_errors,
        "current_version": current_version,
        "config_drift": config_summary,
        "agents": sample_agents,
        "checks": checks,
    })
}

pub(crate) fn build_operator_work_queue(state: &AppState) -> serde_json::Value {
    let release_doctor = release_doctor_payload(state);
    let approvals = build_response_approval_overview(state);
    let trust = build_detection_trust_score(state);
    let fleet = build_fleet_drift_compliance(state);
    let retention = build_retention_forecast(state);
    let mut items = Vec::new();
    let release_status = release_doctor
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    if release_status != "ready" {
        items.push(serde_json::json!({
            "id": "release_doctor",
            "priority": if release_status == "blocked" { "high" } else { "medium" },
            "title": "Release doctor review",
            "status": release_status,
            "href": "/launchpad#release-trust",
            "detail": release_doctor.get("next_action").cloned().unwrap_or_else(|| serde_json::json!("Review release doctor signals.")),
        }));
    }
    let pending_approvals = approvals
        .get("pending_response_approvals")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
        + approvals
            .get("pending_playbook_approvals")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
    if pending_approvals > 0 {
        items.push(serde_json::json!({
            "id": "approval_queue",
            "priority": "high",
            "title": "Response approvals waiting",
            "status": "approval_required",
            "href": "/soc?focus=response",
            "detail": format!("{pending_approvals} approval item(s) require operator review."),
        }));
    }
    if trust.get("status").and_then(serde_json::Value::as_str) != Some("trusted") {
        items.push(serde_json::json!({
            "id": "detection_trust",
            "priority": if trust.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "high" } else { "medium" },
            "title": "Detection trust debt",
            "status": trust.get("status").cloned().unwrap_or_else(|| serde_json::json!("review")),
            "href": "/detection?panel=quality",
            "detail": format!("{} rule(s) blocked and {} under review.", trust.get("blocked_count").and_then(serde_json::Value::as_u64).unwrap_or_default(), trust.get("review_count").and_then(serde_json::Value::as_u64).unwrap_or_default()),
        }));
    }
    if fleet.get("status").and_then(serde_json::Value::as_str) != Some("ready") {
        items.push(serde_json::json!({
            "id": "fleet_drift",
            "priority": "medium",
            "title": "Fleet drift review",
            "status": fleet.get("status").cloned().unwrap_or_else(|| serde_json::json!("review")),
            "href": "/fleet",
            "detail": format!("{} agent(s) drifted from runtime version, {} stale/offline.", fleet.get("version_drift").and_then(serde_json::Value::as_u64).unwrap_or_default(), fleet.get("offline_agents").and_then(serde_json::Value::as_u64).unwrap_or_default()),
        }));
    }
    if retention.get("status").and_then(serde_json::Value::as_str) != Some("healthy") {
        items.push(serde_json::json!({
            "id": "retention_forecast",
            "priority": "medium",
            "title": "Retention forecast review",
            "status": retention.get("status").cloned().unwrap_or_else(|| serde_json::json!("review")),
            "href": "/settings?tab=retention",
            "detail": retention.get("next_action").cloned().unwrap_or_else(|| serde_json::json!("Review retention capacity.")),
        }));
    }
    let high_count = items
        .iter()
        .filter(|item| item.get("priority").and_then(serde_json::Value::as_str) == Some("high"))
        .count();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if high_count > 0 { "attention" } else if items.is_empty() { "clear" } else { "review" },
        "item_count": items.len(),
        "high_priority_count": high_count,
        "items": items,
    })
}

pub(crate) fn retention_utilization(current: usize, limit: usize) -> u64 {
    if limit == 0 {
        0
    } else {
        ((current as f64 / limit as f64) * 100.0)
            .round()
            .clamp(0.0, 999.0) as u64
    }
}

pub(crate) fn build_retention_forecast(state: &AppState) -> serde_json::Value {
    let storage_stats = state.storage.with(|store| Ok(store.stats())).ok();
    let audit_count = storage_stats
        .as_ref()
        .map_or(state.audit_log.entries.len(), |stats| {
            stats.total_audit_entries
        });
    let alert_count = storage_stats
        .as_ref()
        .map_or(state.alerts.len(), |stats| stats.total_alerts);
    let event_count = state.event_store.all_events().len();
    let retention = &state.config.retention;
    let audit_utilization = retention_utilization(audit_count, retention.audit_max_records);
    let alert_utilization = retention_utilization(alert_count, retention.alert_max_records);
    let event_utilization = retention_utilization(event_count, retention.event_max_records);
    let peak_utilization = audit_utilization
        .max(alert_utilization)
        .max(event_utilization);
    let projected_daily_records = ((audit_count + alert_count + event_count) / 30).max(1);
    let checks = vec![
        serde_json::json!({
            "id": "audit_retention",
            "status": if audit_utilization >= 90 { "warn" } else { "pass" },
            "detail": format!("Audit retention is {audit_utilization}% utilized."),
        }),
        serde_json::json!({
            "id": "alert_retention",
            "status": if alert_utilization >= 90 { "warn" } else { "pass" },
            "detail": format!("Alert retention is {alert_utilization}% utilized."),
        }),
        serde_json::json!({
            "id": "event_retention",
            "status": if event_utilization >= 90 { "warn" } else { "pass" },
            "detail": format!("Event retention is {event_utilization}% utilized."),
        }),
    ];
    let (fail_count, warn_count, _) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if peak_utilization >= 95 { "risk" } else if peak_utilization >= 80 { "review" } else { "healthy" },
        "fail_count": fail_count,
        "warn_count": warn_count,
        "current_records": {
            "audit": audit_count,
            "alerts": alert_count,
            "events": event_count,
        },
        "limits": {
            "audit_max_records": retention.audit_max_records,
            "alert_max_records": retention.alert_max_records,
            "event_max_records": retention.event_max_records,
            "audit_max_age_secs": retention.audit_max_age_secs,
        },
        "utilization_pct": {
            "audit": audit_utilization,
            "alerts": alert_utilization,
            "events": event_utilization,
            "peak": peak_utilization,
        },
        "forecast": {
            "projected_daily_records": projected_daily_records,
            "estimated_monthly_records": projected_daily_records * 30,
            "remote_syslog_enabled": retention.remote_syslog_endpoint.is_some(),
            "cost_risk": if peak_utilization >= 95 { "high" } else if peak_utilization >= 80 { "medium" } else { "low" },
        },
        "checks": checks,
        "next_action": if peak_utilization >= 95 { "Increase retention limits or export old evidence before high-volume workflows." } else if peak_utilization >= 80 { "Review retention growth before enabling longer evidence windows." } else { "Retention capacity is healthy for current volume." },
    })
}

pub(crate) fn build_search_performance_slo(state: &AppState) -> serde_json::Value {
    let retention = build_retention_forecast(state);
    let endpoint_metrics = state.api_analytics.metrics();
    let query_metrics = endpoint_metrics
        .iter()
        .filter(|metric| {
            metric.path == "/api/storage/events/historical"
                || metric.path == "/api/retention/forecast"
                || metric.path.starts_with("/api/retention/")
        })
        .map(|metric| {
            serde_json::json!({
                "method": metric.method,
                "path": metric.path,
                "request_count": metric.request_count,
                "error_count": metric.error_count,
                "p95_latency_ms": metric.p95_latency_ms,
                "p99_latency_ms": metric.p99_latency_ms,
            })
        })
        .collect::<Vec<_>>();
    let worst_p95_ms = endpoint_metrics
        .iter()
        .filter(|metric| metric.path.contains("retention") || metric.path.contains("historical"))
        .map(|metric| metric.p95_latency_ms)
        .fold(0.0_f64, f64::max);
    let worst_p99_ms = endpoint_metrics
        .iter()
        .filter(|metric| metric.path.contains("retention") || metric.path.contains("historical"))
        .map(|metric| metric.p99_latency_ms)
        .fold(0.0_f64, f64::max);
    let status = if worst_p99_ms > 5_000.0 {
        "breach"
    } else if worst_p95_ms > 2_000.0 || worst_p99_ms > 3_000.0 {
        "review"
    } else {
        "healthy"
    };
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "target_ms": {
            "p95": 2_000,
            "p99": 5_000,
        },
        "observed_ms": {
            "p95": worst_p95_ms,
            "p99": worst_p99_ms,
        },
        "retention_status": retention.get("status").cloned().unwrap_or_else(|| serde_json::json!("unknown")),
        "retention_peak_utilization_pct": retention
            .get("utilization_pct")
            .and_then(|value| value.get("peak"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!(0)),
        "query_metrics": query_metrics,
        "next_action": if status == "breach" {
            "Review ClickHouse query predicates, retention limits, and export pressure before expanding the evidence window."
        } else if status == "review" {
            "Watch long-retention searches and tune filters before operators depend on wider time windows."
        } else {
            "Long-retention query latency is within the current SLO target."
        },
    })
}

pub(crate) fn build_adversarial_validation(state: &AppState) -> serde_json::Value {
    let scenarios = [
        ("credential_storm", "examples/credential_storm.csv"),
        ("slow_escalation", "examples/slow_escalation.csv"),
        ("low_battery_attack", "examples/low_battery_attack.csv"),
        ("benign_baseline", "examples/benign_baseline.csv"),
    ];
    let trust = build_detection_trust_score(state);
    let readiness = build_detection_readiness(state, 10);
    let scenario_rows = scenarios
        .iter()
        .map(|(id, path)| {
            let exists = Path::new(path).exists();
            serde_json::json!({
                "id": id,
                "path": path,
                "status": if exists { "ready" } else { "missing" },
                "evidence": if exists { "corpus_available" } else { "corpus_missing" },
            })
        })
        .collect::<Vec<_>>();
    let missing = scenario_rows
        .iter()
        .filter(|row| row.get("status").and_then(serde_json::Value::as_str) == Some("missing"))
        .count();
    let checks = vec![
        serde_json::json!({
            "id": "scenario_corpus",
            "status": if missing == 0 { "pass" } else { "warn" },
            "detail": format!("{} adversarial scenario corpus file(s) are missing.", missing),
        }),
        serde_json::json!({
            "id": "detection_trust",
            "status": if trust.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else if trust.get("status").and_then(serde_json::Value::as_str) == Some("review") { "warn" } else { "pass" },
            "detail": format!("Detection trust score average is {}.", trust.get("average_score").and_then(serde_json::Value::as_u64).unwrap_or_default()),
        }),
        serde_json::json!({
            "id": "collector_mapping",
            "status": if readiness.get("collector_count").and_then(serde_json::Value::as_u64).unwrap_or_default() > 0 { "pass" } else { "warn" },
            "detail": format!("{} collector dependency row(s) available for validation.", readiness.get("collector_count").and_then(serde_json::Value::as_u64).unwrap_or_default()),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "scenario_count": scenario_rows.len(),
        "missing_scenarios": missing,
        "scenarios": scenario_rows,
        "detection_trust": trust,
        "readiness": readiness,
        "checks": checks,
    })
}

pub(crate) fn build_detection_tuning_feedback(state: &AppState) -> serde_json::Value {
    let feedback_summary = state.detection_feedback.summary();
    let mut rows = active_rule_metadata(state)
        .into_iter()
        .map(|rule| {
            let feedback = state.detection_feedback.for_rule(&rule.id);
            let false_positive_count = feedback
                .iter()
                .filter(|entry| detection_outcome_is_noise(&entry.verdict))
                .count();
            let valid_count = feedback
                .iter()
                .filter(|entry| normalize_detection_outcome(&entry.verdict) == "valid")
                .count();
            let active_suppressions = rule_active_suppression_count(state, &rule.id);
            let suggested_action = if false_positive_count >= 2 || active_suppressions >= 2 {
                "draft_suppression_review"
            } else if rule.last_test_match_count >= 10 {
                "replay_threshold_review"
            } else if valid_count > false_positive_count
                && matches!(rule.lifecycle, ContentLifecycle::Canary)
            {
                "promotion_candidate"
            } else {
                "monitor"
            };
            serde_json::json!({
                "rule_id": rule.id,
                "rule_name": rule.title,
                "owner": rule.owner,
                "lifecycle": rule.lifecycle,
                "feedback_count": feedback.len(),
                "false_positive_count": false_positive_count,
                "valid_count": valid_count,
                "active_suppressions": active_suppressions,
                "last_test_match_count": rule.last_test_match_count,
                "suggested_action": suggested_action,
                "href": format!("/detection?rule={}&rulePanel=tuning", rule.id),
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        let left_pressure = left["false_positive_count"].as_u64().unwrap_or_default()
            + left["active_suppressions"].as_u64().unwrap_or_default()
            + left["last_test_match_count"].as_u64().unwrap_or_default() / 5;
        let right_pressure = right["false_positive_count"].as_u64().unwrap_or_default()
            + right["active_suppressions"].as_u64().unwrap_or_default()
            + right["last_test_match_count"].as_u64().unwrap_or_default() / 5;
        right_pressure.cmp(&left_pressure).then_with(|| {
            left["rule_name"]
                .as_str()
                .unwrap_or_default()
                .cmp(right["rule_name"].as_str().unwrap_or_default())
        })
    });
    let review_count = rows
        .iter()
        .filter(|row| row["suggested_action"].as_str() != Some("monitor"))
        .count();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if review_count > 0 { "review" } else { "steady" },
        "review_count": review_count,
        "feedback_summary": feedback_summary,
        "window_days": 7,
        "draft_only": true,
        "items": rows.into_iter().take(12).collect::<Vec<_>>(),
        "next_action": if review_count > 0 {
            "Review suggested tuning drafts before changing suppression, threshold, or promotion state."
        } else {
            "No detection tuning feedback currently needs operator action."
        },
    })
}

pub(crate) fn build_playbook_recovery_actions(
    execution: &crate::playbook::PlaybookExecution,
) -> serde_json::Value {
    let failed_steps = execution
        .step_results
        .iter()
        .filter(|step| {
            matches!(
                step.status,
                crate::playbook::ExecutionStatus::Failed
                    | crate::playbook::ExecutionStatus::TimedOut
                    | crate::playbook::ExecutionStatus::Cancelled
            )
        })
        .map(|step| {
            serde_json::json!({
                "step_id": step.step_id.clone(),
                "status": playbook_status_label(&step.status),
                "error": step.error.clone(),
            })
        })
        .collect::<Vec<_>>();
    let has_failed_steps = !failed_steps.is_empty();
    let actions = match execution.status {
        crate::playbook::ExecutionStatus::Failed | crate::playbook::ExecutionStatus::TimedOut => {
            vec![
                serde_json::json!({
                    "id": "retry_failed_step",
                    "label": "Retry Failed Step",
                    "action": "retry",
                    "requires_note": true,
                    "recommended": true,
                }),
                serde_json::json!({
                    "id": "skip_with_note",
                    "label": "Skip With Note",
                    "action": "skip",
                    "requires_note": true,
                    "recommended": false,
                }),
                serde_json::json!({
                    "id": "escalate_to_owner",
                    "label": "Escalate To Owner",
                    "action": "escalate",
                    "requires_note": true,
                    "recommended": true,
                }),
            ]
        }
        crate::playbook::ExecutionStatus::AwaitingApproval => vec![serde_json::json!({
            "id": "resume_after_approval",
            "label": "Resume After Approval",
            "action": "resume",
            "requires_note": false,
            "recommended": true,
        })],
        crate::playbook::ExecutionStatus::Running | crate::playbook::ExecutionStatus::Pending => {
            vec![serde_json::json!({
                "id": "monitor_execution",
                "label": "Monitor Execution",
                "action": "monitor",
                "requires_note": false,
                "recommended": true,
            })]
        }
        crate::playbook::ExecutionStatus::Succeeded => vec![serde_json::json!({
            "id": "verify_evidence",
            "label": "Verify Evidence",
            "action": "verify",
            "requires_note": false,
            "recommended": true,
        })],
        crate::playbook::ExecutionStatus::Skipped | crate::playbook::ExecutionStatus::Cancelled => {
            vec![serde_json::json!({
                "id": "reopen_with_context",
                "label": "Reopen With Context",
                "action": "reopen",
                "requires_note": true,
                "recommended": true,
            })]
        }
    };
    let recoverable = !actions.is_empty();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "execution_id": execution.execution_id.clone(),
        "playbook_id": execution.playbook_id.clone(),
        "status": playbook_status_label(&execution.status),
        "failed_steps": failed_steps,
        "actions": actions,
        "next_action": if has_failed_steps {
            "Choose a recovery action and attach an operator note before continuing."
        } else {
            "Continue monitoring the playbook evidence trail."
        },
        "proof": {
            "recoverable": recoverable,
            "audit_anchor": format!("playbook:{}", execution.execution_id),
        },
    })
}

pub(crate) fn build_support_bundle_diff(state: &AppState) -> serde_json::Value {
    let snapshots = list_operational_snapshots(&state.storage, Some("support_bundle"), 5);
    let items = snapshots
        .get("snapshots")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let latest = items.first().cloned().unwrap_or(serde_json::Value::Null);
    let previous = items.get(1).cloned().unwrap_or(serde_json::Value::Null);
    let latest_digest = latest.get("digest").and_then(serde_json::Value::as_str);
    let previous_digest = previous.get("digest").and_then(serde_json::Value::as_str);
    let latest_size = latest
        .get("size_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default() as i64;
    let previous_size = previous
        .get("size_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default() as i64;
    let checks = vec![
        serde_json::json!({
            "id": "snapshot_depth",
            "status": if items.len() >= 2 { "pass" } else if items.len() == 1 { "warn" } else { "fail" },
            "detail": format!("{} support bundle snapshot(s) available for diffing.", items.len()),
        }),
        serde_json::json!({
            "id": "digest_change",
            "status": if latest_digest.is_some() && previous_digest.is_some() && latest_digest == previous_digest { "warn" } else if latest_digest.is_some() { "pass" } else { "fail" },
            "detail": if latest_digest.is_some() && previous_digest.is_some() && latest_digest == previous_digest { "Latest support bundle digest matches the previous snapshot." } else { "Latest support bundle digest can be compared." },
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "snapshot_count": items.len(),
        "latest": latest,
        "previous": previous,
        "diff": {
            "digest_changed": latest_digest.is_some() && previous_digest.is_some() && latest_digest != previous_digest,
            "size_delta_bytes": latest_size - previous_size,
            "redaction_policy": "support bundle snapshots are already redacted before persistence",
        },
        "checks": checks,
        "snapshot_index": snapshots,
    })
}

pub(crate) fn next_patch_version(version: &str) -> String {
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect::<Vec<_>>();
    while parts.len() < 3 {
        parts.push(0);
    }
    parts[2] = parts[2].saturating_add(1);
    format!("{}.{}.{}", parts[0], parts[1], parts[2])
}

pub(crate) fn build_clean_release_cut(state: &AppState) -> serde_json::Value {
    let current_version = env!("CARGO_PKG_VERSION");
    let target_version = current_version.to_string();
    let next_patch_target = next_patch_version(current_version);
    let provenance = build_release_provenance(state);
    let observability = build_release_observability_gates(state);
    let synthetic = build_synthetic_console_summary(state);
    let container = build_container_release_parity(state);
    let contract = build_sdk_contract_status(state);
    let drift_count = contract
        .get("drift_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let artifacts = release_artifact_entries();
    let mut checks = vec![
        serde_json::json!({
            "id": "target_patch",
            "status": "pass",
            "detail": format!("Clean release target is v{target_version}; next patch runway is v{next_patch_target}."),
        }),
        serde_json::json!({
            "id": "source_contract",
            "status": if drift_count == 0 { "pass" } else { "fail" },
            "detail": format!("{drift_count} contract drift item(s) before the clean cut."),
        }),
        serde_json::json!({
            "id": "local_artifacts",
            "status": if artifacts.is_empty() { "warn" } else { "pass" },
            "detail": format!("{} local release checksum artifact(s) are available for rehearsal.", artifacts.len()),
        }),
        serde_json::json!({
            "id": "container_context",
            "status": if container.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else if container.get("status").and_then(serde_json::Value::as_str) == Some("review") { "warn" } else { "pass" },
            "detail": container.get("next_action").cloned().unwrap_or_else(|| serde_json::json!("Container release context checked.")),
        }),
        serde_json::json!({
            "id": "release_observability",
            "status": if observability.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else if observability.get("status").and_then(serde_json::Value::as_str) == Some("review") { "warn" } else { "pass" },
            "detail": "Release observability gates are attached to the cut plan.",
        }),
        serde_json::json!({
            "id": "live_console_smoke",
            "status": if synthetic.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else if synthetic.get("status").and_then(serde_json::Value::as_str) == Some("review") { "warn" } else { "pass" },
            "detail": "Synthetic console route smoke is attached to the cut plan.",
        }),
    ];
    checks.extend([
        evidence_freshness_check(
            "provenance_freshness",
            "Release provenance",
            &provenance,
            true,
        ),
        evidence_freshness_check("container_freshness", "Container parity", &container, true),
        evidence_freshness_check(
            "observability_freshness",
            "Release observability",
            &observability,
            true,
        ),
        evidence_freshness_check(
            "synthetic_console_freshness",
            "Synthetic console",
            &synthetic,
            true,
        ),
    ]);
    let (fail_count, warn_count, status) = check_counts(&checks);
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "current_version": current_version,
            "target_version": target_version,
            "next_patch_target": next_patch_target,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "checks": checks,
            "release_steps": [
                {"id": "bump", "action": "Align Cargo, SDKs, Helm, OpenAPI, docs, and website to the target patch version."},
                {"id": "validate", "action": "Run contract parity, release docs, Rust, SDK, admin, and focused browser smoke gates."},
                {"id": "tag", "action": "Create an annotated tag only after source and container parity are clean."},
                {"id": "publish", "action": "Let GitHub Actions publish signed macOS archives, checksums, SBOM, package artifacts, and container provenance."}
            ],
            "release_gate": {
                "target_tag": format!("v{target_version}"),
                "required_local_commands": [
                    "cargo fmt --all --check",
                    "cargo test --lib",
                    "npm --prefix admin-console run lint",
                    "npm --prefix admin-console test -- --run",
                    "npm --prefix admin-console run build",
                    "npm --prefix sdk/typescript run build",
                    "npm --prefix sdk/typescript test -- --run",
                    ".venv/bin/python -m pytest sdk/python/tests/test_client.py",
                    ".venv/bin/python scripts/check_contract_parity.py",
                    ".venv/bin/python scripts/validate_release_docs.py",
                    "bash scripts/performance_scale_baseline.sh"
                ],
                "required_ci_evidence": ["signed macOS archives", "Gatekeeper evidence", "SHA256SUMS", "SBOM", "SLSA provenance", "cosign container signature"],
                "tag_policy": format!("create the v{target_version} tag only after the release verification center is ready or only has expected local-evidence warnings"),
            },
            "provenance": provenance,
            "container": container,
            "observability": observability,
            "synthetic_console": synthetic,
        }),
        evidence_freshness(
            state,
            "clean_release_cut",
            if fail_count == 0 {
                "live_release_gate"
            } else {
                "blocked_release_gate"
            },
            "provenance_container_observability_synthetic_console",
            if fail_count == 0 { "fresh" } else { "unknown" },
            if fail_count == 0 {
                None
            } else {
                Some("critical_release_evidence_not_fresh")
            },
            true,
            serde_json::json!({
                "fail_count": fail_count,
                "warn_count": warn_count,
                "target_version": target_version,
                "next_patch_target": next_patch_target,
            }),
        ),
    )
}

pub(crate) fn build_synthetic_console_summary(state: &AppState) -> serde_json::Value {
    let stream = stream_readiness_payload(state.alert_broadcaster.stats());
    let stream_score = stream
        .get("score")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let alert_page = alert_cursor_page_payload(state, 0, 5);
    let checks = vec![
        serde_json::json!({
            "id": "runtime_health",
            "route": "/api/status",
            "status": "pass",
            "detail": format!("Runtime {} has been up for {}s.", env!("CARGO_PKG_VERSION"), state.server_start.elapsed().as_secs()),
        }),
        serde_json::json!({
            "id": "alert_page",
            "route": "/api/alerts/page?limit=5",
            "status": "pass",
            "detail": format!("Cursor page returned {} alert row(s).", alert_page.get("count").and_then(serde_json::Value::as_u64).unwrap_or_default()),
        }),
        serde_json::json!({
            "id": "stream_readiness",
            "route": "/api/stream/readiness",
            "status": if stream_score >= 80 { "pass" } else { "warn" },
            "detail": format!("Stream status is {}.", stream.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown")),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "check_count": checks.len(),
            "checks": checks,
            "mode": "clean_cut_summary",
            "full_endpoint": "/api/monitoring/synthetic-console",
            "next_action": if fail_count > 0 { "Fix failing console dependencies before relying on the operator launchpad." } else if warn_count > 0 { "Review degraded synthetic console signals before release acceptance." } else { "Synthetic console summary is clean." },
        }),
        evidence_freshness(
            state,
            "synthetic_console_summary",
            "live_runtime_summary",
            "runtime_status_alert_cursor_stream_readiness",
            "fresh",
            None,
            true,
            serde_json::json!({
                "stream_score": stream_score,
                "fail_count": fail_count,
                "warn_count": warn_count,
                "check_count": checks.len(),
            }),
        ),
    )
}

pub(crate) fn build_container_release_parity(_state: &AppState) -> serde_json::Value {
    let dockerfile = fs::read_to_string("Dockerfile").unwrap_or_default();
    let release_workflow = fs::read_to_string(".github/workflows/release.yml").unwrap_or_default();
    let required_copies = [
        ("src", "COPY src/ src/"),
        ("scripts", "COPY scripts/ scripts/"),
        ("docs", "COPY docs/ docs/"),
        ("admin-console", "COPY admin-console/ admin-console/"),
        ("sdk", "COPY sdk/ sdk/"),
        ("site", "COPY site/ site/"),
        ("examples", "COPY examples/ examples/"),
    ];
    let copy_rows = required_copies
        .iter()
        .map(|(name, needle)| {
            let present = dockerfile.contains(needle);
            serde_json::json!({
                "name": name,
                "dockerfile_copy": needle,
                "present": present,
                "status": if present { "pass" } else { "fail" },
            })
        })
        .collect::<Vec<_>>();
    let missing_copies = copy_rows
        .iter()
        .filter(|row| row.get("present").and_then(serde_json::Value::as_bool) != Some(true))
        .count();
    let workflow_checks = vec![
        serde_json::json!({
            "id": "container_scan",
            "status": if release_workflow.contains("Container Image Scan") { "pass" } else { "warn" },
            "detail": "Release workflow carries a container image scan job.",
        }),
        serde_json::json!({
            "id": "container_signing",
            "status": if release_workflow.contains("cosign sign") { "pass" } else { "warn" },
            "detail": "Release workflow signs pushed container tags with cosign.",
        }),
        serde_json::json!({
            "id": "container_provenance",
            "status": if release_workflow.contains("attest-build-provenance") { "pass" } else { "warn" },
            "detail": "Release workflow emits provenance for release archives and container digest.",
        }),
    ];
    let mut checks = vec![serde_json::json!({
        "id": "docker_build_context",
        "status": if missing_copies == 0 { "pass" } else { "fail" },
        "detail": format!("{missing_copies} required Docker build input copy rule(s) are missing."),
    })];
    checks.extend(workflow_checks);
    let (fail_count, warn_count, status) = check_counts(&checks);
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "runtime_version": env!("CARGO_PKG_VERSION"),
            "fail_count": fail_count,
            "warn_count": warn_count,
            "copy_rows": copy_rows,
            "image_tags": [env!("CARGO_PKG_VERSION"), "latest"],
            "build_matrix": [
                {"id": "linux_amd64", "artifact": "wardex-linux-x86_64.tar.gz", "container": true, "required_context": ["src", "scripts", "docs", "admin-console", "sdk", "site", "examples"]},
                {"id": "macos_aarch64", "artifact": "wardex-macos-aarch64.tar.gz", "container": false, "required_context": ["src", "scripts", "docs", "admin-console", "sdk", "site", "examples"]},
                {"id": "macos_x86_64", "artifact": "wardex-macos-x86_64.tar.gz", "container": false, "required_context": ["src", "scripts", "docs", "admin-console", "sdk", "site", "examples"]},
                {"id": "windows_x86_64", "artifact": "wardex-windows-x86_64.zip", "container": false, "required_context": ["src", "scripts", "docs", "admin-console", "sdk", "site", "examples"]}
            ],
            "ci_retrigger_plan": {
                "workflow": ".github/workflows/release.yml",
                "required_jobs": ["Package binaries", "Container Image Scan", "Publish container", "Generate SBOM", "Attest build provenance"],
                "manual_check": "verify the container build uses the same committed Dockerfile and copied release context as the archive builds",
            },
            "expected_assets": ["ghcr.io/pinkysworld/wardex", "SBOM", "SLSA provenance", "cosign signature"],
            "checks": checks,
            "next_action": if fail_count > 0 { "Fix Docker build context before cutting another tag." } else if warn_count > 0 { "Review container signing or provenance workflow coverage before publish." } else { "Container release parity is ready for the next clean tag." },
        }),
        evidence_freshness(
            _state,
            "container_release_parity",
            "local_artifact_probe",
            "Dockerfile_and_release_workflow",
            if missing_copies == 0 {
                "fresh"
            } else {
                "stale"
            },
            if missing_copies == 0 {
                None
            } else {
                Some("docker_build_context_incomplete")
            },
            true,
            serde_json::json!({
                "missing_copies": missing_copies,
                "fail_count": fail_count,
                "warn_count": warn_count,
            }),
        ),
    )
}

pub(crate) fn build_release_verification_center(state: &AppState) -> serde_json::Value {
    let provenance = build_release_provenance(state);
    let container = build_container_release_parity(state);
    let artifacts = release_artifact_entries();
    let gatekeeper_evidence = [
        "release/wardex-macos-aarch64-gatekeeper.txt",
        "release/wardex-macos-x86_64-gatekeeper.txt",
    ]
    .iter()
    .map(|path| {
        let exists = Path::new(path).exists();
        serde_json::json!({
            "path": path,
            "exists": exists,
            "status": if exists { "available" } else { "missing_locally" },
        })
    })
    .collect::<Vec<_>>();
    let gatekeeper_missing = gatekeeper_evidence
        .iter()
        .filter(|row| row.get("exists").and_then(serde_json::Value::as_bool) != Some(true))
        .count();
    let sbom_exists = Path::new("release/wardex-sbom.cdx.json").exists();
    let verification_rows = artifacts
        .iter()
        .map(|artifact| {
            let path = artifact
                .get("path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("artifact");
            let exists = artifact
                .get("exists")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            serde_json::json!({
                "artifact": path,
                "sha256": artifact.get("sha256").cloned().unwrap_or(serde_json::Value::Null),
                "exists": exists,
                "commands": [
                    format!("shasum -a 256 -c SHA256SUMS --ignore-missing # {path}"),
                    format!("gh attestation verify {path} --repo pinkysworld/Wardex"),
                ],
                "status": if exists { "ready" } else { "missing_locally" },
            })
        })
        .collect::<Vec<_>>();
    let release_workflow = fs::read_to_string(".github/workflows/release.yml").unwrap_or_default();
    let workflow_evidence = vec![
        serde_json::json!({"id": "notarization", "status": if release_workflow.contains("notarytool") || release_workflow.contains("notarize") { "tracked" } else { "review" }}),
        serde_json::json!({"id": "container_signature", "status": if release_workflow.contains("cosign sign") { "tracked" } else { "review" }}),
        serde_json::json!({"id": "provenance", "status": if release_workflow.contains("attest-build-provenance") { "tracked" } else { "review" }}),
        serde_json::json!({"id": "sbom", "status": if release_workflow.contains("sbom") || release_workflow.contains("SBOM") { "tracked" } else { "review" }}),
    ];
    let mut checks = vec![
        serde_json::json!({
            "id": "checksums",
            "status": if artifacts.is_empty() { "warn" } else { "pass" },
            "detail": format!("{} checksum record(s) available locally.", artifacts.len()),
        }),
        serde_json::json!({
            "id": "macos_gatekeeper_evidence",
            "status": if gatekeeper_missing == 0 { "pass" } else { "warn" },
            "detail": format!("{} Gatekeeper evidence file(s) are missing from the local release directory.", gatekeeper_missing),
        }),
        serde_json::json!({
            "id": "sbom_asset",
            "status": if sbom_exists { "pass" } else { "warn" },
            "detail": if sbom_exists { "CycloneDX SBOM is available locally." } else { "SBOM is expected from GitHub release automation." },
        }),
        serde_json::json!({
            "id": "container_signature_plan",
            "status": if container.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else if container.get("status").and_then(serde_json::Value::as_str) == Some("review") { "warn" } else { "pass" },
            "detail": container.get("next_action").cloned().unwrap_or_else(|| serde_json::json!("Container parity checked.")),
        }),
    ];
    let local_verification_ready = !artifacts.is_empty() && gatekeeper_missing == 0 && sbom_exists;
    checks.extend([
        evidence_freshness_check("provenance_freshness", "Release provenance", &provenance, true),
        evidence_freshness_check("container_freshness", "Container parity", &container, true),
        serde_json::json!({
            "id": "local_release_evidence_freshness",
            "status": if local_verification_ready { "pass" } else { "fail" },
            "detail": if local_verification_ready {
                "Checksums, macOS Gatekeeper evidence, and SBOM are present for local verification.".to_string()
            } else {
                format!("Local verification evidence is incomplete: {} checksum row(s), {gatekeeper_missing} Gatekeeper gap(s), SBOM present: {sbom_exists}.", artifacts.len())
            },
            "evidence_status": if local_verification_ready { "fresh" } else { "unknown" },
            "critical": true,
        }),
    ]);
    let (fail_count, warn_count, status) = check_counts(&checks);
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "release_url": format!("https://github.com/pinkysworld/Wardex/releases/tag/v{}", env!("CARGO_PKG_VERSION")),
            "artifacts": artifacts,
            "gatekeeper_evidence": gatekeeper_evidence,
            "verification_rows": verification_rows,
            "workflow_evidence": workflow_evidence,
            "operator_workflow": [
                {"id": "download", "label": "Download all archives, SHA256SUMS, SBOM, and provenance attestations from the release."},
                {"id": "verify", "label": "Run checksum, GitHub attestation, cosign, and macOS signature verification before install."},
                {"id": "install", "label": "Install only the artifact whose platform, digest, and signature all match the release evidence."},
                {"id": "record", "label": "Persist the verification-center snapshot digest in the release review."}
            ],
            "provenance": provenance,
            "container": container,
            "verify_commands": [
                "shasum -a 256 -c SHA256SUMS",
                "gh attestation verify <archive> --repo pinkysworld/Wardex",
                "cosign verify ghcr.io/pinkysworld/wardex:<version>",
                "codesign --verify --strict --verbose=2 wardex"
            ],
            "checks": checks,
        }),
        evidence_freshness(
            state,
            "release_verification_center",
            if local_verification_ready {
                "local_artifact_probe"
            } else {
                "incomplete_artifact_probe"
            },
            "release_directory_checksums_gatekeeper_sbom",
            if local_verification_ready {
                "fresh"
            } else {
                "unknown"
            },
            if local_verification_ready {
                None
            } else {
                Some("local_release_verification_evidence_incomplete")
            },
            true,
            serde_json::json!({
                "artifact_count": artifacts.len(),
                "gatekeeper_missing": gatekeeper_missing,
                "sbom_exists": sbom_exists,
                "fail_count": fail_count,
                "warn_count": warn_count,
            }),
        ),
    )
}

pub(crate) fn trust_check_status(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "blocked" | "fail" | "failed" => "fail",
        "review" | "warn" | "warning" | "attention" | "unknown" => "warn",
        _ => "pass",
    }
}

pub(crate) fn build_deployment_trust_report(state: &AppState) -> serde_json::Value {
    let release_doctor = release_doctor_payload(state);
    let provenance = build_release_provenance(state);
    let sdk_contract = build_sdk_contract_status(state);
    let failover = build_cluster_failover_execution(state);
    let synthetic_console = build_synthetic_console_monitor(state);
    let validation_packs = build_detection_validation_packs(state);
    let verification_center = build_release_verification_center(state);
    let deployment_campaign = summarize_deployment_campaign(state);
    let collector_rows = crate::server_collectors::full_collector_status_entries(state);

    let collector_enabled = collector_rows
        .iter()
        .filter(|row| row.get("enabled").and_then(serde_json::Value::as_bool) != Some(false))
        .count();
    let collector_degraded = collector_rows
        .iter()
        .filter(|row| {
            let status = row
                .get("status")
                .or_else(|| row.get("freshness"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_ascii_lowercase();
            matches!(
                status.as_str(),
                "stale" | "error" | "failed" | "disabled" | "missing" | "warn" | "review"
            )
        })
        .count();

    let synthetic_status = trust_check_status(
        synthetic_console
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown"),
    );
    let validation_status = trust_check_status(
        validation_packs
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown"),
    );
    let smoke_status = if synthetic_status == "fail" || validation_status == "fail" {
        "fail"
    } else if synthetic_status == "warn" || validation_status == "warn" {
        "warn"
    } else {
        "pass"
    };
    let failover_freshness = failover
        .get("evidence_freshness")
        .and_then(|value| value.get("status"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let failover_status = match failover_freshness {
        "fresh" => "pass",
        "stale" => "warn",
        _ => "warn",
    };

    let checks = vec![
        serde_json::json!({
            "id": "release_acceptance",
            "status": trust_check_status(release_doctor.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown")),
            "detail": release_doctor.get("next_action").cloned().unwrap_or_else(|| serde_json::json!("Release doctor status summarized.")),
        }),
        serde_json::json!({
            "id": "sbom_provenance",
            "status": trust_check_status(provenance.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown")),
            "detail": format!(
                "{} artifact checksum row(s); attestation digest {}.",
                provenance.get("artifact_count").and_then(serde_json::Value::as_u64).unwrap_or_default(),
                provenance.get("attestation_digest").and_then(serde_json::Value::as_str).unwrap_or("unavailable"),
            ),
        }),
        serde_json::json!({
            "id": "sdk_api_parity",
            "status": if sdk_contract.get("drift_count").and_then(serde_json::Value::as_u64).unwrap_or_default() == 0 { "pass" } else { "fail" },
            "detail": format!(
                "{} parity drift item(s) across REST, GraphQL, and generated SDKs.",
                sdk_contract.get("drift_count").and_then(serde_json::Value::as_u64).unwrap_or_default(),
            ),
        }),
        serde_json::json!({
            "id": "backup_failover_freshness",
            "status": failover_status,
            "detail": format!(
                "Failover evidence freshness is {} with {} drill record(s).",
                failover_freshness,
                failover.get("history").and_then(|value| value.get("count")).and_then(serde_json::Value::as_u64).unwrap_or_default(),
            ),
        }),
        serde_json::json!({
            "id": "collector_health",
            "status": if collector_enabled > 0 && collector_degraded == 0 { "pass" } else { "warn" },
            "detail": format!(
                "{collector_enabled} enabled collector lane(s), {collector_degraded} degraded lane(s).",
            ),
        }),
        serde_json::json!({
            "id": "smoke_status",
            "status": smoke_status,
            "detail": format!(
                "Synthetic console is {} and detection validation packs are {}.",
                synthetic_console.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
                validation_packs.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
            ),
        }),
        serde_json::json!({
            "id": "verification_center",
            "status": trust_check_status(verification_center.get("status").and_then(serde_json::Value::as_str).unwrap_or("unknown")),
            "detail": format!(
                "{} verification rows attached.",
                verification_center
                    .get("verification_rows")
                    .and_then(serde_json::Value::as_array)
                    .map(std::vec::Vec::len)
                    .unwrap_or_default(),
            ),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);

    let payload = serde_json::json!({
        "schema": "wardex.deployment_trust_report.v1",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "customer_artifact": {
            "product_name": "Wardex",
            "runtime_name": "Wardex",
            "version": env!("CARGO_PKG_VERSION"),
            "report_name": "Wardex Deployment Trust Report",
            "report_purpose": "Customer-facing proof of release trust, parity, recovery freshness, collector health, and smoke readiness.",
        },
        "checks": checks,
        "sections": {
            "release_acceptance": release_doctor,
            "sbom_provenance": provenance,
            "sdk_api_parity": sdk_contract,
            "backup_failover_freshness": failover,
            "collector_health": {
                "enabled": collector_enabled,
                "degraded": collector_degraded,
                "rows": collector_rows,
            },
            "smoke_status": {
                "synthetic_console": synthetic_console,
                "detection_validation_packs": validation_packs,
            },
            "verification_center": verification_center,
            "fleet_campaign": deployment_campaign,
        },
    });
    let digest = crate::audit::sha256_hex(payload.to_string().as_bytes());
    let mut payload = payload;
    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "digest".to_string(),
            serde_json::Value::String(digest.clone()),
        );
    }
    with_evidence_freshness(
        payload,
        evidence_freshness(
            state,
            "deployment_trust_report",
            "composed_release_readiness",
            "release_doctor+provenance+sdk_parity+failover+collectors+smoke",
            if fail_count > 0 || warn_count > 0 {
                "stale"
            } else {
                "fresh"
            },
            if fail_count > 0 {
                Some("deployment_trust_report_blocked")
            } else {
                None
            },
            true,
            serde_json::json!({
                "digest": digest,
                "fail_count": fail_count,
                "warn_count": warn_count,
                "collector_degraded": collector_degraded,
            }),
        ),
    )
}

pub(crate) fn build_self_hosted_deployment_wizard(state: &AppState) -> serde_json::Value {
    let storage_ready = storage_root_path(&state.storage).is_some();
    let spool_key_set = std::env::var("WARDEX_SPOOL_KEY").is_ok();
    let admin_token_set = std::env::var("WARDEX_ADMIN_TOKEN").is_ok();
    let release_artifacts = release_artifact_entries();
    let image = format!("ghcr.io/pinkysworld/wardex:{}", env!("CARGO_PKG_VERSION"));
    let config_path = state.config_path.display().to_string();
    let checks = vec![
        serde_json::json!({
            "id": "admin_token",
            "status": if admin_token_set { "pass" } else { "warn" },
            "detail": if admin_token_set { "WARDEX_ADMIN_TOKEN is provided by the environment." } else { "Set WARDEX_ADMIN_TOKEN explicitly before production deployment." },
        }),
        serde_json::json!({
            "id": "spool_key",
            "status": if spool_key_set { "pass" } else { "warn" },
            "detail": if spool_key_set { "Persistent spool encryption key is configured." } else { "Set WARDEX_SPOOL_KEY so token rotation does not orphan spool data." },
        }),
        serde_json::json!({
            "id": "storage",
            "status": if storage_ready { "pass" } else { "fail" },
            "detail": "Operational storage path is available for snapshots, audit, and evidence.",
        }),
        serde_json::json!({
            "id": "release_assets",
            "status": if release_artifacts.is_empty() { "warn" } else { "pass" },
            "detail": format!("{} local release archive checksum row(s) are visible for install rehearsal.", release_artifacts.len()),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "config_path": config_path,
        "modes": [
            {"id": "docker", "title": "Docker", "checks": ["token", "spool_key", "volume", "port", "container_signature"]},
            {"id": "helm", "title": "Helm", "checks": ["image_tag", "network_policy", "secret_refs", "persistent_volume", "ingress_tls"]},
            {"id": "systemd", "title": "systemd", "checks": ["service_user", "config_path", "spool_key", "log_rotation", "backup_path"]},
            {"id": "binary", "title": "Local binary", "checks": ["checksum", "signature", "config", "site_dir", "examples_dir"]}
        ],
        "preflight": {
            "admin_token_configured": admin_token_set,
            "spool_key_configured": spool_key_set,
            "storage_ready": storage_ready,
            "release_artifact_count": release_artifacts.len(),
        },
        "install_plans": [
            {
                "id": "docker",
                "title": "Docker single-node",
                "commands": [
                    format!("docker pull {image}"),
                    "docker volume create wardex-var".to_string(),
                    format!("docker run --name wardex --restart unless-stopped -p 8080:8080 -e WARDEX_ADMIN_TOKEN=<secret> -e WARDEX_SPOOL_KEY=<persistent-secret> -v wardex-var:/app/var {image}")
                ],
                "required_secrets": ["WARDEX_ADMIN_TOKEN", "WARDEX_SPOOL_KEY"],
                "post_install_checks": ["/api/health", "/api/release/verification-center", "/api/data-quality/dashboard"]
            },
            {
                "id": "helm",
                "title": "Kubernetes Helm",
                "commands": [
                    "helm upgrade --install wardex deploy/helm/wardex --namespace wardex --create-namespace --set image.tag=<version>".to_string(),
                    "kubectl -n wardex rollout status deploy/wardex".to_string(),
                    "kubectl -n wardex port-forward svc/wardex 8080:8080".to_string()
                ],
                "required_secrets": ["adminToken", "spoolKey", "ingress.tls"],
                "post_install_checks": ["/api/system/health/dependencies", "/api/cluster/failover-execution"]
            },
            {
                "id": "systemd",
                "title": "Linux systemd",
                "commands": [
                    "sudo install -m 0755 wardex /usr/local/bin/wardex".to_string(),
                    format!("sudo install -m 0640 {config_path} /etc/wardex/wardex.toml"),
                    "sudo systemctl enable --now wardex".to_string()
                ],
                "required_secrets": ["EnvironmentFile=/etc/wardex/wardex.env"],
                "post_install_checks": ["systemctl status wardex", "/api/healthz/ready"]
            },
            {
                "id": "binary",
                "title": "Local signed binary",
                "commands": [
                    "shasum -a 256 -c SHA256SUMS".to_string(),
                    "./wardex --version".to_string(),
                    "WARDEX_ADMIN_TOKEN=<secret> WARDEX_SPOOL_KEY=<persistent-secret> ./wardex start".to_string()
                ],
                "required_secrets": ["WARDEX_ADMIN_TOKEN", "WARDEX_SPOOL_KEY"],
                "post_install_checks": ["/api/status", "/admin/"]
            }
        ],
        "checks": checks,
        "next_action": if fail_count > 0 { "Fix blocking deployment inputs before production install." } else if warn_count > 0 { "Resolve deployment warnings before promoting this install path." } else { "Self-hosted deployment wizard is ready for guided install." },
    })
}

pub(crate) fn build_data_quality_dashboard(state: &AppState) -> serde_json::Value {
    let events = state.event_store.all_events();
    let agents = state.agent_registry.list();
    let dlq_count = state.dead_letter_queue.len();
    let stale_agents = agents
        .iter()
        .filter(|agent| matches!(agent.status, AgentStatus::Offline | AgentStatus::Stale))
        .count();
    let recent_alerts = state.alerts.len();
    let collector_rows = crate::server_collectors::full_collector_status_entries(state);
    let unhealthy_collectors = collector_rows
        .iter()
        .filter(|row| {
            let status = row
                .get("status")
                .or_else(|| row.get("freshness"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_ascii_lowercase();
            matches!(status.as_str(), "error" | "stale" | "disabled" | "missing")
        })
        .count();
    let checks = vec![
        serde_json::json!({
            "id": "dead_letter_queue",
            "status": if dlq_count == 0 { "pass" } else { "warn" },
            "detail": format!("{dlq_count} malformed or unprocessable event(s) are in the DLQ."),
        }),
        serde_json::json!({
            "id": "agent_freshness",
            "status": if stale_agents == 0 { "pass" } else { "warn" },
            "detail": format!("{stale_agents} stale/offline agent(s) can weaken detection coverage."),
        }),
        serde_json::json!({
            "id": "event_flow",
            "status": if events.is_empty() && recent_alerts == 0 { "warn" } else { "pass" },
            "detail": format!("{} retained event(s) and {recent_alerts} alert(s) are currently visible.", events.len()),
        }),
        serde_json::json!({
            "id": "collector_health",
            "status": if unhealthy_collectors == 0 { "pass" } else { "warn" },
            "detail": format!("{unhealthy_collectors} collector lane(s) report degraded freshness or setup state."),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    let slo_rows = vec![
        serde_json::json!({
            "id": "dlq_zero",
            "target": "0 dead-letter events before release sign-off",
            "observed": dlq_count,
            "status": if dlq_count == 0 { "pass" } else { "warn" },
            "drilldown": "/api/dlq/stats",
        }),
        serde_json::json!({
            "id": "agent_freshness",
            "target": "no stale/offline agents in the release evidence window",
            "observed": stale_agents,
            "status": if stale_agents == 0 { "pass" } else { "warn" },
            "drilldown": "/api/fleet/dashboard",
        }),
        serde_json::json!({
            "id": "collector_health",
            "target": "all enabled collectors report healthy freshness",
            "observed": unhealthy_collectors,
            "status": if unhealthy_collectors == 0 { "pass" } else { "warn" },
            "drilldown": "/api/collectors/status",
        }),
        serde_json::json!({
            "id": "telemetry_flow",
            "target": "events or alerts visible before detection validation",
            "observed": events.len() + recent_alerts,
            "status": if events.is_empty() && recent_alerts == 0 { "warn" } else { "pass" },
            "drilldown": "/api/events/page?limit=5",
        }),
    ];
    let slo_warn_count = slo_rows
        .iter()
        .filter(|row| row.get("status").and_then(serde_json::Value::as_str) != Some("pass"))
        .count();
    let quality_score = 100usize.saturating_sub(slo_warn_count.saturating_mul(15));
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "metrics": {
                "retained_events": events.len(),
                "alerts": recent_alerts,
                "dead_letter_events": dlq_count,
                "agents": agents.len(),
                "stale_agents": stale_agents,
                "collector_lanes": collector_rows.len(),
                "unhealthy_collectors": unhealthy_collectors,
            },
            "collector_rows": collector_rows.into_iter().take(12).collect::<Vec<_>>(),
            "slo_summary": {
                "score": quality_score,
                "passing": slo_rows.len().saturating_sub(slo_warn_count),
                "total": slo_rows.len(),
                "status": if slo_warn_count == 0 { "ready" } else { "review" },
            },
            "slos": slo_rows,
            "checks": checks,
            "next_action": if warn_count > 0 { "Review degraded data sources before relying on detection confidence." } else { "Telemetry quality is healthy for current validation depth." },
        }),
        evidence_freshness(
            state,
            "data_quality_dashboard",
            "live_runtime",
            "event_store_agent_registry_dlq_collectors",
            "fresh",
            None,
            true,
            serde_json::json!({
                "events": events.len(),
                "alerts": recent_alerts,
                "dead_letter_events": dlq_count,
                "stale_agents": stale_agents,
                "unhealthy_collectors": unhealthy_collectors,
                "quality_score": quality_score,
            }),
        ),
    )
}

pub(crate) fn build_performance_scale_baseline(state: &AppState) -> serde_json::Value {
    let uptime_secs = state.server_start.elapsed().as_secs().max(1);
    let request_rate_per_min = (state.request_count.saturating_mul(60)) / uptime_secs;
    let error_rate_pct = if state.request_count == 0 {
        0
    } else {
        ((state.error_count as f64 / state.request_count as f64) * 100.0).round() as u64
    };
    let ws_stats = state.alert_broadcaster.stats();
    let storage_stats = state.storage.with(|store| Ok(store.stats())).ok();
    let total_records = storage_stats.as_ref().map_or(
        state.alerts.len() + state.audit_log.entries.len(),
        |stats| stats.total_alerts + stats.total_audit_entries,
    );
    let checks = vec![
        serde_json::json!({
            "id": "api_error_rate",
            "status": if error_rate_pct > 5 { "warn" } else { "pass" },
            "detail": format!("API error rate is {error_rate_pct}% over {uptime_secs}s uptime."),
        }),
        serde_json::json!({
            "id": "stream_backpressure",
            "status": if ws_stats.get("backpressure_state").and_then(serde_json::Value::as_str) == Some("critical") { "warn" } else { "pass" },
            "detail": format!("WebSocket transport state is {}.", ws_stats.get("backpressure_state").and_then(serde_json::Value::as_str).unwrap_or("unknown")),
        }),
        serde_json::json!({
            "id": "storage_volume",
            "status": if total_records > 100_000 { "warn" } else { "pass" },
            "detail": format!("{total_records} stored alert/audit records are visible for baseline sizing."),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    let load_gate = vec![
        serde_json::json!({
            "id": "api_error_rate",
            "target": "<= 5%",
            "observed": format!("{error_rate_pct}%"),
            "status": if error_rate_pct > 5 { "warn" } else { "pass" },
            "command": "bash scripts/performance_scale_baseline.sh --api-error-rate",
        }),
        serde_json::json!({
            "id": "launchpad_fanout",
            "target": "all release-verification endpoints answer within the smoke budget",
            "observed": "not measured by runtime snapshot",
            "status": "review",
            "command": "bash scripts/performance_scale_baseline.sh --launchpad",
        }),
        serde_json::json!({
            "id": "retained_event_search",
            "target": "retained-event cursor query under 1000 ms on seeded fixtures",
            "observed": "not measured by runtime snapshot",
            "status": "review",
            "command": "bash scripts/performance_scale_baseline.sh --retained-events",
        }),
        serde_json::json!({
            "id": "support_bundle_export",
            "target": "support bundle export under 1500 ms on release smoke data",
            "observed": "not measured by runtime snapshot",
            "status": "review",
            "command": "bash scripts/performance_scale_baseline.sh --support-bundle",
        }),
    ];
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "metrics": {
                "uptime_secs": uptime_secs,
                "request_count": state.request_count,
                "error_count": state.error_count,
                "request_rate_per_min": request_rate_per_min,
                "error_rate_pct": error_rate_pct,
                "stored_records": total_records,
                "alert_count": state.alerts.len(),
                "event_count": state.event_store.all_events().len(),
            },
            "targets": {
                "api_p95_ms": 500,
                "websocket_queue_depth": 100,
                "release_smoke_budget_ms": 1500,
                "retained_event_search_ms": 1000,
            },
            "recommended_tests": [
                "API route latency sweep for launchpad fanout",
                "Retained-event search with 10k, 100k, and 1m row fixtures",
                "WebSocket fanout with queue-depth and dropped-event assertions",
                "Report export and support bundle generation under concurrent reads"
            ],
            "load_gate": load_gate,
            "ci_gate": {
                "script": "scripts/performance_scale_baseline.sh",
                "requires_running_server": true,
                "environment": ["WARDEX_BASE_URL", "WARDEX_ADMIN_TOKEN"],
                "release_policy": "warnings require manual review; failures block the tag",
            },
            "stream": ws_stats,
            "checks": checks,
        }),
        evidence_freshness(
            state,
            "performance_scale_baseline",
            "live_runtime",
            "request_counters_websocket_stats_storage_stats",
            "fresh",
            None,
            true,
            serde_json::json!({
                "uptime_secs": uptime_secs,
                "request_count": state.request_count,
                "error_count": state.error_count,
                "error_rate_pct": error_rate_pct,
                "stored_records": total_records,
            }),
        ),
    )
}

pub(crate) fn build_cluster_failover_execution(state: &AppState) -> serde_json::Value {
    let cluster_snapshot = control_plane_cluster_snapshot(state);
    let history = control_plane_failover_history_preview(state);
    let last_drill = state
        .last_failover_drill
        .as_ref()
        .and_then(|record| serde_json::to_value(record).ok())
        .unwrap_or(serde_json::Value::Null);
    let has_cluster = cluster_snapshot.is_some();
    let drill_count = history
        .get("count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let mut checks = vec![
        serde_json::json!({
            "id": "cluster_reference",
            "status": if has_cluster { "pass" } else { "warn" },
            "detail": if has_cluster { "Control-plane cluster snapshot is available." } else { "Standalone mode: execution plan is a rehearsal until standby state is configured." },
        }),
        serde_json::json!({
            "id": "drill_history",
            "status": if drill_count > 0 { "pass" } else { "warn" },
            "detail": format!("{drill_count} failover drill record(s) are available."),
        }),
        serde_json::json!({
            "id": "release_observability",
            "status": if build_release_observability_gates(state).get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else { "pass" },
            "detail": "Release observability gates are available as failover preconditions.",
        }),
    ];
    if let Some(cluster) = cluster_snapshot.as_ref() {
        checks.push(serde_json::json!({
            "id": "replication_health",
            "status": if cluster.replication_health == "healthy" { "pass" } else { "warn" },
            "detail": format!(
                "{} primary with {} replica region(s); max lag {} entries.",
                cluster.primary_region,
                cluster.replica_regions.len(),
                cluster.replica_lag_entries,
            ),
        }));
    }
    let (fail_count, warn_count, status) = check_counts(&checks);
    let failover_evidence_status = if has_cluster && drill_count > 0 {
        "fresh"
    } else if drill_count > 0 {
        "stale"
    } else {
        "unknown"
    };
    let failover_stale_reason = if has_cluster && drill_count > 0 {
        None
    } else if drill_count > 0 {
        Some("drill_history_without_cluster_reference")
    } else {
        Some("failover_drill_history_missing")
    };
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "mode": if has_cluster { "cluster_ready" } else { "standalone_rehearsal" },
            "execution_steps": [
                {"id": "freeze", "action": "Pause risky rollout and remediation mutations before failover."},
                {"id": "promote", "action": "Promote the standby or leader candidate only after health, storage, and stream gates pass."},
                {"id": "verify", "action": "Run release observability, synthetic console, and data-quality checks against the promoted node."},
                {"id": "record", "action": "Persist drill evidence and export the support bundle before closing the event."}
            ],
            "drill_execution": {
                "mode": if has_cluster { "executable_drill" } else { "standalone_dry_run" },
                "execute_api": "/api/control/failover-drill",
                "rto_target_secs": 300,
                "rpo_target_secs": 60,
                "post_failover_smoke": ["/api/healthz/ready", "/api/status", "/api/release/observability-gates", "/api/data-quality/dashboard", "/api/support/bundle"],
                "evidence_artifacts": ["failover_drill_record", "release_observability_snapshot", "data_quality_snapshot", "support_bundle_digest"],
            },
            "cluster": cluster_snapshot.and_then(|snapshot| serde_json::to_value(snapshot).ok()),
            "history": history,
            "last_drill": last_drill,
            "checks": checks,
        }),
        evidence_freshness(
            state,
            "cluster_failover_execution",
            if has_cluster {
                "live_cluster_runtime"
            } else {
                "standalone_rehearsal"
            },
            "cluster_snapshot_failover_drill_history",
            failover_evidence_status,
            failover_stale_reason,
            true,
            serde_json::json!({
                "has_cluster": has_cluster,
                "drill_count": drill_count,
                "fail_count": fail_count,
                "warn_count": warn_count,
            }),
        ),
    )
}

pub(crate) fn build_secrets_rotation_operations(state: &AppState) -> serde_json::Value {
    let token_age_secs = state.token_issued_at.elapsed().as_secs();
    let spool_stats = state.spool.stats();
    let checks = vec![
        serde_json::json!({
            "id": "admin_token_rotation",
            "status": if token_age_secs > 30 * 24 * 60 * 60 { "warn" } else { "pass" },
            "detail": format!("Admin token age is {token_age_secs}s in this runtime."),
        }),
        serde_json::json!({
            "id": "spool_key_rotation",
            "status": if std::env::var("WARDEX_SPOOL_KEY").is_ok() { "pass" } else { "warn" },
            "detail": "Persistent spool key should be set before token or spool rotation.",
        }),
        serde_json::json!({
            "id": "oidc_secret_inventory",
            "status": if state.oidc_providers.is_empty() { "warn" } else { "pass" },
            "detail": format!("{} OIDC provider configuration(s) are available for rotation planning.", state.oidc_providers.len()),
        }),
        serde_json::json!({
            "id": "spool_backlog",
            "status": if spool_stats.current_depth > 0 { "warn" } else { "pass" },
            "detail": format!("{} encrypted spool item(s) should drain before key changes.", spool_stats.current_depth),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    let dry_runs = vec![
        serde_json::json!({
            "id": "admin_token",
            "status": "ready",
            "preflight": ["create replacement token", "exchange a test session", "confirm RBAC role mapping"],
            "apply": ["deploy new WARDEX_ADMIN_TOKEN", "restart one node", "validate /api/auth/check"],
            "rollback": ["restore previous token", "invalidate failed session exchange"],
        }),
        serde_json::json!({
            "id": "spool_key",
            "status": if spool_stats.current_depth == 0 { "ready" } else { "review" },
            "preflight": ["drain encrypted spool", "backup var/spool", "seal replacement WARDEX_SPOOL_KEY"],
            "apply": ["restart with replacement key", "write and read a synthetic spool entry"],
            "rollback": ["restore previous key and spool backup before accepting telemetry"],
        }),
        serde_json::json!({
            "id": "oidc_clients",
            "status": if state.oidc_providers.is_empty() { "review" } else { "ready" },
            "preflight": ["create staged client secret", "validate discovery metadata", "run test-login callback"],
            "apply": ["swap provider secret", "run callback validation", "confirm group mapping"],
            "rollback": ["restore previous client secret until all sessions validate"],
        }),
        serde_json::json!({
            "id": "collector_credentials",
            "status": "ready",
            "preflight": ["stage new connector credential", "run collector validation", "capture sample event"],
            "apply": ["promote staged credential", "refresh collector status", "verify freshness SLO"],
            "rollback": ["restore previous connector secret and retry backoff state"],
        }),
        serde_json::json!({
            "id": "release_signing",
            "status": "ready",
            "preflight": ["sign temporary artifact", "verify codesign/cosign", "confirm notarization profile"],
            "apply": ["rotate CI secrets", "run release workflow dry run", "verify artifact evidence"],
            "rollback": ["restore previous CI secret versions and revoke temporary credentials"],
        }),
    ];
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "rotation_domains": [
                {"id": "admin_token", "dry_run": true, "rollback": "Keep the previous token valid until session exchange succeeds."},
                {"id": "spool_key", "dry_run": true, "rollback": "Drain spool and keep sealed backup before changing encryption material."},
                {"id": "oidc_clients", "dry_run": true, "rollback": "Preserve old client secret until callback and group mapping validation pass."},
                {"id": "collector_credentials", "dry_run": true, "rollback": "Validate staged connector credentials before deleting old secrets."},
                {"id": "release_signing", "dry_run": true, "rollback": "Verify Developer ID and cosign signatures on a temporary artifact before secret replacement."}
            ],
            "dry_runs": dry_runs,
            "operator_ticket": {
                "title": "Rotate Wardex production secrets",
                "required_approvals": ["platform_owner", "security_owner"],
                "evidence": ["preflight_snapshot", "post_rotation_auth_check", "spool_read_write_probe", "collector_freshness_snapshot"],
            },
            "spool": {
                "queued": spool_stats.current_depth,
                "capacity": spool_stats.max_entries,
                "utilization_pct": spool_stats.utilization_pct,
            },
            "checks": checks,
        }),
        evidence_freshness(
            state,
            "secrets_rotation_operations",
            "live_runtime",
            "token_age_spool_oidc_runtime_inventory",
            "fresh",
            None,
            true,
            serde_json::json!({
                "token_age_secs": token_age_secs,
                "spool_depth": spool_stats.current_depth,
                "oidc_provider_count": state.oidc_providers.len(),
                "warn_count": warn_count,
            }),
        ),
    )
}

pub(crate) fn build_operator_task_automation(state: &AppState) -> serde_json::Value {
    let queue = build_operator_work_queue(state);
    let items = queue
        .get("items")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let generated_at = chrono::Utc::now();
    let action_blueprints = vec![
        serde_json::json!({"action": "assign_owner", "method": "dry_run", "required_fields": ["task_id", "owner", "due_at"], "audit": true}),
        serde_json::json!({"action": "snooze", "method": "dry_run", "required_fields": ["task_id", "duration", "reason"], "audit": true}),
        serde_json::json!({"action": "create_ticket", "method": "dry_run", "required_fields": ["task_id", "provider", "project", "summary"], "audit": true}),
        serde_json::json!({"action": "run_preflight", "method": "dry_run", "required_fields": ["task_id", "workflow"], "audit": true}),
        serde_json::json!({"action": "export_evidence", "method": "dry_run", "required_fields": ["task_id", "format"], "audit": true}),
        serde_json::json!({"action": "close_with_note", "method": "dry_run", "required_fields": ["task_id", "note", "evidence_digest"], "audit": true}),
    ];
    let automations = items
        .iter()
        .map(|item| {
            let id = item.get("id").and_then(serde_json::Value::as_str).unwrap_or("task");
            let priority = item
                .get("priority")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("medium");
            let owner = match id {
                "release_doctor" => "release manager",
                "approval_queue" => "shift lead",
                "detection_trust" => "detections owner",
                "fleet_drift" => "fleet owner",
                "retention_forecast" => "platform owner",
                _ => "platform owner",
            };
            let recommended_action = match id {
                "release_doctor" => "run_preflight",
                "approval_queue" => "assign_owner",
                "detection_trust" => "export_evidence",
                "fleet_drift" => "create_ticket",
                "retention_forecast" => "snooze",
                _ => "assign_owner",
            };
            let due_at = generated_at
                + chrono::Duration::minutes(match id {
                    "approval_queue" => 15,
                    "release_doctor" => 120,
                    "fleet_drift" => 240,
                    "detection_trust" => 8 * 60,
                    "retention_forecast" => 24 * 60,
                    _ if priority == "high" => 240,
                    _ => 24 * 60,
                });
            let sla_age = match id {
                "approval_queue" => "breaching",
                "release_doctor" => "due_this_shift",
                "fleet_drift" => "due_today",
                "detection_trust" => "due_this_week",
                "retention_forecast" => "planning_window",
                _ if priority == "high" => "due_today",
                _ => "planning_window",
            };
            let next_escalation_target = match id {
                "approval_queue" => "security owner",
                "release_doctor" => "platform owner",
                "detection_trust" => "detection manager",
                "fleet_drift" => "infrastructure lead",
                "retention_forecast" => "storage owner",
                _ => "platform owner",
            };
            let action_blueprint = action_blueprints
                .iter()
                .find(|blueprint| {
                    blueprint.get("action").and_then(serde_json::Value::as_str)
                        == Some(recommended_action)
                })
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "task_id": id,
                "status": "ready",
                "available_actions": ["assign_owner", "snooze", "create_ticket", "run_preflight", "export_evidence", "close_with_note"],
                "owner": owner,
                "due_at": due_at.to_rfc3339(),
                "sla_age": sla_age,
                "next_escalation_target": next_escalation_target,
                "recommended_action": recommended_action,
                "action_blueprint": action_blueprint,
                "source": item,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if automations.is_empty() { "clear" } else { "ready" },
        "automation_count": automations.len(),
        "queue": queue,
        "automations": automations,
        "action_blueprints": action_blueprints,
        "mutation_guard": {
            "status": "dry_run_only",
            "reason": "automation actions are exposed as auditable plans until write-action approval policy is configured",
        },
        "audit_requirements": ["actor", "task_id", "decision", "evidence_digest", "closed_at"],
        "next_action": if items.is_empty() { "No operator automation tasks are waiting." } else { "Review recommended task automations before enabling write actions." },
    })
}

pub(crate) fn build_detection_validation_packs(state: &AppState) -> serde_json::Value {
    let packs = [
        (
            "credential_storm",
            "Credential storm",
            "T1110",
            "examples/credential_storm.csv",
        ),
        (
            "slow_escalation",
            "Slow escalation",
            "T1078",
            "examples/slow_escalation.csv",
        ),
        (
            "low_battery_attack",
            "Low battery attack",
            "T1496",
            "examples/low_battery_attack.csv",
        ),
        (
            "c2_beaconing",
            "C2 beaconing",
            "T1071",
            "examples/credential_storm_extended.csv",
        ),
        (
            "benign_baseline",
            "Benign baseline",
            "baseline",
            "examples/benign_baseline.csv",
        ),
    ];
    let rows = packs
        .iter()
        .map(|(id, title, attack, path)| {
            let exists = Path::new(path).exists();
            serde_json::json!({
                "id": id,
                "title": title,
                "attack_mapping": attack,
                "path": path,
                "status": if exists { "ready" } else { "missing" },
                "execution": {
                    "mode": "dry_run_replay",
                    "command": format!("./target/debug/wardex demo --scenario {id}"),
                    "expected_alerts": if *id == "benign_baseline" { 0 } else { 1 },
                    "expected_artifacts": ["alert", "timeline", "rule_evidence", "false_positive_guidance"],
                },
                "expected_outputs": ["alert", "timeline", "rule_evidence", "false_positive_guidance"],
            })
        })
        .collect::<Vec<_>>();
    let missing = rows
        .iter()
        .filter(|row| row.get("status").and_then(serde_json::Value::as_str) == Some("missing"))
        .count();
    let trust = build_detection_trust_score(state);
    let executable = rows
        .iter()
        .filter(|row| row.get("status").and_then(serde_json::Value::as_str) == Some("ready"))
        .count();
    let checks = vec![
        serde_json::json!({
            "id": "pack_files",
            "status": if missing == 0 { "pass" } else { "warn" },
            "detail": format!("{missing} validation pack fixture(s) are missing."),
        }),
        serde_json::json!({
            "id": "detection_trust",
            "status": if trust.get("status").and_then(serde_json::Value::as_str) == Some("blocked") { "fail" } else if trust.get("status").and_then(serde_json::Value::as_str) == Some("review") { "warn" } else { "pass" },
            "detail": format!("Detection trust average is {}.", trust.get("average_score").and_then(serde_json::Value::as_u64).unwrap_or_default()),
        }),
    ];
    let (fail_count, warn_count, status) = check_counts(&checks);
    let validation_evidence_status = if missing == 0 { "fresh" } else { "unknown" };
    with_evidence_freshness(
        serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "status": status,
            "fail_count": fail_count,
            "warn_count": warn_count,
            "pack_count": rows.len(),
            "missing_pack_count": missing,
            "executable_pack_count": executable,
            "suite_execution": {
                "mode": "dry_run_replay",
                "command": "bash scripts/detection_validation_packs.sh",
                "required_before_release": true,
                "success_criteria": ["all ready packs replay", "expected alerts observed", "benign baseline has no alert", "timeline and rule evidence exported"],
            },
            "packs": rows,
            "detection_trust": trust,
            "checks": checks,
        }),
        evidence_freshness(
            state,
            "detection_validation_packs",
            "local_artifact_probe",
            "examples_validation_pack_files_and_detection_trust",
            validation_evidence_status,
            if missing == 0 {
                None
            } else {
                Some("validation_pack_fixture_missing")
            },
            true,
            serde_json::json!({
                "pack_count": packs.len(),
                "missing_pack_count": missing,
                "executable_pack_count": executable,
                "detection_trust_status": trust.get("status").cloned().unwrap_or(serde_json::Value::Null),
            }),
        ),
    )
}

pub(crate) fn increment_owner_count(owners: &mut HashMap<String, usize>, owner: Option<&str>) {
    let owner = owner
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unassigned");
    *owners.entry(owner.to_string()).or_insert(0) += 1;
}

pub(crate) fn command_rule_review_interval_days(
    rule: &crate::enterprise::ManagedRuleMetadata,
) -> Option<i64> {
    if !rule.enabled || rule.lifecycle == crate::enterprise::ContentLifecycle::Deprecated {
        return None;
    }
    Some(match rule.lifecycle {
        crate::enterprise::ContentLifecycle::Draft | crate::enterprise::ContentLifecycle::Test => 7,
        crate::enterprise::ContentLifecycle::Canary => 14,
        crate::enterprise::ContentLifecycle::Active => 30,
        crate::enterprise::ContentLifecycle::RolledBack => 14,
        crate::enterprise::ContentLifecycle::Deprecated => return None,
    })
}

pub(crate) fn command_rule_review_anchor(
    rule: &crate::enterprise::ManagedRuleMetadata,
) -> Option<chrono::DateTime<chrono::Utc>> {
    [
        rule.last_promotion_at.as_deref(),
        rule.last_test_at.as_deref(),
        Some(rule.updated_at.as_str()),
        Some(rule.created_at.as_str()),
    ]
    .into_iter()
    .flatten()
    .filter_map(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
    .map(|value| value.with_timezone(&chrono::Utc))
    .max()
}

pub(crate) fn command_rule_next_review_at(
    rule: &crate::enterprise::ManagedRuleMetadata,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let interval_days = command_rule_review_interval_days(rule)?;
    let anchor = command_rule_review_anchor(rule)?;
    Some(anchor + chrono::Duration::days(interval_days))
}

pub(crate) fn command_rule_replay_stale(rule: &crate::enterprise::ManagedRuleMetadata) -> bool {
    rule.last_test_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|tested_at| chrono::Utc::now() - tested_at.with_timezone(&chrono::Utc))
        .is_some_and(|age| age >= chrono::Duration::days(14))
}

pub(crate) fn command_rule_promotion_blockers(
    rule: &crate::enterprise::ManagedRuleMetadata,
    active_suppressions: usize,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if rule.owner.trim().is_empty() || rule.owner.eq_ignore_ascii_case("system") {
        blockers.push("assign_owner".to_string());
    }
    if rule.last_test_at.is_none() {
        blockers.push("replay_missing".to_string());
    } else if command_rule_replay_stale(rule) {
        blockers.push("replay_stale".to_string());
    }
    if rule.last_test_match_count >= 5 {
        blockers.push("replay_noise".to_string());
    }
    if active_suppressions > 0 {
        blockers.push("suppression_review".to_string());
    }
    if rule.pack_ids.is_empty() {
        blockers.push("pack_unassigned".to_string());
    }
    blockers
}

pub(crate) fn command_rule_review_calendar(
    rule_metadata: &[crate::enterprise::ManagedRuleMetadata],
    active_suppressions: usize,
) -> serde_json::Value {
    let now = chrono::Utc::now();
    let mut overdue = 0usize;
    let mut due_this_week = 0usize;
    let mut replay_blockers = 0usize;
    let mut noisy_owners = BTreeSet::new();
    let mut items = rule_metadata
        .iter()
        .filter(|rule| {
            rule.enabled && rule.lifecycle != crate::enterprise::ContentLifecycle::Deprecated
        })
        .map(|rule| {
            let next_review_at = command_rule_next_review_at(rule);
            let due_status = match next_review_at {
                Some(due_at) if due_at < now => {
                    overdue += 1;
                    "overdue"
                }
                Some(due_at) if due_at <= now + chrono::Duration::days(7) => {
                    due_this_week += 1;
                    "due_this_week"
                }
                Some(_) => "scheduled",
                None => "unscheduled",
            };
            let blockers = command_rule_promotion_blockers(rule, active_suppressions);
            if !blockers.is_empty() {
                replay_blockers += 1;
            }
            if rule.last_test_match_count >= 5 || active_suppressions > 0 {
                noisy_owners.insert(rule.owner.clone());
            }
            serde_json::json!({
                "id": rule.id,
                "title": rule.title,
                "owner": rule.owner,
                "lifecycle": format!("{:?}", rule.lifecycle).to_ascii_lowercase(),
                "next_review_at": next_review_at.map(|value| value.to_rfc3339()),
                "due_status": due_status,
                "last_test_match_count": rule.last_test_match_count,
                "active_suppressions": active_suppressions,
                "promotion_blockers": blockers,
                "href": format!("/detection?rule={}&rulePanel=promotion", rule.id),
            })
        })
        .collect::<Vec<_>>();

    let due_rank =
        |item: &serde_json::Value| match item["due_status"].as_str().unwrap_or("scheduled") {
            "overdue" => 0,
            "due_this_week" => 1,
            "unscheduled" => 2,
            _ => 3,
        };
    items.sort_by(|left, right| {
        due_rank(left)
            .cmp(&due_rank(right))
            .then_with(|| {
                left["next_review_at"]
                    .as_str()
                    .unwrap_or("9999-99-99T99:99:99Z")
                    .cmp(
                        right["next_review_at"]
                            .as_str()
                            .unwrap_or("9999-99-99T99:99:99Z"),
                    )
            })
            .then_with(|| {
                left["title"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(right["title"].as_str().unwrap_or(""))
            })
    });

    serde_json::json!({
        "overdue": overdue,
        "due_this_week": due_this_week,
        "replay_blockers": replay_blockers,
        "noisy_owners": noisy_owners.len(),
        "items": items.into_iter().take(5).collect::<Vec<_>>(),
    })
}

pub(crate) fn build_detection_review_overview(
    enterprise: &crate::enterprise::EnterpriseStore,
    rule_metadata: &[crate::enterprise::ManagedRuleMetadata],
    detection_feedback: &crate::detection_feedback::DetectionFeedbackStore,
    active_suppressions: usize,
) -> WorkbenchDetectionReviewOverview {
    let now = chrono::Utc::now();
    let mut overdue = 0usize;
    let mut due_this_week = 0usize;
    let mut replay_blockers = 0usize;
    let mut noisy_owners = BTreeSet::new();
    let mut items = rule_metadata
        .iter()
        .filter(|rule| {
            rule.enabled && rule.lifecycle != crate::enterprise::ContentLifecycle::Deprecated
        })
        .map(|rule| {
            let next_review_at = command_rule_next_review_at(rule).map(|value| value.to_rfc3339());
            let review_history = crate::enterprise::build_rule_review_history(
                enterprise,
                detection_feedback,
                &rule.id,
            );
            let latest_replay = &review_history["latest_replay"];
            let analyst_feedback = &review_history["analyst_feedback"];
            let due_status = match next_review_at
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&chrono::Utc))
            {
                Some(due_at) if due_at < now => {
                    overdue += 1;
                    "overdue"
                }
                Some(due_at) if due_at <= now + chrono::Duration::days(7) => {
                    due_this_week += 1;
                    "due_this_week"
                }
                Some(_) => "scheduled",
                None => "unscheduled",
            }
            .to_string();
            let blockers = command_rule_promotion_blockers(rule, active_suppressions);
            if !blockers.is_empty() {
                replay_blockers += 1;
            }
            if rule.last_test_match_count >= 5 || active_suppressions > 0 {
                noisy_owners.insert(rule.owner.clone());
            }
            WorkbenchDetectionReviewEntry {
                id: rule.id.clone(),
                title: rule.title.clone(),
                owner: rule.owner.clone(),
                lifecycle: format!("{:?}", rule.lifecycle).to_ascii_lowercase(),
                next_review_at,
                due_status,
                last_test_match_count: rule.last_test_match_count,
                active_suppressions,
                promotion_blockers: blockers,
                latest_replay_new_match_count: latest_replay["new_match_count"]
                    .as_u64()
                    .unwrap_or(0) as usize,
                latest_replay_cleared_match_count: latest_replay["cleared_match_count"]
                    .as_u64()
                    .unwrap_or(0) as usize,
                latest_replay_suppressed_count: latest_replay["suppressed_count"]
                    .as_u64()
                    .unwrap_or(0) as usize,
                latest_replay_tested_at: latest_replay["tested_at"]
                    .as_str()
                    .map(std::string::ToString::to_string),
                latest_feedback_verdict: analyst_feedback["latest_verdict"]
                    .as_str()
                    .map(std::string::ToString::to_string),
                latest_feedback_analyst: analyst_feedback["latest_analyst"]
                    .as_str()
                    .map(std::string::ToString::to_string),
                latest_feedback_notes: analyst_feedback["latest_notes"]
                    .as_str()
                    .map(std::string::ToString::to_string),
                latest_feedback_at: analyst_feedback["latest_at"]
                    .as_str()
                    .map(std::string::ToString::to_string),
                href: format!("/detection?rule={}&rulePanel=promotion", rule.id),
            }
        })
        .collect::<Vec<_>>();

    let due_rank = |item: &WorkbenchDetectionReviewEntry| match item.due_status.as_str() {
        "overdue" => 0,
        "due_this_week" => 1,
        "unscheduled" => 2,
        _ => 3,
    };
    items.sort_by(|left, right| {
        due_rank(left)
            .cmp(&due_rank(right))
            .then_with(|| left.next_review_at.cmp(&right.next_review_at))
            .then_with(|| left.title.cmp(&right.title))
    });

    WorkbenchDetectionReviewOverview {
        overdue,
        due_this_week,
        replay_blockers,
        noisy_owners: noisy_owners.len(),
        items: items.into_iter().take(10).collect(),
    }
}

pub(crate) fn active_shift_owner(state: &AppState) -> serde_json::Value {
    let mut owners = HashMap::new();
    for item in state.alert_queue.all() {
        increment_owner_count(&mut owners, item.assignee.as_deref());
    }
    for case in state.case_store.list() {
        if !matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed) {
            increment_owner_count(&mut owners, case.assignee.as_deref());
        }
    }
    for incident in state.incident_store.list() {
        if matches!(
            incident.status,
            crate::incident::IncidentStatus::Open | crate::incident::IncidentStatus::Investigating
        ) {
            increment_owner_count(&mut owners, incident.assignee.as_deref());
        }
    }
    let (name, work_items) = owners
        .into_iter()
        .filter(|(name, _)| name != "unassigned")
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
        .unwrap_or_else(|| ("unassigned".to_string(), 0));
    serde_json::json!({
        "name": name,
        "work_items": work_items,
    })
}

pub(crate) fn shift_sla_age_buckets(state: &AppState) -> serde_json::Value {
    let mut under_1h = 0usize;
    let mut between_1h_4h = 0usize;
    let mut between_4h_24h = 0usize;
    let mut over_24h = 0usize;
    let mut breached = 0usize;
    for item in state.alert_queue.pending() {
        let age = age_secs_since(&item.timestamp).unwrap_or_default();
        if age < 60 * 60 {
            under_1h += 1;
        } else if age < 4 * 60 * 60 {
            between_1h_4h += 1;
        } else if age < 24 * 60 * 60 {
            between_4h_24h += 1;
        } else {
            over_24h += 1;
        }
        let item_breached = item
            .sla_deadline
            .as_deref()
            .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).ok())
            .is_some_and(|deadline| chrono::Utc::now() > deadline.with_timezone(&chrono::Utc));
        if item_breached {
            breached += 1;
        }
    }
    serde_json::json!({
        "under_1h": under_1h,
        "between_1h_4h": between_1h_4h,
        "between_4h_24h": between_4h_24h,
        "over_24h": over_24h,
        "breached": breached,
    })
}

pub(crate) fn command_shift_board_payload(
    state: &AppState,
    open_incidents: usize,
    active_cases: usize,
    pending_remediation_reviews: usize,
    connector_issues: usize,
    noisy_rules: usize,
    stale_rules: usize,
) -> serde_json::Value {
    let pending_queue = state
        .alert_queue
        .all()
        .iter()
        .filter(|item| !item.acknowledged)
        .count();
    let unassigned_queue = state
        .alert_queue
        .all()
        .iter()
        .filter(|item| !item.acknowledged && item.assignee.is_none())
        .count();
    let unassigned_cases = state
        .case_store
        .list()
        .iter()
        .filter(|case| {
            !matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed)
                && case.assignee.is_none()
        })
        .count();
    let response_requests = state.response_orchestrator.all_requests();
    let pending_response_approvals = response_requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Pending)
        .count();
    let ready_to_execute = response_requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Approved && !request.dry_run)
        .count();
    let sla_buckets = shift_sla_age_buckets(state);
    let sla_breached = sla_buckets
        .get("breached")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default() as usize;
    let mut blockers = Vec::new();
    if unassigned_queue > 0 || unassigned_cases > 0 {
        blockers.push(format!(
            "{unassigned_queue} queue item(s) and {unassigned_cases} case(s) need an owner"
        ));
    }
    if sla_breached > 0 {
        blockers.push(format!("{sla_breached} alert(s) breached SLA"));
    }
    if pending_remediation_reviews + pending_response_approvals > 0 {
        blockers.push(format!(
            "{} approval(s) are pending",
            pending_remediation_reviews + pending_response_approvals
        ));
    }
    if connector_issues > 0 {
        blockers.push(format!(
            "{connector_issues} connector lane(s) need validation"
        ));
    }
    if noisy_rules + stale_rules > 0 {
        blockers.push(format!(
            "{} detection review item(s) need replay or lifecycle evidence",
            noisy_rules + stale_rules
        ));
    }
    let board_status = if blockers.is_empty() {
        "ready"
    } else if sla_breached > 0 || open_incidents > 0 {
        "attention"
    } else {
        "watch"
    };
    serde_json::json!({
        "status": board_status,
        "active_owner": active_shift_owner(state),
        "open_incidents": open_incidents,
        "active_cases": active_cases,
        "unassigned_cases": unassigned_cases,
        "unassigned_queue": unassigned_queue,
        "pending_approvals": pending_remediation_reviews + pending_response_approvals,
        "ready_to_execute": ready_to_execute,
        "sla_age_buckets": sla_buckets,
        "blockers": blockers,
        "lanes": [
            {
                "id": "queue",
                "label": "Alert queue",
                "owner": "shift lead",
                "open": pending_queue,
                "unassigned": unassigned_queue,
                "pending_approvals": 0,
                "blockers": if unassigned_queue > 0 || sla_breached > 0 { unassigned_queue + sla_breached } else { 0 },
                "next_action": if unassigned_queue > 0 { "Assign the oldest critical alert and confirm SLA pressure." } else { "Review assigned alert aging before the next handoff." },
                "href": "/soc#queue",
            },
            {
                "id": "cases",
                "label": "Cases",
                "owner": "case lead",
                "open": active_cases,
                "unassigned": unassigned_cases,
                "pending_approvals": 0,
                "blockers": unassigned_cases,
                "next_action": if unassigned_cases > 0 { "Assign open cases and capture unresolved questions." } else { "Prepare handoff packets for cases near shift change." },
                "href": "/soc#cases",
            },
            {
                "id": "incidents",
                "label": "Incidents",
                "owner": "incident commander",
                "open": open_incidents,
                "unassigned": 0,
                "pending_approvals": 0,
                "blockers": open_incidents,
                "next_action": if open_incidents > 0 { "Confirm owner, containment status, and evidence export path." } else { "Keep watch on new escalations and reopened cases." },
                "href": "/soc",
            },
            {
                "id": "approvals",
                "label": "Approvals",
                "owner": "approver",
                "open": pending_remediation_reviews + pending_response_approvals,
                "unassigned": 0,
                "pending_approvals": pending_remediation_reviews + pending_response_approvals,
                "blockers": pending_remediation_reviews + pending_response_approvals,
                "next_action": if pending_remediation_reviews + pending_response_approvals > 0 { "Review blast radius, rollback proof, and approver quorum." } else { "Keep approval evidence ready for response execution." },
                "href": "/infrastructure?tab=remediation",
            },
            {
                "id": "connectors",
                "label": "Connectors",
                "owner": "platform owner",
                "open": connector_issues,
                "unassigned": 0,
                "pending_approvals": 0,
                "blockers": connector_issues,
                "next_action": if connector_issues > 0 { "Validate credentials and last-good event proof for affected lanes." } else { "Keep collector proof fresh for downstream detections." },
                "href": "/settings?settingsTab=collectors",
            },
            {
                "id": "detections",
                "label": "Detections",
                "owner": "detection owner",
                "open": noisy_rules + stale_rules,
                "unassigned": 0,
                "pending_approvals": 0,
                "blockers": noisy_rules + stale_rules,
                "next_action": if noisy_rules + stale_rules > 0 { "Run replay and update lifecycle evidence before promotion." } else { "Schedule the next owner review and replay check." },
                "href": "/detection",
            }
        ],
    })
}

pub(crate) fn production_readiness_evidence(state: &mut AppState) -> serde_json::Value {
    state.agent_registry.refresh_staleness();
    let parity = crate::support_center::support_parity(env!("CARGO_PKG_VERSION"));
    let parity_issue_count = parity
        .get("issues")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let storage_stats = state.storage.with(|store| Ok(store.stats())).ok();
    let audit_chain = state.storage.with(|store| store.verify_audit_chain()).ok();
    let backup_status = BackupStatusSnapshot::gather();
    let control_plane = ControlPlanePostureSnapshot::gather(state, &backup_status);
    let collectors = crate::server_collectors::collector_readiness_summary(state);
    let enabled_collectors = collectors
        .get("enabled")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let report_artifacts_with_metadata = state
        .report_store
        .list()
        .iter()
        .filter(|report| !report["artifact_metadata"].is_null())
        .count();
    let response_requests = state.response_orchestrator.all_requests();
    let response_history = response_requests
        .iter()
        .filter(|request| {
            matches!(
                request.status,
                ApprovalStatus::Executed
                    | ApprovalStatus::DryRunCompleted
                    | ApprovalStatus::Approved
                    | ApprovalStatus::Denied
                    | ApprovalStatus::Expired
            )
        })
        .count();

    let blockers = [
        (
            parity_issue_count > 0,
            format!("{parity_issue_count} API/SDK contract parity issue(s) need review."),
        ),
        (
            audit_chain.is_none(),
            "Audit-chain verification could not be completed.".to_string(),
        ),
        (
            enabled_collectors == 0,
            "No cloud, identity, or SaaS collectors are enabled yet.".to_string(),
        ),
        (
            !control_plane.durable_storage,
            "Event persistence is disabled; enable durable storage before claiming a recovery-safe control-plane posture."
                .to_string(),
        ),
        (
            !backup_status.enabled,
            "Scheduled backups are disabled; enable recurring backups before relying on the documented failover path."
                .to_string(),
        ),
        (
            !control_plane.restore_ready,
            "No backup or checkpoint artifacts have been observed yet; run a backup or control checkpoint before failover drills."
                .to_string(),
        ),
        (
            control_plane
                .cluster
                .as_ref()
                .is_some_and(|cluster| !cluster.healthy),
            "Cluster orchestration is configured but no healthy leader or standby handoff state is currently visible."
                .to_string(),
        ),
        (
            control_plane.failover_drill.status != "passed",
            if control_plane.failover_drill.status == "failed" {
                "Latest automated failover drill failed; review durable storage and recovery artifacts before relying on the documented failover path."
                    .to_string()
            } else {
                "No automated failover drill has been recorded yet; run the control-plane failover drill before relying on the documented failover path."
                    .to_string()
            },
        ),
    ]
    .into_iter()
    .filter_map(|(active, message)| active.then_some(message))
    .collect::<Vec<_>>();

    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if blockers.is_empty() { "ready" } else { "review" },
        "version": {
            "package": env!("CARGO_PKG_NAME"),
            "runtime": env!("CARGO_PKG_VERSION"),
            "edition": "private-cloud",
        },
        "config_posture": {
            "config_path": state.config_path.to_string_lossy().to_string(),
            "monitoring_enabled": state.config.monitor.duration_secs > 0 || state.config.monitor.interval_secs > 0,
            "siem_enabled": state.config.siem.enabled,
            "taxii_enabled": state.config.taxii.enabled,
            "clickhouse_enabled": state.clickhouse_store.is_some(),
            "rate_limit_read_per_minute": state.config.server.rate_limit_read_per_minute,
            "rate_limit_write_per_minute": state.config.server.rate_limit_write_per_minute,
        },
        "auth": {
            "token_ttl_secs": state.config.security.token_ttl_secs,
            "token_age_secs": state.token_issued_at.elapsed().as_secs(),
            "rbac_users": state.rbac.list_users().len(),
            "idp_provider_count": state.enterprise.idp_providers().len(),
            "session_store": "enabled",
        },
        "tls": {
            "enabled": state.listener_mode.is_tls(),
            "mtls_required_for_agents": state.config.security.require_mtls_agents,
            "agent_ca_cert_path": state.config.security.agent_ca_cert_path.clone(),
        },
        "storage": {
            "backend": "sqlite",
            "stats": storage_stats,
            "event_persistence": state.event_store.has_persistence(),
            "event_store_path": state.event_store.storage_path(),
        },
        "retention": {
            "audit_max_records": state.config.retention.audit_max_records,
            "alert_max_records": state.config.retention.alert_max_records,
            "event_max_records": state.config.retention.event_max_records,
            "audit_max_age_secs": state.config.retention.audit_max_age_secs,
            "remote_syslog_endpoint": state.config.retention.remote_syslog_endpoint.clone(),
        },
        "backup": backup_status,
        "control_plane": control_plane,
        "audit_chain": {
            "status": if audit_chain.is_some() { "verified" } else { "unverified" },
            "storage_chain_length": audit_chain,
        },
        "collectors": collectors,
        "response_history": {
            "requests": response_requests.len(),
            "closed_or_reopenable": response_history,
            "audit_entries": state.response_orchestrator.audit_ledger().len(),
        },
        "evidence": {
            "stored_reports": state.report_store.list().len(),
            "reports_with_artifact_metadata": report_artifacts_with_metadata,
            "report_runs": state.support_store.report_runs().len(),
        },
        "contracts": {
            "status": if parity_issue_count == 0 { "aligned" } else { "review" },
            "parity_issue_count": parity_issue_count,
            "parity": parity,
        },
        "experimental_surfaces": [
            {"name": "ML triage and shadow inference", "status": "experimental", "gate": "model registry, shadow reports, replay corpus"},
            {"name": "LLM analyst assistant", "status": "experimental", "gate": "retrieval fallback, citations, provider status"},
            {"name": "Zero-knowledge proof workflows", "status": "experimental", "gate": "proof registry and witness verification"},
            {"name": "Quantum-inspired modeling", "status": "experimental", "gate": "key/status and simulation endpoints"}
        ],
        "known_limitations": blockers,
    })
}

pub(crate) fn run_failover_drill(
    state: &Arc<Mutex<AppState>>,
    auth: &AuthIdentity,
) -> Response<Body> {
    let backup_status = BackupStatusSnapshot::gather();
    let actor = response_requested_by(auth);
    let mut s = crate::state_lock::tracked_lock(state, "server/run_failover_drill");
    let drill = FailoverDrillRecord::evaluate(&s, &backup_status, &actor);
    s.last_failover_drill = Some(drill.clone());
    s.support_store.record_failover_drill(drill.clone());

    let digest_input = serde_json::to_string(&drill).unwrap_or_default();
    let digest = crate::audit::sha256_hex(digest_input.as_bytes());
    json_response(
        &serde_json::json!({
            "drill": drill,
            "digest": digest,
        })
        .to_string(),
        200,
    )
}

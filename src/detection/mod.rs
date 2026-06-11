#![allow(clippy::module_inception)]

// Detection & Analytics domain
// This module groups all detection, analytics, ML, and related engines.

pub mod alert_analysis;
pub mod analyst;
pub mod baseline;
pub mod campaign;
pub mod correlation;
pub mod coverage_gap;
pub mod detection_efficacy;
pub mod detection_feedback;
pub mod detector;
pub mod dns_threat;
pub mod edr_blocking;
pub mod entropy_analysis;
pub mod feed_ingestion;
pub mod fixed_threshold;
pub mod ioc_decay;
pub mod kill_chain;
pub mod lateral;
pub mod llm_analyst;
pub mod ml_engine;
pub mod pipeline;
pub mod poisoning;
pub mod process_scoring;
pub mod search;
pub mod sigma;
pub mod sigma_library;
pub mod ueba;
pub mod yara_engine;

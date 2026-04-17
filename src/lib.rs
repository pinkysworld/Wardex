#![recursion_limit = "256"]

// ── Core Server & API ────────────────────────────────────────────────────────
pub mod server;
pub mod config;
pub mod auth;
pub mod oidc;
pub mod rbac;
pub mod secrets;
pub mod openapi;
pub mod graphql;
pub mod ws_stream;

// ── Detection & Analytics ────────────────────────────────────────────────────
pub mod detector;
pub mod sigma;
pub mod sigma_library;
pub mod ml_engine;
#[cfg(feature = "experimental-llm")]
pub mod llm_analyst;
pub mod correlation;
pub mod alert_analysis;
pub mod analyst;
pub mod pipeline;
pub mod search;
pub mod ueba;
pub mod baseline;
pub mod entropy_analysis;
pub mod fixed_threshold;
pub mod detection_efficacy;
pub mod coverage_gap;
pub mod yara_engine;
pub mod dns_threat;
pub mod kill_chain;
pub mod lateral;
pub mod campaign;
pub mod feed_ingestion;
pub mod ioc_decay;
pub mod poisoning;
pub mod process_scoring;
pub mod edr_blocking;

// ── Collection & Ingestion ───────────────────────────────────────────────────
pub mod collector;
pub mod collector_aws;
pub mod collector_azure;
pub mod collector_gcp;
pub mod collector_identity;
pub mod collector_linux;
pub mod collector_macos;
pub mod collector_windows;
pub mod log_collector;
pub mod ocsf;
pub mod spool;
pub mod event_forward;

// ── Incident Response ────────────────────────────────────────────────────────
pub mod incident;
pub mod investigation;
pub mod playbook;
pub mod playbook_dsl;
pub mod response;
pub mod remediation;
pub mod actions;
pub mod escalation;
pub mod quarantine;
pub mod live_response;
pub mod forensics;
pub mod memory_forensics;
pub mod memory_indicators;
pub mod process_tree;

// ── Compliance & Governance ──────────────────────────────────────────────────
pub mod compliance;
pub mod compliance_hipaa;
pub mod compliance_templates;
pub mod privacy;
pub mod report;
pub mod audit;
pub mod proof;

// ── Fleet & Operations ───────────────────────────────────────────────────────
pub mod agent_client;
pub mod agent_lifecycle;
pub mod enrollment;
pub mod auto_update;
pub mod beacon;
pub mod checkpoint;
pub mod cluster;
pub mod edge_cloud;
pub mod swarm;
pub mod policy;
pub mod policy_dist;
pub mod enforcement;
pub mod prevention;
pub mod runtime;

// ── Storage & Persistence ────────────────────────────────────────────────────
pub mod storage;
pub mod storage_clickhouse;
pub mod archival;
pub mod backup;
pub mod replay;

// ── Threat Intelligence ──────────────────────────────────────────────────────
pub mod threat_intel;
pub mod malware_scanner;
pub mod malware_signatures;
pub mod sbom;
pub mod vulnerability;
pub mod mitre_coverage;
pub mod fingerprint;

// ── Networking & Cloud ───────────────────────────────────────────────────────
pub mod ndr;
pub mod tls;
pub mod cert_monitor;
pub mod cloud_inventory;
pub mod container;
pub mod container_image;
pub mod digital_twin;
pub mod quantum;
pub mod side_channel;

// ── Observability & Telemetry ────────────────────────────────────────────────
pub mod metrics;
pub mod monitor;
pub mod telemetry;
pub mod structured_log;
pub mod energy;
pub mod benchmark;
pub mod api_analytics;
pub mod siem;

// ── Business Logic ───────────────────────────────────────────────────────────
pub mod billing;
pub mod license;
pub mod metering;
pub mod marketplace;
pub mod multi_tenant;
pub mod enterprise;
pub mod feature_flags;
pub mod notifications;
pub mod support;

// ── Kernel & System ──────────────────────────────────────────────────────────
pub mod kernel_events;
pub mod fim;
pub mod config_drift;
pub mod ransomware;
pub mod email_analysis;
pub mod entity_extract;
pub mod harness;
pub mod wasm_engine;

// ── Infrastructure ───────────────────────────────────────────────────────────
pub mod attestation;
pub mod inventory;
pub mod service;
pub mod state_machine;

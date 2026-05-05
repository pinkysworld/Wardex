#![recursion_limit = "256"]

// ── Core Server & API ────────────────────────────────────────────────────────
pub mod auth;
pub mod config;
pub mod doctor;
pub mod graphql;
pub mod integration_setup;
pub mod oidc;
pub mod openapi;
pub mod rbac;
pub mod secrets;
pub mod server;
pub mod support_center;
pub mod ws_stream;

// ── Detection & Analytics ────────────────────────────────────────────────────
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

// ── Collection & Ingestion ───────────────────────────────────────────────────
pub mod collector;
pub mod collector_aws;
pub mod collector_azure;
pub mod collector_gcp;
pub mod collector_identity;
pub mod collector_linux;
pub mod collector_macos;
pub mod collector_windows;
pub mod event_forward;
pub mod log_collector;
pub mod ocsf;
pub mod spool;

// ── Incident Response ────────────────────────────────────────────────────────
pub mod actions;
pub mod escalation;
pub mod forensics;
pub mod incident;
pub mod investigation;
pub mod live_response;
pub mod memory_forensics;
pub mod memory_indicators;
pub mod playbook;
pub mod playbook_dsl;
pub mod process_tree;
pub mod quarantine;
pub mod remediation;
pub mod response;

// ── Compliance & Governance ──────────────────────────────────────────────────
pub mod audit;
pub mod compliance;
pub mod compliance_hipaa;
pub mod compliance_templates;
pub mod privacy;
pub mod proof;
pub mod report;

// ── Fleet & Operations ───────────────────────────────────────────────────────
pub mod agent_client;
pub mod agent_lifecycle;
pub mod auto_update;
pub mod beacon;
pub mod checkpoint;
pub mod cluster;
pub mod edge_cloud;
pub mod enforcement;
pub mod enrollment;
pub mod fleet_install;
pub mod policy;
pub mod policy_dist;
pub mod prevention;
pub mod runtime;
pub mod swarm;
pub mod update_trust;

// ── Storage & Persistence ────────────────────────────────────────────────────
pub mod archival;
pub mod backup;
pub mod replay;
pub mod storage;
pub mod storage_clickhouse;

// ── Threat Intelligence ──────────────────────────────────────────────────────
pub mod fingerprint;
pub mod malware_scanner;
pub mod malware_signatures;
pub mod mitre_coverage;
pub mod sbom;
pub mod threat_intel;
pub mod vulnerability;

// ── Networking & Cloud ───────────────────────────────────────────────────────
pub mod cert_monitor;
pub mod cloud_inventory;
pub mod container;
pub mod container_image;
pub mod digital_twin;
pub mod ndr;
pub mod quantum;
pub mod side_channel;
pub mod tls;
pub mod user_preferences;

// ── Observability & Telemetry ────────────────────────────────────────────────
pub mod api_analytics;
pub mod benchmark;
pub mod energy;
pub mod metrics;
pub mod monitor;
pub mod siem;
pub mod structured_log;
pub mod telemetry;

// ── Business Logic ───────────────────────────────────────────────────────────
pub mod billing;
pub mod enterprise;
pub mod feature_flags;
pub mod license;
pub mod marketplace;
pub mod metering;
pub mod multi_tenant;
pub mod notifications;
pub mod support;

// ── Kernel & System ──────────────────────────────────────────────────────────
pub mod config_drift;
pub mod email_analysis;
pub mod entity_extract;
pub mod fim;
pub mod harness;
pub mod kernel_events;
pub mod ransomware;
pub mod wasm_engine;

// ── Infrastructure ───────────────────────────────────────────────────────────
pub mod attestation;
pub mod inventory;
pub mod service;
pub mod state_machine;

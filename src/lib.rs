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
pub mod detection;

// ── Collection & Ingestion ───────────────────────────────────────────────────
pub mod collection;

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
pub mod server_agents;
pub mod server_alerts;
pub mod server_auth;
pub mod server_av;
pub mod server_cluster;
pub mod server_collectors;
pub mod server_control_plane;
pub mod server_evidence;
pub mod server_feeds;
pub mod server_fleet;
pub mod server_metrics;
pub mod server_ml;
pub mod server_response;
pub mod server_routing;
pub mod server_secrets;
pub mod server_static;
pub mod service;
pub mod state_lock;
pub mod state_machine;

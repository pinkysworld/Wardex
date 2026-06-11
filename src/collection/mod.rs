#![allow(clippy::module_inception)]

// Collection & Ingestion domain
// OS-specific, cloud, identity, and log collectors.

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

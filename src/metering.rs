// ── Usage Metering & Trial Management ────────────────────────────────────────
//
// Tracks event volumes, API calls, and storage consumption per tenant.
// Supports free-tier enforcement and usage-based billing triggers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── Metering Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMeter {
    pub tenant_id: String,
    pub events_ingested: u64,
    pub events_limit: u64,
    pub api_calls: u64,
    pub api_calls_limit: u64,
    pub storage_bytes: u64,
    pub storage_limit_bytes: u64,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub plan: MeteringPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MeteringPlan {
    Free,
    Trial { expires: DateTime<Utc> },
    Professional,
    Enterprise,
}

impl MeteringPlan {
    pub fn events_limit(&self) -> u64 {
        match self {
            MeteringPlan::Free => 10_000,
            MeteringPlan::Trial { .. } => 100_000,
            MeteringPlan::Professional => 10_000_000,
            MeteringPlan::Enterprise => u64::MAX,
        }
    }

    pub fn api_calls_limit(&self) -> u64 {
        match self {
            MeteringPlan::Free => 1_000,
            MeteringPlan::Trial { .. } => 50_000,
            MeteringPlan::Professional => 1_000_000,
            MeteringPlan::Enterprise => u64::MAX,
        }
    }

    pub fn storage_limit_bytes(&self) -> u64 {
        match self {
            MeteringPlan::Free => 1_073_741_824,           // 1 GB
            MeteringPlan::Trial { .. } => 10_737_418_240,  // 10 GB
            MeteringPlan::Professional => 107_374_182_400, // 100 GB
            MeteringPlan::Enterprise => u64::MAX,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSnapshot {
    pub timestamp: DateTime<Utc>,
    pub tenant_id: String,
    pub events_ingested: u64,
    pub api_calls: u64,
    pub storage_bytes: u64,
    pub utilization_pct: f64,
}

// ── Metering Manager ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MeteringManager {
    meters: Arc<Mutex<HashMap<String, UsageMeter>>>,
    snapshots: Arc<Mutex<Vec<UsageSnapshot>>>,
}

impl MeteringManager {
    pub fn new() -> Self {
        Self {
            meters: Arc::new(Mutex::new(HashMap::new())),
            snapshots: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn register_tenant(&self, tenant_id: &str, plan: MeteringPlan) {
        let now = Utc::now();
        let period_end = now + chrono::Duration::days(30);
        let meter = UsageMeter {
            tenant_id: tenant_id.to_string(),
            events_ingested: 0,
            events_limit: plan.events_limit(),
            api_calls: 0,
            api_calls_limit: plan.api_calls_limit(),
            storage_bytes: 0,
            storage_limit_bytes: plan.storage_limit_bytes(),
            period_start: now,
            period_end,
            plan,
        };
        self.meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(tenant_id.to_string(), meter);
    }

    pub fn record_events(&self, tenant_id: &str, count: u64) -> Result<(), String> {
        let mut meters = self
            .meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let meter = meters
            .get_mut(tenant_id)
            .ok_or_else(|| format!("Unknown tenant: {tenant_id}"))?;
        if meter.events_ingested + count > meter.events_limit {
            return Err(format!(
                "Event limit exceeded for tenant {tenant_id}: {} + {} > {}",
                meter.events_ingested, count, meter.events_limit
            ));
        }
        meter.events_ingested += count;
        Ok(())
    }

    pub fn record_api_call(&self, tenant_id: &str) -> Result<(), String> {
        let mut meters = self
            .meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let meter = meters
            .get_mut(tenant_id)
            .ok_or_else(|| format!("Unknown tenant: {tenant_id}"))?;
        if meter.api_calls >= meter.api_calls_limit {
            return Err(format!("API call limit exceeded for tenant {tenant_id}"));
        }
        meter.api_calls += 1;
        Ok(())
    }

    pub fn record_storage(&self, tenant_id: &str, bytes: u64) -> Result<(), String> {
        let mut meters = self
            .meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let meter = meters
            .get_mut(tenant_id)
            .ok_or_else(|| format!("Unknown tenant: {tenant_id}"))?;
        if meter.storage_bytes + bytes > meter.storage_limit_bytes {
            return Err(format!("Storage limit exceeded for tenant {tenant_id}"));
        }
        meter.storage_bytes += bytes;
        Ok(())
    }

    pub fn get_usage(&self, tenant_id: &str) -> Option<UsageMeter> {
        self.meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(tenant_id)
            .cloned()
    }

    pub fn snapshot(&self, tenant_id: &str) -> Option<UsageSnapshot> {
        let meters = self
            .meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let meter = meters.get(tenant_id)?;
        let utilization = (meter.events_ingested as f64 / meter.events_limit.max(1) as f64) * 100.0;
        let snap = UsageSnapshot {
            timestamp: Utc::now(),
            tenant_id: tenant_id.to_string(),
            events_ingested: meter.events_ingested,
            api_calls: meter.api_calls,
            storage_bytes: meter.storage_bytes,
            utilization_pct: utilization,
        };
        self.snapshots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(snap.clone());
        Some(snap)
    }

    pub fn check_trial_expiry(&self, tenant_id: &str) -> Option<bool> {
        let meters = self
            .meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let meter = meters.get(tenant_id)?;
        match &meter.plan {
            MeteringPlan::Trial { expires } => Some(Utc::now() > *expires),
            _ => Some(false),
        }
    }

    pub fn list_tenants(&self) -> Vec<String> {
        self.meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    pub fn reset_period(&self, tenant_id: &str) -> Result<(), String> {
        let mut meters = self
            .meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let meter = meters.get_mut(tenant_id).ok_or("Unknown tenant")?;
        meter.events_ingested = 0;
        meter.api_calls = 0;
        let now = Utc::now();
        meter.period_start = now;
        meter.period_end = now + chrono::Duration::days(30);
        Ok(())
    }
}

impl Default for MeteringManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_record() {
        let mgr = MeteringManager::new();
        mgr.register_tenant("acme", MeteringPlan::Professional);
        mgr.record_events("acme", 500).unwrap();
        mgr.record_api_call("acme").unwrap();
        let u = mgr.get_usage("acme").unwrap();
        assert_eq!(u.events_ingested, 500);
        assert_eq!(u.api_calls, 1);
    }

    #[test]
    fn test_free_tier_limits() {
        let mgr = MeteringManager::new();
        mgr.register_tenant("free_user", MeteringPlan::Free);
        assert!(mgr.record_events("free_user", 10_001).is_err());
        assert!(mgr.record_events("free_user", 9_999).is_ok());
    }

    #[test]
    fn test_api_call_limit() {
        let mgr = MeteringManager::new();
        mgr.register_tenant("limited", MeteringPlan::Free);
        for _ in 0..1_000 {
            mgr.record_api_call("limited").unwrap();
        }
        assert!(mgr.record_api_call("limited").is_err());
    }

    #[test]
    fn test_storage_limit() {
        let mgr = MeteringManager::new();
        mgr.register_tenant("store", MeteringPlan::Free);
        // 1 GB limit
        assert!(mgr.record_storage("store", 1_073_741_825).is_err());
        assert!(mgr.record_storage("store", 500_000_000).is_ok());
    }

    #[test]
    fn test_snapshot() {
        let mgr = MeteringManager::new();
        mgr.register_tenant("snap", MeteringPlan::Professional);
        mgr.record_events("snap", 1_000_000).unwrap();
        let s = mgr.snapshot("snap").unwrap();
        assert_eq!(s.events_ingested, 1_000_000);
        assert!(s.utilization_pct > 0.0);
    }

    #[test]
    fn test_trial_expiry() {
        let mgr = MeteringManager::new();
        let expired = Utc::now() - chrono::Duration::days(1);
        mgr.register_tenant("trial_user", MeteringPlan::Trial { expires: expired });
        assert_eq!(mgr.check_trial_expiry("trial_user"), Some(true));
    }

    #[test]
    fn test_reset_period() {
        let mgr = MeteringManager::new();
        mgr.register_tenant("reset", MeteringPlan::Professional);
        mgr.record_events("reset", 5000).unwrap();
        mgr.reset_period("reset").unwrap();
        let u = mgr.get_usage("reset").unwrap();
        assert_eq!(u.events_ingested, 0);
    }

    #[test]
    fn test_unknown_tenant() {
        let mgr = MeteringManager::new();
        assert!(mgr.record_events("nobody", 1).is_err());
        assert!(mgr.get_usage("nobody").is_none());
    }

    #[test]
    fn test_plan_limits() {
        assert_eq!(MeteringPlan::Free.events_limit(), 10_000);
        assert_eq!(MeteringPlan::Professional.api_calls_limit(), 1_000_000);
        assert_eq!(MeteringPlan::Enterprise.storage_limit_bytes(), u64::MAX);
    }
}

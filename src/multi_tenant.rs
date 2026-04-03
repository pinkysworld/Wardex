//! Multi-tenancy isolation engine.
//!
//! Provides per-tenant context separation, resource partitioning,
//! policy isolation, and cross-tenant data protection.
//! Covers R34 (multi-tenancy isolation).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit::sha256_hex;

// ── Tenant Model ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub tier: TenantTier,
    pub created_at: String,
    pub active: bool,
    pub resource_quota: ResourceQuota,
    pub device_ids: Vec<String>,
    pub api_key_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TenantTier {
    Free,
    Standard,
    Enterprise,
    Government,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    pub max_devices: usize,
    pub max_events_per_sec: u64,
    pub max_storage_mb: u64,
    pub max_policies: usize,
    pub retention_days: u32,
}

impl ResourceQuota {
    pub fn for_tier(tier: &TenantTier) -> Self {
        match tier {
            TenantTier::Free => Self {
                max_devices: 5,
                max_events_per_sec: 10,
                max_storage_mb: 100,
                max_policies: 3,
                retention_days: 7,
            },
            TenantTier::Standard => Self {
                max_devices: 50,
                max_events_per_sec: 100,
                max_storage_mb: 5_000,
                max_policies: 20,
                retention_days: 30,
            },
            TenantTier::Enterprise => Self {
                max_devices: 500,
                max_events_per_sec: 1_000,
                max_storage_mb: 100_000,
                max_policies: 100,
                retention_days: 365,
            },
            TenantTier::Government => Self {
                max_devices: 1_000,
                max_events_per_sec: 5_000,
                max_storage_mb: 500_000,
                max_policies: 500,
                retention_days: 2555, // 7 years
            },
        }
    }
}

// ── Tenant Context ───────────────────────────────────────────────────────────

/// Per-request context binding operations to a specific tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext {
    pub tenant_id: String,
    pub tier: TenantTier,
    pub quota: ResourceQuota,
}

impl TenantContext {
    pub fn check_device_limit(&self, current: usize) -> Result<(), String> {
        if current >= self.quota.max_devices {
            Err(format!(
                "tenant {} exceeded device limit ({})",
                self.tenant_id, self.quota.max_devices
            ))
        } else {
            Ok(())
        }
    }

    pub fn check_event_rate(&self, current_eps: u64) -> Result<(), String> {
        if current_eps > self.quota.max_events_per_sec {
            Err(format!(
                "tenant {} exceeded event rate ({}/s)",
                self.tenant_id, self.quota.max_events_per_sec
            ))
        } else {
            Ok(())
        }
    }

    pub fn check_policy_limit(&self, current: usize) -> Result<(), String> {
        if current >= self.quota.max_policies {
            Err(format!(
                "tenant {} exceeded policy limit ({})",
                self.tenant_id, self.quota.max_policies
            ))
        } else {
            Ok(())
        }
    }
}

// ── Multi-Tenant Manager ─────────────────────────────────────────────────────

/// Usage counters for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TenantUsage {
    pub devices: usize,
    pub events_processed: u64,
    pub storage_used_mb: u64,
    pub policies_active: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantReport {
    pub tenant_id: String,
    pub name: String,
    pub tier: TenantTier,
    pub active: bool,
    pub usage: TenantUsage,
    pub quota: ResourceQuota,
    pub utilization_pct: f64,
}

#[derive(Debug)]
pub struct MultiTenantManager {
    tenants: HashMap<String, Tenant>,
    usage: HashMap<String, TenantUsage>,
}

impl Default for MultiTenantManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiTenantManager {
    pub fn new() -> Self {
        Self {
            tenants: HashMap::new(),
            usage: HashMap::new(),
        }
    }

    /// Create a new tenant with a hashed API key.
    pub fn create_tenant(
        &mut self,
        name: &str,
        tier: TenantTier,
        api_key: &str,
    ) -> String {
        let id = sha256_hex(format!("tenant:{name}:{}", self.tenants.len()).as_bytes())
            [..16]
            .to_string();
        let tenant = Tenant {
            id: id.clone(),
            name: name.to_string(),
            tier: tier.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            active: true,
            resource_quota: ResourceQuota::for_tier(&tier),
            device_ids: Vec::new(),
            api_key_hash: sha256_hex(api_key.as_bytes()),
        };
        self.tenants.insert(id.clone(), tenant);
        self.usage.insert(id.clone(), TenantUsage::default());
        id
    }

    /// Authenticate a tenant by API key.
    pub fn authenticate(&self, api_key: &str) -> Option<TenantContext> {
        let hash = sha256_hex(api_key.as_bytes());
        self.tenants.values().find(|t| t.api_key_hash == hash && t.active).map(|t| {
            TenantContext {
                tenant_id: t.id.clone(),
                tier: t.tier.clone(),
                quota: t.resource_quota.clone(),
            }
        })
    }

    /// Register a device under a tenant (with quota check).
    pub fn register_device(
        &mut self,
        tenant_id: &str,
        device_id: &str,
    ) -> Result<(), String> {
        let tenant = self
            .tenants
            .get(tenant_id)
            .ok_or_else(|| "tenant not found".to_string())?;
        let ctx = TenantContext {
            tenant_id: tenant.id.clone(),
            tier: tenant.tier.clone(),
            quota: tenant.resource_quota.clone(),
        };
        let usage = self
            .usage
            .get(tenant_id)
            .ok_or_else(|| "usage not found".to_string())?;
        ctx.check_device_limit(usage.devices)?;

        let tenant_mut = self.tenants.get_mut(tenant_id).unwrap();
        tenant_mut.device_ids.push(device_id.to_string());
        let usage_mut = self.usage.get_mut(tenant_id).unwrap();
        usage_mut.devices += 1;
        Ok(())
    }

    /// Record event processing for a tenant.
    pub fn record_events(&mut self, tenant_id: &str, count: u64) -> Result<(), String> {
        let usage = self
            .usage
            .get_mut(tenant_id)
            .ok_or_else(|| "tenant not found".to_string())?;
        usage.events_processed += count;
        Ok(())
    }

    /// Get a tenant report.
    pub fn report(&self, tenant_id: &str) -> Option<TenantReport> {
        let tenant = self.tenants.get(tenant_id)?;
        let usage = self.usage.get(tenant_id)?;
        let quota = &tenant.resource_quota;
        let utilization = if quota.max_devices > 0 {
            usage.devices as f64 / quota.max_devices as f64 * 100.0
        } else {
            0.0
        };
        Some(TenantReport {
            tenant_id: tenant.id.clone(),
            name: tenant.name.clone(),
            tier: tenant.tier.clone(),
            active: tenant.active,
            usage: usage.clone(),
            quota: quota.clone(),
            utilization_pct: utilization,
        })
    }

    /// Deactivate a tenant.
    pub fn deactivate(&mut self, tenant_id: &str) -> bool {
        if let Some(t) = self.tenants.get_mut(tenant_id) {
            t.active = false;
            true
        } else {
            false
        }
    }

    /// List all active tenant IDs.
    pub fn active_tenant_ids(&self) -> Vec<String> {
        self.tenants
            .values()
            .filter(|t| t.active)
            .map(|t| t.id.clone())
            .collect()
    }

    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// Check whether a device belongs to the given tenant.
    pub fn device_belongs_to(&self, tenant_id: &str, device_id: &str) -> bool {
        self.tenants
            .get(tenant_id)
            .map(|t| t.device_ids.contains(&device_id.to_string()))
            .unwrap_or(false)
    }

    /// Get the tenant that owns a device.
    pub fn tenant_for_device(&self, device_id: &str) -> Option<&Tenant> {
        self.tenants
            .values()
            .find(|t| t.device_ids.contains(&device_id.to_string()))
    }

    /// Resolve tenant context from an API-key header value.
    /// Returns tenant context and tenant_id, or an error message.
    pub fn resolve_request(&self, api_key: &str) -> Result<TenantContext, String> {
        self.authenticate(api_key)
            .ok_or_else(|| "authentication failed".to_string())
    }

    /// Filter a list of item tenant_ids, keeping only those matching `tenant_id`.
    pub fn filter_by_tenant<'a>(
        tenant_id: &str,
        items: &'a [(String, serde_json::Value)],
    ) -> Vec<&'a (String, serde_json::Value)> {
        items
            .iter()
            .filter(|(tid, _)| tid == tenant_id)
            .collect()
    }

    /// Cross-tenant analytics: aggregate usage across all active tenants.
    pub fn cross_tenant_summary(&self) -> CrossTenantSummary {
        let active: Vec<&Tenant> = self.tenants.values().filter(|t| t.active).collect();
        let total_devices: usize = active
            .iter()
            .map(|t| {
                self.usage
                    .get(&t.id)
                    .map(|u| u.devices)
                    .unwrap_or(0)
            })
            .sum();
        let total_events: u64 = active
            .iter()
            .map(|t| {
                self.usage
                    .get(&t.id)
                    .map(|u| u.events_processed)
                    .unwrap_or(0)
            })
            .sum();
        let tier_counts: HashMap<String, usize> = {
            let mut m = HashMap::new();
            for t in &active {
                *m.entry(format!("{:?}", t.tier)).or_default() += 1;
            }
            m
        };

        CrossTenantSummary {
            total_tenants: active.len(),
            total_devices,
            total_events,
            tier_distribution: tier_counts,
        }
    }

    /// Update a tenant's tier (with quota refresh).
    pub fn update_tier(&mut self, tenant_id: &str, new_tier: TenantTier) -> Result<(), String> {
        let tenant = self.tenants.get_mut(tenant_id)
            .ok_or_else(|| "tenant not found".to_string())?;
        tenant.tier = new_tier.clone();
        tenant.resource_quota = ResourceQuota::for_tier(&new_tier);
        Ok(())
    }
}

/// Cross-tenant analytics summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossTenantSummary {
    pub total_tenants: usize,
    pub total_devices: usize,
    pub total_events: u64,
    pub tier_distribution: HashMap<String, usize>,
}

/// Middleware-style request guard for tenant isolation.
#[derive(Debug, Clone)]
pub struct TenantGuard {
    pub tenant_id: String,
    pub tier: TenantTier,
}

impl TenantGuard {
    /// Create from a resolved tenant context.
    pub fn from_context(ctx: &TenantContext) -> Self {
        Self {
            tenant_id: ctx.tenant_id.clone(),
            tier: ctx.tier.clone(),
        }
    }

    /// Check if the guard allows access to a specific tenant's data.
    pub fn allows_access(&self, target_tenant_id: &str) -> bool {
        self.tenant_id == target_tenant_id
    }

    /// Check if the guard allows cross-tenant operations (Enterprise+ only).
    pub fn allows_cross_tenant(&self) -> bool {
        matches!(self.tier, TenantTier::Enterprise | TenantTier::Government)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_authenticate_tenant() {
        let mut mgr = MultiTenantManager::new();
        let _id = mgr.create_tenant("Acme", TenantTier::Standard, "secret-key-123");
        let ctx = mgr.authenticate("secret-key-123");
        assert!(ctx.is_some());
        assert_eq!(ctx.unwrap().tier, TenantTier::Standard);
    }

    #[test]
    fn reject_wrong_key() {
        let mut mgr = MultiTenantManager::new();
        mgr.create_tenant("BadCo", TenantTier::Free, "my-key");
        assert!(mgr.authenticate("wrong-key").is_none());
    }

    #[test]
    fn device_quota_enforced() {
        let mut mgr = MultiTenantManager::new();
        let id = mgr.create_tenant("Small", TenantTier::Free, "k");
        // Free tier = 5 devices max
        for i in 0..5 {
            assert!(mgr.register_device(&id, &format!("dev-{i}")).is_ok());
        }
        assert!(mgr.register_device(&id, "dev-5").is_err());
    }

    #[test]
    fn event_rate_check() {
        let ctx = TenantContext {
            tenant_id: "t1".into(),
            tier: TenantTier::Free,
            quota: ResourceQuota::for_tier(&TenantTier::Free),
        };
        assert!(ctx.check_event_rate(5).is_ok());
        assert!(ctx.check_event_rate(100).is_err());
    }

    #[test]
    fn tenant_report() {
        let mut mgr = MultiTenantManager::new();
        let id = mgr.create_tenant("Corp", TenantTier::Enterprise, "k");
        mgr.register_device(&id, "dev-1").unwrap();
        mgr.record_events(&id, 1000).unwrap();

        let report = mgr.report(&id).unwrap();
        assert_eq!(report.usage.devices, 1);
        assert_eq!(report.usage.events_processed, 1000);
        assert!(report.utilization_pct < 1.0);
    }

    #[test]
    fn deactivate_tenant() {
        let mut mgr = MultiTenantManager::new();
        let id = mgr.create_tenant("Temp", TenantTier::Free, "k");
        assert!(mgr.deactivate(&id));
        assert!(mgr.authenticate("k").is_none());
    }

    #[test]
    fn tier_quotas_differ() {
        let free = ResourceQuota::for_tier(&TenantTier::Free);
        let ent = ResourceQuota::for_tier(&TenantTier::Enterprise);
        assert!(ent.max_devices > free.max_devices);
        assert!(ent.max_storage_mb > free.max_storage_mb);
    }

    #[test]
    fn active_tenants_list() {
        let mut mgr = MultiTenantManager::new();
        let a = mgr.create_tenant("A", TenantTier::Free, "ka");
        let _b = mgr.create_tenant("B", TenantTier::Free, "kb");
        mgr.deactivate(&a);
        assert_eq!(mgr.active_tenant_ids().len(), 1);
    }

    #[test]
    fn device_belongs_to_tenant() {
        let mut mgr = MultiTenantManager::new();
        let id = mgr.create_tenant("DevCo", TenantTier::Standard, "k");
        mgr.register_device(&id, "sensor-1").unwrap();
        assert!(mgr.device_belongs_to(&id, "sensor-1"));
        assert!(!mgr.device_belongs_to(&id, "sensor-999"));
    }

    #[test]
    fn tenant_for_device_lookup() {
        let mut mgr = MultiTenantManager::new();
        let id = mgr.create_tenant("FindMe", TenantTier::Enterprise, "k");
        mgr.register_device(&id, "dev-x").unwrap();
        let t = mgr.tenant_for_device("dev-x");
        assert!(t.is_some());
        assert_eq!(t.unwrap().name, "FindMe");
        assert!(mgr.tenant_for_device("nonexistent").is_none());
    }

    #[test]
    fn resolve_request_ok() {
        let mut mgr = MultiTenantManager::new();
        mgr.create_tenant("Req", TenantTier::Standard, "api-key-1");
        let ctx = mgr.resolve_request("api-key-1");
        assert!(ctx.is_ok());
    }

    #[test]
    fn resolve_request_fail() {
        let mgr = MultiTenantManager::new();
        let ctx = mgr.resolve_request("bad-key");
        assert!(ctx.is_err());
    }

    #[test]
    fn tenant_guard_isolates() {
        let guard = TenantGuard::from_context(&TenantContext {
            tenant_id: "t1".into(),
            tier: TenantTier::Standard,
            quota: ResourceQuota::for_tier(&TenantTier::Standard),
        });
        assert!(guard.allows_access("t1"));
        assert!(!guard.allows_access("t2"));
        assert!(!guard.allows_cross_tenant());
    }

    #[test]
    fn enterprise_allows_cross_tenant() {
        let guard = TenantGuard::from_context(&TenantContext {
            tenant_id: "t1".into(),
            tier: TenantTier::Enterprise,
            quota: ResourceQuota::for_tier(&TenantTier::Enterprise),
        });
        assert!(guard.allows_cross_tenant());
    }

    #[test]
    fn cross_tenant_summary() {
        let mut mgr = MultiTenantManager::new();
        let a = mgr.create_tenant("A", TenantTier::Free, "ka");
        let b = mgr.create_tenant("B", TenantTier::Enterprise, "kb");
        mgr.register_device(&a, "d1").unwrap();
        mgr.register_device(&b, "d2").unwrap();
        mgr.register_device(&b, "d3").unwrap();
        mgr.record_events(&a, 100).unwrap();
        mgr.record_events(&b, 500).unwrap();

        let summary = mgr.cross_tenant_summary();
        assert_eq!(summary.total_tenants, 2);
        assert_eq!(summary.total_devices, 3);
        assert_eq!(summary.total_events, 600);
    }

    #[test]
    fn update_tier() {
        let mut mgr = MultiTenantManager::new();
        let id = mgr.create_tenant("Upgrade", TenantTier::Free, "k");
        assert!(mgr.update_tier(&id, TenantTier::Enterprise).is_ok());
        let ctx = mgr.authenticate("k").unwrap();
        assert_eq!(ctx.tier, TenantTier::Enterprise);
        assert_eq!(ctx.quota.max_devices, 500);
    }

    #[test]
    fn filter_by_tenant_works() {
        let items = vec![
            ("t1".into(), serde_json::json!({"data": 1})),
            ("t2".into(), serde_json::json!({"data": 2})),
            ("t1".into(), serde_json::json!({"data": 3})),
        ];
        let filtered = MultiTenantManager::filter_by_tenant("t1", &items);
        assert_eq!(filtered.len(), 2);
    }
}

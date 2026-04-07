//! Cloud asset inventory unification.
//!
//! Provides a unified model for on-prem hosts, cloud VMs, and cloud
//! services in a single searchable inventory with ownership, tags,
//! and risk scoring.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Unified asset model ─────────────────────────────────────────

/// Asset type classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AssetType {
    OnPremHost,
    CloudVm,
    CloudService,
    Container,
    KubernetesCluster,
    Database,
    LoadBalancer,
    StorageBucket,
    NetworkDevice,
    IoTDevice,
}

/// Cloud provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    None,
    Aws,
    Azure,
    Gcp,
    Custom(String),
}

/// A unified asset record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedAsset {
    pub id: String,
    pub name: String,
    pub asset_type: AssetType,
    pub cloud_provider: CloudProvider,
    pub region: Option<String>,
    pub account_id: Option<String>,
    pub hostname: Option<String>,
    pub ip_addresses: Vec<String>,
    pub os: Option<String>,
    pub agent_id: Option<String>,
    pub owner: Option<String>,
    pub tags: HashMap<String, String>,
    pub risk_score: f32,
    pub status: AssetStatus,
    pub first_seen: String,
    pub last_seen: String,
    pub metadata: HashMap<String, String>,
}

/// Asset operational status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetStatus {
    Active,
    Inactive,
    Decommissioned,
    Unknown,
}

/// Fleet-wide asset summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSummary {
    pub total_assets: usize,
    pub by_type: HashMap<String, usize>,
    pub by_provider: HashMap<String, usize>,
    pub by_status: HashMap<String, usize>,
    pub high_risk_count: usize,
    pub unmanaged_count: usize,
    pub average_risk: f32,
}

// ── Asset inventory store ───────────────────────────────────────

/// Unified asset inventory.
pub struct AssetInventory {
    assets: Vec<UnifiedAsset>,
}

impl Default for AssetInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl AssetInventory {
    pub fn new() -> Self {
        Self { assets: Vec::new() }
    }

    /// Register or update an asset.
    pub fn upsert(&mut self, asset: UnifiedAsset) {
        if let Some(existing) = self.assets.iter_mut().find(|a| a.id == asset.id) {
            *existing = asset;
        } else {
            self.assets.push(asset);
        }
    }

    /// Import on-prem agents into the unified inventory.
    pub fn import_agents(&mut self, agents: &[crate::enrollment::AgentIdentity]) {
        for agent in agents {
            let asset = UnifiedAsset {
                id: format!("agent-{}", agent.id),
                name: agent.hostname.clone(),
                asset_type: AssetType::OnPremHost,
                cloud_provider: CloudProvider::None,
                region: None,
                account_id: None,
                hostname: Some(agent.hostname.clone()),
                ip_addresses: Vec::new(),
                os: Some(agent.platform.clone()),
                agent_id: Some(agent.id.clone()),
                owner: None,
                tags: HashMap::new(),
                risk_score: 0.0,
                status: AssetStatus::Active,
                first_seen: agent.enrolled_at.clone(),
                last_seen: agent.last_seen.clone(),
                metadata: HashMap::new(),
            };
            self.upsert(asset);
        }
    }

    /// Import cloud resources.
    pub fn import_cloud_assets(&mut self, provider: CloudProvider, resources: Vec<CloudResource>) {
        for res in resources {
            let asset = UnifiedAsset {
                id: format!("{:?}-{}", provider, res.resource_id),
                name: res.name,
                asset_type: res.asset_type,
                cloud_provider: provider.clone(),
                region: Some(res.region),
                account_id: Some(res.account_id),
                hostname: res.hostname,
                ip_addresses: res.ip_addresses,
                os: res.os,
                agent_id: None,
                owner: res.owner,
                tags: res.tags,
                risk_score: 0.0,
                status: AssetStatus::Active,
                first_seen: res.created_at,
                last_seen: chrono::Utc::now().to_rfc3339(),
                metadata: HashMap::new(),
            };
            self.upsert(asset);
        }
    }

    /// Update risk scores based on vulnerability reports.
    pub fn update_risk_scores(&mut self, vuln_scores: &HashMap<String, f32>) {
        for asset in &mut self.assets {
            if let Some(agent_id) = &asset.agent_id {
                if let Some(score) = vuln_scores.get(agent_id) {
                    asset.risk_score = *score;
                }
            }
        }
    }

    /// Search assets by query (matches name, hostname, IP, tags).
    pub fn search(&self, query: &str) -> Vec<&UnifiedAsset> {
        let q = query.to_lowercase();
        self.assets.iter().filter(|a| {
            a.name.to_lowercase().contains(&q)
                || a.hostname.as_ref().is_some_and(|h| h.to_lowercase().contains(&q))
                || a.ip_addresses.iter().any(|ip| ip.contains(&q))
                || a.tags.values().any(|v| v.to_lowercase().contains(&q))
                || a.id.to_lowercase().contains(&q)
                || a.owner.as_ref().is_some_and(|o| o.to_lowercase().contains(&q))
        }).collect()
    }

    /// Get asset by ID.
    pub fn get(&self, id: &str) -> Option<&UnifiedAsset> {
        self.assets.iter().find(|a| a.id == id)
    }

    /// Total asset count.
    pub fn count(&self) -> usize {
        self.assets.len()
    }

    /// All assets.
    pub fn all(&self) -> &[UnifiedAsset] {
        &self.assets
    }

    /// Fleet-wide summary.
    pub fn summary(&self) -> AssetSummary {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_provider: HashMap<String, usize> = HashMap::new();
        let mut by_status: HashMap<String, usize> = HashMap::new();
        let mut high_risk = 0;
        let mut unmanaged = 0;
        let mut total_risk = 0.0f32;

        for asset in &self.assets {
            *by_type.entry(format!("{:?}", asset.asset_type)).or_insert(0) += 1;
            *by_provider.entry(format!("{:?}", asset.cloud_provider)).or_insert(0) += 1;
            *by_status.entry(format!("{:?}", asset.status)).or_insert(0) += 1;
            if asset.risk_score >= 7.0 {
                high_risk += 1;
            }
            if asset.agent_id.is_none() && asset.asset_type == AssetType::OnPremHost {
                unmanaged += 1;
            }
            total_risk += asset.risk_score;
        }

        let avg = if self.assets.is_empty() { 0.0 } else { total_risk / self.assets.len() as f32 };

        AssetSummary {
            total_assets: self.assets.len(),
            by_type,
            by_provider,
            by_status,
            high_risk_count: high_risk,
            unmanaged_count: unmanaged,
            average_risk: (avg * 100.0).round() / 100.0,
        }
    }
}

/// A cloud resource to be imported.
#[derive(Debug, Clone)]
pub struct CloudResource {
    pub resource_id: String,
    pub name: String,
    pub asset_type: AssetType,
    pub region: String,
    pub account_id: String,
    pub hostname: Option<String>,
    pub ip_addresses: Vec<String>,
    pub os: Option<String>,
    pub owner: Option<String>,
    pub tags: HashMap<String, String>,
    pub created_at: String,
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_asset(id: &str, name: &str, atype: AssetType) -> UnifiedAsset {
        UnifiedAsset {
            id: id.into(),
            name: name.into(),
            asset_type: atype,
            cloud_provider: CloudProvider::None,
            region: None,
            account_id: None,
            hostname: Some(name.into()),
            ip_addresses: vec!["10.0.0.1".into()],
            os: Some("Linux".into()),
            agent_id: None,
            owner: Some("ops-team".into()),
            tags: HashMap::from([("env".into(), "production".into())]),
            risk_score: 3.0,
            status: AssetStatus::Active,
            first_seen: "2025-01-01T00:00:00Z".into(),
            last_seen: "2025-06-01T00:00:00Z".into(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn upsert_and_search() {
        let mut inv = AssetInventory::new();
        inv.upsert(make_asset("h1", "web-server-1", AssetType::OnPremHost));
        inv.upsert(make_asset("h2", "db-server-1", AssetType::OnPremHost));
        assert_eq!(inv.count(), 2);
        let results = inv.search("web");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn summary_counts() {
        let mut inv = AssetInventory::new();
        inv.upsert(make_asset("h1", "host-1", AssetType::OnPremHost));
        let mut cloud = make_asset("c1", "vm-1", AssetType::CloudVm);
        cloud.cloud_provider = CloudProvider::Aws;
        inv.upsert(cloud);
        let s = inv.summary();
        assert_eq!(s.total_assets, 2);
    }
}

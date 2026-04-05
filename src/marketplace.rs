// ── Content Pack Marketplace ─────────────────────────────────────────────────
//
// Registry for detection rule packs, response playbooks, dashboard templates,
// and integration connectors that can be installed/uninstalled at runtime.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── Content Pack Types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PackCategory {
    DetectionRules,
    ResponsePlaybooks,
    DashboardTemplates,
    IntegrationConnectors,
    ThreatIntelFeeds,
    ComplianceTemplates,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PackStatus {
    Available,
    Installed,
    UpdateAvailable,
    Deprecated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPack {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub category: PackCategory,
    pub tags: Vec<String>,
    pub status: PackStatus,
    pub downloads: u64,
    pub rating: f32,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub size_bytes: u64,
    pub checksum: String,
    pub dependencies: Vec<String>,
    pub min_wardex_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackInstallation {
    pub pack_id: String,
    pub tenant_id: String,
    pub installed_version: String,
    pub installed_at: DateTime<Utc>,
    pub auto_update: bool,
}

// ── Marketplace Manager ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MarketplaceManager {
    registry: Arc<Mutex<HashMap<String, ContentPack>>>,
    installations: Arc<Mutex<Vec<PackInstallation>>>,
}

impl MarketplaceManager {
    pub fn new() -> Self {
        let mgr = Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
            installations: Arc::new(Mutex::new(Vec::new())),
        };
        mgr.seed_builtin_packs();
        mgr
    }

    fn seed_builtin_packs(&self) {
        let packs = vec![
            ("mitre-attack-rules", "MITRE ATT&CK Detection Rules", PackCategory::DetectionRules,
             "Complete Sigma-based detection rules mapped to MITRE ATT&CK techniques", "Wardex Team"),
            ("ransomware-response", "Ransomware Response Playbook", PackCategory::ResponsePlaybooks,
             "Automated containment and recovery playbook for ransomware incidents", "Wardex Team"),
            ("soc-dashboard", "SOC Operations Dashboard", PackCategory::DashboardTemplates,
             "Pre-built dashboard for SOC analysts with KPI tracking", "Wardex Team"),
            ("aws-cloudtrail", "AWS CloudTrail Connector", PackCategory::IntegrationConnectors,
             "Ingest and normalize AWS CloudTrail events", "Wardex Team"),
            ("azure-sentinel", "Azure Sentinel Bridge", PackCategory::IntegrationConnectors,
             "Bi-directional sync with Microsoft Sentinel", "Wardex Team"),
            ("crowdstrike-feed", "CrowdStrike Threat Intel", PackCategory::ThreatIntelFeeds,
             "Automated IOC import from CrowdStrike Falcon", "Wardex Team"),
            ("pci-dss", "PCI-DSS Compliance Pack", PackCategory::ComplianceTemplates,
             "Pre-built rules and reports for PCI-DSS compliance", "Wardex Team"),
            ("hipaa-compliance", "HIPAA Compliance Pack", PackCategory::ComplianceTemplates,
             "Healthcare compliance monitoring with audit trails", "Wardex Team"),
            ("zero-trust", "Zero Trust Detection Pack", PackCategory::DetectionRules,
             "Rules for zero-trust architecture violations and lateral movement", "Community"),
            ("k8s-security", "Kubernetes Security Pack", PackCategory::DetectionRules,
             "Detection rules for container escapes, privilege escalation, and pod security", "Community"),
        ];

        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        for (id, name, category, description, author) in packs {
            registry.insert(
                id.to_string(),
                ContentPack {
                    id: id.to_string(),
                    name: name.to_string(),
                    version: "1.0.0".to_string(),
                    author: author.to_string(),
                    description: description.to_string(),
                    category,
                    tags: vec![],
                    status: PackStatus::Available,
                    downloads: 0,
                    rating: 0.0,
                    created: now,
                    updated: now,
                    size_bytes: 0,
                    checksum: String::new(),
                    dependencies: vec![],
                    min_wardex_version: "0.40.0".to_string(),
                },
            );
        }
    }

    pub fn list_packs(&self, category: Option<PackCategory>) -> Vec<ContentPack> {
        let registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        registry
            .values()
            .filter(|p| category.as_ref().is_none_or(|c| &p.category == c))
            .cloned()
            .collect()
    }

    pub fn get_pack(&self, pack_id: &str) -> Option<ContentPack> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner()).get(pack_id).cloned()
    }

    pub fn search_packs(&self, query: &str) -> Vec<ContentPack> {
        let q = query.to_lowercase();
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|p| {
                p.name.to_lowercase().contains(&q)
                    || p.description.to_lowercase().contains(&q)
                    || p.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .cloned()
            .collect()
    }

    pub fn install_pack(&self, pack_id: &str, tenant_id: &str) -> Result<PackInstallation, String> {
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let pack = registry.get(pack_id).ok_or("Pack not found")?;
        // Check for dependencies before mutating state
        let deps = pack.dependencies.clone();
        for dep in &deps {
            let installed = self.installations.lock().unwrap_or_else(|e| e.into_inner());
            if !installed.iter().any(|i| i.pack_id == *dep && i.tenant_id == tenant_id) {
                return Err(format!("Missing dependency: {dep}"));
            }
        }
        let pack = registry.get_mut(pack_id).ok_or("Pack not found")?;
        pack.downloads += 1;
        pack.status = PackStatus::Installed;
        let installation = PackInstallation {
            pack_id: pack_id.to_string(),
            tenant_id: tenant_id.to_string(),
            installed_version: pack.version.clone(),
            installed_at: Utc::now(),
            auto_update: true,
        };
        drop(registry);
        self.installations.lock().unwrap_or_else(|e| e.into_inner()).push(installation.clone());
        Ok(installation)
    }

    pub fn uninstall_pack(&self, pack_id: &str, tenant_id: &str) -> Result<(), String> {
        let mut installations = self.installations.lock().unwrap_or_else(|e| e.into_inner());
        let before = installations.len();
        installations.retain(|i| !(i.pack_id == pack_id && i.tenant_id == tenant_id));
        if installations.len() == before {
            return Err("Pack not installed".into());
        }
        Ok(())
    }

    pub fn installed_packs(&self, tenant_id: &str) -> Vec<PackInstallation> {
        self.installations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|i| i.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub fn publish_pack(&self, pack: ContentPack) -> Result<(), String> {
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        if registry.contains_key(&pack.id) {
            return Err(format!("Pack {} already exists", pack.id));
        }
        registry.insert(pack.id.clone(), pack);
        Ok(())
    }

    pub fn update_pack(&self, pack_id: &str, new_version: &str) -> Result<(), String> {
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let pack = registry.get_mut(pack_id).ok_or("Pack not found")?;
        pack.version = new_version.to_string();
        pack.updated = Utc::now();
        Ok(())
    }
}

impl Default for MarketplaceManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_packs() {
        let mgr = MarketplaceManager::new();
        let packs = mgr.list_packs(None);
        assert!(packs.len() >= 10);
    }

    #[test]
    fn test_filter_by_category() {
        let mgr = MarketplaceManager::new();
        let rules = mgr.list_packs(Some(PackCategory::DetectionRules));
        assert!(rules.len() >= 2);
        assert!(rules.iter().all(|p| p.category == PackCategory::DetectionRules));
    }

    #[test]
    fn test_install_and_uninstall() {
        let mgr = MarketplaceManager::new();
        mgr.install_pack("mitre-attack-rules", "acme").unwrap();
        let installed = mgr.installed_packs("acme");
        assert_eq!(installed.len(), 1);

        mgr.uninstall_pack("mitre-attack-rules", "acme").unwrap();
        assert!(mgr.installed_packs("acme").is_empty());
    }

    #[test]
    fn test_search_packs() {
        let mgr = MarketplaceManager::new();
        let results = mgr.search_packs("ransomware");
        assert_eq!(results.len(), 1);
        assert!(results[0].name.contains("Ransomware"));
    }

    #[test]
    fn test_download_count() {
        let mgr = MarketplaceManager::new();
        mgr.install_pack("pci-dss", "t1").unwrap();
        mgr.install_pack("pci-dss", "t2").unwrap();
        let pack = mgr.get_pack("pci-dss").unwrap();
        assert_eq!(pack.downloads, 2);
    }

    #[test]
    fn test_publish_pack() {
        let mgr = MarketplaceManager::new();
        let pack = ContentPack {
            id: "custom-pack".into(),
            name: "Custom Detection Pack".into(),
            version: "1.0.0".into(),
            author: "Test Author".into(),
            description: "A test pack".into(),
            category: PackCategory::DetectionRules,
            tags: vec!["test".into()],
            status: PackStatus::Available,
            downloads: 0,
            rating: 0.0,
            created: Utc::now(),
            updated: Utc::now(),
            size_bytes: 1024,
            checksum: "abc123".into(),
            dependencies: vec![],
            min_wardex_version: "0.40.0".into(),
        };
        mgr.publish_pack(pack).unwrap();
        assert!(mgr.get_pack("custom-pack").is_some());
    }

    #[test]
    fn test_uninstall_not_installed() {
        let mgr = MarketplaceManager::new();
        assert!(mgr.uninstall_pack("mitre-attack-rules", "nobody").is_err());
    }

    #[test]
    fn test_update_pack_version() {
        let mgr = MarketplaceManager::new();
        mgr.update_pack("pci-dss", "2.0.0").unwrap();
        let pack = mgr.get_pack("pci-dss").unwrap();
        assert_eq!(pack.version, "2.0.0");
    }
}

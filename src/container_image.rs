//! Container image inventory and scanning.
//!
//! Enumerates container images on a host, tracks image metadata
//! (digest, registry, base image), and correlates with known-bad
//! digests from the malware hash DB and threat intel store.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata for a container image on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub digest: String,
    pub size_mb: f64,
    pub created: String,
    pub labels: HashMap<String, String>,
    pub base_image: Option<String>,
    pub layers: usize,
    pub risk_score: f32,
    pub scan_status: ImageScanStatus,
    pub vulnerabilities: Vec<ImageVulnerability>,
}

/// Scan status of a container image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImageScanStatus {
    NotScanned,
    Scanning,
    Clean,
    Suspicious,
    Malicious,
}

/// A vulnerability found in a container image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageVulnerability {
    pub cve_id: String,
    pub severity: String,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub description: String,
}

/// Container image inventory summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInventorySummary {
    pub total_images: usize,
    pub scanned: usize,
    pub clean: usize,
    pub suspicious: usize,
    pub malicious: usize,
    pub total_vulnerabilities: usize,
    pub critical_vulns: usize,
    pub registries: Vec<String>,
}

/// Container image inventory store.
#[derive(Debug)]
pub struct ImageInventory {
    images: Vec<ContainerImage>,
    known_bad_digests: Vec<String>,
}

impl Default for ImageInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl ImageInventory {
    pub fn new() -> Self {
        Self {
            images: Vec::new(),
            known_bad_digests: Vec::new(),
        }
    }

    /// Upsert an image into the inventory by ID.
    pub fn upsert(&mut self, image: ContainerImage) {
        if let Some(existing) = self.images.iter_mut().find(|i| i.id == image.id) {
            *existing = image;
        } else {
            self.images.push(image);
        }
    }

    /// Remove an image from inventory.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.images.len();
        self.images.retain(|i| i.id != id);
        self.images.len() < before
    }

    /// Get all images.
    pub fn list(&self) -> &[ContainerImage] {
        &self.images
    }

    /// Get an image by ID.
    pub fn get(&self, id: &str) -> Option<&ContainerImage> {
        self.images.iter().find(|i| i.id == id)
    }

    /// Search images by repository name or tag.
    pub fn search(&self, query: &str) -> Vec<&ContainerImage> {
        let q = query.to_lowercase();
        self.images
            .iter()
            .filter(|i| {
                i.repository.to_lowercase().contains(&q)
                    || i.tag.to_lowercase().contains(&q)
                    || i.id.contains(&q)
            })
            .collect()
    }

    /// Add known-bad digest for future correlations.
    pub fn add_known_bad_digest(&mut self, digest: &str) {
        if !self.known_bad_digests.contains(&digest.to_string()) {
            self.known_bad_digests.push(digest.to_string());
        }
    }

    /// Scan all images against known-bad digests and update status.
    pub fn scan_against_known_bad(&mut self) -> usize {
        let mut flagged = 0;
        for image in &mut self.images {
            if self.known_bad_digests.contains(&image.digest) {
                image.scan_status = ImageScanStatus::Malicious;
                image.risk_score = 10.0;
                flagged += 1;
            }
        }
        flagged
    }

    /// Generate inventory summary.
    pub fn summary(&self) -> ImageInventorySummary {
        let mut registries: Vec<String> = self
            .images
            .iter()
            .filter_map(|i| i.repository.split('/').next().map(String::from))
            .collect();
        registries.sort();
        registries.dedup();

        let total_vulns: usize = self.images.iter().map(|i| i.vulnerabilities.len()).sum();
        let critical_vulns: usize = self
            .images
            .iter()
            .flat_map(|i| &i.vulnerabilities)
            .filter(|v| v.severity.to_lowercase() == "critical")
            .count();

        ImageInventorySummary {
            total_images: self.images.len(),
            scanned: self
                .images
                .iter()
                .filter(|i| i.scan_status != ImageScanStatus::NotScanned)
                .count(),
            clean: self
                .images
                .iter()
                .filter(|i| i.scan_status == ImageScanStatus::Clean)
                .count(),
            suspicious: self
                .images
                .iter()
                .filter(|i| i.scan_status == ImageScanStatus::Suspicious)
                .count(),
            malicious: self
                .images
                .iter()
                .filter(|i| i.scan_status == ImageScanStatus::Malicious)
                .count(),
            total_vulnerabilities: total_vulns,
            critical_vulns,
            registries,
        }
    }

    /// Enumerate container images from the local Docker/containerd runtime.
    pub fn collect_from_runtime(&mut self) -> usize {
        let mut count = 0;

        // Try docker first
        if let Ok(out) = std::process::Command::new("docker")
            .args([
                "images",
                "--format",
                "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}",
            ])
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 5 {
                        let size_str = parts[3].trim();
                        let size_mb = parse_docker_size(size_str);
                        let image = ContainerImage {
                            id: parts[0].to_string(),
                            repository: parts[1].to_string(),
                            tag: parts[2].to_string(),
                            digest: String::new(),
                            size_mb,
                            created: parts[4].to_string(),
                            labels: HashMap::new(),
                            base_image: None,
                            layers: 0,
                            risk_score: 0.0,
                            scan_status: ImageScanStatus::NotScanned,
                            vulnerabilities: Vec::new(),
                        };
                        self.upsert(image);
                        count += 1;
                    }
                }
            }
        }

        count
    }
}

fn parse_docker_size(s: &str) -> f64 {
    let s = s.trim();
    if let Some(val) = s.strip_suffix("GB") {
        val.trim().parse::<f64>().unwrap_or(0.0) * 1024.0
    } else if let Some(val) = s.strip_suffix("MB") {
        val.trim().parse::<f64>().unwrap_or(0.0)
    } else if let Some(val) = s.strip_suffix("KB") {
        val.trim().parse::<f64>().unwrap_or(0.0) / 1024.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image() -> ContainerImage {
        ContainerImage {
            id: "abc123".into(),
            repository: "docker.io/library/nginx".into(),
            tag: "1.25".into(),
            digest: "sha256:abcdef1234567890".into(),
            size_mb: 142.5,
            created: "2026-01-01T00:00:00Z".into(),
            labels: HashMap::new(),
            base_image: Some("debian:bookworm-slim".into()),
            layers: 5,
            risk_score: 0.0,
            scan_status: ImageScanStatus::NotScanned,
            vulnerabilities: vec![],
        }
    }

    #[test]
    fn upsert_and_list() {
        let mut inv = ImageInventory::new();
        inv.upsert(sample_image());
        assert_eq!(inv.list().len(), 1);

        // Upsert should replace
        let mut updated = sample_image();
        updated.tag = "1.26".into();
        inv.upsert(updated);
        assert_eq!(inv.list().len(), 1);
        assert_eq!(inv.list()[0].tag, "1.26");
    }

    #[test]
    fn search_images() {
        let mut inv = ImageInventory::new();
        inv.upsert(sample_image());

        let mut img2 = sample_image();
        img2.id = "def456".into();
        img2.repository = "docker.io/library/redis".into();
        inv.upsert(img2);

        assert_eq!(inv.search("nginx").len(), 1);
        assert_eq!(inv.search("docker.io").len(), 2);
    }

    #[test]
    fn known_bad_detection() {
        let mut inv = ImageInventory::new();
        inv.upsert(sample_image());
        inv.add_known_bad_digest("sha256:abcdef1234567890");

        let flagged = inv.scan_against_known_bad();
        assert_eq!(flagged, 1);
        assert_eq!(inv.list()[0].scan_status, ImageScanStatus::Malicious);
    }

    #[test]
    fn summary_reports() {
        let mut inv = ImageInventory::new();
        inv.upsert(sample_image());
        let s = inv.summary();
        assert_eq!(s.total_images, 1);
    }
}

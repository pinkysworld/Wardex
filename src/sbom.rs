//! Supply-chain SBOM (Software Bill of Materials) generator.
//!
//! Produces CycloneDX 1.5 and SPDX 2.3 outputs from Cargo.lock / Cargo.toml,
//! runtime inventory, and build metadata.  Used for compliance (EO 14028)
//! and audit trail generation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── SBOM model ───────────────────────────────────────────────────────

/// A component in the software bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub kind: ComponentKind,
    pub purl: String,
    pub license: Option<String>,
    pub sha256: Option<String>,
    pub supplier: Option<String>,
}

/// Classification of a component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComponentKind {
    Library,
    Application,
    Framework,
    Device,
    Firmware,
}

/// Full SBOM document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDocument {
    pub format: SbomFormat,
    pub spec_version: String,
    pub serial_number: String,
    pub created: String,
    pub tool_name: String,
    pub tool_version: String,
    pub components: Vec<SbomComponent>,
    pub dependencies: Vec<SbomDependency>,
    pub metadata: HashMap<String, String>,
}

/// Dependency relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDependency {
    pub from: String,
    pub to: Vec<String>,
}

/// Supported output formats.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SbomFormat {
    CycloneDX,
    SPDX,
}

// ── Generator ────────────────────────────────────────────────────────

/// SBOM generator engine.
#[derive(Debug)]
pub struct SbomGenerator {
    app_name: String,
    app_version: String,
}

impl SbomGenerator {
    pub fn new(app_name: &str, app_version: &str) -> Self {
        Self {
            app_name: app_name.into(),
            app_version: app_version.into(),
        }
    }

    /// Parse Cargo.lock content into components.
    pub fn parse_cargo_lock(&self, content: &str) -> Vec<SbomComponent> {
        let mut components = Vec::new();
        let mut name = String::new();
        let mut version = String::new();
        let mut checksum: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line == "[[package]]" {
                if !name.is_empty() {
                    components.push(SbomComponent {
                        purl: format!("pkg:cargo/{}@{}", name, version),
                        name: std::mem::take(&mut name),
                        version: std::mem::take(&mut version),
                        kind: ComponentKind::Library,
                        license: None,
                        sha256: checksum.take(),
                        supplier: None,
                    });
                }
            } else if let Some(val) = line.strip_prefix("name = ") {
                name = val.trim_matches('"').to_string();
            } else if let Some(val) = line.strip_prefix("version = ") {
                version = val.trim_matches('"').to_string();
            } else if let Some(val) = line.strip_prefix("checksum = ") {
                checksum = Some(val.trim_matches('"').to_string());
            }
        }
        // Flush last package.
        if !name.is_empty() {
            components.push(SbomComponent {
                purl: format!("pkg:cargo/{}@{}", name, version),
                name,
                version,
                kind: ComponentKind::Library,
                license: None,
                sha256: checksum,
                supplier: None,
            });
        }
        components
    }

    /// Convert a host system inventory into SBOM components.
    /// Each installed software package becomes a component, and hardware info
    /// is stored as Device/Firmware components.
    pub fn from_inventory(&self, inv: &crate::inventory::SystemInventory) -> Vec<SbomComponent> {
        let mut components = Vec::new();

        // Hardware as a device component
        components.push(SbomComponent {
            name: inv.hardware.cpu_model.clone(),
            version: format!("{}-core", inv.hardware.cpu_cores),
            kind: ComponentKind::Device,
            purl: format!("pkg:generic/{}@{}-core", inv.hardware.cpu_model.replace(' ', "-"), inv.hardware.cpu_cores),
            license: None,
            sha256: None,
            supplier: None,
        });

        // Software packages
        for pkg in &inv.software {
            let purl_type = match pkg.source.to_lowercase().as_str() {
                "homebrew" | "brew" => "brew",
                "apt" | "dpkg" | "deb" => "deb",
                "rpm" | "yum" | "dnf" => "rpm",
                "pip" | "pypi" => "pypi",
                "npm" => "npm",
                _ => "generic",
            };
            components.push(SbomComponent {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                kind: ComponentKind::Application,
                purl: format!("pkg:{}/{}@{}", purl_type, pkg.name, pkg.version),
                license: None,
                sha256: None,
                supplier: Some(pkg.source.clone()),
            });
        }

        components
    }

    /// Generate an SBOM document in the specified format.
    pub fn generate(
        &self,
        components: Vec<SbomComponent>,
        dependencies: Vec<SbomDependency>,
        format: SbomFormat,
    ) -> SbomDocument {
        let spec_version = match format {
            SbomFormat::CycloneDX => "1.5".into(),
            SbomFormat::SPDX => "2.3".into(),
        };

        SbomDocument {
            format,
            spec_version,
            serial_number: format!("urn:uuid:{}", uuid_v4()),
            created: chrono::Utc::now().to_rfc3339(),
            tool_name: "Wardex SBOM Generator".into(),
            tool_version: self.app_version.clone(),
            components,
            dependencies,
            metadata: {
                let mut m = HashMap::new();
                m.insert("application".into(), self.app_name.clone());
                m.insert("version".into(), self.app_version.clone());
                m
            },
        }
    }

    /// Generate CycloneDX JSON output.
    pub fn to_cyclonedx_json(&self, doc: &SbomDocument) -> String {
        let components: Vec<serde_json::Value> = doc
            .components
            .iter()
            .map(|c| {
                let mut obj = serde_json::json!({
                    "type": match c.kind {
                        ComponentKind::Library => "library",
                        ComponentKind::Application => "application",
                        ComponentKind::Framework => "framework",
                        ComponentKind::Device => "device",
                        ComponentKind::Firmware => "firmware",
                    },
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                });
                if let Some(ref lic) = c.license {
                    obj["licenses"] = serde_json::json!([{ "license": { "id": lic } }]);
                }
                if let Some(ref sha) = c.sha256 {
                    obj["hashes"] = serde_json::json!([{ "alg": "SHA-256", "content": sha }]);
                }
                obj
            })
            .collect();

        let deps: Vec<serde_json::Value> = doc
            .dependencies
            .iter()
            .map(|d| {
                serde_json::json!({
                    "ref": d.from,
                    "dependsOn": d.to,
                })
            })
            .collect();

        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": doc.spec_version,
            "serialNumber": doc.serial_number,
            "version": 1,
            "metadata": {
                "timestamp": doc.created,
                "tools": [{ "name": doc.tool_name, "version": doc.tool_version }],
                "component": {
                    "type": "application",
                    "name": &self.app_name,
                    "version": &self.app_version,
                }
            },
            "components": components,
            "dependencies": deps,
        })
        .to_string()
    }

    /// Generate SPDX JSON output.
    pub fn to_spdx_json(&self, doc: &SbomDocument) -> String {
        let packages: Vec<serde_json::Value> = doc
            .components
            .iter()
            .map(|c| {
                let mut pkg = serde_json::json!({
                    "SPDXID": format!("SPDXRef-{}", c.name.replace(|ch: char| !ch.is_alphanumeric(), "-")),
                    "name": c.name,
                    "versionInfo": c.version,
                    "downloadLocation": "NOASSERTION",
                    "externalRefs": [{
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": c.purl,
                    }]
                });
                if let Some(ref lic) = c.license {
                    pkg["licenseConcluded"] = serde_json::Value::String(lic.clone());
                } else {
                    pkg["licenseConcluded"] = serde_json::Value::String("NOASSERTION".into());
                }
                if let Some(ref sha) = c.sha256 {
                    pkg["checksums"] = serde_json::json!([{
                        "algorithm": "SHA256",
                        "checksumValue": sha,
                    }]);
                }
                pkg
            })
            .collect();

        let relationships: Vec<serde_json::Value> = doc
            .dependencies
            .iter()
            .flat_map(|d| {
                d.to.iter().map(move |target| {
                    serde_json::json!({
                        "spdxElementId": format!("SPDXRef-{}", d.from.replace(|ch: char| !ch.is_alphanumeric(), "-")),
                        "relatedSpdxElement": format!("SPDXRef-{}", target.replace(|ch: char| !ch.is_alphanumeric(), "-")),
                        "relationshipType": "DEPENDS_ON",
                    })
                })
            })
            .collect();

        serde_json::json!({
            "spdxVersion": format!("SPDX-{}", doc.spec_version),
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.app_name,
            "documentNamespace": doc.serial_number,
            "creationInfo": {
                "created": doc.created,
                "creators": [format!("Tool: {}-{}", doc.tool_name, doc.tool_version)],
            },
            "packages": packages,
            "relationships": relationships,
        })
        .to_string()
    }

    /// Write SBOM document to a file.
    pub fn write_to_file(&self, doc: &SbomDocument, path: &str) -> Result<(), String> {
        let content = match doc.format {
            SbomFormat::CycloneDX => self.to_cyclonedx_json(doc),
            SbomFormat::SPDX => self.to_spdx_json(doc),
        };
        std::fs::write(path, content).map_err(|e| format!("write error: {e}"))
    }
}

/// Generate a v4-like UUID (random).
fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6] & 0x0f,
        bytes[7],
        (bytes[8] & 0x3f) | 0x80,
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lock() -> &'static str {
        r#"
[[package]]
name = "serde"
version = "1.0.200"
checksum = "abc123"

[[package]]
name = "serde_json"
version = "1.0.120"
checksum = "def456"

[[package]]
name = "tokio"
version = "1.38.0"
"#
    }

    #[test]
    fn parse_cargo_lock() {
        let sbgen = SbomGenerator::new("wardex", "0.34.0");
        let components = sbgen.parse_cargo_lock(sample_lock());
        assert_eq!(components.len(), 3);
        assert_eq!(components[0].name, "serde");
        assert_eq!(components[0].version, "1.0.200");
        assert!(components[0].purl.contains("pkg:cargo/serde@1.0.200"));
        assert_eq!(components[0].sha256.as_deref(), Some("abc123"));
        assert!(components[2].sha256.is_none()); // tokio has no checksum
    }

    #[test]
    fn generate_cyclonedx() {
        let sbgen = SbomGenerator::new("wardex", "0.34.0");
        let components = sbgen.parse_cargo_lock(sample_lock());
        let doc = sbgen.generate(components, vec![], SbomFormat::CycloneDX);
        assert_eq!(doc.format, SbomFormat::CycloneDX);
        assert_eq!(doc.spec_version, "1.5");
        assert_eq!(doc.components.len(), 3);

        let json = sbgen.to_cyclonedx_json(&doc);
        assert!(json.contains("CycloneDX"));
        assert!(json.contains("serde"));
        assert!(json.contains("pkg:cargo/serde@1.0.200"));
    }

    #[test]
    fn generate_spdx() {
        let sbgen = SbomGenerator::new("wardex", "0.34.0");
        let components = sbgen.parse_cargo_lock(sample_lock());
        let doc = sbgen.generate(components, vec![], SbomFormat::SPDX);
        assert_eq!(doc.format, SbomFormat::SPDX);
        assert_eq!(doc.spec_version, "2.3");

        let json = sbgen.to_spdx_json(&doc);
        assert!(json.contains("SPDX-2.3"));
        assert!(json.contains("serde_json"));
    }

    #[test]
    fn dependencies_in_output() {
        let sbgen = SbomGenerator::new("wardex", "0.34.0");
        let components = sbgen.parse_cargo_lock(sample_lock());
        let deps = vec![SbomDependency {
            from: "wardex".into(),
            to: vec!["serde".into(), "serde_json".into()],
        }];
        let doc = sbgen.generate(components, deps, SbomFormat::CycloneDX);
        assert_eq!(doc.dependencies.len(), 1);
        assert_eq!(doc.dependencies[0].to.len(), 2);

        let json = sbgen.to_cyclonedx_json(&doc);
        assert!(json.contains("dependsOn"));
    }

    #[test]
    fn uuid_format() {
        let id = uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn empty_lock_file() {
        let sbgen = SbomGenerator::new("wardex", "0.34.0");
        let components = sbgen.parse_cargo_lock("");
        assert!(components.is_empty());
    }

    #[test]
    fn write_and_read_sbom() {
        let dir = std::env::temp_dir().join("wardex_sbom_test");
        let _ = std::fs::create_dir_all(&dir);

        let sbgen = SbomGenerator::new("wardex", "0.34.0");
        let components = sbgen.parse_cargo_lock(sample_lock());
        let doc = sbgen.generate(components, vec![], SbomFormat::CycloneDX);

        let path = dir.join("sbom.json");
        sbgen.write_to_file(&doc, path.to_str().unwrap()).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("CycloneDX"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spdx_relationships() {
        let sbgen = SbomGenerator::new("wardex", "0.34.0");
        let components = vec![SbomComponent {
            name: "foo".into(),
            version: "1.0.0".into(),
            kind: ComponentKind::Library,
            purl: "pkg:cargo/foo@1.0.0".into(),
            license: Some("MIT".into()),
            sha256: None,
            supplier: None,
        }];
        let deps = vec![SbomDependency {
            from: "wardex".into(),
            to: vec!["foo".into()],
        }];
        let doc = sbgen.generate(components, deps, SbomFormat::SPDX);
        let json = sbgen.to_spdx_json(&doc);
        assert!(json.contains("DEPENDS_ON"));
        assert!(json.contains("MIT"));
    }

    #[test]
    fn component_purl_format() {
        let c = SbomComponent {
            name: "my-crate".into(),
            version: "2.5.1".into(),
            kind: ComponentKind::Library,
            purl: "pkg:cargo/my-crate@2.5.1".into(),
            license: None,
            sha256: None,
            supplier: None,
        };
        assert!(c.purl.starts_with("pkg:cargo/"));
        assert!(c.purl.contains("@2.5.1"));
    }
}

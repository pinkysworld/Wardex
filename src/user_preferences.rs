use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DashboardPreset {
    pub name: String,
    #[serde(default)]
    pub widgets: Vec<String>,
    #[serde(default)]
    pub hidden: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UserPreferences {
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub pinned_sections: Vec<String>,
    #[serde(default)]
    pub dashboard_presets: Vec<DashboardPreset>,
    #[serde(default)]
    pub active_dashboard_preset: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserPreferencesPatch {
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub pinned_sections: Option<Vec<String>>,
    #[serde(default)]
    pub dashboard_presets: Option<Vec<DashboardPreset>>,
    #[serde(default)]
    pub active_dashboard_preset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UserPreferencesSnapshot {
    #[serde(default)]
    users: HashMap<String, UserPreferences>,
}

pub struct UserPreferencesStore {
    snapshot: UserPreferencesSnapshot,
    store_path: String,
}

impl UserPreferencesStore {
    pub fn new(store_path: &str) -> Self {
        let safe_path = if let Some(parent) = Path::new(store_path).parent() {
            let _ = fs::create_dir_all(parent);
            match parent.canonicalize() {
                Ok(canon) => canon
                    .join(Path::new(store_path).file_name().unwrap_or_default())
                    .to_string_lossy()
                    .to_string(),
                Err(_) => store_path.to_string(),
            }
        } else {
            store_path.to_string()
        };

        let mut store = Self {
            snapshot: UserPreferencesSnapshot::default(),
            store_path: safe_path,
        };
        store.load();
        store
    }

    fn load(&mut self) {
        let path = Path::new(&self.store_path);
        if path.exists()
            && let Ok(content) = fs::read_to_string(path)
            && let Ok(snapshot) = serde_json::from_str::<UserPreferencesSnapshot>(&content)
        {
            self.snapshot = snapshot;
        }
    }

    fn persist(&self) {
        let path = Path::new(&self.store_path);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.snapshot) {
            let tmp = format!("{}.tmp", self.store_path);
            if fs::write(&tmp, json).is_ok() {
                let _ = fs::rename(&tmp, path);
            }
        }
    }

    pub fn get(&self, actor: &str) -> UserPreferences {
        self.snapshot
            .users
            .get(actor.trim())
            .cloned()
            .unwrap_or_default()
    }

    pub fn upsert(
        &mut self,
        actor: &str,
        patch: UserPreferencesPatch,
    ) -> Result<UserPreferences, String> {
        let actor = actor.trim();
        if actor.is_empty() {
            return Err("actor cannot be empty".into());
        }
        if patch.theme.is_none()
            && patch.pinned_sections.is_none()
            && patch.dashboard_presets.is_none()
            && patch.active_dashboard_preset.is_none()
        {
            return Err("no preferences provided".into());
        }

        let mut current = self.get(actor);
        if let Some(theme) = patch.theme {
            current.theme = Some(normalize_theme(&theme)?);
        }
        if let Some(pinned_sections) = patch.pinned_sections {
            current.pinned_sections = normalize_pinned_sections(pinned_sections);
        }
        if let Some(dashboard_presets) = patch.dashboard_presets {
            current.dashboard_presets = normalize_dashboard_presets(dashboard_presets);
        }
        if let Some(active_dashboard_preset) = patch.active_dashboard_preset {
            current.active_dashboard_preset = normalize_active_dashboard_preset(&active_dashboard_preset);
        }

        current.updated_at = Some(chrono::Utc::now().to_rfc3339());
        self.snapshot
            .users
            .insert(actor.to_string(), current.clone());
        self.persist();
        Ok(current)
    }
}

fn normalize_theme(theme: &str) -> Result<String, String> {
    let normalized = theme.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "dark" | "light" => Ok(normalized),
        _ => Err("theme must be 'light' or 'dark'".into()),
    }
}

fn normalize_pinned_sections(sections: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for section in sections {
        let section = section.trim();
        if section.is_empty() || normalized.iter().any(|existing| existing == section) {
            continue;
        }
        normalized.push(section.to_string());
        if normalized.len() == 6 {
            break;
        }
    }
    normalized
}

fn normalize_dashboard_presets(presets: Vec<DashboardPreset>) -> Vec<DashboardPreset> {
    let mut normalized = Vec::new();
    for preset in presets {
        let name = preset.name.trim();
        if name.is_empty()
            || normalized
                .iter()
                .any(|existing: &DashboardPreset| existing.name.eq_ignore_ascii_case(name))
        {
            continue;
        }

        let widgets = normalize_widget_ids(preset.widgets);
        let hidden = normalize_hidden_widget_ids(preset.hidden, &widgets);

        normalized.push(DashboardPreset {
            name: name.to_string(),
            widgets,
            hidden,
        });

        if normalized.len() == 8 {
            break;
        }
    }
    normalized
}

fn normalize_active_dashboard_preset(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_widget_ids(widget_ids: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for widget_id in widget_ids {
        let trimmed = widget_id.trim();
        if trimmed.is_empty() || normalized.iter().any(|existing| existing == trimmed) {
            continue;
        }
        normalized.push(trimmed.to_string());
    }
    normalized
}

fn normalize_hidden_widget_ids(widget_ids: Vec<String>, widgets: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for widget_id in widget_ids {
        let trimmed = widget_id.trim();
        if trimmed.is_empty()
            || !widgets.iter().any(|widget| widget == trimmed)
            || normalized.iter().any(|existing| existing == trimmed)
        {
            continue;
        }
        normalized.push(trimmed.to_string());
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_persists_preferences_per_actor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store_path = dir.path().join("preferences.json");

        let mut store = UserPreferencesStore::new(&store_path.to_string_lossy());
        let saved = store
            .upsert(
                "alice",
                UserPreferencesPatch {
                    theme: Some("dark".into()),
                    pinned_sections: Some(vec!["fleet".into(), "monitor".into()]),
                    dashboard_presets: Some(vec![DashboardPreset {
                        name: "My SOC".into(),
                        widgets: vec!["threat-overview".into(), "recent-alerts".into()],
                        hidden: vec!["recent-alerts".into()],
                    }]),
                    active_dashboard_preset: Some("saved:My SOC".into()),
                },
            )
            .expect("save preferences");

        assert_eq!(saved.theme.as_deref(), Some("dark"));
        assert_eq!(saved.pinned_sections, vec!["fleet", "monitor"]);
        assert_eq!(saved.dashboard_presets.len(), 1);
        assert_eq!(saved.dashboard_presets[0].name, "My SOC");
        assert_eq!(saved.active_dashboard_preset.as_deref(), Some("saved:My SOC"));
        assert!(saved.updated_at.is_some());

        let reloaded = UserPreferencesStore::new(&store_path.to_string_lossy());
        assert_eq!(reloaded.get("alice"), saved);
        assert_eq!(reloaded.get("bob"), UserPreferences::default());
    }

    #[test]
    fn patch_merges_existing_preferences() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store_path = dir.path().join("preferences.json");

        let mut store = UserPreferencesStore::new(&store_path.to_string_lossy());
        store
            .upsert(
                "analyst",
                UserPreferencesPatch {
                    theme: Some(" DARK ".into()),
                    pinned_sections: Some(vec!["fleet".into(), "fleet".into(), "soc".into()]),
                    dashboard_presets: Some(vec![DashboardPreset {
                        name: "Shared Triage".into(),
                        widgets: vec!["threat-overview".into(), "threat-overview".into()],
                        hidden: vec!["threat-overview".into(), "telemetry".into()],
                    }]),
                    active_dashboard_preset: Some("shared:triage".into()),
                },
            )
            .expect("initial save");

        let updated = store
            .upsert(
                "analyst",
                UserPreferencesPatch {
                    theme: Some("light".into()),
                    pinned_sections: None,
                    dashboard_presets: None,
                    active_dashboard_preset: Some("".into()),
                },
            )
            .expect("update theme");

        assert_eq!(updated.theme.as_deref(), Some("light"));
        assert_eq!(updated.pinned_sections, vec!["fleet", "soc"]);
        assert_eq!(updated.dashboard_presets.len(), 1);
        assert_eq!(updated.dashboard_presets[0].widgets, vec!["threat-overview"]);
        assert_eq!(updated.dashboard_presets[0].hidden, vec!["threat-overview"]);
        assert_eq!(updated.active_dashboard_preset, None);
    }
}

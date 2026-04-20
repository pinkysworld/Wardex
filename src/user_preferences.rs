use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UserPreferences {
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub pinned_sections: Vec<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserPreferencesPatch {
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub pinned_sections: Option<Vec<String>>,
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
        if patch.theme.is_none() && patch.pinned_sections.is_none() {
            return Err("no preferences provided".into());
        }

        let mut current = self.get(actor);
        if let Some(theme) = patch.theme {
            current.theme = Some(normalize_theme(&theme)?);
        }
        if let Some(pinned_sections) = patch.pinned_sections {
            current.pinned_sections = normalize_pinned_sections(pinned_sections);
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
                },
            )
            .expect("save preferences");

        assert_eq!(saved.theme.as_deref(), Some("dark"));
        assert_eq!(saved.pinned_sections, vec!["fleet", "monitor"]);
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
                },
            )
            .expect("initial save");

        let updated = store
            .upsert(
                "analyst",
                UserPreferencesPatch {
                    theme: Some("light".into()),
                    pinned_sections: None,
                },
            )
            .expect("update theme");

        assert_eq!(updated.theme.as_deref(), Some("light"));
        assert_eq!(updated.pinned_sections, vec!["fleet", "soc"]);
    }
}

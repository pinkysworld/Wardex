use serde::{Deserialize, Serialize};

/// A published policy that agents poll from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: u64,
    pub published_at: String,
    pub alert_threshold: Option<f32>,
    pub interval_secs: Option<u64>,
    pub watch_paths: Option<Vec<String>>,
    pub dry_run: Option<bool>,
    pub syslog: Option<bool>,
    pub cef: Option<bool>,
}

/// Server-side policy store.
pub struct PolicyStore {
    current: Option<Policy>,
    history: Vec<Policy>,
    max_history: usize,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self {
            current: None,
            history: Vec::new(),
            max_history: 20,
        }
    }

    /// Publish a new policy version.
    pub fn publish(&mut self, mut policy: Policy) {
        let next_version = self.current.as_ref().map_or(1, |p| p.version + 1);
        policy.version = next_version;
        policy.published_at = chrono::Utc::now().to_rfc3339();

        // Move current to history
        if let Some(prev) = self.current.take() {
            self.history.push(prev);
            if self.history.len() > self.max_history {
                self.history.remove(0);
            }
        }

        self.current = Some(policy);
    }

    /// Get the current active policy.
    pub fn current(&self) -> Option<&Policy> {
        self.current.as_ref()
    }

    /// Get the current policy version number.
    pub fn current_version(&self) -> u64 {
        self.current.as_ref().map_or(0, |p| p.version)
    }

    /// Get policy history.
    pub fn history(&self) -> &[Policy] {
        &self.history
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_and_retrieve() {
        let mut store = PolicyStore::new();
        assert!(store.current().is_none());
        assert_eq!(store.current_version(), 0);

        store.publish(Policy {
            version: 0,
            published_at: String::new(),
            alert_threshold: Some(4.0),
            interval_secs: Some(10),
            watch_paths: None,
            dry_run: None,
            syslog: None,
            cef: None,
        });

        assert_eq!(store.current_version(), 1);
        assert_eq!(store.current().unwrap().alert_threshold, Some(4.0));
    }

    #[test]
    fn publish_increments_version() {
        let mut store = PolicyStore::new();
        for _ in 0..5 {
            store.publish(Policy {
                version: 0,
                published_at: String::new(),
                alert_threshold: Some(3.0),
                interval_secs: None,
                watch_paths: None,
                dry_run: None,
                syslog: None,
                cef: None,
            });
        }
        assert_eq!(store.current_version(), 5);
        assert_eq!(store.history().len(), 4);
    }

    #[test]
    fn history_capped() {
        let mut store = PolicyStore::new();
        for _ in 0..30 {
            store.publish(Policy {
                version: 0,
                published_at: String::new(),
                alert_threshold: None,
                interval_secs: None,
                watch_paths: None,
                dry_run: None,
                syslog: None,
                cef: None,
            });
        }
        assert!(store.history().len() <= 20);
    }
}

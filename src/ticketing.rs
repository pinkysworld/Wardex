//! Bidirectional ticketing integrations: Jira and ServiceNow.
//!
//! Implements real REST clients against Jira Cloud/Server (REST API v2/v3)
//! and the ServiceNow Table API, following the same shape as the cloud
//! collectors: a `Config` struct with `enabled`/credential fields resolved
//! through the existing `secrets::SecretsResolver`, a client with timeouts
//! and graceful degradation, and idempotent create-or-update semantics so
//! retries never create duplicate remote tickets.
//!
//! Local bookkeeping (`enterprise_store::TicketSyncRecord`) is kept as the
//! system of record for "have we synced this case before"; these clients are
//! the transport that makes that bookkeeping true bidirectionally: creating
//! or updating the remote ticket, and pulling its current remote status back
//! into the local record.

use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Jira ─────────────────────────────────────────────────────────────────────

/// Jira Cloud/Server REST client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraConfig {
    /// Base URL, e.g. "https://yourorg.atlassian.net" or an on-prem Jira Server URL.
    pub base_url: String,
    /// Project key to create issues under (e.g. "SEC").
    pub project_key: String,
    /// Issue type name (e.g. "Task", "Incident", "Bug").
    #[serde(default = "default_issue_type")]
    pub issue_type: String,
    /// Basic-auth email (Jira Cloud) — leave empty to use a bearer PAT instead.
    #[serde(default)]
    pub email: String,
    /// API token (Cloud, paired with `email`) or PAT (Server, used as bearer).
    #[serde(skip_serializing)]
    pub api_token: String,
    /// Request timeout, in seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    pub enabled: bool,
}

fn default_issue_type() -> String {
    "Task".to_string()
}
fn default_timeout_secs() -> u64 {
    15
}

impl Default for JiraConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            project_key: String::new(),
            issue_type: default_issue_type(),
            email: String::new(),
            api_token: String::new(),
            timeout_secs: default_timeout_secs(),
            enabled: false,
        }
    }
}

/// Outcome of a create/update/fetch against a ticketing backend, normalised
/// across Jira and ServiceNow so callers (and local bookkeeping) can treat
/// them uniformly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteTicket {
    pub provider: String,
    /// Provider-native key, e.g. "SEC-123" (Jira) or the sys_id (ServiceNow).
    pub external_key: String,
    /// Deep link to the ticket in the provider's UI, when known.
    pub url: Option<String>,
    /// Provider-native status/state string.
    pub status: String,
    pub created: bool,
}

#[derive(Debug)]
pub struct JiraClient {
    config: JiraConfig,
}

impl JiraClient {
    pub fn new(config: JiraConfig) -> Self {
        Self { config }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
            && !self.config.base_url.trim().is_empty()
            && !self.config.project_key.trim().is_empty()
            && !self.config.api_token.trim().is_empty()
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.timeout_secs)
    }

    fn authorize(&self, req: ureq::Request) -> ureq::Request {
        if !self.config.email.trim().is_empty() {
            use base64::Engine;
            let basic = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.config.email, self.config.api_token));
            req.set("Authorization", &format!("Basic {basic}"))
        } else {
            req.set(
                "Authorization",
                &format!("Bearer {}", self.config.api_token),
            )
        }
    }

    fn issue_url(&self, key: &str) -> String {
        format!(
            "{}/browse/{key}",
            self.config.base_url.trim_end_matches('/')
        )
    }

    /// Create a new issue, or (if `existing_key` is `Some`) treat this as an
    /// idempotent re-sync: add a comment to the existing issue instead of
    /// creating a duplicate.
    pub fn create_or_update_issue(
        &self,
        existing_key: Option<&str>,
        summary: &str,
        description: &str,
    ) -> Result<RemoteTicket, String> {
        if !self.is_enabled() {
            return Err("Jira integration is not enabled or configured".into());
        }

        if let Some(key) = existing_key {
            self.add_comment(key, description)?;
            let status = self.get_status(key).unwrap_or_else(|_| "unknown".into());
            return Ok(RemoteTicket {
                provider: "jira".into(),
                external_key: key.to_string(),
                url: Some(self.issue_url(key)),
                status,
                created: false,
            });
        }

        let base = self.config.base_url.trim_end_matches('/');
        let url = format!("{base}/rest/api/2/issue");
        let payload = serde_json::json!({
            "fields": {
                "project": { "key": self.config.project_key },
                "summary": summary,
                "description": description,
                "issuetype": { "name": self.config.issue_type },
            }
        });

        let req = self.authorize(
            ureq::post(&url)
                .set("Content-Type", "application/json")
                .timeout(self.timeout()),
        );
        let resp = req
            .send_string(&payload.to_string())
            .map_err(|e| format!("Jira create issue failed: {e}"))?;
        let body: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("Jira response parse failed: {e}"))?;
        let key = body
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or("Jira create response missing 'key'")?
            .to_string();

        Ok(RemoteTicket {
            provider: "jira".into(),
            url: Some(self.issue_url(&key)),
            status: "created".into(),
            external_key: key,
            created: true,
        })
    }

    pub fn add_comment(&self, key: &str, body: &str) -> Result<(), String> {
        let base = self.config.base_url.trim_end_matches('/');
        let url = format!("{base}/rest/api/2/issue/{key}/comment");
        let payload = serde_json::json!({ "body": body });
        let req = self.authorize(
            ureq::post(&url)
                .set("Content-Type", "application/json")
                .timeout(self.timeout()),
        );
        req.send_string(&payload.to_string())
            .map_err(|e| format!("Jira add comment failed: {e}"))?;
        Ok(())
    }

    /// Transition an issue by target transition name (e.g. "Done"). Looks up
    /// the numeric transition id first, since Jira requires it.
    pub fn transition_issue(&self, key: &str, transition_name: &str) -> Result<(), String> {
        let base = self.config.base_url.trim_end_matches('/');
        let list_url = format!("{base}/rest/api/2/issue/{key}/transitions");
        let req = self.authorize(ureq::get(&list_url).timeout(self.timeout()));
        let resp = req
            .call()
            .map_err(|e| format!("Jira list transitions failed: {e}"))?;
        let body: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("Jira transitions parse failed: {e}"))?;
        let transitions = body
            .get("transitions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let transition_id = transitions
            .iter()
            .find(|t| {
                t.get("name")
                    .and_then(|v| v.as_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case(transition_name))
            })
            .and_then(|t| t.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("No Jira transition named '{transition_name}' available"))?
            .to_string();

        let payload = serde_json::json!({ "transition": { "id": transition_id } });
        let req = self.authorize(
            ureq::post(&list_url)
                .set("Content-Type", "application/json")
                .timeout(self.timeout()),
        );
        req.send_string(&payload.to_string())
            .map_err(|e| format!("Jira transition failed: {e}"))?;
        Ok(())
    }

    /// Fetch the current status name of an issue.
    pub fn get_status(&self, key: &str) -> Result<String, String> {
        let base = self.config.base_url.trim_end_matches('/');
        let url = format!("{base}/rest/api/2/issue/{key}?fields=status");
        let req = self.authorize(ureq::get(&url).timeout(self.timeout()));
        let resp = req
            .call()
            .map_err(|e| format!("Jira get issue failed: {e}"))?;
        let body: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("Jira issue parse failed: {e}"))?;
        body.pointer("/fields/status/name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| "Jira issue response missing status".into())
    }
}

// ── ServiceNow ───────────────────────────────────────────────────────────────

/// ServiceNow Table API client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNowConfig {
    /// Instance base URL, e.g. "https://yourinstance.service-now.com".
    pub instance_url: String,
    /// Table to create/update records in (e.g. "incident").
    #[serde(default = "default_table")]
    pub table: String,
    /// Basic-auth username, or leave empty and set `oauth_token` for OAuth.
    #[serde(default)]
    pub username: String,
    /// Basic-auth password.
    #[serde(skip_serializing)]
    #[serde(default)]
    pub password: String,
    /// OAuth bearer token, used instead of username/password when set.
    #[serde(skip_serializing)]
    #[serde(default)]
    pub oauth_token: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    pub enabled: bool,
}

fn default_table() -> String {
    "incident".to_string()
}

impl Default for ServiceNowConfig {
    fn default() -> Self {
        Self {
            instance_url: String::new(),
            table: default_table(),
            username: String::new(),
            password: String::new(),
            oauth_token: String::new(),
            timeout_secs: default_timeout_secs(),
            enabled: false,
        }
    }
}

#[derive(Debug)]
pub struct ServiceNowClient {
    config: ServiceNowConfig,
}

impl ServiceNowClient {
    pub fn new(config: ServiceNowConfig) -> Self {
        Self { config }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
            && !self.config.instance_url.trim().is_empty()
            && (!self.config.oauth_token.trim().is_empty()
                || (!self.config.username.trim().is_empty()
                    && !self.config.password.trim().is_empty()))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.timeout_secs)
    }

    fn authorize(&self, req: ureq::Request) -> ureq::Request {
        if !self.config.oauth_token.trim().is_empty() {
            req.set(
                "Authorization",
                &format!("Bearer {}", self.config.oauth_token),
            )
        } else {
            use base64::Engine;
            let basic = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.config.username, self.config.password));
            req.set("Authorization", &format!("Basic {basic}"))
        }
    }

    fn table_url(&self) -> String {
        format!(
            "{}/api/now/table/{}",
            self.config.instance_url.trim_end_matches('/'),
            self.config.table
        )
    }

    fn record_url(&self, sys_id: &str) -> String {
        format!("{}/{sys_id}", self.table_url())
    }

    fn ticket_ui_url(&self, sys_id: &str) -> String {
        format!(
            "{}/nav_to.do?uri={}.do?sys_id={sys_id}",
            self.config.instance_url.trim_end_matches('/'),
            self.config.table
        )
    }

    /// Create a new incident, or (if `existing_sys_id` is `Some`) update it
    /// in place — idempotent re-sync without creating a duplicate record.
    pub fn create_or_update_incident(
        &self,
        existing_sys_id: Option<&str>,
        short_description: &str,
        description: &str,
    ) -> Result<RemoteTicket, String> {
        if !self.is_enabled() {
            return Err("ServiceNow integration is not enabled or configured".into());
        }

        if let Some(sys_id) = existing_sys_id {
            let payload = serde_json::json!({
                "short_description": short_description,
                "description": description,
                "work_notes": description,
            });
            let req = self.authorize(
                ureq::request("PATCH", &self.record_url(sys_id))
                    .set("Content-Type", "application/json")
                    .set("Accept", "application/json")
                    .timeout(self.timeout()),
            );
            let resp = req
                .send_string(&payload.to_string())
                .map_err(|e| format!("ServiceNow update incident failed: {e}"))?;
            let body: serde_json::Value = resp
                .into_json()
                .map_err(|e| format!("ServiceNow response parse failed: {e}"))?;
            let status = body
                .pointer("/result/state")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Ok(RemoteTicket {
                provider: "servicenow".into(),
                external_key: sys_id.to_string(),
                url: Some(self.ticket_ui_url(sys_id)),
                status,
                created: false,
            });
        }

        let payload = serde_json::json!({
            "short_description": short_description,
            "description": description,
        });
        let req = self.authorize(
            ureq::post(&self.table_url())
                .set("Content-Type", "application/json")
                .set("Accept", "application/json")
                .timeout(self.timeout()),
        );
        let resp = req
            .send_string(&payload.to_string())
            .map_err(|e| format!("ServiceNow create incident failed: {e}"))?;
        let body: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("ServiceNow response parse failed: {e}"))?;
        let sys_id = body
            .pointer("/result/sys_id")
            .and_then(|v| v.as_str())
            .ok_or("ServiceNow create response missing sys_id")?
            .to_string();
        let number = body
            .pointer("/result/number")
            .and_then(|v| v.as_str())
            .unwrap_or(&sys_id)
            .to_string();

        Ok(RemoteTicket {
            provider: "servicenow".into(),
            url: Some(self.ticket_ui_url(&sys_id)),
            status: "created".into(),
            external_key: number,
            created: true,
        })
    }

    /// Fetch the current state of an incident by sys_id.
    pub fn get_status(&self, sys_id: &str) -> Result<String, String> {
        let req = self.authorize(
            ureq::get(&self.record_url(sys_id))
                .set("Accept", "application/json")
                .timeout(self.timeout()),
        );
        let resp = req
            .call()
            .map_err(|e| format!("ServiceNow get incident failed: {e}"))?;
        let body: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("ServiceNow response parse failed: {e}"))?;
        body.pointer("/result/state")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| "ServiceNow response missing state".into())
    }
}

/// Aggregate ticketing configuration for both providers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TicketingConfig {
    #[serde(default)]
    pub jira: JiraConfig,
    #[serde(default)]
    pub servicenow: ServiceNowConfig,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock HTTP server that answers a fixed sequence of responses, one per
    /// connection, cycling if there are more requests than responses.
    fn spawn_sequenced_mock(responses: Vec<(&'static str, String)>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().expect("addr").port();
        let hit_count = Arc::new(AtomicUsize::new(0));
        let hit_count_thread = hit_count.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 8192];
                let mut received = Vec::new();
                loop {
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        // Best-effort: if there's a Content-Length, keep
                        // reading until we have the full body too.
                        let head = String::from_utf8_lossy(&received);
                        if let Some(idx) = head.find("Content-Length:") {
                            let rest = &head[idx + "Content-Length:".len()..];
                            let len: usize = rest
                                .split_whitespace()
                                .next()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            let header_end = head.find("\r\n\r\n").unwrap_or(head.len()) + 4;
                            if received.len() >= header_end + len {
                                break;
                            }
                            continue;
                        }
                        break;
                    }
                }
                let idx = hit_count_thread.fetch_add(1, Ordering::SeqCst);
                let (status, body) = &responses[idx.min(responses.len() - 1)];
                let response = format!(
                    "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                if idx + 1 >= responses.len() {
                    break;
                }
            }
        });
        (format!("http://127.0.0.1:{port}"), hit_count)
    }

    #[test]
    fn jira_disabled_returns_error() {
        let client = JiraClient::new(JiraConfig::default());
        let result = client.create_or_update_issue(None, "summary", "desc");
        assert!(result.is_err());
    }

    #[test]
    fn jira_creates_issue_when_no_existing_key() {
        let (base_url, _hits) = spawn_sequenced_mock(vec![(
            "HTTP/1.1 201 Created",
            r#"{"id":"10001","key":"SEC-42","self":"http://x"}"#.to_string(),
        )]);
        let client = JiraClient::new(JiraConfig {
            base_url,
            project_key: "SEC".into(),
            email: "bot@example.com".into(),
            api_token: "tok".into(),
            enabled: true,
            ..Default::default()
        });
        let ticket = client
            .create_or_update_issue(None, "New case", "details")
            .expect("create issue");
        assert_eq!(ticket.external_key, "SEC-42");
        assert!(ticket.created);
        assert!(ticket.url.unwrap().contains("SEC-42"));
    }

    #[test]
    fn jira_updates_via_comment_when_key_exists() {
        let (base_url, hits) = spawn_sequenced_mock(vec![
            ("HTTP/1.1 201 Created", r#"{"id":"1"}"#.to_string()),
            (
                "HTTP/1.1 200 OK",
                r#"{"fields":{"status":{"name":"In Progress"}}}"#.to_string(),
            ),
        ]);
        let client = JiraClient::new(JiraConfig {
            base_url,
            project_key: "SEC".into(),
            email: "bot@example.com".into(),
            api_token: "tok".into(),
            enabled: true,
            ..Default::default()
        });
        let ticket = client
            .create_or_update_issue(Some("SEC-1"), "New case", "an update")
            .expect("update issue");
        assert!(!ticket.created);
        assert_eq!(ticket.external_key, "SEC-1");
        assert_eq!(ticket.status, "In Progress");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn servicenow_disabled_returns_error() {
        let client = ServiceNowClient::new(ServiceNowConfig::default());
        let result = client.create_or_update_incident(None, "short", "desc");
        assert!(result.is_err());
    }

    #[test]
    fn servicenow_creates_incident_when_no_existing_id() {
        let (instance_url, _hits) = spawn_sequenced_mock(vec![(
            "HTTP/1.1 201 Created",
            r#"{"result":{"sys_id":"abc123","number":"INC0001234"}}"#.to_string(),
        )]);
        let client = ServiceNowClient::new(ServiceNowConfig {
            instance_url,
            username: "admin".into(),
            password: "pw".into(),
            enabled: true,
            ..Default::default()
        });
        let ticket = client
            .create_or_update_incident(None, "short desc", "body")
            .expect("create incident");
        assert!(ticket.created);
        assert_eq!(ticket.external_key, "INC0001234");
    }

    #[test]
    fn servicenow_updates_incident_when_sys_id_exists() {
        let (instance_url, hits) = spawn_sequenced_mock(vec![(
            "HTTP/1.1 200 OK",
            r#"{"result":{"sys_id":"abc123","state":"2"}}"#.to_string(),
        )]);
        let client = ServiceNowClient::new(ServiceNowConfig {
            instance_url,
            username: "admin".into(),
            password: "pw".into(),
            enabled: true,
            ..Default::default()
        });
        let ticket = client
            .create_or_update_incident(Some("abc123"), "short desc", "update body")
            .expect("update incident");
        assert!(!ticket.created);
        assert_eq!(ticket.status, "2");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn servicenow_oauth_token_enables_client() {
        let config = ServiceNowConfig {
            instance_url: "https://x.service-now.com".into(),
            oauth_token: "tok".into(),
            enabled: true,
            ..Default::default()
        };
        let client = ServiceNowClient::new(config);
        assert!(client.is_enabled());
    }

    #[test]
    fn jira_requires_project_key_to_be_enabled() {
        let config = JiraConfig {
            base_url: "https://x.atlassian.net".into(),
            api_token: "tok".into(),
            enabled: true,
            ..Default::default()
        };
        let client = JiraClient::new(config);
        assert!(!client.is_enabled());
    }
}

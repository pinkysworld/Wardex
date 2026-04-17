// Role-Based Access Control for API endpoint protection.
// ADR-0004: Layered identity model.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

// ── Roles and permissions ───────────────────────────────────────

/// User roles with hierarchical permissions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Role {
    /// Full access: manage users, configure system, respond to incidents.
    Admin,
    /// Investigation access: view events, manage incidents, approve responses.
    Analyst,
    /// Read-only access: view dashboards, read events, list incidents.
    Viewer,
    /// Machine-to-machine: agent enrollment, telemetry submission.
    ServiceAccount,
}

/// API permission flags.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Permission {
    ViewDashboard,
    ViewEvents,
    ViewIncidents,
    ManageIncidents,
    ViewAlerts,
    ManageAlerts,
    ViewAgents,
    ManageAgents,
    SubmitTelemetry,
    ViewConfig,
    ManageConfig,
    ManageUsers,
    ApproveResponses,
    ExecuteResponses,
    ViewAuditLog,
    ManageRules,
    PromoteRules,
    ManageHunts,
    ManageSuppressions,
    ManageConnectors,
    SyncTickets,
    ManageIdentityProviders,
    ManageScim,
    ViewSupport,
    ViewCoverage,
    ViewReports,
    ExportData,
    ManageFeatureFlags,
}

/// Get the permissions granted to a role.
pub fn role_permissions(role: Role) -> Vec<Permission> {
    match role {
        Role::Admin => vec![
            Permission::ViewDashboard,
            Permission::ViewEvents,
            Permission::ViewIncidents,
            Permission::ManageIncidents,
            Permission::ViewAlerts,
            Permission::ManageAlerts,
            Permission::ViewAgents,
            Permission::ManageAgents,
            Permission::SubmitTelemetry,
            Permission::ViewConfig,
            Permission::ManageConfig,
            Permission::ManageUsers,
            Permission::ApproveResponses,
            Permission::ExecuteResponses,
            Permission::ViewAuditLog,
            Permission::ManageRules,
            Permission::PromoteRules,
            Permission::ManageHunts,
            Permission::ManageSuppressions,
            Permission::ManageConnectors,
            Permission::SyncTickets,
            Permission::ManageIdentityProviders,
            Permission::ManageScim,
            Permission::ViewSupport,
            Permission::ViewCoverage,
            Permission::ViewReports,
            Permission::ExportData,
            Permission::ManageFeatureFlags,
        ],
        Role::Analyst => vec![
            Permission::ViewDashboard,
            Permission::ViewEvents,
            Permission::ViewIncidents,
            Permission::ManageIncidents,
            Permission::ViewAlerts,
            Permission::ManageAlerts,
            Permission::ViewAgents,
            Permission::ApproveResponses,
            Permission::ViewAuditLog,
            Permission::ManageRules,
            Permission::ManageHunts,
            Permission::ManageSuppressions,
            Permission::SyncTickets,
            Permission::ViewCoverage,
            Permission::ViewSupport,
            Permission::ViewReports,
            Permission::ExportData,
            Permission::ViewConfig,
        ],
        Role::Viewer => vec![
            Permission::ViewDashboard,
            Permission::ViewEvents,
            Permission::ViewIncidents,
            Permission::ViewAlerts,
            Permission::ViewAgents,
            Permission::ViewReports,
            Permission::ViewConfig,
            Permission::ViewCoverage,
            Permission::ViewSupport,
        ],
        Role::ServiceAccount => vec![Permission::SubmitTelemetry, Permission::ViewConfig],
    }
}

// ── User model ──────────────────────────────────────────────────

/// A user identity with role assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub role: Role,
    /// API token (hashed in production).
    pub token_hash: String,
    pub enabled: bool,
    pub created_at: String,
    /// Optional tenant scope for multi-tenant isolation.
    pub tenant_id: Option<String>,
}

// ── RBAC store ──────────────────────────────────────────────────

/// In-memory user and role store with permission checking.
pub struct RbacStore {
    users: Mutex<HashMap<String, User>>,
    /// Token -> username lookup for fast auth.
    tokens: Mutex<HashMap<String, String>>,
}

impl RbacStore {
    pub fn new() -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Register a user. The token should be pre-hashed for production.
    pub fn add_user(&self, user: User) {
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());

        let token = user.token_hash.clone();
        let username = user.username.clone();

        if let Some(existing) = users.insert(username.clone(), user) {
            tokens.remove(&existing.token_hash);
        }

        tokens.insert(token, username);
    }

    /// Remove a user.
    pub fn remove_user(&self, username: &str) -> bool {
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(user) = users.remove(username) {
            self.tokens
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&user.token_hash);
            true
        } else {
            false
        }
    }

    /// Authenticate by token, returning the user if valid.
    pub fn authenticate(&self, token: &str) -> Option<User> {
        let users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        let tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        let username = tokens.get(token)?;
        let user = users.get(username)?;
        if user.enabled {
            Some(user.clone())
        } else {
            None
        }
    }

    /// Check if a token grants a specific permission.
    pub fn has_permission(&self, token: &str, perm: Permission) -> bool {
        self.authenticate(token)
            .map(|u| role_permissions(u.role).contains(&perm))
            .unwrap_or(false)
    }

    /// Check if a token grants access to a specific API path.
    pub fn check_api_access(&self, token: &str, method: &str, path: &str) -> AccessResult {
        let user = match self.authenticate(token) {
            Some(u) => u,
            None => return AccessResult::Denied("Invalid or disabled token".into()),
        };

        let required = endpoint_permission(method, path);
        let perms = role_permissions(user.role);

        if perms.contains(&required) {
            AccessResult::Allowed(user.username, user.role)
        } else {
            AccessResult::Denied(format!(
                "Role {:?} lacks permission {:?} for {} {}",
                user.role, required, method, path
            ))
        }
    }

    pub fn get_user(&self, username: &str) -> Option<User> {
        self.users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(username)
            .cloned()
    }

    pub fn list_users(&self) -> Vec<User> {
        self.users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    pub fn update_role(&self, username: &str, role: Role) -> bool {
        if let Some(user) = self
            .users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(username)
        {
            user.role = role;
            true
        } else {
            false
        }
    }

    pub fn disable_user(&self, username: &str) -> bool {
        if let Some(user) = self
            .users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(username)
        {
            user.enabled = false;
            true
        } else {
            false
        }
    }

    pub fn enable_user(&self, username: &str) -> bool {
        if let Some(user) = self
            .users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(username)
        {
            user.enabled = true;
            true
        } else {
            false
        }
    }
}

impl Default for RbacStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of an API access check.
#[derive(Debug, Clone)]
pub enum AccessResult {
    Allowed(String, Role),
    Denied(String),
}

impl AccessResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, AccessResult::Allowed(..))
    }
}

/// Map API endpoint to required permission.
pub fn endpoint_permission(method: &str, path: &str) -> Permission {
    let m = method.to_uppercase();
    let normalized = path.split('?').next().unwrap_or(path);
    match (m.as_str(), normalized) {
        // Dashboard
        (_, p) if p.starts_with("/api/dashboard") => Permission::ViewDashboard,

        // Status, reports, and operator overviews
        ("GET", "/api/auth/check") => Permission::ViewSupport,
        ("GET", "/api/auth/session") => Permission::ViewSupport,
        ("POST", "/api/auth/logout") => Permission::ViewSupport,
        ("GET", "/api/status") => Permission::ViewDashboard,
        ("GET", "/api/report") => Permission::ViewReports,
        ("GET", "/api/workbench/overview") => Permission::ViewIncidents,
        ("GET", "/api/manager/overview") => Permission::ViewReports,

        // Events
        ("GET", p) if p.starts_with("/api/telemetry/") => Permission::ViewEvents,
        ("GET", p) if p.starts_with("/api/events") => Permission::ViewEvents,
        ("POST", "/api/events/search") => Permission::ViewEvents,
        (_, p) if p.starts_with("/api/events") => Permission::ManageAlerts,

        // Incidents
        ("GET", p) if p.starts_with("/api/incidents") => Permission::ViewIncidents,
        (_, p) if p.starts_with("/api/incidents") => Permission::ManageIncidents,
        ("GET", p) if p.starts_with("/api/cases") => Permission::ViewIncidents,
        (_, p) if p.starts_with("/api/cases") => Permission::ManageIncidents,

        // Investigation workspace
        ("GET", p) if p.starts_with("/api/queue/") => Permission::ViewAlerts,
        ("POST", "/api/queue/acknowledge") | ("POST", "/api/queue/assign") => {
            Permission::ManageAlerts
        }
        ("GET", p) if p.starts_with("/api/timeline/") || p.starts_with("/api/process-tree") => {
            Permission::ViewIncidents
        }
        ("POST", "/api/investigation/graph") => Permission::ViewIncidents,
        ("GET", p) if p.starts_with("/api/playbooks") => Permission::ViewIncidents,
        ("POST", "/api/playbooks/execute") => Permission::ExecuteResponses,
        ("GET", p) if p.starts_with("/api/live-response/") => Permission::ViewAuditLog,
        ("POST", p) if p.starts_with("/api/live-response/") => Permission::ExecuteResponses,

        // Alerts
        ("GET", p) if p.starts_with("/api/alerts") => Permission::ViewAlerts,
        (_, p) if p.starts_with("/api/alerts") => Permission::ManageAlerts,

        // Agents / Fleet
        ("GET", p) if p.starts_with("/api/agents") || p.starts_with("/api/fleet") => {
            Permission::ViewAgents
        }
        (_, p) if p.starts_with("/api/agents") || p.starts_with("/api/fleet") => {
            Permission::ManageAgents
        }
        ("GET", "/api/rollout/config") => Permission::ViewAgents,

        // Telemetry ingestion
        ("POST", p) if p.starts_with("/api/telemetry") || p.starts_with("/api/ingest") => {
            Permission::SubmitTelemetry
        }

        // Config
        ("GET", p)
            if p == "/api/checkpoints"
                || p == "/api/feature-flags"
                || p.starts_with("/api/policy")
                || p.starts_with("/api/config") =>
        {
            Permission::ViewConfig
        }
        ("POST", p) if p.starts_with("/api/policy") => Permission::ManageConfig,
        ("GET", p) if p.starts_with("/api/config") => Permission::ViewConfig,
        (_, p) if p.starts_with("/api/config") => Permission::ManageConfig,
        ("GET", p) if p.starts_with("/api/retention/") => Permission::ViewSupport,
        (_, p) if p.starts_with("/api/retention/") => Permission::ManageConfig,

        // Users
        (_, p) if p.starts_with("/api/users") || p.starts_with("/api/rbac/users") => {
            Permission::ManageUsers
        }

        // Response orchestration
        ("GET", "/api/response/audit") | ("GET", "/api/response/approvals") => {
            Permission::ViewAuditLog
        }
        ("GET", p) if p.starts_with("/api/response") => Permission::ViewIncidents,
        ("POST", "/api/response/request") => Permission::ApproveResponses,
        ("POST", p) if p.contains("approve") || p.contains("deny") => Permission::ApproveResponses,
        ("POST", p) if p.starts_with("/api/response") => Permission::ExecuteResponses,

        // Audit
        (_, p) if p.starts_with("/api/audit") => Permission::ViewAuditLog,

        // Rules / Detection Content
        ("GET", p)
            if p.starts_with("/api/rules")
                || p.starts_with("/api/sigma")
                || p.starts_with("/api/content/rules")
                || p.starts_with("/api/content/packs")
                || p.starts_with("/api/hunts")
                || p.starts_with("/api/coverage/mitre")
                || p.starts_with("/api/suppressions")
                || p == "/api/threat-intel/status"
                || p.starts_with("/api/entities/")
                || p.ends_with("/storyline") =>
        {
            Permission::ViewCoverage
        }
        ("POST", p)
            if p.starts_with("/api/content/rules/")
                && (p.ends_with("/promote") || p.ends_with("/rollback")) =>
        {
            Permission::PromoteRules
        }
        (_, p)
            if p.starts_with("/api/rules")
                || p.starts_with("/api/sigma")
                || p.starts_with("/api/content/rules") =>
        {
            Permission::ManageRules
        }
        (_, p) if p.starts_with("/api/content/packs") || p == "/api/threat-intel/ioc" => {
            Permission::ManageHunts
        }
        (_, p) if p.starts_with("/api/hunts") => Permission::ManageHunts,
        (_, p) if p.starts_with("/api/suppressions") => Permission::ManageSuppressions,

        // Integrations
        ("GET", p) if p.starts_with("/api/enrichments/connectors") => Permission::ViewSupport,
        (_, p) if p.starts_with("/api/enrichments/connectors") => Permission::ManageConnectors,
        (_, p) if p.starts_with("/api/tickets/sync") => Permission::SyncTickets,
        ("GET", p) if p.starts_with("/api/siem/") || p.starts_with("/api/taxii/") => {
            Permission::ViewSupport
        }
        (_, p) if p.starts_with("/api/siem/") || p.starts_with("/api/taxii/") => {
            Permission::ManageConnectors
        }

        // Identity & provisioning
        ("GET", p) if p.starts_with("/api/idp/providers") => Permission::ViewSupport,
        (_, p) if p.starts_with("/api/idp/providers") => Permission::ManageIdentityProviders,
        ("GET", p) if p.starts_with("/api/scim/config") => Permission::ViewSupport,
        (_, p) if p.starts_with("/api/scim/config") => Permission::ManageScim,

        // Support
        ("GET", p)
            if p == "/api/audit/admin"
                || p == "/api/ocsf/schema"
                || p == "/api/ocsf/schema/version"
                || p == "/api/detection/summary"
                || p == "/api/detection/weights"
                || p == "/api/dlq"
                || p == "/api/dlq/stats"
                || p == "/api/correlation"
                || p == "/api/endpoints"
                || p == "/api/host/info"
                || p == "/api/platform"
                || p == "/api/privacy/budget"
                || p == "/api/quantum/key-status"
                || p == "/api/research-tracks"
                || p == "/api/session/info"
                || p == "/api/slo/status"
                || p == "/api/threads/status"
                || p == "/api/attestation/status"
                || p == "/api/compliance/status"
                || p == "/api/deception/status"
                || p == "/api/digital-twin/status"
                || p == "/api/drift/status"
                || p == "/api/energy/status"
                || p == "/api/enforcement/status"
                || p == "/api/fingerprint/status"
                || p == "/api/mesh/health"
                || p == "/api/monitor/status"
                || p == "/api/monitor/violations"
                || p == "/api/spool/stats"
                || p == "/api/swarm/intel"
                || p == "/api/swarm/intel/stats"
                || p == "/api/side-channel/status"
                || p == "/api/swarm/posture"
                || p == "/api/tenants/count"
                || p == "/api/tls/status"
                || p == "/api/causal/graph"
                || p == "/api/patches"
                || p.starts_with("/api/monitoring/")
                || p.starts_with("/api/support/")
                || p.starts_with("/api/system/health/") =>
        {
            Permission::ViewSupport
        }
        ("GET", "/api/updates/releases") => Permission::ViewAgents,
        ("DELETE", "/api/dlq") => Permission::ManageConfig,

        // Reports
        ("GET", p) if p.starts_with("/api/reports") => Permission::ViewReports,
        (_, p) if p.starts_with("/api/reports") => Permission::ManageConfig,
        (_, "/api/report-templates") => Permission::ViewReports,
        (_, "/api/report-runs") => Permission::ViewReports,
        (_, "/api/report-schedules") => Permission::ViewReports,
        ("GET", "/api/inbox") | ("POST", "/api/inbox/ack") => Permission::ViewSupport,

        // Export
        (_, p) if p.starts_with("/api/export") => Permission::ExportData,

        // Feature flags
        ("GET", p) if p.starts_with("/api/flags") || p == "/api/feature-flags" => {
            Permission::ViewConfig
        }
        (_, p) if p.starts_with("/api/flags") || p == "/api/feature-flags" => {
            Permission::ManageFeatureFlags
        }

        // Default: require admin
        _ => Permission::ManageConfig,
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_store() -> RbacStore {
        let store = RbacStore::new();
        store.add_user(User {
            username: "admin".into(),
            role: Role::Admin,
            token_hash: "admin-token".into(),
            enabled: true,
            created_at: "now".into(),
            tenant_id: None,
        });
        store.add_user(User {
            username: "analyst".into(),
            role: Role::Analyst,
            token_hash: "analyst-token".into(),
            enabled: true,
            created_at: "now".into(),
            tenant_id: None,
        });
        store.add_user(User {
            username: "viewer".into(),
            role: Role::Viewer,
            token_hash: "viewer-token".into(),
            enabled: true,
            created_at: "now".into(),
            tenant_id: None,
        });
        store.add_user(User {
            username: "agent-01".into(),
            role: Role::ServiceAccount,
            token_hash: "sa-token".into(),
            enabled: true,
            created_at: "now".into(),
            tenant_id: None,
        });
        store
    }

    #[test]
    fn admin_has_all_permissions() {
        let store = setup_store();
        assert!(store.has_permission("admin-token", Permission::ManageUsers));
        assert!(store.has_permission("admin-token", Permission::ExecuteResponses));
        assert!(store.has_permission("admin-token", Permission::ManageFeatureFlags));
        assert!(store.has_permission("admin-token", Permission::PromoteRules));
    }

    #[test]
    fn analyst_permissions() {
        let store = setup_store();
        assert!(store.has_permission("analyst-token", Permission::ViewEvents));
        assert!(store.has_permission("analyst-token", Permission::ManageIncidents));
        assert!(store.has_permission("analyst-token", Permission::ApproveResponses));
        assert!(store.has_permission("analyst-token", Permission::ManageHunts));
        assert!(store.has_permission("analyst-token", Permission::ManageRules));
        assert!(!store.has_permission("analyst-token", Permission::ManageUsers));
        assert!(!store.has_permission("analyst-token", Permission::ManageFeatureFlags));
        assert!(!store.has_permission("analyst-token", Permission::PromoteRules));
    }

    #[test]
    fn viewer_read_only() {
        let store = setup_store();
        assert!(store.has_permission("viewer-token", Permission::ViewDashboard));
        assert!(store.has_permission("viewer-token", Permission::ViewEvents));
        assert!(store.has_permission("viewer-token", Permission::ViewSupport));
        assert!(!store.has_permission("viewer-token", Permission::ManageIncidents));
        assert!(!store.has_permission("viewer-token", Permission::ExecuteResponses));
    }

    #[test]
    fn service_account_limited() {
        let store = setup_store();
        assert!(store.has_permission("sa-token", Permission::SubmitTelemetry));
        assert!(store.has_permission("sa-token", Permission::ViewConfig));
        assert!(!store.has_permission("sa-token", Permission::ViewEvents));
        assert!(!store.has_permission("sa-token", Permission::ManageUsers));
    }

    #[test]
    fn authenticate_valid() {
        let store = setup_store();
        let user = store.authenticate("admin-token").unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, Role::Admin);
    }

    #[test]
    fn authenticate_invalid() {
        let store = setup_store();
        assert!(store.authenticate("bad-token").is_none());
    }

    #[test]
    fn disabled_user_blocked() {
        let store = setup_store();
        store.disable_user("analyst");
        assert!(store.authenticate("analyst-token").is_none());
        assert!(!store.has_permission("analyst-token", Permission::ViewEvents));
    }

    #[test]
    fn check_api_access_events() {
        let store = setup_store();
        assert!(
            store
                .check_api_access("viewer-token", "GET", "/api/events")
                .is_allowed()
        );
        assert!(
            !store
                .check_api_access("viewer-token", "POST", "/api/events")
                .is_allowed()
        );
        assert!(
            store
                .check_api_access("admin-token", "POST", "/api/events")
                .is_allowed()
        );
    }

    #[test]
    fn check_api_access_users() {
        let store = setup_store();
        assert!(
            store
                .check_api_access("admin-token", "POST", "/api/users")
                .is_allowed()
        );
        assert!(
            !store
                .check_api_access("analyst-token", "POST", "/api/users")
                .is_allowed()
        );
    }

    #[test]
    fn check_api_telemetry_ingestion() {
        let store = setup_store();
        assert!(
            store
                .check_api_access("sa-token", "POST", "/api/telemetry")
                .is_allowed()
        );
        assert!(
            !store
                .check_api_access("viewer-token", "POST", "/api/telemetry")
                .is_allowed()
        );
    }

    #[test]
    fn update_role() {
        let store = setup_store();
        store.update_role("viewer", Role::Analyst);
        let user = store.get_user("viewer").unwrap();
        assert_eq!(user.role, Role::Analyst);
        // Now should have analyst permissions
        assert!(store.has_permission("viewer-token", Permission::ManageIncidents));
    }

    #[test]
    fn remove_user() {
        let store = setup_store();
        assert!(store.remove_user("viewer"));
        assert!(store.authenticate("viewer-token").is_none());
        assert!(!store.remove_user("nonexistent"));
    }

    #[test]
    fn replacing_user_invalidates_old_token() {
        let store = setup_store();

        store.add_user(User {
            username: "viewer".into(),
            role: Role::Analyst,
            token_hash: "viewer-token-new".into(),
            enabled: true,
            created_at: "later".into(),
            tenant_id: None,
        });

        assert!(store.authenticate("viewer-token").is_none());
        let user = store
            .authenticate("viewer-token-new")
            .expect("replacement token should authenticate");
        assert_eq!(user.username, "viewer");
        assert_eq!(user.role, Role::Analyst);
    }

    #[test]
    fn list_users() {
        let store = setup_store();
        let users = store.list_users();
        assert_eq!(users.len(), 4);
    }

    #[test]
    fn endpoint_permission_mapping() {
        assert_eq!(
            endpoint_permission("GET", "/api/events"),
            Permission::ViewEvents
        );
        assert_eq!(
            endpoint_permission("POST", "/api/events/search"),
            Permission::ViewEvents
        );
        assert_eq!(
            endpoint_permission("POST", "/api/telemetry"),
            Permission::SubmitTelemetry
        );
        assert_eq!(
            endpoint_permission("POST", "/api/users"),
            Permission::ManageUsers
        );
        assert_eq!(
            endpoint_permission("POST", "/api/rbac/users"),
            Permission::ManageUsers
        );
        assert_eq!(
            endpoint_permission("GET", "/api/dashboard"),
            Permission::ViewDashboard
        );
        assert_eq!(
            endpoint_permission("GET", "/api/status"),
            Permission::ViewDashboard
        );
        assert_eq!(
            endpoint_permission("GET", "/api/report"),
            Permission::ViewReports
        );
        assert_eq!(
            endpoint_permission("GET", "/api/reports/42"),
            Permission::ViewReports
        );
        assert_eq!(
            endpoint_permission("DELETE", "/api/reports/42"),
            Permission::ManageConfig
        );
        assert_eq!(
            endpoint_permission("GET", "/api/auth/check"),
            Permission::ViewSupport
        );
        assert_eq!(
            endpoint_permission("GET", "/api/auth/session"),
            Permission::ViewSupport
        );
        assert_eq!(
            endpoint_permission("POST", "/api/auth/logout"),
            Permission::ViewSupport
        );
        assert_eq!(
            endpoint_permission("GET", "/api/telemetry/current"),
            Permission::ViewEvents
        );
        assert_eq!(
            endpoint_permission("GET", "/api/cases"),
            Permission::ViewIncidents
        );
        assert_eq!(
            endpoint_permission("POST", "/api/cases"),
            Permission::ManageIncidents
        );
        assert_eq!(
            endpoint_permission("GET", "/api/workbench/overview"),
            Permission::ViewIncidents
        );
        assert_eq!(
            endpoint_permission("GET", "/api/monitoring/options"),
            Permission::ViewSupport
        );
        assert_eq!(
            endpoint_permission("GET", "/api/queue/alerts"),
            Permission::ViewAlerts
        );
        assert_eq!(
            endpoint_permission("POST", "/api/queue/assign"),
            Permission::ManageAlerts
        );
        assert_eq!(
            endpoint_permission("GET", "/api/playbooks"),
            Permission::ViewIncidents
        );
        assert_eq!(
            endpoint_permission("POST", "/api/playbooks/execute"),
            Permission::ExecuteResponses
        );
        assert_eq!(
            endpoint_permission("GET", "/api/live-response/sessions"),
            Permission::ViewAuditLog
        );
        assert_eq!(
            endpoint_permission("GET", "/api/live-response/audit"),
            Permission::ViewAuditLog
        );
        assert_eq!(
            endpoint_permission("POST", "/api/live-response/session"),
            Permission::ExecuteResponses
        );
        assert_eq!(
            endpoint_permission("POST", "/api/live-response/command"),
            Permission::ExecuteResponses
        );
        assert_eq!(
            endpoint_permission("GET", "/api/rollout/config"),
            Permission::ViewAgents
        );
        assert_eq!(
            endpoint_permission("GET", "/api/updates/releases"),
            Permission::ViewAgents
        );
        assert_eq!(
            endpoint_permission("GET", "/api/threat-intel/status"),
            Permission::ViewCoverage
        );
        assert_eq!(
            endpoint_permission("POST", "/api/response/request"),
            Permission::ApproveResponses
        );
        assert_eq!(
            endpoint_permission("POST", "/api/response/approve"),
            Permission::ApproveResponses
        );
        assert_eq!(
            endpoint_permission("POST", "/api/response/execute"),
            Permission::ExecuteResponses
        );
        assert_eq!(
            endpoint_permission("GET", "/api/response/audit"),
            Permission::ViewAuditLog
        );
        assert_eq!(
            endpoint_permission("GET", "/api/response/approvals"),
            Permission::ViewAuditLog
        );
        assert_eq!(
            endpoint_permission("POST", "/api/content/rules/SE-001/promote"),
            Permission::PromoteRules
        );
    }

    #[test]
    fn report_deletes_require_admin_level_access() {
        let store = setup_store();

        assert!(
            !store
                .check_api_access("viewer-token", "DELETE", "/api/reports/42")
                .is_allowed()
        );
        assert!(
            store
                .check_api_access("admin-token", "DELETE", "/api/reports/42")
                .is_allowed()
        );
    }

    #[test]
    fn analyst_can_submit_but_not_execute_response_actions() {
        let store = setup_store();

        assert!(
            store
                .check_api_access("analyst-token", "POST", "/api/response/request")
                .is_allowed()
        );
        assert!(
            store
                .check_api_access("analyst-token", "POST", "/api/response/approve")
                .is_allowed()
        );
        assert!(
            !store
                .check_api_access("analyst-token", "POST", "/api/response/execute")
                .is_allowed()
        );
    }

    #[test]
    fn analyst_can_view_live_response_audit_but_not_execute_commands() {
        let store = setup_store();

        assert!(
            store
                .check_api_access("analyst-token", "GET", "/api/live-response/sessions")
                .is_allowed()
        );
        assert!(
            store
                .check_api_access("analyst-token", "GET", "/api/live-response/audit")
                .is_allowed()
        );
        assert!(
            !store
                .check_api_access("analyst-token", "POST", "/api/live-response/session")
                .is_allowed()
        );
        assert!(
            !store
                .check_api_access("analyst-token", "POST", "/api/live-response/command")
                .is_allowed()
        );
    }

    #[test]
    fn viewer_and_analyst_can_access_read_only_operator_routes() {
        let store = setup_store();
        for path in [
            "/api/status",
            "/api/report",
            "/api/telemetry/current",
            "/api/host/info",
            "/api/monitoring/options",
            "/api/slo/status",
            "/api/workbench/overview",
            "/api/cases",
            "/api/cases/stats",
            "/api/queue/alerts",
            "/api/playbooks",
            "/api/timeline/host?hostname=demo",
            "/api/updates/releases",
            "/api/threat-intel/status",
        ] {
            assert!(
                store
                    .check_api_access("viewer-token", "GET", path)
                    .is_allowed(),
                "viewer should access {path}"
            );
            assert!(
                store
                    .check_api_access("analyst-token", "GET", path)
                    .is_allowed(),
                "analyst should access {path}"
            );
        }
        assert!(
            store
                .check_api_access("analyst-token", "POST", "/api/queue/assign")
                .is_allowed()
        );
        assert!(
            store
                .check_api_access("analyst-token", "POST", "/api/events/search")
                .is_allowed()
        );
        assert!(
            store
                .check_api_access("analyst-token", "POST", "/api/investigation/graph")
                .is_allowed()
        );
    }

    #[test]
    fn store_survives_poisoned_mutex() {
        let store = std::sync::Arc::new(setup_store());
        // Poison the mutex by panicking while holding the lock
        let s2 = store.clone();
        let _ = std::thread::spawn(move || {
            let _guard = s2.users.lock().unwrap();
            panic!("intentional poison");
        })
        .join();
        // Operations should still succeed despite poisoned lock
        assert!(store.authenticate("admin-token").is_some());
        assert_eq!(store.list_users().len(), 4);
        store.add_user(User {
            username: "new-user".into(),
            role: Role::Viewer,
            token_hash: "new-token".into(),
            enabled: true,
            created_at: "now".into(),
            tenant_id: None,
        });
        assert_eq!(store.list_users().len(), 5);
    }
}

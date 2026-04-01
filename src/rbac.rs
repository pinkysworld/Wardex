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
    ViewReports,
    ExportData,
    ManageFeatureFlags,
}

/// Get the permissions granted to a role.
pub fn role_permissions(role: Role) -> Vec<Permission> {
    match role {
        Role::Admin => vec![
            Permission::ViewDashboard, Permission::ViewEvents, Permission::ViewIncidents,
            Permission::ManageIncidents, Permission::ViewAlerts, Permission::ManageAlerts,
            Permission::ViewAgents, Permission::ManageAgents, Permission::SubmitTelemetry,
            Permission::ViewConfig, Permission::ManageConfig, Permission::ManageUsers,
            Permission::ApproveResponses, Permission::ExecuteResponses, Permission::ViewAuditLog,
            Permission::ManageRules, Permission::ViewReports, Permission::ExportData,
            Permission::ManageFeatureFlags,
        ],
        Role::Analyst => vec![
            Permission::ViewDashboard, Permission::ViewEvents, Permission::ViewIncidents,
            Permission::ManageIncidents, Permission::ViewAlerts, Permission::ManageAlerts,
            Permission::ViewAgents, Permission::ApproveResponses, Permission::ViewAuditLog,
            Permission::ViewReports, Permission::ExportData, Permission::ViewConfig,
        ],
        Role::Viewer => vec![
            Permission::ViewDashboard, Permission::ViewEvents, Permission::ViewIncidents,
            Permission::ViewAlerts, Permission::ViewAgents, Permission::ViewReports,
            Permission::ViewConfig,
        ],
        Role::ServiceAccount => vec![
            Permission::SubmitTelemetry, Permission::ViewConfig,
        ],
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
        let token = user.token_hash.clone();
        let username = user.username.clone();
        self.users.lock().unwrap().insert(username.clone(), user);
        self.tokens.lock().unwrap().insert(token, username);
    }

    /// Remove a user.
    pub fn remove_user(&self, username: &str) -> bool {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.remove(username) {
            self.tokens.lock().unwrap().remove(&user.token_hash);
            true
        } else {
            false
        }
    }

    /// Authenticate by token, returning the user if valid.
    pub fn authenticate(&self, token: &str) -> Option<User> {
        let tokens = self.tokens.lock().unwrap();
        let username = tokens.get(token)?;
        let users = self.users.lock().unwrap();
        let user = users.get(username)?;
        if user.enabled { Some(user.clone()) } else { None }
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
            AccessResult::Denied(format!("Role {:?} lacks permission {:?} for {} {}", user.role, required, method, path))
        }
    }

    pub fn get_user(&self, username: &str) -> Option<User> {
        self.users.lock().unwrap().get(username).cloned()
    }

    pub fn list_users(&self) -> Vec<User> {
        self.users.lock().unwrap().values().cloned().collect()
    }

    pub fn update_role(&self, username: &str, role: Role) -> bool {
        if let Some(user) = self.users.lock().unwrap().get_mut(username) {
            user.role = role;
            true
        } else {
            false
        }
    }

    pub fn disable_user(&self, username: &str) -> bool {
        if let Some(user) = self.users.lock().unwrap().get_mut(username) {
            user.enabled = false;
            true
        } else {
            false
        }
    }

    pub fn enable_user(&self, username: &str) -> bool {
        if let Some(user) = self.users.lock().unwrap().get_mut(username) {
            user.enabled = true;
            true
        } else {
            false
        }
    }
}

impl Default for RbacStore {
    fn default() -> Self { Self::new() }
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
    match (m.as_str(), path) {
        // Dashboard
        (_, p) if p.starts_with("/api/dashboard") => Permission::ViewDashboard,

        // Events
        ("GET", p) if p.starts_with("/api/events") => Permission::ViewEvents,
        (_, p) if p.starts_with("/api/events") => Permission::ManageAlerts,

        // Incidents
        ("GET", p) if p.starts_with("/api/incidents") => Permission::ViewIncidents,
        (_, p) if p.starts_with("/api/incidents") => Permission::ManageIncidents,

        // Alerts
        ("GET", p) if p.starts_with("/api/alerts") => Permission::ViewAlerts,
        (_, p) if p.starts_with("/api/alerts") => Permission::ManageAlerts,

        // Agents / Fleet
        ("GET", p) if p.starts_with("/api/agents") || p.starts_with("/api/fleet") => Permission::ViewAgents,
        (_, p) if p.starts_with("/api/agents") || p.starts_with("/api/fleet") => Permission::ManageAgents,

        // Telemetry ingestion
        ("POST", p) if p.starts_with("/api/telemetry") || p.starts_with("/api/ingest") => Permission::SubmitTelemetry,

        // Config
        ("GET", p) if p.starts_with("/api/config") => Permission::ViewConfig,
        (_, p) if p.starts_with("/api/config") => Permission::ManageConfig,

        // Users
        (_, p) if p.starts_with("/api/users") => Permission::ManageUsers,

        // Response orchestration
        ("GET", p) if p.starts_with("/api/response") => Permission::ViewIncidents,
        ("POST", p) if p.contains("approve") || p.contains("deny") => Permission::ApproveResponses,
        ("POST", p) if p.starts_with("/api/response") => Permission::ExecuteResponses,

        // Audit
        (_, p) if p.starts_with("/api/audit") => Permission::ViewAuditLog,

        // Rules
        ("GET", p) if p.starts_with("/api/rules") || p.starts_with("/api/sigma") => Permission::ViewEvents,
        (_, p) if p.starts_with("/api/rules") || p.starts_with("/api/sigma") => Permission::ManageRules,

        // Reports
        (_, p) if p.starts_with("/api/reports") => Permission::ViewReports,

        // Export
        (_, p) if p.starts_with("/api/export") => Permission::ExportData,

        // Feature flags
        ("GET", p) if p.starts_with("/api/flags") => Permission::ViewConfig,
        (_, p) if p.starts_with("/api/flags") => Permission::ManageFeatureFlags,

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
        store.add_user(User { username: "admin".into(), role: Role::Admin, token_hash: "admin-token".into(), enabled: true, created_at: "now".into(), tenant_id: None });
        store.add_user(User { username: "analyst".into(), role: Role::Analyst, token_hash: "analyst-token".into(), enabled: true, created_at: "now".into(), tenant_id: None });
        store.add_user(User { username: "viewer".into(), role: Role::Viewer, token_hash: "viewer-token".into(), enabled: true, created_at: "now".into(), tenant_id: None });
        store.add_user(User { username: "agent-01".into(), role: Role::ServiceAccount, token_hash: "sa-token".into(), enabled: true, created_at: "now".into(), tenant_id: None });
        store
    }

    #[test]
    fn admin_has_all_permissions() {
        let store = setup_store();
        assert!(store.has_permission("admin-token", Permission::ManageUsers));
        assert!(store.has_permission("admin-token", Permission::ExecuteResponses));
        assert!(store.has_permission("admin-token", Permission::ManageFeatureFlags));
    }

    #[test]
    fn analyst_permissions() {
        let store = setup_store();
        assert!(store.has_permission("analyst-token", Permission::ViewEvents));
        assert!(store.has_permission("analyst-token", Permission::ManageIncidents));
        assert!(store.has_permission("analyst-token", Permission::ApproveResponses));
        assert!(!store.has_permission("analyst-token", Permission::ManageUsers));
        assert!(!store.has_permission("analyst-token", Permission::ManageFeatureFlags));
    }

    #[test]
    fn viewer_read_only() {
        let store = setup_store();
        assert!(store.has_permission("viewer-token", Permission::ViewDashboard));
        assert!(store.has_permission("viewer-token", Permission::ViewEvents));
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
        assert!(store.check_api_access("viewer-token", "GET", "/api/events").is_allowed());
        assert!(!store.check_api_access("viewer-token", "POST", "/api/events").is_allowed());
        assert!(store.check_api_access("admin-token", "POST", "/api/events").is_allowed());
    }

    #[test]
    fn check_api_access_users() {
        let store = setup_store();
        assert!(store.check_api_access("admin-token", "POST", "/api/users").is_allowed());
        assert!(!store.check_api_access("analyst-token", "POST", "/api/users").is_allowed());
    }

    #[test]
    fn check_api_telemetry_ingestion() {
        let store = setup_store();
        assert!(store.check_api_access("sa-token", "POST", "/api/telemetry").is_allowed());
        assert!(!store.check_api_access("viewer-token", "POST", "/api/telemetry").is_allowed());
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
    fn list_users() {
        let store = setup_store();
        let users = store.list_users();
        assert_eq!(users.len(), 4);
    }

    #[test]
    fn endpoint_permission_mapping() {
        assert_eq!(endpoint_permission("GET", "/api/events"), Permission::ViewEvents);
        assert_eq!(endpoint_permission("POST", "/api/telemetry"), Permission::SubmitTelemetry);
        assert_eq!(endpoint_permission("POST", "/api/users"), Permission::ManageUsers);
        assert_eq!(endpoint_permission("GET", "/api/dashboard"), Permission::ViewDashboard);
    }
}

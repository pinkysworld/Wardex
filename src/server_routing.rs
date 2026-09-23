use crate::server::Method;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiRouteAccess {
    Public,
    Agent,
    Cluster,
    Authenticated,
}

impl ApiRouteAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Agent => "agent",
            Self::Cluster => "cluster",
            Self::Authenticated => "authenticated",
        }
    }

    pub fn requires_bearer_auth(self) -> bool {
        !matches!(self, Self::Public)
    }
}

fn is_public_api_endpoint(method: &Method, route_path: &str) -> bool {
    matches!(
        (method, route_path),
        (
            &Method::Get,
            "/api/health"
                | "/api/metrics"
                | "/api/openapi.json"
                | "/api/auth/session"
                | "/api/auth/sso/config"
                | "/api/auth/sso/login"
                | "/api/auth/sso/callback"
        ) | (&Method::Post, "/api/auth/sso/callback")
    )
}

fn is_agent_api_endpoint(method: &Method, route_path: &str) -> bool {
    route_path.starts_with("/api/agents/enroll")
        || route_path.starts_with("/api/agents/update")
        || (route_path.contains("/heartbeat") && route_path.starts_with("/api/agents/"))
        || (*method == Method::Post && route_path == "/api/events")
        || route_path.starts_with("/api/policy/current")
        || route_path.starts_with("/api/updates/download/")
        || (*method == Method::Post
            && route_path.starts_with("/api/agents/")
            && route_path.ends_with("/logs"))
        || (*method == Method::Post
            && route_path.starts_with("/api/agents/")
            && route_path.ends_with("/inventory"))
        || is_federation_agent_route(method, route_path)
}

/// Federated-learning routes that enrolled agents call with their per-agent
/// credential. Matched exactly: a prefix match would also capture admin
/// routes such as `/api/federation/rounds` and let them skip user auth/RBAC.
pub(crate) fn is_federation_agent_route(method: &Method, route_path: &str) -> bool {
    matches!(
        (method, route_path),
        (&Method::Get, "/api/federation/round") | (&Method::Post, "/api/federation/round/submit")
    )
}

pub fn api_route_access(method: &Method, route_path: &str) -> ApiRouteAccess {
    if !route_path.starts_with("/api/") {
        return ApiRouteAccess::Public;
    }
    if route_path.starts_with("/api/cluster/") {
        return ApiRouteAccess::Cluster;
    }
    if is_public_api_endpoint(method, route_path) {
        return ApiRouteAccess::Public;
    }
    if is_agent_api_endpoint(method, route_path) {
        return ApiRouteAccess::Agent;
    }
    ApiRouteAccess::Authenticated
}

pub fn method_from_name(value: &str) -> Option<Method> {
    let normalized = value.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "GET" => Some(Method::Get),
        "POST" => Some(Method::Post),
        "PUT" => Some(Method::Put),
        "DELETE" => Some(Method::Delete),
        "PATCH" => Some(Method::Patch),
        "OPTIONS" => Some(Method::Options),
        "HEAD" => Some(Method::Head),
        _ => None,
    }
}

pub fn classify_api_route_access(method: &str, route_path: &str) -> Option<ApiRouteAccess> {
    method_from_name(method).map(|parsed| api_route_access(&parsed, route_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_agent_routes_are_matched_exactly() {
        assert_eq!(
            api_route_access(&Method::Get, "/api/federation/round"),
            ApiRouteAccess::Agent
        );
        assert_eq!(
            api_route_access(&Method::Post, "/api/federation/round/submit"),
            ApiRouteAccess::Agent
        );
        // Admin history endpoint must stay behind user auth + RBAC.
        assert_eq!(
            api_route_access(&Method::Get, "/api/federation/rounds"),
            ApiRouteAccess::Authenticated
        );
        for path in [
            "/api/federation/roundsx",
            "/api/federation/round/",
            "/api/federation/round/submit/extra",
            "/api/federation/start",
            "/api/federation/status",
        ] {
            assert_eq!(
                api_route_access(&Method::Get, path),
                ApiRouteAccess::Authenticated,
                "{path}"
            );
            assert_eq!(
                api_route_access(&Method::Post, path),
                ApiRouteAccess::Authenticated,
                "{path}"
            );
        }
        assert_eq!(
            api_route_access(&Method::Post, "/api/federation/round"),
            ApiRouteAccess::Authenticated
        );
        assert_eq!(
            api_route_access(&Method::Get, "/api/federation/round/submit"),
            ApiRouteAccess::Authenticated
        );
    }
}

//! Static-asset and embedded admin-console serving.
//!
//! Extracted from `server.rs` as part of the incremental decomposition
//! (alongside `server_auth.rs`, `server_response.rs`, etc.). The admin
//! console is compiled into the binary via `include_dir!`; a filesystem
//! fallback under `site_dir` covers any non-embedded assets. All path
//! handling is hardened against traversal (component check + canonicalize).

use std::fs;
use std::path::Path;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use include_dir::{Dir, include_dir};

use crate::server_response::{cors_origin, error_json, safe_body};

// Admin console embedded at compile time from the React build output.
const EMBEDDED_ADMIN_DIST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/admin-console/dist");

fn cache_policy(content_type: &str) -> &'static str {
    if content_type.contains("html") {
        "no-cache"
    } else {
        "public, max-age=3600, immutable"
    }
}

fn content_type_for_path(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn serve_embedded(content: &[u8], content_type: &str) -> Response<Body> {
    let origin = cors_origin();
    safe_body(
        Response::builder()
            .status(200)
            .header("Content-Type", content_type)
            .header("Access-Control-Allow-Origin", origin)
            .header("X-Content-Type-Options", "nosniff")
            .header("X-Frame-Options", "DENY")
            .header("Cache-Control", cache_policy(content_type)),
        Body::from(content.to_vec()),
    )
}

fn redirect_response(location: &str) -> Response<Body> {
    safe_body(
        Response::builder()
            .status(StatusCode::PERMANENT_REDIRECT)
            .header("Location", location)
            .header("Cache-Control", "no-cache"),
        Body::empty(),
    )
}

fn contains_parent_dir(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

fn serve_embedded_admin(relative: &str) -> Option<Response<Body>> {
    match relative {
        "/admin" | "/admin.html" => return Some(redirect_response("/admin/")),
        _ => {}
    }

    let admin_path = match relative.strip_prefix("/admin/") {
        Some("") => "index.html",
        Some(rest) => rest,
        None => return None,
    };

    if contains_parent_dir(admin_path) {
        return Some(error_json("forbidden", 403));
    }

    if let Some(file) = EMBEDDED_ADMIN_DIST.get_file(admin_path) {
        return Some(serve_embedded(
            file.contents(),
            content_type_for_path(admin_path),
        ));
    }

    let last_segment = admin_path.rsplit('/').next().unwrap_or(admin_path);
    let is_spa_route = !admin_path.starts_with("assets/") && !last_segment.contains('.');
    if is_spa_route && let Some(index) = EMBEDDED_ADMIN_DIST.get_file("index.html") {
        return Some(serve_embedded(index.contents(), "text/html; charset=utf-8"));
    }

    Some(error_json("not found", 404))
}

pub(crate) fn serve_static(url: &str, site_dir: &Path) -> Response<Body> {
    let clean_url = url.split('?').next().unwrap_or(url);
    let relative = if clean_url == "/" {
        "/index.html"
    } else {
        clean_url
    };

    if let Some(response) = serve_embedded_admin(relative) {
        return response;
    }

    // Prevent path traversal via components
    let clean = relative.trim_start_matches('/');
    if contains_parent_dir(clean) {
        return error_json("forbidden", 403);
    }

    let file_path = site_dir.join(clean);

    // Canonicalize to prevent symlink-based path traversal
    let canon_site = match site_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return error_json("server error", 500);
        }
    };
    if let Ok(canon_file) = file_path.canonicalize()
        && !canon_file.starts_with(&canon_site)
    {
        return error_json("forbidden", 403);
    }

    if file_path.is_file() {
        let content_type = content_type_for_path(clean);

        match fs::read(&file_path) {
            Ok(data) => {
                let origin = cors_origin();
                safe_body(
                    Response::builder()
                        .status(200)
                        .header("Content-Type", content_type)
                        .header("Access-Control-Allow-Origin", origin)
                        .header("X-Content-Type-Options", "nosniff")
                        .header("X-Frame-Options", "DENY")
                        .header("Cache-Control", cache_policy(content_type)),
                    Body::from(data),
                )
            }
            Err(_) => error_json("read error", 500),
        }
    } else {
        error_json("not found", 404)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_admin_html_redirects_to_admin_base() {
        let response = serve_static("/admin.html", Path::new("site"));
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get("Location")
                .and_then(|value| value.to_str().ok()),
            Some("/admin/")
        );
    }

    #[test]
    fn embedded_admin_base_serves_react_shell() {
        let response = serve_static("/admin/", Path::new("site"));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("Content-Type")
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
    }

    #[test]
    fn embedded_admin_spa_routes_fall_back_to_index() {
        let response = serve_static("/admin/soc", Path::new("site"));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("Content-Type")
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
    }

    #[test]
    fn contains_parent_dir_detects_traversal() {
        assert!(contains_parent_dir("../etc/passwd"));
        assert!(contains_parent_dir("foo/../../bar"));
        assert!(!contains_parent_dir("foo/bar/baz"));
        assert!(!contains_parent_dir("normal.json"));
    }
}

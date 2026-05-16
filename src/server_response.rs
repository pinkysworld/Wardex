use axum::body::Body;
use axum::response::Response;

pub(crate) fn cors_origin() -> String {
    let origin =
        std::env::var("SENTINEL_CORS_ORIGIN").unwrap_or_else(|_| "http://localhost".into());
    // Block wildcard CORS origin — credentials must not use "*"
    if origin == "*" {
        return "http://localhost".into();
    }
    // Validate origin looks like a URL scheme
    if origin.starts_with("http://") || origin.starts_with("https://") {
        origin
    } else {
        "http://localhost".into()
    }
}

pub(crate) fn security_headers(
    builder: axum::http::response::Builder,
) -> axum::http::response::Builder {
    let origin = cors_origin();
    builder
        .header("Access-Control-Allow-Origin", origin)
        .header("Vary", "Origin")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Cache-Control", "no-store")
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        .header(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )
        .header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'",
        )
        .header("Cross-Origin-Opener-Policy", "same-origin")
        .header("Cross-Origin-Resource-Policy", "same-origin")
        .header("X-DNS-Prefetch-Control", "off")
        .header("X-Permitted-Cross-Domain-Policies", "none")
}

pub(crate) fn safe_body(builder: axum::http::response::Builder, body: Body) -> Response<Body> {
    builder.body(body).unwrap_or_else(|_| {
        Response::builder()
            .status(500)
            .body(Body::from("internal server error"))
            .expect("fallback response must build")
    })
}

pub(crate) fn json_response(body: &str, status: u16) -> Response<Body> {
    safe_body(
        security_headers(Response::builder().status(status))
            .header("Content-Type", "application/json"),
        Body::from(body.to_owned()),
    )
}

pub(crate) fn error_json(message: &str, status: u16) -> Response<Body> {
    let code = match status {
        400 => "VALIDATION_ERROR",
        401 => "AUTH_REQUIRED",
        403 => "FORBIDDEN",
        404 => "NOT_FOUND",
        409 => "CONFLICT",
        413 => "PAYLOAD_TOO_LARGE",
        429 => "RATE_LIMITED",
        500 => "INTERNAL_ERROR",
        503 => "SERVICE_UNAVAILABLE",
        _ => "ERROR",
    };
    let body = serde_json::json!({
        "error": message,
        "code": code,
    })
    .to_string();
    json_response(&body, status)
}

pub(crate) fn text_response(body: &str, status: u16) -> Response<Body> {
    safe_body(
        security_headers(Response::builder().status(status))
            .header("Content-Type", "text/plain; charset=utf-8"),
        Body::from(body.to_owned()),
    )
}

pub(crate) fn csv_response(body: &str, status: u16) -> Response<Body> {
    safe_body(
        security_headers(Response::builder().status(status))
            .header("Content-Type", "text/csv; charset=utf-8"),
        Body::from(body.to_owned()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn error_json_escapes_control_characters_and_backslashes() {
        let response = error_json("invalid path: C:\\tmp\\x\nquote: \"", 400);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("error body");
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("valid json error body");

        assert_eq!(
            parsed["error"],
            serde_json::json!("invalid path: C:\\tmp\\x\nquote: \"")
        );
        assert_eq!(parsed["code"], serde_json::json!("VALIDATION_ERROR"));
    }
}

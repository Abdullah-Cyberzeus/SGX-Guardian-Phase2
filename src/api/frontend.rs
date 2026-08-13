//! Compile-time embedded React frontend.
//!
//! `frontend/dist` is produced before Cargo builds the binary.
//! No Node.js runtime is required on the deployed board.

use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use axum::response::Redirect;

include!(concat!(env!("OUT_DIR"), "/embedded_frontend.rs"));

/// Standard captive-portal probes are redirected to the local member join
/// page. The browser must still verify the Guardian fingerprint; a redirect
/// never establishes trust or grants API access.
pub async fn captive_portal() -> Redirect {
    Redirect::temporary("/join")
}

/// Serve a static frontend asset, falling back to `index.html` for client-side
/// routes such as `/home`.
pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Unknown API routes must remain API 404s instead of returning HTML.
    if path == "api" || path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let requested = if path.is_empty() { "index.html" } else { path };
    let (contents, mime, is_spa_fallback) = match embedded_file(requested) {
        Some((contents, mime)) => (contents, mime, false),
        None => match embedded_file("index.html") {
            Some((contents, mime)) => (contents, mime, true),
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Embedded frontend is missing index.html",
                )
                    .into_response();
            }
        },
    };

    let cache_control = if is_spa_fallback
        || requested == "index.html"
        || requested == "sw.js"
        || requested == "manifest.json"
    {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, cache_control)
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "same-origin")
        .header("X-Frame-Options", "DENY")
        // Camera, microphone, and display capture remain same-origin and are
        // still gated by explicit browser user gestures in the call UI.
        .header("Permissions-Policy", "camera=(self), microphone=(self), display-capture=(self), geolocation=(), payment=(), usb=()");
    if requested == "sw.js" {
        response = response.header("Service-Worker-Allowed", "/");
    }
    response
        .body(Body::from(contents))
        .expect("valid embedded frontend response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn serves_index_for_root_and_react_routes() {
        for uri in ["/", "/home"] {
            let response = serve(uri.parse().unwrap()).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "text/html; charset=utf-8"
            );
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert!(body
                .windows(b"<div id=\"root\">".len())
                .any(|window| { window == b"<div id=\"root\">" }));
        }
    }

    #[tokio::test]
    async fn unknown_api_route_stays_a_404() {
        let response = serve("/api/unknown".parse().unwrap()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

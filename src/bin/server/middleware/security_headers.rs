//! Security headers middleware for API and static file responses.
//! Adds Defense-in-depth headers without changing response bodies.

use axum::{
    body::Body,
    extract::Request,
    http::header::{HeaderValue, REFERRER_POLICY, X_FRAME_OPTIONS},
    middleware::Next,
    response::Response,
};

/// Layer middleware that adds security headers to all responses.
/// Non-invasive: does not modify response bodies or status codes.
pub async fn add_security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    // Clickjacking protection: deny framing entirely
    // Equivalent to CSP frame-ancestors 'none' for legacy browsers
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    // Referrer control: limit info sent to external links
    // strict-origin-when-cross-origin: full URL same-origin, origin only cross-origin
    headers.insert(
        REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Note: CSP is not added here because the frontend uses inline styles
    // and inline scripts that would be blocked by a strict policy.
    // CSP can be added at a reverse proxy if inline resources are externalized.

    response
}

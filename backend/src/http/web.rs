//! Serving the Flutter web build (`WEB_DIR`) from the API's origin, so the
//! web app and the API share it: the session cookie stays first-party and
//! no CORS is needed.
//!
//! - A file that exists is served (`GET`, `HEAD`).
//! - Any other path asked for as HTML (`Accept: text/html`) gets
//!   `index.html`: the app's router handles it (single-page app).
//! - Anything else is a `404` problem, as on any API route.
//!
//! `index.html` is never stored by caches (`no-store`): it names the
//! current build. Flutter does not put content hashes in file names, so
//! the other files are cacheable only with revalidation (`no-cache`, with
//! `Last-Modified`). HTML gets [`WEB_CONTENT_SECURITY_POLICY`]; everything
//! else keeps the API's `default-src 'none'`.

use std::path::Path;

use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

/// The Content Security Policy of the web app's pages. The single source
/// of truth for it (`frontend/AGENTS.md`).
///
/// - `'wasm-unsafe-eval'`: `CanvasKit` is `WebAssembly`.
/// - `style-src 'unsafe-inline'`: the engine positions its DOM elements with
///   inline styles. Inline *scripts* stay forbidden.
/// - `blob:`/`data:` images and fonts: the engine decodes images and loads
///   bundled fonts from in-memory URLs.
/// - Everything else, the API included, is this origin.
pub const WEB_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; \
     script-src 'self' 'wasm-unsafe-eval'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data: blob:; \
     font-src 'self' data: blob:; \
     connect-src 'self'; \
     worker-src 'self' blob:; \
     manifest-src 'self'; \
     base-uri 'self'; \
     form-action 'none'; \
     object-src 'none'; \
     frame-ancestors 'none'";

/// Adds serving of the web build in `dir` to `routes`, for paths no route
/// matches.
pub fn with_web_app(routes: Router, dir: &Path) -> Router {
    let files = ServeDir::new(dir).append_index_html_on_directories(false);
    let index = ServeFile::new(dir.join("index.html"));
    routes.fallback(move |request: Request<Body>| {
        let files = files.clone();
        let index = index.clone();
        async move { serve(files, index, request).await }
    })
}

async fn serve(files: ServeDir, index: ServeFile, request: Request<Body>) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path_is_root = request.uri().path() == "/";
    let wants_html = request
        .headers()
        .get(header::ACCEPT)
        .and_then(|accept| accept.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"));
    let (is_index, response) = if path_is_root {
        (true, index.oneshot(request).await)
    } else {
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts.clone(), body);
        match files.oneshot(request).await {
            Ok(response) if response.status() == StatusCode::NOT_FOUND && wants_html => (
                true,
                index
                    .oneshot(Request::from_parts(parts, Body::empty()))
                    .await,
            ),
            other => (false, other),
        }
    };
    // Serving files cannot fail (`Infallible`); I/O errors are statuses.
    let Ok(response) = response;
    let mut response = response.map(Body::new);
    if response.status().is_success() || response.status() == StatusCode::NOT_MODIFIED {
        let headers = response.headers_mut();
        let cache = if is_index { "no-store" } else { "no-cache" };
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        let is_html = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/html"));
        if is_html {
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(WEB_CONTENT_SECURITY_POLICY),
            );
        }
    }
    response
}

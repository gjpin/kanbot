//! HTTP layer: the router and its middleware stack. Each feature module
//! exposes `routes()`, merged here.

pub mod client_ip;
pub mod extract;
mod health;
pub mod middleware;
pub mod problem;

use std::time::Duration;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
};
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
};

use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};
use utoipa_axum::router::OpenApiRouter;

use crate::{
    error::FieldError,
    http::problem::{ErrorCode, Problem},
    state::AppState,
};
use middleware::{
    security_headers::{add_security_headers, mark_sensitive_headers},
    telemetry::{HttpMetrics, trace_request},
};

/// Largest accepted request body, in bytes.
pub const MAX_BODY_BYTES: usize = 1_048_576;
/// Longest a request may take before it gets a 503.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CORS_MAX_AGE: Duration = Duration::from_secs(3600);

/// The `OpenAPI` document's fixed parts. Paths and their schemas come from
/// each feature's `routes()`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "kanbot API",
        description = "Errors are RFC 9457 problem details (`application/problem+json`) with a stable `code`.",
    ),
    components(schemas(Problem, ErrorCode, FieldError)),
    modifiers(&SecuritySchemes)
)]
struct ApiDoc;

/// Name of the security scheme for IdP-issued JWT access tokens. Protected
/// operations declare `security(("bearer" = []))`.
pub const BEARER_SCHEME: &str = "bearer";

/// Adds the security schemes, which the derive cannot express.
struct SecuritySchemes;

impl Modify for SecuritySchemes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                BEARER_SCHEME,
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some(
                            "An access token from the deployment's OIDC identity provider.",
                        ))
                        .build(),
                ),
            );
    }
}

/// Every route, with its `OpenAPI` description. Merge each feature's
/// `routes()` here.
fn api() -> OpenApiRouter<AppState> {
    let mut doc = ApiDoc::openapi();
    // utoipa copies the crate's license, which a private crate does not have.
    doc.info.license = None;
    OpenApiRouter::with_openapi(doc)
        .merge(health::routes())
        .merge(crate::users::routes())
}

/// The full application: all routes plus the middleware stack.
/// `allowed_origins` are the browser origins allowed to call the API
/// cross-origin. `relay` is the telemetry relay (`telemetry_relay::routes`),
/// when it is configured.
pub fn router(state: AppState, allowed_origins: &[HeaderValue], relay: Option<Router>) -> Router {
    let (routes, _) = api().split_for_parts();
    let routes = routes.with_state(state.clone());
    let routes = match relay {
        Some(relay) => routes.merge(relay),
        None => routes,
    };
    // Every route, the relay included: credentials are checked wherever
    // they are presented.
    let routes = routes.layer(axum::middleware::from_fn_with_state(
        state,
        crate::auth::middleware::authenticate,
    ));
    with_middleware(routes, allowed_origins)
}

/// The `OpenAPI` document of the API: the contract the frontend's client is
/// generated from. `cargo run --bin openapi` writes it to `openapi.json`.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    api().into_openapi()
}

/// Wraps `app` in the middleware stack. Layers added later wrap the earlier
/// ones. The request span (and HTTP metrics) is outermost, so it covers the
/// whole stack. Sensitive headers are marked before anything can log them,
/// every error response gets a problem details body, and security headers
/// are added to every response, including errors produced by the middleware
/// itself.
pub fn with_middleware(app: Router, allowed_origins: &[HeaderValue]) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins.iter().cloned()))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            // W3C trace context, so app traces continue into the API.
            HeaderName::from_static("traceparent"),
            HeaderName::from_static("tracestate"),
        ])
        .max_age(CORS_MAX_AGE);

    let app = app
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        // 503, not 408: a 408 tells the client it was too slow to send the
        // request, and browsers and proxies may resend it automatically.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            REQUEST_TIMEOUT,
        ))
        .layer(CatchPanicLayer::new())
        // Inside CORS, so that browsers can read error bodies too.
        .layer(axum::middleware::map_response(problem::ensure_problem_body))
        .layer(cors);
    let app = mark_sensitive_headers(add_security_headers(app));
    app.layer(axum::middleware::from_fn_with_state(
        HttpMetrics::global(),
        trace_request,
    ))
}

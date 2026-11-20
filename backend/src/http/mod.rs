//! HTTP layer: the router and its middleware stack. Each feature module
//! exposes `routes()`, merged here.

pub mod client_ip;
pub mod extract;
mod health;
pub mod middleware;
pub mod problem;

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use axum::{
    Router,
    error_handling::HandleErrorLayer,
    extract::DefaultBodyLimit,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    response::IntoResponse,
};
use tower::{ServiceBuilder, limit::GlobalConcurrencyLimitLayer};
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
    auth::middleware::{AuthMetrics, Authentication},
    error::{FieldError, StartupError},
    http::{
        client_ip::TrustedProxies,
        problem::{ErrorCode, Problem},
    },
    state::AppState,
};
use middleware::{
    rate_limit::{self, RateLimits},
    security_headers::{add_security_headers, mark_sensitive_headers},
    telemetry::{HttpMetrics, trace_request},
};

/// Largest accepted request body, in bytes.
pub const MAX_BODY_BYTES: usize = 1_048_576;
/// Longest a request may take before it gets a 503.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// `Retry-After` of a request shed because too many are in flight.
pub const OVERLOADED_RETRY_AFTER_SECONDS: u64 = 1;
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
        .merge(crate::sessions::routes())
}

/// How the HTTP layer protects the app (see `backend/AGENTS.md`).
pub struct HttpSettings {
    /// Browser origins allowed to call the API cross-origin
    /// (`CORS_ALLOWED_ORIGINS`).
    pub allowed_origins: Vec<HeaderValue>,
    /// Proxies whose `X-Forwarded-For` is trusted (`TRUSTED_PROXIES`).
    pub trusted_proxies: Arc<TrustedProxies>,
    pub rate_limits: RateLimits,
    /// Requests in flight before new ones get a 503
    /// (`MAX_IN_FLIGHT_REQUESTS`).
    pub max_in_flight_requests: NonZeroUsize,
    pub auth_metrics: AuthMetrics,
}

impl HttpSettings {
    /// The defaults, with metrics on the global meter: no cross-origin
    /// browsers, no trusted proxies, the default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::configured(
            Vec::new(),
            TrustedProxies::default(),
            RateLimits::DEFAULT,
            NonZeroUsize::new(512).unwrap_or(NonZeroUsize::MIN),
        )
    }

    /// The settings from the configuration, with metrics on the global
    /// meter.
    #[must_use]
    pub fn configured(
        allowed_origins: Vec<HeaderValue>,
        trusted_proxies: TrustedProxies,
        rate_limits: RateLimits,
        max_in_flight_requests: NonZeroUsize,
    ) -> Self {
        Self {
            allowed_origins,
            trusted_proxies: Arc::new(trusted_proxies),
            rate_limits,
            max_in_flight_requests,
            auth_metrics: AuthMetrics::global(),
        }
    }
}

impl Default for HttpSettings {
    fn default() -> Self {
        Self::new()
    }
}

/// The full application: all routes plus the middleware stack. `relay` is
/// the telemetry relay (`telemetry_relay::routes`), when it is configured.
/// Spawns the rate limiters' cleanup tasks on the current Tokio runtime.
///
/// A request passes, outermost first: the middleware stack
/// ([`with_middleware`]), the in-flight cap, the per-client limit, the
/// authentication middleware (with the failed-authentication limit), the
/// per-user limit, then the route.
///
/// # Errors
///
/// [`StartupError::RateLimit`] if a limit's period rounds to zero.
pub fn router(
    state: AppState,
    settings: HttpSettings,
    relay: Option<Router>,
) -> Result<Router, StartupError> {
    let (routes, _) = api().split_for_parts();
    let routes = routes.with_state(state.clone()).layer(axum::Extension(
        crate::sessions::TelemetryAvailable(relay.is_some()),
    ));
    let routes = match relay {
        Some(relay) => routes.merge(relay),
        None => routes,
    };
    let routes = rate_limit::limit_per_user(routes, settings.rate_limits.user)?;
    // Every route, the relay included: credentials are checked wherever
    // they are presented.
    let routes = routes.layer(axum::middleware::from_fn_with_state(
        Authentication::new(
            state,
            Arc::clone(&settings.trusted_proxies),
            settings.rate_limits.auth_failure,
            settings.auth_metrics,
        ),
        crate::auth::middleware::authenticate,
    ));
    let routes =
        rate_limit::limit_per_client(routes, settings.trusted_proxies, settings.rate_limits.ip)?;
    let routes = routes.layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: tower::BoxError| async {
                // `ensure_problem_body` adds the problem body.
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, OVERLOADED_RETRY_AFTER_SECONDS)],
                )
                    .into_response()
            }))
            .load_shed()
            // Global: `Router::layer` wraps each route on its own, and a
            // plain concurrency limit would then cap each route separately.
            .layer(GlobalConcurrencyLimitLayer::new(
                settings.max_in_flight_requests.get(),
            )),
    );
    Ok(with_middleware(routes, &settings.allowed_origins))
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;
    use crate::http::middleware::rate_limit::RateLimit;

    #[test]
    fn configured_settings_keep_every_value() {
        let limit = RateLimit {
            per_second: NonZeroU32::new(3).unwrap(),
            burst: NonZeroU32::new(4).unwrap(),
        };
        let limits = RateLimits {
            ip: limit,
            ..RateLimits::DEFAULT
        };
        let proxies = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let settings = HttpSettings::configured(
            vec![HeaderValue::from_static("https://app.example.com")],
            proxies.clone(),
            limits,
            NonZeroUsize::new(7).unwrap(),
        );
        assert_eq!(settings.allowed_origins, ["https://app.example.com"]);
        assert_eq!(*settings.trusted_proxies, proxies);
        assert_eq!(settings.rate_limits, limits);
        assert_eq!(settings.max_in_flight_requests.get(), 7);
    }

    #[test]
    fn default_settings() {
        let settings = HttpSettings::default();
        assert_eq!(settings.allowed_origins, Vec::<HeaderValue>::new());
        assert_eq!(*settings.trusted_proxies, TrustedProxies::default());
        assert_eq!(settings.rate_limits, RateLimits::DEFAULT);
        assert_eq!(settings.max_in_flight_requests.get(), 512);
    }
}

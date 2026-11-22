//! Liveness (`/health`) and readiness (`/ready`) probes.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use axum::{Extension, extract::State, http::StatusCode};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{db, error::AppError, http::problem::Problem, state::AppState};

/// `/health`.
pub fn liveness_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(health))
}

/// `/ready`. Needs a [`Readiness`] extension.
pub fn readiness_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(ready))
}

/// How long a readiness answer is reused. `/ready` is public: without this,
/// every call would cost a database round trip.
const READINESS_TTL: Duration = Duration::from_secs(1);

/// The last readiness answer and when it was found.
#[derive(Clone, Default)]
pub struct Readiness(Arc<Mutex<Option<(Instant, bool)>>>);

impl Readiness {
    fn cached(&self, now: Instant) -> Option<bool> {
        let last = *self.0.lock().unwrap_or_else(PoisonError::into_inner);
        last.filter(|(at, _)| now.saturating_duration_since(*at) < READINESS_TTL)
            .map(|(_, ready)| ready)
    }

    fn store(&self, now: Instant, ready: bool) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((now, ready));
    }
}

/// Liveness: the process is up and serving HTTP.
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses((status = OK, description = "The server is up.", body = String, content_type = "text/plain")),
)]
async fn health() -> &'static str {
    "ok"
}

/// Readiness: the database is reachable, every migration has been applied,
/// and the identity provider's signing keys have been loaded. Until
/// `kanbot-backend migrate` has run, the old schema is in place and
/// requests could fail; until the keys load, no request can be
/// authenticated. Either way the instance takes no traffic.
#[utoipa::path(
    get,
    path = "/ready",
    tag = "health",
    responses(
        (status = OK, description = "Ready to take traffic."),
        (status = SERVICE_UNAVAILABLE, description = "Not ready: the database is unreachable, migrations are pending, or the identity provider's keys have not loaded.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
async fn ready(
    State(state): State<AppState>,
    Extension(readiness): Extension<Readiness>,
) -> Result<StatusCode, AppError> {
    let now = Instant::now();
    let ready = if let Some(ready) = readiness.cached(now) {
        ready
    } else {
        // Keys first: without them nothing is served, whatever the
        // database says. Either warning is then logged once per answer,
        // not once per call.
        let ready = if state.keys.is_loaded() {
            let mut conn = state.db.acquire().await?;
            let ready = db::migrations_are_current(&mut conn, state.migrator).await?;
            if !ready {
                tracing::warn!("not ready: migrations are pending");
            }
            ready
        } else {
            tracing::warn!("not ready: the identity provider's signing keys have not loaded");
            false
        };
        readiness.store(now, ready);
        ready
    };
    if ready {
        Ok(StatusCode::OK)
    } else {
        Err(AppError::Unavailable)
    }
}

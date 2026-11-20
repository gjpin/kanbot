//! Liveness (`/health`) and readiness (`/ready`) probes.

use axum::{extract::State, http::StatusCode};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{db, error::AppError, http::problem::Problem, state::AppState};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(health))
        .routes(routes!(ready))
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

/// Readiness: the database is reachable and every migration has been
/// applied. Until `kanbot-backend migrate` has run, the old schema is in
/// place and requests could fail, so the instance takes no traffic.
#[utoipa::path(
    get,
    path = "/ready",
    tag = "health",
    responses(
        (status = OK, description = "Ready to take traffic."),
        (status = SERVICE_UNAVAILABLE, description = "Not ready: the database is unreachable or migrations are pending.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
async fn ready(State(state): State<AppState>) -> Result<StatusCode, AppError> {
    let mut conn = state.db.acquire().await?;
    if db::migrations_are_current(&mut conn, state.migrator).await? {
        Ok(StatusCode::OK)
    } else {
        tracing::warn!("not ready: migrations are pending");
        Err(AppError::Unavailable)
    }
}

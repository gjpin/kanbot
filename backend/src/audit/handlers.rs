//! Handlers of the `/audit` route.

use axum::{
    Json,
    extract::{Query, State},
};

use crate::{
    audit::{
        dto::{AuditEntryDto, AuditPage, AuditQuery},
        service,
    },
    error::AppError,
    http::{extract::Caller, problem::Problem},
    state::AppState,
};

const DEFAULT_PAGE: i64 = 50;

/// The audit log, newest first. Platform admins only.
#[utoipa::path(
    get,
    path = "/audit",
    operation_id = "list_audit_entries",
    tag = "audit",
    params(AuditQuery),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "A page of the audit log.", body = AuditPage),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to read the audit log.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn list(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditPage>, AppError> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE);
    let entries = service::list(&state.db, &state.authz, &actor, query.before, limit).await?;
    let full =
        i64::try_from(entries.len()).is_ok_and(|len| len == limit.clamp(1, service::MAX_PAGE));
    let next_before = entries.last().filter(|_| full).map(|entry| entry.id);
    Ok(Json(AuditPage {
        entries: entries.into_iter().map(AuditEntryDto::from).collect(),
        next_before,
    }))
}

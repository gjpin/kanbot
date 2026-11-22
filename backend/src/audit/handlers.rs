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
        (status = BAD_REQUEST, description = "Malformed parameters.",
         body = Problem, content_type = "application/problem+json"),
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
    let page = service::list(&state.db, &state.authz, &actor, query.before, query.limit).await?;
    Ok(Json(AuditPage {
        entries: page.entries.into_iter().map(AuditEntryDto::from).collect(),
        next_before: page.next_before,
    }))
}

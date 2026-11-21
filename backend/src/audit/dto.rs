//! Request and response types of the `/audit` route.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{audit::model::Entry, users::dto::UserSummaryDto};

/// `GET /audit` parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    /// Only entries older than this entry ID (the previous page's
    /// `next_before`).
    pub before: Option<i64>,
    /// Entries per page, 1 to 100 (default 50).
    pub limit: Option<i64>,
}

/// One change to an organization or a team.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEntryDto {
    pub id: i64,
    /// When, in RFC 3339 (UTC).
    #[schema(format = "date-time")]
    pub at: String,
    /// Who made the change.
    pub actor: UserSummaryDto,
    /// What happened, as `<target type>.<event>`, for example
    /// `organization.team_linked`.
    pub action: String,
    /// `organization` or `team`.
    pub target_type: String,
    #[schema(value_type = String, format = "uuid")]
    pub target_id: Uuid,
    /// The policies that allowed the change.
    pub policy_ids: Vec<String>,
    /// IDs and enumerated values describing the change.
    #[schema(value_type = Object)]
    pub details: serde_json::Value,
}

/// A page of the audit log, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditPage {
    pub entries: Vec<AuditEntryDto>,
    /// Pass as `before` for the next page; absent on the last one.
    pub next_before: Option<i64>,
}

impl From<Entry> for AuditEntryDto {
    fn from(entry: Entry) -> Self {
        Self {
            id: entry.id,
            at: entry.at,
            actor: entry.actor.into(),
            action: entry.action,
            target_type: entry.target_type,
            target_id: entry.target_id,
            policy_ids: entry.policy_ids,
            details: entry.details,
        }
    }
}

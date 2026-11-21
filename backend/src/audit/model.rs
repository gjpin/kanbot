//! Domain types of the audit log.

use serde_json::Value;

use crate::{
    authz::model::Decision,
    organizations::model::OrganizationId,
    teams::model::TeamId,
    users::model::{UserId, UserSummary},
};

/// What a change was made to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Organization(OrganizationId),
    Team(TeamId),
}

impl Target {
    /// The stored type (`audit_log.target_type`).
    #[must_use]
    pub const fn type_name(self) -> &'static str {
        match self {
            Self::Organization(_) => "organization",
            Self::Team(_) => "team",
        }
    }

    #[must_use]
    pub const fn id(self) -> uuid::Uuid {
        match self {
            Self::Organization(id) => id.as_uuid(),
            Self::Team(id) => id.as_uuid(),
        }
    }
}

/// A change to record.
#[derive(Clone, Debug, PartialEq)]
pub struct NewEntry {
    pub actor: UserId,
    /// What happened, as `<target type>.<event>`, for example
    /// `organization.team_linked`.
    pub action: &'static str,
    pub target: Target,
    /// The policies that allowed the change.
    pub policy_ids: Vec<String>,
    /// IDs and enumerated values only: never names or other personal data.
    pub details: Value,
}

impl NewEntry {
    /// An entry for a change `decision` allowed.
    #[must_use]
    pub fn new(
        actor: UserId,
        action: &'static str,
        target: Target,
        decision: &Decision,
        details: Value,
    ) -> Self {
        Self {
            actor,
            action,
            target,
            policy_ids: decision.policy_ids.clone(),
            details,
        }
    }
}

/// A recorded change.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// Increases with every entry.
    pub id: i64,
    /// RFC 3339, UTC.
    pub at: String,
    pub actor: UserSummary,
    pub action: String,
    pub target_type: String,
    pub target_id: uuid::Uuid,
    pub policy_ids: Vec<String>,
    pub details: Value,
}

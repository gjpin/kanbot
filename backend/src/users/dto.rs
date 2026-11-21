//! Request and response bodies of the users routes.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{
    auth::token::PlatformRole,
    authz::model::Action,
    users::model::{AuthenticatedUser, UserSummary},
};

/// The signed-in user.
#[derive(Debug, Serialize, ToSchema)]
pub struct Me {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// From the identity provider (`name`, else `preferred_username`).
    pub display_name: Option<String>,
    pub platform_role: PlatformRoleDto,
    /// Whether the app may send telemetry. Off until the user opts in.
    pub telemetry_opt_in: bool,
    /// What the user may do across the instance.
    pub permissions: Vec<PlatformPermissionDto>,
}

/// Something the user may do across the instance. The app shows only the
/// controls the user can use; the server checks every request anyway.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlatformPermissionDto {
    CreateOrganization,
    CreateTeam,
    /// Find users by name (`GET /users`), to add them as admins or
    /// members.
    SearchUsers,
    /// Read the audit log (`GET /audit`).
    ViewAudit,
}

/// A user, as other users see them.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserSummaryDto {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// From the identity provider.
    pub display_name: Option<String>,
}

/// `GET /users` parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct UserSearch {
    /// Part of the display name, any case, at most 100 characters. Empty
    /// or absent: the first users by name.
    pub query: Option<String>,
}

/// What the user may do across the whole instance.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlatformRoleDto {
    Admin,
    User,
}

/// The user's preferences.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    /// Allow the app to send telemetry.
    pub telemetry_opt_in: bool,
}

impl Me {
    #[must_use]
    pub fn new(user: AuthenticatedUser, permissions: &[Action]) -> Self {
        Self {
            id: user.id.as_uuid(),
            display_name: user.display_name,
            platform_role: match user.role {
                PlatformRole::Admin => PlatformRoleDto::Admin,
                PlatformRole::User => PlatformRoleDto::User,
            },
            telemetry_opt_in: user.telemetry_opt_in,
            permissions: permissions
                .iter()
                .filter_map(|action| match action {
                    Action::CreateOrganization => Some(PlatformPermissionDto::CreateOrganization),
                    Action::CreateTeam => Some(PlatformPermissionDto::CreateTeam),
                    Action::SearchUsers => Some(PlatformPermissionDto::SearchUsers),
                    Action::ViewAudit => Some(PlatformPermissionDto::ViewAudit),
                    _ => None,
                })
                .collect(),
        }
    }
}

impl From<UserSummary> for UserSummaryDto {
    fn from(user: UserSummary) -> Self {
        Self {
            id: user.id.as_uuid(),
            display_name: user.display_name,
        }
    }
}

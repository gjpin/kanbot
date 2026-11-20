//! Request and response bodies of the users routes.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{auth::token::PlatformRole, users::model::AuthenticatedUser};

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

impl From<AuthenticatedUser> for Me {
    fn from(user: AuthenticatedUser) -> Self {
        Self {
            id: user.id.as_uuid(),
            display_name: user.display_name,
            platform_role: match user.role {
                PlatformRole::Admin => PlatformRoleDto::Admin,
                PlatformRole::User => PlatformRoleDto::User,
            },
            telemetry_opt_in: user.telemetry_opt_in,
        }
    }
}

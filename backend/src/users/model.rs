//! Domain types of users.

use uuid::Uuid;

use crate::auth::token::PlatformRole;

/// A user's internal ID. Safe to log, unlike their subject or name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UserId(Uuid);

impl UserId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

/// The user behind an authenticated request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedUser {
    pub id: UserId,
    pub role: PlatformRole,
    /// From the token. Personal data: never log it.
    pub display_name: Option<String>,
    pub telemetry_opt_in: bool,
    /// The groups claim (`OIDC_GROUPS_CLAIM`). Personal data: never log it.
    pub groups: Vec<String>,
    /// The client the token was issued to (`azp`, `client_id` or `cid`).
    pub client_id: Option<String>,
}

/// What the repository returns for a user seen on a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeenUser {
    pub id: UserId,
    pub disabled: bool,
    pub telemetry_opt_in: bool,
}

/// A user as other users see them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSummary {
    pub id: UserId,
    /// From the identity provider. Personal data: never log it.
    pub display_name: Option<String>,
}

/// A user search: part of a display name, at most 100 characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserQuery(String);

impl UserQuery {
    const MAX_CHARS: usize = 100;

    /// Trims `raw`. `None` if it is longer than 100 characters.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        (trimmed.chars().count() <= Self::MAX_CHARS).then(|| Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
    /// The groups claim (`OIDC_GROUPS_CLAIM`), or the groups stored when it
    /// was last present. Personal data: never log it.
    pub groups: Vec<String>,
    /// Whether `groups` came from this request's token, so team sync may
    /// act on them: a token without the claim says nothing about groups.
    pub groups_claimed: bool,
    /// The client the token was issued to (`azp`, `client_id` or `cid`).
    pub client_id: Option<String>,
}

/// What the repository returns for a user seen on a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenUser {
    pub id: UserId,
    pub disabled: bool,
    pub telemetry_opt_in: bool,
    /// The stored groups (after this request's update, if any).
    pub groups: Vec<String>,
}

/// A user as other users see them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSummary {
    pub id: UserId,
    /// From the identity provider. Personal data: never log it.
    pub display_name: Option<String>,
    /// Disabled in kanbot: still listed where they were, so they can be
    /// removed, but refused everywhere else.
    pub disabled: bool,
}

/// A user search: part of a display name, at most 100 characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserQuery(String);

impl UserQuery {
    const MAX_CHARS: usize = 100;

    /// Trims `raw`.
    ///
    /// # Errors
    ///
    /// The field error code: `too_long` over 100 characters, `invalid`
    /// with a control character (no name has one, and the database refuses
    /// NUL).
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        let trimmed = raw.trim();
        if trimmed.chars().count() > Self::MAX_CHARS {
            Err("too_long")
        } else if trimmed.chars().any(char::is_control) {
            Err("invalid")
        } else {
            Ok(Self(trimmed.to_owned()))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

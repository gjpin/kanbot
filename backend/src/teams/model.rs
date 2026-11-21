//! Domain types of teams.

use uuid::Uuid;

use crate::{
    names::{Name, NameError, Slug},
    users::model::UserSummary,
};

/// A team's ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TeamId(Uuid);

impl TeamId {
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

impl Default for TeamId {
    fn default() -> Self {
        Self::new()
    }
}

/// The identity provider group a team is synced with: 1 to 200
/// characters, no control characters, compared exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdpGroup(String);

impl IdpGroup {
    const MAX_CHARS: usize = 200;

    /// # Errors
    ///
    /// [`NameError`] if `raw` is empty, too long or has control
    /// characters.
    pub fn parse(raw: &str) -> Result<Self, NameError> {
        if raw.is_empty() {
            return Err(NameError::Required);
        }
        if raw.chars().count() > Self::MAX_CHARS {
            return Err(NameError::TooLong);
        }
        if raw.chars().any(char::is_control) {
            return Err(NameError::Invalid);
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A team.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Team {
    pub id: TeamId,
    pub slug: Slug,
    pub name: Name,
    /// Set: the members are the users whose groups claim contains it.
    pub idp_group: Option<IdpGroup>,
}

/// A change to a team: the fields to set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TeamChanges {
    pub slug: Option<Slug>,
    pub name: Option<Name>,
    pub idp_group: Option<IdpGroupChange>,
}

/// A change of a team's identity provider group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdpGroupChange {
    Set(IdpGroup),
    Clear,
}

impl IdpGroupChange {
    /// The new group, if any.
    #[must_use]
    pub fn group(&self) -> Option<&IdpGroup> {
        match self {
            Self::Set(group) => Some(group),
            Self::Clear => None,
        }
    }
}

impl TeamChanges {
    /// The names of the fields that change, for the audit log.
    #[must_use]
    pub fn fields(&self) -> Vec<&'static str> {
        [
            self.slug.as_ref().map(|_| "slug"),
            self.name.as_ref().map(|_| "name"),
            self.idp_group.as_ref().map(|_| "idp_group"),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// A member's role in a team.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeamRole {
    Member,
    /// Manages the team and its members.
    Maintainer,
}

impl TeamRole {
    /// The stored form (`team_members.role`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Maintainer => "maintainer",
        }
    }

    /// The stored form back. `None` for anything else.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "member" => Some(Self::Member),
            "maintainer" => Some(Self::Maintainer),
            _ => None,
        }
    }
}

/// How a member got into a team.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipSource {
    /// Added through the API.
    Manual,
    /// Added by the identity provider group sync; read-only.
    Idp,
}

impl MembershipSource {
    /// The stored form back (`team_members.source`). `None` for anything
    /// else.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "manual" => Some(Self::Manual),
            "idp" => Some(Self::Idp),
            _ => None,
        }
    }
}

/// A member of a team.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub user: UserSummary,
    pub role: TeamRole,
    pub source: MembershipSource,
}

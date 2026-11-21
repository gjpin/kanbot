//! Domain types of organizations.

use uuid::Uuid;

use crate::{
    names::{Name, Slug},
    teams::model::Team,
};

/// An organization's ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OrganizationId(Uuid);

impl OrganizationId {
    /// The Default organization, created by the migrations. It cannot be
    /// deleted.
    pub const DEFAULT: Self = Self(Uuid::from_u128(1));

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

impl Default for OrganizationId {
    fn default() -> Self {
        Self::new()
    }
}

/// What a team linked to an organization may do there. `Write` implies
/// `Read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Access {
    Read,
    Write,
}

impl Access {
    /// The stored form (`organization_teams.access`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// The stored form back. `None` for anything else.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            _ => None,
        }
    }
}

/// An organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Organization {
    pub id: OrganizationId,
    pub slug: Slug,
    pub name: Name,
}

/// A change to an organization: the fields to set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrganizationChanges {
    pub slug: Option<Slug>,
    pub name: Option<Name>,
}

impl OrganizationChanges {
    /// The names of the fields that change, for the audit log.
    #[must_use]
    pub fn fields(&self) -> Vec<&'static str> {
        [
            self.slug.as_ref().map(|_| "slug"),
            self.name.as_ref().map(|_| "name"),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// A team linked to an organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamLink {
    pub team: Team,
    pub access: Access,
}

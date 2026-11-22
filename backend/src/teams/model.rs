//! Domain types of teams.

use uuid::Uuid;

use crate::{
    names::{Name, NameError, Slug},
    users::model::{UserId, UserSummary},
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
    /// The names of the fields whose value differs from `current`'s, for
    /// the audit log. Empty: nothing changes.
    #[must_use]
    pub fn changed(&self, current: &Team) -> Vec<&'static str> {
        [
            self.slug
                .as_ref()
                .filter(|slug| **slug != current.slug)
                .map(|_| "slug"),
            self.name
                .as_ref()
                .filter(|name| **name != current.name)
                .map(|_| "name"),
            self.idp_group
                .as_ref()
                .filter(|change| change.group() != current.idp_group.as_ref())
                .map(|_| "idp_group"),
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

/// Where a page of a team's members ends: the sort key of its last member
/// (maintainers first, then by display name, unnamed last, then by ID).
/// Opaque to clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberCursor {
    pub maintainer: bool,
    pub display_name: Option<String>,
    pub user: UserId,
}

impl MemberCursor {
    /// The cursor of `member`.
    #[must_use]
    pub fn after(member: &Member) -> Self {
        Self {
            maintainer: member.role == TeamRole::Maintainer,
            display_name: member.user.display_name.clone(),
            user: member.user.id,
        }
    }

    /// The opaque form: base64url of `<m|-><n|->:<user id>:<name>`.
    #[must_use]
    pub fn encode(&self) -> String {
        let text = format!(
            "{}{}:{}:{}",
            if self.maintainer { 'm' } else { '-' },
            if self.display_name.is_some() {
                'n'
            } else {
                '-'
            },
            self.user.as_uuid(),
            self.display_name.as_deref().unwrap_or_default()
        );
        crate::base64::encode_url(text.as_bytes())
    }

    /// Reads [`MemberCursor::encode`]'s form. `None` for anything else.
    #[must_use]
    pub fn decode(raw: &str) -> Option<Self> {
        let text = String::from_utf8(crate::base64::decode_url(raw)?).ok()?;
        let (flags, rest) = text.split_once(':')?;
        let (user, name) = rest.split_once(':')?;
        let (maintainer, named) = match flags {
            "mn" => (true, true),
            "m-" => (true, false),
            "-n" => (false, true),
            "--" => (false, false),
            _ => return None,
        };
        // Postgres refuses NUL in text, and no stored display name has one.
        if (!named && !name.is_empty()) || name.contains('\0') {
            return None;
        }
        Some(Self {
            maintainer,
            display_name: named.then(|| name.to_owned()),
            user: UserId::from_uuid(user.parse().ok()?),
        })
    }
}

#[cfg(test)]
mod cursor_tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn cursors_survive_their_opaque_form(
            maintainer: bool,
            name in proptest::option::of("\\PC{0,40}"),
            id: u128,
        ) {
            let cursor = MemberCursor {
                maintainer,
                display_name: name,
                user: UserId::from_uuid(Uuid::from_u128(id)),
            };
            prop_assert_eq!(MemberCursor::decode(&cursor.encode()), Some(cursor));
        }

        #[test]
        fn names_with_nul_are_no_cursor(
            user: u128,
            before in "\\PC{0,10}",
            after in "\\PC{0,10}",
        ) {
            let raw = format!("-n:{}:{before}\0{after}", uuid::Uuid::from_u128(user));
            prop_assert_eq!(
                MemberCursor::decode(&crate::base64::encode_url(raw.as_bytes())),
                None
            );
        }

        #[test]
        fn anything_else_is_no_cursor(raw in "\\PC{0,60}") {
            if let Some(cursor) = MemberCursor::decode(&raw) {
                prop_assert_eq!(cursor.encode(), raw);
            }
        }
    }
}
